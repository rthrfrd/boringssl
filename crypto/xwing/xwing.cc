// Copyright 2025 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <openssl/xwing.h>

#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/mlkem.h>
#include <openssl/rand.h>

#include "../fipsmodule/bcm_interface.h"
#include "../fipsmodule/keccak/internal.h"
#include "../internal.h"

int XWING_generate_key(
    uint8_t out_encoded_public_key[XWING_PUBLIC_KEY_BYTES],
    uint8_t out_encoded_private_key[XWING_PRIVATE_KEY_BYTES]) {
  RAND_bytes(out_encoded_private_key, XWING_PRIVATE_KEY_BYTES);
  return XWING_public_from_private(out_encoded_public_key,
                                   out_encoded_private_key);
}

int XWING_public_from_private(
    uint8_t out_encoded_public_key[XWING_PUBLIC_KEY_BYTES],
    const uint8_t encoded_private_key[XWING_PRIVATE_KEY_BYTES]) {
  uint8_t expanded_seed[96];
  BORINGSSL_keccak(expanded_seed, sizeof(expanded_seed), encoded_private_key,
                   XWING_PRIVATE_KEY_BYTES, boringssl_shake256);

  CBB cbb;
  if (!CBB_init_fixed(&cbb, out_encoded_public_key, XWING_PUBLIC_KEY_BYTES)) {
    return 0;
  }

  // ML-KEM-768
  MLKEM768_private_key mlkem_private_key;
  MLKEM768_private_key_from_seed(&mlkem_private_key, expanded_seed, 64);
  MLKEM768_public_key mlkem_public_key;
  MLKEM768_public_from_private(&mlkem_public_key, &mlkem_private_key);

  if (!MLKEM768_marshal_public_key(&cbb, &mlkem_public_key)) {
    return 0;
  }

  // X25519
  uint8_t *buf;
  if (!CBB_add_space(&cbb, &buf, 32)) {
    return 0;
  }
  X25519_public_from_private(buf, expanded_seed + 64);

  if (CBB_len(&cbb) != XWING_PUBLIC_KEY_BYTES) {
    return 0;
  }
  return 1;
}

static void xwing_combiner(
    uint8_t out_shared_secret[XWING_SHARED_SECRET_BYTES],
    const uint8_t mlkem_shared_secret[MLKEM_SHARED_SECRET_BYTES],
    const uint8_t x25519_shared_secret[32], const uint8_t x25519_ciphertext[32],
    const uint8_t x25519_public_key[32]) {
  struct BORINGSSL_keccak_st context;
  BORINGSSL_keccak_init(&context, boringssl_sha3_256);

  BORINGSSL_keccak_absorb(&context, mlkem_shared_secret,
                          MLKEM_SHARED_SECRET_BYTES);
  BORINGSSL_keccak_absorb(&context, x25519_shared_secret, 32);
  BORINGSSL_keccak_absorb(&context, x25519_ciphertext, 32);
  BORINGSSL_keccak_absorb(&context, x25519_public_key, 32);

  uint8_t xwing_label[6] = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};
  BORINGSSL_keccak_absorb(&context, xwing_label, sizeof(xwing_label));

  BORINGSSL_keccak_squeeze(&context, out_shared_secret,
                           XWING_SHARED_SECRET_BYTES);
}

int XWING_encap(uint8_t out_ciphertext[XWING_CIPHERTEXT_BYTES],
                uint8_t out_shared_secret[XWING_SHARED_SECRET_BYTES],
                const uint8_t encoded_public_key[XWING_PUBLIC_KEY_BYTES]) {
  uint8_t eseed[64];
  RAND_bytes(eseed, sizeof(eseed));

  return XWING_encap_external_entropy(out_ciphertext, out_shared_secret,
                                      encoded_public_key, eseed);
}

int XWING_encap_external_entropy(
    uint8_t out_ciphertext[XWING_CIPHERTEXT_BYTES],
    uint8_t out_shared_secret[XWING_SHARED_SECRET_BYTES],
    const uint8_t encoded_public_key[XWING_PUBLIC_KEY_BYTES],
    const uint8_t eseed[64]) {
  // X25519
  const uint8_t *x25519_public_key =
      encoded_public_key + MLKEM768_PUBLIC_KEY_BYTES;
  const uint8_t *x25519_ephemeral_private_key = eseed + 32;
  uint8_t *x25519_ciphertext = out_ciphertext + MLKEM768_CIPHERTEXT_BYTES;
  X25519_public_from_private(x25519_ciphertext, x25519_ephemeral_private_key);

  uint8_t x25519_shared_secret[32];
  if (!X25519(x25519_shared_secret, x25519_ephemeral_private_key,
              x25519_public_key)) {
    return 0;
  }

  // ML-KEM-768
  const uint8_t *mlkem_encoded_public_key = encoded_public_key;
  CBS cbs;
  CBS_init(&cbs, mlkem_encoded_public_key, XWING_PUBLIC_KEY_BYTES);

  CBS mlkem_cbs;
  if (!CBS_get_bytes(&cbs, &mlkem_cbs, MLKEM768_PUBLIC_KEY_BYTES)) {
    return 0;
  }

  BCM_mlkem768_public_key mlkem_public_key;
  if (!bcm_success(
          BCM_mlkem768_parse_public_key(&mlkem_public_key, &mlkem_cbs))) {
    return 0;
  }

  uint8_t *mlkem_ciphertext = out_ciphertext;
  uint8_t mlkem_shared_secret[MLKEM_SHARED_SECRET_BYTES];
  BCM_mlkem768_encap_external_entropy(mlkem_ciphertext, mlkem_shared_secret,
                                      &mlkem_public_key, eseed);

  // Combine the shared secrets
  xwing_combiner(out_shared_secret, mlkem_shared_secret, x25519_shared_secret,
                 x25519_ciphertext, x25519_public_key);
  return 1;
}

int XWING_decap(uint8_t out_shared_secret[XWING_SHARED_SECRET_BYTES],
                const uint8_t ciphertext[XWING_CIPHERTEXT_BYTES],
                const uint8_t encoded_private_key[XWING_PRIVATE_KEY_BYTES]) {
  uint8_t expanded_seed[96];
  BORINGSSL_keccak(expanded_seed, sizeof(expanded_seed), encoded_private_key,
                   XWING_PRIVATE_KEY_BYTES, boringssl_shake256);

  // Define these upfront so that they don't cross a goto.
  const uint8_t *x25519_ciphertext = ciphertext + MLKEM768_CIPHERTEXT_BYTES;
  const uint8_t *x25519_private_key = expanded_seed + 64;

  // ML-KEM-768
  MLKEM768_private_key mlkem_private_key;
  MLKEM768_private_key_from_seed(&mlkem_private_key, expanded_seed, 64);

  const uint8_t *mlkem_ciphertext = ciphertext;
  uint8_t mlkem_shared_secret[MLKEM_SHARED_SECRET_BYTES];
  if (!MLKEM768_decap(mlkem_shared_secret, mlkem_ciphertext,
                      MLKEM768_CIPHERTEXT_BYTES, &mlkem_private_key)) {
    goto error;
  }

  // X25519
  uint8_t x25519_public_key[32];
  X25519_public_from_private(x25519_public_key, x25519_private_key);

  uint8_t x25519_shared_secret[32];
  if (!X25519(x25519_shared_secret, x25519_private_key, x25519_ciphertext)) {
    goto error;
  }

  // Combine the shared secrets
  xwing_combiner(out_shared_secret, mlkem_shared_secret, x25519_shared_secret,
                 x25519_ciphertext, x25519_public_key);
  return 1;

error:
  // In case of error, fill the shared secret with random bytes so that if the
  // caller forgets to check the return code:
  // - no intermediate information leaks,
  // - the shared secret is unpredictable, so for example any data encrypted
  //   with it wouldn't be trivially decryptable by an attacker.
  RAND_bytes(out_shared_secret, XWING_SHARED_SECRET_BYTES);
  return 0;
}
