/*
 *  Copyright 2024 The BoringSSL Authors
 *  Copyright 2025 Google LLC
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_MLDSA87_H
#define MBEDTLS_MLDSA87_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MLDSA87_PRIVATE_SEED_BYTES 32
#define MLDSA87_RANDOMIZER_BYTES 32
#define MLDSA87_PUBLIC_KEY_BYTES 2592
#define MLDSA87_SIGNATURE_BYTES 4627

void mldsa87_pub_from_seed(
  uint8_t out_encoded_public_key[MLDSA87_PUBLIC_KEY_BYTES],
  const uint8_t private_key_seed[MLDSA87_PRIVATE_SEED_BYTES]);

void mldsa87_sign(
  uint8_t out_encoded_signature[MLDSA87_SIGNATURE_BYTES],
  const uint8_t private_key_seed[MLDSA87_PRIVATE_SEED_BYTES],
  const uint8_t randomizer[MLDSA87_RANDOMIZER_BYTES],
  const uint8_t *msg, size_t msg_len);

void mldsa87_sign_deterministic(
  uint8_t out_encoded_signature[MLDSA87_SIGNATURE_BYTES],
  const uint8_t private_key_seed[MLDSA87_PRIVATE_SEED_BYTES],
  const uint8_t *msg, size_t msg_len);

int mldsa87_verify(const uint8_t encoded_public_key[MLDSA87_PUBLIC_KEY_BYTES],
  const uint8_t encoded_signature[MLDSA87_SIGNATURE_BYTES], const uint8_t *msg,
  size_t msg_len);

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_mldsa87.h */
