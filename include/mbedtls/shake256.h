/**
 * \file shake256.h
 *
 * \brief This file contains SHAKE256 definitions and functions.
 *
 * The Secure Hash Algorithms Keccak (SHAKE256) cryptographic
 * hash functions are defined in <em>FIPS 202: SHA-3 Standard: 
 * Permutation-Based Hash and Extendable-Output Functions </em>.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
 
#ifndef MBEDTLS_SHAKE256_H
#define MBEDTLS_SHAKE256_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** SHAKE256 input data was malformed. */
#define MBEDTLS_ERR_SHAKE256_BAD_INPUT_DATA                 -0x0074

#if !defined(MBEDTLS_SHAKE256_ALT)
// Regular implementation
//

/**
 * \brief          The SHAKE256 context structure.
 *
 *                 The structure is used SHAKE256 checksum calculations.
 */
typedef struct mbedtls_shake256_context {
  uint64_t state[25];
  uint8_t index;
}
mbedtls_shake256_context;

#else  /* MBEDTLS_SHAKE256_ALT */
#include "shake256_alt.h"
#endif /* MBEDTLS_SHAKE256_ALT */

/**
 * \brief          This function initializes a SHAKE256 context.
 *
 * \param ctx      The SHAKE256 context to initialize. This must not be \c NULL.
 */
void mbedtls_shake256_init( mbedtls_shake256_context *ctx );

/**
 * \brief          This function clears a SHAKE256 context.
 *
 * \param ctx      The SHAKE256 context to clear. This may be \c NULL, in which
 *                 case this function returns immediately. If it is not \c NULL,
 *                 it must point to an initialized SHAKE256 context.
 */
void mbedtls_shake256_free( mbedtls_shake256_context *ctx );

/**
 * \brief          This function clones the state of a SHAKE256 context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The context to clone. This must be initialized.
 */
void mbedtls_shake256_clone( mbedtls_shake256_context *dst,
                           const mbedtls_shake256_context *src );

/**
 * \brief          This function starts a SHAKE256 checksum
 *                 calculation.
 *
 * \param ctx      The context to use. This must be initialized.
 * \param is224    This determines which function to use. 
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_shake256_starts( mbedtls_shake256_context *ctx );

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 SHAKE256 checksum calculation.
 *
 * \param ctx      The SHAKE256 context. This must be initialized
 *                 and have a hash operation started.
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_shake256_update( mbedtls_shake256_context *ctx,
                           const unsigned char *input,
                           size_t ilen );

/**
 * \brief          This function finishes the SHAKE256 operation, and writes
 *                 the result to the output buffer.
 *
 * \param ctx      The SHAKE256 context. This must be initialized
 *                 and have a hash operation started.
 * \param output   The SHAKE256 checksum result.
 *                 This must be a writable buffer of length \c olen bytes.
 * \param olen     Defines a variable output length (in bytes). \c output must be
 *                 \c olen bytes length.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_shake256_finish( mbedtls_shake256_context *ctx,
                           unsigned char *output, size_t olen );

/**
 * \brief          This function calculates the SHAKE256
 *                 checksum of a buffer.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHAKE256 result is calculated as
 *                 output = SHAKE256(input buffer, d).
 *
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 * \param output   The SHAKE256 checksum result.
 *                 This must be a writable buffer of length \c olen bytes.
 * \param olen     Determines the length (in bytes) of the output. \c output
 *                 must be \c olen bytes length.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_shake256( const unsigned char *input,
                    size_t ilen,
                    unsigned char *output,
                    size_t olen );

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_shake256.h */
