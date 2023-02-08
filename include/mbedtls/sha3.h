/**
 * \file sha3.h
 *
 * \brief This file contains SHA3 definitions and functions.
 *
 * The Secure Hash Algorithms cryptographic
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

#ifndef MBEDTLS_SHA3_H
#define MBEDTLS_SHA3_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** SHA3 input data was malformed. */
#define MBEDTLS_ERR_SHA3_BAD_INPUT_DATA                 -0x0076

/**
 * SHA-3 family id.
 *
 * It identifies the family (SHA3-256, SHA3-512, etc.)
 */

typedef enum {
    MBEDTLS_SHA3_NONE = 0, /*!< Operation not defined. */
    MBEDTLS_SHA3_224, /*!< SHA3-224 */
    MBEDTLS_SHA3_256, /*!< SHA3-256 */
    MBEDTLS_SHA3_384, /*!< SHA3-384 */
    MBEDTLS_SHA3_512, /*!< SHA3-512 */
    MBEDTLS_SHA3_SHAKE128, /*!< SHA3-SHAKE128 */
    MBEDTLS_SHA3_SHAKE256, /*!< SHA3-SHAKE256 */
    MBEDTLS_SHA3_CSHAKE128, /*!< SHA3-CSHAKE128 */
    MBEDTLS_SHA3_CSHAKE256, /*!< SHA3-CSHAKE256 */
} mbedtls_sha3_id;

struct mbedtls_sha3_context;
typedef struct mbedtls_sha3_family_functions {
    mbedtls_sha3_id id;

    uint16_t r;
    uint16_t olen;
    uint8_t xor_byte;
}
mbedtls_sha3_family_functions;

/**
 * \brief          The SHA-3 context structure.
 *
 *                 The structure is used SHA-3 checksum calculations.
 */
typedef struct mbedtls_sha3_context {
    uint64_t state[25];
    uint8_t index;
    uint8_t id;

    uint16_t r;
    uint16_t olen;
    uint8_t xor_byte;
    uint16_t max_block_size;
    uint8_t finished;
}
mbedtls_sha3_context;

/**
 * \brief          This function initializes a SHA-3 context.
 *
 * \param ctx      The SHA-3 context to initialize. This must not be \c NULL.
 */
void mbedtls_sha3_init(mbedtls_sha3_context *ctx);

/**
 * \brief          This function clears a SHA-3 context.
 *
 * \param ctx      The SHA-3 context to clear. This may be \c NULL, in which
 *                 case this function returns immediately. If it is not \c NULL,
 *                 it must point to an initialized SHA-3 context.
 */
void mbedtls_sha3_free(mbedtls_sha3_context *ctx);

/**
 * \brief          This function clones the state of a SHA-3 context.
 *
 * \param dst      The destination context. This must be initialized.
 * \param src      The context to clone. This must be initialized.
 */
void mbedtls_sha3_clone(mbedtls_sha3_context *dst,
                        const mbedtls_sha3_context *src);

/**
 * \brief          This function starts a SHA-3 checksum
 *                 calculation.
 *
 * \param ctx      The context to use. This must be initialized.
 * \param id       The id of the SHA-3 family.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha3_starts(mbedtls_sha3_context *ctx, mbedtls_sha3_id id);

/**
 * \brief          This function starts a SHA-3 checksum
 *                 calculation with function-name and customization strings.
 *
 * \param ctx      The context to use. This must be initialized.
 * \param id       The id of the SHA-3 family. It can be \c MBEDTLS_SHA3_CSHAKE128 or
 *                 \c MBEDTLS_SHA3_CSHAKE256.
 * \param name     The function-name string.
 * \param name_len The length of \c name in bytes (not counting any terminating \c NUL character).
 * \param custom   The customization string.
 * \param custom_len The length of \c custom in bytes (not counting any terminating \c NUL character).
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 * \note           If no name and no custom strings are provided (are \c NULL),
 *                 it is equivalent to mbedtls_sha3_starts().
 */
int mbedtls_sha3_starts_cshake(mbedtls_sha3_context *ctx,
                               mbedtls_sha3_id id,
                               const char *name, size_t name_len,
                               const char *custom, size_t custom_len);

/**
 * \brief          This function starts a SHA-3 checksum calculation for KMAC
 *                 with key and customization strings.
 *
 * \param ctx      The context to use. This must be initialized.
 * \param id       The id of the SHA-3 family. It must be \c MBEDTLS_SHA3_CSHAKE128 or
 *                 \c MBEDTLS_SHA3_CSHAKE256.
 * \param key      The key buffer.
 * \param key_len  The length of \c key in bytes.
 * \param custom   The customization string.
 * \param custom_len The length of \c custom in bytes (not counting any terminating \c NUL character).
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 * \note           If no name and no custom strings are provided (are \c NULL),
 *                 it is equivalent to mbedtls_sha3_starts().
 */
int mbedtls_sha3_starts_kmac( mbedtls_sha3_context *ctx,
                            mbedtls_sha3_id id,
                            const uint8_t *key, size_t key_len,
                            const char *custom, size_t custom_len );

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 SHA-3 checksum calculation.
 *
 * \param ctx      The SHA-3 context. This must be initialized
 *                 and have a hash operation started.
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen bytes.
 * \param ilen     The length of the input data in bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha3_update(mbedtls_sha3_context *ctx,
                        const uint8_t *input,
                        size_t ilen);

/**
 * \brief          This function finishes the SHA-3 operation, and writes
 *                 the result to the output buffer.
 *
 * \param ctx      The SHA-3 context. This must be initialized
 *                 and have a hash operation started.
 * \param output   The SHA-3 checksum result.
 *                 This must be a writable buffer of length \c olen bytes.
 * \param olen     Defines the length of output buffer (in bytes). For SHA-3 224, SHA-3 256,
 *                 SHA-3 384 and SHA-3 512 \c olen must be at least 28, 32, 48 or 64 bytes,
 *                 respectively. For SHAKE128, SHAKE256, CSHAKE128 and CSHAKE256 the buffer
 *                 will be filled up to \c olen bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha3_finish(mbedtls_sha3_context *ctx,
                        uint8_t *output, size_t olen);

/**
 * \brief          This function finishes the SHA-3 KMAC operation, and writes
 *                 the result to the output buffer.
 *
 * \param ctx      The SHA-3 context. This must be initialized
 *                 and have a hash operation started.
 * \param output   The SHA-3 checksum result.
 *                 This must be a writable buffer of length \c olen bytes.
 * \param olen     Defines the length of output buffer (in bytes). For CSHAKE128 and CSHAKE256
 *                 the buffer will be filled up to \c olen bytes.
 * \param xof      \c 1 performs KMAC XOF operation or \c 0 does not perform XOF.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha3_finish_kmac( mbedtls_sha3_context *ctx,
                           uint8_t *output, size_t olen, int xof );

/**
 * \brief          This function calculates the SHA-3
 *                 checksum of a buffer.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-3 result is calculated as
 *                 output = SHA-3(id, input buffer, d).
 *
 * \param id       The id of the SHA-3 family.
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen bytes.
 * \param ilen     The length of the input data in bytes.
 * \param output   The SHA-3 checksum result.
 *                 This must be a writable buffer of length \c olen bytes.
 * \param olen     Defines the length of output buffer (in bytes). For SHA-3 224, SHA-3 256,
 *                 SHA-3 384 and SHA-3 512 \c olen must be at least 28, 32, 48 or 64 bytes,
 *                 respectively. For SHAKE128 and SHAKE256, the buffer will be filled up to
 *                 \c olen bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_sha3(mbedtls_sha3_id id, const uint8_t *input,
                 size_t ilen,
                 uint8_t *output,
                 size_t olen);

/**
 * \brief          This function calculates the SHA-3
 *                 checksum of a buffer with function-name and customization
 *                 strings.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-3 result is calculated as
 *                 output = SHA-3(id, name || customization || input buffer, d).
 *
 * \param id       The id of the SHA-3 family. It can be \c MBEDTLS_SHA3_CSHAKE128 or
 *                 \c MBEDTLS_SHA3_CSHAKE256.
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen bytes.
 * \param ilen     The length of the input data in bytes.
 * \param name     The function-name string.
 * \param name_len The length of \c name in bytes (not counting any terminating \c NUL character).
 * \param custom   The customization string.
 * \param custom_len The length of \c custom in bytes (not counting any terminating \c NUL character).
 * \param output   The SHA-3 checksum result.
 *                 This must be a writable buffer of length \c olen bytes.
 * \param olen     Defines the length of output buffer (in bytes). For CSHAKE128 and
 *                 CSHAKE256 the buffer will be filled up to \c olen bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 * \note           If no name and no custom strings are provided (are \c NULL),
 *                 it is equivalent to mbedtls_sha3().
 */
int mbedtls_sha3_cshake(mbedtls_sha3_id id, const uint8_t *input,
                        size_t ilen, const char *name, size_t name_len,
                        const char *custom, size_t custom_len,
                        uint8_t *output, size_t olen);

/**
 * \brief          This function calculates the SHA-3 KMAC
 *                 checksum of a buffer with a key and customization
 *                 strings.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-3 result is calculated as
 *                 output = SHA-3(id, key || customization || input buffer, d).
 *
 * \param id       The id of the SHA-3 family. It must be \c MBEDTLS_SHA3_CSHAKE128 or
 *                 \c MBEDTLS_SHA3_CSHAKE256.
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen bytes.
 * \param ilen     The length of the input data in bytes.
 * \param key      The key buffer.
 * \param key_len  The length of \c key in bytes.
 * \param custom   The customization string. It must be zero-terminated.
 * \param custom_len The length of \c custom in Bytes.
 * \param output   The SHA-3 checksum result.
 *                 This must be a writable buffer of length \c olen bytes.
 * \param olen     Defines the length of output buffer (in bytes). For CSHAKE128 and
 *                 CSHAKE256 the buffer will be filled up to \c olen bytes.
 * \param xof      Performs KMAC XOF operation.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 * \note           If no name and no custom strings are provided (are \c NULL),
 *                 it is equivalent to mbedtls_sha3().
 */
int mbedtls_sha3_kmac( mbedtls_sha3_id id, const uint8_t *input,
                    size_t ilen, const uint8_t *key, size_t key_len,
                    const char *custom, size_t custom_len,
                    uint8_t *output, size_t olen, int xof );

#if defined(MBEDTLS_SELF_TEST)
/**
 * \brief          Checkup routine for the algorithms implemented
 *                 by this module: SHA3-224, SHA3-256, SHA3-384, SHA3-512,
 *                 SHAKE128, SHAKE256, cSHAKE128 and cSHAKE256.
 *
 * \return         0 if successful, or 1 if the test failed.
 */
int mbedtls_sha3_self_test(int verbose);
#endif /* MBEDTLS_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_sha3.h */
