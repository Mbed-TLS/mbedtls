/**
 * \file aria.h
 *
 * \brief ARIA block cipher
 *
 *  Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_ARIA_H
#define MBEDTLS_ARIA_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ARIA_ENCRYPT     1
#define MBEDTLS_ARIA_DECRYPT     0

#define MBEDTLS_ERR_ARIA_INVALID_KEY_LENGTH   -0x005C  /**< Invalid key length. */
#define MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH -0x005E  /**< Invalid data input length. */

#if !defined(MBEDTLS_ARIA_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          ARIA context structure
 */

typedef struct
{
    int nr;                         // rounds: nr = 12, 14, or 16
    uint32_t rk[17][4];             // nr+1 round keys (+1 for final)
}
mbedtls_aria_context;

/**
 * \brief          Initialize ARIA context
 *
 * \param ctx      ARIA context to be initialized
 */
void mbedtls_aria_init( mbedtls_aria_context *ctx );

/**
 * \brief          Clear ARIA context
 *
 * \param ctx      ARIA context to be cleared
 */
void mbedtls_aria_free( mbedtls_aria_context *ctx );

/**
 * \brief          ARIA key schedule (encryption)
 *
 * \param ctx      ARIA context to be initialized
 * \param key      encryption key
 * \param keybits  must be 128, 192 or 256
 *
 * \return         0 if successful, or MBEDTLS_ERR_ARIA_INVALID_KEY_LENGTH
 */
int mbedtls_aria_setkey_enc( mbedtls_aria_context *ctx,
                             const unsigned char *key,
                             unsigned int keybits );

/**
 * \brief          ARIA key schedule (decryption)
 *
 * \param ctx      ARIA context to be initialized
 * \param key      decryption key
 * \param keybits  must be 128, 192 or 256
 *
 * \return         0 if successful, or MBEDTLS_ERR_ARIA_INVALID_KEY_LENGTH
 */
int mbedtls_aria_setkey_dec( mbedtls_aria_context *ctx,
                             const unsigned char *key,
                             unsigned int keybits );

/**
 * \brief          ARIA-ECB block encryption/decryption
 *
 * \param ctx      ARIA context
 * \param mode     MBEDTLS_ARIA_ENCRYPT or MBEDTLS_ARIA_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 if successful
 */
int mbedtls_aria_crypt_ecb( mbedtls_aria_context *ctx,
                            int mode,
                            const unsigned char input[16],
                            unsigned char output[16] );

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/**
 * \brief          ARIA-CBC buffer encryption/decryption
 *                 Length should be a multiple of the block
 *                 size (16 bytes)
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      ARIA context
 * \param mode     MBEDTLS_ARIA_ENCRYPT or MBEDTLS_ARIA_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or
 *                 MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH
 */
int mbedtls_aria_crypt_cbc( mbedtls_aria_context *ctx,
                            int mode,
                            size_t length,
                            unsigned char iv[16],
                            const unsigned char *input,
                            unsigned char *output );
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/**
 * \brief          ARIA-CFB128 buffer encryption/decryption
 *
 * Note: Due to the nature of CFB you should use the same key schedule for
 * both encryption and decryption. So a context initialized with
 * mbedtls_aria_setkey_enc() for both MBEDTLS_ARIA_ENCRYPT and CAMELLIE_DECRYPT.
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      ARIA context
 * \param mode     MBEDTLS_ARIA_ENCRYPT or MBEDTLS_ARIA_DECRYPT
 * \param length   length of the input data
 * \param iv_off   offset in IV (updated after use)
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or
 *                 MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH
 */
int mbedtls_aria_crypt_cfb128( mbedtls_aria_context *ctx,
                               int mode,
                               size_t length,
                               size_t *iv_off,
                               unsigned char iv[16],
                               const unsigned char *input,
                               unsigned char *output );
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/**
 * \brief               ARIA-CTR buffer encryption/decryption
 *
 * Warning: You have to keep the maximum use of your counter in mind!
 *
 * Note: Due to the nature of CTR you should use the same key schedule for
 * both encryption and decryption. So a context initialized with
 * mbedtls_aria_setkey_enc() for both MBEDTLS_ARIA_ENCRYPT and MBEDTLS_ARIA_DECRYPT.
 *
 * \param ctx           ARIA context
 * \param length        The length of the data
 * \param nc_off        The offset in the current stream_block (for resuming
 *                      within current cipher stream). The offset pointer to
 *                      should be 0 at the start of a stream.
 * \param nonce_counter The 128-bit nonce and counter.
 * \param stream_block  The saved stream-block for resuming. Is overwritten
 *                      by the function.
 * \param input         The input data stream
 * \param output        The output data stream
 *
 * \return         0 if successful
 */
int mbedtls_aria_crypt_ctr( mbedtls_aria_context *ctx,
                            size_t length,
                            size_t *nc_off,
                            unsigned char nonce_counter[16],
                            unsigned char stream_block[16],
                            const unsigned char *input,
                            unsigned char *output );
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_ARIA_ALT */
#include "aria_alt.h"
#endif /* MBEDTLS_ARIA_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_aria_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* aria.h */
