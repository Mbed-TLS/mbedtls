/**
 * \file chacha20.h
 *
 * \brief ChaCha20 cipher.
 *
 * \author Daniel King <damaki.gh@gmail.com>
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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
#ifndef MBEDTLS_CHACHA20_H
#define MBEDTLS_CHACHA20_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdint.h>
#include <stddef.h>

#define MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA -0x003B /**< Invalid input parameter(s). */

#if !defined(MBEDTLS_CHACHA20_ALT)

typedef struct
{
    uint32_t initial_state[16];  /*! Holds the initial state (before round operations) */
    uint32_t working_state[16];  /*! Holds the working state (after round operations) */
    uint8_t  keystream8[64];     /*! Holds leftover keystream bytes */
    size_t keystream_bytes_used; /*! Number of keystream bytes currently used */
}
mbedtls_chacha20_context;

#else  /* MBEDTLS_CHACHA20_ALT */
#include "chacha20_alt.h"
#endif /* MBEDTLS_CHACHA20_ALT */

/**
 * \brief           Initialize ChaCha20 context
 *
 * \param ctx       ChaCha20 context to be initialized
 */
void mbedtls_chacha20_init( mbedtls_chacha20_context *ctx );

/**
 * \brief           Clear ChaCha20 context
 *
 * \param ctx       ChaCha20 context to be cleared
 */
void mbedtls_chacha20_free( mbedtls_chacha20_context *ctx );

/**
 * \brief           Set the ChaCha20 key.
 *
 * \note            The nonce and counter must be set after calling this function,
 *                  before data can be encrypted/decrypted. The nonce and
 *                  counter are set by calling mbedtls_chacha20_starts.
 *
 * \see             mbedtls_chacha20_starts
 *
 * \param ctx       The context to setup.
 * \param key       Buffer containing the 256-bit key. Must be 32 bytes in length.
 *
 * \return          MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA is returned if ctx or key
 *                  is NULL, or if key_bits is not 128 or 256.
 *                  Otherwise, 0 is returned to indicate success.
 */
int mbedtls_chacha20_setkey( mbedtls_chacha20_context *ctx,
                             const unsigned char key[32] );

/**
 * \brief           Set the ChaCha20 nonce and initial counter value.
 *
 * \note            A ChaCha20 context can be re-used with the same key by
 *                  calling this function to change the nonce and/or initial
 *                  counter value.
 *
 * \param ctx       The ChaCha20 context.
 * \param nonce     Buffer containing the 96-bit nonce. Must be 12 bytes in size.
 * \param counter   Initial counter value to use. This is usually 0.
 *
 * \return          MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA is returned if ctx or
 *                  nonce is NULL.
 *                  Otherwise, 0 is returned to indicate success.
 */
int mbedtls_chacha20_starts( mbedtls_chacha20_context* ctx,
                             const unsigned char nonce[12],
                             uint32_t counter );

/**
 * \brief           Generates a block of keystream bytes for a specific counter value.
 *
 *                  This function uses the key and nonce previously set in
 *                  the context (via mbedtls_chacha20_setkey and
 *                  mbedtls_chacha20_starts), but ignores the previously
 *                  set counter and uses the counter given as the parameter to
 *                  this function.
 *
 * \param ctx       The ChaCha20 context. This context is not modified.
 * \param counter   The counter value to use.
 * \param keystream Buffer to where the generated keystream bytes are written.
 *
 * \return          MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA if ctx or keystream are
 *                  NULL.
 *                  Otherwise, 0 is returned to indicate success.
 */
int mbedtls_chacha20_keystream_block( const mbedtls_chacha20_context *ctx,
                                      uint32_t counter,
                                      unsigned char keystream[64] );

/**
 * \brief           Encrypt or decrypt data.
 *
 *                  This function is used to both encrypt and decrypt data.
 *
 * \note            The \p input and \p output buffers may overlap, but only
 *                  if input >= output (i.e. only if input points ahead of
 *                  the output pointer).
 *
 * \note            mbedtls_chacha20_setkey and mbedtls_chacha20_starts must be
 *                  called at least once to setup the context before this function
 *                  can be called.
 *
 * \param ctx       The ChaCha20 context.
 * \param size      The length (in bytes) to process. This can have any length.
 * \param input     Buffer containing the input data.
 *                  This pointer can be NULL if size == 0.
 * \param output    Buffer containing the output data.
 *                  This pointer can be NULL if size == 0.
 *
 * \return          MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA if the ctx, input, or
 *                  output pointers are NULL.
 *                  Otherwise, 0 is returned to indicate success.
 */
int mbedtls_chacha20_update( mbedtls_chacha20_context *ctx,
                              size_t size,
                              const unsigned char *input,
                              unsigned char *output );

/**
 * \brief           Encrypt or decrypt a message using ChaCha20.
 *
 *                  This function is used the same way for encrypting and
 *                  decrypting data. It's not necessary to specify which
 *                  operation is being performed.
 *
 * \note            The \p input and \p output buffers may overlap, but only
 *                  if input >= output (i.e. only if input points ahead of
 *                  the output pointer).
 *
 * \param key       Buffer containing the 256-bit key. Must be 32 bytes in length.
 * \param nonce     Buffer containing the 96-bit nonce. Must be 12 bytes in length.
 * \param counter   The initial counter value. This is usually 0.
 * \param data_len  The number of bytes to process.
 * \param input     Buffer containing the input data (data to encrypt or decrypt).
 * \param output    Buffer to where the processed data is written.
 *
 * \return          MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA if key, nonce, input,
 *                  or output is NULL.
 *                  Otherwise, 0 is returned to indicate success.
 */
int mbedtls_chacha20_crypt( const unsigned char key[32],
                            const unsigned char nonce[12],
                            uint32_t counter,
                            size_t data_len,
                            const unsigned char* input,
                            unsigned char* output );

/**
 * \brief           Checkup routine
 *
 * \return          0 if successful, or 1 if the test failed
 */
int mbedtls_chacha20_self_test( int verbose );

#endif /* MBEDTLS_CHACHA20_H */
