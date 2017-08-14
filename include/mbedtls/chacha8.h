/**
 * \file chacha8.h
 *
 * \brief The ChaCha8 stream cipher
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
#ifndef MBEDTLS_CHACHA8_H
#define MBEDTLS_CHACHA8_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>


#if !defined(MBEDTLS_CHACHA8_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          CHACHA8 context structure
 */
typedef struct
{
    // Needs to be ChaCha8-specific
    uint32_t input[16];
    uint32_t internal_state[16];
    uint32_t unused_keystream_number_bytes;
    unsigned char current_keystream_buffer[64];
    uint32_t keystream_buffer_offset;
}
mbedtls_chacha8_context;

/**
 * \brief          Initialize CHACHA8 context
 *
 * \param ctx      CHACHA8 context to be initialized
 */
void mbedtls_chacha8_init( mbedtls_chacha8_context *ctx );

/**
 * \brief          Clear CHACHA8 context
 *
 * \param ctx      CHACHA8 context to be cleared
 */
void mbedtls_chacha8_free( mbedtls_chacha8_context *ctx );

/**
 * \brief          Reset CHACHA8 context keystream internal state
 *
 * \param ctx      CHACHA8 context to have keystream reset
 */
void mbedtls_chacha8_reset_keystream_state( mbedtls_chacha8_context *ctx );

/**
 * \brief          ChaCha8 iv setup - to ensure randomness for each operation
 * @param ctx      CHACHA8 context to be setup
 * @param iv       initialization vector
 */
void mbedtls_chacha8_set_iv( mbedtls_chacha8_context *ctx, const unsigned char *iv );

/**
 * \brief          ChaCha8 key schedule
 *
 * \param ctx      CHACHA8 context to be setup
 * \param key      the secret key
 * \param keylen   length of the key, in bytes
 */
void mbedtls_chacha8_setup( mbedtls_chacha8_context *ctx, const unsigned char *key,
                            unsigned int keylen );

/**
 * \brief          CHACHA8 cipher function
 *
 * \param ctx      CHACHA8 context
 * \param length   length of the input data
 * \param input    buffer holding the input data
 * \param output   buffer for the output data
 *
 * \return         0 if successful
 */
int mbedtls_chacha8_crypt( mbedtls_chacha8_context *ctx, size_t length, const unsigned char *input,
                           unsigned char *output );

/**
 * \brief          CHACHA8 generate internal keystream block function
 *
 * \param ctx      CHACHA8 context
 *
 * \return         0 if successful
 */
void mbedtls_chacha8_generate_keystream_block( mbedtls_chacha8_context *ctx );

/**
 * \brief          CHACHA8 cipher function
 *
 * \param ctx      CHACHA8 context
 * \param length   length of the input data
 * \param input    buffer holding the input data
 * \param output   buffer for the output data
 *
 * \return         0 if successful
 */
int mbedtls_chacha8_get_keystream_slice( mbedtls_chacha8_context *ctx, unsigned char *keystream_segment, const uint32_t number_of_bytes_this_run);

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_CHACHA8_ALT */
#include "chacha8_alt.h"
#endif /* MBEDTLS_CHACHA8_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_chacha8_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* chacha8.h */
