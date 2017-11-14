/**
 * \file salsa20.h
 *
 * \brief The Salsa20 stream cipher
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
#ifndef MBEDTLS_SALSA20_H
#define MBEDTLS_SALSA20_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_SALSA20_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SALSA20 context structure
 */
typedef struct
{
    uint32_t internal_state[16];
    uint32_t unused_keystream_number_bytes;
    unsigned char current_keystream_buffer[64];
    uint32_t keystream_buffer_offset;
}
mbedtls_salsa20_context;

/**
 *  \brief         SALSA20 rotation data structure
 */
typedef struct
{
    uint8_t result_index;
    uint8_t sum_index_a;
    uint8_t sum_index_b;
    uint8_t rotation;
}
mbedtls_salsa20_rotation_data;

/**
 * \brief          Initialize SALSA20 context
 *
 * \param ctx      SALSA20 context to be initialized
 */
void mbedtls_salsa20_init( mbedtls_salsa20_context *ctx );

/**
 * \brief          Clear SALSA20 context
 *
 * \param ctx      SALSA20 context to be cleared
 */
void mbedtls_salsa20_free( mbedtls_salsa20_context *ctx );

/**
 * \brief          Reset SALSA20 context keystream internal state
 *
 * \param ctx      SALSA20 context to has keystream reset
 */
void mbedtls_salsa20_reset_keystream_state( mbedtls_salsa20_context *ctx );

/**
 * \brief               SALSA20 key schedule
 *
 * \param ctx           SALSA20 context to be setup
 * \param key           the secret key
 * \param keylen_bits   length of the key
 */
void mbedtls_salsa20_setup( mbedtls_salsa20_context *ctx, const unsigned char *key,
                 const uint32_t keylen_bits );

/**
 * \brief          SALSA20 set IV
 *
 * \param ctx      SALSA20 context to be setup
 * \param iv       SALSA20 iv to be setup
 */
void mbedtls_salsa20_set_iv( mbedtls_salsa20_context *ctx, const unsigned char *iv );

/**
 * \brief          SALSA20 cipher function
 *
 * \param ctx      SALSA20 context
 * \param length   length of the input data
 * \param input    buffer holding the input data
 * \param output   buffer for the output data
 *
 * \return         0 if successful
 */
int mbedtls_salsa20_crypt( mbedtls_salsa20_context *ctx, size_t length, const unsigned char *input,
                unsigned char *output );

void mbedtls_salsa20_generate_keystream_block( mbedtls_salsa20_context *ctx );

int mbedtls_salsa20_get_keystream_slice( mbedtls_salsa20_context *ctx, unsigned char *keystream_segment, const uint32_t number_of_bytes_this_run);
#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_SALSA20_ALT */
#include "salsa20_alt.h"
#endif /* MBEDTLS_SALSA20_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_salsa20_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* salsa20.h */
