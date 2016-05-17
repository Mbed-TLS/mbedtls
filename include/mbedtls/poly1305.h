/**
 * \file poly1305.h
 *
 * \brief Poly1305 authenticator algorithm.
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
#ifndef MBEDTLS_POLY1305_H
#define MBEDTLS_POLY1305_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdint.h>
#include <stddef.h>

#if !defined(MBEDTLS_POLY1305_ALT)

#define MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA -0x0041 /**< Invalid input parameter(s). */

typedef struct
{
    uint32_t r[4];      /** Stores the value for 'r' (low 128 bits of the key) */
    uint32_t s[4];      /** Stores the value for 's' (high 128 bits of the key) */
    uint32_t acc[5];    /** Accumulator number */
    uint8_t queue[16];  /** Stores partial block data */
    size_t queue_len;   /** Number of bytes stored in 'queue'. Always less than 16 */
}
mbedtls_poly1305_context;

/**
 * \brief               Initialize a Poly1305 context
 *
 * \param ctx           The Poly1305 context to be initialized
 */
void mbedtls_poly1305_init( mbedtls_poly1305_context *ctx );

/**
 * \brief               Clear a Poly1305 context
 *
 * \param ctx           The Poly1305 context to be cleared
 */
void mbedtls_poly1305_free( mbedtls_poly1305_context *ctx );

/**
 * \brief               Set the Poly1305 authentication key.
 *
 * \warning             The key should be unique, and \b MUST be
 *                      unpredictable for each invocation of Poly1305.
 *
 * \param ctx           The Poly1305 context.
 * \param key           Buffer containing the 256-bit key.
 *
 * \return              MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA is returned if ctx
 *                      or key are NULL.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_poly1305_setkey( mbedtls_poly1305_context *ctx,
                             const unsigned char key[32] );

/**
 * \brief               Process data with Poly1305.
 *
 *                      This function can be called multiple times to process
 *                      a stream of data.
 *
 * \param ctx           The Poly1305 context.
 * \param ilen          The input length (in bytes). Any value is accepted.
 * \param input         Buffer containing the input data to Process.
 *                      This pointer can be NULL if ilen == 0.
 *
 * \return              MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA is returned if ctx
 *                      or input are NULL.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_poly1305_update( mbedtls_poly1305_context *ctx,
                             size_t ilen,
                             const unsigned char *input );

/**
 * \brief               Generate the Poly1305 MAC.
 *
 * \param ctx           The Poly1305 context.
 * \param mac           Buffer to where the MAC is written. Must be big enough
 *                      to hold the 16-byte MAC.
 *
 * \return              MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA is returned if ctx
 *                      or mac are NULL.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_poly1305_finish( mbedtls_poly1305_context *ctx,
                             unsigned char mac[16] );

#else  /* MBEDTLS_POLY1305_ALT */
#include "poly1305_alt.h"
#endif /* MBEDTLS_POLY1305_ALT */

/**
 * \brief               Generate the Poly1305 MAC of some data with the given key.
 *
 * \warning             The key should be unique, and \b MUST be
 *                      unpredictable for each invocation of Poly1305.
 *
 * \param key           Buffer containing the 256-bit (32 bytes) key.
 * \param ilen          The length of the input data (in bytes).
 * \param input         Buffer containing the input data to process.
 * \param mac           Buffer to where the 128-bit (16 bytes) MAC is written.
 *
 * \return              MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA is returned if key,
 *                      input, or mac are NULL.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_poly1305_mac( const unsigned char key[32],
                          size_t ilen,
                          const unsigned char *input,
                          unsigned char mac[16] );

/**
 * \brief               Checkup routine
 *
 * \return              0 if successful, or 1 if the test failed
 */
int mbedtls_poly1305_self_test( int verbose );

#endif /* MBEDTLS_POLY1305_H */
