/**
 * \file sha256.h
 *
 * \brief The SHA-224 and SHA-256 cryptographic hash function.
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_SHA256_H
#define MBEDTLS_SHA256_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_SHA256_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          The SHA-256 context structure.
 */
typedef struct
{
    uint32_t total[2];          /*!< The number of Bytes processed.  */
    uint32_t state[8];          /*!< The intermediate digest state.  */
    unsigned char buffer[64];   /*!< The data block being processed. */
    int is224;                  /*!< Determines which function to use.
                                     <ul><li>0: use SHA-256.</li>
                                     <li>1: use SHA-224.</li></ul> */
}
mbedtls_sha256_context;

/**
 * \brief          This function initializes a SHA-256 context.
 *
 * \param ctx      The SHA-256 context to initialize.
 */
void mbedtls_sha256_init( mbedtls_sha256_context *ctx );

/**
 * \brief          This function clears a SHA-256 context.
 *
 * \param ctx      The SHA-256 context to clear.
 */
void mbedtls_sha256_free( mbedtls_sha256_context *ctx );

/**
 * \brief          This function clones the state of a SHA-256 context.
 *
 * \param dst      The destination context.
 * \param src      The context to clone.
 */
void mbedtls_sha256_clone( mbedtls_sha256_context *dst,
                           const mbedtls_sha256_context *src );

/**
 * \brief          This function sets up a SHA-256 context.
 *
 * \param ctx      The context to initialize.
 * \param is224    Determines which function to use.
 *                 <ul><li>0: use SHA-256.</li>
 *                 <li>1: use SHA-224.</li></ul>
 */
void mbedtls_sha256_starts( mbedtls_sha256_context *ctx, int is224 );

/**
 * \brief          This function encrypts or decrypts using the
 *                 given SHA-256 context.
 *
 * \param ctx      The SHA-256 context.
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 */
void mbedtls_sha256_update( mbedtls_sha256_context *ctx, const unsigned char *input,
                    size_t ilen );

/**
 * \brief          This function finishes the SHA-256 operation, and writes
 *                 the result to the output buffer.
 *
 * \param ctx      The SHA-256 context.
 * \param output   The SHA-224 or SHA-256 checksum result.
 */
void mbedtls_sha256_finish( mbedtls_sha256_context *ctx, unsigned char output[32] );

/* Internal use */
void mbedtls_sha256_process( mbedtls_sha256_context *ctx, const unsigned char data[64] );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_SHA256_ALT */
#include "sha256_alt.h"
#endif /* MBEDTLS_SHA256_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          This function calculates SHA-256 
 *                 on the input buffer.
 *
 *                 The function allocates the context, performs the 
 *                 calculation, and frees the context.
 *
 *                 The SHA-256 result is calculated as 
 *                 output = SHA-256(input buffer).
 *
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 * \param output   The SHA-224 or SHA-256 checksum result.
 * \param is224    Determines which function to use.
 *                 <ul><li>0: use SHA-256.</li>
 *                 <li>1: use SHA-224.</li></ul>
 */
void mbedtls_sha256( const unsigned char *input, size_t ilen,
           unsigned char output[32], int is224 );

/**
 * \brief          The SHA-224 and SHA-256 checkup routine.
 *
 * \return         \c 0 on success, or \c 1 on failure.
 */
int mbedtls_sha256_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_sha256.h */
