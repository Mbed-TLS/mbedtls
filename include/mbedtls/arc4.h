/**
 * \file arc4.h
 *
 * \brief The ARCFOUR stream cipher
 *
 * \warning   ARC4 is considered a weak cipher and its use constitutes a
 *            security risk. We recommend considering stronger ciphers instead.
 */
/*
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
 *
 */
#ifndef MBEDTLS_ARC4_H
#define MBEDTLS_ARC4_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>

#define MBEDTLS_ERR_ARC4_HW_ACCEL_FAILED                  -0x0019  /**< ARC4 hardware accelerator failed. */
#define MBEDTLS_ERR_ARC4_BAD_INPUT_DATA                   -0x001B  /**< Input invalid. */

#if defined( MBEDTLS_CHECK_PARAMS )
#define MBEDTLS_ARC4_VALIDATE( cond )   do { if( !(cond) ) \
                                            return( MBEDTLS_ERR_ARC4_BAD_INPUT_DATA ); \
                                        } while( 0 )
#else
#define MBEDTLS_ARC4_VALIDATE( cond )
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_ARC4_ALT)
// Regular implementation
//

/**
 * \brief     ARC4 context structure
 *
 * \warning   ARC4 is considered a weak cipher and its use constitutes a
 *            security risk. We recommend considering stronger ciphers instead.
 *
 */
typedef struct
{
    int x;                      /*!< permutation index */
    int y;                      /*!< permutation index */
    unsigned char m[256];       /*!< permutation table */
}
mbedtls_arc4_context;

#else  /* MBEDTLS_ARC4_ALT */
#include "arc4_alt.h"
#endif /* MBEDTLS_ARC4_ALT */

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#if defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_DEPRECATED      __attribute__((deprecated))
#else
#define MBEDTLS_DEPRECATED
#endif

/**
 * \brief          ARC4 key schedule
 *
 * \param ctx      ARC4 context to be setup
 * \param key      the secret key
 * \param keylen   length of the key, in bytes
 *
 * \warning        ARC4 is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 *
 */
MBEDTLS_DEPRECATED void mbedtls_arc4_setup( mbedtls_arc4_context *ctx,
        const unsigned char *key, unsigned int keylen );

/**
 * \brief          Initialize ARC4 context
 *
 * \param ctx      ARC4 context to be initialized
 *
 * \warning        ARC4 is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 *
 */
MBEDTLS_DEPRECATED void mbedtls_arc4_init( mbedtls_arc4_context *ctx );

/**
 * \brief          Clear ARC4 context
 *
 * \param ctx      ARC4 context to be cleared
 *
 * \warning        ARC4 is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 *
 */
MBEDTLS_DEPRECATED void mbedtls_arc4_free( mbedtls_arc4_context *ctx );

#undef MBEDTLS_DEPRECATED
#endif /* !MBEDTLS_DEPRECATED_REMOVED */

/**
 * \brief          Initialize ARC4 context
 *
 * \param ctx      ARC4 context to be initialized
 *
 * \return         0 upon success
 *
 * \warning        ARC4 is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 *
 */
int mbedtls_arc4_init_ret( mbedtls_arc4_context *ctx );

/**
 * \brief          Clear ARC4 context
 *
 * \param ctx      ARC4 context to be cleared
 *
 * \return         0 upon success
 *
 * \warning        ARC4 is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 *
 */
int mbedtls_arc4_free_ret( mbedtls_arc4_context *ctx );

/**
 * \brief          ARC4 key schedule
 *
 * \param ctx      ARC4 context to be setup
 * \param key      the secret key
 * \param keylen   length of the key, in bytes
 *
 * \return         0 upon success
 *
 * \warning        ARC4 is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 *
 */
int mbedtls_arc4_setup_ret( mbedtls_arc4_context *ctx, const unsigned char *key,
                 unsigned int keylen );

/**
 * \brief          ARC4 cipher function
 *
 * \param ctx      ARC4 context
 * \param length   length of the input data
 * \param input    buffer holding the input data
 * \param output   buffer for the output data
 *
 * \return         0 if successful
 *
 * \warning        ARC4 is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 *
 */
int mbedtls_arc4_crypt( mbedtls_arc4_context *ctx, size_t length, const unsigned char *input,
                unsigned char *output );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 *
 * \warning        ARC4 is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 *
 */
int mbedtls_arc4_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* arc4.h */
