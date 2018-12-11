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

/* MBEDTLS_ERR_ARC4_HW_ACCEL_FAILED is deprecated and should not be used. */
#define MBEDTLS_ERR_ARC4_HW_ACCEL_FAILED                  -0x0019  /**< ARC4 hardware accelerator failed. */
#define MBEDTLS_ERR_ARC4_BAD_INPUT_DATA                   -0x001a  /**< Invalid input data.               */

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
typedef struct mbedtls_arc4_context
{
    int x;                      /*!< permutation index */
    int y;                      /*!< permutation index */
    unsigned char m[256];       /*!< permutation table */
}
mbedtls_arc4_context;

#else  /* MBEDTLS_ARC4_ALT */
#include "arc4_alt.h"
#endif /* MBEDTLS_ARC4_ALT */

/**
 * \brief          Initialize an ARC4 context.
 *
 * \param ctx      The ARC4 context to be initialized.
 *                 Must not be \c NULL.
 *
 * \warning        ARC4 is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 *
 */
void mbedtls_arc4_init( mbedtls_arc4_context *ctx );

/**
 * \brief          Clear an ARC4 context.
 *
 * \param ctx      The ARC4 context to be cleared. May be \c NULL,
 *                 in which case this function is a no-op.
 *
 * \warning        ARC4 is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 *
 */
void mbedtls_arc4_free( mbedtls_arc4_context *ctx );

/**
 * \brief          Perform an ARC4 key schedule.
 *
 * \param ctx      The ARC4 context to be setup. Must be initialized.
 * \param key      The secret key buffer.
 *                 Must be a readable buffer of length \p keylen Bytes.
 * \param keylen   The length of the secret key \p key in Bytes.
 *                 Must be in the range from 40 Bits - 2048 Bits.
 *
 * \warning        ARC4 is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 *
 */
void mbedtls_arc4_setup( mbedtls_arc4_context *ctx,
                         const unsigned char *key,
                         unsigned int keylen );

/**
 * \brief          Perform an ARC4 encryption/decryption operation.
 *
 * \param ctx      The ARC4 context to use. Must be initialized.
 * \param length   The length of the input data in Bytes.
 * \param input    The buffer holding the input data.
 *                 Must be a readable buffer of length \p length Bytes.
 * \param output   The buffer for the output data.
 *                 Must be a writable buffer of length \p length Bytes.
 *
 * \return         \c 0 if successful.
 *
 * \warning        ARC4 is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 *
 */
int mbedtls_arc4_crypt( mbedtls_arc4_context *ctx, size_t length,
                        const unsigned char *input,
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
