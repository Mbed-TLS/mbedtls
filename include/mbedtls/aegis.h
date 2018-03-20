/**
 * \file aes.h
 *
 * \brief AES block cipher
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
#ifndef MBEDTLS_AEGIS_H
#define MBEDTLS_AEGIS_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "cipher.h"

#include <stddef.h>
#include <stdint.h>

#if defined(MBEDTLS_AESNI_C)
#include <immintrin.h>
#include <wmmintrin.h>
#endif /* defined(MBEDTLS_AESNI_C) */

/* padlock.c and aesni.c rely on these values! */
#define MBEDTLS_AEGIS_ENCRYPT     1
#define MBEDTLS_AEGIS_DECRYPT     0

#define MBEDTLS_ERR_AEGIS_AUTH_FAILED                       -0x0012
#define MBEDTLS_ERR_AEGIS_BAD_INPUT                     -0x0014  /**< Invalid data input. */
#define MBEDTLS_ERR_AEGIS_INVALID_KEY_LENGTH                -0x0020  /**< Invalid key length. */
#define MBEDTLS_ERR_AEGIS_INVALID_INPUT_LENGTH              -0x0022  /**< Invalid data input length. */

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#if !defined(MBEDTLS_AEGIS_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          AEGIS context structure
 *
 * \note           buf is able to hold 32 extra bytes, which can be used:
 *                 - for alignment purposes if VIA padlock is used, and/or
 *                 - to simplify key expansion in the 256-bit case by
 *                 generating an extra round key
 */
typedef struct
{
    uint64_t len;               /*!< Total data length */
    uint64_t add_len;           /*!< Total add length */
    unsigned char key[16];
#if defined(MBEDTLS_AESNI_C)
    __m128i state[128];
#else
    unsigned char state[128];
#endif /* defined(MBEDTLS_AESNI_C) */
} mbedtls_aegis_context;

/**
 * \brief          Initialize AES context
 *
 * \param ctx      AES context to be initialized
 */
void mbedtls_aegis_init( mbedtls_aegis_context *ctx );

/**
 * \brief          Clear AES context
 *
 * \param ctx      AES context to be cleared
 */
void mbedtls_aegis_free( mbedtls_aegis_context *ctx );

/**
 * \brief          AES key schedule (encryption)
 *
 * \param ctx      AES context to be initialized
 * \param key      encryption key
 * \param keybits  must be 128, 192 or 256
 *
 * \return         0 if successful, or MBEDTLS_ERR_AES_INVALID_KEY_LENGTH
 */
 int mbedtls_aegis_setkey( mbedtls_aegis_context *ctx,
                           const unsigned char *key,
                           unsigned int keybits );

 /**
  * \brief           GCM buffer encryption/decryption using a block cipher
  *
  * \note On encryption, the output buffer can be the same as the input buffer.
  *       On decryption, the output buffer cannot be the same as input buffer.
  *       If buffers overlap, the output buffer must trail at least 8 bytes
  *       behind the input buffer.
  *
  * \param ctx       GCM context
  * \param mode      MBEDTLS_GCM_ENCRYPT or MBEDTLS_GCM_DECRYPT
  * \param length    length of the input data
  * \param iv        initialization vector
  * \param iv_len    length of IV
  * \param add       additional data
  * \param add_len   length of additional data
  * \param input     buffer holding the input data
  * \param output    buffer for holding the output data
  * \param tag_len   length of the tag to generate
  * \param tag       buffer for holding the tag
  *
  * \return         0 if successful
  */
int mbedtls_aegis_crypt_and_tag( mbedtls_aegis_context *ctx,
                      int mode,
                      size_t length,
                      const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *add,
                      size_t add_len,
                      const unsigned char *input,
                      unsigned char *output,
                      size_t tag_len,
                      unsigned char *tag );

 /**
  * \brief           GCM buffer authenticated decryption using a block cipher
  *
  * \note On decryption, the output buffer cannot be the same as input buffer.
  *       If buffers overlap, the output buffer must trail at least 8 bytes
  *       behind the input buffer.
  *
  * \param ctx       GCM context
  * \param length    length of the input data
  * \param iv        initialization vector
  * \param iv_len    length of IV
  * \param add       additional data
  * \param add_len   length of additional data
  * \param tag       buffer holding the tag
  * \param tag_len   length of the tag
  * \param input     buffer holding the input data
  * \param output    buffer for holding the output data
  *
  * \return         0 if successful and authenticated,
  *                 MBEDTLS_ERR_GCM_AUTH_FAILED if tag does not match
  */
int mbedtls_aegis_auth_decrypt( mbedtls_aegis_context *ctx,
                     size_t length,
                     const unsigned char *iv,
                     size_t iv_len,
                     const unsigned char *add,
                     size_t add_len,
                     const unsigned char *tag,
                     size_t tag_len,
                     const unsigned char *input,
                     unsigned char *output );

 /**
  * \brief           Generic GCM stream start function
  *
  * \param ctx       GCM context
  * \param mode      MBEDTLS_GCM_ENCRYPT or MBEDTLS_GCM_DECRYPT
  * \param iv        initialization vector
  * \param iv_len    length of IV
  * \param add       additional data (or NULL if length is 0)
  * \param add_len   length of additional data
  *
  * \return         0 if successful
  */
int mbedtls_aegis_starts( mbedtls_aegis_context *ctx,
               const unsigned char *iv,
               size_t iv_len,
               const unsigned char *add,
               size_t add_len );

 /**
  * \brief           Generic GCM update function. Encrypts/decrypts using the
  *                  given GCM context. Expects input to be a multiple of 16
  *                  bytes! Only the last call before mbedtls_gcm_finish() can be less
  *                  than 16 bytes!
  *
  * \note On decryption, the output buffer cannot be the same as input buffer.
  *       If buffers overlap, the output buffer must trail at least 8 bytes
  *       behind the input buffer.
  *
  * \param ctx       GCM context
  * \param length    length of the input data
  * \param input     buffer holding the input data
  * \param output    buffer for holding the output data
  *
  * \return         0 if successful or MBEDTLS_ERR_GCM_BAD_INPUT
  */
int mbedtls_aegis_update( mbedtls_aegis_context *ctx,
               int mode,
               size_t length,
               const unsigned char *input,
               unsigned char *output );

 /**
  * \brief           Generic GCM finalisation function. Wraps up the GCM stream
  *                  and generates the tag. The tag can have a maximum length of
  *                  16 bytes.
  *
  * \param ctx       GCM context
  * \param tag       buffer for holding the tag
  * \param tag_len   length of the tag to generate (must be at least 4)
  *
  * \return          0 if successful or MBEDTLS_ERR_GCM_BAD_INPUT
  */
int mbedtls_aegis_finish( mbedtls_aegis_context *ctx,
               unsigned char *tag,
               size_t tag_len );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_AES_ALT */
#include "aegis_alt.h"
#endif /* MBEDTLS_AES_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_aegis_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* aes.h */
