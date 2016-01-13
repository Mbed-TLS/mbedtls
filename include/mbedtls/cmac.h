/**
 * \file cmac.h
 *
 * \brief The CMAC Mode for Authentication
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
#ifndef MBEDTLS_CMAC_H
#define MBEDTLS_CMAC_H

#include "cipher.h"

#define MBEDTLS_ERR_CMAC_BAD_INPUT      -0x0011 /**< Bad input parameters to function. */
#define MBEDTLS_ERR_CMAC_VERIFY_FAILED  -0x0013 /**< Verification failed. */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          CCM context structure
 */
typedef struct {
    mbedtls_cipher_context_t cipher_ctx;    /*!< cipher context used */
    unsigned char K1[16];
    unsigned char K2[16];
}
mbedtls_cmac_context;

/**
 * \brief           Initialize CMAC context (just makes references valid)
 *                  Makes the context ready for mbedtls_cmac_setkey() or
 *                  mbedtls_cmac_free().
 *
 * \param ctx       CMAC context to initialize
 */
void mbedtls_cmac_init( mbedtls_cmac_context *ctx );

/**
 * \brief           CMAC initialization
 *
 * \param ctx       CMAC context to be initialized
 * \param cipher    cipher to use (a 128-bit block cipher)
 * \param key       encryption key
 * \param keybits   key size in bits (must be acceptable by the cipher)
 *
 * \return          0 if successful, or a cipher specific error code
 */
int mbedtls_cmac_setkey( mbedtls_cmac_context *ctx,
                         mbedtls_cipher_id_t cipher,
                         const unsigned char *key,
                         unsigned int keybits );

/**
 * \brief           Free a CMAC context and underlying cipher sub-context
 *
 * \param ctx       CMAC context to free
 */
void mbedtls_cmac_free( mbedtls_cmac_context *ctx );

/**
 * \brief           CMAC generate
 *
 * \param ctx       CMAC context
 * \param input     buffer holding the input data
 * \param in_len    length of the input data in bytes
 * \param tag       buffer for holding the generated tag
 * \param tag_len   length of the tag to generate in bytes
 *                  must be between 4, 6, 8, 10, 14 or 16
 *
 * \return          0 if successful
 */
int mbedtls_cmac_generate( mbedtls_cmac_context *ctx,
                           const unsigned char *input, size_t in_len,
                           unsigned char *tag, size_t tag_len );

/**
 * \brief           CMAC verify
 *
 * \param ctx       CMAC context
 * \param input     buffer holding the input data
 * \param in_len    length of the input data in bytes
 * \param tag       buffer holding the tag to verify
 * \param tag_len   length of the tag to verify in bytes
 *                  must be 4, 6, 8, 10, 14 or 16
 *
 * \return          0 if successful and authenticated,
 *                  MBEDTLS_ERR_CMAC_VERIFY_FAILED if tag does not match
 */
int mbedtls_cmac_verify( mbedtls_cmac_context *ctx,
                         const unsigned char *input, size_t in_len,
                         const unsigned char *tag, size_t tag_len );

/**
 * \brief           AES-CMAC-128-PRF
 * TODO: add reference to the standard
 *
 * \param ctx       CMAC context
 * \param key       PRF key
 * \param key_len   PRF key length
 * \param input     buffer holding the input data
 * \param in_len    length of the input data in bytes
 * \param tag       buffer holding the tag to verify (16 bytes)
 *                  TODO: update description of tag
 *
 * \return          0 if successful
 */
int mbedtls_aes_cmac_prf_128( mbedtls_cmac_context *ctx,
                              const unsigned char *key, size_t key_len,
                              const unsigned char *input, size_t in_len,
                              unsigned char *tag );

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_cmac_self_test( int verbose );
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CMAC_H */
