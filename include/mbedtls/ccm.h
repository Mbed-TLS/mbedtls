/**
 * \file ccm.h
 *
 * \brief This file provides an API for the CCM authenticated encryption
 *        mode for block ciphers.
 *
 * CCM combines Counter mode encryption with CBC-MAC authentication
 * for 128-bit block ciphers.
 *
 * Input to CCM includes the following elements:
 * <ul><li>Payload - data that is both authenticated and encrypted.</li>
 * <li>Associated data (Adata) - data that is authenticated but not
 * encrypted, For example, a header.</li>
 * <li>Nonce - A unique value that is assigned to the payload and the
 * associated data.</li></ul>
 *
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

#ifndef MBEDTLS_CCM_H
#define MBEDTLS_CCM_H

#include "cipher.h"

#define MBEDTLS_ERR_CCM_BAD_INPUT       -0x000D /**< Bad input parameters to the function. */
#define MBEDTLS_ERR_CCM_AUTH_FAILED     -0x000F /**< Authenticated decryption failed. */
#define MBEDTLS_ERR_CCM_HW_ACCEL_FAILED -0x0011 /**< CCM hardware accelerator failed. */

#if !defined(MBEDTLS_CCM_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief    The CCM context-type definition. The CCM context is passed
 *           to the APIs called.
 */
typedef struct {
    mbedtls_cipher_context_t cipher_ctx;    /*!< The cipher context used. */
}
mbedtls_ccm_context;

/**
 * \brief           The CCM* callback for encrypting with variable tag length.
 *                  The function pointer is passed to the APIs called. This
 *                  function calculates the nonce and returns it in a buffer.
 *
 * \warning         This function must not return the same nonce more than once
 *                  in the lifetime of the key!
 *
 * \note            To prevent attacks taking advantage of the variable tag
 *                  length CCM* encodes the tag length in the nonce. The method
 *                  of encoding may vary. Standards might mandate encoding other
 *                  information in the nonce (e.g. address and frame counter)
 *                  too.
 *
 * \param app_ctx   A pointer to structure containing the application context
 *                  if it is necessary for calculating the initialisation vector
 *                  (nonce).
 * \param tag_len   Length of the tag in bytes.
 * \nonce           Output variable, points to the buffer capable of holding the
 *                  calculated nonce. Must be at least \p nonce_len bytes long.
 * \nonce_len       The length of the nonce in bytes.
 *
 * \return          \c 0 on success.
 * \return          MBEDTLS_ERR_CCM_BAD_INPUT error code on failure.
 */
typedef int (*mbedtls_ccm_star_get_nonce_t)( void *app_ctx, size_t tag_len,
                                             unsigned char *nonce,
                                             size_t nonce_len );

/**
 * \brief           The CCM* callback for decrypting with variable tag length.
 *                  The function pointer is passed to the APIs called. This
 *                  function calculates and returns the length of the tag in the
 *                  output parameter.
 *
 * \param app_ctx   A pointer to structure containing the application context
 *                  if it is necessary for decoding the tag length or validating
 *                  the initialisation vector (nonce).
 * \param tag_len   Output variable for holding the tag length in bytes.
 * \nonce           A buffer containing the nonce.
 * \nonce_len       The length of the nonce in bytes.
 *
 * \return          \c 0 on success.
 * \return          MBEDTLS_ERR_CCM_BAD_INPUT error code on failure.
 */
typedef int (*mbedtls_ccm_star_get_tag_len_t)( void *app_ctx, size_t* tag_len,
                                               const unsigned char *nonce,
                                               size_t nonce_len );

/**
 * \brief           This function initializes the specified CCM context,
 *                  to make references valid, and prepare the context
 *                  for mbedtls_ccm_setkey() or mbedtls_ccm_free().
 *
 * \param ctx       The CCM context to initialize.
 */
void mbedtls_ccm_init( mbedtls_ccm_context *ctx );

/**
 * \brief           This function initializes the CCM context set in the
 *                  \p ctx parameter and sets the encryption key.
 *
 * \param ctx       The CCM context to initialize.
 * \param cipher    The 128-bit block cipher to use.
 * \param key       The encryption key.
 * \param keybits   The key size in bits. This must be acceptable by the cipher.
 *
 * \return          \c 0 on success.
 * \return          A CCM or cipher-specific error code on failure.
 */
int mbedtls_ccm_setkey( mbedtls_ccm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits );

/**
 * \brief   This function releases and clears the specified CCM context
 *          and underlying cipher sub-context.
 *
 * \param ctx       The CCM context to clear.
 */
void mbedtls_ccm_free( mbedtls_ccm_context *ctx );

/**
 * \brief           This function encrypts a buffer using CCM.
 *
 * \note            The tag is written to a separate buffer. To concatenate
 *                  the \p tag with the \p output, as done in <em>RFC-3610:
 *                  Counter with CBC-MAC (CCM)</em>, use
 *                  \p tag = \p output + \p length, and make sure that the
 *                  output buffer is at least \p length + \p tag_len wide.
 *
 * \param ctx       The CCM context to use for encryption.
 * \param length    The length of the input data in Bytes.
 * \param iv        Initialization vector (nonce).
 * \param iv_len    The length of the IV in Bytes: 7, 8, 9, 10, 11, 12, or 13.
 * \param add       The additional data field.
 * \param add_len   The length of additional data in Bytes.
 *                  Must be less than 2^16 - 2^8.
 * \param input     The buffer holding the input data.
 * \param output    The buffer holding the output data.
 *                  Must be at least \p length Bytes wide.
 * \param tag       The buffer holding the tag.
 * \param tag_len   The length of the tag to generate in Bytes:
 *                  4, 6, 8, 10, 12, 14 or 16.
 *
 * \return          \c 0 on success.
 * \return          A CCM or cipher-specific error code on failure.
 */
int mbedtls_ccm_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *add, size_t add_len,
                         const unsigned char *input, unsigned char *output,
                         unsigned char *tag, size_t tag_len );

/**
 * \brief           This function encrypts a buffer using CCM* with fixed tag
 *                  length.
 *
 * \note            The tag is written to a separate buffer. To concatenate
 *                  the \p tag with the \p output, as done in <em>RFC-3610:
 *                  Counter with CBC-MAC (CCM)</em>, use
 *                  \p tag = \p output + \p length, and make sure that the
 *                  output buffer is at least \p length + \p tag_len wide.
 *
 * \param ctx       The CCM context to use for encryption.
 * \param length    The length of the input data in Bytes.
 * \param iv        Initialization vector (nonce).
 * \param iv_len    The length of the IV in Bytes: 7, 8, 9, 10, 11, 12, or 13.
 * \param add       The additional data field.
 * \param add_len   The length of additional data in Bytes.
 *                  Must be less than 2^16 - 2^8.
 * \param input     The buffer holding the input data.
 * \param output    The buffer holding the output data.
 *                  Must be at least \p length Bytes wide.
 * \param tag       The buffer holding the tag.
 * \param tag_len   The length of the tag to generate in Bytes:
 *                  0, 4, 6, 8, 10, 12, 14 or 16.
 *
 * \warning         Passing 0 as \p tag_len means that the message is no
 *                  longer authenticated.
 *
 * \return          \c 0 on success.
 * \return          A CCM or cipher-specific error code on failure.
 */
int mbedtls_ccm_sfix_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *add, size_t add_len,
                         const unsigned char *input, unsigned char *output,
                         unsigned char *tag, size_t tag_len );

/**
 * \brief               This function encrypts a buffer using CCM* with variable
 *                      tag length.
 *
 * \note                The tag is written to a separate buffer. To concatenate
 *                      the \p tag with the \p output, as done in <em>RFC-3610:
 *                      Counter with CBC-MAC (CCM)</em>, use
 *                      \p tag = \p output + \p length, and make sure that the
 *                      output buffer is at least \p length + \p tag_len wide.
 *
 * \param ctx           The CCM context to use for encryption.
 * \param length        The length of the input data in Bytes.
 * \param iv_len        The length of the IV in Bytes: 7, 8, 9, 10, 11, 12,
 *                      or 13.
 * \param add           The additional data field.
 * \param add_len       The length of additional data in Bytes.
 *                      Must be less than 2^16 - 2^8.
 * \param input         The buffer holding the input data.
 * \param output        The buffer holding the output data.
 *                      Must be at least \p length Bytes wide.
 * \param tag           The buffer holding the tag.
 * \param tag_len       The length of the tag to generate in Bytes:
 *                      0, 4, 6, 8, 10, 12, 14 or 16.
 * \param get_iv        A callback function returning the IV (nonce) with the
 *                      tag length encoded in it.
 * \param get_iv_ctx    Context passed to the \p get_iv callback.
 *
 * \warning             Passing 0 as \p tag_len means that the message is no
 *                      longer authenticated.
 *
 * \return              \c 0 on success.
 * \return              A CCM or cipher-specific error code on failure.
 */
int mbedtls_ccm_svar_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         size_t iv_len, const unsigned char *add,
                         size_t add_len, const unsigned char *input,
                         unsigned char *output, unsigned char *tag,
                         size_t tag_len, mbedtls_ccm_star_get_nonce_t get_iv,
                         void *get_iv_ctx );

/**
 * \brief           This function performs a CCM authenticated decryption of a
 *                  buffer.
 *
 * \param ctx       The CCM context to use for decryption.
 * \param length    The length of the input data in Bytes.
 * \param iv        Initialization vector.
 * \param iv_len    The length of the IV in Bytes: 7, 8, 9, 10, 11, 12, or 13.
 * \param add       The additional data field.
 * \param add_len   The length of additional data in Bytes.
 *                  Must be less than 2^16 - 2^8.
 * \param input     The buffer holding the input data.
 * \param output    The buffer holding the output data.
 *                  Must be at least \p length Bytes wide.
 * \param tag       The buffer holding the tag.
 * \param tag_len   The length of the tag in Bytes.
 *                  4, 6, 8, 10, 12, 14 or 16.
 *
 * \return          \c 0 on success. This indicates that the message is authentic.
 * \return          #MBEDTLS_ERR_CCM_AUTH_FAILED if the tag does not match.
 * \return          A cipher-specific error code on calculation failure.
 */
int mbedtls_ccm_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len );

/**
 * \brief           This function performs a CCM* authenticated decryption of a
 *                  buffer with fixed tag length.
 *
 * \param ctx       The CCM context to use for decryption.
 * \param length    The length of the input data in Bytes.
 * \param iv        Initialization vector.
 * \param iv_len    The length of the IV in Bytes: 7, 8, 9, 10, 11, 12, or 13.
 * \param add       The additional data field.
 * \param add_len   The length of additional data in Bytes.
 *                  Must be less than 2^16 - 2^8.
 * \param input     The buffer holding the input data.
 * \param output    The buffer holding the output data.
 *                  Must be at least \p length Bytes wide.
 * \param tag       The buffer holding the tag.
 * \param tag_len   The length of the tag in Bytes.
 *                  0, 4, 6, 8, 10, 12, 14 or 16.
 *
 * \warning         Passing 0 as \p tag_len means that the message is no
 *                  longer authenticated.
 *
 * \return          \c 0 on success. This indicates that the message is
 *                  authentic.
 * \return          #MBEDTLS_ERR_CCM_AUTH_FAILED if the tag does not match.
 * \return          A cipher-specific error code on calculation failure.
 */
int mbedtls_ccm_sfix_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len );

/**
 * \brief               This function performs a CCM* authenticated decryption
 *                      of a buffer with variable tag length.
 *
 * \param ctx           The CCM context to use for decryption.
 * \param length        The length of the input data in Bytes.
 * \param iv            Initialization vector.
 * \param iv_len        The length of the IV in Bytes: 7, 8, 9, 10, 11, 12,
 *                      or 13.
 * \param add           The additional data field.
 * \param add_len       The length of additional data in Bytes.
 *                      Must be less than 2^16 - 2^8.
 * \param input         The buffer holding the input data. Unlike the \p input
 *                      parameters of other Mbed TLS CCM functions, this buffer
 *                      holds the concatenation of the encrypted data and the
 *                      authentication tag.
 * \param output        The buffer holding the output data.
 *                      Must be at least \p length Bytes wide.
 * \param output_len    The length of the decrypted data.
 * \param get_tag_len   A callback function returning the tag length.
 * \param get_tlen_ctx  Context passed to the \p get_tag_len callback.
 *
 *
 * \return              \c 0 on success. This indicates that the message is
 *                      authentic.
 * \return              #MBEDTLS_ERR_CCM_AUTH_FAILED if the tag does not match.
 * \return              A cipher-specific error code on calculation failure.
 */
int mbedtls_ccm_svar_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      size_t* output_len,
                      mbedtls_ccm_star_get_tag_len_t get_tag_len,
                      void *get_tlen_ctx );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_CCM_ALT */
#include "ccm_alt.h"
#endif /* MBEDTLS_CCM_ALT */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
/**
 * \brief          The CCM checkup routine.
 *
 * \return         \c 0 on success.
 * \return         \c 1 on failure.
 */
int mbedtls_ccm_self_test( int verbose );
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CCM_H */
