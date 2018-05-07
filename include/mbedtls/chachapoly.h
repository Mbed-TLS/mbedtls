/**
 * \file chachapoly.h
 *
 * \brief ChaCha20-Poly1305 AEAD construction based on RFC 7539.
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
#ifndef MBEDTLS_CHACHAPOLY_H
#define MBEDTLS_CHACHAPOLY_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#define MBEDTLS_ERR_CHACHAPOLY_BAD_INPUT_DATA -0x00047 /**< Invalid input parameter(s). */
#define MBEDTLS_ERR_CHACHAPOLY_BAD_STATE      -0x00049 /**< The requested operation is not permitted in the current state */
#define MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED    -0x00049 /**< Authenticated decryption failed: data was not authentic. */


#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    MBEDTLS_CHACHAPOLY_ENCRYPT,
    MBEDTLS_CHACHAPOLY_DECRYPT
}
mbedtls_chachapoly_mode_t;

#if !defined(MBEDTLS_CHACHAPOLY_ALT)

#include "chacha20.h"
#include "poly1305.h"

typedef struct
{
    mbedtls_chacha20_context chacha20_ctx;      /** ChaCha20 context */
    mbedtls_poly1305_context poly1305_ctx;      /** Poly1305 context */
    uint64_t aad_len;                           /** Length (bytes) of the Additional Authenticated Data */
    uint64_t ciphertext_len;                    /** Length (bytes) of the ciphertext */
    int state;                                  /** Current state of the context */
    mbedtls_chachapoly_mode_t mode; /** Cipher mode (encrypt or decrypt) */
}
mbedtls_chachapoly_context;

#else /* !MBEDTLS_CHACHAPOLY_ALT */
#include "chachapoly_alt.h"
#endif /* !MBEDTLS_CHACHAPOLY_ALT */

/**
 * \brief               Initialize ChaCha20-Poly1305 context
 *
 * \param ctx           ChaCha20-Poly1305 context to be initialized
 */
void mbedtls_chachapoly_init( mbedtls_chachapoly_context *ctx );

/**
 * \brief               Clear ChaCha20-Poly1305 context
 *
 * \param ctx           ChaCha20-Poly1305 context to be cleared
 */
void mbedtls_chachapoly_free( mbedtls_chachapoly_context *ctx );

/**
 * \brief               Set the ChaCha20-Poly1305 symmetric encryption key.
 *
 * \param ctx           The ChaCha20-Poly1305 context.
 * \param key           The 256-bit (32 bytes) key.
 *
 * \return              MBEDTLS_ERR_CHACHAPOLY_BAD_INPUT_DATA is returned
 *                      if \p ctx or \p key are NULL.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_chachapoly_setkey( mbedtls_chachapoly_context *ctx,
                               const unsigned char key[32] );

/**
 * \brief               Setup ChaCha20-Poly1305 context for encryption or decryption.
 *
 * \note                If the context is being used for AAD only (no data to
 *                      encrypt or decrypt) then \p mode can be set to any value.
 *
 * \param ctx           The ChaCha20-Poly1305 context.
 * \param nonce         The nonce/IV to use for the message. This must be unique
 *                      for every message encrypted under the same key.
 * \param mode          Specifies whether the context is used to encrypt or
 *                      decrypt data.
 *
 * \return              MBEDTLS_ERR_CHACHAPOLY_BAD_INPUT_DATA is returned
 *                      if \p ctx or \p mac are NULL.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_chachapoly_starts( mbedtls_chachapoly_context *ctx,
                               const unsigned char nonce[12],
                               mbedtls_chachapoly_mode_t mode );

/**
 * \brief               Process additional authenticated data (AAD).
 *
 *                      This function processes data that is authenticated, but
 *                      not encrypted.
 *
 * \note                This function is called before data is encrypted/decrypted.
 *                      I.e. call this function to process the AAD before calling
 *                      mbedtls_chachapoly_update.
 *
 *                      You may call this function multiple times to process
 *                      an arbitrary amount of AAD. It is permitted to call
 *                      this function 0 times, if no AAD is used.
 *
 *                      This function cannot be called any more if data has
 *                      been processed by mbedtls_chachapoly_update,
 *                      or if the context has been finished.
 *
 * \param ctx           The ChaCha20-Poly1305 context.
 * \param aad_len       The length (in bytes) of the AAD. The length has no
 *                      restrictions.
 * \param aad           Buffer containing the AAD.
 *                      This pointer can be NULL if aad_len == 0.
 *
 * \return              MBEDTLS_ERR_CHACHAPOLY_BAD_INPUT_DATA is returned
 *                      if \p ctx or \p aad are NULL.
 *                      MBEDTLS_ERR_CHACHAPOLY_BAD_STATE is returned if
 *                      the context has not been setup, the context has been
 *                      finished, or if the AAD has been finished.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_chachapoly_update_aad( mbedtls_chachapoly_context *ctx,
                                   size_t aad_len,
                                   const unsigned char *aad );

/**
 * \brief               Encrypt/decrypt data.
 *
 *                      The direction (encryption or decryption) depends on the
 *                      mode that was given when calling
 *                      mbedtls_chachapoly_starts.
 *
 *                      You may call this function multiple times to process
 *                      an arbitrary amount of data. It is permitted to call
 *                      this function 0 times, if no data is to be encrypted
 *                      or decrypted.
 *
 * \param ctx           The ChaCha20-Poly1305 context.
 * \param len           The length (in bytes) of the data to encrypt or decrypt.
 * \param input         Buffer containing the data to encrypt or decrypt.
 *                      This pointer can be NULL if len == 0.
 * \param output        Buffer to where the encrypted or decrypted data is written.
 *                      This pointer can be NULL if len == 0.
 *
 * \return              MBEDTLS_ERR_CHACHAPOLY_BAD_INPUT_DATA is returned
 *                      if \p ctx, \p input, or \p output are NULL.
 *                      MBEDTLS_ERR_CHACHAPOLY_BAD_STATE is returned if
 *                      the context has not been setup, or if the context has been
 *                      finished.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_chachapoly_update( mbedtls_chachapoly_context *ctx,
                               size_t len,
                               const unsigned char *input,
                               unsigned char *output );

/**
 * \brief               Compute the ChaCha20-Poly1305 MAC.
 *
 * \param ctx           The ChaCha20-Poly1305 context.
 * \param mac           Buffer to where the 128-bit (16 bytes) MAC is written.
 *
 * \return              MBEDTLS_ERR_CHACHAPOLY_BAD_INPUT_DATA is returned
 *                      if \p ctx or \p mac are NULL.
 *                      MBEDTLS_ERR_CHACHAPOLY_BAD_STATE is returned if
 *                      the context has not been setup.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_chachapoly_finish( mbedtls_chachapoly_context *ctx,
                               unsigned char mac[16] );

/**
 * \brief               Encrypt or decrypt data, and produce a MAC (tag) with ChaCha20-Poly1305.
 *
 * \param ctx           The ChachaPoly context.
 * \param mode          Specifies whether the data in the \p input buffer is to
 *                      be encrypted or decrypted. If there is no data to encrypt
 *                      or decrypt (i.e. \p ilen is 0) then the value of this
 *                      parameter does not matter.
 * \param length        The length (in bytes) of the data to encrypt or decrypt.
 * \param nonce         The 96-bit (12 bytes) nonce/IV to use.
 * \param aad           Buffer containing the additional authenticated data (AAD).
 *                      This pointer can be NULL if aad_len == 0.
 * \param aad_len       The length (in bytes) of the AAD data to process.
 * \param input         Buffer containing the data to encrypt or decrypt.
 *                      This pointer can be NULL if ilen == 0.
 * \param output        Buffer to where the encrypted or decrypted data is written.
 *                      This pointer can be NULL if ilen == 0.
 * \param tag           Buffer to where the computed 128-bit (16 bytes) MAC is written.
 *
 * \return              MBEDTLS_ERR_CHACHAPOLY_BAD_INPUT_DATA is returned
 *                      if one or more of the required parameters are NULL.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_chachapoly_crypt_and_tag( mbedtls_chachapoly_context *ctx,
                                      mbedtls_chachapoly_mode_t mode,
                                      size_t length,
                                      const unsigned char nonce[12],
                                      const unsigned char *aad,
                                      size_t aad_len,
                                      const unsigned char *input,
                                      unsigned char *output,
                                      unsigned char tag[16] );

/**
 * \brief           Decrypt data and check a MAC (tag) with ChaCha20-Poly1305.
 *
 * \param ctx       The ChachaPoly context.
 * \param length    The length of the input and output data.
 * \param nonce     The nonce / initialization vector.
 * \param aad       The buffer holding the additional authenticated data.
 * \param aad_len   The length of the additional authenticated data.
 * \param tag       The buffer holding the tag.
 * \param input     The buffer holding the input data.
 * \param output    The buffer for holding the output data.
 *
 * \return              MBEDTLS_ERR_CHACHAPOLY_BAD_INPUT_DATA is returned
 *                      if one or more of the required parameters are NULL.
 *                      MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED if the tag does not
 *                      match.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_chachapoly_auth_decrypt( mbedtls_chachapoly_context *ctx,
                                     size_t length,
                                     const unsigned char nonce[12],
                                     const unsigned char *aad,
                                     size_t aad_len,
                                     const unsigned char tag[16],
                                     const unsigned char *input,
                                     unsigned char *output );

/**
 * \brief               Checkup routine
 *
 * \return              0 if successful, or 1 if the test failed
 */
int mbedtls_chachapoly_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CHACHAPOLY_H */
