/*  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved.
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
 
/**
 * \file aes.h
 *
 * \brief AES is a family of block ciphers that processes data in multiples of block sizes (16 Bytes).
 * 
 */
 
#ifndef MBEDTLS_AES_H
#define MBEDTLS_AES_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

/* padlock.c and aesni.c rely on these values! */
#define MBEDTLS_AES_ENCRYPT     1 /**< AES encryption mode. */
#define MBEDTLS_AES_DECRYPT     0 /**< AES decryption mode. */

/* Error codes in range 0x0020-0x0022 */
#define MBEDTLS_ERR_AES_INVALID_KEY_LENGTH                -0x0020  /**< Invalid key length. */
#define MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH              -0x0022  /**< Invalid data input length. */

/* Error codes in range 0x0023-0x0023 */
#define MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE               -0x0023  /**< Feature not available. For example, unsupported AES key size. */

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#if !defined(MBEDTLS_AES_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The AES context-type definition. The AES context is passed to the APIs called.
 * \note           This buffer can hold 32 extra Bytes, which can be used for one of the following purposes:
 *                 <ul><li>Alignment if VIA padlock is used.</li>
 *                 <li>Simplifying key expansion in the 256-bit case by generating an extra round key.</li></ul>
 */
typedef struct
{
    int nr;                     /*!< The number of rounds.*/
    uint32_t *rk;               /*!< AES round keys.*/
    uint32_t buf[68];           /*!< Unaligned data buffer.*/
}
mbedtls_aes_context;

/**
 * \brief          This function initializes the specified AES context. To operate the AES machine, this must be the first API called.
 *
 * \param ctx      The AES context to initialize.
 */
void mbedtls_aes_init( mbedtls_aes_context *ctx );

/**
 * \brief          This function releases and clears the specified AES context.
 *
 * \param ctx      The AES context to clear.
 */
void mbedtls_aes_free( mbedtls_aes_context *ctx );

/**
 * \brief          This function initializes the context set in the \p ctx parameter and sets the encryption key schedule for the AES operation.
 *
 * \param ctx      The AES context to initialize.
 * \param key      The encryption key.
 * \param keybits  The size of data passed in bits. Valid options are:<ul><li>128bits</li><li>192bits</li><li>256bits</li></il>
 *
* \return         Zero if successful or #MBEDTLS_ERR_AES_INVALID_KEY_LENGTH on failure.
 */
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits );

/**
 * \brief          This function initializes the context set in the \p ctx parameter and sets the decryption key schedule for the AES operation.
 *
 * \param ctx      The AES context to initialize.
 * \param key      The decryption key.
 * \param keybits  The size of data passed. Valid options are:<ul><li>128bits</li><li>192bits</li><li>256bits</li></il>
 *
 * \return         Zero if successful or #MBEDTLS_ERR_AES_INVALID_KEY_LENGTH on failure.
 */
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits );

/**
 * \brief          This function performs the operation defined in the \p mode parameter (encrypt or decrypt), on the input data buffer defined in the \p input parameter.
 * mbedtls_aes_init(), and either mbedtls_aes_setkey_enc() or mbedtls_aes_setkey_dec() must be called before 
 * the first call to this API with the same context.
 *
 * \param ctx      The AES context to encrypt or decrypt.
 * \param mode     The AES mode: #MBEDTLS_AES_ENCRYPT or #MBEDTLS_AES_DECRYPT.
 * \param input    The 16Byte buffer holding the input data.
 * \param output   The 16Byte buffer holding the output data.
 
 * \return         Zero if successful.
 */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] );

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/**
 * \brief This function performs the operation defined in the \p mode parameter (encrypt/decrypt), on the input data buffer defined in the \p input parameter. 
 * It can be called as many times as needed, until all the input data is processed.
 * mbedtls_aes_init(), and either mbedtls_aes_setkey_enc() or mbedtls_aes_setkey_dec() must be called before 
 * the first call to this API with the same context.
 *
 * \note Upon exit, the content of the IV is updated so that you can
 *       call the same function again on the next
 *       block(s) of data and get the same result as if it was
 *       encrypted in one call. This allows a "streaming" usage.
 *       If you need to retain the contents of the IV, you should 
 *       either save it manually or use the cipher module instead.
 *
 *
 * \param ctx      The AES context to encrypt/decrypt.
 * \param mode     The AES mode: #MBEDTLS_AES_ENCRYPT or #MBEDTLS_AES_DECRYPT.
 * \param length   The length of the input data in Bytes. The buffer encryption/decryption length must be a multiple of the block size (16 Bytes).
 * \param iv       Initialization vector (updated after use).
 * \param input    The buffer holding the input data.
 * \param output   The buffer holding the output data.
 *
 * \return         Zero if successful or #MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH on failure.
 */
int mbedtls_aes_crypt_cbc( mbedtls_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output );
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/**
 * \brief This function performs the operation defined in the \p mode parameter (encrypt or decrypt), on the input data buffer defined in the \p input parameter.
 *
 * Due to the nature of CFB, you must use the same key schedule for
 * both encryption and decryption operations. Therefore, you must use the context initialized with
 * mbedtls_aes_setkey_enc() for both #MBEDTLS_AES_ENCRYPT and #MBEDTLS_AES_DECRYPT.
 *
 * \note Upon exit, the content of the IV is updated so that you can
 *       call the same function again on the next
 *       block(s) of data and get the same result as if it was
 *       encrypted in one call. This allows a "streaming" usage.
 *       If you need to retain the contents of the
 *       IV, you must either save it manually or use the cipher
 *       module instead.
 *
 *
 * \param ctx      The AES context to encrypt/decrypt.
 * \param mode     The AES mode: #MBEDTLS_AES_ENCRYPT or #MBEDTLS_AES_DECRYPT
 * \param length   The length of the input data.
 * \param iv_off   The offset in IV (updated after use).
 * \param iv       The initialization vector (updated after use).
 * \param input    The buffer holding the input data.
 * \param output   The buffer holding the output data.
 *
 * \return         Zero if successful.
 */
int mbedtls_aes_crypt_cfb128( mbedtls_aes_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output );

/**
 * \brief This function performs the operation defined in the \p mode parameter (encrypt/decrypt), on the input data buffer defined in the \p input parameter.
 *
 * Due to the nature of CFB, you must use the same key schedule for
 * both encryption and decryption operations. Therefore, you must use the context initialized with
 * mbedtls_aes_setkey_enc() for both #MBEDTLS_AES_ENCRYPT and #MBEDTLS_AES_DECRYPT.
 *
 * \note Upon exit, the content of the IV is updated so that you can
 *       call the same function again on the next
 *       block(s) of data and get the same result as if it was
 *       encrypted in one call. This allows a "streaming" usage.
 *       If you need to retain the contents of the
 *       IV, you should either save it manually or use the cipher
 *       module instead.
 *
 *
 * \param ctx      The AES context to encrypt/decrypt.
 * \param mode     The AES mode: #MBEDTLS_AES_ENCRYPT or #MBEDTLS_AES_DECRYPT
 * \param length   The length of the input data.
 * \param iv       The initialization vector (updated after use).
 * \param input    The buffer holding the input data.
 * \param output   The buffer holding the output data.
 *
 * \return         Zero if successful.
 */
int mbedtls_aes_crypt_cfb8( mbedtls_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output );
#endif /*MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/**
 * \brief This function performs the operation defined in the \p mode parameter (encrypt/decrypt), on the input data buffer defined in the \p input parameter.
 *
 * Due to the nature of CTR, you must use the same key schedule for
 * both encryption and decryption operations. Therefore, you must use the context initialized with
 * mbedtls_aes_setkey_enc() for both #MBEDTLS_AES_ENCRYPT and #MBEDTLS_AES_DECRYPT.
 *
 * \warning You must keep the maximum use of your counter in mind.
 *
 * \param ctx      		The AES context to encrypt or decrypt.
 * \param length   		The length of the input data.
 * \param nc_off   		The offset in the current \p stream_block, for resuming
 *                 		within current cipher stream. The offset pointer to
 *                 		should be 0 at the start of a stream.
 * \param nonce_counter The 128-bit nonce and counter.
 * \param stream_block  The saved stream block for resuming. This is overwritten
 *                      by the function.
 * \param input    		The buffer holding the input data.
 * \param output   		The buffer holding the output data.
 *
 * \return         Zero if successful.
 */
int mbedtls_aes_crypt_ctr( mbedtls_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output );
#endif /* MBEDTLS_CIPHER_MODE_CTR */

/**
 * \brief Internal AES block encryption function. This is 
 *        only exposed to allow overriding it using #MBEDTLS_AES_ENCRYPT_ALT.
 *
 * \param ctx       The AES context to encrypt.
 * \param input     The plaintext block.
 * \param output    The output (ciphertext) block.
 *
 * \return          Zero if successful.
 */
int mbedtls_internal_aes_encrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] );

/**
 * \brief Internal AES block decryption function. This is
 *        only exposed to allow overriding it using see #MBEDTLS_AES_DECRYPT_ALT.
 *
 * \param ctx       The AES context to decrypt.
 * \param input     The ciphertext block
 * \param output    The output (plaintext) block
 *
 * \return          Zero if successful.
 */
int mbedtls_internal_aes_decrypt( mbedtls_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] );

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#if defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_DEPRECATED      __attribute__((deprecated))
#else
#define MBEDTLS_DEPRECATED
#endif
/**
 * \brief           Deprecated internal AES block encryption function
 *                  without return value.
 *
 * \deprecated      Superseded by mbedtls_aes_encrypt_ext() in 2.5.0.
 *
 * \param ctx       The AES context to encrypt.
 * \param input     Plaintext block.
 * \param output    Output (ciphertext) block.
 */
MBEDTLS_DEPRECATED void mbedtls_aes_encrypt( mbedtls_aes_context *ctx,
                                             const unsigned char input[16],
                                             unsigned char output[16] );

/**
 * \brief           Deprecated internal AES block decryption function
 *                  without return value.
 *
 * \deprecated      Superseded by mbedtls_aes_decrypt_ext() in 2.5.0.
 *
 * \param ctx       The AES context to decrypt.
 * \param input     Ciphertext block.
 * \param output    Output (plaintext) block.
 */
MBEDTLS_DEPRECATED void mbedtls_aes_decrypt( mbedtls_aes_context *ctx,
                                             const unsigned char input[16],
                                             unsigned char output[16] );

#undef MBEDTLS_DEPRECATED
#endif /* !MBEDTLS_DEPRECATED_REMOVED */

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_AES_ALT */
#include "aes_alt.h"
#endif /* MBEDTLS_AES_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Checkup routine.
 *
 * \return         Zero if successful, or 1 if the test failed.
 */
int mbedtls_aes_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* aes.h */
