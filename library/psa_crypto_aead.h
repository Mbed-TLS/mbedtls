/*
 *  PSA AEAD layer on top of Mbed TLS software crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
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
 */

#ifndef PSA_CRYPTO_AEAD_H
#define PSA_CRYPTO_AEAD_H

#include <psa/crypto.h>

#if defined(MBEDTLS_PSA_BUILTIN_ALG_CCM) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_GCM) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305)
#define MBEDTLS_PSA_BUILTIN_AEAD
#endif

/** Process an AEAD encrypt-and-tag operation using mbed TLS libraries.
 *
 * \param attributes              Attributes of the key passed in the
 *                                \p key_buffer buffer. Pre-validated to be
 *                                compatible with the given \p alg algorithm.
 * \param[in] key_buffer          Plaintext key to use for this operation.
 * \param key_buffer_size         Amount of bytes contained in \p key_buffer.
 * \param alg                     The AEAD algorithm to compute
 *                                (\c PSA_ALG_XXX value such that
 *                                #PSA_ALG_IS_AEAD(\p alg) is true).
 * \param[in] nonce               Nonce or IV to use.
 * \param nonce_length            Size of the \p nonce buffer in bytes.
 * \param[in] additional_data     Additional data that will be authenticated
 *                                but not encrypted.
 * \param additional_data_length  Size of \p additional_data in bytes.
 * \param[in] plaintext           Data that will be authenticated and
 *                                encrypted.
 * \param plaintext_length        Size of \p plaintext in bytes.
 * \param[out] ciphertext         Output buffer for the authenticated and
 *                                encrypted data. The additional data is not
 *                                part of this output. For algorithms where the
 *                                encrypted data and the authentication tag
 *                                are defined as separate outputs, the
 *                                authentication tag is appended to the
 *                                encrypted data.
 * \param ciphertext_size         Size of the \p ciphertext buffer in bytes.
 *                                This must be at least
 *                                #PSA_AEAD_ENCRYPT_OUTPUT_SIZE(\p alg,
 *                                \p plaintext_length).
 * \param[out] ciphertext_length  On success, the size of the output
 *                                in the \p ciphertext buffer.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported by this library.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         \p ciphertext_size is too small
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 */
psa_status_t mbedtls_psa_aead_encrypt( const psa_key_attributes_t *attributes,
                                       const uint8_t *key_buffer,
                                       size_t key_buffer_size,
                                       psa_algorithm_t alg,
                                       const uint8_t *nonce,
                                       size_t nonce_length,
                                       const uint8_t *additional_data,
                                       size_t additional_data_length,
                                       const uint8_t *plaintext,
                                       size_t plaintext_length,
                                       uint8_t *ciphertext,
                                       size_t ciphertext_size,
                                       size_t *ciphertext_length );

/** Process an AEAD decrypt-and-verify operation using mbed TLS libraries.
 *
 * \param attributes              Attributes of the key passed in the
 *                                \p key_buffer buffer. Pre-validated to be
 *                                compatible with the given \p alg algorithm.
 * \param[in] key_buffer          Plaintext key to use for this operation.
 * \param key_buffer_size         Amount of bytes contained in \p key_buffer.
 * \param alg                     The AEAD algorithm to compute
 *                                (\c PSA_ALG_XXX value such that
 *                                #PSA_ALG_IS_AEAD(\p alg) is true).
 * \param[in] nonce               Nonce or IV to use.
 * \param nonce_length            Size of the \p nonce buffer in bytes.
 * \param[in] additional_data     Additional data that has been authenticated
 *                                but not encrypted.
 * \param additional_data_length  Size of \p additional_data in bytes.
 * \param[in] ciphertext          Data that has been authenticated and
 *                                encrypted. For algorithms where the
 *                                encrypted data and the authentication tag
 *                                are defined as separate inputs, the buffer
 *                                must contain the encrypted data followed
 *                                by the authentication tag.
 * \param ciphertext_length       Size of \p ciphertext in bytes.
 * \param[out] plaintext          Output buffer for the decrypted data.
 * \param plaintext_size          Size of the \p plaintext buffer in bytes.
 *                                This must be at least
 *                                #PSA_AEAD_DECRYPT_OUTPUT_SIZE(\p alg,
 *                                \p ciphertext_length).
 * \param[out] plaintext_length   On success, the size of the output
 *                                in the \p plaintext buffer.
 *
 * \retval #PSA_SUCCESS
 *         Successfully decrypted and validated the input.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The ciphertext is not authentic.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported by this library.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         \p plaintext_size or \p nonce_length is too small
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 */
psa_status_t mbedtls_psa_aead_decrypt( const psa_key_attributes_t *attributes,
                                       const uint8_t *key_buffer,
                                       size_t key_buffer_size,
                                       psa_algorithm_t alg,
                                       const uint8_t *nonce,
                                       size_t nonce_length,
                                       const uint8_t *additional_data,
                                       size_t additional_data_length,
                                       const uint8_t *ciphertext,
                                       size_t ciphertext_length,
                                       uint8_t *plaintext,
                                       size_t plaintext_size,
                                       size_t *plaintext_length );

/*
 * BEYOND THIS POINT, TEST DRIVER ENTRY POINTS ONLY.
 */

#if defined(PSA_CRYPTO_DRIVER_TEST)

psa_status_t mbedtls_transparent_test_driver_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length );

psa_status_t mbedtls_transparent_test_driver_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length );

psa_status_t mbedtls_opaque_test_driver_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length );

psa_status_t mbedtls_opaque_test_driver_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length );

#endif /* PSA_CRYPTO_DRIVER_TEST */

#endif /* PSA_CRYPTO_AEAD_H */
