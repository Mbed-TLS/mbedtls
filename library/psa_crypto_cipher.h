/*
 *  PSA cipher driver entry points
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

#ifndef PSA_CRYPTO_CIPHER_H
#define PSA_CRYPTO_CIPHER_H

#include <psa/crypto.h>

/**
 * \brief Set the key for a multipart symmetric encryption operation.
 *
 * \note The signature of this function is that of a PSA driver
 *       cipher_encrypt_setup entry point. This function behaves as a
 *       cipher_encrypt_setup entry point as defined in the PSA driver
 *       interface specification for transparent drivers.
 *
 * \param[in,out] operation     The operation object to set up. It has been
 *                              initialized as per the documentation for
 *                              #psa_cipher_operation_t and not yet in use.
 * \param[in] attributes        The attributes of the key to use for the
 *                              operation.
 * \param[in] key_buffer        The buffer containing the key context.
 * \param[in] key_buffer_size   Size of the \p key_buffer buffer in bytes.
 * \param[in] alg               The cipher algorithm to compute
 *                              (\c PSA_ALG_XXX value such that
 *                              #PSA_ALG_IS_CIPHER(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 */
psa_status_t mbedtls_psa_cipher_encrypt_setup(
    psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg );

/**
 * \brief Set the key for a multipart symmetric decryption operation.
 *
 * \note The signature of this function is that of a PSA driver
 *       cipher_decrypt_setup entry point. This function behaves as a
 *       cipher_decrypt_setup entry point as defined in the PSA driver
 *       interface specification for transparent drivers.
 *
 * \param[in,out] operation     The operation object to set up. It has been
 *                              initialized as per the documentation for
 *                              #psa_cipher_operation_t and not yet in use.
 * \param[in] attributes        The attributes of the key to use for the
 *                              operation.
 * \param[in] key_buffer        The buffer containing the key context.
 * \param[in] key_buffer_size   Size of the \p key_buffer buffer in bytes.
 * \param[in] alg               The cipher algorithm to compute
 *                              (\c PSA_ALG_XXX value such that
 *                              #PSA_ALG_IS_CIPHER(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 */
psa_status_t mbedtls_psa_cipher_decrypt_setup(
    psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg );

#endif /* PSA_CRYPTO_CIPHER_H */
