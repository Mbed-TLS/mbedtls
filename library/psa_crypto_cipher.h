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
    mbedtls_psa_cipher_operation_t *operation,
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
    mbedtls_psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg );

/** Generate an IV for a symmetric encryption operation.
 *
 * This function generates a random IV (initialization vector), nonce
 * or initial counter value for the encryption operation as appropriate
 * for the chosen algorithm, key type and key size.
 *
 * \note The signature of this function is that of a PSA driver
 *       cipher_generate_iv entry point. This function behaves as a
 *       cipher_generate_iv entry point as defined in the PSA driver
 *       interface specification for transparent drivers.
 *
 * \param[in,out] operation     Active cipher operation.
 * \param[out] iv               Buffer where the generated IV is to be written.
 * \param[in]  iv_size          Size of the \p iv buffer in bytes.
 * \param[out] iv_length        On success, the number of bytes of the
 *                              generated IV.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p iv buffer is too small.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 */
psa_status_t mbedtls_psa_cipher_generate_iv(
    mbedtls_psa_cipher_operation_t *operation,
    uint8_t *iv, size_t iv_size, size_t *iv_length );

/** Set the IV for a symmetric encryption or decryption operation.
 *
 * This function sets the IV (initialization vector), nonce
 * or initial counter value for the encryption or decryption operation.
 *
 * \note The signature of this function is that of a PSA driver
 *       cipher_set_iv entry point. This function behaves as a
 *       cipher_set_iv entry point as defined in the PSA driver
 *       interface specification for transparent drivers.
 *
 * \param[in,out] operation     Active cipher operation.
 * \param[in] iv                Buffer containing the IV to use.
 * \param[in] iv_length         Size of the IV in bytes.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The size of \p iv is not acceptable for the chosen algorithm,
 *         or the chosen algorithm does not use an IV.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 */
psa_status_t mbedtls_psa_cipher_set_iv(
    mbedtls_psa_cipher_operation_t *operation,
    const uint8_t *iv, size_t iv_length );

/** Encrypt or decrypt a message fragment in an active cipher operation.
 *
 * \note The signature of this function is that of a PSA driver
 *       cipher_update entry point. This function behaves as a
 *       cipher_update entry point as defined in the PSA driver
 *       interface specification for transparent drivers.
 *
 * \param[in,out] operation     Active cipher operation.
 * \param[in] input             Buffer containing the message fragment to
 *                              encrypt or decrypt.
 * \param[in] input_length      Size of the \p input buffer in bytes.
 * \param[out] output           Buffer where the output is to be written.
 * \param[in]  output_size      Size of the \p output buffer in bytes.
 * \param[out] output_length    On success, the number of bytes
 *                              that make up the returned output.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p output buffer is too small.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 */
psa_status_t mbedtls_psa_cipher_update(
    mbedtls_psa_cipher_operation_t *operation,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length );

/** Finish encrypting or decrypting a message in a cipher operation.
 *
 * \note The signature of this function is that of a PSA driver
 *       cipher_finish entry point. This function behaves as a
 *       cipher_finish entry point as defined in the PSA driver
 *       interface specification for transparent drivers.
 *
 * \param[in,out] operation     Active cipher operation.
 * \param[out] output           Buffer where the output is to be written.
 * \param[in]  output_size      Size of the \p output buffer in bytes.
 * \param[out] output_length    On success, the number of bytes
 *                              that make up the returned output.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The total input size passed to this operation is not valid for
 *         this particular algorithm. For example, the algorithm is a based
 *         on block cipher and requires a whole number of blocks, but the
 *         total input size is not a multiple of the block size.
 * \retval #PSA_ERROR_INVALID_PADDING
 *         This is a decryption operation for an algorithm that includes
 *         padding, and the ciphertext does not contain valid padding.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p output buffer is too small.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 */
psa_status_t mbedtls_psa_cipher_finish(
    mbedtls_psa_cipher_operation_t *operation,
    uint8_t *output, size_t output_size, size_t *output_length );

/** Abort a cipher operation.
 *
 * Aborting an operation frees all associated resources except for the
 * \p operation structure itself. Once aborted, the operation object
 * can be reused for another operation.
 *
 * \note The signature of this function is that of a PSA driver
 *       cipher_abort entry point. This function behaves as a
 *       cipher_abort entry point as defined in the PSA driver
 *       interface specification for transparent drivers.
 *
 * \param[in,out] operation     Initialized cipher operation.
 *
 * \retval #PSA_SUCCESS
 */
psa_status_t mbedtls_psa_cipher_abort( mbedtls_psa_cipher_operation_t *operation );

#endif /* PSA_CRYPTO_CIPHER_H */
