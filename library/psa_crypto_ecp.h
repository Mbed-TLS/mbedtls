/*
 *  PSA ECP layer on top of Mbed TLS crypto
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

#ifndef PSA_CRYPTO_ECP_H
#define PSA_CRYPTO_ECP_H

#include <psa/crypto.h>
#include <mbedtls/ecp.h>

/** Load the contents of a key buffer into an internal ECP representation
 *
 * \param[in] type          The type of key contained in \p data.
 * \param[in] data          The buffer from which to load the representation.
 * \param[in] data_length   The size in bytes of \p data.
 * \param[out] p_ecp        Returns a pointer to an ECP context on success.
 *                          The caller is responsible for freeing both the
 *                          contents of the context and the context itself
 *                          when done.
 */
psa_status_t mbedtls_psa_ecp_load_representation( psa_key_type_t type,
                                                  const uint8_t *data,
                                                  size_t data_length,
                                                  mbedtls_ecp_keypair **p_ecp );

/** Export an ECP key to export representation
 *
 * \param[in] type          The type of key (public/private) to export
 * \param[in] ecp           The internal ECP representation from which to export
 * \param[out] data         The buffer to export to
 * \param[in] data_size     The length of the buffer to export to
 * \param[out] data_length  The amount of bytes written to \p data
 */
psa_status_t mbedtls_psa_ecp_export_key( psa_key_type_t type,
                                         mbedtls_ecp_keypair *ecp,
                                         uint8_t *data,
                                         size_t data_size,
                                         size_t *data_length );

/** Export an ECP public key or the public part of an ECP key pair in binary
 *  format.
 *
 * \note The signature of this function is that of a PSA driver
 *       export_public_key entry point. This function behaves as an
 *       export_public_key entry point as defined in the PSA driver interface
 *       specification.
 *
 * \param[in]  attributes       The attributes for the key to export.
 * \param[in]  key_buffer       Material or context of the key to export.
 * \param[in]  key_buffer_size  Size of the \p key_buffer buffer in bytes.
 * \param[out] data             Buffer where the key data is to be written.
 * \param[in]  data_size        Size of the \p data buffer in bytes.
 * \param[out] data_length      On success, the number of bytes written in
 *                              \p data
 *
 * \retval #PSA_SUCCESS  The ECP public key was exported successfully.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 * \retval #PSA_ERROR_STORAGE_FAILURE
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 */
psa_status_t mbedtls_psa_ecp_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length );

/*
 * BEYOND THIS POINT, TEST DRIVER ENTRY POINTS ONLY.
 */

#if defined(PSA_CRYPTO_DRIVER_TEST)
psa_status_t mbedtls_transparent_test_driver_ecp_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length );
#endif /* PSA_CRYPTO_DRIVER_TEST */

#endif /* PSA_CRYPTO_ECP_H */
