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
#endif /* PSA_CRYPTO_ECP */
