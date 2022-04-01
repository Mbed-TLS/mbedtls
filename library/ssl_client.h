/**
 *  TLS 1.2 and 1.3 client-side functions
 *
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

#ifndef MBEDTLS_SSL_CLIENT_H
#define MBEDTLS_SSL_CLIENT_H

#include "common.h"

#if defined(MBEDTLS_SSL_TLS_C)
#include "ssl_misc.h"
#endif

#include <stddef.h>

/**
 * \brief Validate cipher suite against config in SSL context.
 *
 * \param ssl            SSL context
 * \param suite_info     Cipher suite to validate
 * \param min_minor_ver  Minimal minor version to accept a cipher suite
 * \param max_minor_ver  Maximal minor version to accept a cipher suite
 *
 * \return 0 if valid, negative value otherwise.
 */
int mbedtls_ssl_validate_ciphersuite(
    const mbedtls_ssl_context *ssl,
    const mbedtls_ssl_ciphersuite_t *suite_info,
    int min_minor_ver, int max_minor_ver );

int mbedtls_ssl_write_client_hello( mbedtls_ssl_context *ssl );

#endif /* MBEDTLS_SSL_CLIENT_H */
