/**
 * \file x509_invasive.h
 *
 * \brief x509 module: interfaces for invasive testing only.
 *
 * The interfaces in this file are intended for testing purposes only.
 * They SHOULD NOT be made available in library integrations except when
 * building the library for testing.
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

#ifndef MBEDTLS_X509_INVASIVE_H
#define MBEDTLS_X509_INVASIVE_H

#include "common.h"

#if defined(MBEDTLS_TEST_HOOKS)

/**
 * \brief          This function parses a CN string as an IP address.
 *
 * \param cn       The CN string to parse. CN string MUST be NUL-terminated.
 * \param dst      The target buffer to populate with the binary IP address.
 *                 The buffer MUST be 16 bytes to save IPv6, and should be
 *                 4-byte aligned if the result will be used as struct in_addr.
 *                 e.g. uint32_t dst[4]
 *
 * \note           \cn is parsed as an IPv6 address if string contains ':',
 *                 else \cn is parsed as an IPv4 address.
 *
 * \return         Length of binary IP address; num bytes written to target.
 * \return         \c 0 on failure to parse CN string as an IP address.
 */
size_t mbedtls_x509_crt_parse_cn_inet_pton(const char *cn, void *dst);

#endif /* MBEDTLS_TEST_HOOKS */

#endif /* MBEDTLS_X509_INVASIVE_H */
