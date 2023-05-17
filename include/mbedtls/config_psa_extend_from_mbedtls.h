/**
 * \file mbedtls/config_psa_extend_from_mbedtls.h
 * \brief Extend the PSA crypto configuration (PSA_WANT_xxx) based on
 *        the legacy Mbed TLS crypto configuration (MBEDTLS_xxx).
 *
 * Do not include this header directly! It is automatically included
 * by public headers as needed.
 *
 * This file is used when #MBEDTLS_PSA_CRYPTO_C is enabled, regardless
 * of the status of #MBEDTLS_PSA_CRYPTO_CONFIG.
 *
 * This file automatically enables certain features when it would be
 * too complicated and basically useless not to (e.g. when there is
 * no practical use for enabling A without B, or when A+B requires almost
 * no extra code compared with A lone).
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

#ifndef MBEDTLS_CONFIG_PSA_EXTEND_FROM_MBEDTLS_H
#define MBEDTLS_CONFIG_PSA_EXTEND_FROM_MBEDTLS_H

/****************************************************************/
/* Hashes that are built in are also enabled in PSA.
 * This simplifies dependency declarations especially
 * for modules that obey MBEDTLS_USE_PSA_CRYPTO. */
/****************************************************************/

#if defined(MBEDTLS_MD5_C)
#define PSA_WANT_ALG_MD5 1
#endif

#if defined(MBEDTLS_RIPEMD160_C)
#define PSA_WANT_ALG_RIPEMD160 1
#endif

#if defined(MBEDTLS_SHA1_C)
#define PSA_WANT_ALG_SHA_1 1
#endif

#if defined(MBEDTLS_SHA224_C)
#define PSA_WANT_ALG_SHA_224 1
#endif

#if defined(MBEDTLS_SHA256_C)
#define PSA_WANT_ALG_SHA_256 1
#endif

#if defined(MBEDTLS_SHA384_C)
#define PSA_WANT_ALG_SHA_384 1
#endif

#if defined(MBEDTLS_SHA512_C)
#define PSA_WANT_ALG_SHA_512 1
#endif

#endif /* MBEDTLS_CONFIG_PSA_EXTEND_FROM_MBEDTLS_H */
