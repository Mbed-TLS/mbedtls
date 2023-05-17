/**
 * \file mbedtls/config_crypto_adjust.h
 * \brief Adjust the legacy crypto configuration (various MBEDTLS_xxx symbols)
 *        to automatically enable dependencies or simplify some
 *        configuration checks.
 *
 * Do not include this header directly! It is automatically included
 * by public headers as needed.
 *
 * This header never automatically enables cryptographic mechanisms as such:
 * in the legacy crypto API, if A requires B then a user who wants A and
 * doesn't care about B must manually enable both A and B. In this header:
 *
 * - We enable automatic dependencies on sub-features such as xxx_LIGHT
 *   added after Mbed TLS 3.0 and mostly intended for internal purposes.
 * - We enable some internal dependencies on high-level interface modules
 *   such as MD, cipher and PK.
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

#ifndef MBEDTLS_CONFIG_CRYPTO_ADJUST_H
#define MBEDTLS_CONFIG_CRYPTO_ADJUST_H

/* Auto-enable MBEDTLS_CTR_DRBG_USE_128_BIT_KEY if
 * MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH and MBEDTLS_CTR_DRBG_C defined
 * to ensure a 128-bit key size in CTR_DRBG.
 */
#if defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH) && defined(MBEDTLS_CTR_DRBG_C)
#define MBEDTLS_CTR_DRBG_USE_128_BIT_KEY
#endif

/* Auto-enable MBEDTLS_MD_C if needed by a module that didn't require it
 * in a previous release, to ensure backwards compatibility.
 */
#if defined(MBEDTLS_PKCS5_C)
#define MBEDTLS_MD_C
#endif

/* Auto-enable MBEDTLS_MD_LIGHT based on MBEDTLS_MD_C.
 * This allows checking for MD_LIGHT rather than MD_LIGHT || MD_C.
 */
#if defined(MBEDTLS_MD_C)
#define MBEDTLS_MD_LIGHT
#endif

/* Auto-enable MBEDTLS_MD_LIGHT if needed by a module that didn't require it
 * in a previous release, to ensure backwards compatibility.
 */
#if defined(MBEDTLS_ECJPAKE_C) || \
    defined(MBEDTLS_PEM_PARSE_C) || \
    defined(MBEDTLS_ENTROPY_C) || \
    defined(MBEDTLS_PK_C) || \
    defined(MBEDTLS_PKCS12_C) || \
    defined(MBEDTLS_RSA_C) || \
    defined(MBEDTLS_SSL_TLS_C) || \
    defined(MBEDTLS_X509_USE_C) || \
    defined(MBEDTLS_X509_CREATE_C)
#define MBEDTLS_MD_LIGHT
#endif

/* MBEDTLS_ECP_LIGHT is auto-enabled by the following symbols:
 * - MBEDTLS_ECP_C because now it consists of MBEDTLS_ECP_LIGHT plus functions
 *   for curve arithmetic. As a consequence if MBEDTLS_ECP_C is required for
 *   some reason, then MBEDTLS_ECP_LIGHT should be enabled as well.
 * - MBEDTLS_PK_PARSE_EC_EXTENDED and MBEDTLS_PK_PARSE_EC_COMPRESSED because
 *   these features are not supported in PSA so the only way to have them is
 *   to enable the built-in solution.
 *   Both of them are temporary dependencies:
 *   - PK_PARSE_EC_EXTENDED will be removed after #7779 and #7789
 *   - support for compressed points should also be added to PSA, but in this
 *     case there is no associated issue to track it yet.
 * - PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE because Weierstrass key derivation
 *   still depends on ECP_LIGHT.
 * - PK_C + USE_PSA + PSA_WANT_ALG_ECDSA is a temporary dependency which will
 *   be fixed by #7453.
 */
#if defined(MBEDTLS_ECP_C) || \
    defined(MBEDTLS_PK_PARSE_EC_EXTENDED) || \
    defined(MBEDTLS_PK_PARSE_EC_COMPRESSED) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_DERIVE)
#define MBEDTLS_ECP_LIGHT
#endif

/* MBEDTLS_PK_PARSE_EC_COMPRESSED is introduced in MbedTLS version 3.5, while
 * in previous version compressed points were automatically supported as long
 * as PK_PARSE_C and ECP_C were enabled. As a consequence, for backward
 * compatibility, we auto-enable PK_PARSE_EC_COMPRESSED when these conditions
 * are met. */
#if defined(MBEDTLS_PK_PARSE_C) && defined(MBEDTLS_ECP_C)
#define MBEDTLS_PK_PARSE_EC_COMPRESSED
#endif

/* If MBEDTLS_PSA_CRYPTO_C is defined, make sure MBEDTLS_PSA_CRYPTO_CLIENT
 * is defined as well to include all PSA code.
 */
#if defined(MBEDTLS_PSA_CRYPTO_C)
#define MBEDTLS_PSA_CRYPTO_CLIENT
#endif /* MBEDTLS_PSA_CRYPTO_C */

/* The PK wrappers need pk_write functions to format RSA key objects
 * when they are dispatching to the PSA API. This happens under USE_PSA_CRYPTO,
 * and also even without USE_PSA_CRYPTO for mbedtls_pk_sign_ext(). */
#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_RSA_C)
#define MBEDTLS_PK_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PK_PARSE_C
#endif

#endif /* MBEDTLS_CONFIG_CRYPTO_ADJUST_H */
