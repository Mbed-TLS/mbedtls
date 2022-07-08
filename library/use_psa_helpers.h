/**
 *  Internal macros for parts of the code governed by MBEDTLS_USE_PSA_CRYPTO.
 *  Some macros allow checking if an algorithm is available, either via the
 *  legacy API or the PSA Crypto API, depending on MBEDTLS_USE_PSA_CRYPTO;
 *  when possible, they're named after the corresponding PSA_WANT_ macro.
 *  Other macros provide max sizes or similar information in a USE_PSA-aware
 *  way; they're name after a similar constant from the legacy API or PSA.
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

#ifndef MBEDTLS_USE_PSA_HELPERS_H
#define MBEDTLS_USE_PSA_HELPERS_H

#include "common.h"

/* Hash algorithms */
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_MD5_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_MD5) )
#define MBEDTLS_USE_PSA_WANT_ALG_MD5
#endif
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_RIPEMD160_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_RIPEMD160) )
#define MBEDTLS_USE_PSA_WANT_ALG_RIPEMD160
#endif
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_SHA1_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_1) )
#define MBEDTLS_USE_PSA_WANT_ALG_SHA_1
#endif
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_SHA224_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_224) )
#define MBEDTLS_USE_PSA_WANT_ALG_SHA_224
#endif
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_SHA256_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_256) )
#define MBEDTLS_USE_PSA_WANT_ALG_SHA_256
#endif
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_SHA384_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_384) )
#define MBEDTLS_USE_PSA_WANT_ALG_SHA_384
#endif
#if ( !defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_SHA512_C) ) || \
    ( defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_512) )
#define MBEDTLS_USE_PSA_WANT_ALG_SHA_512
#endif

/* Hash information */
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#define MBEDTLS_USE_PSA_MD_MAX_SIZE PSA_HASH_MAX_SIZE
#else
#define MBEDTLS_USE_PSA_MD_MAX_SIZE MBEDTLS_MD_MAX_SIZE
#endif

#endif /* MBEDTLS_USE_PSA_HELPERS_H */
