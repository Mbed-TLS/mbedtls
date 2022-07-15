/**
 *  Internal macros for parts of the code that depend on an algorithm being
 *  available either via the legacy API or the PSA Crypto API.
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

#ifndef MBEDTLS_OR_PSA_HELPERS_H
#define MBEDTLS_OR_PSA_HELPERS_H

#include "common.h"

/* Hash algorithms */
#if defined(MBEDTLS_MD5_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_MD5) )
#define MBEDTLS_OR_PSA_WANT_ALG_MD5
#endif
#if defined(MBEDTLS_RIPEMD160_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_RIPEMD160) )
#define MBEDTLS_OR_PSA_WANT_ALG_RIPEMD160
#endif
#if defined(MBEDTLS_SHA1_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_1) )
#define MBEDTLS_OR_PSA_WANT_ALG_SHA_1
#endif
#if defined(MBEDTLS_SHA224_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_224) )
#define MBEDTLS_OR_PSA_WANT_ALG_SHA_224
#endif
#if defined(MBEDTLS_SHA256_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_256) )
#define MBEDTLS_OR_PSA_WANT_ALG_SHA_256
#endif
#if defined(MBEDTLS_SHA384_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_384) )
#define MBEDTLS_OR_PSA_WANT_ALG_SHA_384
#endif
#if defined(MBEDTLS_SHA512_C) || \
    ( defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_512) )
#define MBEDTLS_OR_PSA_WANT_ALG_SHA_512
#endif

#endif /* MBEDTLS_OR_PSA_HELPERS_H */
