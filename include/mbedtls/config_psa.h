/**
 * \file mbedtls/config_psa.h
 * \brief PSA crypto configuration options (set of defines)
 *
 *  This set of compile-time options takes settings defined in
 *  include/mbedtls/mbedtls_config.h and include/psa/crypto_config.h and uses
 *  those definitions to define symbols used in the library code.
 *
 *  Users and integrators should not edit this file, please edit
 *  include/mbedtls/mbedtls_config.h for MBEDTLS_XXX settings or
 *  include/psa/crypto_config.h for PSA_WANT_XXX settings.
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

#ifndef MBEDTLS_CONFIG_PSA_H
#define MBEDTLS_CONFIG_PSA_H

#include "psa/crypto_legacy.h"

/****************************************************************/
/* De facto synonyms */
/****************************************************************/

#if defined(PSA_WANT_ALG_ECDSA_ANY) && !defined(PSA_WANT_ALG_ECDSA)
#define PSA_WANT_ALG_ECDSA PSA_WANT_ALG_ECDSA_ANY
#elif !defined(PSA_WANT_ALG_ECDSA_ANY) && defined(PSA_WANT_ALG_ECDSA)
#define PSA_WANT_ALG_ECDSA_ANY PSA_WANT_ALG_ECDSA
#endif

#if defined(PSA_WANT_ALG_CCM_STAR_NO_TAG) && !defined(PSA_WANT_ALG_CCM)
#define PSA_WANT_ALG_CCM PSA_WANT_ALG_CCM_STAR_NO_TAG
#elif !defined(PSA_WANT_ALG_CCM_STAR_NO_TAG) && defined(PSA_WANT_ALG_CCM)
#define PSA_WANT_ALG_CCM_STAR_NO_TAG PSA_WANT_ALG_CCM
#endif

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW) && !defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW
#elif !defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW) && defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN_RAW PSA_WANT_ALG_RSA_PKCS1V15_SIGN
#endif

#if defined(PSA_WANT_ALG_RSA_PSS_ANY_SALT) && !defined(PSA_WANT_ALG_RSA_PSS)
#define PSA_WANT_ALG_RSA_PSS PSA_WANT_ALG_RSA_PSS_ANY_SALT
#elif !defined(PSA_WANT_ALG_RSA_PSS_ANY_SALT) && defined(PSA_WANT_ALG_RSA_PSS)
#define PSA_WANT_ALG_RSA_PSS_ANY_SALT PSA_WANT_ALG_RSA_PSS
#endif


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


/****************************************************************/
/* Require built-in implementations based on PSA requirements */
/****************************************************************/

#if defined(MBEDTLS_PSA_CRYPTO_CONFIG)

#include "config_mbedtls_from_psa.h"

/****************************************************************/
/* Infer PSA requirements from Mbed TLS capabilities */
/****************************************************************/

#else /* MBEDTLS_PSA_CRYPTO_CONFIG */

/*
 * Ensure PSA_WANT_* defines are setup properly if MBEDTLS_PSA_CRYPTO_CONFIG
 * is not defined
 */

#include "config_psa_from_mbedtls.h"

#endif /* MBEDTLS_PSA_CRYPTO_CONFIG */

#if defined(PSA_WANT_ALG_JPAKE)
#define PSA_WANT_ALG_SOME_PAKE 1
#endif

/* Even though KEY_PAIR symbols' feature several level of support (BASIC, IMPORT,
 * EXPORT, GENERATE, DERIVE) we're not planning to have support only for BASIC
 * without IMPORT/EXPORT since these last 2 features are strongly used in tests.
 * In general it is allowed to include more feature than what is strictly
 * requested.
 * As a consequence IMPORT and EXPORT features will be automatically enabled
 * as soon as the BASIC one is. */
#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT 1
#endif

/* See description above */
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_BASIC)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_IMPORT 1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_EXPORT 1
#endif

/* Temporary internal migration helpers */
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC) || \
    defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT) || \
    defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT) || \
    defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE)
#define MBEDTLS_PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_LEGACY
#endif

/* Temporary internal migration helpers */
#if defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_BASIC) || \
    defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_IMPORT) || \
    defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_EXPORT) || \
    defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_GENERATE)
#define MBEDTLS_PSA_WANT_KEY_TYPE_DH_KEY_PAIR_LEGACY
#endif

/* These features are always enabled. */
#define PSA_WANT_KEY_TYPE_DERIVE 1
#define PSA_WANT_KEY_TYPE_PASSWORD 1
#define PSA_WANT_KEY_TYPE_PASSWORD_HASH 1
#define PSA_WANT_KEY_TYPE_RAW_DATA 1

#endif /* MBEDTLS_CONFIG_PSA_H */
