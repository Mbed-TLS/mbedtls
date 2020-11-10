/**
 * \file mbedtls/config_psa.h
 * \brief PSA crypto configuration options (set of defines)
 *
 *  This set of compile-time options takes settings defined in
 *  include/mbedtls/config.h and include/psa/crypto_config.h and uses
 *  those definitions to define symbols used in the library code.
 *
 *  Users and integrators should not edit this file, please edit
 *  include/mbedtls/config.h for MBETLS_XXX settings or
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

#if defined(MBEDTLS_PSA_CRYPTO_CONFIG)
#include "psa/crypto_config.h"
#endif /* defined(MBEDTLS_PSA_CRYPTO_CONFIG) */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_PSA_CRYPTO_CONFIG)

#if defined(PSA_WANT_ALG_ECDSA)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA)
#define MBEDTLS_PSA_BUILTIN_ALG_ECDSA                   1
#define MBEDTLS_ECDSA_C
#endif /* !MBEDTLS_PSA_ACCEL_ALG_ECDSA */
#endif /* PSA_WANT_ALG_ECDSA */

#if defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA)
#define MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA     1
#define MBEDTLS_ECDSA_DETERMINISTIC
#define MBEDTLS_ECDSA_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_MD_C
#endif /* !MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA */
#endif /* PSA_WANT_ALG_DETERMINISTIC_ECDSA */

#if defined(PSA_WANT_ALG_ECDH)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_ECDH)
#define MBEDTLS_PSA_BUILTIN_ALG_ECDH                    1
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECP_C
#define MBEDTLS_BIGNUM_C
#endif /* !MBEDTLS_PSA_ACCEL_ALG_ECDH */
#endif /* PSA_WANT_ALG_ECDH */

#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY              1
#define MBEDTLS_ECP_C
#define MBEDTLS_BIGNUM_C
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY */
#endif /* PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY */

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR                1
#define MBEDTLS_ECP_C
#define MBEDTLS_BIGNUM_C
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR */
#endif /* PSA_WANT_KEY_TYPE_ECC_KEY_PAIR */

#if defined(PSA_WANT_ALG_HMAC)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_HMAC)
#define MBEDTLS_PSA_BUILTIN_ALG_HMAC                    1
#define MBEDTLS_MD_C
#endif /* !MBEDTLS_PSA_ACCEL_ALG_HMAC */
#endif /* PSA_WANT_ALG_HMAC */

#if defined(PSA_WANT_ALG_HKDF)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_HKDF)
#define MBEDTLS_PSA_BUILTIN_ALG_HMAC                    1
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF                    1
#define MBEDTLS_HKDF_C
#define MBEDTLS_MD_C
#endif /* !MBEDTLS_PSA_ACCEL_ALG_HKDF */
#endif /* PSA_WANT_ALG_HKDF */

#if defined(PSA_WANT_ALG_RSA_OAEP)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_RSA_OAEP)
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP                1
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS1_V21
#endif /* !MBEDTLS_PSA_ACCEL_ALG_RSA_OAEP */
#endif /* PSA_WANT_ALG_RSA_OAEP */

#if defined(PSA_WANT_ALG_RSA_PSS)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PSS)
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS                 1
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS1_V21
#endif /* !MBEDTLS_PSA_ACCEL_ALG_RSA_PSS */
#endif /* PSA_WANT_ALG_RSA_PSS */

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_CRYPT)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_CRYPT)
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT      1
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS1_V15
#endif /* !MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_CRYPT */
#endif /* PSA_WANT_ALG_RSA_PKCS1V15_CRYPT */

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN)
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN       1
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS1_V15
#endif /* !MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN */
#endif /* PSA_WANT_ALG_RSA_PKCS1V15_SIGN */

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR       1
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_GENPRIME
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR */
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR */

#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY)
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY     1
#define MBEDTLS_RSA_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_GENPRIME
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY */
#endif /* PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY */

#else /* MBEDTLS_PSA_CRYPTO_CONFIG */

/*
 * Ensure PSA_WANT_* defines are setup properly if MBEDTLS_PSA_CRYPTO_CONFIG
 * is not defined
 */
#if defined(MBEDTLS_ECDSA_C)
#define MBEDTLS_PSA_BUILTIN_ALG_ECDSA                   1

// Only add in DETERMINISTIC support if ECDSA is also enabled
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
#define MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA     1
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

#endif /* MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_ECDH_C)
#define MBEDTLS_PSA_BUILTIN_ALG_ECDH                    1
#endif /* MBEDTLS_ECDH_C */

#if defined(MBEDTLS_ECP_C)
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR       1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY     1
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_MD_C)
#define MBEDTLS_PSA_BUILTIN_ALG_HMAC                    1
#endif /* MBEDTLS_MD_C */

#if defined(MBEDTLS_HKDF_C)
#define MBEDTLS_PSA_BUILTIN_ALG_HMAC                    1
#define MBEDTLS_PSA_BUILTIN_ALG_HKDF                    1
#endif /* MBEDTLS_HKDF_C */

#if defined(MBEDTLS_RSA_C)
#if defined(MBEDTLS_PKCS1_V15)
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT      1
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN       1
#endif /* MBEDTLSS_PKCS1_V15 */
#if defined(MBEDTLS_PKCS1_V21)
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP                1
#define MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS                 1
#endif /* MBEDTLS_PKCS1_V21 */
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR       1
#define MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY     1
#endif /* MBEDTLS_RSA_C */

#endif /* MBEDTLS_PSA_CRYPTO_CONFIG */

#include "mbedtls/check_config_psa.h"

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CONFIG_PSA_H */
