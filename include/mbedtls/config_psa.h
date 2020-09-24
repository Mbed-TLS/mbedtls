/**
 * \file mbedtls/config_psa.h
 * \brief PSA crypto configuration options (set of defines)
 *
 *  This set of compile-time options may be used to enable
 *  or disable PSA crypto features selectively. This will aid
 *  in reducing the size of the library by removing unused code.
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

#include "psa/crypto_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_PSA_CRYPTO_CONFIG)

#if defined(PSA_WANT_ALG_ECDSA)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA)
#define MBEDTLS_PSA_BUILTIN_ALG_ECDSA
#else /* !defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA) */
#define MBEDTLS_ECDSA_C
#endif /* !defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA) */
#endif /* defined(PSA_WANT_ALG_ECDSA) */

#if defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
#if !defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA_DETERMINISTIC)
#define MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA
#else /*  && !defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA_DETERMINISTIC) */
#define MBEDTLS_ECDSA_DETERMINISTIC
#endif /* !defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA_DETERMINISTIC) */
#endif /* defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA) */

#endif /* MBEDTLS_PSA_CRYPTO_CONFIG */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CONFIG_PSA_H */
