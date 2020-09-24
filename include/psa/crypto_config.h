/**
 * \file psa/crypto_config.h
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

#ifndef PSA_CRYPTO_CONFIG_H
#define PSA_CRYPTO_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#define PSA_WANT_ALG_ECDSA

#define PSA_WANT_ALG_ECDSA_DETERMINISTIC

//#define MBEDTLS_PSA_ACCEL_ALG_ECDSA
//#define MBEDTLS_PSA_ACCEL_ALG_ECDSA_DETERMINISTIC

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_CONFIG_H */
