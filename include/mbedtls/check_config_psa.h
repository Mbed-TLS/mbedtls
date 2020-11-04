/**
 * \file check_config_psa.h
 *
 * \brief Consistency checks for PSA configuration options
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

/*
 * It is recommended to include this file from your config_psa.h
 * in order to catch dependency issues early.
 */

#ifndef MBEDTLS_CHECK_CONFIG_PSA_H
#define MBEDTLS_CHECK_CONFIG_PSA_H

#if defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) && \
    !( defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR) || \
       defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_PUBLIC_KEY) || \
       defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) || \
       defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY) )
#error "MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA defined, but not all prerequisites"
#endif

#endif /* MBEDTLS_CHECK_CONFIG_PSA_H */
