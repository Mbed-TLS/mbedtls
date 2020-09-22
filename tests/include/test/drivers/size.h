/*
 * Test driver for context size functions
 */
/*  Copyright The Mbed TLS Contributors
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

#ifndef PSA_CRYPTO_TEST_DRIVERS_SIZE_H
#define PSA_CRYPTO_TEST_DRIVERS_SIZE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(PSA_CRYPTO_DRIVER_TEST)
#include <psa/crypto_driver_common.h>

typedef struct {
    unsigned int context;
} test_driver_key_context_t;

/** \def TEST_DRIVER_KEY_CONTEXT_BASE_SIZE
 *
 * This macro returns the base size for the key context. It should include
 * the size for any driver context information stored with each key.
 */
#define TEST_DRIVER_KEY_CONTEXT_BASE_SIZE          sizeof(test_driver_key_context_t)

/** \def TEST_DRIVER_KEY_CONTEXT_KEY_PAIR_SIZE
 *
 * Number of bytes included in every key context for a key pair.
 */

#define TEST_DRIVER_KEY_CONTEXT_KEY_PAIR_SIZE      0

/** \def TEST_DRIVER_KEY_CONTEXT_PUBLIC_KEY_SIZE
 *
 * Number of bytes included in every key context for a public key.
 */
#define TEST_DRIVER_KEY_CONTEXT_PUBLIC_KEY_SIZE    0

/** \def TEST_DRIVER_KEY_CONTEXT_SYMMETRIC_FACTOR
 *
 * Every key context for a symmetric key includes this many times the key size.
 */
#define TEST_DRIVER_KEY_CONTEXT_SYMMETRIC_FACTOR   0

/** \def TEST_DRIVER_KEY_CONTEXT_STORE_PUBLIC_KEY
 *
 * If this is true for a key pair, the key context includes space for the public key.
 * If this is false, no additional space is added for the public key.
 */
#define TEST_DRIVER_KEY_CONTEXT_STORE_PUBLIC_KEY   0

/** \def TEST_DRIVER_KEY_CONTEXT_SIZE_FUNCTION
 *
 * If TEST_DRIVER_KEY_CONTEXT_SIZE_FUNCTION is defined, the test driver
 * provides a size_function entry point, otherwise, it does not.
 *
 * Some opaque drivers have the need to support a custom size for the storage
 * of key and context information. The size_function provides the ability to
 * provide that customization.
 */
//#define TEST_DRIVER_KEY_CONTEXT_SIZE_FUNCTION

#ifdef TEST_DRIVER_KEY_CONTEXT_SIZE_FUNCTION
size_t test_size_function(
    const psa_key_type_t key_type,
    const size_t key_bits );
#endif /* TEST_DRIVER_KEY_CONTEXT_SIZE_FUNCTION */

#endif /* PSA_CRYPTO_DRIVER_TEST */
#endif /* PSA_CRYPTO_TEST_DRIVERS_KEYGEN_H */
