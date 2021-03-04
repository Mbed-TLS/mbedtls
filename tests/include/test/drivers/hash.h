/*
 * Test driver for hash functions
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

#ifndef PSA_CRYPTO_TEST_DRIVERS_HASH_H
#define PSA_CRYPTO_TEST_DRIVERS_HASH_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(PSA_CRYPTO_DRIVER_TEST)
/* Include path is relative to the tests/include folder, which is the base
 * include path for including this (hash.h) test driver header. */
#include "../../library/psa_crypto_hash.h"

typedef struct {
    mbedtls_psa_hash_operation_t operation;
} test_transparent_hash_operation_t;

psa_status_t test_transparent_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length);

psa_status_t test_transparent_hash_setup(
    test_transparent_hash_operation_t *operation,
    psa_algorithm_t alg );

psa_status_t test_transparent_hash_clone(
    const test_transparent_hash_operation_t *source_operation,
    test_transparent_hash_operation_t *target_operation );

psa_status_t test_transparent_hash_update(
    test_transparent_hash_operation_t *operation,
    const uint8_t *input,
    size_t input_length );

psa_status_t test_transparent_hash_finish(
    test_transparent_hash_operation_t *operation,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length );

psa_status_t test_transparent_hash_abort(
    test_transparent_hash_operation_t *operation );

#endif /* PSA_CRYPTO_DRIVER_TEST */
#endif /* PSA_CRYPTO_TEST_DRIVERS_HASH_H */
