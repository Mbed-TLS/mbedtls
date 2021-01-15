/*
 * Test driver for hash functions.
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
#include <psa/crypto_driver_common.h>

#if defined(MBEDTLS_SHA256_C)
#include "mbedtls/sha256.h"
#endif

typedef struct {
    psa_algorithm_t alg;
    union {
        uint32_t dummy;
#if defined(MBEDTLS_SHA256_C)
        mbedtls_sha256_context sha256;
#endif
    } context;
} test_transparent_hash_operation_t;

typedef struct {
    /* If non-null, on success, copy this to the output. */
    void *forced_output;
    size_t forced_output_length;
    /* If not PSA_SUCCESS, return this error code instead of processing the
     * function call. */
    psa_status_t forced_status;
    /* Count the amount of times one of the signature driver functions is called. */
    unsigned long hits;
} test_driver_hash_hooks_t;

#define TEST_DRIVER_HASH_INIT { NULL, 0, PSA_ERROR_NOT_SUPPORTED, 0 }
static inline test_driver_hash_hooks_t test_driver_hash_hooks_init( void )
{
    const test_driver_hash_hooks_t v = TEST_DRIVER_HASH_INIT;
    return( v );
}

extern test_driver_hash_hooks_t test_driver_hash_hooks;

psa_status_t test_transparent_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *hash, size_t hash_size,
    size_t *hash_length );

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
