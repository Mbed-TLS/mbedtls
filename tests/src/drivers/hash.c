/*
 * Test driver for hash entry points.
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS) && defined(PSA_CRYPTO_DRIVER_TEST)
#include "psa_crypto_hash.h"

#include "test/drivers/hash.h"

test_driver_hash_hooks_t test_driver_hash_hooks = TEST_DRIVER_HASH_INIT;

psa_status_t test_transparent_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *hash, size_t hash_size, size_t *hash_length )
{
    test_driver_hash_hooks.hits++;

    if( test_driver_hash_hooks.forced_status != PSA_SUCCESS )
    {
         test_driver_hash_hooks.driver_status =
             test_driver_hash_hooks.forced_status;
    }
    else
    {
        test_driver_hash_hooks.driver_status =
            mbedtls_transparent_test_driver_hash_compute(
                alg, input, input_length,
                hash, hash_size, hash_length );
    }

    return( test_driver_hash_hooks.driver_status );
}

psa_status_t test_transparent_hash_setup(
    mbedtls_transparent_test_driver_hash_operation_t *operation,
    psa_algorithm_t alg )
{
    test_driver_hash_hooks.hits++;

    if( test_driver_hash_hooks.forced_status != PSA_SUCCESS )
    {
         test_driver_hash_hooks.driver_status =
             test_driver_hash_hooks.forced_status;
    }
    else
    {
        test_driver_hash_hooks.driver_status =
            mbedtls_transparent_test_driver_hash_setup( operation, alg );
    }

    return( test_driver_hash_hooks.driver_status );
}

psa_status_t test_transparent_hash_clone(
    const mbedtls_transparent_test_driver_hash_operation_t *source_operation,
    mbedtls_transparent_test_driver_hash_operation_t *target_operation )
{
    test_driver_hash_hooks.hits++;

    if( test_driver_hash_hooks.forced_status != PSA_SUCCESS )
    {
         test_driver_hash_hooks.driver_status =
             test_driver_hash_hooks.forced_status;
    }
    else
    {
        test_driver_hash_hooks.driver_status =
            mbedtls_transparent_test_driver_hash_clone( source_operation,
                                                        target_operation );
    }

    return( test_driver_hash_hooks.driver_status );
}

psa_status_t test_transparent_hash_update(
    mbedtls_transparent_test_driver_hash_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    test_driver_hash_hooks.hits++;

    if( test_driver_hash_hooks.forced_status != PSA_SUCCESS )
    {
         test_driver_hash_hooks.driver_status =
             test_driver_hash_hooks.forced_status;
    }
    else
    {
        test_driver_hash_hooks.driver_status =
            mbedtls_transparent_test_driver_hash_update(
                operation, input, input_length );
    }

    return( test_driver_hash_hooks.driver_status );
}

psa_status_t test_transparent_hash_finish(
    mbedtls_transparent_test_driver_hash_operation_t *operation,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length )
{
    test_driver_hash_hooks.hits++;

    if( test_driver_hash_hooks.forced_status != PSA_SUCCESS )
    {
         test_driver_hash_hooks.driver_status =
             test_driver_hash_hooks.forced_status;
    }
    else
    {
        test_driver_hash_hooks.driver_status =
            mbedtls_transparent_test_driver_hash_finish(
                operation, hash, hash_size, hash_length );
    }

    return( test_driver_hash_hooks.driver_status );
}

psa_status_t test_transparent_hash_abort(
    mbedtls_transparent_test_driver_hash_operation_t *operation )
{
    test_driver_hash_hooks.hits++;

    if( test_driver_hash_hooks.forced_status != PSA_SUCCESS )
    {
         test_driver_hash_hooks.driver_status =
             test_driver_hash_hooks.forced_status;
    }
    else
    {
        test_driver_hash_hooks.driver_status =
            mbedtls_transparent_test_driver_hash_abort( operation );
    }

    return( test_driver_hash_hooks.driver_status );
}
#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
