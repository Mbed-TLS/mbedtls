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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS) && defined(PSA_CRYPTO_DRIVER_TEST)
#include "psa/crypto.h"
#include "psa_crypto_core.h"
#include "test/drivers/hash.h"

#if defined(MBEDTLS_SHA256_C)
#include "mbedtls/sha256.h"
#endif


#include <string.h>

/* Test driver implements SHA-256 only. Its default behaviour (when its return
 * status is not overridden through the hooks) is to take care of all SHA-256
 * operations when there's mbed TLS support for it, and return
 * PSA_ERROR_NOT_SUPPORTED for all others.
 * Set test_driver_hash_hooks.forced_status to PSA_ERROR_NOT_SUPPORTED to use
 * fallback even for SHA-256. */
test_driver_hash_hooks_t test_driver_hash_hooks = TEST_DRIVER_HASH_INIT;

psa_status_t test_transparent_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *hash, size_t hash_size,
    size_t *hash_length )
{
    test_driver_hash_hooks.hits++;

#if defined(MBEDTLS_SHA256_C)
    if( test_driver_hash_hooks.forced_status == PSA_SUCCESS )
    {
        if( alg != PSA_ALG_SHA_256 )
            return( PSA_ERROR_NOT_SUPPORTED );

        if( hash_size < 32)
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        *hash_length = 32;

        return( mbedtls_to_psa_error(
                    mbedtls_sha256_ret(
                        input, input_length, hash, 0 ) ) );
    }
    else
    {
        if( test_driver_hash_hooks.forced_output != NULL )
        {
            if( hash_size < test_driver_hash_hooks.forced_output_length)
                return( PSA_ERROR_BUFFER_TOO_SMALL );

            memcpy(hash,
                   test_driver_hash_hooks.forced_output,
                   test_driver_hash_hooks.forced_output_length);
            *hash_length = test_driver_hash_hooks.forced_output_length;
        }
        return( test_driver_hash_hooks.forced_status );
    }
#endif
    (void) alg;
    (void) input;
    (void) input_length;
    (void) hash;
    (void) hash_size;
    (void) hash_length;
    return( test_driver_hash_hooks.forced_status );
}

psa_status_t test_transparent_hash_setup(
    test_transparent_hash_operation_t *operation,
    psa_algorithm_t alg )
{
    test_driver_hash_hooks.hits++;

#if defined(MBEDTLS_SHA256_C)
    if( test_driver_hash_hooks.forced_status == PSA_SUCCESS )
    {
        if( alg != PSA_ALG_SHA_256 )
            return( PSA_ERROR_NOT_SUPPORTED );

        operation->alg = alg;
        mbedtls_sha256_init(&operation->context.sha256);
        return( mbedtls_to_psa_error(
                    mbedtls_sha256_starts_ret(
                        &operation->context.sha256, 0 ) ) );
    }
    else
        return( test_driver_hash_hooks.forced_status );
#endif
    (void) operation;
    (void) alg;
    return( test_driver_hash_hooks.forced_status );
}

psa_status_t test_transparent_hash_clone(
    const test_transparent_hash_operation_t *source_operation,
    test_transparent_hash_operation_t *target_operation )
{
    test_driver_hash_hooks.hits++;

#if defined(MBEDTLS_SHA256_C)
    if( test_driver_hash_hooks.forced_status == PSA_SUCCESS )
    {
        if( source_operation->alg != PSA_ALG_SHA_256 )
        {
            // Driver delegation tried to call us, but we never accepted
            // this operation.
            return( PSA_ERROR_BAD_STATE );
        }

        target_operation->alg = source_operation->alg;
        mbedtls_sha256_clone(&target_operation->context.sha256,
                             &source_operation->context.sha256);
        return( PSA_SUCCESS );
    }
    else
        return( test_driver_hash_hooks.forced_status );
#endif
    (void) source_operation;
    (void) target_operation;
    return( test_driver_hash_hooks.forced_status );
}

psa_status_t test_transparent_hash_update(
    test_transparent_hash_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    test_driver_hash_hooks.hits++;

#if defined(MBEDTLS_SHA256_C)
    if( test_driver_hash_hooks.forced_status == PSA_SUCCESS )
    {
        if( operation->alg != PSA_ALG_SHA_256 )
            return( PSA_ERROR_BAD_STATE );

        return( mbedtls_to_psa_error(
                    mbedtls_sha256_update_ret(
                        &operation->context.sha256,
                        input,
                        input_length) ) );
    }
    else
        return( test_driver_hash_hooks.forced_status );
#endif
    (void) operation;
    (void) input;
    (void) input_length;
    return( test_driver_hash_hooks.forced_status );
}

psa_status_t test_transparent_hash_finish(
    test_transparent_hash_operation_t *operation,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length )
{
    test_driver_hash_hooks.hits++;

#if defined(MBEDTLS_SHA256_C)
    if( test_driver_hash_hooks.forced_status == PSA_SUCCESS )
    {
        if( operation->alg != PSA_ALG_SHA_256 )
            return( PSA_ERROR_BAD_STATE );

        if( hash_size < 32 )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        psa_status_t status = mbedtls_to_psa_error(
                                mbedtls_sha256_finish_ret(
                                    &operation->context.sha256,
                                    hash ) );
        if( status == PSA_SUCCESS )
            *hash_length = 32;

        return( status );
    }
    else
    {
        if( test_driver_hash_hooks.forced_output != NULL )
        {
            if( hash_size < test_driver_hash_hooks.forced_output_length)
                return( PSA_ERROR_BUFFER_TOO_SMALL );

            memcpy(hash,
                   test_driver_hash_hooks.forced_output,
                   test_driver_hash_hooks.forced_output_length);
            *hash_length = test_driver_hash_hooks.forced_output_length;
        }
        return( test_driver_hash_hooks.forced_status );
    }
#endif
    (void) operation;
    (void) hash;
    (void) hash_size;
    (void) hash_length;
    return( test_driver_hash_hooks.forced_status );
}

psa_status_t test_transparent_hash_abort(
    test_transparent_hash_operation_t *operation )
{
    test_driver_hash_hooks.hits++;

#if defined(MBEDTLS_SHA256_C)
    if( test_driver_hash_hooks.forced_status == PSA_SUCCESS )
    {
        if( operation->alg == 0 )
            return( PSA_SUCCESS );

        if( operation->alg != PSA_ALG_SHA_256 )
            return( PSA_ERROR_BAD_STATE );

        mbedtls_sha256_free( &operation->context.sha256 );
        operation->alg = 0;
        return( PSA_SUCCESS );
    }
    else
        return( test_driver_hash_hooks.forced_status );
#endif
    (void) operation;
    return( test_driver_hash_hooks.forced_status );
}

#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
