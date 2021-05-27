/*
 * Test driver for MAC entry points.
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

#include <test/helpers.h>

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS) && defined(PSA_CRYPTO_DRIVER_TEST)
#include "psa_crypto_mac.h"

#include "test/drivers/mac.h"

mbedtls_test_driver_mac_hooks_t mbedtls_test_driver_mac_hooks =
    MBEDTLS_TEST_DRIVER_MAC_INIT;

psa_status_t mbedtls_test_transparent_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_transparent_test_driver_mac_compute(
                attributes, key_buffer, key_buffer_size, alg,
                input, input_length,
                mac, mac_size, mac_length );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

psa_status_t mbedtls_test_transparent_mac_sign_setup(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_transparent_test_driver_mac_sign_setup(
                operation, attributes, key_buffer, key_buffer_size, alg );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

psa_status_t mbedtls_test_transparent_mac_verify_setup(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_transparent_test_driver_mac_verify_setup(
                operation, attributes, key_buffer, key_buffer_size, alg );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

psa_status_t mbedtls_test_transparent_mac_update(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_transparent_test_driver_mac_update(
                operation, input, input_length );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

psa_status_t mbedtls_test_transparent_mac_sign_finish(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_transparent_test_driver_mac_sign_finish(
                operation, mac, mac_size, mac_length );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

psa_status_t mbedtls_test_transparent_mac_verify_finish(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    const uint8_t *mac,
    size_t mac_length )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_transparent_test_driver_mac_verify_finish(
                operation, mac, mac_length );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

psa_status_t mbedtls_test_transparent_mac_abort(
    mbedtls_transparent_test_driver_mac_operation_t *operation )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_transparent_test_driver_mac_abort( operation );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

psa_status_t mbedtls_test_opaque_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_opaque_test_driver_mac_compute(
                attributes, key_buffer, key_buffer_size, alg,
                input, input_length,
                mac, mac_size, mac_length );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

psa_status_t mbedtls_test_opaque_mac_sign_setup(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_opaque_test_driver_mac_sign_setup(
                operation, attributes, key_buffer, key_buffer_size, alg );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

psa_status_t mbedtls_test_opaque_mac_verify_setup(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_opaque_test_driver_mac_verify_setup(
                operation, attributes, key_buffer, key_buffer_size, alg );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

psa_status_t mbedtls_test_opaque_mac_update(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_opaque_test_driver_mac_update(
                operation, input, input_length );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

psa_status_t mbedtls_test_opaque_mac_sign_finish(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_opaque_test_driver_mac_sign_finish(
                operation, mac, mac_size, mac_length );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

psa_status_t mbedtls_test_opaque_mac_verify_finish(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    const uint8_t *mac,
    size_t mac_length )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_opaque_test_driver_mac_verify_finish(
                operation, mac, mac_length );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

psa_status_t mbedtls_test_opaque_mac_abort(
    mbedtls_opaque_test_driver_mac_operation_t *operation )
{
    mbedtls_test_driver_mac_hooks.hits++;

    if( mbedtls_test_driver_mac_hooks.forced_status != PSA_SUCCESS )
    {
         mbedtls_test_driver_mac_hooks.driver_status =
             mbedtls_test_driver_mac_hooks.forced_status;
    }
    else
    {
        mbedtls_test_driver_mac_hooks.driver_status =
            mbedtls_opaque_test_driver_mac_abort( operation );
    }

    return( mbedtls_test_driver_mac_hooks.driver_status );
}

#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
