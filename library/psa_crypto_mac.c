/*
 *  PSA MAC layer on top of Mbed TLS software crypto
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

#include "common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include <psa/crypto.h>
#include "psa_crypto_core.h"
#include "psa_crypto_mac.h"

#include <mbedtls/error.h>
#include <string.h>

/* Use builtin defines specific to this compilation unit, since the test driver
 * relies on the software driver. */
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_CMAC) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_CMAC) ) )
#define BUILTIN_ALG_CMAC        1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_HMAC) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_HMAC) ) )
#define BUILTIN_ALG_HMAC        1
#endif

/* Implement the PSA driver MAC interface on top of mbed TLS if either the
 * software driver or the test driver requires it. */
#if defined(MBEDTLS_PSA_BUILTIN_MAC) || defined(PSA_CRYPTO_DRIVER_TEST)
static psa_status_t mac_compute(
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
    /* To be fleshed out in a subsequent commit */
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

static psa_status_t mac_sign_setup(
    mbedtls_psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    /* To be fleshed out in a subsequent commit */
    (void) operation;
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

static psa_status_t mac_verify_setup(
    mbedtls_psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    /* To be fleshed out in a subsequent commit */
    (void) operation;
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

static psa_status_t mac_update(
    mbedtls_psa_mac_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    /* To be fleshed out in a subsequent commit */
    (void) operation;
    (void) input;
    (void) input_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

static psa_status_t mac_sign_finish(
    mbedtls_psa_mac_operation_t *operation,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    /* To be fleshed out in a subsequent commit */
    (void) operation;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

static psa_status_t mac_verify_finish(
    mbedtls_psa_mac_operation_t *operation,
    const uint8_t *mac,
    size_t mac_length )
{
    /* To be fleshed out in a subsequent commit */
    (void) operation;
    (void) mac;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

static psa_status_t mac_abort(
    mbedtls_psa_mac_operation_t *operation )
{
    /* To be fleshed out in a subsequent commit */
    (void) operation;
    return( PSA_ERROR_NOT_SUPPORTED );
}
#endif /* MBEDTLS_PSA_BUILTIN_MAC || PSA_CRYPTO_DRIVER_TEST */

#if defined(MBEDTLS_PSA_BUILTIN_MAC)
psa_status_t mbedtls_psa_mac_compute(
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
    return( mac_compute( attributes, key_buffer, key_buffer_size, alg,
                         input, input_length,
                         mac, mac_size, mac_length ) );
}

psa_status_t mbedtls_psa_mac_sign_setup(
    mbedtls_psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    return( mac_sign_setup( operation, attributes,
                            key_buffer, key_buffer_size, alg ) );
}

psa_status_t mbedtls_psa_mac_verify_setup(
    mbedtls_psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    return( mac_verify_setup( operation, attributes,
                              key_buffer, key_buffer_size, alg ) );
}

psa_status_t mbedtls_psa_mac_update(
    mbedtls_psa_mac_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    return( mac_update( operation, input, input_length ) );
}

psa_status_t mbedtls_psa_mac_sign_finish(
    mbedtls_psa_mac_operation_t *operation,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    return( mac_sign_finish( operation, mac, mac_size, mac_length ) );
}

psa_status_t mbedtls_psa_mac_verify_finish(
    mbedtls_psa_mac_operation_t *operation,
    const uint8_t *mac,
    size_t mac_length )
{
    return( mac_verify_finish( operation, mac, mac_length ) );
}

psa_status_t mbedtls_psa_mac_abort(
    mbedtls_psa_mac_operation_t *operation )
{
    return( mac_abort( operation ) );
}
#endif /* MBEDTLS_PSA_BUILTIN_MAC */

 /*
  * BEYOND THIS POINT, TEST DRIVER ENTRY POINTS ONLY.
  */
#if defined(PSA_CRYPTO_DRIVER_TEST)

static int is_mac_accelerated( psa_algorithm_t alg )
{
#if defined(MBEDTLS_PSA_ACCEL_ALG_HMAC)
    if( PSA_ALG_IS_HMAC( alg ) )
        return( 1 );
#endif

    switch( PSA_ALG_FULL_LENGTH_MAC( alg ) )
    {
#if defined(MBEDTLS_PSA_ACCEL_ALG_CMAC)
        case PSA_ALG_CMAC:
            return( 1 );
#endif
        default:
            return( 0 );
    }
}

psa_status_t mbedtls_transparent_test_driver_mac_compute(
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
    if( is_mac_accelerated( alg ) )
        return( mac_compute( attributes, key_buffer, key_buffer_size, alg,
                             input, input_length,
                             mac, mac_size, mac_length ) );
    else
        return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_transparent_test_driver_mac_sign_setup(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    if( is_mac_accelerated( alg ) )
        return( mac_sign_setup( operation, attributes,
                                key_buffer, key_buffer_size, alg ) );
    else
        return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_transparent_test_driver_mac_verify_setup(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    if( is_mac_accelerated( alg ) )
        return( mac_verify_setup( operation, attributes,
                                  key_buffer, key_buffer_size, alg ) );
    else
        return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_transparent_test_driver_mac_update(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    if( is_mac_accelerated( operation->alg ) )
        return( mac_update( operation, input, input_length ) );
    else
        return( PSA_ERROR_BAD_STATE );
}

psa_status_t mbedtls_transparent_test_driver_mac_sign_finish(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    if( is_mac_accelerated( operation->alg ) )
        return( mac_sign_finish( operation, mac, mac_size, mac_length ) );
    else
        return( PSA_ERROR_BAD_STATE );
}

psa_status_t mbedtls_transparent_test_driver_mac_verify_finish(
    mbedtls_transparent_test_driver_mac_operation_t *operation,
    const uint8_t *mac,
    size_t mac_length )
{
    if( is_mac_accelerated( operation->alg ) )
        return( mac_verify_finish( operation, mac, mac_length ) );
    else
        return( PSA_ERROR_BAD_STATE );
}

psa_status_t mbedtls_transparent_test_driver_mac_abort(
    mbedtls_transparent_test_driver_mac_operation_t *operation )
{
    return( mac_abort( operation ) );
}

psa_status_t mbedtls_opaque_test_driver_mac_compute(
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
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_mac_sign_setup(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) operation;
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_mac_verify_setup(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) operation;
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_mac_update(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    const uint8_t *input,
    size_t input_length )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) operation;
    (void) input;
    (void) input_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_mac_sign_finish(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    uint8_t *mac,
    size_t mac_size,
    size_t *mac_length )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) operation;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_mac_verify_finish(
    mbedtls_opaque_test_driver_mac_operation_t *operation,
    const uint8_t *mac,
    size_t mac_length )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) operation;
    (void) mac;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_mac_abort(
    mbedtls_opaque_test_driver_mac_operation_t *operation )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) operation;
    return( PSA_ERROR_NOT_SUPPORTED );
}

#endif /* PSA_CRYPTO_DRIVER_TEST */

#endif /* MBEDTLS_PSA_CRYPTO_C */
