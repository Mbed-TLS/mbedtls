/*
 * Test driver for MAC functions.
 * Currently not implemented. Present to validate no impact on PSA Crypto core.
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

#include "test/drivers/mac.h"
#include <string.h>

test_driver_mac_hooks_t test_driver_mac_hooks = TEST_DRIVER_MAC_INIT;

/*
 * Transparent test driver
 */

psa_status_t test_transparent_mac_sign_setup(
    test_transparent_mac_operation_t *operation,
    psa_key_slot_t *slot,
    psa_algorithm_t alg )
{
    (void) operation;
    (void) slot;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_transparent_mac_verify_setup(
    test_transparent_mac_operation_t *operation,
    psa_key_slot_t *slot,
    psa_algorithm_t alg )
{
    (void) operation;
    (void) slot;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_transparent_mac_update(
    test_transparent_mac_operation_t *operation,
    const uint8_t *input, size_t input_length )
{
    (void) operation;
    (void) input;
    (void) input_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_transparent_mac_sign_finish(
    test_transparent_mac_operation_t *operation,
    uint8_t *mac, size_t mac_size, size_t *mac_length )
{
    (void) operation;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_transparent_mac_verify_finish(
    test_transparent_mac_operation_t *operation,
    const uint8_t *mac, size_t mac_length )
{
    (void) operation;
    (void) mac;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_transparent_mac_abort(
    test_transparent_mac_operation_t *operation )
{
    (void) operation;
    return( PSA_ERROR_NOT_SUPPORTED );
}

/*
 * Opaque test driver
 */

psa_status_t test_opaque_mac_sign_setup(
    test_opaque_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg )
{
    (void) operation;
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_opaque_mac_verify_setup(
    test_opaque_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg )
{
    (void) operation;
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_opaque_mac_update(
    test_opaque_mac_operation_t *operation,
    const uint8_t *input, size_t input_length )
{
    (void) operation;
    (void) input;
    (void) input_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_opaque_mac_sign_finish(
    test_opaque_mac_operation_t *operation,
    uint8_t *mac, size_t mac_size, size_t *mac_length )
{
    (void) operation;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_opaque_mac_verify_finish(
    test_opaque_mac_operation_t *operation,
    const uint8_t *mac, size_t mac_length )
{
    (void) operation;
    (void) mac;
    (void) mac_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_opaque_mac_abort(
    test_opaque_mac_operation_t *operation )
{
    (void) operation;
    return( PSA_ERROR_NOT_SUPPORTED );
}

#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
