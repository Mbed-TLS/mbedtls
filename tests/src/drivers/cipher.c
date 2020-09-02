/*
 * Test driver for cipher functions.
 * Currently only supports multi-part operations using AES-CTR.
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
#include "mbedtls/cipher.h"

#include "drivers/cipher.h"

#include "test/random.h"

#include <string.h>

/* If non-null, on success, copy this to the output. */
void *test_driver_cipher_forced_output = NULL;
size_t test_driver_cipher_forced_output_length = 0;

/* Test driver, if not explicitly setup, returns 'PSA_ERROR_NOT_SUPPORTED' by default,
 * causing regular test suites to pass since the core will go into fallback mode. */
psa_status_t test_transparent_cipher_status = PSA_ERROR_NOT_SUPPORTED;
unsigned long test_transparent_cipher_hit = 0;

psa_status_t test_transparent_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) input;
    (void) input_length;
    test_transparent_cipher_hit++;

    if( test_transparent_cipher_status != PSA_SUCCESS )
        return test_transparent_cipher_status;
    if( output_size < test_driver_cipher_forced_output_length )
        return PSA_ERROR_BUFFER_TOO_SMALL;

    memcpy(output, test_driver_cipher_forced_output, test_driver_cipher_forced_output_length);
    *output_length = test_driver_cipher_forced_output_length;

    return test_transparent_cipher_status;
}

psa_status_t test_transparent_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) input;
    (void) input_length;
    test_transparent_cipher_hit++;

    if( test_transparent_cipher_status != PSA_SUCCESS )
        return test_transparent_cipher_status;
    if( output_size < test_driver_cipher_forced_output_length )
        return PSA_ERROR_BUFFER_TOO_SMALL;

    memcpy(output, test_driver_cipher_forced_output, test_driver_cipher_forced_output_length);
    *output_length = test_driver_cipher_forced_output_length;

    return test_transparent_cipher_status;
}

psa_status_t test_transparent_cipher_encrypt_setup(
    test_transparent_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;

    /* write our struct, this will trigger memory corruption failures
     * in test when we go outside of bounds. */
    memset(operation, 0, sizeof(test_transparent_cipher_operation_t));

    test_transparent_cipher_hit++;
    return test_transparent_cipher_status;
}

psa_status_t test_transparent_cipher_decrypt_setup(
    test_transparent_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;

    /* write our struct, this will trigger memory corruption failures
     * in test when we go outside of bounds. */
    memset(operation, 0, sizeof(test_transparent_cipher_operation_t));

    test_transparent_cipher_hit++;
    return test_transparent_cipher_status;
}

psa_status_t test_transparent_cipher_abort(
    test_transparent_cipher_operation_t *operation)
{
    /* write our struct, this will trigger memory corruption failures
     * in test when we go outside of bounds. */
    memset(operation, 0, sizeof(test_transparent_cipher_operation_t));

    test_transparent_cipher_hit++;
    return test_transparent_cipher_status;
}

psa_status_t test_transparent_cipher_generate_iv(
    test_transparent_cipher_operation_t *operation,
    uint8_t *iv,
    size_t iv_size,
    size_t *iv_length)
{
    (void) operation;
    (void) iv;
    (void) iv_size;
    (void) iv_length;

    test_transparent_cipher_hit++;
    return test_transparent_cipher_status;
}

psa_status_t test_transparent_cipher_set_iv(
    test_transparent_cipher_operation_t *operation,
    const uint8_t *iv,
    size_t iv_length)
{
    (void) operation;
    (void) iv;
    (void) iv_length;

    test_transparent_cipher_hit++;
    return test_transparent_cipher_status;
}

psa_status_t test_transparent_cipher_update(
    test_transparent_cipher_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    (void) operation;
    (void) input;
    (void) input_length;
    test_transparent_cipher_hit++;

    if( test_transparent_cipher_status != PSA_SUCCESS )
        return test_transparent_cipher_status;
    if( output_size < test_driver_cipher_forced_output_length )
        return PSA_ERROR_BUFFER_TOO_SMALL;

    memcpy(output, test_driver_cipher_forced_output, test_driver_cipher_forced_output_length);
    *output_length = test_driver_cipher_forced_output_length;

    return test_transparent_cipher_status;
}

psa_status_t test_transparent_cipher_finish(
    test_transparent_cipher_operation_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    (void) operation;
    test_transparent_cipher_hit++;

    if( test_transparent_cipher_status != PSA_SUCCESS )
        return test_transparent_cipher_status;
    if( output_size < test_driver_cipher_forced_output_length )
        return PSA_ERROR_BUFFER_TOO_SMALL;

    memcpy(output, test_driver_cipher_forced_output, test_driver_cipher_forced_output_length);
    *output_length = test_driver_cipher_forced_output_length;

    return test_transparent_cipher_status;
}

/*
 * opaque versions, to do
 */
psa_status_t test_opaque_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_encrypt_setup(
    test_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    (void) operation;
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_decrypt_setup(
    test_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    (void) operation;
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_abort(
    test_opaque_cipher_operation_t *operation)
{
    (void) operation;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_generate_iv(
    test_opaque_cipher_operation_t *operation,
    uint8_t *iv,
    size_t iv_size,
    size_t *iv_length)
{
    (void) operation;
    (void) iv;
    (void) iv_size;
    (void) iv_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_set_iv(
    test_opaque_cipher_operation_t *operation,
    const uint8_t *iv,
    size_t iv_length)
{
    (void) operation;
    (void) iv;
    (void) iv_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_update(
    test_opaque_cipher_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    (void) operation;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t test_opaque_cipher_finish(
    test_opaque_cipher_operation_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    (void) operation;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}
#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
