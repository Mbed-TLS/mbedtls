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
#include "psa_crypto_cipher.h"
#include "psa_crypto_core.h"
#include "mbedtls/cipher.h"

#include "test/drivers/cipher.h"

#include "test/random.h"

#include <string.h>

/* Test driver implements AES-CTR only. Its default behaviour (when its return
 * status is not overridden through the hooks) is to take care of all AES-CTR
 * operations, and return PSA_ERROR_NOT_SUPPORTED for all others.
 * Set test_driver_cipher_hooks.forced_status to PSA_ERROR_NOT_SUPPORTED to use
 * fallback even for AES-CTR. */
test_driver_cipher_hooks_t test_driver_cipher_hooks = TEST_DRIVER_CIPHER_INIT;

static psa_status_t test_transparent_cipher_oneshot(
    mbedtls_operation_t direction,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    test_driver_cipher_hooks.hits++;

    /* Test driver supports AES-CTR only, to verify operation calls. */
    if( alg != PSA_ALG_CTR ||
        psa_get_key_type( attributes ) != PSA_KEY_TYPE_AES )
        return( PSA_ERROR_NOT_SUPPORTED );

    /* If test driver response code is not SUCCESS, we can return early */
    if( test_driver_cipher_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_cipher_hooks.forced_status );

    /* If test driver output is overridden, we don't need to do actual crypto */
    if( test_driver_cipher_hooks.forced_output != NULL )
    {
        if( output_size < test_driver_cipher_hooks.forced_output_length )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        memcpy( output,
                test_driver_cipher_hooks.forced_output,
                test_driver_cipher_hooks.forced_output_length );
        *output_length = test_driver_cipher_hooks.forced_output_length;

        return( test_driver_cipher_hooks.forced_status );
    }

    /* Run AES-CTR using the cipher module */
    {
        mbedtls_test_rnd_pseudo_info rnd_info;
        memset( &rnd_info, 0x5A, sizeof( mbedtls_test_rnd_pseudo_info ) );

        const mbedtls_cipher_info_t *cipher_info =
            mbedtls_cipher_info_from_values( MBEDTLS_CIPHER_ID_AES,
                                             key_length * 8,
                                             MBEDTLS_MODE_CTR );
        mbedtls_cipher_context_t cipher;
        int ret = 0;
        uint8_t temp_output_buffer[16] = {0};
        size_t temp_output_length = 0;

        if( direction == MBEDTLS_ENCRYPT )
        {
            /* Oneshot encrypt needs to prepend the IV to the output */
            if( output_size < ( input_length + 16 ) )
                return( PSA_ERROR_BUFFER_TOO_SMALL );
        }
        else
        {
            /* Oneshot decrypt has the IV prepended to the input */
            if( output_size < ( input_length - 16 ) )
                return( PSA_ERROR_BUFFER_TOO_SMALL );
        }

        if( cipher_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );

        mbedtls_cipher_init( &cipher );
        ret = mbedtls_cipher_setup( &cipher, cipher_info );
        if( ret != 0 )
            goto exit;

        ret = mbedtls_cipher_setkey( &cipher,
                                     key,
                                     key_length * 8, direction );
        if( ret != 0 )
            goto exit;

        if( direction == MBEDTLS_ENCRYPT )
        {
            mbedtls_test_rnd_pseudo_info rnd_info;
            memset( &rnd_info, 0x5A, sizeof( mbedtls_test_rnd_pseudo_info ) );

            ret = mbedtls_test_rnd_pseudo_rand( &rnd_info,
                                                temp_output_buffer,
                                                16 );
            if( ret != 0 )
                goto exit;

            ret = mbedtls_cipher_set_iv( &cipher, temp_output_buffer, 16 );
        }
        else
            ret = mbedtls_cipher_set_iv( &cipher, input, 16 );

        if( ret != 0 )
            goto exit;

        if( direction == MBEDTLS_ENCRYPT )
        {
            ret = mbedtls_cipher_update( &cipher,
                                         input, input_length,
                                         &output[16], output_length );
            if( ret == 0 )
            {
                memcpy( output, temp_output_buffer, 16 );
                *output_length += 16;
            }
        }
        else
            ret = mbedtls_cipher_update( &cipher,
                                         &input[16], input_length - 16,
                                         output, output_length );

        if( ret != 0 )
            goto exit;

        ret = mbedtls_cipher_finish( &cipher,
                                     temp_output_buffer,
                                     &temp_output_length );

exit:
        if( ret != 0 )
        {
            *output_length = 0;
            memset(output, 0, output_size);
        }

        mbedtls_cipher_free( &cipher );
        return( mbedtls_to_psa_error( ret ) );
    }
}

psa_status_t test_transparent_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    return (
        test_transparent_cipher_oneshot(
            MBEDTLS_ENCRYPT,
            attributes,
            key, key_length,
            alg,
            input, input_length,
            output, output_size, output_length) );
}

psa_status_t test_transparent_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    return (
        test_transparent_cipher_oneshot(
            MBEDTLS_DECRYPT,
            attributes,
            key, key_length,
            alg,
            input, input_length,
            output, output_size, output_length) );
}

psa_status_t test_transparent_cipher_encrypt_setup(
    mbedtls_transparent_test_driver_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    test_driver_cipher_hooks.hits++;

    /* Wiping the entire struct here, instead of member-by-member. This is
     * useful for the test suite, since it gives a chance of catching memory
     * corruption errors should the core not have allocated (enough) memory for
     * our context struct. */
    memset( operation, 0, sizeof( *operation ) );

    if( test_driver_cipher_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_cipher_hooks.forced_status );

    return ( mbedtls_transparent_test_driver_cipher_encrypt_setup(
                 operation, attributes, key, key_length, alg ) );
}

psa_status_t test_transparent_cipher_decrypt_setup(
    mbedtls_transparent_test_driver_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    test_driver_cipher_hooks.hits++;

    if( test_driver_cipher_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_cipher_hooks.forced_status );

    return ( mbedtls_transparent_test_driver_cipher_decrypt_setup(
                 operation, attributes, key, key_length, alg ) );
}

psa_status_t test_transparent_cipher_abort(
    mbedtls_transparent_test_driver_cipher_operation_t *operation)
{
    test_driver_cipher_hooks.hits++;

    if( operation->alg == 0 )
        return( PSA_SUCCESS );

    mbedtls_transparent_test_driver_cipher_abort( operation );

    /* Wiping the entire struct here, instead of member-by-member. This is
     * useful for the test suite, since it gives a chance of catching memory
     * corruption errors should the core not have allocated (enough) memory for
     * our context struct. */
    memset( operation, 0, sizeof( *operation ) );

    return( test_driver_cipher_hooks.forced_status );
}

psa_status_t test_transparent_cipher_set_iv(
    mbedtls_transparent_test_driver_cipher_operation_t *operation,
    const uint8_t *iv,
    size_t iv_length)
{
    test_driver_cipher_hooks.hits++;

    if( test_driver_cipher_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_cipher_hooks.forced_status );

    return( mbedtls_transparent_test_driver_cipher_set_iv(
                operation, iv, iv_length ) );
}

psa_status_t test_transparent_cipher_update(
    mbedtls_transparent_test_driver_cipher_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    test_driver_cipher_hooks.hits++;

    if( test_driver_cipher_hooks.forced_output != NULL )
    {
        if( output_size < test_driver_cipher_hooks.forced_output_length )
            return PSA_ERROR_BUFFER_TOO_SMALL;

        memcpy( output,
                test_driver_cipher_hooks.forced_output,
                test_driver_cipher_hooks.forced_output_length );
        *output_length = test_driver_cipher_hooks.forced_output_length;

        return( test_driver_cipher_hooks.forced_status );
    }

    if( test_driver_cipher_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_cipher_hooks.forced_status );

    return( mbedtls_transparent_test_driver_cipher_update(
                operation, input, input_length,
                output, output_size, output_length ) );
}

psa_status_t test_transparent_cipher_finish(
    mbedtls_transparent_test_driver_cipher_operation_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    test_driver_cipher_hooks.hits++;

    if( test_driver_cipher_hooks.forced_output != NULL )
    {
        if( output_size < test_driver_cipher_hooks.forced_output_length )
            return PSA_ERROR_BUFFER_TOO_SMALL;

        memcpy( output,
                test_driver_cipher_hooks.forced_output,
                test_driver_cipher_hooks.forced_output_length );
        *output_length = test_driver_cipher_hooks.forced_output_length;

        return( test_driver_cipher_hooks.forced_status );
    }

    if( test_driver_cipher_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_cipher_hooks.forced_status );

    return( mbedtls_transparent_test_driver_cipher_finish(
                operation, output, output_size, output_length ) );
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
    return( PSA_ERROR_NOT_SUPPORTED );
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
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_opaque_cipher_encrypt_setup(
    mbedtls_opaque_test_driver_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    (void) operation;
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_opaque_cipher_decrypt_setup(
    mbedtls_opaque_test_driver_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    (void) operation;
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_opaque_cipher_abort(
    mbedtls_opaque_test_driver_cipher_operation_t *operation )
{
    (void) operation;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_opaque_cipher_set_iv(
    mbedtls_opaque_test_driver_cipher_operation_t *operation,
    const uint8_t *iv,
    size_t iv_length)
{
    (void) operation;
    (void) iv;
    (void) iv_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_opaque_cipher_update(
    mbedtls_opaque_test_driver_cipher_operation_t *operation,
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
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_opaque_cipher_finish(
    mbedtls_opaque_test_driver_cipher_operation_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    (void) operation;
    (void) output;
    (void) output_size;
    (void) output_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}
#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
