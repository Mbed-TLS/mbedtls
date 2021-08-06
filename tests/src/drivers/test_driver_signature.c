/*
 * Test driver for signature functions.
 * Currently supports signing and verifying precalculated hashes, using
 * only deterministic ECDSA on curves secp256r1, secp384r1 and secp521r1.
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
#include "psa/crypto.h"
#include "psa_crypto_core.h"
#include "psa_crypto_ecp.h"
#include "psa_crypto_hash.h"
#include "psa_crypto_rsa.h"
#include "mbedtls/ecp.h"

#include "test/drivers/signature.h"

#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"

#include "test/random.h"

#include <string.h>

mbedtls_test_driver_signature_hooks_t
    mbedtls_test_driver_signature_sign_hooks = MBEDTLS_TEST_DRIVER_SIGNATURE_INIT;
mbedtls_test_driver_signature_hooks_t
    mbedtls_test_driver_signature_verify_hooks = MBEDTLS_TEST_DRIVER_SIGNATURE_INIT;

psa_status_t sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length )
{
#if defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN) || \
    defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PSS)
    if( attributes->core.type == PSA_KEY_TYPE_RSA_KEY_PAIR )
    {
        return( mbedtls_transparent_test_driver_rsa_sign_hash(
                    attributes,
                    key_buffer, key_buffer_size,
                    alg, hash, hash_length,
                    signature, signature_size, signature_length ) );
    }
    else
#endif /* defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN) ||
        * defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PSS) */

#if defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA) || \
    defined(MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA)
    if( PSA_KEY_TYPE_IS_ECC( attributes->core.type ) )
    {
        if(
#if defined(MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA)
            PSA_ALG_IS_ECDSA( alg )
#else
            PSA_ALG_IS_RANDOMIZED_ECDSA( alg )
#endif
            )
        {
            return( mbedtls_transparent_test_driver_ecdsa_sign_hash(
                        attributes,
                        key_buffer, key_buffer_size,
                        alg, hash, hash_length,
                        signature, signature_size, signature_length ) );
        }
        else
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
    }
    else
#endif /* defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA) */
    {
        (void)attributes;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        (void)hash;
        (void)hash_length;
        (void)signature;
        (void)signature_size;
        (void)signature_length;
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}

psa_status_t verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length )
{
#if defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN) || \
    defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PSS)
    if( PSA_KEY_TYPE_IS_RSA( attributes->core.type ) )
    {
        return( mbedtls_transparent_test_driver_rsa_verify_hash(
                    attributes,
                    key_buffer, key_buffer_size,
                    alg, hash, hash_length,
                    signature, signature_length ) );
    }
    else
#endif /* defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN) ||
        * defined(MBEDTLS_PSA_ACCEL_ALG_RSA_PSS) */

#if defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA) || \
    defined(MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA)
    if( PSA_KEY_TYPE_IS_ECC( attributes->core.type ) )
    {
        if( PSA_ALG_IS_ECDSA( alg ) )
        {
            return( mbedtls_transparent_test_driver_ecdsa_verify_hash(
                        attributes,
                        key_buffer, key_buffer_size,
                        alg, hash, hash_length,
                        signature, signature_length ) );
        }
        else
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
    }
    else
#endif /* defined(MBEDTLS_PSA_ACCEL_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA) */
    {
        (void)attributes;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        (void)hash;
        (void)hash_length;
        (void)signature;
        (void)signature_length;

        return( PSA_ERROR_NOT_SUPPORTED );
    }
}

psa_status_t mbedtls_test_transparent_signature_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t hash_length;
    uint8_t hash[PSA_HASH_MAX_SIZE];

    ++mbedtls_test_driver_signature_sign_hooks.hits;

    if( mbedtls_test_driver_signature_sign_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_signature_sign_hooks.forced_status );

    if( mbedtls_test_driver_signature_sign_hooks.forced_output != NULL )
    {
        if( mbedtls_test_driver_signature_sign_hooks.forced_output_length > signature_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        memcpy( signature, mbedtls_test_driver_signature_sign_hooks.forced_output,
                mbedtls_test_driver_signature_sign_hooks.forced_output_length );
        *signature_length = mbedtls_test_driver_signature_sign_hooks.forced_output_length;

        return( PSA_SUCCESS );
    }

    status = mbedtls_transparent_test_driver_hash_compute(
                PSA_ALG_SIGN_GET_HASH( alg ), input, input_length,
                hash, sizeof( hash ), &hash_length );

    if( status != PSA_SUCCESS )
        return status;

    return sign_hash( attributes, key_buffer, key_buffer_size,
                      alg, hash, hash_length,
                      signature, signature_size, signature_length );
}

psa_status_t mbedtls_test_opaque_signature_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key,
    size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length )
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;

    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_transparent_signature_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    const uint8_t *signature,
    size_t signature_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t hash_length;
    uint8_t hash[PSA_HASH_MAX_SIZE];

    ++mbedtls_test_driver_signature_verify_hooks.hits;

    if( mbedtls_test_driver_signature_verify_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_signature_verify_hooks.forced_status );

    status = mbedtls_transparent_test_driver_hash_compute(
                PSA_ALG_SIGN_GET_HASH( alg ), input, input_length,
                hash, sizeof( hash ), &hash_length );

    if( status != PSA_SUCCESS )
        return status;

    return verify_hash( attributes, key_buffer, key_buffer_size,
                        alg, hash, hash_length,
                        signature, signature_length );
}

psa_status_t mbedtls_test_opaque_signature_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key,
    size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    const uint8_t *signature,
    size_t signature_length )
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) signature;
    (void) signature_length;

    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_transparent_signature_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{
    ++mbedtls_test_driver_signature_sign_hooks.hits;

    if( mbedtls_test_driver_signature_sign_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_signature_sign_hooks.forced_status );

    if( mbedtls_test_driver_signature_sign_hooks.forced_output != NULL )
    {
        if( mbedtls_test_driver_signature_sign_hooks.forced_output_length > signature_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( signature, mbedtls_test_driver_signature_sign_hooks.forced_output,
                mbedtls_test_driver_signature_sign_hooks.forced_output_length );
        *signature_length = mbedtls_test_driver_signature_sign_hooks.forced_output_length;
        return( PSA_SUCCESS );
    }

    return sign_hash( attributes, key_buffer, key_buffer_size,
                      alg, hash, hash_length,
                      signature, signature_size, signature_length );
}

psa_status_t mbedtls_test_opaque_signature_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;

    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_transparent_signature_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length )
{
    ++mbedtls_test_driver_signature_verify_hooks.hits;

    if( mbedtls_test_driver_signature_verify_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_signature_verify_hooks.forced_status );

    return verify_hash( attributes, key_buffer, key_buffer_size,
                        alg, hash, hash_length,
                        signature, signature_length );
}

psa_status_t mbedtls_test_opaque_signature_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length )
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
