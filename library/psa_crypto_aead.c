/*
 *  PSA AEAD layer on top of Mbed TLS software crypto
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
#include "psa_crypto_aead.h"

/* Use builtin defines specific to this compilation unit, since the test driver
 * relies on the software driver. */
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_CCM) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_CCM) ) )
#define BUILTIN_ALG_CCM                 1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_GCM) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_GCM) ) )
#define BUILTIN_ALG_GCM                 1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305) ) )
#define BUILTIN_ALG_CHACHA20_POLY1305   1
#endif

/* Implement the PSA driver hash interface on top of mbed TLS if either the
 * software driver or the test driver requires it. */
#if defined(MBEDTLS_PSA_BUILTIN_AEAD) || defined(PSA_CRYPTO_DRIVER_TEST)
static psa_status_t aead_encrypt( const psa_key_attributes_t *attributes,
                                  const uint8_t *key_buffer,
                                  size_t key_buffer_size,
                                  psa_algorithm_t alg,
                                  const uint8_t *nonce,
                                  size_t nonce_length,
                                  const uint8_t *additional_data,
                                  size_t additional_data_length,
                                  const uint8_t *plaintext,
                                  size_t plaintext_length,
                                  uint8_t *ciphertext,
                                  size_t ciphertext_size,
                                  size_t *ciphertext_length )
{
    // To be fleshed out in later commit
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) nonce;
    (void) nonce_length;
    (void) additional_data;
    (void) additional_data_length;
    (void) plaintext;
    (void) plaintext_length,
    (void) ciphertext;
    (void) ciphertext_size;
    (void) ciphertext_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

static psa_status_t aead_decrypt( const psa_key_attributes_t *attributes,
                                  const uint8_t *key_buffer,
                                  size_t key_buffer_size,
                                  psa_algorithm_t alg,
                                  const uint8_t *nonce,
                                  size_t nonce_length,
                                  const uint8_t *additional_data,
                                  size_t additional_data_length,
                                  const uint8_t *ciphertext,
                                  size_t ciphertext_length,
                                  uint8_t *plaintext,
                                  size_t plaintext_size,
                                  size_t *plaintext_length )
{
    // To be fleshed out in later commit
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) nonce;
    (void) nonce_length;
    (void) additional_data;
    (void) additional_data_length;
    (void) ciphertext;
    (void) ciphertext_length,
    (void) plaintext;
    (void) plaintext_size;
    (void) plaintext_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}
#endif /* MBEDTLS_PSA_BUILTIN_AEAD || PSA_CRYPTO_DRIVER_TEST */

#if defined(MBEDTLS_PSA_BUILTIN_AEAD)
psa_status_t mbedtls_psa_aead_encrypt( const psa_key_attributes_t *attributes,
                                       const uint8_t *key_buffer,
                                       size_t key_buffer_size,
                                       psa_algorithm_t alg,
                                       const uint8_t *nonce,
                                       size_t nonce_length,
                                       const uint8_t *additional_data,
                                       size_t additional_data_length,
                                       const uint8_t *plaintext,
                                       size_t plaintext_length,
                                       uint8_t *ciphertext,
                                       size_t ciphertext_size,
                                       size_t *ciphertext_length )
{
    return ( aead_encrypt( attributes, key_buffer, key_buffer_size, alg,
                           nonce, nonce_length,
                           additional_data, additional_data_length,
                           plaintext, plaintext_length,
                           ciphertext, ciphertext_size, ciphertext_length ) );
}

psa_status_t mbedtls_psa_aead_decrypt( const psa_key_attributes_t *attributes,
                                       const uint8_t *key_buffer,
                                       size_t key_buffer_size,
                                       psa_algorithm_t alg,
                                       const uint8_t *nonce,
                                       size_t nonce_length,
                                       const uint8_t *additional_data,
                                       size_t additional_data_length,
                                       const uint8_t *ciphertext,
                                       size_t ciphertext_length,
                                       uint8_t *plaintext,
                                       size_t plaintext_size,
                                       size_t *plaintext_length )
{
    return ( aead_decrypt( attributes, key_buffer, key_buffer_size, alg,
                           nonce, nonce_length,
                           additional_data, additional_data_length,
                           ciphertext, ciphertext_length,
                           plaintext, plaintext_size, plaintext_length ) );
}
#endif /* MBEDTLS_PSA_BUILTIN_AEAD */

 /*
  * BEYOND THIS POINT, TEST DRIVER ENTRY POINTS ONLY.
  */
#if defined(PSA_CRYPTO_DRIVER_TEST)

static psa_status_t is_aead_accelerated( psa_algorithm_t alg )
{
    switch( PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg, 0 ) )
    {
#if defined(MBEDTLS_PSA_ACCEL_ALG_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 ):
            return( PSA_SUCCESS );
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_GCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 ):
            return( PSA_SUCCESS );
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CHACHA20_POLY1305, 0 ):
            return( PSA_SUCCESS );
#endif
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }
}

psa_status_t mbedtls_transparent_test_driver_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length )
{
    if( is_aead_accelerated( alg ) == PSA_SUCCESS )
    {
        return( aead_encrypt( attributes, key_buffer, key_buffer_size, alg,
                              nonce, nonce_length,
                              additional_data, additional_data_length,
                              plaintext, plaintext_length,
                              ciphertext, ciphertext_size, ciphertext_length ) );
    }
    else
        return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_transparent_test_driver_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length )
{
    if( is_aead_accelerated( alg ) == PSA_SUCCESS )
    {
        return( aead_decrypt( attributes, key_buffer, key_buffer_size, alg,
                              nonce, nonce_length,
                              additional_data, additional_data_length,
                              ciphertext, ciphertext_length,
                              plaintext, plaintext_size, plaintext_length ) );
    }
    else
        return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) nonce;
    (void) nonce_length;
    (void) additional_data;
    (void) additional_data_length;
    (void) plaintext;
    (void) plaintext_length,
    (void) ciphertext;
    (void) ciphertext_size;
    (void) ciphertext_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) nonce;
    (void) nonce_length;
    (void) additional_data;
    (void) additional_data_length;
    (void) ciphertext;
    (void) ciphertext_length,
    (void) plaintext;
    (void) plaintext_size;
    (void) plaintext_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

#endif /* PSA_CRYPTO_DRIVER_TEST */

#endif /* MBEDTLS_PSA_CRYPTO_C */
