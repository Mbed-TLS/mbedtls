/*
 * Test driver for cipher functions
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

#ifndef PSA_CRYPTO_TEST_DRIVERS_CIPHER_H
#define PSA_CRYPTO_TEST_DRIVERS_CIPHER_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(PSA_CRYPTO_DRIVER_TEST)
#include <psa/crypto_driver_common.h>

#include "mbedtls/cipher.h"
typedef struct {
    psa_algorithm_t alg;
    unsigned int key_set : 1;
    unsigned int iv_required : 1;
    unsigned int iv_set : 1;
    uint8_t iv_size;
    uint8_t block_size;
    mbedtls_cipher_context_t cipher;
} test_transparent_cipher_operation_t;

typedef struct{
    unsigned int initialised : 1;
    test_transparent_cipher_operation_t ctx;
} test_opaque_cipher_operation_t;

typedef struct {
    /* If non-null, on success, copy this to the output. */
    void *forced_output;
    size_t forced_output_length;
    /* If not PSA_SUCCESS, return this error code instead of processing the
     * function call. */
    psa_status_t forced_status;
    /* Count the amount of times one of the cipher driver functions is called. */
    unsigned long hits;
} test_driver_cipher_hooks_t;

#define TEST_DRIVER_CIPHER_INIT { NULL, 0, PSA_SUCCESS, 0 }
static inline test_driver_cipher_hooks_t test_driver_cipher_hooks_init( void )
{
    const test_driver_cipher_hooks_t v = TEST_DRIVER_CIPHER_INIT;
    return( v );
}

extern test_driver_cipher_hooks_t test_driver_cipher_hooks;

psa_status_t test_transparent_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t test_transparent_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t test_transparent_cipher_encrypt_setup(
    test_transparent_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg);

psa_status_t test_transparent_cipher_decrypt_setup(
    test_transparent_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg);

psa_status_t test_transparent_cipher_abort(
    test_transparent_cipher_operation_t *operation);

psa_status_t test_transparent_cipher_generate_iv(
    test_transparent_cipher_operation_t *operation,
    uint8_t *iv,
    size_t iv_size,
    size_t *iv_length);

psa_status_t test_transparent_cipher_set_iv(
    test_transparent_cipher_operation_t *operation,
    const uint8_t *iv,
    size_t iv_length);

psa_status_t test_transparent_cipher_update(
    test_transparent_cipher_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

psa_status_t test_transparent_cipher_finish(
    test_transparent_cipher_operation_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

/*
 * opaque versions
 */
psa_status_t test_opaque_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t test_opaque_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t test_opaque_cipher_encrypt_setup(
    test_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg);

psa_status_t test_opaque_cipher_decrypt_setup(
    test_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg);

psa_status_t test_opaque_cipher_abort(
    test_opaque_cipher_operation_t *operation);

psa_status_t test_opaque_cipher_generate_iv(
    test_opaque_cipher_operation_t *operation,
    uint8_t *iv,
    size_t iv_size,
    size_t *iv_length);

psa_status_t test_opaque_cipher_set_iv(
    test_opaque_cipher_operation_t *operation,
    const uint8_t *iv,
    size_t iv_length);

psa_status_t test_opaque_cipher_update(
    test_opaque_cipher_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

psa_status_t test_opaque_cipher_finish(
    test_opaque_cipher_operation_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

#endif /* PSA_CRYPTO_DRIVER_TEST */
#endif /* PSA_CRYPTO_TEST_DRIVERS_CIPHER_H */
