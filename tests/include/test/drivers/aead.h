/*
 * Test driver for AEAD driver entry points.
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_TEST_DRIVERS_AEAD_H
#define PSA_CRYPTO_TEST_DRIVERS_AEAD_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(PSA_CRYPTO_DRIVER_TEST)
#include <psa/crypto_driver_common.h>

typedef struct {
    /* If not PSA_SUCCESS, return this error code instead of processing the
     * function call. */
    psa_status_t forced_status;
    /* Count the amount of times AEAD driver functions are called. */
    unsigned long hits;
    /* Status returned by the last AEAD driver function call. */
    psa_status_t driver_status;
} mbedtls_test_driver_aead_hooks_t;

#define MBEDTLS_TEST_DRIVER_AEAD_INIT { 0, 0, 0 }
static inline mbedtls_test_driver_aead_hooks_t
mbedtls_test_driver_aead_hooks_init(void)
{
    const mbedtls_test_driver_aead_hooks_t v = MBEDTLS_TEST_DRIVER_AEAD_INIT;
    return v;
}

extern mbedtls_test_driver_aead_hooks_t mbedtls_test_driver_aead_hooks;

psa_status_t mbedtls_test_transparent_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length);

psa_status_t mbedtls_test_transparent_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length);

#endif /* PSA_CRYPTO_DRIVER_TEST */
#endif /* PSA_CRYPTO_TEST_DRIVERS_AEAD_H */
