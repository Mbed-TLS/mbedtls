/*
 * Test driver for generating and verifying keys.
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_TEST_DRIVERS_KEY_MANAGEMENT_H
#define PSA_CRYPTO_TEST_DRIVERS_KEY_MANAGEMENT_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(PSA_CRYPTO_DRIVER_TEST)
#include <psa/crypto_driver_common.h>

#define PSA_CRYPTO_TEST_DRIVER_BUILTIN_AES_KEY_SLOT     0
#define PSA_CRYPTO_TEST_DRIVER_BUILTIN_ECDSA_KEY_SLOT   1

typedef struct {
    /* If non-null, on success, copy this to the output. */
    void *forced_output;
    size_t forced_output_length;
    /* If not PSA_SUCCESS, return this error code instead of processing the
     * function call. */
    psa_status_t forced_status;
    /* Count the amount of times one of the key management driver functions
     * is called. */
    unsigned long hits;
    /* Location of the last key management driver called to import a key. */
    psa_key_location_t location;
} mbedtls_test_driver_key_management_hooks_t;

/* The location is initialized to the invalid value 0x800000. Invalid in the
 * sense that no PSA specification will assign a meaning to this location
 * (stated first in version 1.0.1 of the specification) and that it is not
 * used as a location of an opaque test drivers. */
#define MBEDTLS_TEST_DRIVER_KEY_MANAGEMENT_INIT { NULL, 0, PSA_SUCCESS, 0, 0x800000 }
static inline mbedtls_test_driver_key_management_hooks_t
mbedtls_test_driver_key_management_hooks_init(void)
{
    const mbedtls_test_driver_key_management_hooks_t
        v = MBEDTLS_TEST_DRIVER_KEY_MANAGEMENT_INIT;
    return v;
}

extern mbedtls_test_driver_key_management_hooks_t
    mbedtls_test_driver_key_management_hooks;

psa_status_t mbedtls_test_transparent_init(void);
void mbedtls_test_transparent_free(void);
psa_status_t mbedtls_test_opaque_init(void);
void mbedtls_test_opaque_free(void);

psa_status_t mbedtls_test_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length);

psa_status_t mbedtls_test_opaque_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length);

psa_status_t mbedtls_test_opaque_export_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length);

psa_status_t mbedtls_test_transparent_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length);

psa_status_t mbedtls_test_opaque_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length);

psa_status_t mbedtls_test_transparent_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length,
    size_t *bits);

psa_status_t mbedtls_test_opaque_get_builtin_key(
    psa_drv_slot_number_t slot_number,
    psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length);

#endif /* PSA_CRYPTO_DRIVER_TEST */
#endif /* PSA_CRYPTO_TEST_DRIVERS_KEY_MANAGEMENT_H */
