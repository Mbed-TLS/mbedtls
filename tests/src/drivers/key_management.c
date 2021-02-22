/*
 * Test driver for generating and verifying keys.
 * Currently only supports generating and verifying ECC keys.
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
#include "psa_crypto_ecp.h"
#include "psa_crypto_rsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/error.h"

#include "test/drivers/key_management.h"

#include "test/random.h"

#include <string.h>

test_driver_key_management_hooks_t test_driver_key_management_hooks =
    TEST_DRIVER_KEY_MANAGEMENT_INIT;

#if defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
const uint8_t test_driver_aes_key[16] =
    { 0x36, 0x77, 0x39, 0x7A, 0x24, 0x43, 0x26, 0x46,
      0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52, 0x66, 0x55 };
const uint8_t test_driver_ecdsa_key[32] =
    { 0xdc, 0x7d, 0x9d, 0x26, 0xd6, 0x7a, 0x4f, 0x63,
      0x2c, 0x34, 0xc2, 0xdc, 0x0b, 0x69, 0x86, 0x18,
      0x38, 0x82, 0xc2, 0x06, 0xdf, 0x04, 0xcd, 0xb7,
      0xd6, 0x9a, 0xab, 0xe2, 0x8b, 0xe4, 0xf8, 0x1a };
const uint8_t test_driver_ecdsa_pubkey[65] =
    { 0x04,
      0x85, 0xf6, 0x4d, 0x89, 0xf0, 0x0b, 0xe6, 0x6c,
      0x88, 0xdd, 0x93, 0x7e, 0xfd, 0x6d, 0x7c, 0x44,
      0x56, 0x48, 0xdc, 0xb7, 0x01, 0x15, 0x0b, 0x8a,
      0x95, 0x09, 0x29, 0x58, 0x50, 0xf4, 0x1c, 0x19,
      0x31, 0xe5, 0x71, 0xfb, 0x8f, 0x8c, 0x78, 0x31,
      0x7a, 0x20, 0xb3, 0x80, 0xe8, 0x66, 0x58, 0x4b,
      0xbc, 0x25, 0x16, 0xc3, 0xd2, 0x70, 0x2d, 0x79,
      0x2f, 0x13, 0x1a, 0x92, 0x20, 0x95, 0xfd, 0x6c };

static const psa_drv_slot_number_t aes_slot = PSA_CRYPTO_TEST_DRIVER_BUILTIN_AES_KEY_SLOT;
static const psa_drv_slot_number_t ecdsa_slot = PSA_CRYPTO_TEST_DRIVER_BUILTIN_ECDSA_KEY_SLOT;
#endif /* MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */

psa_status_t test_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length )
{
    ++test_driver_key_management_hooks.hits;

    if( test_driver_key_management_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_key_management_hooks.forced_status );

    if( test_driver_key_management_hooks.forced_output != NULL )
    {
        if( test_driver_key_management_hooks.forced_output_length > key_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( key, test_driver_key_management_hooks.forced_output,
                test_driver_key_management_hooks.forced_output_length );
        *key_length = test_driver_key_management_hooks.forced_output_length;
        return( PSA_SUCCESS );
    }

    /* Copied from psa_crypto.c */
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR)
    if ( PSA_KEY_TYPE_IS_ECC( psa_get_key_type( attributes ) )
         && PSA_KEY_TYPE_IS_KEY_PAIR( psa_get_key_type( attributes ) ) )
    {
        return( mbedtls_transparent_test_driver_ecp_generate_key(
                    attributes, key, key_size, key_length ) );
    }
    else
#endif /* defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) */

#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR)
    if ( psa_get_key_type( attributes ) == PSA_KEY_TYPE_RSA_KEY_PAIR )
        return( mbedtls_transparent_test_driver_rsa_generate_key(
                    attributes, key, key_size, key_length ) );
    else
#endif /* defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR) */
    {
        (void)attributes;
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}

psa_status_t test_opaque_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length )
{
    (void) attributes;
    (void) key;
    (void) key_size;
    (void) key_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_transparent_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length,
    size_t *bits)
{
    ++test_driver_key_management_hooks.hits;

    if( test_driver_key_management_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_key_management_hooks.forced_status );

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t type = psa_get_key_type( attributes );

#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)
    if( PSA_KEY_TYPE_IS_ECC( type ) )
    {
        status = mbedtls_transparent_test_driver_ecp_import_key(
                     attributes,
                     data, data_length,
                     key_buffer, key_buffer_size,
                     key_buffer_length, bits );
    }
    else
#endif
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY)
    if( PSA_KEY_TYPE_IS_RSA( type ) )
    {
        status = mbedtls_transparent_test_driver_rsa_import_key(
                     attributes,
                     data, data_length,
                     key_buffer, key_buffer_size,
                     key_buffer_length, bits );
    }
    else
#endif
    {
        status = PSA_ERROR_NOT_SUPPORTED;
        (void)data;
        (void)data_length;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)key_buffer_length;
        (void)bits;
        (void)type;
    }

    return( status );
}

psa_status_t test_opaque_export_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length )
{
#if defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
    if( psa_key_id_is_builtin( MBEDTLS_SVC_KEY_ID_GET_KEY_ID( psa_get_key_id( attributes ) ) ) )
    {
        if( key_length != sizeof( psa_drv_slot_number_t ) )
            return( PSA_ERROR_INVALID_ARGUMENT );

        if( memcmp( key, &ecdsa_slot, sizeof( psa_drv_slot_number_t ) ) == 0 )
        {
            /* This is the ECDSA slot. Verify key attributes before returning pubkey. */
            if( psa_get_key_type( attributes ) != PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 ) )
                return( PSA_ERROR_CORRUPTION_DETECTED );
            if( psa_get_key_bits( attributes ) != 256 )
                return( PSA_ERROR_CORRUPTION_DETECTED );
            if( psa_get_key_algorithm( attributes ) != PSA_ALG_ECDSA( PSA_ALG_ANY_HASH ) )
                return( PSA_ERROR_CORRUPTION_DETECTED );
            if( (psa_get_key_usage_flags( attributes ) & PSA_KEY_USAGE_EXPORT) == 0 )
                return( PSA_ERROR_CORRUPTION_DETECTED );

            if( data_size < sizeof( test_driver_ecdsa_key ) )
                return( PSA_ERROR_BUFFER_TOO_SMALL );

            memcpy( data, test_driver_ecdsa_key, sizeof( test_driver_ecdsa_key ) );
            *data_length = sizeof( test_driver_ecdsa_key );
            return( PSA_SUCCESS );
        }

        if( memcmp( key, &aes_slot, sizeof( psa_drv_slot_number_t ) ) == 0 )
        {
            /* This is the ECDSA slot. Verify key attributes before returning pubkey. */
            if( psa_get_key_type( attributes ) != PSA_KEY_TYPE_AES )
                return( PSA_ERROR_CORRUPTION_DETECTED );
            if( psa_get_key_bits( attributes ) != 128 )
                return( PSA_ERROR_CORRUPTION_DETECTED );
            if( psa_get_key_algorithm( attributes ) != PSA_ALG_CTR )
                return( PSA_ERROR_CORRUPTION_DETECTED );
            if( (psa_get_key_usage_flags( attributes ) & PSA_KEY_USAGE_EXPORT) == 0 )
                return( PSA_ERROR_CORRUPTION_DETECTED );

            if( data_size < sizeof( test_driver_aes_key ) )
                return( PSA_ERROR_BUFFER_TOO_SMALL );

            memcpy( data, test_driver_aes_key, sizeof( test_driver_aes_key ) );
            *data_length = sizeof( test_driver_aes_key );
            return( PSA_SUCCESS );
        }

        /* Potentially add more slots here */

        return( PSA_ERROR_DOES_NOT_EXIST );
    }
#endif /* MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) data;
    (void) data_size;
    (void) data_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_transparent_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    ++test_driver_key_management_hooks.hits;

    if( test_driver_key_management_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_key_management_hooks.forced_status );

    if( test_driver_key_management_hooks.forced_output != NULL )
    {
        if( test_driver_key_management_hooks.forced_output_length > data_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( data, test_driver_key_management_hooks.forced_output,
                test_driver_key_management_hooks.forced_output_length );
        *data_length = test_driver_key_management_hooks.forced_output_length;
        return( PSA_SUCCESS );
    }

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t key_type = psa_get_key_type( attributes );

#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)
    if( PSA_KEY_TYPE_IS_ECC( key_type ) )
    {
        status = mbedtls_transparent_test_driver_ecp_export_public_key(
                      attributes,
                      key_buffer, key_buffer_size,
                      data, data_size, data_length );
    }
    else
#endif
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY)
    if( PSA_KEY_TYPE_IS_RSA( key_type ) )
    {
        status = mbedtls_transparent_test_driver_rsa_export_public_key(
                      attributes,
                      key_buffer, key_buffer_size,
                      data, data_size, data_length );
    }
    else
#endif
    {
        status = PSA_ERROR_NOT_SUPPORTED;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)key_type;
    }

    return( status );
}

psa_status_t test_opaque_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length )
{
#if defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
    if( psa_key_id_is_builtin( MBEDTLS_SVC_KEY_ID_GET_KEY_ID( psa_get_key_id( attributes ) ) ) )
    {
        if( key_length != sizeof( psa_drv_slot_number_t ) )
            return( PSA_ERROR_INVALID_ARGUMENT );

        if( memcmp( key, &ecdsa_slot, sizeof( psa_drv_slot_number_t ) ) == 0 )
        {
            /* This is the ECDSA slot. Verify key attributes before returning pubkey. */
            if( psa_get_key_type( attributes ) != PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 ) )
                return( PSA_ERROR_CORRUPTION_DETECTED );
            if( psa_get_key_bits( attributes ) != 256 )
                return( PSA_ERROR_CORRUPTION_DETECTED );
            if( psa_get_key_algorithm( attributes ) != PSA_ALG_ECDSA( PSA_ALG_ANY_HASH ) )
                return( PSA_ERROR_CORRUPTION_DETECTED );

            if( data_size < sizeof( test_driver_ecdsa_pubkey ) )
                return( PSA_ERROR_BUFFER_TOO_SMALL );

            memcpy(data, test_driver_ecdsa_pubkey, sizeof( test_driver_ecdsa_pubkey ) );
            *data_length = sizeof( test_driver_ecdsa_pubkey );
            return( PSA_SUCCESS );
        }

        /* Potentially add more slots here */

        return( PSA_ERROR_DOES_NOT_EXIST );
    }
#endif /* MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) data;
    (void) data_size;
    (void) data_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

/* The opaque test driver exposes two built-in keys when builtin key support is
 * compiled in.
 * The key in slot #PSA_CRYPTO_TEST_DRIVER_BUILTIN_AES_KEY_SLOT is an AES-128 key which allows CTR mode
 * The key in slot #PSA_CRYPTO_TEST_DRIVER_BUILTIN_ECDSA_KEY_SLOT is a secp256r1 private key which allows ECDSA sign & verify
 * The key buffer format for these is the raw format of psa_drv_slot_number_t
 * (i.e. for an actual driver this would mean 'builtin_key_size' = sizeof(psa_drv_slot_number_t))
 */
psa_status_t test_opaque_get_builtin_key(
    psa_drv_slot_number_t slot_number,
    psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length )
{
#if defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
    switch( slot_number )
    {
        case PSA_CRYPTO_TEST_DRIVER_BUILTIN_AES_KEY_SLOT:
            if( key_buffer_size < sizeof( psa_drv_slot_number_t ) )
                return( PSA_ERROR_BUFFER_TOO_SMALL );

            psa_set_key_type( attributes, PSA_KEY_TYPE_AES );
            psa_set_key_bits( attributes, 128 );
            psa_set_key_usage_flags( attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm( attributes, PSA_ALG_CTR );

            *( (psa_drv_slot_number_t*) key_buffer ) =
                PSA_CRYPTO_TEST_DRIVER_BUILTIN_AES_KEY_SLOT;
            *key_buffer_length = sizeof( psa_drv_slot_number_t );
            return( PSA_SUCCESS );
        case PSA_CRYPTO_TEST_DRIVER_BUILTIN_ECDSA_KEY_SLOT:
            if( key_buffer_size < sizeof( psa_drv_slot_number_t ) )
                return( PSA_ERROR_BUFFER_TOO_SMALL );

            psa_set_key_type( attributes, PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 ) );
            psa_set_key_bits( attributes, 256 );
            psa_set_key_usage_flags( attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm( attributes, PSA_ALG_ECDSA( PSA_ALG_ANY_HASH ) );

            *( (psa_drv_slot_number_t*) key_buffer) =
                PSA_CRYPTO_TEST_DRIVER_BUILTIN_ECDSA_KEY_SLOT;
            *key_buffer_length = sizeof( psa_drv_slot_number_t );
            return( PSA_SUCCESS );
        default:
            (void) slot_number;
            (void) attributes;
            (void) key_buffer;
            (void) key_buffer_size;
            (void) key_buffer_length;
            return( PSA_ERROR_INVALID_ARGUMENT );
    }
#else /* MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */
    (void) slot_number;
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) key_buffer_length;
    return( PSA_ERROR_DOES_NOT_EXIST );
#endif /* MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */
}

#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
