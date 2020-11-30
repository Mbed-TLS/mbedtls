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

psa_status_t test_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length )
{
#if !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) && \
    !defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)
    (void)attributes;
#endif /* !MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR &&
        * !MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY */
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
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)
    if ( PSA_KEY_TYPE_IS_ECC( psa_get_key_type( attributes ) )
         && PSA_KEY_TYPE_IS_KEY_PAIR( psa_get_key_type( attributes ) ) )
    {
        psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY(
            psa_get_key_type( attributes ) );
        mbedtls_ecp_group_id grp_id =
            mbedtls_ecc_group_of_psa(
                curve,
                PSA_BITS_TO_BYTES( psa_get_key_bits( attributes ) ) );
        const mbedtls_ecp_curve_info *curve_info =
            mbedtls_ecp_curve_info_from_grp_id( grp_id );
        mbedtls_ecp_keypair ecp;
        mbedtls_test_rnd_pseudo_info rnd_info;
        memset( &rnd_info, 0x5A, sizeof( mbedtls_test_rnd_pseudo_info ) );

        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        if( attributes->domain_parameters_size != 0 )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( grp_id == MBEDTLS_ECP_DP_NONE || curve_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( curve_info->bit_size != psa_get_key_bits( attributes ) )
            return( PSA_ERROR_INVALID_ARGUMENT );
        mbedtls_ecp_keypair_init( &ecp );
        ret = mbedtls_ecp_gen_key( grp_id, &ecp,
                                   &mbedtls_test_rnd_pseudo_rand,
                                   &rnd_info );
        if( ret != 0 )
        {
            mbedtls_ecp_keypair_free( &ecp );
            return( mbedtls_to_psa_error( ret ) );
        }

        /* Make sure to use export representation */
        size_t bytes = PSA_BITS_TO_BYTES( psa_get_key_bits( attributes ) );
        if( key_size < bytes )
        {
            mbedtls_ecp_keypair_free( &ecp );
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        }
        psa_status_t status = mbedtls_to_psa_error(
            mbedtls_mpi_write_binary( &ecp.d, key, bytes ) );

        if( status == PSA_SUCCESS )
        {
            *key_length = bytes;
        }
        else
        {
            memset( key, 0, bytes );
        }

        mbedtls_ecp_keypair_free( &ecp );
        return( status );
    }
    else
#endif /* MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR ||
        * MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY */
    return( PSA_ERROR_NOT_SUPPORTED );
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
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) data;
    (void) data_size;
    (void) data_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
