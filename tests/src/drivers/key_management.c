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

psa_status_t test_transparent_validate_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    size_t *bits )
{
    ++test_driver_key_management_hooks.hits;

    if( test_driver_key_management_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_key_management_hooks.forced_status );

#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)
    psa_key_type_t type = psa_get_key_type( attributes );
    if ( PSA_KEY_TYPE_IS_ECC( type ) )
    {
        // Code mostly copied from psa_load_ecp_representation
        psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY( type );
        mbedtls_ecp_group_id grp_id;
        mbedtls_ecp_keypair ecp;
        psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

        if( psa_get_key_bits( attributes ) == 0 )
        {
            // Attempt auto-detect of curve bit size
            size_t curve_size = data_length;

            if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) &&
                PSA_KEY_TYPE_ECC_GET_FAMILY( type ) != PSA_ECC_FAMILY_MONTGOMERY )
            {
                /* A Weierstrass public key is represented as:
                 * - The byte 0x04;
                 * - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
                 * - `y_P` as a `ceiling(m/8)`-byte string, big-endian.
                 * So its data length is 2m+1 where m is the curve size in bits.
                 */
                if( ( data_length & 1 ) == 0 )
                    return( PSA_ERROR_INVALID_ARGUMENT );
                curve_size = data_length / 2;

                /* Montgomery public keys are represented in compressed format, meaning
                 * their curve_size is equal to the amount of input. */

                /* Private keys are represented in uncompressed private random integer
                 * format, meaning their curve_size is equal to the amount of input. */
            }

            grp_id = mbedtls_ecc_group_of_psa( curve, curve_size );
        }
        else
        {
            grp_id = mbedtls_ecc_group_of_psa( curve,
                PSA_BITS_TO_BYTES( psa_get_key_bits( attributes ) ) );
        }

        const mbedtls_ecp_curve_info *curve_info =
            mbedtls_ecp_curve_info_from_grp_id( grp_id );

        if( attributes->domain_parameters_size != 0 )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( grp_id == MBEDTLS_ECP_DP_NONE || curve_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );

        *bits = curve_info->bit_size;

        mbedtls_ecp_keypair_init( &ecp );

        status = mbedtls_to_psa_error(
                    mbedtls_ecp_group_load( &ecp.grp, grp_id ) );
        if( status != PSA_SUCCESS )
            goto ecp_exit;

        /* Load the key material. */
        if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) )
        {
            /* Load the public value. */
            status = mbedtls_to_psa_error(
                mbedtls_ecp_point_read_binary( &ecp.grp, &ecp.Q,
                                               data,
                                               data_length ) );
            if( status != PSA_SUCCESS )
                goto ecp_exit;

            /* Check that the point is on the curve. */
            status = mbedtls_to_psa_error(
                mbedtls_ecp_check_pubkey( &ecp.grp, &ecp.Q ) );
        }
        else
        {
            /* Load and validate the secret value. */
            status = mbedtls_to_psa_error(
                mbedtls_ecp_read_key( ecp.grp.id,
                                      &ecp,
                                      data,
                                      data_length ) );
        }

ecp_exit:
        mbedtls_ecp_keypair_free( &ecp );
        return( status );
    }
    return( PSA_ERROR_NOT_SUPPORTED );
#else
    (void) attributes;
    (void) data;
    (void) data_length;
    (void) bits;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR ||
        * MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY */
}

psa_status_t test_transparent_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
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

    if( key == NULL || key_length == 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    psa_key_type_t keytype = psa_get_key_type( attributes );
    (void) keytype;

#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)
    if( PSA_KEY_TYPE_IS_ECC( keytype ) )
    {
        if( !PSA_KEY_TYPE_IS_KEY_PAIR( keytype ) )
            return( PSA_ERROR_INVALID_ARGUMENT );

        /* Mostly copied from psa_crypto.c */
        mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_NONE;
        psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
        mbedtls_ecp_keypair ecp;
        mbedtls_test_rnd_pseudo_info rnd_info;
        memset( &rnd_info, 0x5A, sizeof( mbedtls_test_rnd_pseudo_info ) );

        if( attributes->domain_parameters_size != 0 )
            return( PSA_ERROR_NOT_SUPPORTED );

        grp_id = mbedtls_ecc_group_of_psa( PSA_KEY_TYPE_ECC_GET_FAMILY( keytype ),
                                           PSA_BITS_TO_BYTES( psa_get_key_bits( attributes ) ) );
        if( grp_id == MBEDTLS_ECP_DP_NONE )
            return( PSA_ERROR_NOT_SUPPORTED );

        mbedtls_ecp_keypair_init( &ecp );

        status = mbedtls_to_psa_error(
                    mbedtls_ecp_group_load( &ecp.grp, grp_id ) );
        if( status != PSA_SUCCESS )
            goto ecp_exit;

        status = mbedtls_to_psa_error(
            mbedtls_ecp_read_key( ecp.grp.id,
                                  &ecp,
                                  key,
                                  key_length ) );
        if( status != PSA_SUCCESS )
            goto ecp_exit;

        /* Calculate the public key */
        status = mbedtls_to_psa_error(
            mbedtls_ecp_mul( &ecp.grp, &ecp.Q, &ecp.d, &ecp.grp.G,
                             &mbedtls_test_rnd_pseudo_rand,
                             &rnd_info ) );
        if( status != PSA_SUCCESS )
            goto ecp_exit;

        status = mbedtls_to_psa_error(
                    mbedtls_ecp_point_write_binary( &ecp.grp, &ecp.Q,
                                                    MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                    data_length,
                                                    data,
                                                    data_size ) );
        if( status != PSA_SUCCESS )
            memset( data, 0, data_size );
ecp_exit:
        mbedtls_ecp_keypair_free( &ecp );
        return( status );
    }
#endif /* MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR ||
        * MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY */

    return( PSA_ERROR_NOT_SUPPORTED );
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
