/*
 * Test driver for generating keys.
 * Currently only supports generating ECC keys.
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

#include "drivers/keygen.h"

#include "test/random.h"

#include <string.h>

test_driver_keygen_hooks_t test_driver_keygen_hooks = TEST_DRIVER_KEYGEN_INIT;

psa_status_t test_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length )
{
    ++test_driver_keygen_hooks.hits;

    if( test_driver_keygen_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_keygen_hooks.forced_status );

    if( test_driver_keygen_hooks.forced_output != NULL )
    {
        if( test_driver_keygen_hooks.forced_output_length > key_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( key, test_driver_keygen_hooks.forced_output,
                test_driver_keygen_hooks.forced_output_length );
        *key_length = test_driver_keygen_hooks.forced_output_length;
        return( PSA_SUCCESS );
    }

    /* Copied from psa_crypto.c */
#if defined(MBEDTLS_ECP_C)
    if ( PSA_KEY_TYPE_IS_ECC( psa_get_key_type( attributes ) )
         && PSA_KEY_TYPE_IS_KEY_PAIR( psa_get_key_type( attributes ) ) )
    {
        psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY( psa_get_key_type( attributes ) );
        mbedtls_ecp_group_id grp_id =
            mbedtls_ecc_group_of_psa( curve, PSA_BITS_TO_BYTES( psa_get_key_bits( attributes ) ) );
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

        mbedtls_ecp_keypair_free( &ecp );
        return( status );
    }
    else
#endif /* MBEDTLS_ECP_C */
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

#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
