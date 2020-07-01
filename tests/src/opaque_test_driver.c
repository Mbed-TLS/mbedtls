/**
 * \file opaque_test_driver.c
 *
 * \brief   This file contains the opaque driver sample implementation.
 */

/*
 *  Copyright (C) 2020, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include "opaque_test_driver.h"

#if defined(MBEDTLS_OPAQUE_TEST_DRIVER_C)

#include "test/random.h"
#include "mbedtls/error.h"
#include <string.h>
#include <ctype.h>

/* Parameter validation macros */
#define OPQTD_VALIDATE_RET( cond ) \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, PSA_ERROR_INVALID_ARGUMENT )
#define OPQTD_VALIDATE( cond ) \
    MBEDTLS_INTERNAL_VALIDATE( cond )


static void rot13( const uint8_t *in,
                   size_t len,
                   uint8_t *out )
{
    char c;
    while( len-- )
    {
        c = (char) *in;
        *out = isalpha( c ) ? tolower(c) < 'n' ? c+13 : c-13 : c;
        in++;
        out++;
    }
}

psa_status_t opaque_test_driver_export_public_key(
                                        const psa_key_attributes_t *attributes,
                                        const uint8_t *in,
                                        size_t in_length,
                                        uint8_t *out,
                                        size_t out_size,
                                        size_t *out_length )
{
    OPQTD_VALIDATE_RET( attributes != NULL );
    OPQTD_VALIDATE_RET( in != NULL );
    OPQTD_VALIDATE_RET( out != NULL );
    OPQTD_VALIDATE_RET( out_length != NULL );

    (void) attributes;

    if( in_length <= OPAQUE_TEST_DRIVER_KEYHEADER_SIZE )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( in_length - OPAQUE_TEST_DRIVER_KEYHEADER_SIZE > out_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    *out_length = in_length - OPAQUE_TEST_DRIVER_KEYHEADER_SIZE;
    rot13( in + OPAQUE_TEST_DRIVER_KEYHEADER_SIZE, *out_length, out );

    return( PSA_SUCCESS );
}

psa_status_t opaque_test_driver_generate_key(
                                        const psa_key_attributes_t *attributes,
                                        uint8_t *key,
                                        size_t key_size,
                                        size_t *key_length )
{
    psa_status_t status;
    uint8_t key_buffer[32];
    size_t key_buffer_length;

    OPQTD_VALIDATE_RET( attributes != NULL );
    OPQTD_VALIDATE_RET( key != NULL );
    OPQTD_VALIDATE_RET( key_length != NULL );

    if( psa_get_key_bits( attributes ) == 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( psa_get_key_type( attributes ) != PSA_KEY_TYPE_AES )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( ( psa_get_key_bits( attributes ) != 128 ) &&      // AES-128
        ( psa_get_key_bits( attributes ) != 192 ) &&      // AES-192
        ( psa_get_key_bits( attributes ) != 256 ) )       // AES-256
        return( PSA_ERROR_NOT_SUPPORTED );

    if( OPAQUE_TEST_DRIVER_KEYHEADER_SIZE +
        PSA_BITS_TO_BYTES( psa_get_key_bits( attributes ) ) > key_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    /* Generate key data. */
    if( PSA_KEY_TYPE_IS_UNSTRUCTURED( attributes->core.type ) )
    {
        key_buffer_length = PSA_BITS_TO_BYTES( psa_get_key_bits( attributes ) );
        status = psa_generate_random( key_buffer, key_buffer_length );
        if( status != PSA_SUCCESS )
            return( status );
    }
    else
#if defined(MBEDTLS_ECP_C)
    if ( PSA_KEY_TYPE_IS_ECC( attributes->core.type ) && PSA_KEY_TYPE_IS_KEY_PAIR( attributes->core.type ) )
    {
        psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY( attributes->core.type );
        mbedtls_ecp_group_id grp_id =
            mbedtls_ecc_group_of_psa( curve, PSA_BITS_TO_BYTES( attributes->core.bits ) );
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
        if( curve_info->bit_size != attributes->core.bits )
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
        size_t bytes = PSA_BITS_TO_BYTES( attributes->core.bits );
        if( key_size < bytes )
        {
            mbedtls_ecp_keypair_free( &ecp );
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        }
        psa_status_t status = mbedtls_to_psa_error(
            mbedtls_mpi_write_binary( &ecp.d, key, bytes ) );

        if( status == PSA_SUCCESS )
            *key_length = bytes;

        mbedtls_ecp_keypair_free( &ecp );
        return( status );
    }

    else
#endif /* MBEDTLS_ECP_C */
        return( PSA_ERROR_NOT_SUPPORTED );

    return( opaque_test_driver_import_key( attributes,
                                           key_buffer,
                                           key_buffer_length,
                                           key,
                                           key_size,
                                           key_length ) );
}

psa_status_t opaque_test_driver_import_key(
                                        const psa_key_attributes_t *attributes,
                                        const uint8_t *in,
                                        size_t in_length,
                                        uint8_t *out,
                                        size_t out_size,
                                        size_t *out_length )
{
    OPQTD_VALIDATE_RET( attributes != NULL );
    OPQTD_VALIDATE_RET( in != NULL );
    OPQTD_VALIDATE_RET( out != NULL );
    OPQTD_VALIDATE_RET( out_length != NULL );

    if( ( psa_get_key_type( attributes ) != PSA_KEY_TYPE_AES ) &&
        ( psa_get_key_type( attributes ) !=
          PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_CURVE_SECP_R1 ) ) )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( ( psa_get_key_bits( attributes ) != 128 ) &&      // AES-128
        ( psa_get_key_bits( attributes ) != 192 ) &&      // AES-192
        ( psa_get_key_bits( attributes ) != 256 ) )       // AES-256
        return( PSA_ERROR_NOT_SUPPORTED );

    if( psa_get_key_bits( attributes ) != PSA_BYTES_TO_BITS( in_length ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( OPAQUE_TEST_DRIVER_KEYHEADER_SIZE + in_length > out_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    strcpy( (char *) out, OPAQUE_TEST_DRIVER_KEYHEADER );

    /* Obscure key slightly. */
    rot13( in, in_length, out + OPAQUE_TEST_DRIVER_KEYHEADER_SIZE );

    *out_length = in_length + OPAQUE_TEST_DRIVER_KEYHEADER_SIZE;

    return( PSA_SUCCESS );
}

psa_status_t opaque_test_driver_sign_hash(
                                        const psa_key_attributes_t *attributes,
                                        const uint8_t *key,
                                        size_t key_length,
                                        psa_algorithm_t alg,
                                        const uint8_t *hash,
                                        size_t hash_length,
                                        uint8_t *signature,
                                        size_t signature_size,
                                        size_t *signature_length )
{
    #define OPQ_BUFSIZE 64
    size_t key_buffer_length;
    psa_key_handle_t handle = 0;
    uint8_t key_buffer[OPQ_BUFSIZE];
    psa_status_t status = PSA_SUCCESS;

    OPQTD_VALIDATE_RET( attributes != NULL );
    OPQTD_VALIDATE_RET( key != NULL );
    OPQTD_VALIDATE_RET( hash != NULL );
    OPQTD_VALIDATE_RET( signature != NULL );
    OPQTD_VALIDATE_RET( signature_length != NULL );

    if( key_length <= OPAQUE_TEST_DRIVER_KEYHEADER_SIZE )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = opaque_test_driver_export_public_key( attributes,
                                                   key,
                                                   key_length,
                                                   key_buffer,
                                                   OPQ_BUFSIZE,
                                                   &key_buffer_length );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_import_key( attributes,
                             key_buffer, key_buffer_length,
                             &handle );
    if( status != PSA_SUCCESS )
        return( status );

    if( PSA_SIGN_OUTPUT_SIZE( psa_get_key_type( attributes ),
                              psa_get_key_bits( attributes ),
                              alg ) > signature_size )
    {
        psa_destroy_key( handle );
        return( PSA_ERROR_BUFFER_TOO_SMALL );
    }

    status = psa_sign_hash( handle, alg, hash, hash_length,
                            signature, signature_size, signature_length );
    if( status != PSA_SUCCESS )
    {
        psa_destroy_key( handle );
        return( status );
    }

    status = psa_destroy_key( handle );
    if( status != PSA_SUCCESS )
        return( status );

    return( status );
    #undef OPQ_BUFSIZE
}

psa_status_t opaque_test_driver_verify_hash(
                                        const psa_key_attributes_t *attributes,
                                        const uint8_t *key,
                                        size_t key_length,
                                        psa_algorithm_t alg,
                                        const uint8_t *hash,
                                        size_t hash_length,
                                        const uint8_t *signature,
                                        size_t signature_length )
{
    #define OPQ_BUFSIZE 64
    size_t key_buffer_length;
    psa_key_handle_t handle = 0;
    uint8_t key_buffer[OPQ_BUFSIZE];
    psa_status_t status = PSA_SUCCESS;

    OPQTD_VALIDATE_RET( attributes != NULL );
    OPQTD_VALIDATE_RET( key != NULL );
    OPQTD_VALIDATE_RET( hash != NULL );
    OPQTD_VALIDATE_RET( signature != NULL );

    if( key_length <= OPAQUE_TEST_DRIVER_KEYHEADER_SIZE )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = opaque_test_driver_export_public_key( attributes,
                                                   key,
                                                   key_length,
                                                   key_buffer,
                                                   OPQ_BUFSIZE,
                                                   &key_buffer_length );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_import_key( attributes,
                             key_buffer, key_buffer_length,
                             &handle );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_verify_hash( handle, alg, hash, hash_length,
                              signature, signature_length );
    if( status != PSA_SUCCESS )
    {
        psa_destroy_key( handle );
        return( status );
    }

    status = psa_destroy_key( handle );
    if( status != PSA_SUCCESS )
        return( status );

    return( status );
    #undef OPQ_BUFSIZE
}

#endif /* defined(MBEDTLS_OPAQUE_TEST_DRIVER_C) */
