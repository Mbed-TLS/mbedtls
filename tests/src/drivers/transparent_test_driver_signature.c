/*
 *  Test driver for transparent driver signature interface
 *
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS) && defined(TRANSPARENT_TEST_DRIVER)

#include "drivers/transparent_test_driver.h"
#include "psa/crypto.h"
#include "mbedtls/ecdsa.h"
#include "test/random.h"
#include <string.h>

/* Parameter validation macro */
#define _VALIDATE_PARAM( cond )  \
    do {                                            \
        if( !(cond) )                               \
        {                                           \
            return( PSA_ERROR_INVALID_ARGUMENT );   \
        }                                           \
    } while( 0 )

/****************************************************************/
/* Transparent Driver Signature Interface functions             */
/****************************************************************/

psa_status_t transparent_test_driver_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    _VALIDATE_PARAM( attributes != NULL );
    _VALIDATE_PARAM( key != NULL );
    _VALIDATE_PARAM( hash != NULL );
    _VALIDATE_PARAM( signature != NULL );
    _VALIDATE_PARAM( signature_length != NULL );

    if( PSA_KEY_LIFETIME_GET_LOCATION( psa_get_key_lifetime( attributes ) )
        != PSA_KEY_LOCATION_LOCAL_STORAGE )
    {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

    if ( key_length == 0 )
    {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
  ( defined(MBEDTLS_SHA256_C) || defined(MBEDTLS_SHA384_C) )

    mbedtls_ecp_group_id grp_id;
    switch( psa_get_key_type( attributes ) )
    {
        case PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_CURVE_SECP_R1 ):

            switch( psa_get_key_bits( attributes ) )
            {
                case 256:
                    grp_id = MBEDTLS_ECP_DP_SECP256R1;
                    break;
                case 384:
                    grp_id = MBEDTLS_ECP_DP_SECP384R1;
                    break;
                case 521:
                    grp_id = MBEDTLS_ECP_DP_SECP521R1;
                    break;
                default:
                    return( PSA_ERROR_NOT_SUPPORTED );
            }
            break;
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    mbedtls_md_type_t md_alg;
    switch( alg )
    {
        case PSA_ALG_DETERMINISTIC_ECDSA( PSA_ALG_SHA_256 ):
            md_alg = MBEDTLS_MD_SHA256;
            break;
        case PSA_ALG_DETERMINISTIC_ECDSA( PSA_ALG_SHA_384 ):
            md_alg = MBEDTLS_MD_SHA384;
            break;
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    /* Beyond this point, the driver is actually doing the work of
     * calculating the signature. */

    status = PSA_ERROR_GENERIC_ERROR;
    int ret = 0;
    mbedtls_mpi r, s;
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );
    mbedtls_ecp_keypair ecp;
    mbedtls_ecp_keypair_init( &ecp );
    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &ecp.grp, grp_id ) );
    size_t curve_bytes = PSA_BITS_TO_BYTES( ecp.grp.pbits );

    MBEDTLS_MPI_CHK( mbedtls_ecp_read_key( grp_id, &ecp, key, key_length ) );

    /* Code adapted from psa_ecdsa_sign() in psa_crypto.c. */
    if( signature_size < 2 * curve_bytes )
    {
        ret = status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_ecdsa_sign_det( &ecp.grp, &r, &s, &ecp.d,
                                  hash, hash_length, md_alg ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &r,
                                               signature,
                                               curve_bytes ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &s,
                                               signature + curve_bytes,
                                               curve_bytes ) );
cleanup:
    if( ret == 0 )
        status = PSA_SUCCESS;
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    mbedtls_ecp_keypair_free( &ecp );
    if( status == PSA_SUCCESS )
        *signature_length = 2 * curve_bytes;
#else /* defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
         ( defined(MBEDTLS_SHA256_C) || defined(MBEDTLS_SHA384_C) ) */
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
#endif /* defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
         ( defined(MBEDTLS_SHA256_C) || defined(MBEDTLS_SHA384_C) ) */

    return( status );
}

psa_status_t transparent_test_driver_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length )
{
    _VALIDATE_PARAM( attributes != NULL );
    _VALIDATE_PARAM( key != NULL );
    _VALIDATE_PARAM( hash != NULL );
    _VALIDATE_PARAM( signature != NULL );

    psa_key_type_t key_type = psa_get_key_type( attributes );
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    if( PSA_KEY_LIFETIME_GET_LOCATION( psa_get_key_lifetime( attributes ) )
        != PSA_KEY_LOCATION_LOCAL_STORAGE )
    {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

    if ( key_length == 0 ) {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
  ( defined(MBEDTLS_SHA256_C) || defined(MBEDTLS_SHA384_C) )

    mbedtls_ecp_group_id grp_id;
    switch( key_type )
    {
        case PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_CURVE_SECP_R1 ):
            switch( psa_get_key_bits( attributes ) )
            {
                case 256:
                    grp_id = MBEDTLS_ECP_DP_SECP256R1;
                    break;
                case 384:
                    grp_id = MBEDTLS_ECP_DP_SECP384R1;
                    break;
                case 521:
                    grp_id = MBEDTLS_ECP_DP_SECP521R1;
                    break;
                default:
                    return( PSA_ERROR_NOT_SUPPORTED );
            }
            break;
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    switch( alg )
    {
        case PSA_ALG_DETERMINISTIC_ECDSA( PSA_ALG_SHA_256 ):
        case PSA_ALG_DETERMINISTIC_ECDSA( PSA_ALG_SHA_384 ):
            break;
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    /* Beyond this point, the driver is actually doing the work of
     * calculating the signature. */

    status = PSA_ERROR_GENERIC_ERROR;
    int ret = 0;
    mbedtls_mpi r, s;
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );
    mbedtls_ecp_keypair ecp;
    mbedtls_ecp_keypair_init( &ecp );
    mbedtls_test_rnd_pseudo_info rnd_info;
    memset( &rnd_info, 0x5A, sizeof( mbedtls_test_rnd_pseudo_info ) );

    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &ecp.grp, grp_id ) );

    size_t curve_bytes = PSA_BITS_TO_BYTES( ecp.grp.pbits );

    /* Code adapted from psa_ecdsa_verify() in psa_crypto.c. */
    if( signature_length < 2 * curve_bytes )
    {
        ret = status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &r,
                                              signature,
                                              curve_bytes ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &s,
                                              signature + curve_bytes,
                                              curve_bytes ) );

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( key_type ) ) {
        MBEDTLS_MPI_CHK( mbedtls_ecp_point_read_binary( &ecp.grp, &ecp.Q,
                                                    key, key_length ) );
    } else {
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ecp.d, key, key_length ) );
        MBEDTLS_MPI_CHK(
            mbedtls_ecp_mul( &ecp.grp, &ecp.Q, &ecp.d, &ecp.grp.G,
                             &mbedtls_test_rnd_pseudo_rand,
                             &rnd_info ) );
    }
    // Preset status
    // status will be set to PSA_SUCCESS if mbedtls_ecdsa_verify returns 0.
    status = PSA_ERROR_INVALID_SIGNATURE;
    MBEDTLS_MPI_CHK( mbedtls_ecdsa_verify( &ecp.grp, hash, hash_length,
                                &ecp.Q, &r, &s ) );
cleanup:
    if( ret == 0 )
        status = PSA_SUCCESS;
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    mbedtls_ecp_keypair_free( &ecp );
#else /* defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
         ( defined(MBEDTLS_SHA256_C) || defined(MBEDTLS_SHA384_C) ) */
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
#endif /* defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
         ( defined(MBEDTLS_SHA256_C) || defined(MBEDTLS_SHA384_C) ) */

    return( status );
}

#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && TRANSPARENT_TEST_DRIVER */
