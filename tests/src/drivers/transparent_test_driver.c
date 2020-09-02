/*
 *  Test driver for transparent driver interface
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

#include "psa/crypto.h"

#include "mbedtls/arc4.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/blowfish.h"
#include "mbedtls/camellia.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ccm.h"
#include "mbedtls/cmac.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/des.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md2.h"
#include "mbedtls/md4.h"
#include "mbedtls/md5.h"
#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/xtea.h"

#include "drivers/transparent_test_driver.h"

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
/* static forward declarations                                  */
/****************************************************************/

static psa_status_t mbedtls_to_psa_error( int ret );
static int pk_write_pubkey_simple( mbedtls_pk_context *key,
                                   unsigned char *buf, size_t size );
static int key_type_is_raw_bytes( psa_key_type_t type );
static psa_status_t psa_import_ec_private_key( psa_ecc_family_t curve,
                                               const uint8_t *data,
                                               size_t data_length,
                                               mbedtls_ecp_keypair **p_ecp );

/****************************************************************/
/* Transparent Driver Interface functions               */
/****************************************************************/
psa_status_t transparent_test_driver_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length )
{
    _VALIDATE_PARAM( attributes != NULL );
    _VALIDATE_PARAM( key != NULL );
    _VALIDATE_PARAM( key_length != NULL );

    size_t key_bits = psa_get_key_bits( attributes );
    psa_key_type_t type = attributes->core.type;

    if( key_type_is_raw_bytes( type ) )
    {
        psa_status_t status;
        switch( key_bits )
        {
            case 128:
            case 192:
            case 256:
                break;
            default:
               return( PSA_ERROR_NOT_SUPPORTED );
        }

        if ( key_bits/8 > key_size ) {
          return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        status = psa_generate_random( key, key_size );

        if( status != PSA_SUCCESS )
            return( status );
    }
    else

    /* Copied from psa_crypto.c */
#if defined(MBEDTLS_ECP_C)
    if ( PSA_KEY_TYPE_IS_ECC( type ) && PSA_KEY_TYPE_IS_KEY_PAIR( type ) )
    {
        psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY( type );
        mbedtls_ecp_group_id grp_id =
            mbedtls_ecc_group_of_psa( curve, PSA_BITS_TO_BYTES( attributes->core.bits ) );
        const mbedtls_ecp_curve_info *curve_info =
            mbedtls_ecp_curve_info_from_grp_id( grp_id );
        mbedtls_ecp_keypair ecp;
        mbedtls_test_rnd_pseudo_info rnd_info;
        memset( &rnd_info, 0x5A, sizeof( mbedtls_test_rnd_pseudo_info ) );

        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
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
            mbedtls_ecp_write_key( &ecp, key, bytes ) );

        if( status == PSA_SUCCESS )
        {
            *key_length = bytes;
        }

        mbedtls_ecp_keypair_free( &ecp );
        return( status );
    }
    else
#endif /* MBEDTLS_ECP_C */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }
    return( PSA_SUCCESS );
}

psa_status_t transparent_test_driver_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key,
    size_t key_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length)
{
    _VALIDATE_PARAM( attributes != NULL );
    _VALIDATE_PARAM( key != NULL );
    _VALIDATE_PARAM( data != NULL );
    _VALIDATE_PARAM( data_length != NULL );

    psa_key_type_t type = attributes->core.type;

    if ( key_size == 0 ) {
      return PSA_ERROR_INVALID_ARGUMENT;
    }

    if( key_type_is_raw_bytes( type ) )
    {
        if( key_size > data_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( data, key, key_size );
        memset( data + key_size, 0, data_size - key_size );
        *data_length = key_size;
        return( PSA_SUCCESS );
    }

#if defined(MBEDTLS_ECP_C)
    mbedtls_pk_context pk;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status;
    mbedtls_ecp_keypair ecp;
    mbedtls_ecp_keypair *p_ecp = &ecp;

    status = psa_import_ec_private_key( PSA_KEY_TYPE_ECC_GET_FAMILY( type ),
                                        key, key_size,
                                        &p_ecp );
    if( status != PSA_SUCCESS )
        return status;

    mbedtls_pk_init( &pk );
    pk.pk_info = &mbedtls_eckey_info;
    pk.pk_ctx = p_ecp;

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( type ) )
    {
        ret = pk_write_pubkey_simple( &pk, data, data_size );
    }
    else
    {
        ret = mbedtls_pk_write_key_der( &pk, data, data_size );
    }
    if( ret < 0 )
    {
        memset( data, 0, data_size );
        return( mbedtls_to_psa_error( ret ) );
    }
    /* The mbedtls_pk_xxx functions write to the end of the buffer.
     * Move the data to the beginning and erase remaining data
     * at the original location. */
    if( 2 * (size_t) ret <= data_size )
    {
        memcpy( data, data + data_size - ret, ret );
        memset( data + data_size - ret, 0, ret );
    }
    else if( (size_t) ret < data_size )
    {
      memmove( data, data + data_size - ret, ret );
      memset( data + ret, 0, data_size - ret );
    }
    *data_length = ret;
    return( PSA_SUCCESS );
#else
    return( PSA_ERROR_NOT_SUPPORTED );
#endif
}

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

    if ( key_length == 0 ) {
      return PSA_ERROR_INVALID_ARGUMENT;
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
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    _VALIDATE_PARAM( attributes != NULL );
    _VALIDATE_PARAM( key != NULL );
    _VALIDATE_PARAM( hash != NULL );
    _VALIDATE_PARAM( signature != NULL );

    if ( key_length == 0 ) {
      return PSA_ERROR_INVALID_ARGUMENT;
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

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( psa_get_key_type( attributes ) ) ) {
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

static int key_type_is_raw_bytes( psa_key_type_t type )
{
    return( PSA_KEY_TYPE_IS_UNSTRUCTURED( type ) );
}

#if defined(MBEDTLS_ECP_C)

static psa_status_t psa_prepare_import_ec_key( psa_ecc_family_t curve,
                                               size_t data_length,
                                               int is_public,
                                               mbedtls_ecp_keypair **p_ecp )
{
    mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_NONE;
    *p_ecp = mbedtls_calloc( 1, sizeof( mbedtls_ecp_keypair ) );
    if( *p_ecp == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    mbedtls_ecp_keypair_init( *p_ecp );

    if( is_public )
    {
        /* A public key is represented as:
         * - The byte 0x04;
         * - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
         * - `y_P` as a `ceiling(m/8)`-byte string, big-endian.
         * So its data length is 2m+1 where n is the key size in bits.
         */
        if( ( data_length & 1 ) == 0 )
            return( PSA_ERROR_INVALID_ARGUMENT );
        data_length = data_length / 2;
    }

    /* Load the group. */
    grp_id = mbedtls_ecc_group_of_psa( curve, data_length );
    if( grp_id == MBEDTLS_ECP_DP_NONE )
        return( PSA_ERROR_INVALID_ARGUMENT );
    return( mbedtls_to_psa_error(
                mbedtls_ecp_group_load( &( *p_ecp )->grp, grp_id ) ) );
}

/* Import a private key given as a byte string which is the private value
 * in big-endian order. */
static psa_status_t psa_import_ec_private_key( psa_ecc_family_t curve,
                                               const uint8_t *data,
                                               size_t data_length,
                                               mbedtls_ecp_keypair **p_ecp )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_keypair *ecp = NULL;

    status = psa_prepare_import_ec_key( curve, data_length, 0, &ecp );
    if( status != PSA_SUCCESS )
        goto exit;

    /* Load and validate the secret key */
    status = mbedtls_to_psa_error(
        mbedtls_ecp_read_key( ecp->grp.id, ecp, data, data_length ) );
    if( status != PSA_SUCCESS )
        goto exit;

    /* Calculate the public key from the private key. */
    status = mbedtls_to_psa_error(
        mbedtls_ecp_mul( &ecp->grp, &ecp->Q, &ecp->d, &ecp->grp.G, NULL, NULL ) );

    if( status != PSA_SUCCESS )
        goto exit;

    *p_ecp = ecp;
    return( PSA_SUCCESS );

exit:
    if( ecp != NULL )
    {
        mbedtls_ecp_keypair_free( ecp );
        mbedtls_free( ecp );
    }
    return( status );
}

static int pk_write_pubkey_simple( mbedtls_pk_context *key,
                                   unsigned char *buf, size_t size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *c;
    size_t len = 0;

    c = buf + size;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_pk_write_pubkey( &c, buf, key ) );

    return( (int) len );
}

#endif /* defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECP_C) */

static psa_status_t mbedtls_to_psa_error( int ret )
{
    /* If there's both a high-level code and low-level code, dispatch on
     * the high-level code. */
    switch( ret < -0x7f ? - ( -ret & 0x7f80 ) : ret )
    {
        case 0:
            return( PSA_SUCCESS );

        case MBEDTLS_ERR_AES_INVALID_KEY_LENGTH:
        case MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH:
        case MBEDTLS_ERR_AES_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_AES_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_ARC4_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_ASN1_OUT_OF_DATA:
        case MBEDTLS_ERR_ASN1_UNEXPECTED_TAG:
        case MBEDTLS_ERR_ASN1_INVALID_LENGTH:
        case MBEDTLS_ERR_ASN1_LENGTH_MISMATCH:
        case MBEDTLS_ERR_ASN1_INVALID_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_ASN1_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_ASN1_BUF_TOO_SMALL:
            return( PSA_ERROR_BUFFER_TOO_SMALL );

#if defined(MBEDTLS_ERR_BLOWFISH_BAD_INPUT_DATA)
        case MBEDTLS_ERR_BLOWFISH_BAD_INPUT_DATA:
#elif defined(MBEDTLS_ERR_BLOWFISH_INVALID_KEY_LENGTH)
        case MBEDTLS_ERR_BLOWFISH_INVALID_KEY_LENGTH:
#endif
        case MBEDTLS_ERR_BLOWFISH_INVALID_INPUT_LENGTH:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_BLOWFISH_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

#if defined(MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA)
        case MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA:
#elif defined(MBEDTLS_ERR_CAMELLIA_INVALID_KEY_LENGTH)
        case MBEDTLS_ERR_CAMELLIA_INVALID_KEY_LENGTH:
#endif
        case MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_CAMELLIA_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_CCM_BAD_INPUT:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_CCM_AUTH_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_CCM_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );

        case MBEDTLS_ERR_CHACHAPOLY_BAD_STATE:
            return( PSA_ERROR_BAD_STATE );
        case MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );

        case MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_CIPHER_INVALID_PADDING:
            return( PSA_ERROR_INVALID_PADDING );
        case MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED:
            return( PSA_ERROR_BAD_STATE );
        case MBEDTLS_ERR_CIPHER_AUTH_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_CIPHER_INVALID_CONTEXT:
            return( PSA_ERROR_CORRUPTION_DETECTED );
        case MBEDTLS_ERR_CIPHER_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );
        case MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG:
        case MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );

        case MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_DES_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED:
        case MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE:
        case MBEDTLS_ERR_ENTROPY_SOURCE_FAILED:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );

        case MBEDTLS_ERR_GCM_AUTH_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_GCM_BAD_INPUT:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_GCM_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_MD2_HW_ACCEL_FAILED:
        case MBEDTLS_ERR_MD4_HW_ACCEL_FAILED:
        case MBEDTLS_ERR_MD5_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_MD_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MD_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_MD_FILE_IO_ERROR:
            return( PSA_ERROR_STORAGE_FAILURE );
        case MBEDTLS_ERR_MD_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_MPI_FILE_IO_ERROR:
            return( PSA_ERROR_STORAGE_FAILURE );
        case MBEDTLS_ERR_MPI_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_INVALID_CHARACTER:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL:
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        case MBEDTLS_ERR_MPI_NEGATIVE_VALUE:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_DIVISION_BY_ZERO:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_NOT_ACCEPTABLE:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_MPI_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );

        case MBEDTLS_ERR_PK_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_PK_TYPE_MISMATCH:
        case MBEDTLS_ERR_PK_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_PK_FILE_IO_ERROR:
            return( PSA_ERROR_STORAGE_FAILURE );
        case MBEDTLS_ERR_PK_KEY_INVALID_VERSION:
        case MBEDTLS_ERR_PK_KEY_INVALID_FORMAT:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_PK_UNKNOWN_PK_ALG:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_PK_PASSWORD_REQUIRED:
        case MBEDTLS_ERR_PK_PASSWORD_MISMATCH:
            return( PSA_ERROR_NOT_PERMITTED );
        case MBEDTLS_ERR_PK_INVALID_PUBKEY:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_PK_INVALID_ALG:
        case MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE:
        case MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_PK_SIG_LEN_MISMATCH:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_PK_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );
        case MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED:
            return( PSA_ERROR_NOT_SUPPORTED );

        case MBEDTLS_ERR_RIPEMD160_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_RSA_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_RSA_INVALID_PADDING:
            return( PSA_ERROR_INVALID_PADDING );
        case MBEDTLS_ERR_RSA_KEY_GEN_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );
        case MBEDTLS_ERR_RSA_KEY_CHECK_FAILED:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_RSA_PUBLIC_FAILED:
        case MBEDTLS_ERR_RSA_PRIVATE_FAILED:
            return( PSA_ERROR_CORRUPTION_DETECTED );
        case MBEDTLS_ERR_RSA_VERIFY_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE:
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        case MBEDTLS_ERR_RSA_RNG_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_RSA_UNSUPPORTED_OPERATION:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_RSA_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_SHA1_HW_ACCEL_FAILED:
        case MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED:
        case MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_XTEA_INVALID_INPUT_LENGTH:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_XTEA_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_ECP_BAD_INPUT_DATA:
        case MBEDTLS_ERR_ECP_INVALID_KEY:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL:
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        case MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH:
        case MBEDTLS_ERR_ECP_VERIFY_FAILED:
            return( PSA_ERROR_INVALID_SIGNATURE );
        case MBEDTLS_ERR_ECP_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_ECP_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );
        case MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED:
            return( PSA_ERROR_CORRUPTION_DETECTED );

        default:
            return( PSA_ERROR_GENERIC_ERROR );
    }
}

#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && TRANSPARENT_TEST_DRIVER */
