/**
 * \file opaque_test_driver.c
 *
 * \brief   Test driver for the opaque driver interface.
 */

/*
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

#include "opaque_test_driver.h"

#if defined(MBEDTLS_OPAQUE_TEST_DRIVER_C)

#include "test/random.h"

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

#include <string.h>

/* Parameter validation macro */
#define OPQTD_VALIDATE_RET( cond )                  \
    do {                                            \
        if( !(cond) )                               \
        {                                           \
            return( PSA_ERROR_INVALID_ARGUMENT );   \
        }                                           \
    } while( 0 )

static psa_status_t mbedtls_to_psa_error( int ret );
static void rot13( const uint8_t *in,
                   size_t len,
                   uint8_t *out )
{
    char c;
    for(; len ; len--, in++, out++)
    {
        c = (char) *in;
        if (c >= 'a' && c <= 'm') { *out = c + 13; continue; }
        if (c >= 'A' && c <= 'M') { *out = c + 13; continue; }
        if (c >= 'n' && c <= 'z') { *out = c - 13; continue; }
        if (c >= 'N' && c <= 'Z') { *out = c - 13; continue; }
        *out = *in;
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

#endif /* defined(MBEDTLS_OPAQUE_TEST_DRIVER_C) */
