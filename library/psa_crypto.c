/*
 *  PSA crypto layer on top of Mbed TLS crypto
 */
/*  Copyright (C) 2018, ARM Limited, All Rights Reserved
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include "psa/crypto.h"

#include <stdlib.h>
#include <string.h>
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

#include "mbedtls/arc4.h"
#include "mbedtls/asn1.h"
#include "mbedtls/blowfish.h"
#include "mbedtls/camellia.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ccm.h"
#include "mbedtls/cmac.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/des.h"
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
#include "mbedtls/ripemd160.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/xtea.h"



/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n )
{
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/* constant-time buffer comparison */
static inline int safer_memcmp( const uint8_t *a, const uint8_t *b, size_t n )
{
    size_t i;
    unsigned char diff = 0;

    for( i = 0; i < n; i++ )
        diff |= a[i] ^ b[i];

    return( diff );
}



/****************************************************************/
/* Global data, support functions and library management */
/****************************************************************/

/* Number of key slots (plus one because 0 is not used).
 * The value is a compile-time constant for now, for simplicity. */
#define PSA_KEY_SLOT_COUNT 32

typedef struct
{
    psa_key_type_t type;
    psa_key_policy_t policy;
    psa_key_lifetime_t lifetime;
    union
    {
        struct raw_data
        {
            uint8_t *data;
            size_t bytes;
        } raw;
#if defined(MBEDTLS_RSA_C)
        mbedtls_rsa_context *rsa;
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
        mbedtls_ecp_keypair *ecp;
#endif /* MBEDTLS_ECP_C */
    } data;
} key_slot_t;

static int key_type_is_raw_bytes( psa_key_type_t type )
{
    psa_key_type_t category = type & PSA_KEY_TYPE_CATEGORY_MASK;
    return( category == PSA_KEY_TYPE_RAW_DATA ||
            category == PSA_KEY_TYPE_CATEGORY_SYMMETRIC );
}

typedef struct
{
    int initialized;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    key_slot_t key_slots[PSA_KEY_SLOT_COUNT];
} psa_global_data_t;

static psa_global_data_t global_data;

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

        case MBEDTLS_ERR_BLOWFISH_INVALID_KEY_LENGTH:
        case MBEDTLS_ERR_BLOWFISH_INVALID_INPUT_LENGTH:
            return( PSA_ERROR_NOT_SUPPORTED );
        case MBEDTLS_ERR_BLOWFISH_HW_ACCEL_FAILED:
            return( PSA_ERROR_HARDWARE_FAILURE );

        case MBEDTLS_ERR_CAMELLIA_INVALID_KEY_LENGTH:
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
            return( PSA_ERROR_TAMPERING_DETECTED );
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
            return( PSA_ERROR_NOT_SUPPORTED );
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
            return( PSA_ERROR_TAMPERING_DETECTED );
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

        default:
            return( PSA_ERROR_UNKNOWN_ERROR );
    }
}



/****************************************************************/
/* Key management */
/****************************************************************/

static psa_ecc_curve_t mbedtls_ecc_group_to_psa( mbedtls_ecp_group_id grpid )
{
    switch( grpid )
    {
        case MBEDTLS_ECP_DP_SECP192R1:
            return( PSA_ECC_CURVE_SECP192R1 );
        case MBEDTLS_ECP_DP_SECP224R1:
            return( PSA_ECC_CURVE_SECP224R1 );
        case MBEDTLS_ECP_DP_SECP256R1:
            return( PSA_ECC_CURVE_SECP256R1 );
        case MBEDTLS_ECP_DP_SECP384R1:
            return( PSA_ECC_CURVE_SECP384R1 );
        case MBEDTLS_ECP_DP_SECP521R1:
            return( PSA_ECC_CURVE_SECP521R1 );
        case MBEDTLS_ECP_DP_BP256R1:
            return( PSA_ECC_CURVE_BRAINPOOL_P256R1 );
        case MBEDTLS_ECP_DP_BP384R1:
            return( PSA_ECC_CURVE_BRAINPOOL_P384R1 );
        case MBEDTLS_ECP_DP_BP512R1:
            return( PSA_ECC_CURVE_BRAINPOOL_P512R1 );
        case MBEDTLS_ECP_DP_CURVE25519:
            return( PSA_ECC_CURVE_CURVE25519 );
        case MBEDTLS_ECP_DP_SECP192K1:
            return( PSA_ECC_CURVE_SECP192K1 );
        case MBEDTLS_ECP_DP_SECP224K1:
            return( PSA_ECC_CURVE_SECP224K1 );
        case MBEDTLS_ECP_DP_SECP256K1:
            return( PSA_ECC_CURVE_SECP256K1 );
        case MBEDTLS_ECP_DP_CURVE448:
            return( PSA_ECC_CURVE_CURVE448 );
        default:
            return( 0 );
    }
}

static mbedtls_ecp_group_id mbedtls_ecc_group_of_psa( psa_ecc_curve_t curve )
{
    switch( curve )
    {
        case PSA_ECC_CURVE_SECP192R1:
            return( MBEDTLS_ECP_DP_SECP192R1 );
        case PSA_ECC_CURVE_SECP224R1:
            return( MBEDTLS_ECP_DP_SECP224R1 );
        case PSA_ECC_CURVE_SECP256R1:
            return( MBEDTLS_ECP_DP_SECP256R1 );
        case PSA_ECC_CURVE_SECP384R1:
            return( MBEDTLS_ECP_DP_SECP384R1 );
        case PSA_ECC_CURVE_SECP521R1:
            return( MBEDTLS_ECP_DP_SECP521R1 );
        case PSA_ECC_CURVE_BRAINPOOL_P256R1:
            return( MBEDTLS_ECP_DP_BP256R1 );
        case PSA_ECC_CURVE_BRAINPOOL_P384R1:
            return( MBEDTLS_ECP_DP_BP384R1 );
        case PSA_ECC_CURVE_BRAINPOOL_P512R1:
            return( MBEDTLS_ECP_DP_BP512R1 );
        case PSA_ECC_CURVE_CURVE25519:
            return( MBEDTLS_ECP_DP_CURVE25519 );
        case PSA_ECC_CURVE_SECP192K1:
            return( MBEDTLS_ECP_DP_SECP192K1 );
        case PSA_ECC_CURVE_SECP224K1:
            return( MBEDTLS_ECP_DP_SECP224K1 );
        case PSA_ECC_CURVE_SECP256K1:
            return( MBEDTLS_ECP_DP_SECP256K1 );
        case PSA_ECC_CURVE_CURVE448:
            return( MBEDTLS_ECP_DP_CURVE448 );
        default:
            return( MBEDTLS_ECP_DP_NONE );
    }
}

static psa_status_t prepare_raw_data_slot( psa_key_type_t type,
                                           size_t bits,
                                           struct raw_data *raw )
{
    /* Check that the bit size is acceptable for the key type */
    switch( type )
    {
        case PSA_KEY_TYPE_RAW_DATA:
#if defined(MBEDTLS_MD_C)
        case PSA_KEY_TYPE_HMAC:
#endif
            break;
#if defined(MBEDTLS_AES_C)
        case PSA_KEY_TYPE_AES:
            if( bits != 128 && bits != 192 && bits != 256 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(MBEDTLS_CAMELLIA_C)
        case PSA_KEY_TYPE_CAMELLIA:
            if( bits != 128 && bits != 192 && bits != 256 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(MBEDTLS_DES_C)
        case PSA_KEY_TYPE_DES:
            if( bits != 64 && bits != 128 && bits != 192 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(MBEDTLS_ARC4_C)
        case PSA_KEY_TYPE_ARC4:
            if( bits < 8 || bits > 2048 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }
    if( bits % 8 != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    /* Allocate memory for the key */
    raw->bytes = PSA_BITS_TO_BYTES( bits );
    raw->data = mbedtls_calloc( 1, raw->bytes );
    if( raw->data == NULL )
    {
        raw->bytes = 0;
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    }
    return( PSA_SUCCESS );
}

psa_status_t psa_import_key( psa_key_slot_t key,
                             psa_key_type_t type,
                             const uint8_t *data,
                             size_t data_length )
{
    key_slot_t *slot;

    if( key == 0 || key > PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_INVALID_ARGUMENT );
    slot = &global_data.key_slots[key];
    if( slot->type != PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_OCCUPIED_SLOT );

    if( key_type_is_raw_bytes( type ) )
    {
        psa_status_t status;
        /* Ensure that a bytes-to-bit conversion won't overflow. */
        if( data_length > SIZE_MAX / 8 )
            return( PSA_ERROR_NOT_SUPPORTED );
        status = prepare_raw_data_slot( type,
                                        PSA_BYTES_TO_BITS( data_length ),
                                        &slot->data.raw );
        if( status != PSA_SUCCESS )
            return( status );
        memcpy( slot->data.raw.data, data, data_length );
    }
    else
#if defined(MBEDTLS_PK_PARSE_C)
    if( type == PSA_KEY_TYPE_RSA_PUBLIC_KEY ||
        type == PSA_KEY_TYPE_RSA_KEYPAIR ||
        PSA_KEY_TYPE_IS_ECC( type ) )
    {
        int ret;
        mbedtls_pk_context pk;
        psa_status_t status = PSA_SUCCESS;
        mbedtls_pk_init( &pk );
        if( PSA_KEY_TYPE_IS_KEYPAIR( type ) )
            ret = mbedtls_pk_parse_key( &pk, data, data_length, NULL, 0 );
        else
            ret = mbedtls_pk_parse_public_key( &pk, data, data_length );
        if( ret != 0 )
            return( mbedtls_to_psa_error( ret ) );
        switch( mbedtls_pk_get_type( &pk ) )
        {
#if defined(MBEDTLS_RSA_C)
            case MBEDTLS_PK_RSA:
                if( type == PSA_KEY_TYPE_RSA_PUBLIC_KEY ||
                    type == PSA_KEY_TYPE_RSA_KEYPAIR )
                    slot->data.rsa = mbedtls_pk_rsa( pk );
                else
                    status = PSA_ERROR_INVALID_ARGUMENT;
                break;
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
            case MBEDTLS_PK_ECKEY:
                if( PSA_KEY_TYPE_IS_ECC( type ) )
                {
                    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec( pk );
                    psa_ecc_curve_t actual_curve =
                        mbedtls_ecc_group_to_psa( ecp->grp.id );
                    psa_ecc_curve_t expected_curve =
                        PSA_KEY_TYPE_GET_CURVE( type );
                    if( actual_curve != expected_curve )
                    {
                        status = PSA_ERROR_INVALID_ARGUMENT;
                        break;
                    }
                    slot->data.ecp = ecp;
                }
                else
                    status = PSA_ERROR_INVALID_ARGUMENT;
                break;
#endif /* MBEDTLS_ECP_C */
            default:
                status = PSA_ERROR_INVALID_ARGUMENT;
                break;
        }
        /* Free the content of the pk object only on error. On success,
         * the content of the object has been stored in the slot. */
        if( status != PSA_SUCCESS )
        {
            mbedtls_pk_free( &pk );
            return( status );
        }
    }
    else
#endif /* defined(MBEDTLS_PK_PARSE_C) */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    slot->type = type;
    return( PSA_SUCCESS );
}

psa_status_t psa_destroy_key( psa_key_slot_t key )
{
    key_slot_t *slot;

    if( key == 0 || key > PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_INVALID_ARGUMENT );
    slot = &global_data.key_slots[key];
    if( slot->type == PSA_KEY_TYPE_NONE )
    {
        /* No key material to clean, but do zeroize the slot below to wipe
         * metadata such as policies. */
    }
    else if( key_type_is_raw_bytes( slot->type ) )
    {
        mbedtls_free( slot->data.raw.data );
    }
    else
#if defined(MBEDTLS_RSA_C)
    if( slot->type == PSA_KEY_TYPE_RSA_PUBLIC_KEY ||
        slot->type == PSA_KEY_TYPE_RSA_KEYPAIR )
    {
        mbedtls_rsa_free( slot->data.rsa );
        mbedtls_free( slot->data.rsa );
    }
    else
#endif /* defined(MBEDTLS_RSA_C) */
#if defined(MBEDTLS_ECP_C)
    if( PSA_KEY_TYPE_IS_ECC( slot->type ) )
    {
        mbedtls_ecp_keypair_free( slot->data.ecp );
        mbedtls_free( slot->data.ecp );
    }
    else
#endif /* defined(MBEDTLS_ECP_C) */
    {
        /* Shouldn't happen: the key type is not any type that we
         * put in. */
        return( PSA_ERROR_TAMPERING_DETECTED );
    }

    mbedtls_zeroize( slot, sizeof( *slot ) );
    return( PSA_SUCCESS );
}

psa_status_t psa_get_key_information( psa_key_slot_t key,
                                      psa_key_type_t *type,
                                      size_t *bits )
{
    key_slot_t *slot;

    if( key == 0 || key > PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_EMPTY_SLOT );
    slot = &global_data.key_slots[key];
    if( type != NULL )
        *type = slot->type;
    if( bits != NULL )
        *bits = 0;
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );

    if( key_type_is_raw_bytes( slot->type ) )
    {
        if( bits != NULL )
            *bits = slot->data.raw.bytes * 8;
    }
    else
#if defined(MBEDTLS_RSA_C)
    if( slot->type == PSA_KEY_TYPE_RSA_PUBLIC_KEY ||
        slot->type == PSA_KEY_TYPE_RSA_KEYPAIR )
    {
        if( bits != NULL )
            *bits = mbedtls_rsa_get_bitlen( slot->data.rsa );
    }
    else
#endif /* defined(MBEDTLS_RSA_C) */
#if defined(MBEDTLS_ECP_C)
    if( PSA_KEY_TYPE_IS_ECC( slot->type ) )
    {
        if( bits != NULL )
            *bits = slot->data.ecp->grp.pbits;
    }
    else
#endif /* defined(MBEDTLS_ECP_C) */
    {
        /* Shouldn't happen: the key type is not any type that we
         * put in. */
        return( PSA_ERROR_TAMPERING_DETECTED );
    }

    return( PSA_SUCCESS );
}

static  psa_status_t psa_internal_export_key( psa_key_slot_t key,
                                              uint8_t *data,
                                              size_t data_size,
                                              size_t *data_length,
                                              int export_public_key )
{
    key_slot_t *slot;

    /* Set the key to empty now, so that even when there are errors, we always
     * set data_length to a value between 0 and data_size. On error, setting
     * the key to empty is a good choice because an empty key representation is
     * unlikely to be accepted anywhere. */
    *data_length = 0;

    if( key == 0 || key > PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_EMPTY_SLOT );
    slot = &global_data.key_slots[key];
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );

    if( export_public_key && ! PSA_KEY_TYPE_IS_ASYMMETRIC( slot->type ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( ! export_public_key &&
        ! PSA_KEY_TYPE_IS_PUBLIC_KEY( slot->type ) &&
        ( slot->policy.usage & PSA_KEY_USAGE_EXPORT ) == 0 )
        return( PSA_ERROR_NOT_PERMITTED );

    if( key_type_is_raw_bytes( slot->type ) )
    {
        if( slot->data.raw.bytes > data_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( data, slot->data.raw.data, slot->data.raw.bytes );
        *data_length = slot->data.raw.bytes;
        return( PSA_SUCCESS );
    }
    else
    {
#if defined(MBEDTLS_PK_WRITE_C)
        if( slot->type == PSA_KEY_TYPE_RSA_PUBLIC_KEY ||
            slot->type == PSA_KEY_TYPE_RSA_KEYPAIR ||
            PSA_KEY_TYPE_IS_ECC( slot->type ) )
        {
            mbedtls_pk_context pk;
            int ret;
            mbedtls_pk_init( &pk );
            if( slot->type == PSA_KEY_TYPE_RSA_PUBLIC_KEY ||
                slot->type == PSA_KEY_TYPE_RSA_KEYPAIR )
            {
                pk.pk_info = &mbedtls_rsa_info;
                pk.pk_ctx = slot->data.rsa;
            }
            else
            {
                pk.pk_info = &mbedtls_eckey_info;
                pk.pk_ctx = slot->data.ecp;
            }
            if( export_public_key || PSA_KEY_TYPE_IS_PUBLIC_KEY( slot->type ) )
                ret = mbedtls_pk_write_pubkey_der( &pk, data, data_size );
            else
                ret = mbedtls_pk_write_key_der( &pk, data, data_size );
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
        }
        else
#endif /* defined(MBEDTLS_PK_WRITE_C) */
        {
            /* This shouldn't happen in the reference implementation, but
               it is valid for a special-purpose implementation to omit
               support for exporting certain key types. */
            return( PSA_ERROR_NOT_SUPPORTED );
        }
    }
}

psa_status_t psa_export_key( psa_key_slot_t key,
                             uint8_t *data,
                             size_t data_size,
                             size_t *data_length )
{
    return( psa_internal_export_key( key, data, data_size,
                                     data_length, 0 ) );
}

psa_status_t psa_export_public_key( psa_key_slot_t key,
                                    uint8_t *data,
                                    size_t data_size,
                                    size_t *data_length )
{
    return( psa_internal_export_key( key, data, data_size,
                                     data_length, 1 ) );
}



/****************************************************************/
/* Message digests */
/****************************************************************/

static const mbedtls_md_info_t *mbedtls_md_info_from_psa( psa_algorithm_t alg )
{
    switch( alg )
    {
#if defined(MBEDTLS_MD2_C)
        case PSA_ALG_MD2:
            return( &mbedtls_md2_info );
#endif
#if defined(MBEDTLS_MD4_C)
        case PSA_ALG_MD4:
            return( &mbedtls_md4_info );
#endif
#if defined(MBEDTLS_MD5_C)
        case PSA_ALG_MD5:
            return( &mbedtls_md5_info );
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case PSA_ALG_RIPEMD160:
            return( &mbedtls_ripemd160_info );
#endif
#if defined(MBEDTLS_SHA1_C)
        case PSA_ALG_SHA_1:
            return( &mbedtls_sha1_info );
#endif
#if defined(MBEDTLS_SHA256_C)
        case PSA_ALG_SHA_224:
            return( &mbedtls_sha224_info );
        case PSA_ALG_SHA_256:
            return( &mbedtls_sha256_info );
#endif
#if defined(MBEDTLS_SHA512_C)
        case PSA_ALG_SHA_384:
            return( &mbedtls_sha384_info );
        case PSA_ALG_SHA_512:
            return( &mbedtls_sha512_info );
#endif
        default:
            return( NULL );
    }
}

psa_status_t psa_hash_abort( psa_hash_operation_t *operation )
{
    switch( operation->alg )
    {
        case 0:
            /* The object has (apparently) been initialized but it is not
             * in use. It's ok to call abort on such an object, and there's
             * nothing to do. */
            break;
#if defined(MBEDTLS_MD2_C)
        case PSA_ALG_MD2:
            mbedtls_md2_free( &operation->ctx.md2 );
            break;
#endif
#if defined(MBEDTLS_MD4_C)
        case PSA_ALG_MD4:
            mbedtls_md4_free( &operation->ctx.md4 );
            break;
#endif
#if defined(MBEDTLS_MD5_C)
        case PSA_ALG_MD5:
            mbedtls_md5_free( &operation->ctx.md5 );
            break;
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case PSA_ALG_RIPEMD160:
            mbedtls_ripemd160_free( &operation->ctx.ripemd160 );
            break;
#endif
#if defined(MBEDTLS_SHA1_C)
        case PSA_ALG_SHA_1:
            mbedtls_sha1_free( &operation->ctx.sha1 );
            break;
#endif
#if defined(MBEDTLS_SHA256_C)
        case PSA_ALG_SHA_224:
        case PSA_ALG_SHA_256:
            mbedtls_sha256_free( &operation->ctx.sha256 );
            break;
#endif
#if defined(MBEDTLS_SHA512_C)
        case PSA_ALG_SHA_384:
        case PSA_ALG_SHA_512:
            mbedtls_sha512_free( &operation->ctx.sha512 );
            break;
#endif
        default:
            return( PSA_ERROR_BAD_STATE );
    }
    operation->alg = 0;
    return( PSA_SUCCESS );
}

psa_status_t psa_hash_start( psa_hash_operation_t *operation,
                             psa_algorithm_t alg )
{
    int ret;
    operation->alg = 0;
    switch( alg )
    {
#if defined(MBEDTLS_MD2_C)
        case PSA_ALG_MD2:
            mbedtls_md2_init( &operation->ctx.md2 );
            ret = mbedtls_md2_starts_ret( &operation->ctx.md2 );
            break;
#endif
#if defined(MBEDTLS_MD4_C)
        case PSA_ALG_MD4:
            mbedtls_md4_init( &operation->ctx.md4 );
            ret = mbedtls_md4_starts_ret( &operation->ctx.md4 );
            break;
#endif
#if defined(MBEDTLS_MD5_C)
        case PSA_ALG_MD5:
            mbedtls_md5_init( &operation->ctx.md5 );
            ret = mbedtls_md5_starts_ret( &operation->ctx.md5 );
            break;
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case PSA_ALG_RIPEMD160:
            mbedtls_ripemd160_init( &operation->ctx.ripemd160 );
            ret = mbedtls_ripemd160_starts_ret( &operation->ctx.ripemd160 );
            break;
#endif
#if defined(MBEDTLS_SHA1_C)
        case PSA_ALG_SHA_1:
            mbedtls_sha1_init( &operation->ctx.sha1 );
            ret = mbedtls_sha1_starts_ret( &operation->ctx.sha1 );
            break;
#endif
#if defined(MBEDTLS_SHA256_C)
        case PSA_ALG_SHA_224:
            mbedtls_sha256_init( &operation->ctx.sha256 );
            ret = mbedtls_sha256_starts_ret( &operation->ctx.sha256, 1 );
            break;
        case PSA_ALG_SHA_256:
            mbedtls_sha256_init( &operation->ctx.sha256 );
            ret = mbedtls_sha256_starts_ret( &operation->ctx.sha256, 0 );
            break;
#endif
#if defined(MBEDTLS_SHA512_C)
        case PSA_ALG_SHA_384:
            mbedtls_sha512_init( &operation->ctx.sha512 );
            ret = mbedtls_sha512_starts_ret( &operation->ctx.sha512, 1 );
            break;
        case PSA_ALG_SHA_512:
            mbedtls_sha512_init( &operation->ctx.sha512 );
            ret = mbedtls_sha512_starts_ret( &operation->ctx.sha512, 0 );
            break;
#endif
        default:
            return( PSA_ALG_IS_HASH( alg ) ?
                    PSA_ERROR_NOT_SUPPORTED :
                    PSA_ERROR_INVALID_ARGUMENT );
    }
    if( ret == 0 )
        operation->alg = alg;
    else
        psa_hash_abort( operation );
    return( mbedtls_to_psa_error( ret ) );
}

psa_status_t psa_hash_update( psa_hash_operation_t *operation,
                              const uint8_t *input,
                              size_t input_length )
{
    int ret;
    switch( operation->alg )
    {
#if defined(MBEDTLS_MD2_C)
        case PSA_ALG_MD2:
            ret = mbedtls_md2_update_ret( &operation->ctx.md2,
                                          input, input_length );
            break;
#endif
#if defined(MBEDTLS_MD4_C)
        case PSA_ALG_MD4:
            ret = mbedtls_md4_update_ret( &operation->ctx.md4,
                                          input, input_length );
            break;
#endif
#if defined(MBEDTLS_MD5_C)
        case PSA_ALG_MD5:
            ret = mbedtls_md5_update_ret( &operation->ctx.md5,
                                          input, input_length );
            break;
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case PSA_ALG_RIPEMD160:
            ret = mbedtls_ripemd160_update_ret( &operation->ctx.ripemd160,
                                                input, input_length );
            break;
#endif
#if defined(MBEDTLS_SHA1_C)
        case PSA_ALG_SHA_1:
            ret = mbedtls_sha1_update_ret( &operation->ctx.sha1,
                                           input, input_length );
            break;
#endif
#if defined(MBEDTLS_SHA256_C)
        case PSA_ALG_SHA_224:
        case PSA_ALG_SHA_256:
            ret = mbedtls_sha256_update_ret( &operation->ctx.sha256,
                                             input, input_length );
            break;
#endif
#if defined(MBEDTLS_SHA512_C)
        case PSA_ALG_SHA_384:
        case PSA_ALG_SHA_512:
            ret = mbedtls_sha512_update_ret( &operation->ctx.sha512,
                                             input, input_length );
            break;
#endif
        default:
            ret = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
            break;
    }
    if( ret != 0 )
        psa_hash_abort( operation );
    return( mbedtls_to_psa_error( ret ) );
}

psa_status_t psa_hash_finish( psa_hash_operation_t *operation,
                              uint8_t *hash,
                              size_t hash_size,
                              size_t *hash_length )
{
    int ret;
    size_t actual_hash_length = PSA_HASH_SIZE( operation->alg );

    /* Fill the output buffer with something that isn't a valid hash
     * (barring an attack on the hash and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    *hash_length = actual_hash_length;
    memset( hash, '!', hash_size );

    if( hash_size < actual_hash_length )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    switch( operation->alg )
    {
#if defined(MBEDTLS_MD2_C)
        case PSA_ALG_MD2:
            ret = mbedtls_md2_finish_ret( &operation->ctx.md2, hash );
            break;
#endif
#if defined(MBEDTLS_MD4_C)
        case PSA_ALG_MD4:
            ret = mbedtls_md4_finish_ret( &operation->ctx.md4, hash );
            break;
#endif
#if defined(MBEDTLS_MD5_C)
        case PSA_ALG_MD5:
            ret = mbedtls_md5_finish_ret( &operation->ctx.md5, hash );
            break;
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case PSA_ALG_RIPEMD160:
            ret = mbedtls_ripemd160_finish_ret( &operation->ctx.ripemd160, hash );
            break;
#endif
#if defined(MBEDTLS_SHA1_C)
        case PSA_ALG_SHA_1:
            ret = mbedtls_sha1_finish_ret( &operation->ctx.sha1, hash );
            break;
#endif
#if defined(MBEDTLS_SHA256_C)
        case PSA_ALG_SHA_224:
        case PSA_ALG_SHA_256:
            ret = mbedtls_sha256_finish_ret( &operation->ctx.sha256, hash );
            break;
#endif
#if defined(MBEDTLS_SHA512_C)
        case PSA_ALG_SHA_384:
        case PSA_ALG_SHA_512:
            ret = mbedtls_sha512_finish_ret( &operation->ctx.sha512, hash );
            break;
#endif
        default:
            ret = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
            break;
    }

    if( ret == 0 )
    {
        return( psa_hash_abort( operation ) );
    }
    else
    {
        psa_hash_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }
}

psa_status_t psa_hash_verify( psa_hash_operation_t *operation,
                              const uint8_t *hash,
                              size_t hash_length )
{
    uint8_t actual_hash[MBEDTLS_MD_MAX_SIZE];
    size_t actual_hash_length;
    psa_status_t status = psa_hash_finish( operation,
                                           actual_hash, sizeof( actual_hash ),
                                           &actual_hash_length );
    if( status != PSA_SUCCESS )
        return( status );
    if( actual_hash_length != hash_length )
        return( PSA_ERROR_INVALID_SIGNATURE );
    if( safer_memcmp( hash, actual_hash, actual_hash_length ) != 0 )
        return( PSA_ERROR_INVALID_SIGNATURE );
    return( PSA_SUCCESS );
}



/****************************************************************/
/* MAC */
/****************************************************************/

static const mbedtls_cipher_info_t *mbedtls_cipher_info_from_psa(
    psa_algorithm_t alg,
    psa_key_type_t key_type,
    size_t key_bits,
    mbedtls_cipher_id_t* cipher_id )
{
    mbedtls_cipher_mode_t mode;
    mbedtls_cipher_id_t cipher_id_tmp;

    if( PSA_ALG_IS_CIPHER( alg ) || PSA_ALG_IS_AEAD( alg ) )
    {
        if( PSA_ALG_IS_BLOCK_CIPHER( alg ) )
        {
            alg &= ~PSA_ALG_BLOCK_CIPHER_PADDING_MASK;
        }

        switch( alg )
        {
            case PSA_ALG_STREAM_CIPHER:
                mode = MBEDTLS_MODE_STREAM;
                break;
            case PSA_ALG_CBC_BASE:
                mode = MBEDTLS_MODE_CBC;
                break;
            case PSA_ALG_CFB_BASE:
                mode = MBEDTLS_MODE_CFB;
                break;
            case PSA_ALG_OFB_BASE:
                mode = MBEDTLS_MODE_OFB;
                break;
            case PSA_ALG_CTR:
                mode = MBEDTLS_MODE_CTR;
                break;
            case PSA_ALG_CCM:
                mode = MBEDTLS_MODE_CCM;
                break;
            case PSA_ALG_GCM:
                mode = MBEDTLS_MODE_GCM;
                break;
            default:
                return( NULL );
        }
    }
    else if( alg == PSA_ALG_CMAC )
        mode = MBEDTLS_MODE_ECB;
    else if( alg == PSA_ALG_GMAC )
        mode = MBEDTLS_MODE_GCM;
    else
        return( NULL );

    switch( key_type )
    {
        case PSA_KEY_TYPE_AES:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_AES;
            break;
        case PSA_KEY_TYPE_DES:
            /* key_bits is 64 for Single-DES, 128 for two-key Triple-DES,
             * and 192 for three-key Triple-DES. */
            if( key_bits == 64 )
                cipher_id_tmp = MBEDTLS_CIPHER_ID_DES;
            else
                cipher_id_tmp = MBEDTLS_CIPHER_ID_3DES;
            /* mbedtls doesn't recognize two-key Triple-DES as an algorithm,
             * but two-key Triple-DES is functionally three-key Triple-DES
             * with K1=K3, so that's how we present it to mbedtls. */
            if( key_bits == 128 )
                key_bits = 192;
            break;
        case PSA_KEY_TYPE_CAMELLIA:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_CAMELLIA;
            break;
        case PSA_KEY_TYPE_ARC4:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_ARC4;
            break;
        default:
            return( NULL );
    }
    if( cipher_id != NULL )
        *cipher_id = cipher_id_tmp;

    return( mbedtls_cipher_info_from_values( cipher_id_tmp, key_bits, mode ) );
}

static size_t psa_get_hash_block_size( psa_algorithm_t alg )
{
    switch( alg )
    {
        case PSA_ALG_MD2:
            return( 16 );
        case PSA_ALG_MD4:
            return( 64 );
        case PSA_ALG_MD5:
            return( 64 );
        case PSA_ALG_RIPEMD160:
            return( 64 );
        case PSA_ALG_SHA_1:
            return( 64 );
        case PSA_ALG_SHA_224:
            return( 64 );
        case PSA_ALG_SHA_256:
            return( 64 );
        case PSA_ALG_SHA_384:
            return( 128 );
        case PSA_ALG_SHA_512:
            return( 128 );
        default:
            return( 0 );
    }
}

/* Initialize the MAC operation structure. Once this function has been
 * called, psa_mac_abort can run and will do the right thing. */
static psa_status_t psa_mac_init( psa_mac_operation_t *operation,
                                  psa_algorithm_t alg )
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    operation->alg = alg;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_required = 0;
    operation->has_input = 0;
    operation->key_usage_sign = 0;
    operation->key_usage_verify = 0;

#if defined(MBEDTLS_CMAC_C)
    if( alg == PSA_ALG_CMAC )
    {
        operation->iv_required = 0;
        mbedtls_cipher_init( &operation->ctx.cmac );
        status = PSA_SUCCESS;
    }
    else
#endif /* MBEDTLS_CMAC_C */
#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HMAC( operation->alg ) )
    {
        status = psa_hash_start( &operation->ctx.hmac.hash_ctx,
                                 PSA_ALG_HMAC_HASH( alg ) );
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        if( ! PSA_ALG_IS_MAC( alg ) )
            status = PSA_ERROR_INVALID_ARGUMENT;
    }

    if( status != PSA_SUCCESS )
        memset( operation, 0, sizeof( *operation ) );
    return( status );
}

psa_status_t psa_mac_abort( psa_mac_operation_t *operation )
{
    switch( operation->alg )
    {
        case 0:
            /* The object has (apparently) been initialized but it is not
             * in use. It's ok to call abort on such an object, and there's
             * nothing to do. */
            return( PSA_SUCCESS );
#if defined(MBEDTLS_CMAC_C)
        case PSA_ALG_CMAC:
            mbedtls_cipher_free( &operation->ctx.cmac );
            break;
#endif /* MBEDTLS_CMAC_C */
        default:
#if defined(MBEDTLS_MD_C)
            if( PSA_ALG_IS_HMAC( operation->alg ) )
            {
                unsigned int block_size =
                    psa_get_hash_block_size( PSA_ALG_HMAC_HASH( operation->alg ) );

                if( block_size == 0 )
                    return( PSA_ERROR_NOT_SUPPORTED );

                psa_hash_abort( &operation->ctx.hmac.hash_ctx );
                mbedtls_zeroize( operation->ctx.hmac.opad, block_size );
            }
            else
#endif /* MBEDTLS_MD_C */
            {
                /* Sanity check (shouldn't happen: operation->alg should
                 * always have been initialized to a valid value). */
                return( PSA_ERROR_BAD_STATE );
            }
    }

    operation->alg = 0;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_required = 0;
    operation->has_input = 0;
    operation->key_usage_sign = 0;
    operation->key_usage_verify = 0;

    return( PSA_SUCCESS );
}

#if defined(MBEDTLS_CMAC_C)
static int psa_cmac_start( psa_mac_operation_t *operation,
                           size_t key_bits,
                           key_slot_t *slot,
                           const mbedtls_cipher_info_t *cipher_info )
{
    int ret;

    operation->mac_size = cipher_info->block_size;

    ret = mbedtls_cipher_setup( &operation->ctx.cmac, cipher_info );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_cipher_cmac_starts( &operation->ctx.cmac,
                                      slot->data.raw.data,
                                      key_bits );
    return( ret );
}
#endif /* MBEDTLS_CMAC_C */

#if defined(MBEDTLS_MD_C)
static int psa_hmac_start( psa_mac_operation_t *operation,
                           psa_key_type_t key_type,
                           key_slot_t *slot,
                           psa_algorithm_t alg )
{
    unsigned char ipad[PSA_HMAC_MAX_HASH_BLOCK_SIZE];
    unsigned char *opad = operation->ctx.hmac.opad;
    size_t i;
    size_t block_size =
        psa_get_hash_block_size( PSA_ALG_HMAC_HASH( alg ) );
    unsigned int digest_size =
        PSA_HASH_SIZE( PSA_ALG_HMAC_HASH( alg ) );
    size_t key_length = slot->data.raw.bytes;
    psa_status_t status;

    if( block_size == 0 || digest_size == 0 )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( key_type != PSA_KEY_TYPE_HMAC )
        return( PSA_ERROR_INVALID_ARGUMENT );

    operation->mac_size = digest_size;

    /* The hash was started earlier in psa_mac_init. */
    if( key_length > block_size )
    {
        status = psa_hash_update( &operation->ctx.hmac.hash_ctx,
                                  slot->data.raw.data, slot->data.raw.bytes );
        if( status != PSA_SUCCESS )
            return( status );
        status = psa_hash_finish( &operation->ctx.hmac.hash_ctx,
                                  ipad, sizeof( ipad ), &key_length );
        if( status != PSA_SUCCESS )
            return( status );
    }
    else
        memcpy( ipad, slot->data.raw.data, slot->data.raw.bytes );

    /* ipad contains the key followed by garbage. Xor and fill with 0x36
     * to create the ipad value. */
    for( i = 0; i < key_length; i++ )
        ipad[i] ^= 0x36;
    memset( ipad + key_length, 0x36, block_size - key_length );

    /* Copy the key material from ipad to opad, flipping the requisite bits,
     * and filling the rest of opad with the requisite constant. */
    for( i = 0; i < key_length; i++ )
        opad[i] = ipad[i] ^ 0x36 ^ 0x5C;
    memset( opad + key_length, 0x5C, block_size - key_length );

    status = psa_hash_start( &operation->ctx.hmac.hash_ctx,
                             PSA_ALG_HMAC_HASH( alg ) );
    if( status != PSA_SUCCESS )
        goto cleanup;

    status = psa_hash_update( &operation->ctx.hmac.hash_ctx, ipad,
                              block_size );

cleanup:
    mbedtls_zeroize( ipad, key_length );
    /* opad is in the context. It needs to stay in memory if this function
     * succeeds, and it will be wiped by psa_mac_abort() called from
     * psa_mac_start in the error case. */

    return( status );
}
#endif /* MBEDTLS_MD_C */

psa_status_t psa_mac_start( psa_mac_operation_t *operation,
                            psa_key_slot_t key,
                            psa_algorithm_t alg )
{
    psa_status_t status;
    key_slot_t *slot;
    psa_key_type_t key_type;
    size_t key_bits;
    const mbedtls_cipher_info_t *cipher_info = NULL;

    status = psa_mac_init( operation, alg );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_get_key_information( key, &key_type, &key_bits );
    if( status != PSA_SUCCESS )
        return( status );

    slot = &global_data.key_slots[key];
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );

    if( ( slot->policy.usage & PSA_KEY_USAGE_SIGN ) != 0 )
        operation->key_usage_sign = 1;

    if( ( slot->policy.usage & PSA_KEY_USAGE_VERIFY ) != 0 )
        operation->key_usage_verify = 1;

    if( ! PSA_ALG_IS_HMAC( alg ) )
    {
        cipher_info = mbedtls_cipher_info_from_psa( alg, key_type, key_bits, NULL );
        if( cipher_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        operation->mac_size = cipher_info->block_size;
    }
    switch( alg )
    {
#if defined(MBEDTLS_CMAC_C)
        case PSA_ALG_CMAC:
            status = mbedtls_to_psa_error( psa_cmac_start( operation,
                                                           key_bits,
                                                           slot,
                                                           cipher_info ) );
            break;
#endif /* MBEDTLS_CMAC_C */
        default:
#if defined(MBEDTLS_MD_C)
            if( PSA_ALG_IS_HMAC( alg ) )
                status = psa_hmac_start( operation, key_type, slot, alg );
            else
#endif /* MBEDTLS_MD_C */
                return( PSA_ERROR_NOT_SUPPORTED );
    }

    /* If we reach this point, then the algorithm-specific part of the
     * context may contain data that needs to be wiped on error. */
    if( status != PSA_SUCCESS )
    {
        psa_mac_abort( operation );
    }
    else
    {
        operation->key_set = 1;
    }
    return( status );
}

psa_status_t psa_mac_update( psa_mac_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length )
{
    int ret = 0 ;
    psa_status_t status = PSA_SUCCESS;
    if( ! operation->key_set )
        return( PSA_ERROR_BAD_STATE );
    if( operation->iv_required && ! operation->iv_set )
        return( PSA_ERROR_BAD_STATE );
    operation->has_input = 1;

    switch( operation->alg )
    {
#if defined(MBEDTLS_CMAC_C)
        case PSA_ALG_CMAC:
            ret = mbedtls_cipher_cmac_update( &operation->ctx.cmac,
                                              input, input_length );
            break;
#endif /* MBEDTLS_CMAC_C */
        default:
#if defined(MBEDTLS_MD_C)
            if( PSA_ALG_IS_HMAC( operation->alg ) )
            {
                status = psa_hash_update( &operation->ctx.hmac.hash_ctx, input,
                                          input_length );
            }
            else
#endif /* MBEDTLS_MD_C */
            {
                ret = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
            }
            break;
    }
    if( ret != 0 || status != PSA_SUCCESS )
    {
        psa_mac_abort( operation );
        if( ret != 0 )
            status = mbedtls_to_psa_error( ret );
    }

    return( status );
}

static psa_status_t psa_mac_finish_internal( psa_mac_operation_t *operation,
                                             uint8_t *mac,
                                             size_t mac_size,
                                             size_t *mac_length )
{
    int ret = 0;
    psa_status_t status = PSA_SUCCESS;
    if( ! operation->key_set )
        return( PSA_ERROR_BAD_STATE );
    if( operation->iv_required && ! operation->iv_set )
        return( PSA_ERROR_BAD_STATE );

    /* Fill the output buffer with something that isn't a valid mac
     * (barring an attack on the mac and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    *mac_length = operation->mac_size;
    memset( mac, '!', mac_size );

    if( mac_size < operation->mac_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    switch( operation->alg )
    {
#if defined(MBEDTLS_CMAC_C)
        case PSA_ALG_CMAC:
            ret = mbedtls_cipher_cmac_finish( &operation->ctx.cmac, mac );
            break;
#endif /* MBEDTLS_CMAC_C */
        default:
#if defined(MBEDTLS_MD_C)
            if( PSA_ALG_IS_HMAC( operation->alg ) )
            {
                unsigned char tmp[MBEDTLS_MD_MAX_SIZE];
                unsigned char *opad = operation->ctx.hmac.opad;
                size_t hash_size = 0;
                size_t block_size =
                    psa_get_hash_block_size( PSA_ALG_HMAC_HASH( operation->alg ) );

                if( block_size == 0 )
                    return( PSA_ERROR_NOT_SUPPORTED );

                status = psa_hash_finish( &operation->ctx.hmac.hash_ctx, tmp,
                                          sizeof( tmp ), &hash_size );
                if( status != PSA_SUCCESS )
                    goto cleanup;
                /* From here on, tmp needs to be wiped. */

                status = psa_hash_start( &operation->ctx.hmac.hash_ctx,
                                         PSA_ALG_HMAC_HASH( operation->alg ) );
                if( status != PSA_SUCCESS )
                    goto hmac_cleanup;

                status = psa_hash_update( &operation->ctx.hmac.hash_ctx, opad,
                                          block_size );
                if( status != PSA_SUCCESS )
                    goto hmac_cleanup;

                status = psa_hash_update( &operation->ctx.hmac.hash_ctx, tmp,
                                          hash_size );
                if( status != PSA_SUCCESS )
                    goto hmac_cleanup;

                status = psa_hash_finish( &operation->ctx.hmac.hash_ctx, mac,
                                          mac_size, mac_length );
            hmac_cleanup:
                mbedtls_zeroize( tmp, hash_size );
            }
            else
#endif /* MBEDTLS_MD_C */
            {
                ret = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
            }
            break;
    }
cleanup:

    if( ret == 0 && status == PSA_SUCCESS )
    {
        return( psa_mac_abort( operation ) );
    }
    else
    {
        psa_mac_abort( operation );
        if( ret != 0 )
            status = mbedtls_to_psa_error( ret );

        return( status );
    }
}

psa_status_t psa_mac_finish( psa_mac_operation_t *operation,
                             uint8_t *mac,
                             size_t mac_size,
                             size_t *mac_length )
{
    if( ! operation->key_usage_sign )
        return( PSA_ERROR_NOT_PERMITTED );

    return( psa_mac_finish_internal( operation, mac,
                                     mac_size, mac_length ) );
}

#define PSA_MAC_MAX_SIZE                                \
    ( MBEDTLS_MD_MAX_SIZE > MBEDTLS_MAX_BLOCK_LENGTH ?  \
      MBEDTLS_MD_MAX_SIZE :                             \
      MBEDTLS_MAX_BLOCK_LENGTH )
psa_status_t psa_mac_verify( psa_mac_operation_t *operation,
                             const uint8_t *mac,
                             size_t mac_length )
{
    uint8_t actual_mac[PSA_MAC_MAX_SIZE];
    size_t actual_mac_length;
    psa_status_t status;

    if( ! operation->key_usage_verify )
        return( PSA_ERROR_NOT_PERMITTED );

    status = psa_mac_finish_internal( operation,
                                      actual_mac, sizeof( actual_mac ),
                                      &actual_mac_length );
    if( status != PSA_SUCCESS )
        return( status );
    if( actual_mac_length != mac_length )
        return( PSA_ERROR_INVALID_SIGNATURE );
    if( safer_memcmp( mac, actual_mac, actual_mac_length ) != 0 )
        return( PSA_ERROR_INVALID_SIGNATURE );
    return( PSA_SUCCESS );
}



/****************************************************************/
/* Asymmetric cryptography */
/****************************************************************/

/* Decode the hash algorithm from alg and store the mbedtls encoding in
 * md_alg. Verify that the hash length is consistent. */
static psa_status_t psa_rsa_decode_md_type( psa_algorithm_t alg,
                                            size_t hash_length,
                                            mbedtls_md_type_t *md_alg )
{
    psa_algorithm_t hash_alg = PSA_ALG_SIGN_GET_HASH( alg );
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_psa( hash_alg );
    *md_alg = hash_alg == 0 ? MBEDTLS_MD_NONE : mbedtls_md_get_type( md_info );
    if( *md_alg == MBEDTLS_MD_NONE )
    {
#if SIZE_MAX > UINT_MAX
        if( hash_length > UINT_MAX )
            return( PSA_ERROR_INVALID_ARGUMENT );
#endif
    }
    else
    {
        if( mbedtls_md_get_size( md_info ) != hash_length )
            return( PSA_ERROR_INVALID_ARGUMENT );
        if( md_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
    }
    return( PSA_SUCCESS );
}

psa_status_t psa_asymmetric_sign( psa_key_slot_t key,
                                  psa_algorithm_t alg,
                                  const uint8_t *hash,
                                  size_t hash_length,
                                  const uint8_t *salt,
                                  size_t salt_length,
                                  uint8_t *signature,
                                  size_t signature_size,
                                  size_t *signature_length )
{
    key_slot_t *slot;
    psa_status_t status;
    *signature_length = 0;
    (void) salt;
    (void) salt_length;

    if( key == 0 || key > PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_EMPTY_SLOT );
    slot = &global_data.key_slots[key];
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );
    if( ! PSA_KEY_TYPE_IS_KEYPAIR( slot->type ) )
        return( PSA_ERROR_INVALID_ARGUMENT );
    if( ! ( slot->policy.usage & PSA_KEY_USAGE_SIGN ) )
        return( PSA_ERROR_NOT_PERMITTED );

#if defined(MBEDTLS_RSA_C)
    if( slot->type == PSA_KEY_TYPE_RSA_KEYPAIR )
    {
        mbedtls_rsa_context *rsa = slot->data.rsa;
        int ret;
        mbedtls_md_type_t md_alg;
        status = psa_rsa_decode_md_type( alg, hash_length, &md_alg );
        if( status != PSA_SUCCESS )
            return( status );

        if( signature_size < rsa->len )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
#if defined(MBEDTLS_PKCS1_V15)
        if( PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) )
        {
            mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V15,
                                     MBEDTLS_MD_NONE );
            ret = mbedtls_rsa_pkcs1_sign( rsa,
                                          mbedtls_ctr_drbg_random,
                                          &global_data.ctr_drbg,
                                          MBEDTLS_RSA_PRIVATE,
                                          md_alg, hash_length, hash,
                                          signature );
        }
        else
#endif /* MBEDTLS_PKCS1_V15 */
#if defined(MBEDTLS_PKCS1_V21)
        if( alg == PSA_ALG_RSA_PSS_MGF1 )
        {
            mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V21, md_alg );
            ret = mbedtls_rsa_rsassa_pss_sign( rsa,
                                               mbedtls_ctr_drbg_random,
                                               &global_data.ctr_drbg,
                                               MBEDTLS_RSA_PRIVATE,
                                               md_alg, hash_length, hash,
                                               signature );
        }
        else
#endif /* MBEDTLS_PKCS1_V21 */
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
        if( ret == 0 )
            *signature_length = rsa->len;
        return( mbedtls_to_psa_error( ret ) );
    }
    else
#endif /* defined(MBEDTLS_RSA_C) */
#if defined(MBEDTLS_ECP_C)
    if( PSA_KEY_TYPE_IS_ECC( slot->type ) )
    {
        mbedtls_ecp_keypair *ecdsa = slot->data.ecp;
        int ret;
        const mbedtls_md_info_t *md_info;
        mbedtls_md_type_t md_alg;
        if( signature_size < PSA_ECDSA_SIGNATURE_SIZE( ecdsa->grp.pbits ) )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        md_info = mbedtls_md_info_from_psa( alg );
        md_alg = mbedtls_md_get_type( md_info );
        ret = mbedtls_ecdsa_write_signature( ecdsa, md_alg, hash, hash_length,
                                             signature, signature_length,
                                             mbedtls_ctr_drbg_random,
                                             &global_data.ctr_drbg );
        return( mbedtls_to_psa_error( ret ) );
    }
    else
#endif /* defined(MBEDTLS_ECP_C) */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}

psa_status_t psa_asymmetric_verify( psa_key_slot_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash,
                                    size_t hash_length,
                                    const uint8_t *salt,
                                    size_t salt_length,
                                    uint8_t *signature,
                                    size_t signature_size )
{
    key_slot_t *slot;
    psa_status_t status;
    (void) salt;
    (void) salt_length;

    if( key == 0 || key > PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_INVALID_ARGUMENT );
    slot = &global_data.key_slots[key];
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );
    if( ! ( slot->policy.usage & PSA_KEY_USAGE_VERIFY ) )
        return( PSA_ERROR_NOT_PERMITTED );

#if defined(MBEDTLS_RSA_C)
    if( slot->type == PSA_KEY_TYPE_RSA_KEYPAIR ||
        slot->type == PSA_KEY_TYPE_RSA_PUBLIC_KEY )
    {
        mbedtls_rsa_context *rsa = slot->data.rsa;
        int ret;
        mbedtls_md_type_t md_alg;
        status = psa_rsa_decode_md_type( alg, hash_length, &md_alg );
        if( status != PSA_SUCCESS )
            return( status );

        if( signature_size < rsa->len )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
#if defined(MBEDTLS_PKCS1_V15)
        if( PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) )
        {
            mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V15,
                                     MBEDTLS_MD_NONE );

            ret = mbedtls_rsa_pkcs1_verify( rsa,
                                            mbedtls_ctr_drbg_random,
                                            &global_data.ctr_drbg,
                                            MBEDTLS_RSA_PUBLIC,
                                            md_alg,
                                            hash_length,
                                            hash,
                                            signature );

        }
        else
#endif /* MBEDTLS_PKCS1_V15 */
#if defined(MBEDTLS_PKCS1_V21)
        if( alg == PSA_ALG_RSA_PSS_MGF1 )
        {
            mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V21, md_alg );
            ret = mbedtls_rsa_rsassa_pss_verify( rsa,
                                                 mbedtls_ctr_drbg_random,
                                                 &global_data.ctr_drbg,
                                                 MBEDTLS_RSA_PUBLIC,
                                                 md_alg, hash_length, hash,
                                                 signature );
        }
        else
#endif /* MBEDTLS_PKCS1_V21 */
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
        return( mbedtls_to_psa_error( ret ) );
    }
    else
#endif /* defined(MBEDTLS_RSA_C) */
#if defined(MBEDTLS_ECP_C)
    if( PSA_KEY_TYPE_IS_ECC( slot->type ) )
    {
        mbedtls_ecp_keypair *ecdsa = slot->data.ecp;
        int ret;
        (void) alg;
        ret = mbedtls_ecdsa_read_signature( ecdsa, hash, hash_length,
                                            signature, signature_size );
        return( mbedtls_to_psa_error( ret ) );
    }
    else
#endif /* defined(MBEDTLS_ECP_C) */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}

psa_status_t psa_asymmetric_encrypt( psa_key_slot_t key,
                                     psa_algorithm_t alg,
                                     const uint8_t *input,
                                     size_t input_length,
                                     const uint8_t *salt,
                                     size_t salt_length,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_length )
{
    key_slot_t *slot;
    (void) salt;
    (void) salt_length;
    *output_length = 0;

    if( key == 0 || key > PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_INVALID_ARGUMENT );
    slot = &global_data.key_slots[key];
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );
    if( ! PSA_KEY_TYPE_IS_KEYPAIR( slot->type ) )
        return( PSA_ERROR_INVALID_ARGUMENT );
    if( ! ( slot->policy.usage & PSA_KEY_USAGE_ENCRYPT ) )
        return( PSA_ERROR_NOT_PERMITTED );

#if defined(MBEDTLS_RSA_C)
    if( slot->type == PSA_KEY_TYPE_RSA_KEYPAIR ||
        slot->type == PSA_KEY_TYPE_RSA_PUBLIC_KEY )
    {
        mbedtls_rsa_context *rsa = slot->data.rsa;
        int ret;
        if( output_size < rsa->len )
            return( PSA_ERROR_INVALID_ARGUMENT );
#if defined(MBEDTLS_PKCS1_V15)
        if( alg == PSA_ALG_RSA_PKCS1V15_CRYPT )
        {
            ret = mbedtls_rsa_pkcs1_encrypt( rsa,
                                             mbedtls_ctr_drbg_random,
                                             &global_data.ctr_drbg,
                                             MBEDTLS_RSA_PUBLIC,
                                             input_length,
                                             input,
                                             output );
        }
        else
#endif /* MBEDTLS_PKCS1_V15 */
#if defined(MBEDTLS_PKCS1_V21)
        if( PSA_ALG_IS_RSA_OAEP_MGF1( alg ) )
        {
            return( PSA_ERROR_NOT_SUPPORTED );
        }
        else
#endif /* MBEDTLS_PKCS1_V21 */
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
        if( ret == 0 )
            *output_length = rsa->len;
        return( mbedtls_to_psa_error( ret ) );
    }
    else
#endif /* defined(MBEDTLS_RSA_C) */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}

psa_status_t psa_asymmetric_decrypt( psa_key_slot_t key,
                                     psa_algorithm_t alg,
                                     const uint8_t *input,
                                     size_t input_length,
                                     const uint8_t *salt,
                                     size_t salt_length,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_length )
{
    key_slot_t *slot;
    (void) salt;
    (void) salt_length;
    *output_length = 0;

    if( key == 0 || key > PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_EMPTY_SLOT );
    slot = &global_data.key_slots[key];
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );
    if( ! PSA_KEY_TYPE_IS_KEYPAIR( slot->type ) )
        return( PSA_ERROR_INVALID_ARGUMENT );
    if( ! ( slot->policy.usage & PSA_KEY_USAGE_DECRYPT ) )
        return( PSA_ERROR_NOT_PERMITTED );

#if defined(MBEDTLS_RSA_C)
    if( slot->type == PSA_KEY_TYPE_RSA_KEYPAIR )
    {
        mbedtls_rsa_context *rsa = slot->data.rsa;
        int ret;

        if( input_length != rsa->len )
            return( PSA_ERROR_INVALID_ARGUMENT );

#if defined(MBEDTLS_PKCS1_V15)
        if( alg == PSA_ALG_RSA_PKCS1V15_CRYPT )
        {
            ret = mbedtls_rsa_pkcs1_decrypt( rsa,
                                             mbedtls_ctr_drbg_random,
                                             &global_data.ctr_drbg,
                                             MBEDTLS_RSA_PRIVATE,
                                             output_length,
                                             input,
                                             output,
                                             output_size );
        }
        else
#endif /* MBEDTLS_PKCS1_V15 */
#if defined(MBEDTLS_PKCS1_V21)
        if( PSA_ALG_IS_RSA_OAEP_MGF1( alg ) )
        {
            return( PSA_ERROR_NOT_SUPPORTED );
        }
        else
#endif /* MBEDTLS_PKCS1_V21 */
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }

        return( mbedtls_to_psa_error( ret ) );
    }
    else
#endif /* defined(MBEDTLS_RSA_C) */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}



/****************************************************************/
/* Symmetric cryptography */
/****************************************************************/

/* Initialize the cipher operation structure. Once this function has been
 * called, psa_cipher_abort can run and will do the right thing. */
static psa_status_t psa_cipher_init( psa_cipher_operation_t *operation,
                                     psa_algorithm_t alg )
{
    if( ! PSA_ALG_IS_CIPHER( alg ) )
    {
        memset( operation, 0, sizeof( *operation ) );
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

    operation->alg = alg;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_required = 1;
    operation->iv_size = 0;
    operation->block_size = 0;
    mbedtls_cipher_init( &operation->ctx.cipher );
    return( PSA_SUCCESS );
}

static psa_status_t psa_cipher_setup( psa_cipher_operation_t *operation,
                                      psa_key_slot_t key,
                                      psa_algorithm_t alg,
                                      mbedtls_operation_t cipher_operation )
{
    int ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    psa_status_t status;
    key_slot_t *slot;
    psa_key_type_t key_type;
    size_t key_bits;
    const mbedtls_cipher_info_t *cipher_info = NULL;

    status = psa_cipher_init( operation, alg );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_get_key_information( key, &key_type, &key_bits );
    if( status != PSA_SUCCESS )
        return( status );
    slot = &global_data.key_slots[key];

    cipher_info = mbedtls_cipher_info_from_psa( alg, key_type, key_bits, NULL );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    ret = mbedtls_cipher_setup( &operation->ctx.cipher, cipher_info );
    if( ret != 0 )
    {
        psa_cipher_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }

#if defined(MBEDTLS_DES_C)
    if( key_type == PSA_KEY_TYPE_DES && key_bits == 128 )
    {
        /* Two-key Triple-DES is 3-key Triple-DES with K1=K3 */
        unsigned char keys[24];
        memcpy( keys, slot->data.raw.data, 16 );
        memcpy( keys + 16, slot->data.raw.data, 8 );
        ret = mbedtls_cipher_setkey( &operation->ctx.cipher,
                                     keys,
                                     192, cipher_operation );
    }
    else
#endif
    {
        ret = mbedtls_cipher_setkey( &operation->ctx.cipher,
                                     slot->data.raw.data,
                                     key_bits, cipher_operation );
    }
    if( ret != 0 )
    {
        psa_cipher_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    if( ( alg & ~PSA_ALG_BLOCK_CIPHER_PADDING_MASK ) == PSA_ALG_CBC_BASE )
    {
        psa_algorithm_t padding_mode = alg & PSA_ALG_BLOCK_CIPHER_PADDING_MASK;
        mbedtls_cipher_padding_t mode;

        switch ( padding_mode )
        {
            case PSA_ALG_BLOCK_CIPHER_PAD_PKCS7:
                mode = MBEDTLS_PADDING_PKCS7;
                break;
            case PSA_ALG_BLOCK_CIPHER_PAD_NONE:
                mode = MBEDTLS_PADDING_NONE;
                break;
            default:
                psa_cipher_abort( operation );
                return( PSA_ERROR_INVALID_ARGUMENT );
        }
        ret = mbedtls_cipher_set_padding_mode( &operation->ctx.cipher, mode );
        if( ret != 0 )
        {
            psa_cipher_abort( operation );
            return( mbedtls_to_psa_error( ret ) );
        }
    }
#endif //MBEDTLS_CIPHER_MODE_WITH_PADDING

    operation->key_set = 1;
    operation->block_size = ( PSA_ALG_IS_BLOCK_CIPHER( alg ) ?
                              PSA_BLOCK_CIPHER_BLOCK_SIZE( key_type ) :
                              1 );
    if( PSA_ALG_IS_BLOCK_CIPHER( alg ) || alg == PSA_ALG_CTR )
    {
        operation->iv_size = PSA_BLOCK_CIPHER_BLOCK_SIZE( key_type );
    }

    return( PSA_SUCCESS );
}

psa_status_t psa_encrypt_setup( psa_cipher_operation_t *operation,
                                psa_key_slot_t key,
                                psa_algorithm_t alg )
{
    return( psa_cipher_setup( operation, key, alg, MBEDTLS_ENCRYPT ) );
}

psa_status_t psa_decrypt_setup( psa_cipher_operation_t *operation,
                                psa_key_slot_t key,
                                psa_algorithm_t alg )
{
    return( psa_cipher_setup( operation, key, alg, MBEDTLS_DECRYPT ) );
}

psa_status_t psa_encrypt_generate_iv( psa_cipher_operation_t *operation,
                                      unsigned char *iv,
                                      size_t iv_size,
                                      size_t *iv_length )
{
    int ret = PSA_SUCCESS;
    if( operation->iv_set || ! operation->iv_required )
        return( PSA_ERROR_BAD_STATE );
    if( iv_size < operation->iv_size )
    {
        ret = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }
    ret = mbedtls_ctr_drbg_random( &global_data.ctr_drbg,
                                   iv, operation->iv_size );
    if( ret != 0 )
    {
        ret = mbedtls_to_psa_error( ret );
        goto exit;
    }

    *iv_length = operation->iv_size;
    ret = psa_encrypt_set_iv( operation, iv, *iv_length );

exit:
    if( ret != PSA_SUCCESS )
        psa_cipher_abort( operation );
    return( ret );
}

psa_status_t psa_encrypt_set_iv( psa_cipher_operation_t *operation,
                                 const unsigned char *iv,
                                 size_t iv_length )
{
    int ret = PSA_SUCCESS;
    if( operation->iv_set || ! operation->iv_required )
        return( PSA_ERROR_BAD_STATE );
    if( iv_length != operation->iv_size )
    {
        psa_cipher_abort( operation );
        return( PSA_ERROR_INVALID_ARGUMENT );
    }
    ret =  mbedtls_cipher_set_iv( &operation->ctx.cipher, iv, iv_length );
    if( ret != 0 )
    {
        psa_cipher_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }

    operation->iv_set = 1;

    return( PSA_SUCCESS );
}

psa_status_t psa_cipher_update( psa_cipher_operation_t *operation,
                                const uint8_t *input,
                                size_t input_length,
                                unsigned char *output,
                                size_t output_size,
                                size_t *output_length )
{
    int ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    size_t expected_output_size;
    if( PSA_ALG_IS_BLOCK_CIPHER( operation->alg ) )
    {
        /* Take the unprocessed partial block left over from previous
         * update calls, if any, plus the input to this call. Remove
         * the last partial block, if any. You get the data that will be
         * output in this call. */
        expected_output_size =
            ( operation->ctx.cipher.unprocessed_len + input_length )
            / operation->block_size * operation->block_size;
    }
    else
    {
        expected_output_size = input_length;
    }
    if( output_size < expected_output_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    ret = mbedtls_cipher_update( &operation->ctx.cipher, input,
                                 input_length, output, output_length );
    if( ret != 0 )
    {
        psa_cipher_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }

    return( PSA_SUCCESS );
}

psa_status_t psa_cipher_finish( psa_cipher_operation_t *operation,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length )
{
    int ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    uint8_t temp_output_buffer[MBEDTLS_MAX_BLOCK_LENGTH];

    if( ! operation->key_set )
    {
        psa_cipher_abort( operation );
        return( PSA_ERROR_BAD_STATE );
    }
    if( operation->iv_required && ! operation->iv_set )
    {
        psa_cipher_abort( operation );
        return( PSA_ERROR_BAD_STATE );
    }
    if( operation->ctx.cipher.operation == MBEDTLS_ENCRYPT &&
        PSA_ALG_IS_BLOCK_CIPHER( operation->alg ) )
    {
        psa_algorithm_t padding_mode =
            operation->alg & PSA_ALG_BLOCK_CIPHER_PADDING_MASK;
        if( operation->ctx.cipher.unprocessed_len >= operation->block_size )
        {
            psa_cipher_abort( operation );
            return( PSA_ERROR_TAMPERING_DETECTED );
        }
        if( padding_mode == PSA_ALG_BLOCK_CIPHER_PAD_NONE )
        {
            if( operation->ctx.cipher.unprocessed_len != 0 )
            {
                psa_cipher_abort( operation );
                return( PSA_ERROR_INVALID_ARGUMENT );
            }
        }
    }

    ret = mbedtls_cipher_finish( &operation->ctx.cipher, temp_output_buffer,
                                 output_length );
    if( ret != 0 )
    {
        psa_cipher_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }
    if( output_size >= *output_length )
        memcpy( output, temp_output_buffer, *output_length );
    else
    {
        psa_cipher_abort( operation );
        return( PSA_ERROR_BUFFER_TOO_SMALL );
    }

    return( PSA_SUCCESS );
}

psa_status_t psa_cipher_abort( psa_cipher_operation_t *operation )
{
    if( operation->alg == 0 )
    {
        /* The object has (apparently) been initialized but it is not
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
        return( PSA_SUCCESS );
    }

    /* Sanity check (shouldn't happen: operation->alg should
     * always have been initialized to a valid value). */
    if( ! PSA_ALG_IS_CIPHER( operation->alg ) )
        return( PSA_ERROR_BAD_STATE );

    mbedtls_cipher_free( &operation->ctx.cipher );

    operation->alg = 0;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_size = 0;
    operation->block_size = 0;
    operation->iv_required = 0;

    return( PSA_SUCCESS );
}



/****************************************************************/
/* Key Policy */
/****************************************************************/

void psa_key_policy_init( psa_key_policy_t *policy )
{
    memset( policy, 0, sizeof( *policy ) );
}

void psa_key_policy_set_usage( psa_key_policy_t *policy,
                               psa_key_usage_t usage,
                               psa_algorithm_t alg )
{
    policy->usage = usage;
    policy->alg = alg;
}

psa_key_usage_t psa_key_policy_get_usage( psa_key_policy_t *policy )
{
    return( policy->usage );
}

psa_algorithm_t psa_key_policy_get_algorithm( psa_key_policy_t *policy )
{
    return( policy->alg );
}

psa_status_t psa_set_key_policy( psa_key_slot_t key,
                                 const psa_key_policy_t *policy )
{
    key_slot_t *slot;

    if( key == 0 || key > PSA_KEY_SLOT_COUNT || policy == NULL )
        return( PSA_ERROR_INVALID_ARGUMENT );

    slot = &global_data.key_slots[key];
    if( slot->type != PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_OCCUPIED_SLOT );

    if( ( policy->usage & ~( PSA_KEY_USAGE_EXPORT |
                             PSA_KEY_USAGE_ENCRYPT |
                             PSA_KEY_USAGE_DECRYPT |
                             PSA_KEY_USAGE_SIGN |
                             PSA_KEY_USAGE_VERIFY ) ) != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    slot->policy = *policy;

    return( PSA_SUCCESS );
}

psa_status_t psa_get_key_policy( psa_key_slot_t key,
                                 psa_key_policy_t *policy )
{
    key_slot_t *slot;

    if( key == 0 || key > PSA_KEY_SLOT_COUNT || policy == NULL )
        return( PSA_ERROR_INVALID_ARGUMENT );

    slot = &global_data.key_slots[key];

    *policy = slot->policy;

    return( PSA_SUCCESS );
}



/****************************************************************/
/* Key Lifetime */
/****************************************************************/

psa_status_t psa_get_key_lifetime( psa_key_slot_t key,
                                   psa_key_lifetime_t *lifetime )
{
    key_slot_t *slot;

    if( key == 0 || key > PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_INVALID_ARGUMENT );

    slot = &global_data.key_slots[key];

    *lifetime = slot->lifetime;

    return( PSA_SUCCESS );
}

psa_status_t psa_set_key_lifetime( psa_key_slot_t key,
                                   const psa_key_lifetime_t lifetime )
{
    key_slot_t *slot;

    if( key == 0 || key > PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( lifetime != PSA_KEY_LIFETIME_VOLATILE &&
        lifetime != PSA_KEY_LIFETIME_PERSISTENT &&
        lifetime != PSA_KEY_LIFETIME_WRITE_ONCE)
        return( PSA_ERROR_INVALID_ARGUMENT );

    slot = &global_data.key_slots[key];
    if( slot->type != PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_OCCUPIED_SLOT );

    if( lifetime != PSA_KEY_LIFETIME_VOLATILE )
        return( PSA_ERROR_NOT_SUPPORTED );

    slot->lifetime = lifetime;

    return( PSA_SUCCESS );
}



/****************************************************************/
/* AEAD */
/****************************************************************/

psa_status_t psa_aead_encrypt( psa_key_slot_t key,
                               psa_algorithm_t alg,
                               const uint8_t *nonce,
                               size_t nonce_length,
                               const uint8_t *additional_data,
                               size_t additional_data_length,
                               const uint8_t *plaintext,
                               size_t plaintext_length,
                               uint8_t *ciphertext,
                               size_t ciphertext_size,
                               size_t *ciphertext_length )
{
    int ret;
    psa_status_t status;
    key_slot_t *slot;
    psa_key_type_t key_type;
    size_t key_bits;
    uint8_t *tag;
    size_t tag_length;
    mbedtls_cipher_id_t cipher_id;
    const mbedtls_cipher_info_t *cipher_info = NULL;

    *ciphertext_length = 0;

    status = psa_get_key_information( key, &key_type, &key_bits );
    if( status != PSA_SUCCESS )
        return( status );
    slot = &global_data.key_slots[key];
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );

    cipher_info = mbedtls_cipher_info_from_psa( alg, key_type,
                                                key_bits, &cipher_id );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( ( slot->policy.usage & PSA_KEY_USAGE_ENCRYPT ) == 0 )
        return( PSA_ERROR_NOT_PERMITTED );

    if( ( key_type & PSA_KEY_TYPE_CATEGORY_MASK ) !=
        PSA_KEY_TYPE_CATEGORY_SYMMETRIC )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( alg == PSA_ALG_GCM )
    {
        mbedtls_gcm_context gcm;
        tag_length = 16;

        if( PSA_BLOCK_CIPHER_BLOCK_SIZE( key_type ) != 16 )
            return( PSA_ERROR_INVALID_ARGUMENT );

        //make sure we have place to hold the tag in the ciphertext buffer
        if( ciphertext_size < ( plaintext_length + tag_length ) )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        //update the tag pointer to point to the end of the ciphertext_length
        tag = ciphertext + plaintext_length;

        mbedtls_gcm_init( &gcm );
        ret = mbedtls_gcm_setkey( &gcm, cipher_id,
                                  slot->data.raw.data,
                                  key_bits );
        if( ret != 0 )
        {
            mbedtls_gcm_free( &gcm );
            return( mbedtls_to_psa_error( ret ) );
        }
        ret = mbedtls_gcm_crypt_and_tag( &gcm, MBEDTLS_GCM_ENCRYPT,
                                         plaintext_length, nonce,
                                         nonce_length, additional_data,
                                         additional_data_length, plaintext,
                                         ciphertext, tag_length, tag );
        mbedtls_gcm_free( &gcm );
    }
    else if( alg == PSA_ALG_CCM )
    {
        mbedtls_ccm_context ccm;
        tag_length = 16;

        if( PSA_BLOCK_CIPHER_BLOCK_SIZE( key_type ) != 16 )
            return( PSA_ERROR_INVALID_ARGUMENT );

        if( nonce_length < 7 || nonce_length > 13 )
            return( PSA_ERROR_INVALID_ARGUMENT );

        //make sure we have place to hold the tag in the ciphertext buffer
        if( ciphertext_size < ( plaintext_length + tag_length ) )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        //update the tag pointer to point to the end of the ciphertext_length
        tag = ciphertext + plaintext_length;

        mbedtls_ccm_init( &ccm );
        ret = mbedtls_ccm_setkey( &ccm, cipher_id,
                                  slot->data.raw.data, key_bits );
        if( ret != 0 )
        {
            mbedtls_ccm_free( &ccm );
            return( mbedtls_to_psa_error( ret ) );
        }
        ret = mbedtls_ccm_encrypt_and_tag( &ccm, plaintext_length,
                                           nonce, nonce_length,
                                           additional_data,
                                           additional_data_length,
                                           plaintext, ciphertext,
                                           tag, tag_length );
        mbedtls_ccm_free( &ccm );
    }
    else
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( ret != 0 )
    {
        memset( ciphertext, 0, ciphertext_size );
        return( mbedtls_to_psa_error( ret ) );
    }

    *ciphertext_length = plaintext_length + tag_length;
    return( PSA_SUCCESS );
}

/* Locate the tag in a ciphertext buffer containing the encrypted data
 * followed by the tag. Return the length of the part preceding the tag in
 * *plaintext_length. This is the size of the plaintext in modes where
 * the encrypted data has the same size as the plaintext, such as
 * CCM and GCM. */
static psa_status_t psa_aead_unpadded_locate_tag( size_t tag_length,
                                                  const uint8_t *ciphertext,
                                                  size_t ciphertext_length,
                                                  size_t plaintext_size,
                                                  const uint8_t **p_tag )
{
    size_t payload_length;
    if( tag_length > ciphertext_length )
        return( PSA_ERROR_INVALID_ARGUMENT );
    payload_length = ciphertext_length - tag_length;
    if( payload_length > plaintext_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );
    *p_tag = ciphertext + payload_length;
    return( PSA_SUCCESS );
}

psa_status_t psa_aead_decrypt( psa_key_slot_t key,
                               psa_algorithm_t alg,
                               const uint8_t *nonce,
                               size_t nonce_length,
                               const uint8_t *additional_data,
                               size_t additional_data_length,
                               const uint8_t *ciphertext,
                               size_t ciphertext_length,
                               uint8_t *plaintext,
                               size_t plaintext_size,
                               size_t *plaintext_length )
{
    int ret;
    psa_status_t status;
    key_slot_t *slot;
    psa_key_type_t key_type;
    size_t key_bits;
    const uint8_t *tag;
    size_t tag_length;
    mbedtls_cipher_id_t cipher_id;
    const mbedtls_cipher_info_t *cipher_info = NULL;

    *plaintext_length = 0;

    status = psa_get_key_information( key, &key_type, &key_bits );
    if( status != PSA_SUCCESS )
        return( status );
    slot = &global_data.key_slots[key];
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );

    cipher_info = mbedtls_cipher_info_from_psa( alg, key_type,
                                                key_bits, &cipher_id );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( !( slot->policy.usage & PSA_KEY_USAGE_DECRYPT ) )
        return( PSA_ERROR_NOT_PERMITTED );

    if( ( key_type & PSA_KEY_TYPE_CATEGORY_MASK ) !=
        PSA_KEY_TYPE_CATEGORY_SYMMETRIC )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( alg == PSA_ALG_GCM )
    {
        mbedtls_gcm_context gcm;

        tag_length = 16;
        status = psa_aead_unpadded_locate_tag( tag_length,
                                               ciphertext, ciphertext_length,
                                               plaintext_size, &tag );
        if( status != PSA_SUCCESS )
            return( status );

        mbedtls_gcm_init( &gcm );
        ret = mbedtls_gcm_setkey( &gcm, cipher_id,
                                  slot->data.raw.data, key_bits );
        if( ret != 0 )
        {
            mbedtls_gcm_free( &gcm );
            return( mbedtls_to_psa_error( ret ) );
        }

        ret = mbedtls_gcm_auth_decrypt( &gcm,
                                        ciphertext_length - tag_length,
                                        nonce, nonce_length,
                                        additional_data,
                                        additional_data_length,
                                        tag, tag_length,
                                        ciphertext, plaintext );
        mbedtls_gcm_free( &gcm );
    }
    else if( alg == PSA_ALG_CCM )
    {
        mbedtls_ccm_context ccm;

        if( nonce_length < 7 || nonce_length > 13 )
            return( PSA_ERROR_INVALID_ARGUMENT );

        tag_length = 16;
        status = psa_aead_unpadded_locate_tag( tag_length,
                                               ciphertext, ciphertext_length,
                                               plaintext_size, &tag );
        if( status != PSA_SUCCESS )
            return( status );

        mbedtls_ccm_init( &ccm );
        ret = mbedtls_ccm_setkey( &ccm, cipher_id,
                                  slot->data.raw.data, key_bits );
        if( ret != 0 )
        {
            mbedtls_ccm_free( &ccm );
            return( mbedtls_to_psa_error( ret ) );
        }
        ret = mbedtls_ccm_auth_decrypt( &ccm, ciphertext_length - tag_length,
                                        nonce, nonce_length,
                                        additional_data,
                                        additional_data_length,
                                        ciphertext, plaintext,
                                        tag, tag_length );
        mbedtls_ccm_free( &ccm );
    }
    else
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    if( ret != 0 )
        memset( plaintext, 0, plaintext_size );
    else
        *plaintext_length = ciphertext_length - tag_length;

    return( mbedtls_to_psa_error( ret ) );
}



/****************************************************************/
/* Key generation */
/****************************************************************/

psa_status_t psa_generate_random( uint8_t *output,
                                  size_t output_size )
{
    int ret = mbedtls_ctr_drbg_random( &global_data.ctr_drbg,
                                       output, output_size );
    return( mbedtls_to_psa_error( ret ) );
}

psa_status_t psa_generate_key( psa_key_slot_t key,
                               psa_key_type_t type,
                               size_t bits,
                               const void *parameters,
                               size_t parameters_size )
{
    key_slot_t *slot;

    if( key == 0 || key > PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_INVALID_ARGUMENT );
    slot = &global_data.key_slots[key];
    if( slot->type != PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_OCCUPIED_SLOT );
    if( parameters == NULL && parameters_size != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( key_type_is_raw_bytes( type ) )
    {
        psa_status_t status = prepare_raw_data_slot( type, bits,
                                                     &slot->data.raw );
        if( status != PSA_SUCCESS )
            return( status );
        status = psa_generate_random( slot->data.raw.data,
                                      slot->data.raw.bytes );
        if( status != PSA_SUCCESS )
        {
            mbedtls_free( slot->data.raw.data );
            return( status );
        }
#if defined(MBEDTLS_DES_C)
        if( type == PSA_KEY_TYPE_DES )
        {
            mbedtls_des_key_set_parity( slot->data.raw.data );
            if( slot->data.raw.bytes >= 16 )
                mbedtls_des_key_set_parity( slot->data.raw.data + 8 );
            if( slot->data.raw.bytes == 24 )
                mbedtls_des_key_set_parity( slot->data.raw.data + 16 );
        }
#endif /* MBEDTLS_DES_C */
    }
    else

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if ( type == PSA_KEY_TYPE_RSA_KEYPAIR )
    {
        mbedtls_rsa_context *rsa;
        int ret;
        int exponent = 65537;
        if( parameters != NULL )
        {
            const unsigned *p = parameters;
            if( parameters_size != sizeof( *p ) )
                return( PSA_ERROR_INVALID_ARGUMENT );
            if( *p > INT_MAX )
                return( PSA_ERROR_INVALID_ARGUMENT );
            exponent = *p;
        }
        rsa = mbedtls_calloc( 1, sizeof( *rsa ) );
        if( rsa == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        mbedtls_rsa_init( rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE );
        ret = mbedtls_rsa_gen_key( rsa,
                                   mbedtls_ctr_drbg_random,
                                   &global_data.ctr_drbg,
                                   bits,
                                   exponent );
        if( ret != 0 )
        {
            mbedtls_rsa_free( rsa );
            mbedtls_free( rsa );
            return( mbedtls_to_psa_error( ret ) );
        }
        slot->data.rsa = rsa;
    }
    else
#endif /* MBEDTLS_RSA_C && MBEDTLS_GENPRIME */

#if defined(MBEDTLS_ECP_C)
    if ( PSA_KEY_TYPE_IS_ECC( type ) && PSA_KEY_TYPE_IS_KEYPAIR( type ) )
    {
        psa_ecc_curve_t curve = PSA_KEY_TYPE_GET_CURVE( type );
        mbedtls_ecp_group_id grp_id = mbedtls_ecc_group_of_psa( curve );
        const mbedtls_ecp_curve_info *curve_info =
            mbedtls_ecp_curve_info_from_grp_id( grp_id );
        mbedtls_ecp_keypair *ecp;
        int ret;
        if( parameters != NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( grp_id == MBEDTLS_ECP_DP_NONE || curve_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( curve_info->bit_size != bits )
            return( PSA_ERROR_INVALID_ARGUMENT );
        ecp = mbedtls_calloc( 1, sizeof( *ecp ) );
        if( ecp == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        mbedtls_ecp_keypair_init( ecp );
        ret = mbedtls_ecp_gen_key( grp_id, ecp,
                                   mbedtls_ctr_drbg_random,
                                   &global_data.ctr_drbg );
        if( ret != 0 )
        {
            mbedtls_ecp_keypair_free( ecp );
            mbedtls_free( ecp );
            return( mbedtls_to_psa_error( ret ) );
        }
        slot->data.ecp = ecp;
    }
    else
#endif /* MBEDTLS_ECP_C */

        return( PSA_ERROR_NOT_SUPPORTED );

    slot->type = type;
    return( PSA_SUCCESS );
}


/****************************************************************/
/* Module setup */
/****************************************************************/

void mbedtls_psa_crypto_free( void )
{
    size_t key;
    for( key = 1; key < PSA_KEY_SLOT_COUNT; key++ )
        psa_destroy_key( key );
    mbedtls_ctr_drbg_free( &global_data.ctr_drbg );
    mbedtls_entropy_free( &global_data.entropy );
    mbedtls_zeroize( &global_data, sizeof( global_data ) );
}

psa_status_t psa_crypto_init( void )
{
    int ret;
    const unsigned char drbg_seed[] = "PSA";

    if( global_data.initialized != 0 )
        return( PSA_SUCCESS );

    mbedtls_zeroize( &global_data, sizeof( global_data ) );
    mbedtls_entropy_init( &global_data.entropy );
    mbedtls_ctr_drbg_init( &global_data.ctr_drbg );

    ret = mbedtls_ctr_drbg_seed( &global_data.ctr_drbg,
                                 mbedtls_entropy_func,
                                 &global_data.entropy,
                                 drbg_seed, sizeof( drbg_seed ) - 1 );
    if( ret != 0 )
        goto exit;

    global_data.initialized = 1;

exit:
    if( ret != 0 )
        mbedtls_psa_crypto_free( );
    return( mbedtls_to_psa_error( ret ) );
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
