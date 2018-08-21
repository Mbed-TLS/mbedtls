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
/*
 * In case MBEDTLS_PSA_CRYPTO_SPM is defined the code is built for SPM (Secure
 * Partition Manager) integration which separate the code into two parts
 * NSPE (Non-Secure Process Environment) and SPE (Secure Process Environment).
 * In this mode an additional header file should be included.
 */
#if defined(MBEDTLS_PSA_CRYPTO_SPM)
/*
 * PSA_CRYPTO_SECURE means that this file is compiled to the SPE side.
 * some headers will be affected by this flag.
 */
#define PSA_CRYPTO_SECURE 1
#include "crypto_spe.h"
#endif

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
#include "mbedtls/bignum.h"
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



#define ARRAY_LENGTH( array ) ( sizeof( array ) / sizeof( *( array ) ) )

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
    return( PSA_KEY_TYPE_IS_UNSTRUCTURED( type ) );
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

/* Retrieve a key slot, occupied or not. */
static psa_status_t psa_get_key_slot( psa_key_slot_t key,
                                      key_slot_t **p_slot )
{
    /* 0 is not a valid slot number under any circumstance. This
     * implementation provides slots number 1 to N where N is the
     * number of available slots. */
    if( key == 0 || key > ARRAY_LENGTH( global_data.key_slots ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    *p_slot = &global_data.key_slots[key - 1];
    return( PSA_SUCCESS );
}

/* Retrieve an empty key slot (slot with no key data, but possibly
 * with some metadata such as a policy). */
static psa_status_t psa_get_empty_key_slot( psa_key_slot_t key,
                                            key_slot_t **p_slot )
{
    psa_status_t status;
    key_slot_t *slot = NULL;

    *p_slot = NULL;

    status = psa_get_key_slot( key, &slot );
    if( status != PSA_SUCCESS )
        return( status );

    if( slot->type != PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_OCCUPIED_SLOT );

    *p_slot = slot;
    return( status );
}

/** Retrieve a slot which must contain a key. The key must have allow all the
 * usage flags set in \p usage. If \p alg is nonzero, the key must allow
 * operations with this algorithm. */
static psa_status_t psa_get_key_from_slot( psa_key_slot_t key,
                                           key_slot_t **p_slot,
                                           psa_key_usage_t usage,
                                           psa_algorithm_t alg )
{
    psa_status_t status;
    key_slot_t *slot = NULL;

    *p_slot = NULL;

    status = psa_get_key_slot( key, &slot );
    if( status != PSA_SUCCESS )
        return( status );
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );

    /* Enforce that usage policy for the key slot contains all the flags
     * required by the usage parameter. There is one exception: public
     * keys can always be exported, so we treat public key objects as
     * if they had the export flag. */
    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( slot->type ) )
        usage &= ~PSA_KEY_USAGE_EXPORT;
    if( ( slot->policy.usage & usage ) != usage )
        return( PSA_ERROR_NOT_PERMITTED );
    if( alg != 0 && ( alg != slot->policy.alg ) )
        return( PSA_ERROR_NOT_PERMITTED );

    *p_slot = slot;
    return( PSA_SUCCESS );
}



/****************************************************************/
/* Key management */
/****************************************************************/

#if defined(MBEDTLS_ECP_C)
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
#endif /* defined(MBEDTLS_ECP_C) */

static psa_status_t prepare_raw_data_slot( psa_key_type_t type,
                                           size_t bits,
                                           struct raw_data *raw )
{
    /* Check that the bit size is acceptable for the key type */
    switch( type )
    {
        case PSA_KEY_TYPE_RAW_DATA:
            if( bits == 0 )
            {
                raw->bytes = 0;
                raw->data = NULL;
                return( PSA_SUCCESS );
            }
            break;
#if defined(MBEDTLS_MD_C)
        case PSA_KEY_TYPE_HMAC:
#endif
        case PSA_KEY_TYPE_DERIVE:
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

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PK_PARSE_C)
static psa_status_t psa_import_rsa_key( mbedtls_pk_context *pk,
                                        mbedtls_rsa_context **p_rsa )
{
    if( mbedtls_pk_get_type( pk ) != MBEDTLS_PK_RSA )
        return( PSA_ERROR_INVALID_ARGUMENT );
    else
    {
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa( *pk );
        size_t bits = mbedtls_rsa_get_bitlen( rsa );
        if( bits > PSA_VENDOR_RSA_MAX_KEY_BITS )
            return( PSA_ERROR_NOT_SUPPORTED );
        *p_rsa = rsa;
        return( PSA_SUCCESS );
    }
}
#endif /* defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PK_PARSE_C) */

#if defined(MBEDTLS_ECP_C) && defined(MBEDTLS_PK_PARSE_C)
static psa_status_t psa_import_ecp_key( psa_ecc_curve_t expected_curve,
                                        mbedtls_pk_context *pk,
                                        mbedtls_ecp_keypair **p_ecp )
{
    if( mbedtls_pk_get_type( pk ) != MBEDTLS_PK_ECKEY )
        return( PSA_ERROR_INVALID_ARGUMENT );
    else
    {
        mbedtls_ecp_keypair *ecp = mbedtls_pk_ec( *pk );
        psa_ecc_curve_t actual_curve = mbedtls_ecc_group_to_psa( ecp->grp.id );
        if( actual_curve != expected_curve )
            return( PSA_ERROR_INVALID_ARGUMENT );
        *p_ecp = ecp;
        return( PSA_SUCCESS );
    }
}
#endif /* defined(MBEDTLS_ECP_C) && defined(MBEDTLS_PK_PARSE_C) */

psa_status_t psa_import_key( psa_key_slot_t key,
                             psa_key_type_t type,
                             const uint8_t *data,
                             size_t data_length )
{
    key_slot_t *slot;
    psa_status_t status = PSA_SUCCESS;
    status = psa_get_empty_key_slot( key, &slot );
    if( status != PSA_SUCCESS )
        return( status );

    if( key_type_is_raw_bytes( type ) )
    {
        /* Ensure that a bytes-to-bit conversion won't overflow. */
        if( data_length > SIZE_MAX / 8 )
            return( PSA_ERROR_NOT_SUPPORTED );
        status = prepare_raw_data_slot( type,
                                        PSA_BYTES_TO_BITS( data_length ),
                                        &slot->data.raw );
        if( status != PSA_SUCCESS )
            return( status );
        if( data_length != 0 )
            memcpy( slot->data.raw.data, data, data_length );
    }
    else
#if defined(MBEDTLS_PK_PARSE_C)
    if( PSA_KEY_TYPE_IS_RSA( type ) || PSA_KEY_TYPE_IS_ECC( type ) )
    {
        int ret;
        mbedtls_pk_context pk;
        mbedtls_pk_init( &pk );

        /* Parse the data. */
        if( PSA_KEY_TYPE_IS_KEYPAIR( type ) )
            ret = mbedtls_pk_parse_key( &pk, data, data_length, NULL, 0 );
        else
            ret = mbedtls_pk_parse_public_key( &pk, data, data_length );
        if( ret != 0 )
            return( mbedtls_to_psa_error( ret ) );

        /* We have something that the pkparse module recognizes.
         * If it has the expected type and passes any type-specific
         * checks, store it. */
#if defined(MBEDTLS_RSA_C)
        if( PSA_KEY_TYPE_IS_RSA( type ) )
            status = psa_import_rsa_key( &pk, &slot->data.rsa );
        else
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
        if( PSA_KEY_TYPE_IS_ECC( type ) )
            status = psa_import_ecp_key( PSA_KEY_TYPE_GET_CURVE( type ),
                                         &pk, &slot->data.ecp );
        else
#endif /* MBEDTLS_ECP_C */
        {
            status = PSA_ERROR_NOT_SUPPORTED;
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
    psa_status_t status;

    status = psa_get_key_slot( key, &slot );
    if( status != PSA_SUCCESS )
        return( status );

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
    if( PSA_KEY_TYPE_IS_RSA( slot->type ) )
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

/* Return the size of the key in the given slot, in bits. */
static size_t psa_get_key_bits( const key_slot_t *slot )
{
    if( key_type_is_raw_bytes( slot->type ) )
        return( slot->data.raw.bytes * 8 );
#if defined(MBEDTLS_RSA_C)
    if( PSA_KEY_TYPE_IS_RSA( slot->type ) )
        return( mbedtls_rsa_get_bitlen( slot->data.rsa ) );
#endif /* defined(MBEDTLS_RSA_C) */
#if defined(MBEDTLS_ECP_C)
    if( PSA_KEY_TYPE_IS_ECC( slot->type ) )
        return( slot->data.ecp->grp.pbits );
#endif /* defined(MBEDTLS_ECP_C) */
    /* Shouldn't happen except on an empty slot. */
    return( 0 );
}

psa_status_t psa_get_key_information( psa_key_slot_t key,
                                      psa_key_type_t *type,
                                      size_t *bits )
{
    key_slot_t *slot;
    psa_status_t status;

    if( type != NULL )
        *type = 0;
    if( bits != NULL )
        *bits = 0;
    status = psa_get_key_slot( key, &slot );
    if( status != PSA_SUCCESS )
        return( status );

    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );
    if( type != NULL )
        *type = slot->type;
    if( bits != NULL )
        *bits = psa_get_key_bits( slot );
    return( PSA_SUCCESS );
}

static  psa_status_t psa_internal_export_key( psa_key_slot_t key,
                                              uint8_t *data,
                                              size_t data_size,
                                              size_t *data_length,
                                              int export_public_key )
{
    key_slot_t *slot;
    psa_status_t status;
    /* Exporting a public key doesn't require a usage flag. If we're
     * called by psa_export_public_key(), don't require the EXPORT flag.
     * If we're called by psa_export_key(), do require the EXPORT flag;
     * if the key turns out to be public key object, psa_get_key_from_slot()
     * will ignore this flag. */
    psa_key_usage_t usage = export_public_key ? 0 : PSA_KEY_USAGE_EXPORT;

    /* Set the key to empty now, so that even when there are errors, we always
     * set data_length to a value between 0 and data_size. On error, setting
     * the key to empty is a good choice because an empty key representation is
     * unlikely to be accepted anywhere. */
    *data_length = 0;

    status = psa_get_key_from_slot( key, &slot, usage, 0 );
    if( status != PSA_SUCCESS )
        return( status );
    if( export_public_key && ! PSA_KEY_TYPE_IS_ASYMMETRIC( slot->type ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( key_type_is_raw_bytes( slot->type ) )
    {
        if( slot->data.raw.bytes > data_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        if( slot->data.raw.bytes != 0 )
            memcpy( data, slot->data.raw.data, slot->data.raw.bytes );
        *data_length = slot->data.raw.bytes;
        return( PSA_SUCCESS );
    }
    else
    {
#if defined(MBEDTLS_PK_WRITE_C)
        if( PSA_KEY_TYPE_IS_RSA( slot->type ) ||
            PSA_KEY_TYPE_IS_ECC( slot->type ) )
        {
            mbedtls_pk_context pk;
            int ret;
            if( PSA_KEY_TYPE_IS_RSA( slot->type ) )
            {
#if defined(MBEDTLS_RSA_C)
                mbedtls_pk_init( &pk );
                pk.pk_info = &mbedtls_rsa_info;
                pk.pk_ctx = slot->data.rsa;
#else
                return( PSA_ERROR_NOT_SUPPORTED );
#endif
            }
            else
            {
#if defined(MBEDTLS_ECP_C)
                mbedtls_pk_init( &pk );
                pk.pk_info = &mbedtls_eckey_info;
                pk.pk_ctx = slot->data.ecp;
#else
                return( PSA_ERROR_NOT_SUPPORTED );
#endif
            }
            if( export_public_key || PSA_KEY_TYPE_IS_PUBLIC_KEY( slot->type ) )
                ret = mbedtls_pk_write_pubkey_der( &pk, data, data_size );
            else
                ret = mbedtls_pk_write_key_der( &pk, data, data_size );
            if( ret < 0 )
            {
                /* If data_size is 0 then data may be NULL and then the
                 * call to memset would have undefined behavior. */
                if( data_size != 0 )
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

psa_status_t psa_hash_setup( psa_hash_operation_t *operation,
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

    /* Don't require hash implementations to behave correctly on a
     * zero-length input, which may have an invalid pointer. */
    if( input_length == 0 )
        return( PSA_SUCCESS );

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
    psa_status_t status;
    int ret;
    size_t actual_hash_length = PSA_HASH_SIZE( operation->alg );

    /* Fill the output buffer with something that isn't a valid hash
     * (barring an attack on the hash and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    *hash_length = hash_size;
    /* If hash_size is 0 then hash may be NULL and then the
     * call to memset would have undefined behavior. */
    if( hash_size != 0 )
        memset( hash, '!', hash_size );

    if( hash_size < actual_hash_length )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

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
    status = mbedtls_to_psa_error( ret );

exit:
    if( status == PSA_SUCCESS )
    {
        *hash_length = actual_hash_length;
        return( psa_hash_abort( operation ) );
    }
    else
    {
        psa_hash_abort( operation );
        return( status );
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
        switch( alg )
        {
            case PSA_ALG_ARC4:
                mode = MBEDTLS_MODE_STREAM;
                break;
            case PSA_ALG_CTR:
                mode = MBEDTLS_MODE_CTR;
                break;
            case PSA_ALG_CFB:
                mode = MBEDTLS_MODE_CFB;
                break;
            case PSA_ALG_OFB:
                mode = MBEDTLS_MODE_OFB;
                break;
            case PSA_ALG_CBC_NO_PADDING:
                mode = MBEDTLS_MODE_CBC;
                break;
            case PSA_ALG_CBC_PKCS7:
                mode = MBEDTLS_MODE_CBC;
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

    return( mbedtls_cipher_info_from_values( cipher_id_tmp,
                                             (int) key_bits, mode ) );
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
    operation->is_sign = 0;

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
        /* We'll set up the hash operation later in psa_hmac_setup_internal. */
        operation->ctx.hmac.hash_ctx.alg = 0;
        status = PSA_SUCCESS;
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

#if defined(MBEDTLS_MD_C)
static psa_status_t psa_hmac_abort_internal( psa_hmac_internal_data *hmac )
{
    mbedtls_zeroize( hmac->opad, sizeof( hmac->opad ) );
    return( psa_hash_abort( &hmac->hash_ctx ) );
}
#endif /* MBEDTLS_MD_C */

psa_status_t psa_mac_abort( psa_mac_operation_t *operation )
{
    if( operation->alg == 0 )
    {
        /* The object has (apparently) been initialized but it is not
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
        return( PSA_SUCCESS );
    }
    else
#if defined(MBEDTLS_CMAC_C)
    if( operation->alg == PSA_ALG_CMAC )
    {
        mbedtls_cipher_free( &operation->ctx.cmac );
    }
    else
#endif /* MBEDTLS_CMAC_C */
#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HMAC( operation->alg ) )
    {
        psa_hmac_abort_internal( &operation->ctx.hmac );
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        /* Sanity check (shouldn't happen: operation->alg should
         * always have been initialized to a valid value). */
        goto bad_state;
    }

    operation->alg = 0;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_required = 0;
    operation->has_input = 0;
    operation->is_sign = 0;

    return( PSA_SUCCESS );

bad_state:
    /* If abort is called on an uninitialized object, we can't trust
     * anything. Wipe the object in case it contains confidential data.
     * This may result in a memory leak if a pointer gets overwritten,
     * but it's too late to do anything about this. */
    memset( operation, 0, sizeof( *operation ) );
    return( PSA_ERROR_BAD_STATE );
}

#if defined(MBEDTLS_CMAC_C)
static int psa_cmac_setup( psa_mac_operation_t *operation,
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
static psa_status_t psa_hmac_setup_internal( psa_hmac_internal_data *hmac,
                                             const uint8_t *key,
                                             size_t key_length,
                                             psa_algorithm_t hash_alg )
{
    unsigned char ipad[PSA_HMAC_MAX_HASH_BLOCK_SIZE];
    size_t i;
    size_t hash_size = PSA_HASH_SIZE( hash_alg );
    size_t block_size = psa_get_hash_block_size( hash_alg );
    psa_status_t status;

    /* Sanity checks on block_size, to guarantee that there won't be a buffer
     * overflow below. This should never trigger if the hash algorithm
     * is implemented correctly. */
    /* The size checks against the ipad and opad buffers cannot be written
     * `block_size > sizeof( ipad ) || block_size > sizeof( hmac->opad )`
     * because that triggers -Wlogical-op on GCC 7.3. */
    if( block_size > sizeof( ipad ) )
        return( PSA_ERROR_NOT_SUPPORTED );
    if( block_size > sizeof( hmac->opad ) )
        return( PSA_ERROR_NOT_SUPPORTED );
    if( block_size < hash_size )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( key_length > block_size )
    {
        status = psa_hash_setup( &hmac->hash_ctx, hash_alg );
        if( status != PSA_SUCCESS )
            goto cleanup;
        status = psa_hash_update( &hmac->hash_ctx, key, key_length );
        if( status != PSA_SUCCESS )
            goto cleanup;
        status = psa_hash_finish( &hmac->hash_ctx,
                                  ipad, sizeof( ipad ), &key_length );
        if( status != PSA_SUCCESS )
            goto cleanup;
    }
    /* A 0-length key is not commonly used in HMAC when used as a MAC,
     * but it is permitted. It is common when HMAC is used in HKDF, for
     * example. Don't call `memcpy` in the 0-length because `key` could be
     * an invalid pointer which would make the behavior undefined. */
    else if( key_length != 0 )
        memcpy( ipad, key, key_length );

    /* ipad contains the key followed by garbage. Xor and fill with 0x36
     * to create the ipad value. */
    for( i = 0; i < key_length; i++ )
        ipad[i] ^= 0x36;
    memset( ipad + key_length, 0x36, block_size - key_length );

    /* Copy the key material from ipad to opad, flipping the requisite bits,
     * and filling the rest of opad with the requisite constant. */
    for( i = 0; i < key_length; i++ )
        hmac->opad[i] = ipad[i] ^ 0x36 ^ 0x5C;
    memset( hmac->opad + key_length, 0x5C, block_size - key_length );

    status = psa_hash_setup( &hmac->hash_ctx, hash_alg );
    if( status != PSA_SUCCESS )
        goto cleanup;

    status = psa_hash_update( &hmac->hash_ctx, ipad, block_size );

cleanup:
    mbedtls_zeroize( ipad, key_length );

    return( status );
}
#endif /* MBEDTLS_MD_C */

static psa_status_t psa_mac_setup( psa_mac_operation_t *operation,
                                   psa_key_slot_t key,
                                   psa_algorithm_t alg,
                                   int is_sign )
{
    psa_status_t status;
    key_slot_t *slot;
    size_t key_bits;
    psa_key_usage_t usage =
        is_sign ? PSA_KEY_USAGE_SIGN : PSA_KEY_USAGE_VERIFY;

    status = psa_mac_init( operation, alg );
    if( status != PSA_SUCCESS )
        return( status );
    if( is_sign )
        operation->is_sign = 1;

    status = psa_get_key_from_slot( key, &slot, usage, alg );
    if( status != PSA_SUCCESS )
        goto exit;
    key_bits = psa_get_key_bits( slot );

#if defined(MBEDTLS_CMAC_C)
    if( alg == PSA_ALG_CMAC )
    {
        const mbedtls_cipher_info_t *cipher_info =
            mbedtls_cipher_info_from_psa( alg, slot->type, key_bits, NULL );
        int ret;
        if( cipher_info == NULL )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        operation->mac_size = cipher_info->block_size;
        ret = psa_cmac_setup( operation, key_bits, slot, cipher_info );
        status = mbedtls_to_psa_error( ret );
    }
    else
#endif /* MBEDTLS_CMAC_C */
#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HMAC( alg ) )
    {
        psa_algorithm_t hash_alg = PSA_ALG_HMAC_HASH( alg );
        if( hash_alg == 0 )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }

        operation->mac_size = PSA_HASH_SIZE( hash_alg );
        /* Sanity check. This shouldn't fail on a valid configuration. */
        if( operation->mac_size == 0 ||
            operation->mac_size > sizeof( operation->ctx.hmac.opad ) )
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }

        if( slot->type != PSA_KEY_TYPE_HMAC )
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        status = psa_hmac_setup_internal( &operation->ctx.hmac,
                                          slot->data.raw.data,
                                          slot->data.raw.bytes,
                                          hash_alg );
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

exit:
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

psa_status_t psa_mac_sign_setup( psa_mac_operation_t *operation,
                                 psa_key_slot_t key,
                                 psa_algorithm_t alg )
{
    return( psa_mac_setup( operation, key, alg, 1 ) );
}

psa_status_t psa_mac_verify_setup( psa_mac_operation_t *operation,
                                   psa_key_slot_t key,
                                   psa_algorithm_t alg )
{
    return( psa_mac_setup( operation, key, alg, 0 ) );
}

psa_status_t psa_mac_update( psa_mac_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length )
{
    psa_status_t status = PSA_ERROR_BAD_STATE;
    if( ! operation->key_set )
        goto cleanup;
    if( operation->iv_required && ! operation->iv_set )
        goto cleanup;
    operation->has_input = 1;

#if defined(MBEDTLS_CMAC_C)
    if( operation->alg == PSA_ALG_CMAC )
    {
        int ret = mbedtls_cipher_cmac_update( &operation->ctx.cmac,
                                              input, input_length );
        status = mbedtls_to_psa_error( ret );
    }
    else
#endif /* MBEDTLS_CMAC_C */
#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HMAC( operation->alg ) )
    {
        status = psa_hash_update( &operation->ctx.hmac.hash_ctx, input,
                                  input_length );
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        /* This shouldn't happen if `operation` was initialized by
         * a setup function. */
        status = PSA_ERROR_BAD_STATE;
    }

cleanup:
    if( status != PSA_SUCCESS )
        psa_mac_abort( operation );
    return( status );
}

#if defined(MBEDTLS_MD_C)
static psa_status_t psa_hmac_finish_internal( psa_hmac_internal_data *hmac,
                                              uint8_t *mac,
                                              size_t mac_size )
{
    unsigned char tmp[MBEDTLS_MD_MAX_SIZE];
    psa_algorithm_t hash_alg = hmac->hash_ctx.alg;
    size_t hash_size = 0;
    size_t block_size = psa_get_hash_block_size( hash_alg );
    psa_status_t status;

    status = psa_hash_finish( &hmac->hash_ctx, tmp, sizeof( tmp ), &hash_size );
    if( status != PSA_SUCCESS )
        return( status );
    /* From here on, tmp needs to be wiped. */

    status = psa_hash_setup( &hmac->hash_ctx, hash_alg );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_hash_update( &hmac->hash_ctx, hmac->opad, block_size );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_hash_update( &hmac->hash_ctx, tmp, hash_size );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_hash_finish( &hmac->hash_ctx, mac, mac_size, &hash_size );

exit:
    mbedtls_zeroize( tmp, hash_size );
    return( status );
}
#endif /* MBEDTLS_MD_C */

static psa_status_t psa_mac_finish_internal( psa_mac_operation_t *operation,
                                             uint8_t *mac,
                                             size_t mac_size )
{
    if( ! operation->key_set )
        return( PSA_ERROR_BAD_STATE );
    if( operation->iv_required && ! operation->iv_set )
        return( PSA_ERROR_BAD_STATE );

    if( mac_size < operation->mac_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

#if defined(MBEDTLS_CMAC_C)
    if( operation->alg == PSA_ALG_CMAC )
    {
        int ret = mbedtls_cipher_cmac_finish( &operation->ctx.cmac, mac );
        return( mbedtls_to_psa_error( ret ) );
    }
    else
#endif /* MBEDTLS_CMAC_C */
#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HMAC( operation->alg ) )
    {
        return( psa_hmac_finish_internal( &operation->ctx.hmac,
                                          mac, mac_size ) );
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        /* This shouldn't happen if `operation` was initialized by
         * a setup function. */
        return( PSA_ERROR_BAD_STATE );
    }
}

psa_status_t psa_mac_sign_finish( psa_mac_operation_t *operation,
                                  uint8_t *mac,
                                  size_t mac_size,
                                  size_t *mac_length )
{
    psa_status_t status;

    /* Fill the output buffer with something that isn't a valid mac
     * (barring an attack on the mac and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    *mac_length = mac_size;
    /* If mac_size is 0 then mac may be NULL and then the
     * call to memset would have undefined behavior. */
    if( mac_size != 0 )
        memset( mac, '!', mac_size );

    if( ! operation->is_sign )
    {
        status = PSA_ERROR_BAD_STATE;
        goto cleanup;
    }

    status = psa_mac_finish_internal( operation, mac, mac_size );

cleanup:
    if( status == PSA_SUCCESS )
    {
        status = psa_mac_abort( operation );
        if( status == PSA_SUCCESS )
            *mac_length = operation->mac_size;
        else
            memset( mac, '!', mac_size );
    }
    else
        psa_mac_abort( operation );
    return( status );
}

psa_status_t psa_mac_verify_finish( psa_mac_operation_t *operation,
                                    const uint8_t *mac,
                                    size_t mac_length )
{
    uint8_t actual_mac[PSA_MAC_MAX_SIZE];
    psa_status_t status;

    if( operation->is_sign )
    {
        status = PSA_ERROR_BAD_STATE;
        goto cleanup;
    }
    if( operation->mac_size != mac_length )
    {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto cleanup;
    }

    status = psa_mac_finish_internal( operation,
                                      actual_mac, sizeof( actual_mac ) );

    if( safer_memcmp( mac, actual_mac, mac_length ) != 0 )
        status = PSA_ERROR_INVALID_SIGNATURE;

cleanup:
    if( status == PSA_SUCCESS )
        status = psa_mac_abort( operation );
    else
        psa_mac_abort( operation );

    return( status );
}



/****************************************************************/
/* Asymmetric cryptography */
/****************************************************************/

#if defined(MBEDTLS_RSA_C)
/* Decode the hash algorithm from alg and store the mbedtls encoding in
 * md_alg. Verify that the hash length is acceptable. */
static psa_status_t psa_rsa_decode_md_type( psa_algorithm_t alg,
                                            size_t hash_length,
                                            mbedtls_md_type_t *md_alg )
{
    psa_algorithm_t hash_alg = PSA_ALG_SIGN_GET_HASH( alg );
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_psa( hash_alg );
    *md_alg = mbedtls_md_get_type( md_info );

    /* The Mbed TLS RSA module uses an unsigned int for hash length
     * parameters. Validate that it fits so that we don't risk an
     * overflow later. */
#if SIZE_MAX > UINT_MAX
    if( hash_length > UINT_MAX )
        return( PSA_ERROR_INVALID_ARGUMENT );
#endif

#if defined(MBEDTLS_PKCS1_V15)
    /* For PKCS#1 v1.5 signature, if using a hash, the hash length
     * must be correct. */
    if( PSA_ALG_IS_RSA_PKCS1V15_SIGN( alg ) &&
        alg != PSA_ALG_RSA_PKCS1V15_SIGN_RAW )
    {
        if( md_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( mbedtls_md_get_size( md_info ) != hash_length )
            return( PSA_ERROR_INVALID_ARGUMENT );
    }
#endif /* MBEDTLS_PKCS1_V15 */

#if defined(MBEDTLS_PKCS1_V21)
    /* PSS requires a hash internally. */
    if( PSA_ALG_IS_RSA_PSS( alg ) )
    {
        if( md_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
    }
#endif /* MBEDTLS_PKCS1_V21 */

    return( PSA_SUCCESS );
}

static psa_status_t psa_rsa_sign( mbedtls_rsa_context *rsa,
                                  psa_algorithm_t alg,
                                  const uint8_t *hash,
                                  size_t hash_length,
                                  uint8_t *signature,
                                  size_t signature_size,
                                  size_t *signature_length )
{
    psa_status_t status;
    int ret;
    mbedtls_md_type_t md_alg;

    status = psa_rsa_decode_md_type( alg, hash_length, &md_alg );
    if( status != PSA_SUCCESS )
        return( status );

    if( signature_size < mbedtls_rsa_get_len( rsa ) )
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
                                      md_alg,
                                      (unsigned int) hash_length,
                                      hash,
                                      signature );
    }
    else
#endif /* MBEDTLS_PKCS1_V15 */
#if defined(MBEDTLS_PKCS1_V21)
    if( PSA_ALG_IS_RSA_PSS( alg ) )
    {
        mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V21, md_alg );
        ret = mbedtls_rsa_rsassa_pss_sign( rsa,
                                           mbedtls_ctr_drbg_random,
                                           &global_data.ctr_drbg,
                                           MBEDTLS_RSA_PRIVATE,
                                           MBEDTLS_MD_NONE,
                                           (unsigned int) hash_length,
                                           hash,
                                           signature );
    }
    else
#endif /* MBEDTLS_PKCS1_V21 */
    {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

    if( ret == 0 )
        *signature_length = mbedtls_rsa_get_len( rsa );
    return( mbedtls_to_psa_error( ret ) );
}

static psa_status_t psa_rsa_verify( mbedtls_rsa_context *rsa,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash,
                                    size_t hash_length,
                                    const uint8_t *signature,
                                    size_t signature_length )
{
    psa_status_t status;
    int ret;
    mbedtls_md_type_t md_alg;

    status = psa_rsa_decode_md_type( alg, hash_length, &md_alg );
    if( status != PSA_SUCCESS )
        return( status );

    if( signature_length < mbedtls_rsa_get_len( rsa ) )
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
                                        (unsigned int) hash_length,
                                        hash,
                                        signature );
    }
    else
#endif /* MBEDTLS_PKCS1_V15 */
#if defined(MBEDTLS_PKCS1_V21)
    if( PSA_ALG_IS_RSA_PSS( alg ) )
    {
        mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V21, md_alg );
        ret = mbedtls_rsa_rsassa_pss_verify( rsa,
                                             mbedtls_ctr_drbg_random,
                                             &global_data.ctr_drbg,
                                             MBEDTLS_RSA_PUBLIC,
                                             MBEDTLS_MD_NONE,
                                             (unsigned int) hash_length,
                                             hash,
                                             signature );
    }
    else
#endif /* MBEDTLS_PKCS1_V21 */
    {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }
    return( mbedtls_to_psa_error( ret ) );
}
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECDSA_C)
/* `ecp` cannot be const because `ecp->grp` needs to be non-const
 * for mbedtls_ecdsa_sign() and mbedtls_ecdsa_sign_det()
 * (even though these functions don't modify it). */
static psa_status_t psa_ecdsa_sign( mbedtls_ecp_keypair *ecp,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash,
                                    size_t hash_length,
                                    uint8_t *signature,
                                    size_t signature_size,
                                    size_t *signature_length )
{
    int ret;
    mbedtls_mpi r, s;
    size_t curve_bytes = PSA_BITS_TO_BYTES( ecp->grp.pbits );
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    if( signature_size < 2 * curve_bytes )
    {
        ret = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    if( PSA_ALG_DSA_IS_DETERMINISTIC( alg ) )
    {
        psa_algorithm_t hash_alg = PSA_ALG_SIGN_GET_HASH( alg );
        const mbedtls_md_info_t *md_info = mbedtls_md_info_from_psa( hash_alg );
        mbedtls_md_type_t md_alg = mbedtls_md_get_type( md_info );
        MBEDTLS_MPI_CHK( mbedtls_ecdsa_sign_det( &ecp->grp, &r, &s, &ecp->d,
                                                 hash, hash_length,
                                                 md_alg ) );
    }
    else
    {
        MBEDTLS_MPI_CHK( mbedtls_ecdsa_sign( &ecp->grp, &r, &s, &ecp->d,
                                             hash, hash_length,
                                             mbedtls_ctr_drbg_random,
                                             &global_data.ctr_drbg ) );
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &r,
                                               signature,
                                               curve_bytes ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &s,
                                               signature + curve_bytes,
                                               curve_bytes ) );

cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    if( ret == 0 )
        *signature_length = 2 * curve_bytes;
    return( mbedtls_to_psa_error( ret ) );
}

static psa_status_t psa_ecdsa_verify( mbedtls_ecp_keypair *ecp,
                                      const uint8_t *hash,
                                      size_t hash_length,
                                      const uint8_t *signature,
                                      size_t signature_length )
{
    int ret;
    mbedtls_mpi r, s;
    size_t curve_bytes = PSA_BITS_TO_BYTES( ecp->grp.pbits );
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );

    if( signature_length != 2 * curve_bytes )
        return( PSA_ERROR_INVALID_SIGNATURE );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &r,
                                              signature,
                                              curve_bytes ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &s,
                                              signature + curve_bytes,
                                              curve_bytes ) );

    ret = mbedtls_ecdsa_verify( &ecp->grp, hash, hash_length,
                                &ecp->Q, &r, &s );

cleanup:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    return( mbedtls_to_psa_error( ret ) );
}
#endif /* MBEDTLS_ECDSA_C */

psa_status_t psa_asymmetric_sign( psa_key_slot_t key,
                                  psa_algorithm_t alg,
                                  const uint8_t *hash,
                                  size_t hash_length,
                                  uint8_t *signature,
                                  size_t signature_size,
                                  size_t *signature_length )
{
    key_slot_t *slot;
    psa_status_t status;

    *signature_length = signature_size;

    status = psa_get_key_from_slot( key, &slot, PSA_KEY_USAGE_SIGN, alg );
    if( status != PSA_SUCCESS )
        goto exit;
    if( ! PSA_KEY_TYPE_IS_KEYPAIR( slot->type ) )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

#if defined(MBEDTLS_RSA_C)
    if( slot->type == PSA_KEY_TYPE_RSA_KEYPAIR )
    {
        status = psa_rsa_sign( slot->data.rsa,
                               alg,
                               hash, hash_length,
                               signature, signature_size,
                               signature_length );
    }
    else
#endif /* defined(MBEDTLS_RSA_C) */
#if defined(MBEDTLS_ECP_C)
    if( PSA_KEY_TYPE_IS_ECC( slot->type ) )
    {
#if defined(MBEDTLS_ECDSA_C)
        if( PSA_ALG_IS_ECDSA( alg ) )
            status = psa_ecdsa_sign( slot->data.ecp,
                                     alg,
                                     hash, hash_length,
                                     signature, signature_size,
                                     signature_length );
        else
#endif /* defined(MBEDTLS_ECDSA_C) */
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else
#endif /* defined(MBEDTLS_ECP_C) */
    {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

exit:
    /* Fill the unused part of the output buffer (the whole buffer on error,
     * the trailing part on success) with something that isn't a valid mac
     * (barring an attack on the mac and deliberately-crafted input),
     * in case the caller doesn't check the return status properly. */
    if( status == PSA_SUCCESS )
        memset( signature + *signature_length, '!',
                signature_size - *signature_length );
    else if( signature_size != 0 )
        memset( signature, '!', signature_size );
    /* If signature_size is 0 then we have nothing to do. We must not call
     * memset because signature may be NULL in this case. */
    return( status );
}

psa_status_t psa_asymmetric_verify( psa_key_slot_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash,
                                    size_t hash_length,
                                    const uint8_t *signature,
                                    size_t signature_length )
{
    key_slot_t *slot;
    psa_status_t status;

    status = psa_get_key_from_slot( key, &slot, PSA_KEY_USAGE_VERIFY, alg );
    if( status != PSA_SUCCESS )
        return( status );

#if defined(MBEDTLS_RSA_C)
    if( PSA_KEY_TYPE_IS_RSA( slot->type ) )
    {
        return( psa_rsa_verify( slot->data.rsa,
                                alg,
                                hash, hash_length,
                                signature, signature_length ) );
    }
    else
#endif /* defined(MBEDTLS_RSA_C) */
#if defined(MBEDTLS_ECP_C)
    if( PSA_KEY_TYPE_IS_ECC( slot->type ) )
    {
#if defined(MBEDTLS_ECDSA_C)
        if( PSA_ALG_IS_ECDSA( alg ) )
            return( psa_ecdsa_verify( slot->data.ecp,
                                      hash, hash_length,
                                      signature, signature_length ) );
        else
#endif /* defined(MBEDTLS_ECDSA_C) */
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
    }
    else
#endif /* defined(MBEDTLS_ECP_C) */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PKCS1_V21)
static void psa_rsa_oaep_set_padding_mode( psa_algorithm_t alg,
                                           mbedtls_rsa_context *rsa )
{
    psa_algorithm_t hash_alg = PSA_ALG_RSA_OAEP_GET_HASH( alg );
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_psa( hash_alg );
    mbedtls_md_type_t md_alg = mbedtls_md_get_type( md_info );
    mbedtls_rsa_set_padding( rsa, MBEDTLS_RSA_PKCS_V21, md_alg );
}
#endif /* defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PKCS1_V21) */

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
    psa_status_t status;

    (void) input;
    (void) input_length;
    (void) salt;
    (void) output;
    (void) output_size;

    *output_length = 0;

    if( ! PSA_ALG_IS_RSA_OAEP( alg ) && salt_length != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_get_key_from_slot( key, &slot, PSA_KEY_USAGE_ENCRYPT, alg );
    if( status != PSA_SUCCESS )
        return( status );
    if( ! ( PSA_KEY_TYPE_IS_PUBLIC_KEY( slot->type ) ||
            PSA_KEY_TYPE_IS_KEYPAIR( slot->type ) ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

#if defined(MBEDTLS_RSA_C)
    if( PSA_KEY_TYPE_IS_RSA( slot->type ) )
    {
        mbedtls_rsa_context *rsa = slot->data.rsa;
        int ret;
        if( output_size < mbedtls_rsa_get_len( rsa ) )
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
        if( PSA_ALG_IS_RSA_OAEP( alg ) )
        {
            psa_rsa_oaep_set_padding_mode( alg, rsa );
            ret = mbedtls_rsa_rsaes_oaep_encrypt( rsa,
                                                  mbedtls_ctr_drbg_random,
                                                  &global_data.ctr_drbg,
                                                  MBEDTLS_RSA_PUBLIC,
                                                  salt, salt_length,
                                                  input_length,
                                                  input,
                                                  output );
        }
        else
#endif /* MBEDTLS_PKCS1_V21 */
        {
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
        if( ret == 0 )
            *output_length = mbedtls_rsa_get_len( rsa );
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
    psa_status_t status;

    (void) input;
    (void) input_length;
    (void) salt;
    (void) output;
    (void) output_size;

    *output_length = 0;

    if( ! PSA_ALG_IS_RSA_OAEP( alg ) && salt_length != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_get_key_from_slot( key, &slot, PSA_KEY_USAGE_DECRYPT, alg );
    if( status != PSA_SUCCESS )
        return( status );
    if( ! PSA_KEY_TYPE_IS_KEYPAIR( slot->type ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

#if defined(MBEDTLS_RSA_C)
    if( slot->type == PSA_KEY_TYPE_RSA_KEYPAIR )
    {
        mbedtls_rsa_context *rsa = slot->data.rsa;
        int ret;

        if( input_length != mbedtls_rsa_get_len( rsa ) )
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
        if( PSA_ALG_IS_RSA_OAEP( alg ) )
        {
            psa_rsa_oaep_set_padding_mode( alg, rsa );
            ret = mbedtls_rsa_rsaes_oaep_decrypt( rsa,
                                                  mbedtls_ctr_drbg_random,
                                                  &global_data.ctr_drbg,
                                                  MBEDTLS_RSA_PRIVATE,
                                                  salt, salt_length,
                                                  output_length,
                                                  input,
                                                  output,
                                                  output_size );
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
    size_t key_bits;
    const mbedtls_cipher_info_t *cipher_info = NULL;
    psa_key_usage_t usage = ( cipher_operation == MBEDTLS_ENCRYPT ?
                              PSA_KEY_USAGE_ENCRYPT :
                              PSA_KEY_USAGE_DECRYPT );

    status = psa_cipher_init( operation, alg );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_get_key_from_slot( key, &slot, usage, alg);
    if( status != PSA_SUCCESS )
        return( status );
    key_bits = psa_get_key_bits( slot );

    cipher_info = mbedtls_cipher_info_from_psa( alg, slot->type, key_bits, NULL );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    ret = mbedtls_cipher_setup( &operation->ctx.cipher, cipher_info );
    if( ret != 0 )
    {
        psa_cipher_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }

#if defined(MBEDTLS_DES_C)
    if( slot->type == PSA_KEY_TYPE_DES && key_bits == 128 )
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
                                     (int) key_bits, cipher_operation );
    }
    if( ret != 0 )
    {
        psa_cipher_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    switch( alg )
    {
        case PSA_ALG_CBC_NO_PADDING:
            ret = mbedtls_cipher_set_padding_mode( &operation->ctx.cipher,
                                                   MBEDTLS_PADDING_NONE );
            break;
        case PSA_ALG_CBC_PKCS7:
            ret = mbedtls_cipher_set_padding_mode( &operation->ctx.cipher,
                                                   MBEDTLS_PADDING_PKCS7 );
            break;
        default:
            /* The algorithm doesn't involve padding. */
            ret = 0;
            break;
    }
    if( ret != 0 )
    {
        psa_cipher_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }
#endif //MBEDTLS_CIPHER_MODE_WITH_PADDING

    operation->key_set = 1;
    operation->block_size = ( PSA_ALG_IS_STREAM_CIPHER( alg ) ? 1 :
                              PSA_BLOCK_CIPHER_BLOCK_SIZE( slot->type ) );
    if( alg & PSA_ALG_CIPHER_FROM_BLOCK_FLAG )
    {
        operation->iv_size = PSA_BLOCK_CIPHER_BLOCK_SIZE( slot->type );
    }

    return( PSA_SUCCESS );
}

psa_status_t psa_cipher_encrypt_setup( psa_cipher_operation_t *operation,
                                       psa_key_slot_t key,
                                       psa_algorithm_t alg )
{
    return( psa_cipher_setup( operation, key, alg, MBEDTLS_ENCRYPT ) );
}

psa_status_t psa_cipher_decrypt_setup( psa_cipher_operation_t *operation,
                                       psa_key_slot_t key,
                                       psa_algorithm_t alg )
{
    return( psa_cipher_setup( operation, key, alg, MBEDTLS_DECRYPT ) );
}

psa_status_t psa_cipher_generate_iv( psa_cipher_operation_t *operation,
                                     unsigned char *iv,
                                     size_t iv_size,
                                     size_t *iv_length )
{
    psa_status_t status;
    int ret;
    if( operation->iv_set || ! operation->iv_required )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }
    if( iv_size < operation->iv_size )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }
    ret = mbedtls_ctr_drbg_random( &global_data.ctr_drbg,
                                   iv, operation->iv_size );
    if( ret != 0 )
    {
        status = mbedtls_to_psa_error( ret );
        goto exit;
    }

    *iv_length = operation->iv_size;
    status = psa_cipher_set_iv( operation, iv, *iv_length );

exit:
    if( status != PSA_SUCCESS )
        psa_cipher_abort( operation );
    return( status );
}

psa_status_t psa_cipher_set_iv( psa_cipher_operation_t *operation,
                                const unsigned char *iv,
                                size_t iv_length )
{
    psa_status_t status;
    int ret;
    if( operation->iv_set || ! operation->iv_required )
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }
    if( iv_length != operation->iv_size )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    ret = mbedtls_cipher_set_iv( &operation->ctx.cipher, iv, iv_length );
    status = mbedtls_to_psa_error( ret );
exit:
    if( status == PSA_SUCCESS )
        operation->iv_set = 1;
    else
        psa_cipher_abort( operation );
    return( status );
}

psa_status_t psa_cipher_update( psa_cipher_operation_t *operation,
                                const uint8_t *input,
                                size_t input_length,
                                unsigned char *output,
                                size_t output_size,
                                size_t *output_length )
{
    psa_status_t status;
    int ret;
    size_t expected_output_size;
    if( ! PSA_ALG_IS_STREAM_CIPHER( operation->alg ) )
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
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    ret = mbedtls_cipher_update( &operation->ctx.cipher, input,
                                 input_length, output, output_length );
    status = mbedtls_to_psa_error( ret );
exit:
    if( status != PSA_SUCCESS )
        psa_cipher_abort( operation );
    return( status );
}

psa_status_t psa_cipher_finish( psa_cipher_operation_t *operation,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length )
{
    psa_status_t status = PSA_ERROR_UNKNOWN_ERROR;
    int cipher_ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    uint8_t temp_output_buffer[MBEDTLS_MAX_BLOCK_LENGTH];

    if( ! operation->key_set )
    {
        status = PSA_ERROR_BAD_STATE;
        goto error;
    }
    if( operation->iv_required && ! operation->iv_set )
    {
        status = PSA_ERROR_BAD_STATE;
        goto error;
    }

    if( operation->ctx.cipher.operation == MBEDTLS_ENCRYPT &&
        operation->alg == PSA_ALG_CBC_NO_PADDING &&
        operation->ctx.cipher.unprocessed_len != 0 )
    {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto error;
    }

    cipher_ret = mbedtls_cipher_finish( &operation->ctx.cipher,
                                        temp_output_buffer,
                                        output_length );
    if( cipher_ret != 0 )
    {
        status = mbedtls_to_psa_error( cipher_ret );
        goto error;
    }

    if( *output_length == 0 )
        ; /* Nothing to copy. Note that output may be NULL in this case. */
    else if( output_size >= *output_length )
        memcpy( output, temp_output_buffer, *output_length );
    else
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto error;
    }

    mbedtls_zeroize( temp_output_buffer, sizeof( temp_output_buffer ) );
    status = psa_cipher_abort( operation );

    return( status );

error:

    *output_length = 0;

    mbedtls_zeroize( temp_output_buffer, sizeof( temp_output_buffer ) );
    (void) psa_cipher_abort( operation );

    return( status );
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

#if !defined(MBEDTLS_PSA_CRYPTO_SPM)
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

psa_key_usage_t psa_key_policy_get_usage( const psa_key_policy_t *policy )
{
    return( policy->usage );
}

psa_algorithm_t psa_key_policy_get_algorithm( const psa_key_policy_t *policy )
{
    return( policy->alg );
}
#endif /* !defined(MBEDTLS_PSA_CRYPTO_SPM) */

psa_status_t psa_set_key_policy( psa_key_slot_t key,
                                 const psa_key_policy_t *policy )
{
    key_slot_t *slot;
    psa_status_t status;

    if( policy == NULL )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_get_empty_key_slot( key, &slot );
    if( status != PSA_SUCCESS )
        return( status );

    if( ( policy->usage & ~( PSA_KEY_USAGE_EXPORT |
                             PSA_KEY_USAGE_ENCRYPT |
                             PSA_KEY_USAGE_DECRYPT |
                             PSA_KEY_USAGE_SIGN |
                             PSA_KEY_USAGE_VERIFY |
                             PSA_KEY_USAGE_DERIVE ) ) != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    slot->policy = *policy;

    return( PSA_SUCCESS );
}

psa_status_t psa_get_key_policy( psa_key_slot_t key,
                                 psa_key_policy_t *policy )
{
    key_slot_t *slot;
    psa_status_t status;

    if( policy == NULL )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_get_key_slot( key, &slot );
    if( status != PSA_SUCCESS )
        return( status );

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
    psa_status_t status;

    status = psa_get_key_slot( key, &slot );
    if( status != PSA_SUCCESS )
        return( status );

    *lifetime = slot->lifetime;

    return( PSA_SUCCESS );
}

psa_status_t psa_set_key_lifetime( psa_key_slot_t key,
                                   psa_key_lifetime_t lifetime )
{
    key_slot_t *slot;
    psa_status_t status;

    if( lifetime != PSA_KEY_LIFETIME_VOLATILE &&
        lifetime != PSA_KEY_LIFETIME_PERSISTENT &&
        lifetime != PSA_KEY_LIFETIME_WRITE_ONCE)
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_get_empty_key_slot( key, &slot );
    if( status != PSA_SUCCESS )
        return( status );

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
    size_t key_bits;
    uint8_t *tag;
    size_t tag_length;
    mbedtls_cipher_id_t cipher_id;
    const mbedtls_cipher_info_t *cipher_info = NULL;

    *ciphertext_length = 0;

    status = psa_get_key_from_slot( key, &slot, PSA_KEY_USAGE_ENCRYPT, alg );
    if( status != PSA_SUCCESS )
        return( status );
    key_bits = psa_get_key_bits( slot );

    cipher_info = mbedtls_cipher_info_from_psa( alg, slot->type,
                                                key_bits, &cipher_id );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( ( slot->type & PSA_KEY_TYPE_CATEGORY_MASK ) !=
        PSA_KEY_TYPE_CATEGORY_SYMMETRIC )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( alg == PSA_ALG_GCM )
    {
        mbedtls_gcm_context gcm;
        tag_length = 16;

        if( PSA_BLOCK_CIPHER_BLOCK_SIZE( slot->type ) != 16 )
            return( PSA_ERROR_INVALID_ARGUMENT );

        //make sure we have place to hold the tag in the ciphertext buffer
        if( ciphertext_size < ( plaintext_length + tag_length ) )
            return( PSA_ERROR_BUFFER_TOO_SMALL );

        //update the tag pointer to point to the end of the ciphertext_length
        tag = ciphertext + plaintext_length;

        mbedtls_gcm_init( &gcm );
        ret = mbedtls_gcm_setkey( &gcm, cipher_id,
                                  slot->data.raw.data,
                                  (unsigned int) key_bits );
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

        if( PSA_BLOCK_CIPHER_BLOCK_SIZE( slot->type ) != 16 )
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
                                  slot->data.raw.data,
                                  (unsigned int) key_bits );
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
        /* If ciphertext_size is 0 then ciphertext may be NULL and then the
         * call to memset would have undefined behavior. */
        if( ciphertext_size != 0 )
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
    size_t key_bits;
    const uint8_t *tag;
    size_t tag_length;
    mbedtls_cipher_id_t cipher_id;
    const mbedtls_cipher_info_t *cipher_info = NULL;

    *plaintext_length = 0;

    status = psa_get_key_from_slot( key, &slot, PSA_KEY_USAGE_DECRYPT, alg );
    if( status != PSA_SUCCESS )
        return( status );
    key_bits = psa_get_key_bits( slot );

    cipher_info = mbedtls_cipher_info_from_psa( alg, slot->type,
                                                key_bits, &cipher_id );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( ( slot->type & PSA_KEY_TYPE_CATEGORY_MASK ) !=
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
                                  slot->data.raw.data,
                                  (unsigned int) key_bits );
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
                                  slot->data.raw.data,
                                  (unsigned int) key_bits );
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
    {
        /* If plaintext_size is 0 then plaintext may be NULL and then the
         * call to memset has undefined behavior. */
        if( plaintext_size != 0 )
            memset( plaintext, 0, plaintext_size );
    }
    else
        *plaintext_length = ciphertext_length - tag_length;

    return( mbedtls_to_psa_error( ret ) );
}



/****************************************************************/
/* Generators */
/****************************************************************/

psa_status_t psa_generator_abort( psa_crypto_generator_t *generator )
{
    psa_status_t status = PSA_SUCCESS;
    if( generator->alg == 0 )
    {
        /* The object has (apparently) been initialized but it is not
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
    }
    else
#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HKDF( generator->alg ) )
    {
        mbedtls_free( generator->ctx.hkdf.info );
        status = psa_hmac_abort_internal( &generator->ctx.hkdf.hmac );
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        status = PSA_ERROR_BAD_STATE;
    }
    memset( generator, 0, sizeof( *generator ) );
    return( status );
}


psa_status_t psa_get_generator_capacity(const psa_crypto_generator_t *generator,
                                        size_t *capacity)
{
    *capacity = generator->capacity;
    return( PSA_SUCCESS );
}

#if defined(MBEDTLS_MD_C)
/* Read some bytes from an HKDF-based generator. This performs a chunk
 * of the expand phase of the HKDF algorithm. */
static psa_status_t psa_generator_hkdf_read( psa_hkdf_generator_t *hkdf,
                                             psa_algorithm_t hash_alg,
                                             uint8_t *output,
                                             size_t output_length )
{
    uint8_t hash_length = PSA_HASH_SIZE( hash_alg );
    psa_status_t status;

    while( output_length != 0 )
    {
        /* Copy what remains of the current block */
        uint8_t n = hash_length - hkdf->offset_in_block;
        if( n > output_length )
            n = (uint8_t) output_length;
        memcpy( output, hkdf->output_block + hkdf->offset_in_block, n );
        output += n;
        output_length -= n;
        hkdf->offset_in_block += n;
        if( output_length == 0 )
            break;
        /* We can't be wanting more output after block 0xff, otherwise
         * the capacity check in psa_generator_read() would have
         * prevented this call. It could happen only if the generator
         * object was corrupted or if this function is called directly
         * inside the library. */
        if( hkdf->block_number == 0xff )
            return( PSA_ERROR_BAD_STATE );

        /* We need a new block */
        ++hkdf->block_number;
        hkdf->offset_in_block = 0;
        status = psa_hmac_setup_internal( &hkdf->hmac,
                                          hkdf->prk, hash_length,
                                          hash_alg );
        if( status != PSA_SUCCESS )
            return( status );
        if( hkdf->block_number != 1 )
        {
            status = psa_hash_update( &hkdf->hmac.hash_ctx,
                                      hkdf->output_block,
                                      hash_length );
            if( status != PSA_SUCCESS )
                return( status );
        }
        status = psa_hash_update( &hkdf->hmac.hash_ctx,
                                  hkdf->info,
                                  hkdf->info_length );
        if( status != PSA_SUCCESS )
            return( status );
        status = psa_hash_update( &hkdf->hmac.hash_ctx,
                                  &hkdf->block_number, 1 );
        if( status != PSA_SUCCESS )
            return( status );
        status = psa_hmac_finish_internal( &hkdf->hmac,
                                           hkdf->output_block,
                                           sizeof( hkdf->output_block ) );
        if( status != PSA_SUCCESS )
            return( status );
    }

    return( PSA_SUCCESS );
}
#endif /* MBEDTLS_MD_C */

psa_status_t psa_generator_read( psa_crypto_generator_t *generator,
                                 uint8_t *output,
                                 size_t output_length )
{
    psa_status_t status;

    if( output_length > generator->capacity )
    {
        generator->capacity = 0;
        /* Go through the error path to wipe all confidential data now
         * that the generator object is useless. */
        status = PSA_ERROR_INSUFFICIENT_CAPACITY;
        goto exit;
    }
    if( output_length == 0 &&
        generator->capacity == 0 && generator->alg == 0 )
    {
        /* Edge case: this is a blank or finished generator, and 0
         * bytes were requested. The right error in this case could
         * be either INSUFFICIENT_CAPACITY or BAD_STATE. Return
         * INSUFFICIENT_CAPACITY, which is right for a finished
         * generator, for consistency with the case when
         * output_length > 0. */
        return( PSA_ERROR_INSUFFICIENT_CAPACITY );
    }
    generator->capacity -= output_length;

#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HKDF( generator->alg ) )
    {
        psa_algorithm_t hash_alg = PSA_ALG_HKDF_GET_HASH( generator->alg );
        status = psa_generator_hkdf_read( &generator->ctx.hkdf, hash_alg,
                                          output, output_length );
    }
    else
#endif /* MBEDTLS_MD_C */
    {
        return( PSA_ERROR_BAD_STATE );
    }

exit:
    if( status != PSA_SUCCESS )
    {
        psa_generator_abort( generator );
        memset( output, '!', output_length );
    }
    return( status );
}

#if defined(MBEDTLS_DES_C)
static void psa_des_set_key_parity( uint8_t *data, size_t data_size )
{
    if( data_size >= 8 )
        mbedtls_des_key_set_parity( data );
    if( data_size >= 16 )
        mbedtls_des_key_set_parity( data + 8 );
    if( data_size >= 24 )
        mbedtls_des_key_set_parity( data + 16 );
}
#endif /* MBEDTLS_DES_C */

psa_status_t psa_generator_import_key( psa_key_slot_t key,
                                       psa_key_type_t type,
                                       size_t bits,
                                       psa_crypto_generator_t *generator )
{
    uint8_t *data = NULL;
    size_t bytes = PSA_BITS_TO_BYTES( bits );
    psa_status_t status;

    if( ! key_type_is_raw_bytes( type ) )
        return( PSA_ERROR_INVALID_ARGUMENT );
    if( bits % 8 != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );
    data = mbedtls_calloc( 1, bytes );
    if( data == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );

    status = psa_generator_read( generator, data, bytes );
    if( status != PSA_SUCCESS )
        goto exit;
#if defined(MBEDTLS_DES_C)
    if( type == PSA_KEY_TYPE_DES )
        psa_des_set_key_parity( data, bytes );
#endif /* MBEDTLS_DES_C */
    status = psa_import_key( key, type, data, bytes );

exit:
    mbedtls_free( data );
    return( status );
}



/****************************************************************/
/* Key derivation */
/****************************************************************/

/* Set up an HKDF-based generator. This is exactly the extract phase
 * of the HKDF algorithm. */
static psa_status_t psa_generator_hkdf_setup( psa_hkdf_generator_t *hkdf,
                                              key_slot_t *slot,
                                              psa_algorithm_t hash_alg,
                                              const uint8_t *salt,
                                              size_t salt_length,
                                              const uint8_t *label,
                                              size_t label_length )
{
    psa_status_t status;
    status = psa_hmac_setup_internal( &hkdf->hmac,
                                      salt, salt_length,
                                      PSA_ALG_HMAC_HASH( hash_alg ) );
    if( status != PSA_SUCCESS )
        return( status );
    status = psa_hash_update( &hkdf->hmac.hash_ctx,
                              slot->data.raw.data,
                              slot->data.raw.bytes );
    if( status != PSA_SUCCESS )
        return( status );
    status = psa_hmac_finish_internal( &hkdf->hmac,
                                       hkdf->prk,
                                       sizeof( hkdf->prk ) );
    if( status != PSA_SUCCESS )
        return( status );
    hkdf->offset_in_block = PSA_HASH_SIZE( hash_alg );
    hkdf->block_number = 0;
    hkdf->info_length = label_length;
    if( label_length != 0 )
    {
        hkdf->info = mbedtls_calloc( 1, label_length );
        if( hkdf->info == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        memcpy( hkdf->info, label, label_length );
    }
    return( PSA_SUCCESS );
}

psa_status_t psa_key_derivation( psa_crypto_generator_t *generator,
                                 psa_key_slot_t key,
                                 psa_algorithm_t alg,
                                 const uint8_t *salt,
                                 size_t salt_length,
                                 const uint8_t *label,
                                 size_t label_length,
                                 size_t capacity )
{
    key_slot_t *slot;
    psa_status_t status;

    if( generator->alg != 0 )
        return( PSA_ERROR_BAD_STATE );

    status = psa_get_key_from_slot( key, &slot, PSA_KEY_USAGE_DERIVE, alg );
    if( status != PSA_SUCCESS )
        return( status );
    if( slot->type != PSA_KEY_TYPE_DERIVE )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( ! PSA_ALG_IS_KEY_DERIVATION( alg ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

#if defined(MBEDTLS_MD_C)
    if( PSA_ALG_IS_HKDF( alg ) )
    {
        psa_algorithm_t hash_alg = PSA_ALG_HKDF_GET_HASH( alg );
        size_t hash_size = PSA_HASH_SIZE( hash_alg );
        if( hash_size == 0 )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( capacity > 255 * hash_size )
            return( PSA_ERROR_INVALID_ARGUMENT );
        status = psa_generator_hkdf_setup( &generator->ctx.hkdf,
                                           slot,
                                           hash_alg,
                                           salt, salt_length,
                                           label, label_length );
    }
    else
#endif
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }

    /* Set generator->alg even on failure so that abort knows what to do. */
    generator->alg = alg;
    if( status == PSA_SUCCESS )
        generator->capacity = capacity;
    else
        psa_generator_abort( generator );
    return( status );
}



/****************************************************************/
/* Random generation */
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
                               const void *extra,
                               size_t extra_size )
{
    key_slot_t *slot;
    psa_status_t status;

    if( extra == NULL && extra_size != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    status = psa_get_empty_key_slot( key, &slot );
    if( status != PSA_SUCCESS )
        return( status );

    if( key_type_is_raw_bytes( type ) )
    {
        status = prepare_raw_data_slot( type, bits, &slot->data.raw );
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
            psa_des_set_key_parity( slot->data.raw.data,
                                    slot->data.raw.bytes );
#endif /* MBEDTLS_DES_C */
    }
    else

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
    if ( type == PSA_KEY_TYPE_RSA_KEYPAIR )
    {
        mbedtls_rsa_context *rsa;
        int ret;
        int exponent = 65537;
        if( bits > PSA_VENDOR_RSA_MAX_KEY_BITS )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( extra != NULL )
        {
            const psa_generate_key_extra_rsa *p = extra;
            if( extra_size != sizeof( *p ) )
                return( PSA_ERROR_INVALID_ARGUMENT );
#if INT_MAX < 0xffffffff
            /* Check that the uint32_t value passed by the caller fits
             * in the range supported by this implementation. */
            if( p->e > INT_MAX )
                return( PSA_ERROR_NOT_SUPPORTED );
#endif
            exponent = p->e;
        }
        rsa = mbedtls_calloc( 1, sizeof( *rsa ) );
        if( rsa == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        mbedtls_rsa_init( rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE );
        ret = mbedtls_rsa_gen_key( rsa,
                                   mbedtls_ctr_drbg_random,
                                   &global_data.ctr_drbg,
                                   (unsigned int) bits,
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
        if( extra != NULL )
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
    psa_key_slot_t key;
    for( key = 1; key <= PSA_KEY_SLOT_COUNT; key++ )
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
