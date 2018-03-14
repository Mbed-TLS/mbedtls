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
#define MBEDTLS_PSA_KEY_SLOT_COUNT 32

typedef struct {
    psa_key_type_t type;
    psa_key_policy_t policy;
    psa_key_lifetime_t lifetime;
    union {
        struct raw_data {
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

typedef struct {
    int initialized;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    key_slot_t key_slots[MBEDTLS_PSA_KEY_SLOT_COUNT];
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

        default:
            return( PSA_ERROR_UNKNOWN_ERROR );
    }
}



/****************************************************************/
/* Key management */
/****************************************************************/

psa_status_t psa_import_key(psa_key_slot_t key,
                            psa_key_type_t type,
                            const uint8_t *data,
                            size_t data_length)
{
    key_slot_t *slot;

    if( key == 0 || key > MBEDTLS_PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_INVALID_ARGUMENT );
    slot = &global_data.key_slots[key];
    if( slot->type != PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_OCCUPIED_SLOT );

    if( PSA_KEY_TYPE_IS_RAW_BYTES( type ) )
    {
        /* Ensure that a bytes-to-bit conversion won't overflow. */
        if( data_length > SIZE_MAX / 8 )
            return( PSA_ERROR_NOT_SUPPORTED );
        slot->data.raw.data = mbedtls_calloc( 1, data_length );
        if( slot->data.raw.data == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        memcpy( slot->data.raw.data, data, data_length );
        slot->data.raw.bytes = data_length;
    }
    else
#if defined(MBEDTLS_PK_PARSE_C)
    if( type == PSA_KEY_TYPE_RSA_PUBLIC_KEY ||
        type == PSA_KEY_TYPE_RSA_KEYPAIR ||
        PSA_KEY_TYPE_IS_ECC( type ) )
    {
        int ret;
        mbedtls_pk_context pk;
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
                    slot->data.rsa = pk.pk_ctx;
                else
                    return( PSA_ERROR_INVALID_ARGUMENT );
                break;
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
            case MBEDTLS_PK_ECKEY:
                if( PSA_KEY_TYPE_IS_ECC( type ) )
                {
                    // TODO: check curve
                    slot->data.ecp = pk.pk_ctx;
                }
                else
                    return( PSA_ERROR_INVALID_ARGUMENT );
                break;
#endif /* MBEDTLS_ECP_C */
            default:
                return( PSA_ERROR_INVALID_ARGUMENT );
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

psa_status_t psa_destroy_key(psa_key_slot_t key)
{
    key_slot_t *slot;

    if( key == 0 || key > MBEDTLS_PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_INVALID_ARGUMENT );
    slot = &global_data.key_slots[key];
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );

    if( PSA_KEY_TYPE_IS_RAW_BYTES( slot->type ) )
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

psa_status_t psa_get_key_information(psa_key_slot_t key,
                                     psa_key_type_t *type,
                                     size_t *bits)
{
    key_slot_t *slot;

    if( key == 0 || key > MBEDTLS_PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_EMPTY_SLOT );
    slot = &global_data.key_slots[key];
    if( type != NULL )
        *type = slot->type;
    if( bits != NULL )
        *bits = 0;
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );

    if( PSA_KEY_TYPE_IS_RAW_BYTES( slot->type ) )
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

psa_status_t psa_export_key(psa_key_slot_t key,
                            uint8_t *data,
                            size_t data_size,
                            size_t *data_length)
{
    key_slot_t *slot;

    if( key == 0 || key > MBEDTLS_PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_EMPTY_SLOT );
    slot = &global_data.key_slots[key];
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );

    if( !( slot->policy.usage & PSA_KEY_USAGE_EXPORT ) )
        return( PSA_ERROR_NOT_PERMITTED );

    if( PSA_KEY_TYPE_IS_RAW_BYTES( slot->type ) )
    {
        if( slot->data.raw.bytes > data_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( data, slot->data.raw.data, slot->data.raw.bytes );
        *data_length = slot->data.raw.bytes;
        return( PSA_SUCCESS );
    }
    else
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
        if( PSA_KEY_TYPE_IS_KEYPAIR( slot->type ) )
            ret = mbedtls_pk_write_key_der( &pk, data, data_size );
        else
            ret = mbedtls_pk_write_pubkey_der( &pk, data, data_size );
        if( ret < 0 )
            return( mbedtls_to_psa_error( ret ) );
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

#if 0
static psa_algorithm_t mbedtls_md_alg_to_psa( mbedtls_md_type_t md_alg )
{
    switch( md_alg )
    {
        case MBEDTLS_MD_NONE:
            return( 0 );
        case MBEDTLS_MD_MD2:
            return( PSA_ALG_MD2 );
        case MBEDTLS_MD_MD4:
            return( PSA_ALG_MD4 );
        case MBEDTLS_MD_MD5:
            return( PSA_ALG_MD5 );
        case MBEDTLS_MD_SHA1:
            return( PSA_ALG_SHA_1 );
        case MBEDTLS_MD_SHA224:
            return( PSA_ALG_SHA_224 );
        case MBEDTLS_MD_SHA256:
            return( PSA_ALG_SHA_256 );
        case MBEDTLS_MD_SHA384:
            return( PSA_ALG_SHA_384 );
        case MBEDTLS_MD_SHA512:
            return( PSA_ALG_SHA_512 );
        case MBEDTLS_MD_RIPEMD160:
            return( PSA_ALG_RIPEMD160 );
        default:
            return( 0 );
    }
}
#endif

psa_status_t psa_hash_abort( psa_hash_operation_t *operation )
{
    switch( operation->alg )
    {
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
            return( PSA_ERROR_NOT_SUPPORTED );
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
            return( PSA_ERROR_NOT_SUPPORTED );
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
    size_t actual_hash_length = PSA_HASH_FINAL_SIZE( operation->alg );

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

psa_status_t psa_hash_verify(psa_hash_operation_t *operation,
                             const uint8_t *hash,
                             size_t hash_length)
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
    size_t key_bits )
{
    mbedtls_cipher_id_t cipher_id;
    mbedtls_cipher_mode_t mode;

    if( PSA_ALG_IS_CIPHER( alg ) || PSA_ALG_IS_AEAD( alg ) )
    {
        switch( alg )
        {
            case PSA_ALG_STREAM_CIPHER:
                mode = MBEDTLS_MODE_STREAM;
                break;
            case PSA_ALG_ECB_BASE:
                mode = MBEDTLS_MODE_ECB;
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
            cipher_id = MBEDTLS_CIPHER_ID_AES;
            break;
        case PSA_KEY_TYPE_DES:
            if( key_bits == 64 )
                cipher_id = MBEDTLS_CIPHER_ID_DES;
            else
                cipher_id = MBEDTLS_CIPHER_ID_3DES;
            break;
        case PSA_KEY_TYPE_CAMELLIA:
            cipher_id = MBEDTLS_CIPHER_ID_CAMELLIA;
            break;
        case PSA_KEY_TYPE_ARC4:
            cipher_id = MBEDTLS_CIPHER_ID_ARC4;
            break;
        default:
            return( NULL );
    }

    return( mbedtls_cipher_info_from_values( cipher_id, key_bits, mode ) );
}

psa_status_t psa_mac_abort( psa_mac_operation_t *operation )
{
    switch( operation->alg )
    {
#if defined(MBEDTLS_CMAC_C)
        case PSA_ALG_CMAC:
            mbedtls_cipher_free( &operation->ctx.cmac );
            break;
#endif /* MBEDTLS_CMAC_C */
        default:
#if defined(MBEDTLS_MD_C)
            if( PSA_ALG_IS_HMAC( operation->alg ) )
                mbedtls_md_free( &operation->ctx.hmac );
            else
#endif /* MBEDTLS_MD_C */
                return( PSA_ERROR_NOT_SUPPORTED );
    }
    operation->alg = 0;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_required = 0;
    operation->has_input = 0;
    return( PSA_SUCCESS );
}

psa_status_t psa_mac_start( psa_mac_operation_t *operation,
                            psa_key_slot_t key,
                            psa_algorithm_t alg )
{
    int ret = MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
    psa_status_t status;
    key_slot_t *slot;
    psa_key_type_t key_type;
    size_t key_bits;
    const mbedtls_cipher_info_t *cipher_info = NULL;

    operation->alg = 0;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->iv_required = 1;
    operation->has_input = 0;

    status = psa_get_key_information( key, &key_type, &key_bits );
    if( status != PSA_SUCCESS )
        return( status );
    slot = &global_data.key_slots[key];

    if ( ( slot->policy.usage & PSA_KEY_USAGE_SIGN ) != 0 )
        operation->key_usage_sign = 1;

    if ( ( slot->policy.usage & PSA_KEY_USAGE_VERIFY ) != 0 )
        operation->key_usage_verify = 1;

    if( ! PSA_ALG_IS_HMAC( alg ) )
    {
        cipher_info = mbedtls_cipher_info_from_psa( alg, key_type, key_bits );
        if( cipher_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        operation->mac_size = cipher_info->block_size;
    }
    switch( alg )
    {
#if defined(MBEDTLS_CMAC_C)
        case PSA_ALG_CMAC:
            operation->iv_required = 0;
            mbedtls_cipher_init( &operation->ctx.cmac );
            ret = mbedtls_cipher_setup( &operation->ctx.cmac, cipher_info );
            if( ret != 0 )
                break;
            ret = mbedtls_cipher_cmac_starts( &operation->ctx.cmac,
                                              slot->data.raw.data,
                                              key_bits );
            break;
#endif /* MBEDTLS_CMAC_C */
        default:
#if defined(MBEDTLS_MD_C)
            if( PSA_ALG_IS_HMAC( alg ) )
            {
                const mbedtls_md_info_t *md_info =
                    mbedtls_md_info_from_psa( PSA_ALG_HMAC_HASH( alg ) );
                if( md_info == NULL )
                    return( PSA_ERROR_NOT_SUPPORTED );
                if( key_type != PSA_KEY_TYPE_HMAC )
                    return( PSA_ERROR_INVALID_ARGUMENT );
                operation->iv_required = 0;
                operation->mac_size = mbedtls_md_get_size( md_info );
                mbedtls_md_init( &operation->ctx.hmac );
                ret = mbedtls_md_setup( &operation->ctx.hmac, md_info, 1 );
                if( ret != 0 )
                    break;
                ret = mbedtls_md_hmac_starts( &operation->ctx.hmac,
                                              slot->data.raw.data,
                                              slot->data.raw.bytes );
                break;
            }
            else
#endif /* MBEDTLS_MD_C */
                return( PSA_ERROR_NOT_SUPPORTED );
    }

    /* If we reach this point, then the algorithm-specific part of the
     * context has at least been initialized, and may contain data that
     * needs to be wiped on error. */
    operation->alg = alg;
    if( ret != 0 )
    {
        psa_mac_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }
    operation->key_set = 1;
    return( PSA_SUCCESS );
}

psa_status_t psa_mac_update( psa_mac_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length )
{
    int ret;
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
                ret = mbedtls_md_hmac_update( &operation->ctx.hmac,
                                              input, input_length );
            }
            else
#endif /* MBEDTLS_MD_C */
            {
                ret = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
            }
            break;
    }
    if( ret != 0 )
        psa_mac_abort( operation );
    return( mbedtls_to_psa_error( ret ) );
}

static psa_status_t psa_mac_finish_internal( psa_mac_operation_t *operation,
                             uint8_t *mac,
                             size_t mac_size,
                             size_t *mac_length )
{
    int ret;
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
                ret = mbedtls_md_hmac_finish( &operation->ctx.hmac, mac );
            }
            else
#endif /* MBEDTLS_MD_C */
            {
                ret = MBEDTLS_ERR_MD_BAD_INPUT_DATA;
            }
            break;
    }

    if( ret == 0 )
    {
        return( psa_mac_abort( operation ) );
    }
    else
    {
        psa_mac_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }
}

psa_status_t psa_mac_finish( psa_mac_operation_t *operation,
                             uint8_t *mac,
                             size_t mac_size,
                             size_t *mac_length )
{
    if( !( operation->key_usage_sign ) )
        return( PSA_ERROR_NOT_PERMITTED );

    return( psa_mac_finish_internal(operation, mac, mac_size, mac_length ) );
}

#define MBEDTLS_PSA_MAC_MAX_SIZE                       \
    ( MBEDTLS_MD_MAX_SIZE > MBEDTLS_MAX_BLOCK_LENGTH ? \
      MBEDTLS_MD_MAX_SIZE :                            \
      MBEDTLS_MAX_BLOCK_LENGTH )
psa_status_t psa_mac_verify( psa_mac_operation_t *operation,
                             const uint8_t *mac,
                             size_t mac_length )
{
    uint8_t actual_mac[MBEDTLS_PSA_MAC_MAX_SIZE];
    size_t actual_mac_length;
    psa_status_t status;

    if( !( operation->key_usage_verify ) )
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

psa_status_t psa_asymmetric_sign(psa_key_slot_t key,
                                 psa_algorithm_t alg,
                                 const uint8_t *hash,
                                 size_t hash_length,
                                 const uint8_t *salt,
                                 size_t salt_length,
                                 uint8_t *signature,
                                 size_t signature_size,
                                 size_t *signature_length)
{
    key_slot_t *slot;

    *signature_length = 0;
    (void) salt;
    (void) salt_length;

    if( key == 0 || key > MBEDTLS_PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_EMPTY_SLOT );
    slot = &global_data.key_slots[key];
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );
    if( ! PSA_KEY_TYPE_IS_KEYPAIR( slot->type ) )
        return( PSA_ERROR_INVALID_ARGUMENT );
    if( !( slot->policy.usage & PSA_KEY_USAGE_SIGN ) )
        return( PSA_ERROR_NOT_PERMITTED );

#if defined(MBEDTLS_RSA_C)
    if( slot->type == PSA_KEY_TYPE_RSA_KEYPAIR )
    {
        mbedtls_rsa_context *rsa = slot->data.rsa;
        int ret;
        psa_algorithm_t hash_alg = PSA_ALG_RSA_GET_HASH( alg );
        const mbedtls_md_info_t *md_info = mbedtls_md_info_from_psa( hash_alg );
        mbedtls_md_type_t md_alg =
            hash_alg == 0 ? MBEDTLS_MD_NONE : mbedtls_md_get_type( md_info );
        if( md_alg == MBEDTLS_MD_NONE )
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
        // TODO
        return( PSA_ERROR_NOT_SUPPORTED );
    }
    else
#endif /* defined(MBEDTLS_ECP_C) */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}


/****************************************************************/
/* Symmetric cryptography */
/****************************************************************/

psa_status_t psa_decrypt_setup(psa_cipher_operation_t *operation,
                               psa_key_slot_t key,
                               psa_algorithm_t alg)
{
    int ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    psa_status_t status;
    key_slot_t *slot;
    psa_key_type_t key_type;
    size_t key_bits;
    const mbedtls_cipher_info_t *cipher_info = NULL;

    operation->alg = 0;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->block_size = 0;
    operation->iv_size = 0;

    status = psa_get_key_information( key, &key_type, &key_bits );
    if( status != PSA_SUCCESS )
        return( status );
    slot = &global_data.key_slots[key];

    cipher_info = mbedtls_cipher_info_from_psa( alg, key_type, key_bits );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    operation->block_size = cipher_info->block_size;

    mbedtls_cipher_init( &operation->ctx.cipher );
    ret = mbedtls_cipher_setup( &operation->ctx.cipher, cipher_info );
    if (ret != 0)
    {
        psa_cipher_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }

    ret = mbedtls_cipher_setkey( &operation->ctx.cipher, slot->data.raw.data,
                   key_bits, MBEDTLS_DECRYPT );
    if (ret != 0)
    {
        psa_cipher_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }

    operation->key_set = 1;
    operation->alg = alg;

    return ( PSA_SUCCESS );
}

psa_status_t psa_encrypt_generate_iv(unsigned char *iv,
                                     size_t iv_size,
                                     size_t *iv_length)
{
    int ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    
    ret = mbedtls_ctr_drbg_random( &global_data.ctr_drbg, iv, iv_size);
    if (ret != 0)
    {
        return( mbedtls_to_psa_error( ret ) );       
    }
    
    *iv_length = iv_size;
    return ( PSA_SUCCESS );
}

psa_status_t psa_encrypt_set_iv(psa_cipher_operation_t *operation,
                                const unsigned char *iv,
                                size_t iv_length)
{
    int ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;

    ret =  mbedtls_cipher_set_iv( &operation->ctx.cipher, iv, iv_length );
    if (ret != 0)
    {
        psa_cipher_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }

    operation->iv_set = 1;
    operation->iv_size = iv_length;

    return ( PSA_SUCCESS );
}

psa_status_t psa_cipher_update(psa_cipher_operation_t *operation,
                               const uint8_t *input,
                               size_t input_length,
                               unsigned char *output, 
                               size_t output_size, 
                               size_t *output_length)
{
    int ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;

    if ( output_size < input_length )
        return ( PSA_ERROR_BUFFER_TOO_SMALL );

    ret = mbedtls_cipher_update( &operation->ctx.cipher, input,
                   input_length, output, output_length );
    if (ret != 0)
    {
        psa_cipher_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }

    return ( PSA_SUCCESS );
}

psa_status_t psa_cipher_finish(psa_cipher_operation_t *operation,
                               uint8_t *output,
                               size_t output_size,
                               size_t *output_length)
{
    int ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;

    if ( output_size < operation->block_size )
        return ( PSA_ERROR_BUFFER_TOO_SMALL );
    
    if( ! operation->key_set )
        return( PSA_ERROR_BAD_STATE );
    if( ! operation->iv_set )
        return( PSA_ERROR_BAD_STATE );

    ret = mbedtls_cipher_finish( &operation->ctx.cipher, output, 
                                output_length );
    if (ret != 0)
    {
        psa_cipher_abort( operation );
        return( mbedtls_to_psa_error( ret ) );
    }

    return ( PSA_SUCCESS );
}

psa_status_t psa_cipher_abort(psa_cipher_operation_t *operation)
{   
    mbedtls_cipher_free( &operation->ctx.cipher );
    
    operation->alg = 0;
    operation->key_set = 0;
    operation->iv_set = 0;
    operation->block_size = 0;
    operation->iv_size = 0;
    
    return ( PSA_SUCCESS );
}


/****************************************************************/
/* Key Policy */
/****************************************************************/

void psa_key_policy_init(psa_key_policy_t *policy)
{
    memset( policy, 0, sizeof( psa_key_policy_t ) );
}

void psa_key_policy_set_usage(psa_key_policy_t *policy,
                              psa_key_usage_t usage,
                              psa_algorithm_t alg)
{
    policy->usage = usage;
    policy->alg = alg;
}

psa_key_usage_t psa_key_policy_get_usage(psa_key_policy_t *policy)
{
    return( policy->usage );
}

psa_algorithm_t psa_key_policy_get_algorithm(psa_key_policy_t *policy)
{
    return( policy->alg );
}

psa_status_t psa_set_key_policy(psa_key_slot_t key,
                                const psa_key_policy_t *policy)
{
    key_slot_t *slot;

    if( key == 0 || key > MBEDTLS_PSA_KEY_SLOT_COUNT || policy == NULL )
        return( PSA_ERROR_INVALID_ARGUMENT );
    
    slot = &global_data.key_slots[key];
    if( slot->type != PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_OCCUPIED_SLOT );

    if( ( policy->usage & ~( PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT 
                        | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_SIGN 
                        | PSA_KEY_USAGE_VERIFY ) ) != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    slot->policy = *policy;

    return( PSA_SUCCESS );
}

psa_status_t psa_get_key_policy(psa_key_slot_t key,
                                psa_key_policy_t *policy)
{
    key_slot_t *slot;

    if( key == 0 || key > MBEDTLS_PSA_KEY_SLOT_COUNT || policy == NULL )
        return( PSA_ERROR_INVALID_ARGUMENT );

    slot = &global_data.key_slots[key];
    
    *policy = slot->policy;

    return( PSA_SUCCESS );
}



/****************************************************************/
/* Key Lifetime */
/****************************************************************/

psa_status_t psa_get_key_lifetime(psa_key_slot_t key,
                                  psa_key_lifetime_t *lifetime)
{
    key_slot_t *slot;

    if( key == 0 || key > MBEDTLS_PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_INVALID_ARGUMENT );

    slot = &global_data.key_slots[key];
    
    *lifetime = slot->lifetime;

    return( PSA_SUCCESS );
}

psa_status_t psa_set_key_lifetime(psa_key_slot_t key,
                                  const psa_key_lifetime_t lifetime)
{
    key_slot_t *slot;

    if( key == 0 || key > MBEDTLS_PSA_KEY_SLOT_COUNT )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( lifetime != PSA_KEY_LIFETIME_VOLATILE && 
        lifetime != PSA_KEY_LIFETIME_PERSISTENT && 
        lifetime != PSA_KEY_LIFETIME_WRITE_ONCE)
        return( PSA_ERROR_INVALID_ARGUMENT );

    slot = &global_data.key_slots[key];
    if( slot->type != PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_OCCUPIED_SLOT );

    if ( lifetime != PSA_KEY_LIFETIME_VOLATILE )
        return( PSA_ERROR_NOT_SUPPORTED );
        
    slot->lifetime = lifetime;

    return( PSA_SUCCESS );
}



/****************************************************************/
/* Module setup */
/****************************************************************/

void mbedtls_psa_crypto_free( void )
{
    size_t key;
    for( key = 1; key < MBEDTLS_PSA_KEY_SLOT_COUNT; key++ )
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
