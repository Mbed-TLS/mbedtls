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

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"


/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n )
{
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/****************************************************************/
/* Global data, support functions and library management */
/****************************************************************/

/* Number of key slots (plus one because 0 is not used).
 * The value is a compile-time constant for now, for simplicity. */
#define MBEDTLS_PSA_KEY_SLOT_COUNT 32

typedef struct {
    psa_key_type_t type;
    union {
        struct raw_data {
            uint8_t *data;
            size_t bytes;
        } raw;
#if defined(MBEDTLS_PK_C)
        mbedtls_pk_context pk;
#endif /* MBEDTLS_PK_C */
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
    switch( ret )
    {
        case 0:
            return( PSA_SUCCESS );
        case MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED:
        case MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE:
        case MBEDTLS_ERR_ENTROPY_SOURCE_FAILED:
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );
        case MBEDTLS_ERR_PK_ALLOC_FAILED:
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        case MBEDTLS_ERR_PK_TYPE_MISMATCH:
        case MBEDTLS_ERR_PK_BAD_INPUT_DATA:
            return( PSA_ERROR_INVALID_ARGUMENT );
        case MBEDTLS_ERR_PK_FILE_IO_ERROR:
            return( PSA_ERROR_TAMPERING_DETECTED );
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

    if( type == PSA_KEY_TYPE_RAW_DATA )
    {
        if( data_length > SIZE_MAX / 8 )
            return( PSA_ERROR_NOT_SUPPORTED );
        slot->data.raw.data = mbedtls_calloc( 1, data_length );
        if( slot->data.raw.data == NULL )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
        memcpy( slot->data.raw.data, data, data_length );
        slot->data.raw.bytes = data_length;
    }
    else
#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_PK_PARSE_C)
    if( type == PSA_KEY_TYPE_RSA || PSA_KEY_TYPE_IS_ECC( type ) )
    {
        int ret;
        mbedtls_pk_init( &slot->data.pk );
        ret = mbedtls_pk_parse_key( &slot->data.pk,
                                    data, data_length,
                                    NULL, 0 );
        if( ret != 0 )
            return( mbedtls_to_psa_error( ret ) );
    }
    else
#endif /* defined(MBEDTLS_PK_C) && defined(MBEDTLS_PK_PARSE_C) */
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

    if( slot->type == PSA_KEY_TYPE_RAW_DATA )
    {
        mbedtls_free( slot->data.raw.data );
    }
    else
#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_PK_PARSE_C)
    if( slot->type == PSA_KEY_TYPE_RSA ||
        PSA_KEY_TYPE_IS_ECC( slot->type ) )
    {
        mbedtls_pk_free( &slot->data.pk );
    }
    else
#endif /* defined(MBEDTLS_PK_C) && defined(MBEDTLS_PK_PARSE_C) */
    {
        /* Shouldn't happen: the key type is not any type that we
         * put it. */
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
        return( PSA_ERROR_INVALID_ARGUMENT );
    slot = &global_data.key_slots[key];
    if( type != NULL )
        *type = slot->type;
    if( bits != NULL )
        *bits = 0;
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );

    if( slot->type == PSA_KEY_TYPE_RAW_DATA )
    {
        if( bits != NULL )
            *bits = slot->data.raw.bytes * 8;
    }
    else
#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_PK_PARSE_C)
    if( slot->type == PSA_KEY_TYPE_RSA ||
        PSA_KEY_TYPE_IS_ECC( slot->type ) )
    {
        if( bits != NULL )
            *bits = mbedtls_pk_get_bitlen( &slot->data.pk );
    }
    else
#endif /* defined(MBEDTLS_PK_C) && defined(MBEDTLS_PK_PARSE_C) */
    {
        /* Shouldn't happen: the key type is not any type that we
         * put it. */
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
        return( PSA_ERROR_INVALID_ARGUMENT );
    slot = &global_data.key_slots[key];
    if( slot->type == PSA_KEY_TYPE_NONE )
        return( PSA_ERROR_EMPTY_SLOT );

    if( slot->type == PSA_KEY_TYPE_RAW_DATA )
    {
        if( slot->data.raw.bytes > data_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( data, slot->data.raw.data, slot->data.raw.bytes );
        *data_length = slot->data.raw.bytes;
        return( PSA_SUCCESS );
    }
    else
#if defined(MBEDTLS_PK_C) && defined(MBEDTLS_PK_PARSE_C)
    if( slot->type == PSA_KEY_TYPE_RSA ||
        PSA_KEY_TYPE_IS_ECC( slot->type ) )
    {
        int ret;
        ret = mbedtls_pk_write_key_der( &slot->data.pk,
                                        data, data_size );
        if( ret < 0 )
            return( mbedtls_to_psa_error( ret ) );
        *data_length = ret;
        return( PSA_SUCCESS );
    }
    else
#endif /* defined(MBEDTLS_PK_C) && defined(MBEDTLS_PK_PARSE_C) */
    {
        return( PSA_ERROR_NOT_SUPPORTED );
    }
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

exit:
    if( ret != 0 )
        mbedtls_psa_crypto_free( );
    return( mbedtls_to_psa_error( ret ) );
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
