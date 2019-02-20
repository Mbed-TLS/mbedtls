/*
 *  PSA persistent key storage
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

#if defined(MBEDTLS_CONFIG_FILE)
#include MBEDTLS_CONFIG_FILE
#else
#include "mbedtls/config.h"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)

#include <stdlib.h>
#include <string.h>

#include "psa_crypto_service_integration.h"
#include "psa/crypto.h"
#include "psa_crypto_storage.h"
#include "psa_crypto_storage_backend.h"
#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc   calloc
#define mbedtls_free     free
#endif

/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                                    \
{                                                               \
    (b)[(i)    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
    (b)[(i) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
    (b)[(i) + 2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );    \
    (b)[(i) + 3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );    \
}
#endif

/**
 * Persistent key storage magic header.
 */
#define PSA_KEY_STORAGE_MAGIC_HEADER "PSA\0KEY"
#define PSA_KEY_STORAGE_MAGIC_HEADER_LENGTH ( sizeof( PSA_KEY_STORAGE_MAGIC_HEADER ) )

typedef struct {
    uint8_t magic[PSA_KEY_STORAGE_MAGIC_HEADER_LENGTH];
    uint8_t version[4];
    uint8_t type[sizeof( psa_key_type_t )];
    uint8_t policy[sizeof( psa_key_policy_t )];
    uint8_t data_len[4];
    uint8_t key_data[];
} psa_persistent_key_storage_format;

void psa_format_key_data_for_storage( const uint8_t *data,
                                      const size_t data_length,
                                      const psa_key_type_t type,
                                      const psa_key_policy_t *policy,
                                      uint8_t *storage_data )
{
    psa_persistent_key_storage_format *storage_format =
        (psa_persistent_key_storage_format *) storage_data;

    memcpy( storage_format->magic, PSA_KEY_STORAGE_MAGIC_HEADER, PSA_KEY_STORAGE_MAGIC_HEADER_LENGTH );
    PUT_UINT32_LE(0, storage_format->version, 0);
    PUT_UINT32_LE(type, storage_format->type, 0);
    PUT_UINT32_LE(policy->usage, storage_format->policy, 0);
    PUT_UINT32_LE(policy->alg, storage_format->policy, sizeof( uint32_t ));
    PUT_UINT32_LE(data_length, storage_format->data_len, 0);
    memcpy( storage_format->key_data, data, data_length );
}

static psa_status_t check_magic_header( const uint8_t *data )
{
    if( memcmp( data, PSA_KEY_STORAGE_MAGIC_HEADER,
                PSA_KEY_STORAGE_MAGIC_HEADER_LENGTH ) != 0 )
        return( PSA_ERROR_STORAGE_FAILURE );
    return( PSA_SUCCESS );
}

psa_status_t psa_parse_key_data_from_storage( const uint8_t *storage_data,
                                              size_t storage_data_length,
                                              uint8_t **key_data,
                                              size_t *key_data_length,
                                              psa_key_type_t *type,
                                              psa_key_policy_t *policy )
{
    psa_status_t status;
    const psa_persistent_key_storage_format *storage_format =
        (const psa_persistent_key_storage_format *)storage_data;
    uint32_t version;

    if( storage_data_length < sizeof(*storage_format) )
        return( PSA_ERROR_STORAGE_FAILURE );

    status = check_magic_header( storage_data );
    if( status != PSA_SUCCESS )
        return( status );

    GET_UINT32_LE(version, storage_format->version, 0);
    if( version != 0 )
        return( PSA_ERROR_STORAGE_FAILURE );

    GET_UINT32_LE(*key_data_length, storage_format->data_len, 0);
    if( *key_data_length > ( storage_data_length - sizeof(*storage_format) ) ||
        *key_data_length > PSA_CRYPTO_MAX_STORAGE_SIZE )
        return( PSA_ERROR_STORAGE_FAILURE );

    *key_data = mbedtls_calloc( 1, *key_data_length );
    if( *key_data == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );

    GET_UINT32_LE(*type, storage_format->type, 0);
    GET_UINT32_LE(policy->usage, storage_format->policy, 0);
    GET_UINT32_LE(policy->alg, storage_format->policy, sizeof( uint32_t ));

    memcpy( *key_data, storage_format->key_data, *key_data_length );

    return( PSA_SUCCESS );
}

psa_status_t psa_save_persistent_key( const psa_key_file_id_t key,
                                      const psa_key_type_t type,
                                      const psa_key_policy_t *policy,
                                      const uint8_t *data,
                                      const size_t data_length )
{
    size_t storage_data_length;
    uint8_t *storage_data;
    psa_status_t status;

    if( data_length > PSA_CRYPTO_MAX_STORAGE_SIZE )
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    storage_data_length = data_length + sizeof( psa_persistent_key_storage_format );

    storage_data = mbedtls_calloc( 1, storage_data_length );
    if( storage_data == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );

    psa_format_key_data_for_storage( data, data_length, type, policy,
                                     storage_data );

    status = psa_crypto_storage_store( key,
                                       storage_data, storage_data_length );

    mbedtls_free( storage_data );

    return( status );
}

void psa_free_persistent_key_data( uint8_t *key_data, size_t key_data_length )
{
    if( key_data != NULL )
    {
        mbedtls_platform_zeroize( key_data, key_data_length );
    }
    mbedtls_free( key_data );
}

psa_status_t psa_load_persistent_key( psa_key_file_id_t key,
                                      psa_key_type_t *type,
                                      psa_key_policy_t *policy,
                                      uint8_t **data,
                                      size_t *data_length )
{
    psa_status_t status = PSA_SUCCESS;
    uint8_t *loaded_data;
    size_t storage_data_length = 0;

    status = psa_crypto_storage_get_data_length( key, &storage_data_length );
    if( status != PSA_SUCCESS )
        return( status );

    loaded_data = mbedtls_calloc( 1, storage_data_length );

    if( loaded_data == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );

    status = psa_crypto_storage_load( key, loaded_data, storage_data_length );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_parse_key_data_from_storage( loaded_data, storage_data_length,
                                              data, data_length, type, policy );

exit:
    mbedtls_free( loaded_data );
    return( status );
}

#endif /* MBEDTLS_PSA_CRYPTO_STORAGE_C */
