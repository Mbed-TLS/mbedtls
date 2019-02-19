/*
 *  PSA file storage backend for persistent keys
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

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_FILE_C)

#include <string.h>

#include "psa/crypto.h"
#include "psa_crypto_storage_backend.h"
#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_snprintf snprintf
#endif

/* This option sets where files are to be stored. If this is left unset,
 * the files by default will be stored in the same location as the program,
 * which may not be desired or possible. */
#if !defined(CRYPTO_STORAGE_FILE_LOCATION)
#define CRYPTO_STORAGE_FILE_LOCATION ""
#endif

enum { MAX_LOCATION_LEN = sizeof(CRYPTO_STORAGE_FILE_LOCATION) + 40 };

static void key_id_to_location( const psa_key_file_id_t key,
                                char *location,
                                size_t location_size )
{
    mbedtls_snprintf( location, location_size,
                      CRYPTO_STORAGE_FILE_LOCATION "psa_key_slot_%lu",
                      (unsigned long) key );
}

psa_status_t psa_crypto_storage_load( const psa_key_file_id_t key, uint8_t *data,
                                      size_t data_size )
{
    psa_status_t status = PSA_SUCCESS;
    FILE *file;
    size_t num_read;
    char slot_location[MAX_LOCATION_LEN];

    key_id_to_location( key, slot_location, MAX_LOCATION_LEN );
    file = fopen( slot_location, "rb" );
    if( file == NULL )
    {
        status = PSA_ERROR_STORAGE_FAILURE;
        goto exit;
    }
    num_read = fread( data, 1, data_size, file );
    if( num_read != data_size )
        status = PSA_ERROR_STORAGE_FAILURE;

exit:
    if( file != NULL )
        fclose( file );
    return( status );
}

int psa_is_key_present_in_storage( const psa_key_file_id_t key )
{
    char slot_location[MAX_LOCATION_LEN];
    FILE *file;

    key_id_to_location( key, slot_location, MAX_LOCATION_LEN );

    file = fopen( slot_location, "r" );
    if( file == NULL )
    {
        /* File doesn't exist */
        return( 0 );
    }

    fclose( file );
    return( 1 );
}

psa_status_t psa_crypto_storage_store( const psa_key_file_id_t key,
                                       const uint8_t *data,
                                       size_t data_length )
{
    psa_status_t status = PSA_SUCCESS;
    int ret;
    size_t num_written;
    char slot_location[MAX_LOCATION_LEN];
    FILE *file;
    /* The storage location corresponding to "key slot 0" is used as a
     * temporary location in order to make the apparition of the actual slot
     * file atomic. 0 is not a valid key slot number, so this should not
     * affect actual keys. */
    const char *temp_location = CRYPTO_STORAGE_FILE_LOCATION "psa_key_slot_0";

    key_id_to_location( key, slot_location, MAX_LOCATION_LEN );

    if( psa_is_key_present_in_storage( key ) == 1 )
        return( PSA_ERROR_ALREADY_EXISTS );

    file = fopen( temp_location, "wb" );
    if( file == NULL )
    {
        status = PSA_ERROR_STORAGE_FAILURE;
        goto exit;
    }

    num_written = fwrite( data, 1, data_length, file );
    if( num_written != data_length )
    {
        status = PSA_ERROR_STORAGE_FAILURE;
        goto exit;
    }

    ret = fclose( file );
    file = NULL;
    if( ret != 0 )
    {
        status = PSA_ERROR_STORAGE_FAILURE;
        goto exit;
    }

    if( rename( temp_location, slot_location ) != 0 )
    {
        status = PSA_ERROR_STORAGE_FAILURE;
        goto exit;
    }

exit:
    if( file != NULL )
        fclose( file );
    remove( temp_location );
    return( status );
}

psa_status_t psa_destroy_persistent_key( const psa_key_file_id_t key )
{
    FILE *file;
    char slot_location[MAX_LOCATION_LEN];

    key_id_to_location( key, slot_location, MAX_LOCATION_LEN );

    /* Only try remove the file if it exists */
    file = fopen( slot_location, "rb" );
    if( file != NULL )
    {
        fclose( file );

        if( remove( slot_location ) != 0 )
            return( PSA_ERROR_STORAGE_FAILURE );
    }
    return( PSA_SUCCESS );
}

psa_status_t psa_crypto_storage_get_data_length( const psa_key_file_id_t key,
                                                 size_t *data_length )
{
    psa_status_t status = PSA_SUCCESS;
    FILE *file;
    long file_size;
    char slot_location[MAX_LOCATION_LEN];

    key_id_to_location( key, slot_location, MAX_LOCATION_LEN );

    file = fopen( slot_location, "rb" );
    if( file == NULL )
        return( PSA_ERROR_DOES_NOT_EXIST );

    if( fseek( file, 0, SEEK_END ) != 0 )
    {
        status = PSA_ERROR_STORAGE_FAILURE;
        goto exit;
    }

    file_size = ftell( file );

    if( file_size < 0 )
    {
        status = PSA_ERROR_STORAGE_FAILURE;
        goto exit;
    }

#if LONG_MAX > SIZE_MAX
    if( (unsigned long) file_size > SIZE_MAX )
    {
        status = PSA_ERROR_STORAGE_FAILURE;
        goto exit;
    }
#endif
    *data_length = (size_t) file_size;

exit:
    fclose( file );
    return( status );
}

#endif /* MBEDTLS_PSA_CRYPTO_STORAGE_FILE_C */
