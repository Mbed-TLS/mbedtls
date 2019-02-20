/*
 *  PSA storage backend for persistent keys using psa_its APIs.
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

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_ITS_C)

#include "psa/error.h"
#include "psa_crypto_service_integration.h"
#include "psa/crypto.h"
#include "psa_crypto_storage_backend.h"
#include "psa/internal_trusted_storage.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#endif

/* Determine a file name (ITS file identifier) for the given key file
 * identifier. The file name must be distinct from any file that is used
 * for a purpose other than storing a key. Currently, the only such file
 * is the random seed file whose name is PSA_CRYPTO_ITS_RANDOM_SEED_UID
 * and whose value is 0xFFFFFF52. */
static psa_storage_uid_t psa_its_identifier_of_slot( psa_key_file_id_t file_id )
{
#if defined(MBEDTLS_PSA_CRYPTO_KEY_FILE_ID_ENCODES_OWNER) && \
    defined(PSA_CRYPTO_SECURE)
    /* Encode the owner in the upper 32 bits. This means that if
     * owner values are nonzero (as they are on a PSA platform),
     * no key file will ever have a value less than 0x100000000, so
     * the whole range 0..0xffffffff is available for non-key files. */
    uint32_t unsigned_owner = (uint32_t) file_id.owner;
    return( (uint64_t) unsigned_owner << 32 | file_id.key_id );
#else
    /* Use the key id directly as a file name.
     * psa_is_key_file_id_valid() in psa_crypto_slot_management.c
     * is responsible for ensuring that key identifiers do not have a
     * value that is reserved for non-key files. */
    return( file_id );
#endif
}

psa_status_t psa_crypto_storage_load( const psa_key_file_id_t key, uint8_t *data,
                                      size_t data_size )
{
    psa_status_t status;
    psa_storage_uid_t data_identifier = psa_its_identifier_of_slot( key );
    struct psa_storage_info_t data_identifier_info;

    status = psa_its_get_info( data_identifier, &data_identifier_info );
    if( status  != PSA_SUCCESS )
        return( status );

    status = psa_its_get( data_identifier, 0, data_size, data );

    return( status );
}

int psa_is_key_present_in_storage( const psa_key_file_id_t key )
{
    psa_status_t ret;
    psa_storage_uid_t data_identifier = psa_its_identifier_of_slot( key );
    struct psa_storage_info_t data_identifier_info;

    ret = psa_its_get_info( data_identifier, &data_identifier_info );

    if( ret == PSA_ERROR_DOES_NOT_EXIST )
        return( 0 );
    return( 1 );
}

psa_status_t psa_crypto_storage_store( const psa_key_file_id_t key,
                                       const uint8_t *data,
                                       size_t data_length )
{
    psa_status_t status;
    psa_storage_uid_t data_identifier = psa_its_identifier_of_slot( key );
    struct psa_storage_info_t data_identifier_info;

    if( psa_is_key_present_in_storage( key ) == 1 )
        return( PSA_ERROR_ALREADY_EXISTS );

    status = psa_its_set( data_identifier, data_length, data, 0 );
    if( status != PSA_SUCCESS )
    {
        return( PSA_ERROR_STORAGE_FAILURE );
    }

    status = psa_its_get_info( data_identifier, &data_identifier_info );
    if( status != PSA_SUCCESS )
    {
        goto exit;
    }

    if( data_identifier_info.size != data_length )
    {
        status = PSA_ERROR_STORAGE_FAILURE;
        goto exit;
    }

exit:
    if( status != PSA_SUCCESS )
        psa_its_remove( data_identifier );
    return( status );
}

psa_status_t psa_destroy_persistent_key( const psa_key_file_id_t key )
{
    psa_status_t ret;
    psa_storage_uid_t data_identifier = psa_its_identifier_of_slot( key );
    struct psa_storage_info_t data_identifier_info;

    ret = psa_its_get_info( data_identifier, &data_identifier_info );
    if( ret == PSA_ERROR_DOES_NOT_EXIST )
        return( PSA_SUCCESS );

    if( psa_its_remove( data_identifier ) != PSA_SUCCESS )
        return( PSA_ERROR_STORAGE_FAILURE );

    ret = psa_its_get_info( data_identifier, &data_identifier_info );
    if( ret != PSA_ERROR_DOES_NOT_EXIST )
        return( PSA_ERROR_STORAGE_FAILURE );

    return( PSA_SUCCESS );
}

psa_status_t psa_crypto_storage_get_data_length( const psa_key_file_id_t key,
                                                 size_t *data_length )
{
    psa_status_t status;
    psa_storage_uid_t data_identifier = psa_its_identifier_of_slot( key );
    struct psa_storage_info_t data_identifier_info;

    status = psa_its_get_info( data_identifier, &data_identifier_info );
    if( status != PSA_SUCCESS )
        return( status );

    *data_length = (size_t) data_identifier_info.size;

    return( PSA_SUCCESS );
}

#endif /* MBEDTLS_PSA_CRYPTO_STORAGE_ITS_C */
