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

#include "psa_crypto_service_integration.h"
#include "psa/crypto.h"

#include "psa_crypto_core.h"
#include "psa_crypto_slot_management.h"
#include "psa_crypto_storage.h"

#include <stdlib.h>
#include <string.h>
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

#define ARRAY_LENGTH( array ) ( sizeof( array ) / sizeof( *( array ) ) )

typedef struct
{
    psa_key_slot_t key_slots[PSA_KEY_SLOT_COUNT];
    unsigned key_slots_initialized : 1;
} psa_global_data_t;

static psa_global_data_t global_data;

/* Access a key slot at the given handle. The handle of a key slot is
 * the index of the slot in the global slot array, plus one so that handles
 * start at 1 and not 0. */
psa_status_t psa_get_key_slot( psa_key_handle_t handle,
                               psa_key_slot_t **p_slot )
{
    psa_key_slot_t *slot = NULL;

    if( ! global_data.key_slots_initialized )
        return( PSA_ERROR_BAD_STATE );

    /* 0 is not a valid handle under any circumstance. This
     * implementation provides slots number 1 to N where N is the
     * number of available slots. */
    if( handle == 0 || handle > ARRAY_LENGTH( global_data.key_slots ) )
        return( PSA_ERROR_INVALID_HANDLE );
    slot = &global_data.key_slots[handle - 1];

    /* If the slot hasn't been allocated, the handle is invalid. */
    if( ! slot->allocated )
        return( PSA_ERROR_INVALID_HANDLE );

    *p_slot = slot;
    return( PSA_SUCCESS );
}

psa_status_t psa_initialize_key_slots( void )
{
    /* Nothing to do: program startup and psa_wipe_all_key_slots() both
     * guarantee that the key slots are initialized to all-zero, which
     * means that all the key slots are in a valid, empty state. */
    global_data.key_slots_initialized = 1;
    return( PSA_SUCCESS );
}

void psa_wipe_all_key_slots( void )
{
    psa_key_handle_t key;
    for( key = 1; key <= PSA_KEY_SLOT_COUNT; key++ )
    {
        psa_key_slot_t *slot = &global_data.key_slots[key - 1];
        (void) psa_wipe_key_slot( slot );
    }
    global_data.key_slots_initialized = 0;
}

psa_status_t psa_internal_allocate_key_slot( psa_key_handle_t *handle,
                                             psa_key_slot_t **p_slot )
{
    if( ! global_data.key_slots_initialized )
        return( PSA_ERROR_BAD_STATE );

    for( *handle = PSA_KEY_SLOT_COUNT; *handle != 0; --( *handle ) )
    {
        *p_slot = &global_data.key_slots[*handle - 1];
        if( ! ( *p_slot )->allocated )
        {
            ( *p_slot )->allocated = 1;
            return( PSA_SUCCESS );
        }
    }
    *p_slot = NULL;
    return( PSA_ERROR_INSUFFICIENT_MEMORY );
}

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
static psa_status_t psa_load_persistent_key_into_slot( psa_key_slot_t *p_slot )
{
    psa_status_t status = PSA_SUCCESS;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;

    status = psa_load_persistent_key( p_slot->persistent_storage_id,
                                      &( p_slot )->type,
                                      &( p_slot )->policy, &key_data,
                                      &key_data_length );
    if( status != PSA_SUCCESS )
        goto exit;
    status = psa_import_key_into_slot( p_slot,
                                       key_data, key_data_length );
exit:
    psa_free_persistent_key_data( key_data, key_data_length );
    return( status );
}

/** Check whether a key identifier is acceptable.
 *
 * For backward compatibility, key identifiers that were valid in a
 * past released version must remain valid, unless a migration path
 * is provided.
 *
 * \param file_id       The key identifier to check.
 * \param vendor_ok     Nonzero to allow key ids in the vendor range.
 *                      0 to allow only key ids in the application range.
 *
 * \return              1 if \p file_id is acceptable, otherwise 0.
 */
static int psa_is_key_id_valid( psa_key_file_id_t file_id,
                                int vendor_ok )
{
    psa_app_key_id_t key_id = PSA_KEY_FILE_GET_KEY_ID( file_id );
    if( PSA_KEY_ID_USER_MIN <= key_id && key_id <= PSA_KEY_ID_USER_MAX )
        return( 1 );
    else if( vendor_ok &&
             PSA_KEY_ID_VENDOR_MIN <= key_id &&
             key_id <= PSA_KEY_ID_VENDOR_MAX )
        return( 1 );
    else
        return( 0 );
}
#endif /* defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) */

psa_status_t psa_validate_persistent_key_parameters(
    psa_key_lifetime_t lifetime,
    psa_key_file_id_t id,
    int creating )
{
    if( lifetime != PSA_KEY_LIFETIME_PERSISTENT )
        return( PSA_ERROR_INVALID_ARGUMENT );

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    if( ! psa_is_key_id_valid( id, ! creating ) )
        return( PSA_ERROR_INVALID_ARGUMENT );
    return( PSA_SUCCESS );

#else /* MBEDTLS_PSA_CRYPTO_STORAGE_C */
    (void) id;
    (void) creating;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* !MBEDTLS_PSA_CRYPTO_STORAGE_C */
}

psa_status_t psa_open_key( psa_key_file_id_t id, psa_key_handle_t *handle )
{
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    psa_status_t status;
    psa_key_slot_t *slot;

    *handle = 0;

    status = psa_validate_persistent_key_parameters(
        PSA_KEY_LIFETIME_PERSISTENT, id, 0 );
    if( status != PSA_SUCCESS )
        return( status );

    status = psa_internal_allocate_key_slot( handle, &slot );
    if( status != PSA_SUCCESS )
        return( status );

    slot->lifetime = PSA_KEY_LIFETIME_PERSISTENT;
    slot->persistent_storage_id = id;

    status = psa_load_persistent_key_into_slot( slot );
    if( status != PSA_SUCCESS )
    {
        psa_wipe_key_slot( slot );
        *handle = 0;
    }
    return( status );

#else /* defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) */
    (void) id;
    *handle = 0;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* !defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) */
}

psa_status_t psa_close_key( psa_key_handle_t handle )
{
    psa_status_t status;
    psa_key_slot_t *slot;

    status = psa_get_key_slot( handle, &slot );
    if( status != PSA_SUCCESS )
        return( status );

    return( psa_wipe_key_slot( slot ) );
}

void mbedtls_psa_get_stats( mbedtls_psa_stats_t *stats )
{
    psa_key_handle_t key;
    memset( stats, 0, sizeof( *stats ) );
    for( key = 1; key <= PSA_KEY_SLOT_COUNT; key++ )
    {
        psa_key_slot_t *slot = &global_data.key_slots[key - 1];
        if( slot->type == PSA_KEY_TYPE_NONE )
        {
            if( slot->allocated )
                ++stats->half_filled_slots;
            else
                ++stats->empty_slots;
            continue;
        }
        if( slot->lifetime == PSA_KEY_LIFETIME_VOLATILE )
            ++stats->volatile_slots;
        else if( slot->lifetime == PSA_KEY_LIFETIME_PERSISTENT )
        {
            ++stats->persistent_slots;
            if( slot->persistent_storage_id > stats->max_open_internal_key_id )
                stats->max_open_internal_key_id = slot->persistent_storage_id;
        }
        else
        {
            ++stats->external_slots;
            if( slot->persistent_storage_id > stats->max_open_external_key_id )
                stats->max_open_external_key_id = slot->persistent_storage_id;
        }
    }
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
