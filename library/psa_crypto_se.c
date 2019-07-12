/*
 *  PSA crypto support for secure element drivers
 */
/*  Copyright (C) 2019, ARM Limited, All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PSA_CRYPTO_SE_C)

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "psa/crypto_se_driver.h"

#include "psa_crypto_se.h"

#include "mbedtls/platform.h"
#if !defined(MBEDTLS_PLATFORM_C)
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif



/****************************************************************/
/* Driver lookup */
/****************************************************************/

/* This structure is identical to psa_drv_se_context_t declared in
 * `crypto_se_driver.h`, except that some parts are writable here
 * (non-const, or pointer to non-const). */
typedef struct
{
    void *persistent_data;
    size_t persistent_data_size;
    uintptr_t transient_data;
} psa_drv_se_internal_context_t;

typedef struct psa_se_drv_table_entry_s
{
    psa_key_lifetime_t lifetime;
    const psa_drv_se_t *methods;
    union
    {
        psa_drv_se_internal_context_t internal;
        psa_drv_se_context_t context;
    };
} psa_se_drv_table_entry_t;

static psa_se_drv_table_entry_t driver_table[PSA_MAX_SE_DRIVERS];

psa_se_drv_table_entry_t *psa_get_se_driver_entry(
    psa_key_lifetime_t lifetime )
{
    size_t i;
    if( lifetime == 0 )
        return( NULL );
    for( i = 0; i < PSA_MAX_SE_DRIVERS; i++ )
    {
        if( driver_table[i].lifetime == lifetime )
            return( &driver_table[i] );
    }
    return( NULL );
}

const psa_drv_se_t *psa_get_se_driver_methods(
    const psa_se_drv_table_entry_t *driver )
{
    return( driver->methods );
}

psa_drv_se_context_t *psa_get_se_driver_context(
    psa_se_drv_table_entry_t *driver )
{
    return( &driver->context );
}

int psa_get_se_driver( psa_key_lifetime_t lifetime,
                       const psa_drv_se_t **p_methods,
                       psa_drv_se_context_t **p_drv_context)
{
    psa_se_drv_table_entry_t *driver = psa_get_se_driver_entry( lifetime );
    if( p_methods != NULL )
        *p_methods = ( driver ? driver->methods : NULL );
    if( p_drv_context != NULL )
        *p_drv_context = ( driver ? &driver->context : NULL );
    return( driver != NULL );
}



/****************************************************************/
/* Persistent data management */
/****************************************************************/

psa_status_t psa_load_se_persistent_data(
    const psa_se_drv_table_entry_t *driver )
{
    /*TODO*/
    (void) driver;
    return( PSA_SUCCESS );
}

psa_status_t psa_save_se_persistent_data(
    const psa_se_drv_table_entry_t *driver )
{
    /*TODO*/
    (void) driver;
    return( PSA_SUCCESS );
}

psa_status_t psa_find_se_slot_for_key(
    const psa_key_attributes_t *attributes,
    psa_se_drv_table_entry_t *driver,
    psa_key_slot_number_t *slot_number )
{
    psa_status_t status;
    psa_drv_se_allocate_key_t p_allocate = NULL;

    /* If the lifetime is wrong, it's a bug in the library. */
    if( driver->lifetime != attributes->lifetime )
        return( PSA_ERROR_CORRUPTION_DETECTED );

    /* If the driver doesn't support key creation in any way, give up now. */
    if( driver->methods->key_management == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );
    p_allocate = driver->methods->key_management->p_allocate;

    /* If the driver doesn't tell us how to allocate a slot, that's
     * not supported for the time being. */
    if( p_allocate == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    status = ( *p_allocate )( &driver->context,
                              driver->internal.persistent_data,
                              attributes,
                              slot_number );
    return( status );
}

psa_status_t psa_destroy_se_key( psa_se_drv_table_entry_t *driver,
                                 psa_key_slot_number_t slot_number )
{
    psa_status_t status;
    psa_status_t storage_status;
    if( driver->methods->key_management == NULL ||
        driver->methods->key_management->p_destroy == NULL )
        return( PSA_ERROR_NOT_PERMITTED );
    status = driver->methods->key_management->p_destroy(
        &driver->context,
        driver->internal.persistent_data,
        slot_number );
    storage_status = psa_save_se_persistent_data( driver );
    return( status == PSA_SUCCESS ? storage_status : status );
}



/****************************************************************/
/* Driver registration */
/****************************************************************/

psa_status_t psa_register_se_driver(
    psa_key_lifetime_t lifetime,
    const psa_drv_se_t *methods)
{
    size_t i;
    psa_status_t status;

    if( methods->hal_version != PSA_DRV_SE_HAL_VERSION )
        return( PSA_ERROR_NOT_SUPPORTED );
    /* Driver table entries are 0-initialized. 0 is not a valid driver
     * lifetime because it means a volatile key. */
#if defined(static_assert)
    static_assert( PSA_KEY_LIFETIME_VOLATILE == 0,
                   "Secure element support requires 0 to mean a volatile key" );
#endif
    if( lifetime == PSA_KEY_LIFETIME_VOLATILE ||
        lifetime == PSA_KEY_LIFETIME_PERSISTENT )
    {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

    for( i = 0; i < PSA_MAX_SE_DRIVERS; i++ )
    {
        if( driver_table[i].lifetime == 0 )
            break;
        /* Check that lifetime isn't already in use up to the first free
         * entry. Since entries are created in order and never deleted,
         * there can't be a used entry after the first free entry. */
        if( driver_table[i].lifetime == lifetime )
            return( PSA_ERROR_ALREADY_EXISTS );
    }
    if( i == PSA_MAX_SE_DRIVERS )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );

    driver_table[i].lifetime = lifetime;
    driver_table[i].methods = methods;

    if( methods->persistent_data_size != 0 )
    {
        driver_table[i].internal.persistent_data =
            mbedtls_calloc( 1, methods->persistent_data_size );
        if( driver_table[i].internal.persistent_data == NULL )
        {
            status = PSA_ERROR_INSUFFICIENT_MEMORY;
            goto error;
        }
        status = psa_load_se_persistent_data( &driver_table[i] );
        if( status != PSA_SUCCESS )
            goto error;
    }
    driver_table[i].internal.persistent_data_size =
        methods->persistent_data_size;

    return( PSA_SUCCESS );

error:
    memset( &driver_table[i], 0, sizeof( driver_table[i] ) );
    return( status );
}

void psa_unregister_all_se_drivers( void )
{
    size_t i;
    for( i = 0; i < PSA_MAX_SE_DRIVERS; i++ )
    {
        if( driver_table[i].internal.persistent_data != NULL )
            mbedtls_free( driver_table[i].internal.persistent_data );
    }
    memset( driver_table, 0, sizeof( driver_table ) );
}



/****************************************************************/
/* The end */
/****************************************************************/

#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
