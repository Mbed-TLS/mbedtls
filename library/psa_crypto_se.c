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

#if defined(MBEDTLS_PSA_ITS_FILE_C)
#include "psa_crypto_its.h"
#else /* Native ITS implementation */
#include "psa/error.h"
#include "psa/internal_trusted_storage.h"
#endif

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
    /* In the driver table, lifetime=0 means an entry that isn't used.
     * No driver has a lifetime of 0 because it's a reserved value
     * (which designates volatile keys). Make sure we never return
     * a driver entry for lifetime 0. */
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

static psa_status_t psa_get_se_driver_its_file_uid(
    const psa_se_drv_table_entry_t *driver,
    psa_storage_uid_t *uid )
{
    if( driver->lifetime > PSA_MAX_SE_LIFETIME )
        return( PSA_ERROR_NOT_SUPPORTED );

#if SIZE_MAX > UINT32_MAX
    /* ITS file sizes are limited to 32 bits. */
    if( driver->internal.persistent_data_size > UINT32_MAX )
        return( PSA_ERROR_NOT_SUPPORTED );
#endif

    /* See the documentation of PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE. */
    *uid = PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE + driver->lifetime;
    return( PSA_SUCCESS );
}

psa_status_t psa_load_se_persistent_data(
    const psa_se_drv_table_entry_t *driver )
{
    psa_status_t status;
    psa_storage_uid_t uid;
    size_t length;

    status = psa_get_se_driver_its_file_uid( driver, &uid );
    if( status != PSA_SUCCESS )
        return( status );

    /* Read the amount of persistent data that the driver requests.
     * If the data in storage is larger, it is truncated. If the data
     * in storage is smaller, silently keep what is already at the end
     * of the output buffer. */
    /* psa_get_se_driver_its_file_uid ensures that the size_t
     * persistent_data_size is in range, but compilers don't know that,
     * so cast to reassure them. */
    return( psa_its_get( uid, 0,
                         (uint32_t) driver->internal.persistent_data_size,
                         driver->internal.persistent_data,
                         &length ) );
}

psa_status_t psa_save_se_persistent_data(
    const psa_se_drv_table_entry_t *driver )
{
    psa_status_t status;
    psa_storage_uid_t uid;

    status = psa_get_se_driver_its_file_uid( driver, &uid );
    if( status != PSA_SUCCESS )
        return( status );

    /* psa_get_se_driver_its_file_uid ensures that the size_t
     * persistent_data_size is in range, but compilers don't know that,
     * so cast to reassure them. */
    return( psa_its_set( uid,
                         (uint32_t) driver->internal.persistent_data_size,
                         driver->internal.persistent_data,
                         0 ) );
}

psa_status_t psa_destroy_se_persistent_data( psa_key_lifetime_t lifetime )
{
    psa_storage_uid_t uid;
    if( lifetime > PSA_MAX_SE_LIFETIME )
        return( PSA_ERROR_NOT_SUPPORTED );
    uid = PSA_CRYPTO_SE_DRIVER_ITS_UID_BASE + lifetime;
    return( psa_its_remove( uid ) );
}

psa_status_t psa_find_se_slot_for_key(
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_se_drv_table_entry_t *driver,
    psa_key_slot_number_t *slot_number )
{
    psa_status_t status;

    /* If the lifetime is wrong, it's a bug in the library. */
    if( driver->lifetime != psa_get_key_lifetime( attributes ) )
        return( PSA_ERROR_CORRUPTION_DETECTED );

    /* If the driver doesn't support key creation in any way, give up now. */
    if( driver->methods->key_management == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( psa_get_key_slot_number( attributes, slot_number ) == PSA_SUCCESS )
    {
        /* The application wants to use a specific slot. Allow it if
         * the driver supports it. On a system with isolation,
         * the crypto service must check that the application is
         * permitted to request this slot. */
        psa_drv_se_validate_slot_number_t p_validate_slot_number =
            driver->methods->key_management->p_validate_slot_number;
        if( p_validate_slot_number == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        status = p_validate_slot_number( &driver->context,
                                         attributes, method,
                                         *slot_number );
    }
    else
    {
        /* The application didn't tell us which slot to use. Let the driver
         * choose. This is the normal case. */
        psa_drv_se_allocate_key_t p_allocate =
            driver->methods->key_management->p_allocate;
        if( p_allocate == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        status = p_allocate( &driver->context,
                             driver->internal.persistent_data,
                             attributes, method,
                             slot_number );
    }
    return( status );
}

psa_status_t psa_destroy_se_key( psa_se_drv_table_entry_t *driver,
                                 psa_key_slot_number_t slot_number )
{
    psa_status_t status;
    psa_status_t storage_status;
    /* Normally a missing method would mean that the action is not
     * supported. But psa_destroy_key() is not supposed to return
     * PSA_ERROR_NOT_SUPPORTED: if you can create a key, you should
     * be able to destroy it. The only use case for a driver that
     * does not have a way to destroy keys at all is if the keys are
     * locked in a read-only state: we can use the keys but not
     * destroy them. Hence, if the driver doesn't support destroying
     * keys, it's really a lack of permission. */
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
    if( lifetime > PSA_MAX_SE_LIFETIME )
        return( PSA_ERROR_NOT_SUPPORTED );

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
        /* Load the driver's persistent data. On first use, the persistent
         * data does not exist in storage, and is initialized to
         * all-bits-zero by the calloc call just above. */
        status = psa_load_se_persistent_data( &driver_table[i] );
        if( status != PSA_SUCCESS && status != PSA_ERROR_DOES_NOT_EXIST )
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
