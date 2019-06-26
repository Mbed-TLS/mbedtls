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
#include <string.h>

#include "psa_crypto_se.h"

/****************************************************************/
/* Driver lookup */
/****************************************************************/

typedef struct psa_se_drv_table_entry_s
{
    psa_key_lifetime_t lifetime;
    const psa_drv_se_t *methods;
} psa_se_drv_table_entry_t;

static psa_se_drv_table_entry_t driver_table[PSA_MAX_SE_DRIVERS];

const psa_se_drv_table_entry_t *psa_get_se_driver_entry(
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
    const psa_se_drv_table_entry_t *drv )
{
    return( drv->methods );
}

const psa_drv_se_t *psa_get_se_driver( psa_key_lifetime_t lifetime )
{
    const psa_se_drv_table_entry_t *drv = psa_get_se_driver_entry( lifetime );
    if( drv == NULL )
        return( NULL );
    else
        return( drv->methods );
}




/****************************************************************/
/* Driver registration */
/****************************************************************/

psa_status_t psa_register_se_driver(
    psa_key_lifetime_t lifetime,
    const psa_drv_se_t *methods)
{
    size_t i;

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
    return( PSA_SUCCESS );
}

void psa_unregister_all_se_drivers( void )
{
    memset( driver_table, 0, sizeof( driver_table ) );
}



/****************************************************************/
/* The end */
/****************************************************************/

#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
