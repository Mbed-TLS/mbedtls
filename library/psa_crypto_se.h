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

#ifndef PSA_CRYPTO_SE_H
#define PSA_CRYPTO_SE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "psa/crypto.h"
#include "psa/crypto_se_driver.h"

/** The maximum number of registered secure element driver lifetimes. */
#define PSA_MAX_SE_DRIVERS 4

/** Unregister all secure element drivers.
 *
 * \warning Do not call this function while the library is in the initialized
 *          state. This function is only intended to be called at the end
 *          of mbedtls_psa_crypto_free().
 */
void psa_unregister_all_se_drivers( void );

/** A structure that describes a registered secure element driver.
 *
 * A secure element driver table entry contains a pointer to the
 * driver's method table as well as the driver context structure.
 */
typedef struct psa_se_drv_table_entry_s psa_se_drv_table_entry_t;

/** Return the secure element driver information for a lifetime value.
 *
 * \param lifetime              The lifetime value to query.
 * \param[out] p_methods        On output, if there is a driver,
 *                              \c *methods points to its method table.
 *                              Otherwise \c *methods is \c NULL.
 * \param[out] p_drv_context    On output, if there is a driver,
 *                              \c *drv_context points to its context
 *                              structure.
 *                              Otherwise \c *drv_context is \c NULL.
 *
 * \retval 1
 *         \p lifetime corresponds to a registered driver.
 * \retval 0
 *         \p lifetime does not correspond to a registered driver.
 */
int psa_get_se_driver( psa_key_lifetime_t lifetime,
                       const psa_drv_se_t **p_methods,
                       psa_drv_se_context_t **p_drv_context);

/** Return the secure element driver table entry for a lifetime value.
 *
 * \param lifetime      The lifetime value to query.
 *
 * \return The driver table entry for \p lifetime, or
 *         \p NULL if \p lifetime does not correspond to a registered driver.
 */
psa_se_drv_table_entry_t *psa_get_se_driver_entry(
    psa_key_lifetime_t lifetime );

/** Return the method table for a secure element driver.
 *
 * \param[in] driver    The driver table entry to access, or \c NULL.
 *
 * \return The driver's method table.
 *         \c NULL if \p driver is \c NULL.
 */
const psa_drv_se_t *psa_get_se_driver_methods(
    const psa_se_drv_table_entry_t *driver );

/** Return the context of a secure element driver.
 *
 * \param[in] driver    The driver table entry to access, or \c NULL.
 *
 * \return A pointer to the driver context.
 *         \c NULL if \p driver is \c NULL.
 */
psa_drv_se_context_t *psa_get_se_driver_context(
    psa_se_drv_table_entry_t *driver );

/** Find a free slot for a key that is to be created.
 *
 * This function calls the relevant method in the driver to find a suitable
 * slot for a key with the given attributes.
 *
 * \param[in] attributes    Metadata about the key that is about to be created.
 * \param[in] driver        The driver table entry to query.
 * \param[out] slot_number  On success, a slot number that is free in this
 *                          secure element.
 */
psa_status_t psa_find_se_slot_for_key(
    const psa_key_attributes_t *attributes,
    psa_se_drv_table_entry_t *driver,
    psa_key_slot_number_t *slot_number );

/** Load the persistent data of a secure element driver.
 *
 * \param driver        The driver table entry containing the persistent
 *                      data to load from storage.
 */
psa_status_t psa_load_se_persistent_data(
    const psa_se_drv_table_entry_t *driver );

/** Save the persistent data of a secure element driver.
 *
 * \param[in] driver    The driver table entry containing the persistent
 *                      data to save to storage.
 */
psa_status_t psa_save_se_persistent_data(
    const psa_se_drv_table_entry_t *driver );

#endif /* PSA_CRYPTO_SE_H */
