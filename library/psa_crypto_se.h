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
 * driver's method table and a pointer to the driver's slot usage
 * structure.
 */
typedef struct psa_se_drv_table_entry_s psa_se_drv_table_entry_t;

/** Return the secure element driver table entry for a lifetime value.
 *
 * \param lifetime      The lifetime value to query.
 *
 * \return The driver table entry for \p lifetime, or
 *         \p NULL if \p lifetime does not correspond to a registered driver.
 */
const psa_se_drv_table_entry_t *psa_get_se_driver_entry(
    psa_key_lifetime_t lifetime );

/** Return the method table for a secure element driver.
 *
 * \param[in] drv       The driver table entry to access.
 *
 * \return The driver table entry for \p lifetime, or
 *         \p NULL if \p lifetime does not correspond to a registered driver.
 */
const psa_drv_se_t *psa_get_se_driver_methods(
    const psa_se_drv_table_entry_t *drv );

/** Return the secure element driver method table for a lifetime value.
 *
 * \param lifetime      The lifetime value to query.
 *
 * \return The driver method table for \p lifetime, or
 *         \p NULL if \p lifetime does not correspond to a registered driver.
 */
const psa_drv_se_t *psa_get_se_driver(
    psa_key_lifetime_t lifetime );

#endif /* PSA_CRYPTO_SE_H */
