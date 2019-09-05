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

#ifndef PSA_CRYPTO_SLOT_MANAGEMENT_H
#define PSA_CRYPTO_SLOT_MANAGEMENT_H

#include "psa/crypto.h"
#include "psa_crypto_se.h"

/* Number of key slots (plus one because 0 is not used).
 * The value is a compile-time constant for now, for simplicity. */
#define PSA_KEY_SLOT_COUNT 32

/** Access a key slot at the given handle.
 *
 * \param handle        Key handle to query.
 * \param[out] p_slot   On success, `*p_slot` contains a pointer to the
 *                      key slot in memory designated by \p handle.
 *
 * \retval PSA_SUCCESS
 *         Success: \p handle is a handle to `*p_slot`. Note that `*p_slot`
 *         may be empty or occupied.
 * \retval PSA_ERROR_INVALID_HANDLE
 *         \p handle is out of range or is not in use.
 * \retval PSA_ERROR_BAD_STATE
 *         The library has not been initialized.
 */
psa_status_t psa_get_key_slot( psa_key_handle_t handle,
                               psa_key_slot_t **p_slot );

/** Initialize the key slot structures.
 *
 * \retval PSA_SUCCESS
 *         Currently this function always succeeds.
 */
psa_status_t psa_initialize_key_slots( void );

/** Delete all data from key slots in memory.
 *
 * This does not affect persistent storage. */
void psa_wipe_all_key_slots( void );

/** Find a free key slot.
 *
 * This function returns a key slot that is available for use and is in its
 * ground state (all-bits-zero).
 *
 * \param[out] handle   On success, a slot number that can be used as a
 *                      handle to the slot.
 * \param[out] p_slot   On success, a pointer to the slot.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_BAD_STATE
 */
psa_status_t psa_get_empty_key_slot( psa_key_handle_t *handle,
                                     psa_key_slot_t **p_slot );

/** Test whether a lifetime designates a key in an external cryptoprocessor.
 *
 * \param lifetime      The lifetime to test.
 *
 * \retval 1
 *         The lifetime designates an external key. There should be a
 *         registered driver for this lifetime, otherwise the key cannot
 *         be created or manipulated.
 * \retval 0
 *         The lifetime designates a key that is volatile or in internal
 *         storage.
 */
static inline int psa_key_lifetime_is_external( psa_key_lifetime_t lifetime )
{
    return( lifetime != PSA_KEY_LIFETIME_VOLATILE &&
            lifetime != PSA_KEY_LIFETIME_PERSISTENT );
}

/** Test whether the given parameters are acceptable for a persistent key.
 *
 * This function does not access the storage in any way. It only tests
 * whether the parameters are meaningful and permitted by general policy.
 * It does not test whether the a file by the given id exists or could be
 * created.
 *
 * If the key is in external storage, this function returns the corresponding
 * driver.
 *
 * \param lifetime      The lifetime to test.
 * \param id            The key id to test.
 * \param[out] p_drv    On output, if \p lifetime designates a key
 *                      in an external processor, \c *p_drv is a pointer
 *                      to the driver table entry fot this lifetime.
 *                      If \p lifetime designates a transparent key,
 *                      \c *p_drv is \c NULL.
 * \param creating      0 if attempting to open an existing key.
 *                      Nonzero if attempting to create a key.
 *
 * \retval PSA_SUCCESS
 *         The given parameters are valid.
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         \p lifetime is volatile or is invalid.
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         \p id is invalid.
 */
psa_status_t psa_validate_persistent_key_parameters(
    psa_key_lifetime_t lifetime,
    psa_key_file_id_t id,
    psa_se_drv_table_entry_t **p_drv,
    int creating );


#endif /* PSA_CRYPTO_SLOT_MANAGEMENT_H */
