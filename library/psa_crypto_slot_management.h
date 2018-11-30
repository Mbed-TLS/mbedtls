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

/* Number of key slots (plus one because 0 is not used).
 * The value is a compile-time constant for now, for simplicity. */
#define PSA_KEY_SLOT_COUNT 32

/* All dynamically allocated handles have this bit set. */
#define PSA_KEY_HANDLE_ALLOCATED_FLAG ( (psa_key_handle_t) 0x8000 )

/** \defgroup core_slot_management Internal functions exposed by the core
 * @{
 */

/** Find a free key slot and mark it as in use.
 *
 * \param[out] handle   On success, a slot number that is not in use.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 */
psa_status_t psa_internal_allocate_key_slot( psa_key_handle_t *handle );

/** Wipe an a key slot and mark it as available.
 *
 * This does not affect persistent storage.
 *
 * \param handle        The key slot number to release.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_internal_release_key_slot( psa_key_handle_t handle );

/** Declare a slot as persistent and load it from storage.
 *
 * This function may only be called immediately after a successful call
 * to psa_internal_allocate_key_slot().
 *
 * \param handle        A handle to a key slot freshly allocated with
 *                      psa_internal_allocate_key_slot().
 *
 * \retval #PSA_SUCCESS
 *         The slot content was loaded successfully.
 * \retval #PSA_ERROR_EMPTY_SLOT
 *         There is no content for this slot in persistent storage.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p id is not acceptable.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_STORAGE_FAILURE
 */
psa_status_t psa_internal_make_key_persistent( psa_key_handle_t handle,
                                               psa_key_id_t id );

/**@}*/

#endif /* PSA_CRYPTO_SLOT_MANAGEMENT_H */
