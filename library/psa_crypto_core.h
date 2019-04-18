/*
 *  PSA crypto core internal interfaces
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

#ifndef PSA_CRYPTO_CORE_H
#define PSA_CRYPTO_CORE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "psa/crypto.h"

#include "mbedtls/ecp.h"
#include "mbedtls/rsa.h"

/** The data structure representing a key slot, containing key material
 * and metadata for one key.
 */
typedef struct
{
    psa_key_type_t type;
    psa_key_policy_t policy;
    psa_key_lifetime_t lifetime;
    psa_key_file_id_t persistent_storage_id;
    unsigned allocated : 1;
    union
    {
        struct raw_data
        {
            uint8_t *data;
            size_t bytes;
        } raw;
#if defined(MBEDTLS_RSA_C)
        mbedtls_rsa_context *rsa;
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
        mbedtls_ecp_keypair *ecp;
#endif /* MBEDTLS_ECP_C */
    } data;
} psa_key_slot_t;

/** Completely wipe a slot in memory, including its policy.
 *
 * Persistent storage is not affected.
 *
 * \param[in,out] slot  The key slot to wipe.
 *
 * \retval PSA_SUCCESS
 *         Success. This includes the case of a key slot that was
 *         already fully wiped.
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_wipe_key_slot( psa_key_slot_t *slot );

/** Import key data into a slot.
 *
 * `slot->type` must have been set previously.
 * This function assumes that the slot does not contain any key material yet.
 * On failure, the slot content is unchanged.
 *
 * Persistent storage is not affected.
 *
 * \param[in,out] slot  The key slot to import data into.
 *                      Its `type` field must have previously been set to
 *                      the desired key type.
 *                      It must not contain any key material yet.
 * \param[in] data      Buffer containing the key material to parse and import.
 * \param data_length   Size of \p data in bytes.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_INVALID_ARGUMENT
 * \retval PSA_ERROR_NOT_SUPPORTED
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 */
psa_status_t psa_import_key_into_slot( psa_key_slot_t *slot,
                                       const uint8_t *data,
                                       size_t data_length );

#endif /* PSA_CRYPTO_CORE_H */
