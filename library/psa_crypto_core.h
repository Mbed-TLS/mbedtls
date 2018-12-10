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
    psa_key_id_t persistent_storage_id;
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
 * Persistent storage is not affected. */
psa_status_t psa_wipe_key_slot( psa_key_slot_t *slot );

#endif /* PSA_CRYPTO_CORE_H */
