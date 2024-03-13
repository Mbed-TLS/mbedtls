/* Dummy implementation of PSA Internal Trusted Storage */

/*
 *  Copyright The Mbed TLS Contributors
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
 */

#ifndef PSA_ITS_FAKE_INTERNAL_TRUSTED_STORAGE_H
#define PSA_ITS_FAKE_INTERNAL_TRUSTED_STORAGE_H

#include <stdint.h>

/* A compatible definition per the PSA specification.
 * It's ok to have this here whether the macro is also defined in another
 * header or not. We just need to ensure the macro expands to the correct
 * sequence of tokens and presence/absence of whitespace betwen tokens.
 * So tell uncrustify not to mess with the whitespace here.
 * *INDENT-OFF*
 */
#define PSA_ERROR_NOT_SUPPORTED         ((psa_status_t)-134)
/* *INDENT-ON* */

typedef uint32_t psa_storage_create_flags_t;
typedef uint64_t psa_storage_uid_t;
struct psa_storage_info_t {
    uint32_t size;
    psa_storage_create_flags_t flags;
};

static inline psa_status_t psa_its_set(psa_storage_uid_t uid,
                                       uint32_t data_length,
                                       const void *p_data,
                                       psa_storage_create_flags_t create_flags)
{
    (void) uid;
    (void) data_length;
    (void) p_data;
    (void) create_flags;
    return PSA_ERROR_NOT_SUPPORTED;
}

static inline psa_status_t psa_its_get(psa_storage_uid_t uid,
                                       uint32_t data_offset,
                                       uint32_t data_length,
                                       void *p_data,
                                       size_t *p_data_length)
{
    (void) uid;
    (void) data_offset;
    (void) data_length;
    (void) p_data;
    (void) p_data_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

static inline psa_status_t psa_its_get_info(psa_storage_uid_t uid,
                                            struct psa_storage_info_t *p_info)
{
    (void) uid;
    (void) p_info;
    return PSA_ERROR_NOT_SUPPORTED;
}

static inline psa_status_t psa_its_remove(psa_storage_uid_t uid)
{
    (void) uid;
    return PSA_ERROR_NOT_SUPPORTED;
}

#endif /* PSA_ITS_FAKE_INTERNAL_TRUSTED_STORAGE_H */
