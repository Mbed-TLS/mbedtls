/*
 *  Declaration of context structures for use with the PSA driver wrapper
 *  interface.
 *
 *  Warning: This file will be auto-generated in the future.
 */
/*  Copyright The Mbed TLS Contributors
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

#ifndef PSA_CRYPTO_DRIVER_WRAPPERS_CONTEXTS_H
#define PSA_CRYPTO_DRIVER_WRAPPERS_CONTEXTS_H

#include "psa/crypto.h"
#include "psa/crypto_driver_common.h"

/* Include all structure definitions for the drivers that have been included
 * during the auto-generation of this file (autogeneration not yet in place) */
#if defined(PSA_CRYPTO_DRIVER_TEST)
#include "test/drivers/test_driver.h"
#endif

/* Include the structure definitions for the mbed TLS software drivers */
#include "psa_crypto_hash.h"

/* Define the context to be used for an operation that is executed through the
 * PSA Driver wrapper layer as the union of all possible driver's contexts.
 *
 * The union members are the driver's context structures, and the member names
 * are formatted as `'drivername'_ctx`. This allows for procedural generation
 * of both this file and the content of psa_crypto_driver_wrappers.c */

typedef union {
    unsigned dummy; /* Make sure this structure is always non-empty */
    mbedtls_psa_hash_operation_t mbedtls_ctx;
#if defined(PSA_CRYPTO_DRIVER_TEST)
    test_transparent_hash_operation_t test_ctx;
#endif
} psa_driver_hash_context_t;

#endif /* PSA_CRYPTO_DRIVER_WRAPPERS_CONTEXTS_H */
/* End of automatically generated file. */
