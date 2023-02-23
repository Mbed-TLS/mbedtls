/*
 * Test driver for PAKE driver entry points.
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

#ifndef PSA_CRYPTO_TEST_DRIVERS_PAKE_H
#define PSA_CRYPTO_TEST_DRIVERS_PAKE_H

#include "mbedtls/build_info.h"

#if defined(PSA_CRYPTO_DRIVER_TEST)
#include <psa/crypto_driver_common.h>

typedef struct {
    /* If not PSA_SUCCESS, return this error code instead of processing the
     * function call. */
    psa_status_t forced_status;
    /* PAKE driver setup is executed on the first call to
       pake_output/pake_input (added to distinguish forced statuses). */
    psa_status_t forced_setup_status;
    /* Count the amount of times PAKE driver functions are called. */
    struct {
        unsigned long total;
        unsigned long setup;
        unsigned long input;
        unsigned long output;
        unsigned long implicit_key;
        unsigned long abort;
    } hits;
    /* Status returned by the last PAKE driver function call. */
    psa_status_t driver_status;
    /* Output returned by pake_output */
    void *forced_output;
    size_t forced_output_length;
} mbedtls_test_driver_pake_hooks_t;

#define MBEDTLS_TEST_DRIVER_PAKE_INIT { PSA_SUCCESS, PSA_SUCCESS, { 0, 0, 0, 0, 0, 0 }, PSA_SUCCESS, \
                                        NULL, 0 }
static inline mbedtls_test_driver_pake_hooks_t
mbedtls_test_driver_pake_hooks_init(void)
{
    const mbedtls_test_driver_pake_hooks_t v = MBEDTLS_TEST_DRIVER_PAKE_INIT;
    return v;
}

extern mbedtls_test_driver_pake_hooks_t mbedtls_test_driver_pake_hooks;

psa_status_t mbedtls_test_transparent_pake_setup(
    mbedtls_transparent_test_driver_pake_operation_t *operation,
    const psa_crypto_driver_pake_inputs_t *inputs);

psa_status_t mbedtls_test_transparent_pake_output(
    mbedtls_transparent_test_driver_pake_operation_t *operation,
    psa_crypto_driver_pake_step_t step,
    uint8_t *output,
    size_t output_size,
    size_t *output_length);

psa_status_t mbedtls_test_transparent_pake_input(
    mbedtls_transparent_test_driver_pake_operation_t *operation,
    psa_crypto_driver_pake_step_t step,
    const uint8_t *input,
    size_t input_length);

psa_status_t mbedtls_test_transparent_pake_get_implicit_key(
    mbedtls_transparent_test_driver_pake_operation_t *operation,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t mbedtls_test_transparent_pake_abort(
    mbedtls_transparent_test_driver_pake_operation_t *operation);

#endif /* PSA_CRYPTO_DRIVER_TEST */
#endif /* PSA_CRYPTO_TEST_DRIVERS_PAKE_H */
