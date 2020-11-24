/*
 * Helper functions for tests that use the PSA Crypto API.
 */
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

#ifndef PSA_CRYPTO_HELPERS_H
#define PSA_CRYPTO_HELPERS_H

#include "test/psa_helpers.h"

#include <psa/crypto.h>
#include <psa_crypto_slot_management.h>

/** Check for things that have not been cleaned up properly in the
 * PSA subsystem.
 *
 * \return NULL if nothing has leaked.
 * \return A string literal explaining what has not been cleaned up
 *         if applicable.
 */
const char *mbedtls_test_helper_is_psa_leaking( void );

/** Check that no PSA Crypto key slots are in use.
 */
#define ASSERT_PSA_PRISTINE( )                                  \
    TEST_ASSERT( ! mbedtls_test_helper_is_psa_leaking( ) )

/** Shut down the PSA Crypto subsystem. Expect a clean shutdown, with no slots
 * in use.
 */
#define PSA_DONE( )                                     \
    do                                                  \
    {                                                   \
        ASSERT_PSA_PRISTINE( );                         \
        mbedtls_psa_crypto_free( );                     \
    }                                                   \
    while( 0 )



#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
/** Enable the insecure implementation of mbedtls_psa_external_get_random().
 *
 * The insecure implementation of mbedtls_psa_external_get_random() is
 * disabled by default.
 *
 * When MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG is enabled and the test
 * helpers are linked into a program, you must enable this before any code
 * that uses the PSA subsystem to generate random data (including internal
 * random generation for purposes such as blinding when the random generation
 * is routed through PSA).
 *
 * You can enable and disable it at any time, regardless of the state
 * of the PSA subsystem. You may disable it temporarily to simulate a
 * depleted entropy source.
 */
void mbedtls_test_enable_insecure_external_rng( void );

/** Disable the insecure implementation of mbedtls_psa_external_get_random().
 *
 * See mbedtls_test_enable_insecure_external_rng().
 */
void mbedtls_test_disable_insecure_external_rng( void );
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */


#if defined(RECORD_PSA_STATUS_COVERAGE_LOG)
psa_status_t mbedtls_test_record_status( psa_status_t status,
                                         const char *func,
                                         const char *file, int line,
                                         const char *expr );

/** Return value logging wrapper macro.
 *
 * Evaluate \p expr. Write a line recording its value to the log file
 * #STATUS_LOG_FILE_NAME and return the value. The line is a colon-separated
 * list of fields:
 * ```
 * value of expr:string:__FILE__:__LINE__:expr
 * ```
 *
 * The test code does not call this macro explicitly because that would
 * be very invasive. Instead, we instrument the source code by defining
 * a bunch of wrapper macros like
 * ```
 * #define psa_crypto_init() RECORD_STATUS("psa_crypto_init", psa_crypto_init())
 * ```
 * These macro definitions must be present in `instrument_record_status.h`
 * when building the test suites.
 *
 * \param string    A string, normally a function name.
 * \param expr      An expression to evaluate, normally a call of the function
 *                  whose name is in \p string. This expression must return
 *                  a value of type #psa_status_t.
 * \return          The value of \p expr.
 */
#define RECORD_STATUS( string, expr )                                   \
    mbedtls_test_record_status( ( expr ), string, __FILE__, __LINE__, #expr )

#include "instrument_record_status.h"

#endif /* defined(RECORD_PSA_STATUS_COVERAGE_LOG) */

#endif /* PSA_CRYPTO_HELPERS_H */
