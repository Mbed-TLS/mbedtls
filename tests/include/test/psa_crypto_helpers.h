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
static const char *mbedtls_test_helper_is_psa_leaking( void )
{
    mbedtls_psa_stats_t stats;

    mbedtls_psa_get_stats( &stats );

    if( stats.volatile_slots != 0 )
        return( "A volatile slot has not been closed properly." );
    if( stats.persistent_slots != 0 )
        return( "A persistent slot has not been closed properly." );
    if( stats.external_slots != 0 )
        return( "An external slot has not been closed properly." );
     if( stats.half_filled_slots != 0 )
        return( "A half-filled slot has not been cleared properly." );
    if( stats.locked_slots != 0 )
        return( "Some slots are still marked as locked." );

    return( NULL );
}

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



#if defined(RECORD_PSA_STATUS_COVERAGE_LOG)
#include <psa/crypto.h>

/** Name of the file where return statuses are logged by #RECORD_STATUS. */
#define STATUS_LOG_FILE_NAME "statuses.log"

static psa_status_t mbedtls_test_record_status( psa_status_t status,
                                                const char *func,
                                                const char *file, int line,
                                                const char *expr )
{
    /* We open the log file on first use.
     * We never close the log file, so the record_status feature is not
     * compatible with resource leak detectors such as Asan.
     */
    static FILE *log;
    if( log == NULL )
        log = fopen( STATUS_LOG_FILE_NAME, "a" );
    fprintf( log, "%d:%s:%s:%d:%s\n", (int) status, func, file, line, expr );
    return( status );
}

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
