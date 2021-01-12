/** \file psa_crypto_helpers.c
 *
 * \brief Helper functions to test PSA crypto functionality.
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

#include <test/helpers.h>
#include <test/macros.h>
#include <test/psa_crypto_helpers.h>

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include <psa/crypto.h>

const char *mbedtls_test_helper_is_psa_leaking( void )
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

#if defined(RECORD_PSA_STATUS_COVERAGE_LOG)
/** Name of the file where return statuses are logged by #RECORD_STATUS. */
#define STATUS_LOG_FILE_NAME "statuses.log"

psa_status_t mbedtls_test_record_status( psa_status_t status,
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
#endif /* defined(RECORD_PSA_STATUS_COVERAGE_LOG) */

#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
#include <test/random.h>

static int test_insecure_external_rng_enabled = 0;

void mbedtls_test_enable_insecure_external_rng( void )
{
    test_insecure_external_rng_enabled = 1;
}

void mbedtls_test_disable_insecure_external_rng( void )
{
    test_insecure_external_rng_enabled = 0;
}

psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context,
    uint8_t *output, size_t output_size, size_t *output_length )
{
    (void) context;

    if( !test_insecure_external_rng_enabled )
        return( PSA_ERROR_INSUFFICIENT_ENTROPY );

    /* This implementation is for test purposes only!
     * Use the libc non-cryptographic random generator. */
    mbedtls_test_rnd_std_rand( NULL, output, output_size );
    *output_length = output_size;
    return( PSA_SUCCESS );
}
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

#endif /* MBEDTLS_PSA_CRYPTO_C */
