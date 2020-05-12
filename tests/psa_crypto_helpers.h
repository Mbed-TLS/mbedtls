/*
 * Helper functions for tests that use the PSA Crypto API.
 */
/*  Copyright (C) 2019, ARM Limited, All Rights Reserved
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

#ifndef PSA_CRYPTO_HELPERS_H
#define PSA_CRYPTO_HELPERS_H

#include "psa_helpers.h"

#include <psa/crypto.h>

static int test_helper_is_psa_pristine( int line, const char *file )
{
    mbedtls_psa_stats_t stats;
    const char *msg = NULL;

    mbedtls_psa_get_stats( &stats );

    if( stats.volatile_slots != 0 )
        msg = "A volatile slot has not been closed properly.";
    else if( stats.persistent_slots != 0 )
        msg = "A persistent slot has not been closed properly.";
    else if( stats.external_slots != 0 )
        msg = "An external slot has not been closed properly.";
    else if( stats.half_filled_slots != 0 )
        msg = "A half-filled slot has not been cleared properly.";

    /* If the test has already failed, don't overwrite the failure
     * information. Do keep the stats lookup above, because it can be
     * convenient to break on it when debugging a failure. */
    if( msg != NULL && test_info.result == TEST_RESULT_SUCCESS )
        test_fail( msg, line, file );

    return( msg == NULL );
}

/** Check that no PSA Crypto key slots are in use.
 */
#define ASSERT_PSA_PRISTINE( )                                    \
    do                                                            \
    {                                                             \
        if( ! test_helper_is_psa_pristine( __LINE__, __FILE__ ) ) \
            goto exit;                                            \
    }                                                             \
    while( 0 )

static void test_helper_psa_done( int line, const char *file )
{
    (void) test_helper_is_psa_pristine( line, file );
    mbedtls_psa_crypto_free( );
}

/** Shut down the PSA Crypto subsystem. Expect a clean shutdown, with no slots
 * in use.
 */
#define PSA_DONE( ) test_helper_psa_done( __LINE__, __FILE__ )



#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS)

#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"

/* If non-null, on success, copy this to the output. */
void *test_driver_forced_output = NULL;
size_t test_driver_forced_output_length = 0;

psa_status_t test_transparent_signature_sign_hash_status = PSA_ERROR_NOT_SUPPORTED;
unsigned long test_transparent_signature_sign_hash_hit = 0;
psa_status_t test_transparent_signature_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{
    ++test_transparent_signature_sign_hash_hit;

    if( test_transparent_signature_sign_hash_status != PSA_SUCCESS )
        return( test_transparent_signature_sign_hash_status );

    if( test_driver_forced_output != NULL )
    {
        if( test_driver_forced_output_length > signature_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( signature, test_driver_forced_output,
                test_driver_forced_output_length );
        *signature_length = test_driver_forced_output_length;
        return( PSA_SUCCESS );
    }

    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
    defined(MBEDTLS_SHA256_C)
    if( alg != PSA_ALG_DETERMINISTIC_ECDSA( PSA_ALG_SHA_256 ) )
        return( PSA_ERROR_NOT_SUPPORTED );
    mbedtls_ecp_group_id grp_id;
    switch( psa_get_key_type( attributes ) )
    {
        case PSA_ECC_CURVE_SECP_R1:
            switch( psa_get_key_bits( attributes ) )
            {
                case 256:
                    grp_id = MBEDTLS_ECP_DP_SECP256R1;
                    break;
                case 384:
                    grp_id = MBEDTLS_ECP_DP_SECP384R1;
                    break;
                case 521:
                    grp_id = MBEDTLS_ECP_DP_SECP521R1;
                    break;
                default:
                    return( PSA_ERROR_NOT_SUPPORTED );
            }
            break;
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    /* Beyond this point, the driver is actually doing the work of
     * calculating the signature. */

    status = PSA_ERROR_GENERIC_ERROR;
    int ret = 0;
    mbedtls_mpi r, s;
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );
    mbedtls_ecp_keypair ecp;
    mbedtls_ecp_keypair_init( &ecp );
    size_t curve_bytes = PSA_BITS_TO_BYTES( ecp.grp.pbits );

    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &ecp.grp, grp_id ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_read_binary( &ecp.grp, &ecp.Q,
                                                    key, key_length ) );

    /* Code adapted from psa_ecdsa_sign() in psa_crypto.c. */
    mbedtls_md_type_t md_alg = MBEDTLS_MD_SHA256;
    if( signature_size < 2 * curve_bytes )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }
    MBEDTLS_MPI_CHK( mbedtls_ecdsa_sign_det( &ecp.grp, &r, &s, &ecp.d,
                                  hash, hash_length, md_alg ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &r,
                                               signature,
                                               curve_bytes ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &s,
                                               signature + curve_bytes,
                                               curve_bytes ) );
cleanup:
    /* There's no easy way to translate the error code except through a
     * library function that's not exported. Use a debugger. */
    if( ret == 0 )
        status = PSA_SUCCESS;
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    mbedtls_ecp_keypair_free( &ecp );
    if( status == PSA_SUCCESS )
        *signature_length = 2 * curve_bytes;
#else /* defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
         defined(MBEDTLS_SHA256_C) */
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
#endif /* defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
          defined(MBEDTLS_SHA256_C) */

    return( status );
}

psa_status_t test_opaque_signature_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}
#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS */



#if defined(RECORD_PSA_STATUS_COVERAGE_LOG)
#include <psa/crypto.h>

/** Name of the file where return statuses are logged by #RECORD_STATUS. */
#define STATUS_LOG_FILE_NAME "statuses.log"

static psa_status_t record_status( psa_status_t status,
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
    record_status( ( expr ), string, __FILE__, __LINE__, #expr )

#include "instrument_record_status.h"

#endif /* defined(RECORD_PSA_STATUS_COVERAGE_LOG) */

#endif /* PSA_CRYPTO_HELPERS_H */
