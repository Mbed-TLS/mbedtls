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

#endif /* PSA_CRYPTO_HELPERS_H */
