/** \file psa_driver_facilities.c
 *
 * \brief Sanity checks for basic psa/crypto_driver.h functionality.
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

#include <test/psa_crypto_driver.h>

/* Include enough for TEST_ASSERT and friends. Do not include anything that
 * includes <psa/crypto.h>, so that if this file compiles successfully, it
 * validates that <psa/crypto_driver.h> can stand on its own. */
#include <test/helpers.h>

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS)

#if defined(PSA_CRYPTO_H)
#error "This file includes <psa/crypto.h> indirectly, which makes it inconclusive as a test for the autonomy of <psa/crypto_driver.h>."
#endif

int mbedtls_test_psa_crypto_driver_basics( void )
{
    int ok = 0;

    /* Check the availability of a few definitions */
    psa_algorithm_t alg_sha256 = PSA_ALG_SHA_256;
    ASSERT_EQUAL( alg_sha256, 0x02000009 );
    TEST_ASSERT( PSA_ALG_IS_HASH( alg_sha256 ) );

    ok = 1;
exit:
    return( ok );
}

#endif  /* MBEDTLS_PSA_CRYPTO_DRIVERS */
