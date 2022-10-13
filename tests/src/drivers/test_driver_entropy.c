/*
 * Test driver for entropy.
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

#include <test/helpers.h>

#if defined(MBEDTLS_ENTROPY_PSA) && defined(PSA_CRYPTO_DRIVER_TEST)
#include "test/drivers/entropy.h"
#include <test/random.h>
#include <psa/crypto.h>
#include "../library/psa_crypto_driver_wrappers.h"

static size_t entropy_available = 0;
static int limited_entropy_calls = 0;

void mbedtls_test_set_insecure_psa_crypto_entropy( size_t entropy, int calls )
{
    entropy_available = entropy;
    limited_entropy_calls = calls;
}


psa_status_t mbedtls_test_psa_driver_get_entropy( uint32_t flags,
    size_t *estimate_bits, uint8_t *output, size_t output_size )
{
    if ( !(flags & PSA_DRIVER_GET_ENTROPY_BLOCK) )
        return( PSA_ERROR_INSUFFICIENT_ENTROPY );
    if ( limited_entropy_calls ) {
        if( !entropy_available )
            return( PSA_ERROR_INSUFFICIENT_ENTROPY );

        if( entropy_available < output_size * 8 ) {
            *estimate_bits = entropy_available;
        } else {
            *estimate_bits = output_size * 8;
        }

        entropy_available -= *estimate_bits;
        output_size = (*estimate_bits + 7) / 8;
        limited_entropy_calls--;
    } else {
        *estimate_bits = output_size * 8;
    }

    /* This implementation is for test purposes only!
     * Use the libc non-cryptographic random generator. */
    mbedtls_test_rnd_std_rand( NULL, output, output_size );
    return( PSA_SUCCESS );
}

#endif /* MBEDTLS_ENTROPY_PSA && PSA_CRYPTO_DRIVER_TEST */
