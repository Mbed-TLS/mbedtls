/*
 *  Example illustrating random number generation using the PSA
 *  Crypto API.
 *
 *  Random number generation is probably one of the simplest operation
 *  from a developers point of view since only a single API call is needed,
 *  namely psa_generate_random().
 *
 *  Unfortunately, many operating systems available for embedded systems do
 *  not offer developers an integration with the required hardware randomness
 *  source. Hence, an embedded developer needs to use the hooks offered by
 *  the PSA Crypto API to integrate a hardware entropy source. This example
 *  offers the skeleton of this integration with the C-processor directive
 *  MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG.
 *
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


#include "mbedtls/build_info.h"

#include <psa/crypto.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "mbedtls/entropy.h"

#define BUFFER_SIZE 100

#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
#include <mbedtls/psa_util.h>
#include <psa/crypto_platform.h>

typedef mbedtls_psa_external_random_context_t mbedtls_psa_random_context_t;


typedef struct
{
    mbedtls_psa_random_context_t rng;
    unsigned initialized : 1;
    unsigned rng_state : 2;
} psa_global_data_t;

static psa_global_data_t global_data;

psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context,
    uint8_t *output, size_t output_size, size_t *output_length )
{
    (void) context;
    size_t i;

    /* This implementation is for test purposes only! */
    for( i = 0; i < output_size; ++i )
        output[i] = '\0';

    *output_length = output_size;
    return( PSA_SUCCESS );
}
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

#if !defined(MBEDTLS_PSA_CRYPTO_C)
int main( void )
{
    printf( "MBEDTLS_PSA_CRYPTO_C not defined.\r\n" );
    return( 0 );
}
#else
int main( void )
{
    psa_status_t status;
    uint8_t output[BUFFER_SIZE] = {0};

    status = psa_crypto_init( );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_crypto_init failed\n" );
        return( EXIT_FAILURE );
    }
#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
    size_t output_length = 0;
    status = mbedtls_psa_external_get_random( &global_data.rng,
                                              output, output_size,
                                              &output_length );

    status = mbedtls_psa_external_get_random ( output, BUFFER_SIZE );
    if( status != PSA_SUCCESS )
    {
        printf( "mbedtls_psa_external_get_random failed\n" );
        return( EXIT_FAILURE );
    }

#else
    status = psa_generate_random( output, BUFFER_SIZE );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_generate_random failed\n" );
        return( EXIT_FAILURE );
    }
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

    printf( "Random bytes generated:\n" );

    for( size_t j = 0; j < BUFFER_SIZE; j++ )
    {
        if( j % 8 == 0 ) printf( "\n    " );
        printf( "%02x ", output[j] );
    }

    printf( "\n" );

    mbedtls_psa_crypto_free( );
    return( 0 );
}
#endif /* MBEDTLS_PSA_CRYPTO_C */
