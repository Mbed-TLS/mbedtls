/*
 *  Example computing a SHA-256 hash using the PSA Crypto API
 *
 *  The example computes the SHA-256 hash of a test string using the
 *  one-shot API call psa_hash_compute() and the using multi-part
 *  operation, which requires psa_hash_setup(), psa_hash_update() and
 *  psa_hash_finish(). The multi-part operation is popular on embedded
 *  devices where a rolling hash needs to be computed.
 *
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


#include "psa/crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "mbedtls/build_info.h"

#define TEST_SHA256_HASH {                                                 \
   0x5a, 0x09, 0xe8, 0xfa, 0x9c, 0x77, 0x80, 0x7b, 0x24, 0xe9, 0x9c, 0x9c, \
   0xf9, 0x99, 0xde, 0xbf, 0xad, 0x84, 0x41, 0xe2, 0x69, 0xeb, 0x96, 0x0e, \
   0x20, 0x1f, 0x61, 0xfc, 0x3d, 0xe2, 0x0d, 0x5a                          \
}

const uint8_t mbedtls_test_sha256_hash[] = TEST_SHA256_HASH;

const size_t mbedtls_test_sha256_hash_len =
    sizeof( mbedtls_test_sha256_hash );

#if !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(MBEDTLS_SHA256_C)
int main( void )
{
    printf( "MBEDTLS_PSA_CRYPTO_C and MBEDTLS_SHA256_C"
            "not defined.\r\n" );
    return( EXIT_SUCCESS );
}
#else

int main( void )
{
    uint8_t buf[] = "Hello World!";
    psa_status_t status;
    uint8_t hash[PSA_HASH_MAX_SIZE];
    size_t hash_size;
    psa_hash_operation_t sha256_psa = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t cloned_sha256 = PSA_HASH_OPERATION_INIT;

    printf( "PSA Crypto API: SHA-256 example\n\n" );

    status = psa_crypto_init( );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_crypto_init failed\n" );
        return( EXIT_FAILURE );
    }


    /* Compute hash using multi-part operation */

    status = psa_hash_setup( &sha256_psa, PSA_ALG_SHA_256 );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_hash_setup failed\n" );
        return( EXIT_FAILURE );
    }

    status = psa_hash_update( &sha256_psa, buf, sizeof( buf ) );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_hash_update failed\n" );
        return( EXIT_FAILURE );
    }

    status = psa_hash_clone( &sha256_psa, &cloned_sha256 );
    if( status != PSA_SUCCESS )
    {
        printf( "PSA hash clone failed" );
        return( EXIT_FAILURE );
    }

    status = psa_hash_finish( &sha256_psa, hash, sizeof( hash ), &hash_size );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_hash_finish failed\n" );
        return( EXIT_FAILURE );
    }

    status = psa_hash_verify( &cloned_sha256, mbedtls_test_sha256_hash, mbedtls_test_sha256_hash_len );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_hash_verify failed\n" );
        return( EXIT_FAILURE );
    } else
    {
        printf( "Multi-part hash operation successful!\n");
    }

    /* Compute hash using one-shot function call */
    memset( hash,0,sizeof( hash ) );
    hash_size = 0;

    status = psa_hash_compute( PSA_ALG_SHA_256,
                               buf, sizeof( buf ),
                               hash, sizeof( hash ),
                               &hash_size );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_hash_compute failed\n" );
        return( EXIT_FAILURE );
    }

    for( size_t j = 0; j < mbedtls_test_sha256_hash_len; j++ )
    {
        if( hash[j] != mbedtls_test_sha256_hash[j] )
        {
            printf( "One-shot hash operation failed!\n\n");
            return( EXIT_FAILURE );
        }
    }

    printf( "One-shot hash operation successful!\n\n");

    printf( "The SHA-256( '%s' ) is:\n", buf );

    for( size_t j = 0; j < mbedtls_test_sha256_hash_len; j++ )
    {
        if( j % 8 == 0 ) printf( "\n    " );
        printf( "%02x ", hash[j] );
    }

    printf( "\n" );

    mbedtls_psa_crypto_free( );
    return( EXIT_SUCCESS );
}
#endif /* MBEDTLS_PSA_CRYPTO_C && MBEDTLS_SHA256_C */
