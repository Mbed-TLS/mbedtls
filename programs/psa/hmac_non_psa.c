/**
 * MD API multi-part HMAC demonstration.
 *
 * This programs computes the HMAC of two messages using the multi-part API.
 *
 * This is a companion to hmac_psa.c, doing the same operations with the
 * legacy MD API. The goal is that comparing the two programs will help people
 * migrating to the PSA Crypto API.
 *
 * When it comes to multi-part HMAC operations, the `mbedtls_md_context`
 * serves a dual purpose (1) hold the key, and (2) save progress information
 * for the current operation. With PSA those roles are held by two disinct
 * objects: (1) a psa_key_id_t to hold the key, and (2) a psa_operation_t for
 * multi-part progress.
 *
 * This program and its companion hmac_non_psa.c illustrate this by doing the
 * same sequence of multi-part HMAC computation with both APIs; looking at the
 * two side by side should make the differences and similarities clear.
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

/* First include Mbed TLS headers to get the Mbed TLS configuration and
 * platform definitions that we'll use in this program. Also include
 * standard C headers for functions we'll use here. */
#include "mbedtls/build_info.h"

#include "mbedtls/md.h"

#include <stdlib.h>
#include <stdio.h>

/* If the build options we need are not enabled, compile a placeholder. */
#if !defined(MBEDTLS_MD_C)
int main( void )
{
    printf( "MBEDTLS_MD_C not defined\r\n" );
    return( 0 );
}
#else

/* The real program starts here. */

/* Dummy inputs for HMAC */
const unsigned char msg1_part1[] = { 0x01, 0x02 };
const unsigned char msg1_part2[] = { 0x03, 0x04 };
const unsigned char msg2_part1[] = { 0x05, 0x05 };
const unsigned char msg2_part2[] = { 0x06, 0x06 };

/* Dummy key material - never do this in production!
 * This example program uses SHA-256, so a 32-byte key makes sense. */
const unsigned char key_bytes[32] = { 0 };

/* Buffer for the output - using SHA-256, so 32-byte output */
unsigned char out[32];

/* Print the contents of the output buffer in hex */
void print_out( const char *title )
{
    printf( "%s:", title );
    for( size_t i = 0; i < sizeof( out ); i++ )
        printf( " %02x", out[i] );
    printf( "\n" );
}

/* Run an Mbed TLS function and bail out if it fails. */
#define CHK( expr )                                             \
    do                                                          \
    {                                                           \
        ret = ( expr );                                         \
        if( ret != 0 )                                          \
        {                                                       \
            printf( "Error %d at line %d: %s\n",                \
                    ret,                                        \
                    __LINE__,                                   \
                    #expr );                                    \
            goto exit;                                          \
        }                                                       \
    } while( 0 )

/*
 * This function demonstrates computation of the HMAC of two messages using
 * the multipart API.
 */
int hmac_demo(void)
{
    int ret;
    mbedtls_md_context_t ctx;

    mbedtls_md_init( &ctx );

    /* prepare context and load key */
    CHK( mbedtls_md_setup( &ctx, mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), 1 ) );
    CHK( mbedtls_md_hmac_starts( &ctx, key_bytes, sizeof( key_bytes ) ) );

    /* compute HMAC(key, msg1_part1 | msg1_part2) */
    CHK( mbedtls_md_hmac_update( &ctx, msg1_part1, sizeof( msg1_part1 ) ) );
    CHK( mbedtls_md_hmac_update( &ctx, msg1_part2, sizeof( msg1_part2 ) ) );
    CHK( mbedtls_md_hmac_finish( &ctx, out ) );
    print_out( "msg1" );

    /* compute HMAC(key, msg2_part1 | msg2_part2) */
    CHK( mbedtls_md_hmac_reset( &ctx ) ); // prepare for new operation
    CHK( mbedtls_md_hmac_update( &ctx, msg2_part1, sizeof( msg2_part1 ) ) );
    CHK( mbedtls_md_hmac_update( &ctx, msg2_part2, sizeof( msg2_part2 ) ) );
    CHK( mbedtls_md_hmac_finish( &ctx, out ) );
    print_out( "msg2" );

exit:
    mbedtls_md_free( &ctx );

    return( ret );
}

int main(void)
{
    int ret;

    CHK( hmac_demo() );

exit:
    return( ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE );
}

#endif
