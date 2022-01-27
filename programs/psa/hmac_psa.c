/*
 * This is a simple example of multi-part HMAC computation using the PSA
 * Crypto API. It comes with a companion program hmac_non_psa.c, which does
 * the same operations with the legacy MD API. The goal is that comparing the
 * two programs will help people migrating to the PSA Crypto API.
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

/*
 * When in comes to multi-part HMAC operations, the `mbedtls_md_context`
 * serves a dual purpose (1) hold the key, and (2) save progress information
 * for the current operation. With PSA those roles are held by two disinct
 * objects: (1) a psa_key_id_t to hold the key, and (2) a psa_operation_t for
 * multi-part progress.
 *
 * This program and its companion hmac_non_psa.c illustrate this by doing the
 * same sequence of multi-part HMAC computation with both APIs; looking at the
 * two side by side should make the differences and similarities clear.
 */

#include <stdio.h>

#include "mbedtls/build_info.h"

#if !defined(MBEDTLS_PSA_CRYPTO_C) || \
    defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
int main( void )
{
    printf( "MBEDTLS_PSA_CRYPTO_C not defined, "
            "and/or MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER defined\r\n" );
    return( 0 );
}
#else

#include "psa/crypto.h"

/*
 * Dummy inputs for HMAC
 */
const unsigned char msg1_part1[] = { 0x01, 0x02 };
const unsigned char msg1_part2[] = { 0x03, 0x04 };
const unsigned char msg2_part1[] = { 0x05, 0x05 };
const unsigned char msg2_part2[] = { 0x06, 0x06 };

const unsigned char key_bytes[32] = { 0 };

unsigned char out[32];

void print_out( const char *title )
{
    printf( "%s:", title );
    for( size_t i = 0; i < sizeof( out ); i++ )
        printf( " %02x", out[i] );
    printf( "\n" );
}

#define CHK( code )     \
    do {                \
        status = code;     \
        if( status != PSA_SUCCESS )  \
            goto exit;  \
    } while( 0 )

psa_status_t hmac_demo(void)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    psa_algorithm_t alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);

    /* prepare key */
    psa_set_key_usage_flags( &attributes, PSA_KEY_USAGE_SIGN_MESSAGE );
    psa_set_key_algorithm( &attributes, alg );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_HMAC );
    psa_set_key_bits( &attributes, 8 * sizeof( key_bytes ) );

    status = psa_import_key( &attributes, key_bytes, sizeof( key_bytes ), &key );
    if( status != PSA_SUCCESS )
        return( status );

    /* prepare operation */
    psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
    size_t out_len = 0;

    /* compute HMAC(key, msg1_part1 | msg1_part2) */
    CHK( psa_mac_sign_setup( &op, key, alg ) );
    CHK( psa_mac_update( &op, msg1_part1, sizeof( msg1_part1 ) ) );
    CHK( psa_mac_update( &op, msg1_part2, sizeof( msg1_part2 ) ) );
    CHK( psa_mac_sign_finish( &op, out, sizeof( out ), &out_len ) );
    print_out( "msg1" );

    /* compute HMAC(key, msg2_part1 | msg2_part2) */
    CHK( psa_mac_sign_setup( &op, key, alg ) );
    CHK( psa_mac_update( &op, msg2_part1, sizeof( msg2_part1 ) ) );
    CHK( psa_mac_update( &op, msg2_part2, sizeof( msg2_part2 ) ) );
    CHK( psa_mac_sign_finish( &op, out, sizeof( out ), &out_len ) );
    print_out( "msg2" );

exit:
    psa_mac_abort( &op );
    psa_destroy_key( key );

    return( status );
}

int main(void)
{
    psa_status_t status = psa_crypto_init();
    if( status != PSA_SUCCESS )
        printf( "psa init: %d\n", status );

    status = hmac_demo();
    if( status != PSA_SUCCESS )
        printf( "hmac_demo: %d\n", status );
}

#endif
