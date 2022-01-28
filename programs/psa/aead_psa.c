/*
 * This is a simple example of multi-part AEAD computation using the PSA
 * Crypto API. It comes with a companion program aead_non_psa.c, which does
 * the same operations with the legacy Cipher API. The goal is that comparing the
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
 * When used with multi-part AEAD operations, the `mbedtls_cipher_context`
 * serves a triple purpose (1) hold the key, (2) store the algorithm when no
 * operation is active, and (3) save progress information for the current
 * operation. With PSA those roles are held by disinct objects: (1) a
 * psa_key_id_t to hold the key, a (2) psa_algorithm_t to represent the
 * algorithm, and (3) a psa_operation_t for multi-part progress.
 *
 * On the other hand, with PSA, the algorithms encodes the desired tag length;
 * with Cipher the desired tag length needs to be tracked separately.
 *
 * This program and its compation aead_non_psa.c illustrate this by doing the
 * same sequence of multi-part AEAD computation with both APIs; looking at the
 * two side by side should make the differences and similarities clear.
 */

#include <stdio.h>

#include "mbedtls/build_info.h"

#if !defined(MBEDTLS_PSA_CRYPTO_C) || \
    !defined(MBEDTLS_AES_C) || !defined(MBEDTLS_GCM_C) || \
    !defined(MBEDTLS_CHACHAPOLY_C) || \
    defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
int main( void )
{
    printf( "MBEDTLS_PSA_CRYPTO_C and/or "
            "MBEDTLS_AES_C and/or MBEDTLS_GCM_C and/or "
            "MBEDTLS_CHACHAPOLY_C not defined, and/or "
            "MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER defined\r\n" );
    return( 0 );
}
#else

#include <string.h>

#include "psa/crypto.h"

/*
 * Dummy data and helper functions
 */
const char usage[] = "Usage: aead_psa [aes128-gcm|aes256-gcm|aes128-gcm_8|chachapoly]";

const unsigned char iv1[12] = { 0x00 };
const unsigned char add_data1[] = { 0x01, 0x02 };
const unsigned char msg1_part1[] = { 0x03, 0x04 };
const unsigned char msg1_part2[] = { 0x05, 0x06, 0x07 };

const unsigned char iv2[12] = { 0x10 };
const unsigned char add_data2[] = { 0x11, 0x12 };
const unsigned char msg2_part1[] = { 0x13, 0x14 };
const unsigned char msg2_part2[] = { 0x15, 0x16, 0x17 };

#define MSG_MAX_SIZE 5

const unsigned char key_bytes[32] = { 0x2a };

void print_out( const char *title, unsigned char *out, size_t len )
{
    printf( "%s:", title );
    for( size_t i = 0; i < len; i++ )
        printf( " %02x", out[i] );
    printf( "\n" );
}

#define CHK( code )     \
    do {                \
        status = code;     \
        if( status != PSA_SUCCESS ) { \
            printf( "%03d: status = %d\n", __LINE__, status ); \
            goto exit;  \
        } \
    } while( 0 )

static psa_status_t aead_prepare( const char *info,
                                  psa_key_id_t *key,
                                  psa_algorithm_t *alg )
{
    psa_status_t status;

    size_t key_bits;
    psa_key_type_t key_type;
    if( strcmp( info, "aes128-gcm" ) == 0 ) {
        *alg = PSA_ALG_GCM;
        key_bits = 128;
        key_type = PSA_KEY_TYPE_AES;
    } else if( strcmp( info, "aes256-gcm" ) == 0 ) {
        *alg = PSA_ALG_GCM;
        key_bits = 256;
        key_type = PSA_KEY_TYPE_AES;
    } else if( strcmp( info, "aes128-gcm_8" ) == 0 ) {
        *alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 8);
        key_bits = 128;
        key_type = PSA_KEY_TYPE_AES;
    } else if( strcmp( info, "chachapoly" ) == 0 ) {
        *alg = PSA_ALG_CHACHA20_POLY1305;
        key_bits = 256;
        key_type = PSA_KEY_TYPE_CHACHA20;
    } else {
        puts( usage );
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags( &attributes, PSA_KEY_USAGE_ENCRYPT );
    psa_set_key_algorithm( &attributes, *alg );
    psa_set_key_type( &attributes, key_type );
    psa_set_key_bits( &attributes, key_bits );

    CHK( psa_import_key( &attributes, key_bytes, key_bits / 8, key ) );

exit:
    return( status );
}

static void aead_info( psa_key_id_t key, psa_algorithm_t alg )
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    (void) psa_get_key_attributes( key, &attr );
    psa_key_type_t key_type = psa_get_key_type( &attr );
    size_t key_bits = psa_get_key_bits( &attr );
    psa_algorithm_t base_alg = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG( alg );
    size_t tag_len = PSA_AEAD_TAG_LENGTH( key_type, key_bits, alg );

    const char *type_str = key_type == PSA_KEY_TYPE_AES ? "AES"
                         : key_type == PSA_KEY_TYPE_CHACHA20 ? "Chacha"
                         : "???";
    const char *base_str = base_alg == PSA_ALG_GCM ? "GCM"
                         : base_alg == PSA_ALG_CHACHA20_POLY1305 ? "ChachaPoly"
                         : "???";

    printf( "%s, %u, %s, %u\n",
            type_str, (unsigned) key_bits, base_str, (unsigned) tag_len );
}

static int aead_encrypt( psa_key_id_t key, psa_algorithm_t alg,
        const unsigned char *iv, size_t iv_len,
        const unsigned char *ad, size_t ad_len,
        const unsigned char *pa, size_t pa_len,
        const unsigned char *pb, size_t pb_len )
{
    psa_status_t status;
    size_t olen, olen_tag;
    unsigned char out[PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(MSG_MAX_SIZE)];
    unsigned char *p = out, *end = out + sizeof( out );
    unsigned char tag[PSA_AEAD_TAG_MAX_SIZE];

    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    CHK( psa_aead_encrypt_setup( &op, key, alg ) );

    CHK( psa_aead_set_nonce( &op, iv, iv_len ) );
    CHK( psa_aead_update_ad( &op, ad, ad_len ) );
    CHK( psa_aead_update( &op, pa, pa_len, p, end - p, &olen ) );
    p += olen;
    CHK( psa_aead_update( &op, pb, pb_len, p, end - p, &olen ) );
    p += olen;
    CHK( psa_aead_finish( &op, p, end - p, &olen,
                               tag, sizeof( tag ), &olen_tag ) );
    p += olen;
    memcpy( p, tag, olen_tag );
    p += olen_tag;

    olen = p - out;
    print_out( "out", out, olen );

exit:
    /* required on errors, harmless on success */
    psa_aead_abort( &op );
    return( status );
}

static psa_status_t aead_demo( const char *info )
{
    psa_status_t status;

    psa_key_id_t key;
    psa_algorithm_t alg;

    CHK( aead_prepare( info, &key, &alg ) );

    aead_info( key, alg );

    CHK( aead_encrypt( key, alg,
                       iv1, sizeof( iv1 ), add_data1, sizeof( add_data1 ),
                       msg1_part1, sizeof( msg1_part1 ),
                       msg1_part2, sizeof( msg1_part2 ) ) );
    CHK( aead_encrypt( key, alg,
                       iv2, sizeof( iv2 ), add_data2, sizeof( add_data2 ),
                       msg2_part1, sizeof( msg2_part1 ),
                       msg2_part2, sizeof( msg2_part2 ) ) );

exit:
    psa_destroy_key( key );

    return( status );
}

/*
 * Main function
 */
int main( int argc, char **argv )
{
    if( argc != 2 )
    {
        puts( usage );
        return( 1 );
    }

    psa_status_t status = psa_crypto_init();
    if( status != PSA_SUCCESS )
        printf( "psa init: %d\n", status );

    aead_demo( argv[1] );
}

#endif
