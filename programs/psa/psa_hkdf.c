/*
 *  The example demonstrates a key derivation function using the PSA Crypto
 *  API. In particular, the use of the HMAC-based Extract-and-Expand Key
 *  Derivation Function (HKDF) is described, which is defined in [RFC5869].
 *  HKDF is a popular key derivation algorithm used in modern cryptographic
 *  protocols, such as TLS 1.3.
 *
 *  HKDF requires several inputs, namely
 *   - input keying material (IKM),
 *   - a salt, and
 *   - an info string.
 *
 *  After calling the psa_key_derivation_setup(), the three inputs need to
 *  be processed with psa_key_derivation_input_bytes() (for salt and info)
 *  and psa_key_derivation_input_key() (for the IKM).
 *  psa_key_derivation_output_bytes() then derives the output keying
 *  material (OKM). Finally, the psa_key_derivation_abort() performs a
 *  clean-up of the key derivation operation object.
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
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;

    /* Example test vector from RFC 5869 */

    /* Input keying material (IKM) */
    unsigned char ikm[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

    unsigned char salt[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };

    /* Context and application specific information, which can be of zero length */
    unsigned char info[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };

    /* Expected OKM based on the RFC 5869-provided test vector */
    unsigned char expected_okm[] = { 0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43,
                                     0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90,
                                     0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
                                     0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
                                     0x58, 0x65 };

    /* The output size of the HKDF function depends on the hash function used.
     * In our case we use SHA-256, which produces a 32 byte fingerprint.
     * Therefore, we allocate a buffer of 32 bytes to hold the output keying
     * material (OKM).
     */
    unsigned char output[32];

    psa_algorithm_t alg = PSA_ALG_HKDF( PSA_ALG_SHA_256 );

    printf( "PSA Crypto API: HKDF SHA-256 example\n\n" );

    status = psa_crypto_init( );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_crypto_init failed\n" );
        return( EXIT_FAILURE );
    }

    psa_set_key_usage_flags( &attributes, PSA_KEY_USAGE_DERIVE );
    psa_set_key_algorithm( &attributes, PSA_ALG_HKDF( PSA_ALG_SHA_256 ) );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_DERIVE );

    status = psa_import_key( &attributes, ikm, sizeof( ikm ), &key_id );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_import_key failed\n" );
        return( EXIT_FAILURE );
    }

    status = psa_key_derivation_setup( &operation, alg );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_key_derivation_setup failed" );
        return( EXIT_FAILURE );
    }

    status = psa_key_derivation_input_bytes( &operation, PSA_KEY_DERIVATION_INPUT_SALT,
                                             salt, sizeof( salt ) );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_key_derivation_input_bytes (salt) failed" );
        return( EXIT_FAILURE );
    }

    status = psa_key_derivation_input_key( &operation, PSA_KEY_DERIVATION_INPUT_SECRET,
                                           key_id );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_key_derivation_input_key failed" );
        return( EXIT_FAILURE );
    }

    status = psa_key_derivation_input_bytes( &operation, PSA_KEY_DERIVATION_INPUT_INFO,
                                             info, sizeof( info ) );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_key_derivation_input_bytes (info) failed" );
        return( EXIT_FAILURE );
    }

    status = psa_key_derivation_output_bytes( &operation, output, sizeof( output ) );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_key_derivation_output_bytes failed" );
        return( EXIT_FAILURE );
    }

    status = psa_key_derivation_abort( &operation );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_key_derivation_abort failed" );
        return( EXIT_FAILURE );
    }

    printf( "OKM: \n");

    for( size_t j = 0; j < sizeof( output ); j++ )
    {
        if ( output[j] != expected_okm[j] )
        {
            printf( "\n --- Unexpected outcome!\n" );
            return( EXIT_FAILURE );
        }

        if( j % 8 == 0 ) printf( "\n    " );
        printf( "%02x ", output[j] );
    }

    printf( "\n" );
    return( EXIT_SUCCESS );
}
#endif /* MBEDTLS_PSA_CRYPTO_C && MBEDTLS_SHA256_C */
