/*
 *  RSA simple data encryption program
 *
 *  Copyright (C) 2006-2011, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include <string.h>
#include <stdio.h>

#include "polarssl/error.h"
#include "polarssl/pk.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_PK_PARSE_C) ||  \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_FS_IO) || \
    !defined(POLARSSL_CTR_DRBG_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    printf("POLARSSL_BIGNUM_C and/or POLARSSL_PK_PARSE_C and/or "
           "POLARSSL_ENTROPY_C and/or POLARSSL_FS_IO and/or "
           "POLARSSL_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    int ret;
    size_t i, olen = 0;
    pk_context pk;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    unsigned char input[1024];
    unsigned char buf[512];
    const char *pers = "pk_encrypt";

    ret = 1;

    if( argc != 3 )
    {
        printf( "usage: pk_encrypt <key_file> <string of max 100 characters>\n" );

#if defined(_WIN32)
        printf( "\n" );
#endif

        goto exit;
    }

    printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! ctr_drbg_init returned -0x%04x\n", -ret );
        goto exit;
    }

    printf( "\n  . Reading public key from '%s'", argv[1] );
    fflush( stdout );

    pk_init( &pk );

    if( ( ret = pk_parse_public_keyfile( &pk, argv[1] ) ) != 0 )
    {
        printf( " failed\n  ! pk_parse_public_keyfile returned -0x%04x\n", -ret );
        goto exit;
    }

    if( strlen( argv[2] ) > 100 )
    {
        printf( " Input data larger than 100 characters.\n\n" );
        goto exit;
    }

    memcpy( input, argv[2], strlen( argv[2] ) );

    /*
     * Calculate the RSA encryption of the hash.
     */
    printf( "\n  . Generating the encrypted value" );
    fflush( stdout );

    if( ( ret = pk_encrypt( &pk, input, strlen( argv[2] ),
                            buf, &olen, sizeof(buf),
                            ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! pk_encrypt returned -0x%04x\n", -ret );
        goto exit;
    }

    /*
     * Write the signature into result-enc.txt
     */
    if( ( f = fopen( "result-enc.txt", "wb+" ) ) == NULL )
    {
        ret = 1;
        printf( " failed\n  ! Could not create %s\n\n", "result-enc.txt" );
        goto exit;
    }

    for( i = 0; i < olen; i++ )
        fprintf( f, "%02X%s", buf[i],
                 ( i + 1 ) % 16 == 0 ? "\r\n" : " " );

    fclose( f );

    printf( "\n  . Done (created \"%s\")\n\n", "result-enc.txt" );

exit:
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#if defined(POLARSSL_ERROR_C)
    polarssl_strerror( ret, (char *) buf, sizeof(buf) );
    printf( "  !  Last error was: %s\n", buf );
#endif

#if defined(_WIN32)
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_PK_PARSE_C && POLARSSL_ENTROPY_C &&
          POLARSSL_FS_IO && POLARSSL_CTR_DRBG_C */
