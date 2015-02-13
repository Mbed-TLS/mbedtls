/*
 *  RSA/SHA-1 signature creation program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://polarssl.org)
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

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>

#include "polarssl/config.h"

#include "polarssl/rsa.h"
#include "polarssl/sha1.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/entropy.h"

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_RSA_C) ||  \
    !defined(POLARSSL_SHA1_C) || !defined(POLARSSL_FS_IO) ||    \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_CTR_DRBG_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    printf("POLARSSL_BIGNUM_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_SHA1_C and/or POLARSSL_FS_IO "
           "and/or POLARSSL_ENTROPY_C and/or POLARSSL_CTR_DRBG_C "
           "not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    int ret;
    size_t i;
    rsa_context rsa;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    unsigned char hash[20];
    unsigned char buf[POLARSSL_MPI_MAX_SIZE];
    const char *pers = "rsa_decrypt";

    ret = 1;

    if( argc != 2 )
    {
        printf( "usage: rsa_sign <filename>\n" );

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
        printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    printf( "\n  . Reading private key from rsa_priv.txt" );
    fflush( stdout );

    if( ( f = fopen( "rsa_priv.txt", "rb" ) ) == NULL )
    {
        ret = 1;
        printf( " failed\n  ! Could not open rsa_priv.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }

    rsa_init( &rsa, RSA_PKCS_V15, 0 );
    
    if( ( ret = mpi_read_file( &rsa.N , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.E , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.D , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.P , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.Q , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.DP, 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.DQ, 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.QP, 16, f ) ) != 0 )
    {
        printf( " failed\n  ! mpi_read_file returned %d\n\n", ret );
        goto exit;
    }

    rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;

    fclose( f );

    printf( "\n  . Checking the private key" );
    fflush( stdout );
    if( ( ret = rsa_check_privkey( &rsa ) ) != 0 )
    {
        printf( " failed\n  ! rsa_check_privkey failed with -0x%0x\n", -ret );
        goto exit;
    }

    /*
     * Compute the SHA-1 hash of the input file,
     * then calculate the RSA signature of the hash.
     */
    printf( "\n  . Generating the RSA/SHA-1 signature" );
    fflush( stdout );

    if( ( ret = sha1_file( argv[1], hash ) ) != 0 )
    {
        printf( " failed\n  ! Could not open or read %s\n\n", argv[1] );
        goto exit;
    }

    if( ( ret = rsa_pkcs1_sign( &rsa, ctr_drbg_random, &ctr_drbg, RSA_PRIVATE,
                                SIG_RSA_SHA1, 20, hash, buf ) ) != 0 )
    {
        printf( " failed\n  ! rsa_pkcs1_sign returned -0x%0x\n\n", -ret );
        goto exit;
    }

    /*
     * Write the signature into <filename>-sig.txt
     */
    memcpy( argv[1] + strlen( argv[1] ), ".sig", 5 );

    if( ( f = fopen( argv[1], "wb+" ) ) == NULL )
    {
        ret = 1;
        printf( " failed\n  ! Could not create %s\n\n", argv[1] );
        goto exit;
    }

    for( i = 0; i < rsa.len; i++ )
        fprintf( f, "%02X%s", buf[i],
                 ( i + 1 ) % 16 == 0 ? "\r\n" : " " );

    fclose( f );

    printf( "\n  . Done (created \"%s\")\n\n", argv[1] );

exit:

#if defined(_WIN32)
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_RSA_C && POLARSSL_SHA1_C &&
          POLARSSL_FS_IO */
