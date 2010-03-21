/*
 *  Benchmark demonstration program
 *
 *  Copyright (C) 2006-2010, Paul Bakker <polarssl_maintainer at polarssl.org>
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

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "polarssl/config.h"

#include "polarssl/md4.h"
#include "polarssl/md5.h"
#include "polarssl/sha1.h"
#include "polarssl/sha2.h"
#include "polarssl/sha4.h"
#include "polarssl/arc4.h"
#include "polarssl/des.h"
#include "polarssl/aes.h"
#include "polarssl/camellia.h"
#include "polarssl/rsa.h"
#include "polarssl/timing.h"

#define BUFSIZE 1024

static int myrand( void *rng_state )
{
    if( rng_state != NULL )
        rng_state  = NULL;

    return( rand() );
}

unsigned char buf[BUFSIZE];

int main( void )
{
    int keysize;
    unsigned long i, j, tsc;
    unsigned char tmp[64];
#if defined(POLARSSL_ARC4_C)
    arc4_context arc4;
#endif
#if defined(POLARSSL_DES_C)
    des3_context des3;
    des_context des;
#endif
#if defined(POLARSSL_AES_C)
    aes_context aes;
#endif
#if defined(POLARSSL_CAMELLIA_C)
    camellia_context camellia;
#endif
#if defined(POLARSSL_RSA_C)
    rsa_context rsa;
#endif

    memset( buf, 0xAA, sizeof( buf ) );

    printf( "\n" );

#if defined(POLARSSL_MD4_C)
    printf( "  MD4       :  " );
    fflush( stdout );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        md4( buf, BUFSIZE, tmp );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        md4( buf, BUFSIZE, tmp );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );
#endif

#if defined(POLARSSL_MD5_C)
    printf( "  MD5       :  " );
    fflush( stdout );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        md5( buf, BUFSIZE, tmp );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        md5( buf, BUFSIZE, tmp );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );
#endif

#if defined(POLARSSL_SHA1_C)
    printf( "  SHA-1     :  " );
    fflush( stdout );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        sha1( buf, BUFSIZE, tmp );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        sha1( buf, BUFSIZE, tmp );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );
#endif

#if defined(POLARSSL_SHA2_C)
    printf( "  SHA-256   :  " );
    fflush( stdout );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        sha2( buf, BUFSIZE, tmp, 0 );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        sha2( buf, BUFSIZE, tmp, 0 );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );
#endif

#if defined(POLARSSL_SHA4_C)
    printf( "  SHA-512   :  " );
    fflush( stdout );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        sha4( buf, BUFSIZE, tmp, 0 );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        sha4( buf, BUFSIZE, tmp, 0 );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );
#endif

#if defined(POLARSSL_ARC4_C)
    printf( "  ARC4      :  " );
    fflush( stdout );

    arc4_setup( &arc4, tmp, 32 );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        arc4_crypt( &arc4, BUFSIZE, buf, buf );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        arc4_crypt( &arc4, BUFSIZE, buf, buf );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );
#endif

#if defined(POLARSSL_DES_C)
    printf( "  3DES      :  " );
    fflush( stdout );

    des3_set3key_enc( &des3, tmp );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        des3_crypt_cbc( &des3, DES_ENCRYPT, BUFSIZE, tmp, buf, buf );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        des3_crypt_cbc( &des3, DES_ENCRYPT, BUFSIZE, tmp, buf, buf );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );

    printf( "  DES       :  " );
    fflush( stdout );

    des_setkey_enc( &des, tmp );

    set_alarm( 1 );
    for( i = 1; ! alarmed; i++ )
        des_crypt_cbc( &des, DES_ENCRYPT, BUFSIZE, tmp, buf, buf );

    tsc = hardclock();
    for( j = 0; j < 1024; j++ )
        des_crypt_cbc( &des, DES_ENCRYPT, BUFSIZE, tmp, buf, buf );

    printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                    ( hardclock() - tsc ) / ( j * BUFSIZE ) );
#endif

#if defined(POLARSSL_AES_C)
    for( keysize = 128; keysize <= 256; keysize += 64 )
    {
        printf( "  AES-%d   :  ", keysize );
        fflush( stdout );

        memset( buf, 0, sizeof( buf ) );
        memset( tmp, 0, sizeof( tmp ) );
        aes_setkey_enc( &aes, tmp, keysize );

        set_alarm( 1 );

        for( i = 1; ! alarmed; i++ )
            aes_crypt_cbc( &aes, AES_ENCRYPT, BUFSIZE, tmp, buf, buf );

        tsc = hardclock();
        for( j = 0; j < 4096; j++ )
            aes_crypt_cbc( &aes, AES_ENCRYPT, BUFSIZE, tmp, buf, buf );

        printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                        ( hardclock() - tsc ) / ( j * BUFSIZE ) );
    }
#endif

#if defined(POLARSSL_CAMELLIA_C)
    for( keysize = 128; keysize <= 256; keysize += 64 )
    {
        printf( "  CAMELLIA-%d   :  ", keysize );
        fflush( stdout );

        memset( buf, 0, sizeof( buf ) );
        memset( tmp, 0, sizeof( tmp ) );
        camellia_setkey_enc( &camellia, tmp, keysize );

        set_alarm( 1 );

        for( i = 1; ! alarmed; i++ )
            camellia_crypt_cbc( &camellia, CAMELLIA_ENCRYPT, BUFSIZE, tmp, buf, buf );

        tsc = hardclock();
        for( j = 0; j < 4096; j++ )
            camellia_crypt_cbc( &camellia, CAMELLIA_ENCRYPT, BUFSIZE, tmp, buf, buf );

        printf( "%9lu Kb/s,  %9lu cycles/byte\n", i * BUFSIZE / 1024,
                        ( hardclock() - tsc ) / ( j * BUFSIZE ) );
    }
#endif

#if defined(POLARSSL_RSA_C)
    rsa_init( &rsa, RSA_PKCS_V15, 0, myrand, NULL );
    rsa_gen_key( &rsa, 1024, 65537 );

    printf( "  RSA-1024  :  " );
    fflush( stdout );
    set_alarm( 3 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_public( &rsa, buf, buf );
    }

    printf( "%9lu  public/s\n", i / 3 );

    printf( "  RSA-1024  :  " );
    fflush( stdout );
    set_alarm( 3 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_private( &rsa, buf, buf );
    }

    printf( "%9lu private/s\n", i / 3 );

    rsa_free( &rsa );

    rsa_init( &rsa, RSA_PKCS_V15, 0, myrand, NULL );
    rsa_gen_key( &rsa, 2048, 65537 );

    printf( "  RSA-2048  :  " );
    fflush( stdout );
    set_alarm( 3 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_public( &rsa, buf, buf );
    }

    printf( "%9lu  public/s\n", i / 3 );

    printf( "  RSA-2048  :  " );
    fflush( stdout );
    set_alarm( 3 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_private( &rsa, buf, buf );
    }

    printf( "%9lu private/s\n", i / 3 );

    rsa_free( &rsa );

    rsa_init( &rsa, RSA_PKCS_V15, 0, myrand, NULL );
    rsa_gen_key( &rsa, 4096, 65537 );

    printf( "  RSA-4096  :  " );
    fflush( stdout );
    set_alarm( 3 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_public( &rsa, buf, buf );
    }

    printf( "%9lu  public/s\n", i / 3 );

    printf( "  RSA-4096  :  " );
    fflush( stdout );
    set_alarm( 3 );

    for( i = 1; ! alarmed; i++ )
    {
        buf[0] = 0;
        rsa_private( &rsa, buf, buf );
    }

    printf( "%9lu private/s\n", i / 3 );

    rsa_free( &rsa );
#endif

    printf( "\n" );

#ifdef WIN32
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( 0 );
}
