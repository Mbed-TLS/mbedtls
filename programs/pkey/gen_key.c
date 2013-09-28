/*
 *  Key generation application
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
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

#include "polarssl/config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "polarssl/error.h"
#include "polarssl/pk.h"
#include "polarssl/ecdsa.h"
#include "polarssl/rsa.h"
#include "polarssl/error.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#if !defined(POLARSSL_PK_WRITE_C) || !defined(POLARSSL_FS_IO) ||    \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_CTR_DRBG_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    printf( "POLARSSL_PK_WRITE_C and/or POLARSSL_FS_IO and/or "
            "POLARSSL_ENTROPY_C and/or POLARSSL_CTR_DRBG_C "
            "not defined.\n" );
    return( 0 );
}
#else

#define TYPE_RSA                0

#define FORMAT_PEM              0
#define FORMAT_DER              1

#define DFL_TYPE                TYPE_RSA
#define DFL_RSA_KEYSIZE         4096
#define DFL_FILENAME            "keyfile.key"
#define DFL_FORMAT              FORMAT_PEM

/*
 * global options
 */
struct options
{
    int type;                   /* the type of key to generate          */
    int rsa_keysize;            /* length of key in bits                */
    const char *filename;       /* filename of the key file             */
    int format;                 /* the output format to use             */
} opt;

static int write_private_key( pk_context *key, const char *output_file )
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);
    if( opt.format == FORMAT_PEM )
    {
        if( ( ret = pk_write_key_pem( key, output_buf, 16000 ) ) != 0 )
            return( ret );

        len = strlen( (char *) output_buf );
    }
    else
    {
        if( ( ret = pk_write_key_der( key, output_buf, 16000 ) ) < 0 )
            return( ret );

        len = ret;
        c = output_buf + sizeof(output_buf) - len - 1;
    }

    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( c, 1, len, f ) != len )
        return( -1 );

    fclose(f);

    return( 0 );
}

#define USAGE \
    "\n usage: gen_key param=<>...\n"                    \
    "\n acceptable parameters:\n"                       \
    "    type=rsa              default: rsa\n"          \
    "    rsa_keysize=%%d      default: 4096\n"          \
    "    filename=%%s         default: keyfile.key\n"   \
    "    format=pem|der        default: pem\n"          \
    "\n"

int main( int argc, char *argv[] )
{
    int ret = 0;
    pk_context key;
    char buf[1024];
    int i;
    char *p, *q;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    const char *pers = "gen_key";

    /*
     * Set to sane values
     */
    pk_init( &key );
    memset( buf, 0, sizeof( buf ) );

    if( argc == 0 )
    {
    usage:
        ret = 1;
        printf( USAGE );
        goto exit;
    }

    opt.type                = DFL_TYPE;
    opt.rsa_keysize         = DFL_RSA_KEYSIZE;
    opt.filename            = DFL_FILENAME;
    opt.format              = DFL_FORMAT;

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "type" ) == 0 )
        {
            if( strcmp( q, "rsa" ) == 0 )
                opt.type = TYPE_RSA;
            else
                goto usage;
        }
        else if( strcmp( p, "format" ) == 0 )
        {
            if( strcmp( q, "pem" ) == 0 )
                opt.format = FORMAT_PEM;
            else if( strcmp( q, "der" ) == 0 )
                opt.format = FORMAT_DER;
            else
                goto usage;
        }
        else if( strcmp( p, "rsa_keysize" ) == 0 )
        {
            opt.rsa_keysize = atoi( q );
            if( opt.rsa_keysize < 1024 || opt.rsa_keysize > 8192 )
                goto usage;
        }
        else if( strcmp( p, "filename" ) == 0 )
            opt.filename = q;
        else
            goto usage;
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

    /*
     * 1.1. Generate the key
     */
    printf( "\n  . Generating the private key ..." );
    fflush( stdout );

#if defined(POLARSSL_RSA_C) && defined(POLARSSL_GENPRIME)
    if( opt.type == TYPE_RSA )
    {
        pk_init_ctx( &key, pk_info_from_type( POLARSSL_PK_RSA ) );
        ret = rsa_gen_key( pk_rsa( key ), ctr_drbg_random, &ctr_drbg,
                           opt.rsa_keysize, 65537 );
        if( ret != 0 )
        {
            printf( " failed\n  !  rsa_gen_key returned -0x%04x", -ret );
            goto exit;
        }

        printf( " ok\n" );
    }
    else
#endif /* POLARSSL_RSA_C */
    {
        printf( " failed\n  !  key type not supported in library" );
        goto exit;
    }

    /*
     * 1.2 Print the key
     */
    printf( "  . Key information    ...\n" );

#if defined(POLARSSL_RSA_C)
    if( pk_get_type( &key ) == POLARSSL_PK_RSA )
    {
        rsa_context *rsa = pk_rsa( key );
        mpi_write_file( "N:  ",  &rsa->N,  16, NULL );
        mpi_write_file( "E:  ",  &rsa->E,  16, NULL );
        mpi_write_file( "D:  ",  &rsa->D,  16, NULL );
        mpi_write_file( "P:  ",  &rsa->P,  16, NULL );
        mpi_write_file( "Q:  ",  &rsa->Q,  16, NULL );
        mpi_write_file( "DP: ",  &rsa->DP, 16, NULL );
        mpi_write_file( "DQ:  ", &rsa->DQ, 16, NULL );
        mpi_write_file( "QP:  ", &rsa->QP, 16, NULL );
    }
    else
#endif
#if defined(POLARSSL_ECP_C)
    if( pk_get_type( &key ) == POLARSSL_PK_ECKEY )
    {
        ecp_keypair *ecp = pk_ec( key );
        mpi_write_file( "Q(X): ", &ecp->Q.X, 16, NULL );
        mpi_write_file( "Q(Y): ", &ecp->Q.Y, 16, NULL );
        mpi_write_file( "Q(Z): ", &ecp->Q.Z, 16, NULL );
        mpi_write_file( "D   : ", &ecp->d  , 16, NULL );
    }
    else
#endif
        printf("key type not supported yet\n");

    write_private_key( &key, opt.filename );

exit:

    if( ret != 0 && ret != 1)
    {
#ifdef POLARSSL_ERROR_C
        polarssl_strerror( ret, buf, sizeof( buf ) );
        printf( " - %s\n", buf );
#else
        printf("\n");
#endif
    }

    pk_free( &key );
    entropy_free( &entropy );

#if defined(_WIN32)
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_PK_WRITE_C && POLARSSL_FS_IO */
