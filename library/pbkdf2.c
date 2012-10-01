/**
 * \file pbkdf2.c
 *
 * \brief Password-Based Key Derivation Function 2 (from PKCS#5)
 *
 * \author Mathias Olsson <mathias@kompetensum.com>
 *
 *  Copyright (C) 2006-2012, Brainspark B.V.
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
/*
 * PBKDF2 is part of PKCS#5
 *
 * http://tools.ietf.org/html/rfc2898 (Specification)
 * http://tools.ietf.org/html/rfc6070 (Test vectors)
 */

#include "polarssl/config.h"

#if defined(POLARSSL_PBKDF2_C)

#include "polarssl/pbkdf2.h"

int pbkdf2_hmac( md_context_t *ctx, const unsigned char *password, size_t plen,
                 const unsigned char *salt, size_t slen,
                 unsigned int iteration_count,
                 uint32_t key_length, unsigned char *output )
{
    int ret, j;
    unsigned int i;
    unsigned char md1[POLARSSL_MD_MAX_SIZE];
    unsigned char work[POLARSSL_MD_MAX_SIZE];
    unsigned char md_size = md_get_size( ctx->md_info );
    size_t use_len;
    unsigned char *out_p = output;
    unsigned char counter[4];

    memset( counter, 0, 4 );
    counter[3] = 1;

    if( iteration_count > 0xFFFFFFFF )
        return( POLARSSL_ERR_PBKDF2_BAD_INPUT_DATA );

    while( key_length )
    {
        // U1 ends up in work
        //
        if( ( ret = md_hmac_starts( ctx, password, plen ) ) != 0 )
            return( ret );

        if( ( ret = md_hmac_update( ctx, salt, slen ) ) != 0 )
            return( ret );

        if( ( ret = md_hmac_update( ctx, counter, 4 ) ) != 0 )
            return( ret );

        if( ( ret = md_hmac_finish( ctx, work ) ) != 0 )
            return( ret );

        memcpy( md1, work, md_size );

        for ( i = 1; i < iteration_count; i++ )
        {
            // U2 ends up in md1
            //
            if( ( ret = md_hmac_starts( ctx, password, plen ) ) != 0 )
                return( ret );

            if( ( ret = md_hmac_update( ctx, md1, md_size ) ) != 0 )
                return( ret );

            if( ( ret = md_hmac_finish( ctx, md1 ) ) != 0 )
                return( ret );

            // U1 xor U2
            //
            for( j = 0; j < md_size; j++ )
                work[j] ^= md1[j];
        }

        use_len = ( key_length < md_size ) ? key_length : md_size;
        memcpy( out_p, work, use_len );

        key_length -= use_len;
        out_p += use_len;

        for( i = 4; i > 0; i-- )
            if( ++counter[i - 1] != 0 )
                break;
    }

    return( 0 );
}


#if defined(POLARSSL_SELF_TEST)

#include <stdio.h>

#define MAX_TESTS   6

size_t plen[MAX_TESTS] =
    { 8, 8, 8, 8, 24, 9 };

unsigned char password[MAX_TESTS][32] =
{
    "password",
    "password",
    "password",
    "password",
    "passwordPASSWORDpassword",
    "pass\0word",
};
    
size_t slen[MAX_TESTS] =
    { 4, 4, 4, 4, 36, 5 };

unsigned char salt[MAX_TESTS][40] =
{
    "salt",
    "salt",
    "salt",
    "salt",
    "saltSALTsaltSALTsaltSALTsaltSALTsalt",
    "sa\0lt",
};

uint32_t it_cnt[MAX_TESTS] =
    { 1, 2, 4096, 16777216, 4096, 4096 };

uint32_t key_len[MAX_TESTS] =
    { 20, 20, 20, 20, 25, 16 };


unsigned char result_key[MAX_TESTS][32] = 
{
    { 0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
      0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
      0x2f, 0xe0, 0x37, 0xa6 },
    { 0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
      0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
      0xd8, 0xde, 0x89, 0x57 },
    { 0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
      0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
      0x65, 0xa4, 0x29, 0xc1 },
    { 0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4,
      0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c,
      0x26, 0x34, 0xe9, 0x84 },
    { 0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
      0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
      0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
      0x38 },
    { 0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
      0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3 },
};

int pbkdf2_self_test( int verbose )
{
    md_context_t sha1_ctx;
    const md_info_t *info_sha1;
    int ret, i;
    unsigned char key[64];

    info_sha1 = md_info_from_type( POLARSSL_MD_SHA1 );
    if( info_sha1 == NULL )
        return( 1 );

    if( ( ret = md_init_ctx( &sha1_ctx, info_sha1 ) ) != 0 )
        return( 1 );

    for( i = 0; i < MAX_TESTS; i++ )
    {
        printf( "  PBKDF2 (SHA1) #%d: ", i );

        ret = pbkdf2_hmac( &sha1_ctx, password[i], plen[i], salt[i], slen[i],
                           it_cnt[i], key_len[i], key );
        if( ret != 0 ||
            memcmp( result_key[i], key, key_len[i] ) != 0 )
        {
            if( verbose != 0 )
                printf( "failed\n" );

            return( 1 );
        }

        if( verbose != 0 )
            printf( "passed\n" );
    }

    printf( "\n" );

    return( 0 );
}

#endif /* POLARSSL_SELF_TEST */

#endif /* POLARSSL_PBKDF2_C */
