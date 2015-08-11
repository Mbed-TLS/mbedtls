/*
 *  Elliptic curve J-PAKE
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 * We implement EC-JPAKE as defined in Chapter 7.4 of the Thread v1.0
 * Specification. References below are to this document.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ECJPAKE_C)

#include "mbedtls/ecjpake.h"

#include <string.h>

/*
 * Write a point plus its length to a buffer
 */
static int ecjpake_write_len_point( unsigned char **p,
                                    const unsigned char *end,
                                    const mbedtls_ecp_group *grp,
                                    const mbedtls_ecp_point *P )
{
    int ret;
    size_t len;

    /* Need at least 4 for length plus 1 for point */
    if( end < *p || end - *p < 5 )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    ret = mbedtls_ecp_point_write_binary( grp, P, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &len, *p + 4, end - ( *p + 4 ) );
    if( ret != 0 )
        return( ret );

    (*p)[0] = (unsigned char)( ( len >> 24 ) & 0xFF );
    (*p)[1] = (unsigned char)( ( len >> 16 ) & 0xFF );
    (*p)[2] = (unsigned char)( ( len >>  8 ) & 0xFF );
    (*p)[3] = (unsigned char)( ( len       ) & 0xFF );

    *p += 4 + len;

    return( 0 );
}

/*
 * Size of the temporary buffer for ecjpake_hash:
 * 3 EC points plus their length, plus ID (6 bytes)
 */
#define ECJPAKE_HASH_BUF_LEN    ( 3 * ( 4 + MBEDTLS_ECP_MAX_PT_LEN ) + 6 )

/*
 * Compute hash for ZKP (7.4.2.2.2.1)
 */
static int ecjpake_hash( const mbedtls_md_info_t *md_info,
                         const mbedtls_ecp_group *grp,
                         const mbedtls_ecp_point *G,
                         const mbedtls_ecp_point *V,
                         const mbedtls_ecp_point *X,
                         const char *id,
                         mbedtls_mpi *h )
{
    int ret;
    unsigned char buf[ECJPAKE_HASH_BUF_LEN];
    unsigned char *p = buf;
    const unsigned char *end = buf + sizeof( buf );
    const size_t id_len = strlen( id );
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];

    /* Write things to temporary buffer */
    MBEDTLS_MPI_CHK( ecjpake_write_len_point( &p, end, grp, G ) );
    MBEDTLS_MPI_CHK( ecjpake_write_len_point( &p, end, grp, V ) );
    MBEDTLS_MPI_CHK( ecjpake_write_len_point( &p, end, grp, X ) );

    if( end < p || (size_t)( end - p ) < id_len )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    *p++ = (unsigned char)( ( id_len >> 24 ) & 0xFF );
    *p++ = (unsigned char)( ( id_len >> 16 ) & 0xFF );
    *p++ = (unsigned char)( ( id_len >>  8 ) & 0xFF );
    *p++ = (unsigned char)( ( id_len       ) & 0xFF );

    memcpy( p, id, id_len );
    p += id_len;

    /* Compute hash */
    mbedtls_md( md_info, buf, p - buf, hash );

    /* Turn it into an integer mod n */
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( h, hash,
                                        mbedtls_md_get_size( md_info ) ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( h, h, &grp->N ) );

cleanup:
    return( ret );
}

/*
 * Generate ZKP (7.4.2.3.2) and write it as ECSchnorrZKP (7.4.2.2.2)
 */
static int ecjpake_write_zkp( const mbedtls_md_info_t *md_info,
                              const mbedtls_ecp_group *grp,
                              const mbedtls_ecp_point *G,
                              const mbedtls_mpi *x,
                              const mbedtls_ecp_point *X,
                              const char *id,
                              unsigned char **p,
                              const unsigned char *end,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    int ret;
    mbedtls_ecp_point V;
    mbedtls_mpi v;
    mbedtls_mpi h; /* later recycled to hold r */
    size_t len;

    if( end < *p )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    mbedtls_ecp_point_init( &V );
    mbedtls_mpi_init( &v );
    mbedtls_mpi_init( &h );

    /* Compute signature */
    MBEDTLS_MPI_CHK( mbedtls_ecp_gen_keypair_base( (mbedtls_ecp_group *) grp,
                                                   G, &v, &V, f_rng, p_rng ) );
    MBEDTLS_MPI_CHK( ecjpake_hash( md_info, grp, G, &V, X, id, &h ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &h, &h, x ) ); /* x*h */
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &h, &v, &h ) ); /* v - x*h */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &h, &h, &grp->N ) ); /* r */

    /* Write it out */
    MBEDTLS_MPI_CHK( mbedtls_ecp_tls_write_point( grp, &V,
                MBEDTLS_ECP_PF_UNCOMPRESSED, &len, *p, end - *p ) );
    *p += len;

    len = mbedtls_mpi_size( &h ); /* actually r */
    if( end < *p || (size_t)( end - *p ) < 1 + len || len > 255 )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    *(*p)++ = (unsigned char)( len & 0xFF );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &h, *p, len ) ); /* r */
    *p += len;

cleanup:
    mbedtls_ecp_point_free( &V );
    mbedtls_mpi_free( &v );
    mbedtls_mpi_free( &h );

    return( ret );
}

#if defined(MBEDTLS_SELF_TEST)

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) || \
    !defined(MBEDTLS_SHA256_C)
int mbedtls_ecjpake_self_test( int verbose )
{
    (void) verbose;
    return( 0 );
}
#else

static const unsigned char ecjpake_test_G[] = {
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6,
    0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
    0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42,
    0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40,
    0x68, 0x37, 0xbf, 0x51, 0xf5
};

static const unsigned char ecjpake_test_V[] = {
    0x04, 0xfa, 0x9a, 0x24, 0x9d, 0x73, 0x6e, 0x30, 0x28, 0xd1, 0x2d, 0xf1,
    0xdc, 0xfa, 0x22, 0xd1, 0xed, 0x62, 0x82, 0xbf, 0xab, 0x27, 0x7c, 0x7c,
    0x52, 0x56, 0xf3, 0xfd, 0x38, 0x07, 0xa5, 0xae, 0xe0, 0x72, 0xfb, 0x4d,
    0x9c, 0x2b, 0xd6, 0xa4, 0x70, 0xf7, 0xb4, 0xd0, 0xbd, 0xfb, 0x4a, 0x94,
    0x96, 0xcf, 0xcd, 0xd3, 0x53, 0xf9, 0x90, 0x3c, 0x0a, 0x69, 0xa4, 0x4b,
    0x18, 0xc6, 0xd2, 0x9b, 0xb8
};

static const unsigned char ecjpake_test_X[] = {
    0x04, 0x52, 0xa4, 0xda, 0x90, 0xa5, 0x15, 0x7f, 0xc0, 0xe5, 0x1f, 0x79,
    0x4b, 0xe3, 0xbb, 0x3f, 0x1d, 0xf8, 0xdf, 0xb1, 0xe3, 0x18, 0xa8, 0x10,
    0xf2, 0x05, 0x2e, 0x64, 0xa8, 0xe8, 0x35, 0x64, 0xe8, 0xe2, 0x8c, 0x17,
    0x15, 0xab, 0xf7, 0x8d, 0x1f, 0x8b, 0x18, 0x99, 0x6d, 0x6a, 0xb7, 0xbd,
    0xcc, 0xbe, 0x52, 0x08, 0x1a, 0x3a, 0xe7, 0x65, 0x4b, 0xdf, 0x66, 0x62,
    0xf5, 0x74, 0xe0, 0xfd, 0x80
};

static const unsigned char ecjpake_test_h[] = {
    0xec, 0xf3, 0x24, 0x46, 0x16, 0xce, 0xa5, 0x34, 0x58, 0x46, 0xd2, 0x45,
    0xba, 0x27, 0x63, 0x36, 0x50, 0xc4, 0x70, 0x3d, 0x56, 0x0c, 0x7a, 0x7c,
    0x51, 0x69, 0xfe, 0xa7, 0xa3, 0xf7, 0x79, 0x10
};

/* For tests we don't need a secure RNG;
 * use the LGC from Numerical Recipes for simplicity */
static int ecjpake_lgc( void *p, unsigned char *out, size_t len )
{
    static uint32_t x = 42;
    (void) p;

    while( len > 0 )
    {
        size_t use_len = len > 4 ? 4 : len;
        x = 1664525 * x + 1013904223;
        memcpy( out, &x, use_len );
        out += use_len;
        len -= use_len;
    }

    return( 0 );
}

/*
 * Checkup routine
 */
int mbedtls_ecjpake_self_test( int verbose )
{
    int ret;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point G, V, X;
    mbedtls_mpi x, h, h_ref;
    const mbedtls_md_info_t *md_info;
    unsigned char buf[1000];
    unsigned char *p;

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &G );
    mbedtls_ecp_point_init( &V );
    mbedtls_ecp_point_init( &X );
    mbedtls_mpi_init( &h_ref );
    mbedtls_mpi_init( &h );
    mbedtls_mpi_init( &x );

    /* Common to all tests */
    md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );
    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_SECP256R1 ) );

    if( verbose != 0 )
        mbedtls_printf( "  ECJPAKE test #1 (hash): " );

    MBEDTLS_MPI_CHK( mbedtls_ecp_point_read_binary( &grp, &G, ecjpake_test_G,
                                                      sizeof( ecjpake_test_G ) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_read_binary( &grp, &V, ecjpake_test_V,
                                                      sizeof( ecjpake_test_V ) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_read_binary( &grp, &X, ecjpake_test_X,
                                                      sizeof( ecjpake_test_X ) ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &h_ref, ecjpake_test_h,
                                              sizeof( ecjpake_test_h ) ) );

    MBEDTLS_MPI_CHK( ecjpake_hash( md_info, &grp, &G, &V, &X, "client", &h ) );

    if( mbedtls_mpi_cmp_mpi( &h, &h_ref ) != 0 )
    {
        ret = 1;
        goto cleanup;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    if( verbose != 0 )
        mbedtls_printf( "  ECJPAKE test #2 (zkp, WIP): " );

    MBEDTLS_MPI_CHK( mbedtls_ecp_gen_keypair_base( &grp, &G, &x, &X,
                                                   ecjpake_lgc, NULL ) );

    p = buf;
    MBEDTLS_MPI_CHK( ecjpake_write_zkp( md_info, &grp, &G, &x, &X, "client",
                                        &p, buf + sizeof( buf ),
                                        ecjpake_lgc, NULL ) );

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

cleanup:
    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &G );
    mbedtls_ecp_point_free( &V );
    mbedtls_ecp_point_free( &X );
    mbedtls_mpi_free( &h_ref );
    mbedtls_mpi_free( &h );
    mbedtls_mpi_free( &x );

    if( ret != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( ret );
}

#endif /* MBEDTLS_ECP_DP_SECP256R1_ENABLED && MBEDTLS_SHA256_C */

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_ECJPAKE_C */
