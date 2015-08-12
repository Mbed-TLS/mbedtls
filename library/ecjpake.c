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
static int ecjpake_zkp_write( const mbedtls_md_info_t *md_info,
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

/*
 * Parse a ECShnorrZKP (7.4.2.2.2) and verify it (7.4.2.3.3)
 */
static int ecjpake_zkp_read( const mbedtls_md_info_t *md_info,
                             const mbedtls_ecp_group *grp,
                             const mbedtls_ecp_point *G,
                             const mbedtls_ecp_point *X,
                             const char *id,
                             unsigned char **p,
                             const unsigned char *end )
{
    int ret;
    mbedtls_ecp_point V, VV;
    mbedtls_mpi r, h;
    size_t r_len;

    mbedtls_ecp_point_init( &V );
    mbedtls_ecp_point_init( &VV );
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &h );

    /*
     * struct {
     *     ECPoint V;
     *     opaque r<1..2^8-1>;
     * } ECSchnorrZKP;
     */
    if( end < *p )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    MBEDTLS_MPI_CHK( mbedtls_ecp_tls_read_point( grp, &V,
                     (const unsigned char **) p, end - *p ) );

    if( end < *p || (size_t)( end - *p ) < 1 )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    r_len = *(*p)++;
    if( end < *p || (size_t)( end - *p ) < r_len )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &r, *p, r_len ) );
    *p += r_len;

    /*
     * Verification
     */
    MBEDTLS_MPI_CHK( ecjpake_hash( md_info, grp, G, &V, X, id, &h ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_muladd( (mbedtls_ecp_group *) grp,
                     &VV, &h, X, &r, G ) );

    if( mbedtls_ecp_point_cmp( &VV, &V ) != 0 )
        return( MBEDTLS_ERR_ECP_VERIFY_FAILED );

cleanup:
    mbedtls_ecp_point_free( &V );
    mbedtls_ecp_point_free( &VV );
    mbedtls_mpi_free( &r );
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

static const unsigned char ecjpake_test_X[] = {
    0x04, 0xac, 0xcf, 0x01, 0x06, 0xef, 0x85, 0x8f, 0xa2, 0xd9, 0x19, 0x33,
    0x13, 0x46, 0x80, 0x5a, 0x78, 0xb5, 0x8b, 0xba, 0xd0, 0xb8, 0x44, 0xe5,
    0xc7, 0x89, 0x28, 0x79, 0x14, 0x61, 0x87, 0xdd, 0x26, 0x66, 0xad, 0xa7,
    0x81, 0xbb, 0x7f, 0x11, 0x13, 0x72, 0x25, 0x1a, 0x89, 0x10, 0x62, 0x1f,
    0x63, 0x4d, 0xf1, 0x28, 0xac, 0x48, 0xe3, 0x81, 0xfd, 0x6e, 0xf9, 0x06,
    0x07, 0x31, 0xf6, 0x94, 0xa4
};

static const unsigned char ecjpake_test_zkp[] = {
    0x41, 0x04, 0x1d, 0xd0, 0xbd, 0x5d, 0x45, 0x66, 0xc9, 0xbe, 0xd9, 0xce,
    0x7d, 0xe7, 0x01, 0xb5, 0xe8, 0x2e, 0x08, 0xe8, 0x4b, 0x73, 0x04, 0x66,
    0x01, 0x8a, 0xb9, 0x03, 0xc7, 0x9e, 0xb9, 0x82, 0x17, 0x22, 0x36, 0xc0,
    0xc1, 0x72, 0x8a, 0xe4, 0xbf, 0x73, 0x61, 0x0d, 0x34, 0xde, 0x44, 0x24,
    0x6e, 0xf3, 0xd9, 0xc0, 0x5a, 0x22, 0x36, 0xfb, 0x66, 0xa6, 0x58, 0x3d,
    0x74, 0x49, 0x30, 0x8b, 0xab, 0xce, 0x20, 0x72, 0xfe, 0x16, 0x66, 0x29,
    0x92, 0xe9, 0x23, 0x5c, 0x25, 0x00, 0x2f, 0x11, 0xb1, 0x50, 0x87, 0xb8,
    0x27, 0x38, 0xe0, 0x3c, 0x94, 0x5b, 0xf7, 0xa2, 0x99, 0x5d, 0xda, 0x1e,
    0x98, 0x34, 0x58
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
    mbedtls_ecp_point X;
    mbedtls_mpi x;
    const mbedtls_md_info_t *md_info;
    unsigned char buf[1000];
    unsigned char *p;
    const unsigned char *end;

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &X );
    mbedtls_mpi_init( &x );

    /* Common to all tests */
    md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );
    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_SECP256R1 ) );

    if( verbose != 0 )
        mbedtls_printf( "  ECJPAKE test #1 (zkp read): " );

    MBEDTLS_MPI_CHK( mbedtls_ecp_point_read_binary( &grp, &X,
                                            ecjpake_test_X,
                                    sizeof( ecjpake_test_X ) ) );

    p = (unsigned char *) ecjpake_test_zkp;
    end = ecjpake_test_zkp + sizeof( ecjpake_test_zkp );
    MBEDTLS_MPI_CHK( ecjpake_zkp_read( md_info, &grp, &grp.G, &X, "client",
                                       &p, end ) );

    /* Corrupt proof */
    memcpy( buf, ecjpake_test_zkp, sizeof( ecjpake_test_zkp ) );
    buf[sizeof( ecjpake_test_zkp ) - 1]--;
    p = buf;
    end = buf + sizeof( ecjpake_test_zkp );
    ret = ecjpake_zkp_read( md_info, &grp, &grp.G, &X, "client", &p, end );

    if( ret != MBEDTLS_ERR_ECP_VERIFY_FAILED )
    {
        ret = 1;
        goto cleanup;
    }
    ret = 0;

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    if( verbose != 0 )
        mbedtls_printf( "  ECJPAKE test #2 (zkp write/read): " );

    MBEDTLS_MPI_CHK( mbedtls_ecp_gen_keypair_base( &grp, &grp.G, &x, &X,
                                                   ecjpake_lgc, NULL ) );

    p = buf;
    MBEDTLS_MPI_CHK( ecjpake_zkp_write( md_info, &grp, &grp.G, &x, &X, "client",
                                        &p, buf + sizeof( buf ),
                                        ecjpake_lgc, NULL ) );

    p = buf;
    MBEDTLS_MPI_CHK( ecjpake_zkp_read( md_info, &grp, &grp.G, &X, "client",
                                       &p, buf + sizeof( buf ) ) );

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

cleanup:
    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &X );
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
