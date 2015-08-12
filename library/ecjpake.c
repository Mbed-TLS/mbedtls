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
    {
        ret = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        goto cleanup;
    }

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
                             const unsigned char **p,
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

    MBEDTLS_MPI_CHK( mbedtls_ecp_tls_read_point( grp, &V, p, end - *p ) );

    if( end < *p || (size_t)( end - *p ) < 1 )
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    r_len = *(*p)++;

    if( end < *p || (size_t)( end - *p ) < r_len )
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &r, *p, r_len ) );
    *p += r_len;

    /*
     * Verification
     */
    MBEDTLS_MPI_CHK( ecjpake_hash( md_info, grp, G, &V, X, id, &h ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_muladd( (mbedtls_ecp_group *) grp,
                     &VV, &h, X, &r, G ) );

    if( mbedtls_ecp_point_cmp( &VV, &V ) != 0 )
    {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free( &V );
    mbedtls_ecp_point_free( &VV );
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &h );

    return( ret );
}

/*
 * Parse a ECJPAKEKeyKP (7.4.2.2.1) and check proof
 * Output: verified public key X
 */
static int ecjpake_kkp_read( const mbedtls_md_info_t *md_info,
                             const mbedtls_ecp_group *grp,
                             const mbedtls_ecp_point *G,
                             mbedtls_ecp_point *X,
                             const char *id,
                             const unsigned char **p,
                             const unsigned char *end )
{
    int ret;

    if( end < *p )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );

    /*
     * struct {
     *     ECPoint X;
     *     ECSchnorrZKP zkp;
     * } ECJPAKEKeyKP;
     */
    MBEDTLS_MPI_CHK( mbedtls_ecp_tls_read_point( grp, X, p, end - *p ) );
    MBEDTLS_MPI_CHK( ecjpake_zkp_read( md_info, grp, G, X, id, p, end ) );

cleanup:
    return( ret );
}

/*
 * Generate an ECJPAKEKeyKP
 * Output: the serialized structure, plus private/public key pair
 */
static int ecjpake_kkp_write( const mbedtls_md_info_t *md_info,
                              const mbedtls_ecp_group *grp,
                              const mbedtls_ecp_point *G,
                              mbedtls_mpi *x,
                              mbedtls_ecp_point *X,
                              const char *id,
                              unsigned char **p,
                              const unsigned char *end,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    int ret;
    size_t len;

    if( end < *p )
        return( MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL );

    /* Generate key (7.4.2.3.1) and write it out */
    MBEDTLS_MPI_CHK( mbedtls_ecp_gen_keypair_base( (mbedtls_ecp_group *) grp, G, x, X,
                                                   f_rng, p_rng ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_tls_write_point( grp, X,
                MBEDTLS_ECP_PF_UNCOMPRESSED, &len, *p, end - *p ) );
    *p += len;

    /* Generate and write proof */
    MBEDTLS_MPI_CHK( ecjpake_zkp_write( md_info, grp, G, x, X, id,
                                        p, end, f_rng, p_rng ) );

cleanup:
    return( ret );
}

/*
 * Read a ECJPAKEKeyKPPairList (7.4.2.3) and check proofs
 * Ouputs: verified peer public keys Xa, Xb
 */
static int ecjpake_kkpp_read( const mbedtls_md_info_t *md_info,
                              const mbedtls_ecp_group *grp,
                              const mbedtls_ecp_point *G,
                              mbedtls_ecp_point *Xa,
                              mbedtls_ecp_point *Xb,
                              const char *id,
                              const unsigned char *buf,
                              size_t len )
{
    int ret;
    const unsigned char *p = buf;
    const unsigned char *end = buf + len;

    /*
     * struct {
     *     ECJPAKEKeyKP ecjpake_key_kp_pair_list[2];
     * } ECJPAKEKeyKPPairList;
     */
    MBEDTLS_MPI_CHK( ecjpake_kkp_read( md_info, grp, G, Xa, id, &p, end ) );
    MBEDTLS_MPI_CHK( ecjpake_kkp_read( md_info, grp, G, Xb, id, &p, end ) );

    if( p != end )
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

cleanup:
    return( ret );
}

/*
 * Generate a ECJPAKEKeyKPPairList
 * Outputs: the serialized structure, plus two private/public key pairs
 */
static int ecjpake_kkpp_write( const mbedtls_md_info_t *md_info,
                               const mbedtls_ecp_group *grp,
                               const mbedtls_ecp_point *G,
                               mbedtls_mpi *xa,
                               mbedtls_ecp_point *Xa,
                               mbedtls_mpi *xb,
                               mbedtls_ecp_point *Xb,
                               const char *id,
                               unsigned char *buf,
                               size_t len,
                               size_t *olen,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng )
{
    int ret;
    unsigned char *p = buf;
    const unsigned char *end = buf + len;

    MBEDTLS_MPI_CHK( ecjpake_kkp_write( md_info, grp, G, xa, Xa, id,
                &p, end, f_rng, p_rng ) );
    MBEDTLS_MPI_CHK( ecjpake_kkp_write( md_info, grp, G, xb, Xb, id,
                &p, end, f_rng, p_rng ) );

    *olen = p - buf;

cleanup:
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

static const unsigned char ecjpake_test_kkpp[] = {
    0x41, 0x04, 0xac, 0xcf, 0x01, 0x06, 0xef, 0x85, 0x8f, 0xa2, 0xd9, 0x19,
    0x33, 0x13, 0x46, 0x80, 0x5a, 0x78, 0xb5, 0x8b, 0xba, 0xd0, 0xb8, 0x44,
    0xe5, 0xc7, 0x89, 0x28, 0x79, 0x14, 0x61, 0x87, 0xdd, 0x26, 0x66, 0xad,
    0xa7, 0x81, 0xbb, 0x7f, 0x11, 0x13, 0x72, 0x25, 0x1a, 0x89, 0x10, 0x62,
    0x1f, 0x63, 0x4d, 0xf1, 0x28, 0xac, 0x48, 0xe3, 0x81, 0xfd, 0x6e, 0xf9,
    0x06, 0x07, 0x31, 0xf6, 0x94, 0xa4, 0x41, 0x04, 0x1d, 0xd0, 0xbd, 0x5d,
    0x45, 0x66, 0xc9, 0xbe, 0xd9, 0xce, 0x7d, 0xe7, 0x01, 0xb5, 0xe8, 0x2e,
    0x08, 0xe8, 0x4b, 0x73, 0x04, 0x66, 0x01, 0x8a, 0xb9, 0x03, 0xc7, 0x9e,
    0xb9, 0x82, 0x17, 0x22, 0x36, 0xc0, 0xc1, 0x72, 0x8a, 0xe4, 0xbf, 0x73,
    0x61, 0x0d, 0x34, 0xde, 0x44, 0x24, 0x6e, 0xf3, 0xd9, 0xc0, 0x5a, 0x22,
    0x36, 0xfb, 0x66, 0xa6, 0x58, 0x3d, 0x74, 0x49, 0x30, 0x8b, 0xab, 0xce,
    0x20, 0x72, 0xfe, 0x16, 0x66, 0x29, 0x92, 0xe9, 0x23, 0x5c, 0x25, 0x00,
    0x2f, 0x11, 0xb1, 0x50, 0x87, 0xb8, 0x27, 0x38, 0xe0, 0x3c, 0x94, 0x5b,
    0xf7, 0xa2, 0x99, 0x5d, 0xda, 0x1e, 0x98, 0x34, 0x58, 0x41, 0x04, 0x7e,
    0xa6, 0xe3, 0xa4, 0x48, 0x70, 0x37, 0xa9, 0xe0, 0xdb, 0xd7, 0x92, 0x62,
    0xb2, 0xcc, 0x27, 0x3e, 0x77, 0x99, 0x30, 0xfc, 0x18, 0x40, 0x9a, 0xc5,
    0x36, 0x1c, 0x5f, 0xe6, 0x69, 0xd7, 0x02, 0xe1, 0x47, 0x79, 0x0a, 0xeb,
    0x4c, 0xe7, 0xfd, 0x65, 0x75, 0xab, 0x0f, 0x6c, 0x7f, 0xd1, 0xc3, 0x35,
    0x93, 0x9a, 0xa8, 0x63, 0xba, 0x37, 0xec, 0x91, 0xb7, 0xe3, 0x2b, 0xb0,
    0x13, 0xbb, 0x2b, 0x41, 0x04, 0xa4, 0x95, 0x58, 0xd3, 0x2e, 0xd1, 0xeb,
    0xfc, 0x18, 0x16, 0xaf, 0x4f, 0xf0, 0x9b, 0x55, 0xfc, 0xb4, 0xca, 0x47,
    0xb2, 0xa0, 0x2d, 0x1e, 0x7c, 0xaf, 0x11, 0x79, 0xea, 0x3f, 0xe1, 0x39,
    0x5b, 0x22, 0xb8, 0x61, 0x96, 0x40, 0x16, 0xfa, 0xba, 0xf7, 0x2c, 0x97,
    0x56, 0x95, 0xd9, 0x3d, 0x4d, 0xf0, 0xe5, 0x19, 0x7f, 0xe9, 0xf0, 0x40,
    0x63, 0x4e, 0xd5, 0x97, 0x64, 0x93, 0x77, 0x87, 0xbe, 0x20, 0xbc, 0x4d,
    0xee, 0xbb, 0xf9, 0xb8, 0xd6, 0x0a, 0x33, 0x5f, 0x04, 0x6c, 0xa3, 0xaa,
    0x94, 0x1e, 0x45, 0x86, 0x4c, 0x7c, 0xad, 0xef, 0x9c, 0xf7, 0x5b, 0x3d,
    0x8b, 0x01, 0x0e, 0x44, 0x3e, 0xf0
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

#define TEST_ASSERT( x )    \
    do {                    \
        if( x )             \
            ret = 0;        \
        else                \
        {                   \
            ret = 1;        \
            goto cleanup;   \
        }                   \
    } while( 0 )

/*
 * Checkup routine
 */
int mbedtls_ecjpake_self_test( int verbose )
{
    int ret;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Xa, Xb;
    mbedtls_mpi xa, xb;
    const mbedtls_md_info_t *md_info;
    unsigned char buf[1000];
    size_t len;

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &Xa );
    mbedtls_ecp_point_init( &Xb );
    mbedtls_mpi_init( &xa );
    mbedtls_mpi_init( &xb );

    /* Common to all tests */
    md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );
    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_SECP256R1 ) );

    if( verbose != 0 )
        mbedtls_printf( "  ECJPAKE test #1 (kkpp read): " );

    TEST_ASSERT( ecjpake_kkpp_read( md_info, &grp, &grp.G,
                                    &Xa, &Xb, "client",
                                    ecjpake_test_kkpp,
                            sizeof( ecjpake_test_kkpp ) ) == 0 );

    /* Corrupt message */
    memcpy( buf, ecjpake_test_kkpp, sizeof( ecjpake_test_kkpp ) );
    buf[sizeof( ecjpake_test_kkpp ) - 1]--;
    TEST_ASSERT( ecjpake_kkpp_read( md_info, &grp, &grp.G,
                                    &Xa, &Xb, "client",
                                    buf, sizeof( ecjpake_test_kkpp ) )
                    == MBEDTLS_ERR_ECP_VERIFY_FAILED );

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    if( verbose != 0 )
        mbedtls_printf( "  ECJPAKE test #2 (kkpp write/read): " );

    TEST_ASSERT( ecjpake_kkpp_write( md_info, &grp, &grp.G,
                                     &xa, &Xa, &xb, &Xb, "client",
                                     buf, sizeof( buf ), &len,
                                     ecjpake_lgc, NULL ) == 0 );

    TEST_ASSERT( ecjpake_kkpp_read( md_info, &grp, &grp.G,
                                    &Xa, &Xb, "client",
                                    buf, len ) == 0 );

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

cleanup:
    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &Xa );
    mbedtls_ecp_point_free( &Xb );
    mbedtls_mpi_free( &xa );
    mbedtls_mpi_free( &xb );

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

#undef TEST_ASSERT

#endif /* MBEDTLS_ECP_DP_SECP256R1_ENABLED && MBEDTLS_SHA256_C */

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_ECJPAKE_C */
