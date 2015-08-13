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
 * Initialize context
 */
void mbedtls_ecjpake_init( mbedtls_ecjpake_context *ctx )
{
    if( ctx == NULL )
        return;

    ctx->md_info = NULL;
    mbedtls_ecp_group_init( &ctx->grp );

    mbedtls_ecp_point_init( &ctx->X1 );
    mbedtls_ecp_point_init( &ctx->X2 );
    mbedtls_ecp_point_init( &ctx->X3 );
    mbedtls_ecp_point_init( &ctx->X4 );
    mbedtls_ecp_point_init( &ctx->Xp );

    mbedtls_mpi_init( &ctx->xa );
    mbedtls_mpi_init( &ctx->xb );
    mbedtls_mpi_init( &ctx->s  );
}

/*
 * Free context
 */
void mbedtls_ecjpake_free( mbedtls_ecjpake_context *ctx )
{
    if( ctx == NULL )
        return;

    ctx->md_info = NULL;
    mbedtls_ecp_group_free( &ctx->grp );

    mbedtls_ecp_point_free( &ctx->X1 );
    mbedtls_ecp_point_free( &ctx->X2 );
    mbedtls_ecp_point_free( &ctx->X3 );
    mbedtls_ecp_point_free( &ctx->X4 );
    mbedtls_ecp_point_free( &ctx->Xp );

    mbedtls_mpi_free( &ctx->xa );
    mbedtls_mpi_free( &ctx->xb );
    mbedtls_mpi_free( &ctx->s  );
}

/*
 * Setup context
 */
int mbedtls_ecjpake_setup( mbedtls_ecjpake_context *ctx,
                           mbedtls_md_type_t hash,
                           mbedtls_ecp_group_id curve,
                           const unsigned char *secret,
                           size_t len )
{
    int ret;

    if( ( ctx->md_info = mbedtls_md_info_from_type( hash ) ) == NULL )
        return( MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE );

    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &ctx->grp, curve ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ctx->s, secret, len ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->s, &ctx->s, &ctx->grp.N ) );

cleanup:
    if( ret != 0 )
        mbedtls_ecjpake_free( ctx );

    return( ret );
}

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

/*
 * Read the contents of the ClientHello extension
 */
int mbedtls_ecjpake_tls_read_client_ext( mbedtls_ecjpake_context *ctx,
                                         const unsigned char *buf,
                                         size_t len )
{
    return( ecjpake_kkpp_read( ctx->md_info, &ctx->grp, &ctx->grp.G,
                               &ctx->X1, &ctx->X2, "client",
                               buf, len ) );
}

/*
 * Read the contents of the ServerHello extension
 */
int mbedtls_ecjpake_tls_read_server_ext( mbedtls_ecjpake_context *ctx,
                                         const unsigned char *buf,
                                         size_t len )
{
    return( ecjpake_kkpp_read( ctx->md_info, &ctx->grp, &ctx->grp.G,
                               &ctx->X3, &ctx->X4, "server",
                               buf, len ) );
}

/*
 * Generate the contents of the ClientHello extension
 */
int mbedtls_ecjpake_tls_write_client_ext( mbedtls_ecjpake_context *ctx,
                            unsigned char *buf, size_t len, size_t *olen,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng )
{
    return( ecjpake_kkpp_write( ctx->md_info, &ctx->grp, &ctx->grp.G,
                                &ctx->xa, &ctx->X1, &ctx->xb, &ctx->X2,
                                "client", buf, len, olen, f_rng, p_rng ) );
}

/*
 * Generate the contents of the ServerHello extension
 */
int mbedtls_ecjpake_tls_write_server_ext( mbedtls_ecjpake_context *ctx,
                            unsigned char *buf, size_t len, size_t *olen,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng )
{
    return( ecjpake_kkpp_write( ctx->md_info, &ctx->grp, &ctx->grp.G,
                                &ctx->xa, &ctx->X3, &ctx->xb, &ctx->X4,
                                "server", buf, len, olen, f_rng, p_rng ) );
}

/*
 * Read and process ServerECJPAKEParams (7.4.2.5)
 */
int mbedtls_ecjpake_tls_read_server_params( mbedtls_ecjpake_context *ctx,
                                            const unsigned char *buf,
                                            size_t len )
{
    int ret;
    const unsigned char *p = buf;
    const unsigned char *end = buf + len;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point GB;
    mbedtls_mpi one;

    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &GB );
    mbedtls_mpi_init( &one );

    /*
     * We need that before parsing in order to check Xs as we read it
     * GB = X1 + X2 + X3 (7.4.2.5.1)
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &one, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_muladd( &ctx->grp, &GB, &one, &ctx->X1,
                                                         &one, &ctx->X2 ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_muladd( &ctx->grp, &GB, &one, &GB,
                                                         &one, &ctx->X3 ) );

    /*
     * struct {
     *     ECParameters curve_params;
     *     ECJPAKEKeyKP ecjpake_key_kp;
     * } ServerECJPAKEParams;
     */
    MBEDTLS_MPI_CHK( mbedtls_ecp_tls_read_group( &grp, &p, len ) );
    MBEDTLS_MPI_CHK( ecjpake_kkp_read( ctx->md_info, &ctx->grp,
                            &GB, &ctx->Xp, "server", &p, end ) );

    if( p != end )
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    /*
     * Xs already checked, only thing left to check is the group
     */
    if( grp.id != ctx->grp.id )
    {
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &GB );
    mbedtls_mpi_free( &one );

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

static const unsigned char ecjpake_test_cli_ext[] = {
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

static const unsigned char ecjpake_test_srv_ext[] = {
    0x41, 0x04, 0x7e, 0xa6, 0xe3, 0xa4, 0x48, 0x70, 0x37, 0xa9, 0xe0, 0xdb,
    0xd7, 0x92, 0x62, 0xb2, 0xcc, 0x27, 0x3e, 0x77, 0x99, 0x30, 0xfc, 0x18,
    0x40, 0x9a, 0xc5, 0x36, 0x1c, 0x5f, 0xe6, 0x69, 0xd7, 0x02, 0xe1, 0x47,
    0x79, 0x0a, 0xeb, 0x4c, 0xe7, 0xfd, 0x65, 0x75, 0xab, 0x0f, 0x6c, 0x7f,
    0xd1, 0xc3, 0x35, 0x93, 0x9a, 0xa8, 0x63, 0xba, 0x37, 0xec, 0x91, 0xb7,
    0xe3, 0x2b, 0xb0, 0x13, 0xbb, 0x2b, 0x41, 0x04, 0x09, 0xf8, 0x5b, 0x3d,
    0x20, 0xeb, 0xd7, 0x88, 0x5c, 0xe4, 0x64, 0xc0, 0x8d, 0x05, 0x6d, 0x64,
    0x28, 0xfe, 0x4d, 0xd9, 0x28, 0x7a, 0xa3, 0x65, 0xf1, 0x31, 0xf4, 0x36,
    0x0f, 0xf3, 0x86, 0xd8, 0x46, 0x89, 0x8b, 0xc4, 0xb4, 0x15, 0x83, 0xc2,
    0xa5, 0x19, 0x7f, 0x65, 0xd7, 0x87, 0x42, 0x74, 0x6c, 0x12, 0xa5, 0xec,
    0x0a, 0x4f, 0xfe, 0x2f, 0x27, 0x0a, 0x75, 0x0a, 0x1d, 0x8f, 0xb5, 0x16,
    0x20, 0x93, 0x4d, 0x74, 0xeb, 0x43, 0xe5, 0x4d, 0xf4, 0x24, 0xfd, 0x96,
    0x30, 0x6c, 0x01, 0x17, 0xbf, 0x13, 0x1a, 0xfa, 0xbf, 0x90, 0xa9, 0xd3,
    0x3d, 0x11, 0x98, 0xd9, 0x05, 0x19, 0x37, 0x35, 0x14, 0x41, 0x04, 0x19,
    0x0a, 0x07, 0x70, 0x0f, 0xfa, 0x4b, 0xe6, 0xae, 0x1d, 0x79, 0xee, 0x0f,
    0x06, 0xae, 0xb5, 0x44, 0xcd, 0x5a, 0xdd, 0xaa, 0xbe, 0xdf, 0x70, 0xf8,
    0x62, 0x33, 0x21, 0x33, 0x2c, 0x54, 0xf3, 0x55, 0xf0, 0xfb, 0xfe, 0xc7,
    0x83, 0xed, 0x35, 0x9e, 0x5d, 0x0b, 0xf7, 0x37, 0x7a, 0x0f, 0xc4, 0xea,
    0x7a, 0xce, 0x47, 0x3c, 0x9c, 0x11, 0x2b, 0x41, 0xcc, 0xd4, 0x1a, 0xc5,
    0x6a, 0x56, 0x12, 0x41, 0x04, 0x36, 0x0a, 0x1c, 0xea, 0x33, 0xfc, 0xe6,
    0x41, 0x15, 0x64, 0x58, 0xe0, 0xa4, 0xea, 0xc2, 0x19, 0xe9, 0x68, 0x31,
    0xe6, 0xae, 0xbc, 0x88, 0xb3, 0xf3, 0x75, 0x2f, 0x93, 0xa0, 0x28, 0x1d,
    0x1b, 0xf1, 0xfb, 0x10, 0x60, 0x51, 0xdb, 0x96, 0x94, 0xa8, 0xd6, 0xe8,
    0x62, 0xa5, 0xef, 0x13, 0x24, 0xa3, 0xd9, 0xe2, 0x78, 0x94, 0xf1, 0xee,
    0x4f, 0x7c, 0x59, 0x19, 0x99, 0x65, 0xa8, 0xdd, 0x4a, 0x20, 0x91, 0x84,
    0x7d, 0x2d, 0x22, 0xdf, 0x3e, 0xe5, 0x5f, 0xaa, 0x2a, 0x3f, 0xb3, 0x3f,
    0xd2, 0xd1, 0xe0, 0x55, 0xa0, 0x7a, 0x7c, 0x61, 0xec, 0xfb, 0x8d, 0x80,
    0xec, 0x00, 0xc2, 0xc9, 0xeb, 0x12
};

static const unsigned char ecjpake_test_srv_kx[] = {
    0x03, 0x00, 0x17, 0x41, 0x04, 0x0f, 0xb2, 0x2b, 0x1d, 0x5d, 0x11, 0x23,
    0xe0, 0xef, 0x9f, 0xeb, 0x9d, 0x8a, 0x2e, 0x59, 0x0a, 0x1f, 0x4d, 0x7c,
    0xed, 0x2c, 0x2b, 0x06, 0x58, 0x6e, 0x8f, 0x2a, 0x16, 0xd4, 0xeb, 0x2f,
    0xda, 0x43, 0x28, 0xa2, 0x0b, 0x07, 0xd8, 0xfd, 0x66, 0x76, 0x54, 0xca,
    0x18, 0xc5, 0x4e, 0x32, 0xa3, 0x33, 0xa0, 0x84, 0x54, 0x51, 0xe9, 0x26,
    0xee, 0x88, 0x04, 0xfd, 0x7a, 0xf0, 0xaa, 0xa7, 0xa6, 0x41, 0x04, 0x55,
    0x16, 0xea, 0x3e, 0x54, 0xa0, 0xd5, 0xd8, 0xb2, 0xce, 0x78, 0x6b, 0x38,
    0xd3, 0x83, 0x37, 0x00, 0x29, 0xa5, 0xdb, 0xe4, 0x45, 0x9c, 0x9d, 0xd6,
    0x01, 0xb4, 0x08, 0xa2, 0x4a, 0xe6, 0x46, 0x5c, 0x8a, 0xc9, 0x05, 0xb9,
    0xeb, 0x03, 0xb5, 0xd3, 0x69, 0x1c, 0x13, 0x9e, 0xf8, 0x3f, 0x1c, 0xd4,
    0x20, 0x0f, 0x6c, 0x9c, 0xd4, 0xec, 0x39, 0x22, 0x18, 0xa5, 0x9e, 0xd2,
    0x43, 0xd3, 0xc8, 0x20, 0xff, 0x72, 0x4a, 0x9a, 0x70, 0xb8, 0x8c, 0xb8,
    0x6f, 0x20, 0xb4, 0x34, 0xc6, 0x86, 0x5a, 0xa1, 0xcd, 0x79, 0x06, 0xdd,
    0x7c, 0x9b, 0xce, 0x35, 0x25, 0xf5, 0x08, 0x27, 0x6f, 0x26, 0x83, 0x6c
};

#if 0
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
#endif

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
    mbedtls_ecjpake_context ctx;
    char secret[] = "test passphrase";

    mbedtls_ecjpake_init( &ctx );

    /* Common to all tests */
    TEST_ASSERT( mbedtls_ecjpake_setup( &ctx,
                    MBEDTLS_MD_SHA256, MBEDTLS_ECP_DP_SECP256R1,
                    (const unsigned char *) secret,
                    sizeof( secret ) - 1 ) == 0 );

    if( verbose != 0 )
        mbedtls_printf( "  ECJPAKE test #1 (read in sequence): " );

    /* This is not realistic because it uses the same context for client and
     * server, but it ensures the context has all of X1 to X4 when reading the
     * key exchange message, so this is convenient for a quick test */

    TEST_ASSERT( mbedtls_ecjpake_tls_read_client_ext( &ctx,
                                    ecjpake_test_cli_ext,
                            sizeof( ecjpake_test_cli_ext ) ) == 0 );

    TEST_ASSERT( mbedtls_ecjpake_tls_read_server_ext( &ctx,
                                    ecjpake_test_srv_ext,
                            sizeof( ecjpake_test_srv_ext ) ) == 0 );

    TEST_ASSERT( mbedtls_ecjpake_tls_read_server_params( &ctx,
                                    ecjpake_test_srv_kx,
                            sizeof( ecjpake_test_srv_kx ) ) == 0 );

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

cleanup:
    mbedtls_ecjpake_free( &ctx );

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
