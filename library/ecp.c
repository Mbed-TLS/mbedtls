/*
 *  Elliptic curves over GF(p)
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

/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 * GECC = Guide to Elliptic Curve Cryptography - Hankerson, Menezes, Vanstone
 * FIPS 186-3 http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
 * RFC 4492 for the related TLS structures and constants
 *
 * [1] OKEYA, Katsuyuki and TAKAGI, Tsuyoshi. The width-w NAF method provides
 *     small memory and fast elliptic scalar multiplications secure against
 *     side channel attacks. In : Topics in Cryptology—CT-RSA 2003. Springer
 *     Berlin Heidelberg, 2003. p. 328-343.
 *     <http://rd.springer.com/chapter/10.1007/3-540-36563-X_23>.
 *
 * [2] CORON, Jean-Sébastien. Resistance against differential power analysis
 *     for elliptic curve cryptosystems. In : Cryptographic Hardware and
 *     Embedded Systems. Springer Berlin Heidelberg, 1999. p. 292-302.
 *     <http://link.springer.com/chapter/10.1007/3-540-48059-5_25>
 */

#include "polarssl/config.h"

#if defined(POLARSSL_ECP_C)

#include "polarssl/ecp.h"

#if defined(POLARSSL_MEMORY_C)
#include "polarssl/memory.h"
#else
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

#include <limits.h>
#include <stdlib.h>

#if defined(POLARSSL_SELF_TEST)
/*
 * Counts of point addition and doubling operations.
 * Used to test resistance of point multiplication to simple timing attacks.
 */
unsigned long add_count, dbl_count;
#endif

/*
 * List of supported curves:
 *  - internal ID
 *  - TLS NamedCurve ID (RFC 4492 section 5.1.1)
 *  - size in bits
 *  - readeble name
 */
const ecp_curve_info ecp_supported_curves[] =
{
#if defined(POLARSSL_ECP_DP_SECP521R1_ENABLED)
    { POLARSSL_ECP_DP_SECP521R1,    25,     521,    "secp521r1" },
#endif
#if defined(POLARSSL_ECP_DP_SECP384R1_ENABLED)
    { POLARSSL_ECP_DP_SECP384R1,    24,     384,    "secp384r1" },
#endif
#if defined(POLARSSL_ECP_DP_SECP256R1_ENABLED)
    { POLARSSL_ECP_DP_SECP256R1,    23,     256,    "secp256r1" },
#endif
#if defined(POLARSSL_ECP_DP_SECP224R1_ENABLED)
    { POLARSSL_ECP_DP_SECP224R1,    21,     224,    "secp224r1" },
#endif
#if defined(POLARSSL_ECP_DP_SECP192R1_ENABLED)
    { POLARSSL_ECP_DP_SECP192R1,    19,     192,    "secp192r1" },
#endif
    { POLARSSL_ECP_DP_NONE,          0,     0,      NULL        },
};

/*
 * List of supported curves and associated info
 */
const ecp_curve_info *ecp_curve_list( void )
{
    return ecp_supported_curves;
}

/*
 * Initialize (the components of) a point
 */
void ecp_point_init( ecp_point *pt )
{
    if( pt == NULL )
        return;

    mpi_init( &pt->X );
    mpi_init( &pt->Y );
    mpi_init( &pt->Z );
}

/*
 * Initialize (the components of) a group
 */
void ecp_group_init( ecp_group *grp )
{
    if( grp == NULL )
        return;

    memset( grp, 0, sizeof( ecp_group ) );
}

/*
 * Initialize (the components of) a key pair
 */
void ecp_keypair_init( ecp_keypair *key )
{
    if ( key == NULL )
        return;

    ecp_group_init( &key->grp );
    mpi_init( &key->d );
    ecp_point_init( &key->Q );
}

/*
 * Unallocate (the components of) a point
 */
void ecp_point_free( ecp_point *pt )
{
    if( pt == NULL )
        return;

    mpi_free( &( pt->X ) );
    mpi_free( &( pt->Y ) );
    mpi_free( &( pt->Z ) );
}

/*
 * Unallocate (the components of) a group
 */
void ecp_group_free( ecp_group *grp )
{
    size_t i;

    if( grp == NULL )
        return;

    mpi_free( &grp->P );
    mpi_free( &grp->B );
    ecp_point_free( &grp->G );
    mpi_free( &grp->N );

    if( grp->T != NULL )
    {
        for( i = 0; i < grp->T_size; i++ )
            ecp_point_free( &grp->T[i] );
        polarssl_free( grp->T );
    }

    memset( grp, 0, sizeof( ecp_group ) );
}

/*
 * Unallocate (the components of) a key pair
 */
void ecp_keypair_free( ecp_keypair *key )
{
    if ( key == NULL )
        return;

    ecp_group_free( &key->grp );
    mpi_free( &key->d );
    ecp_point_free( &key->Q );
}

/*
 * Set point to zero
 */
int ecp_set_zero( ecp_point *pt )
{
    int ret;

    MPI_CHK( mpi_lset( &pt->X , 1 ) );
    MPI_CHK( mpi_lset( &pt->Y , 1 ) );
    MPI_CHK( mpi_lset( &pt->Z , 0 ) );

cleanup:
    return( ret );
}

/*
 * Tell if a point is zero
 */
int ecp_is_zero( ecp_point *pt )
{
    return( mpi_cmp_int( &pt->Z, 0 ) == 0 );
}

/*
 * Copy the contents of Q into P
 */
int ecp_copy( ecp_point *P, const ecp_point *Q )
{
    int ret;

    MPI_CHK( mpi_copy( &P->X, &Q->X ) );
    MPI_CHK( mpi_copy( &P->Y, &Q->Y ) );
    MPI_CHK( mpi_copy( &P->Z, &Q->Z ) );

cleanup:
    return( ret );
}

/*
 * Copy the contents of a group object
 */
int ecp_group_copy( ecp_group *dst, const ecp_group *src )
{
    return ecp_use_known_dp( dst, src->id );
}

/*
 * Import a non-zero point from ASCII strings
 */
int ecp_point_read_string( ecp_point *P, int radix,
                           const char *x, const char *y )
{
    int ret;

    MPI_CHK( mpi_read_string( &P->X, radix, x ) );
    MPI_CHK( mpi_read_string( &P->Y, radix, y ) );
    MPI_CHK( mpi_lset( &P->Z, 1 ) );

cleanup:
    return( ret );
}

/*
 * Import an ECP group from ASCII strings
 */
int ecp_group_read_string( ecp_group *grp, int radix,
                           const char *p, const char *b,
                           const char *gx, const char *gy, const char *n)
{
    int ret;

    MPI_CHK( mpi_read_string( &grp->P, radix, p ) );
    MPI_CHK( mpi_read_string( &grp->B, radix, b ) );
    MPI_CHK( ecp_point_read_string( &grp->G, radix, gx, gy ) );
    MPI_CHK( mpi_read_string( &grp->N, radix, n ) );

    grp->pbits = mpi_msb( &grp->P );
    grp->nbits = mpi_msb( &grp->N );

cleanup:
    return( ret );
}

/*
 * Export a point into unsigned binary data (SEC1 2.3.3)
 */
int ecp_point_write_binary( const ecp_group *grp, const ecp_point *P,
                            int format, size_t *olen,
                            unsigned char *buf, size_t buflen )
{
    int ret = 0;
    size_t plen;

    if( format != POLARSSL_ECP_PF_UNCOMPRESSED &&
        format != POLARSSL_ECP_PF_COMPRESSED )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Common case: P == 0
     */
    if( mpi_cmp_int( &P->Z, 0 ) == 0 )
    {
        if( buflen < 1 )
            return( POLARSSL_ERR_ECP_BUFFER_TOO_SMALL );

        buf[0] = 0x00;
        *olen = 1;

        return( 0 );
    }

    plen = mpi_size( &grp->P );

    if( format == POLARSSL_ECP_PF_UNCOMPRESSED )
    {
        *olen = 2 * plen + 1;

        if( buflen < *olen )
            return( POLARSSL_ERR_ECP_BUFFER_TOO_SMALL );

        buf[0] = 0x04;
        MPI_CHK( mpi_write_binary( &P->X, buf + 1, plen ) );
        MPI_CHK( mpi_write_binary( &P->Y, buf + 1 + plen, plen ) );
    }
    else if( format == POLARSSL_ECP_PF_COMPRESSED )
    {
        *olen = plen + 1;

        if( buflen < *olen )
            return( POLARSSL_ERR_ECP_BUFFER_TOO_SMALL );

        buf[0] = 0x02 + mpi_get_bit( &P->Y, 0 );
        MPI_CHK( mpi_write_binary( &P->X, buf + 1, plen ) );
    }

cleanup:
    return( ret );
}

/*
 * Import a point from unsigned binary data (SEC1 2.3.4)
 */
int ecp_point_read_binary( const ecp_group *grp, ecp_point *pt,
                           const unsigned char *buf, size_t ilen ) {
    int ret;
    size_t plen;

    if( ilen == 1 && buf[0] == 0x00 )
        return( ecp_set_zero( pt ) );

    plen = mpi_size( &grp->P );

    if( ilen != 2 * plen + 1 || buf[0] != 0x04 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    MPI_CHK( mpi_read_binary( &pt->X, buf + 1, plen ) );
    MPI_CHK( mpi_read_binary( &pt->Y, buf + 1 + plen, plen ) );
    MPI_CHK( mpi_lset( &pt->Z, 1 ) );

cleanup:
    return( ret );
}

/*
 * Import a point from a TLS ECPoint record (RFC 4492)
 *      struct {
 *          opaque point <1..2^8-1>;
 *      } ECPoint;
 */
int ecp_tls_read_point( const ecp_group *grp, ecp_point *pt,
                        const unsigned char **buf, size_t buf_len )
{
    unsigned char data_len;
    const unsigned char *buf_start;

    /*
     * We must have at least two bytes (1 for length, at least of for data)
     */
    if( buf_len < 2 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    data_len = *(*buf)++;
    if( data_len < 1 || data_len > buf_len - 1 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Save buffer start for read_binary and update buf
     */
    buf_start = *buf;
    *buf += data_len;

    return ecp_point_read_binary( grp, pt, buf_start, data_len );
}

/*
 * Export a point as a TLS ECPoint record (RFC 4492)
 *      struct {
 *          opaque point <1..2^8-1>;
 *      } ECPoint;
 */
int ecp_tls_write_point( const ecp_group *grp, const ecp_point *pt,
                         int format, size_t *olen,
                         unsigned char *buf, size_t blen )
{
    int ret;

    /*
     * buffer length must be at least one, for our length byte
     */
    if( blen < 1 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = ecp_point_write_binary( grp, pt, format,
                    olen, buf + 1, blen - 1) ) != 0 )
        return( ret );

    /*
     * write length to the first byte and update total length
     */
    buf[0] = *olen;
    ++*olen;

    return 0;
}

/*
 * Wrapper around fast quasi-modp functions, with fall-back to mpi_mod_mpi.
 * See the documentation of struct ecp_group.
 */
static int ecp_modp( mpi *N, const ecp_group *grp )
{
    int ret;

    if( grp->modp == NULL )
        return( mpi_mod_mpi( N, N, &grp->P ) );

    if( mpi_cmp_int( N, 0 ) < 0 || mpi_msb( N ) > 2 * grp->pbits )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    MPI_CHK( grp->modp( N ) );

    while( mpi_cmp_int( N, 0 ) < 0 )
        MPI_CHK( mpi_add_mpi( N, N, &grp->P ) );

    while( mpi_cmp_mpi( N, &grp->P ) >= 0 )
        MPI_CHK( mpi_sub_mpi( N, N, &grp->P ) );

cleanup:
    return( ret );
}

#if defined(POLARSSL_ECP_DP_SECP192R1_ENABLED)
/*
 * 192 bits in terms of t_uint
 */
#define P192_SIZE_INT   ( 192 / CHAR_BIT / sizeof( t_uint ) )

/*
 * Table to get S1, S2, S3 of FIPS 186-3 D.2.1:
 * -1 means let this chunk be 0
 * a positive value i means A_i.
 */
#define P192_CHUNKS         3
#define P192_CHUNK_CHAR     ( 64 / CHAR_BIT )
#define P192_CHUNK_INT      ( P192_CHUNK_CHAR / sizeof( t_uint ) )

const signed char p192_tbl[][P192_CHUNKS] = {
    { -1,   3,  3   }, /* S1 */
    { 4,    4,  -1  }, /* S2 */
    { 5,    5,  5   }, /* S3 */
};

/*
 * Fast quasi-reduction modulo p192 (FIPS 186-3 D.2.1)
 */
static int ecp_mod_p192( mpi *N )
{
    int ret;
    unsigned char i, j, offset;
    signed char chunk;
    mpi tmp, acc;
    t_uint tmp_p[P192_SIZE_INT], acc_p[P192_SIZE_INT + 1];

    tmp.s = 1;
    tmp.n = sizeof( tmp_p ) / sizeof( tmp_p[0] );
    tmp.p = tmp_p;

    acc.s = 1;
    acc.n = sizeof( acc_p ) / sizeof( acc_p[0] );
    acc.p = acc_p;

    MPI_CHK( mpi_grow( N, P192_SIZE_INT * 2 ) );

    /*
     * acc = T
     */
    memset( acc_p, 0, sizeof( acc_p ) );
    memcpy( acc_p, N->p, P192_CHUNK_CHAR * P192_CHUNKS );

    for( i = 0; i < sizeof( p192_tbl ) / sizeof( p192_tbl[0] ); i++)
    {
        /*
         * tmp = S_i
         */
        memset( tmp_p, 0, sizeof( tmp_p ) );
        for( j = 0, offset = P192_CHUNKS - 1; j < P192_CHUNKS; j++, offset-- )
        {
            chunk = p192_tbl[i][j];
            if( chunk >= 0 )
                memcpy( tmp_p + offset * P192_CHUNK_INT,
                        N->p + chunk * P192_CHUNK_INT,
                        P192_CHUNK_CHAR );
        }

        /*
         * acc += tmp
         */
        MPI_CHK( mpi_add_abs( &acc, &acc, &tmp ) );
    }

    MPI_CHK( mpi_copy( N, &acc ) );

cleanup:
    return( ret );
}
#endif /* POLARSSL_ECP_DP_SECP192R1_ENABLED */

#if defined(POLARSSL_ECP_DP_SECP521R1_ENABLED)
/*
 * Size of p521 in terms of t_uint
 */
#define P521_SIZE_INT   ( 521 / CHAR_BIT / sizeof( t_uint ) + 1 )

/*
 * Bits to keep in the most significant t_uint
 */
#if defined(POLARSS_HAVE_INT8)
#define P521_MASK       0x01
#else
#define P521_MASK       0x01FF
#endif

/*
 * Fast quasi-reduction modulo p521 (FIPS 186-3 D.2.5)
 */
static int ecp_mod_p521( mpi *N )
{
    int ret;
    t_uint Mp[P521_SIZE_INT];
    mpi M;

    if( N->n < P521_SIZE_INT )
        return( 0 );

    memset( Mp, 0, P521_SIZE_INT * sizeof( t_uint ) );
    memcpy( Mp, N->p, P521_SIZE_INT * sizeof( t_uint ) );
    Mp[P521_SIZE_INT - 1] &= P521_MASK;

    M.s = 1;
    M.n = P521_SIZE_INT;
    M.p = Mp;

    MPI_CHK( mpi_shift_r( N, 521 ) );

    MPI_CHK( mpi_add_abs( N, N, &M ) );

cleanup:
    return( ret );
}
#endif /* POLARSSL_ECP_DP_SECP521R1_ENABLED */

/*
 * Domain parameters for secp192r1
 */
#define SECP192R1_P \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"
#define SECP192R1_B \
    "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1"
#define SECP192R1_GX \
    "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"
#define SECP192R1_GY \
    "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"
#define SECP192R1_N \
    "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"

/*
 * Domain parameters for secp224r1
 */
#define SECP224R1_P \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001"
#define SECP224R1_B \
    "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4"
#define SECP224R1_GX \
    "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
#define SECP224R1_GY \
    "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"
#define SECP224R1_N \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"

/*
 * Domain parameters for secp256r1
 */
#define SECP256R1_P \
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
#define SECP256R1_B \
    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"
#define SECP256R1_GX \
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
#define SECP256R1_GY \
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
#define SECP256R1_N \
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"

/*
 * Domain parameters for secp384r1
 */
#define SECP384R1_P \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
    "FFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"
#define SECP384R1_B \
    "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE814112" \
    "0314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"
#define SECP384R1_GX \
    "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B98" \
    "59F741E082542A385502F25DBF55296C3A545E3872760AB7"
#define SECP384R1_GY \
    "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147C" \
    "E9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"
#define SECP384R1_N \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
    "C7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"

/*
 * Domain parameters for secp521r1
 */
#define SECP521R1_P \
    "000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
#define SECP521R1_B \
    "00000051953EB9618E1C9A1F929A21A0B68540EEA2DA725B" \
    "99B315F3B8B489918EF109E156193951EC7E937B1652C0BD" \
    "3BB1BF073573DF883D2C34F1EF451FD46B503F00"
#define SECP521R1_GX \
    "000000C6858E06B70404E9CD9E3ECB662395B4429C648139" \
    "053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127" \
    "A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
#define SECP521R1_GY \
    "0000011839296A789A3BC0045C8A5FB42C7D1BD998F54449" \
    "579B446817AFBD17273E662C97EE72995EF42640C550B901" \
    "3FAD0761353C7086A272C24088BE94769FD16650"
#define SECP521R1_N \
    "000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
    "FFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148" \
    "F709A5D03BB5C9B8899C47AEBB6FB71E91386409"

/*
 * Set a group using well-known domain parameters
 */
int ecp_use_known_dp( ecp_group *grp, ecp_group_id id )
{
    grp->id = id;

    switch( id )
    {
#if defined(POLARSSL_ECP_DP_SECP192R1_ENABLED)
        case POLARSSL_ECP_DP_SECP192R1:
            grp->modp = ecp_mod_p192;
            return( ecp_group_read_string( grp, 16,
                        SECP192R1_P, SECP192R1_B,
                        SECP192R1_GX, SECP192R1_GY, SECP192R1_N ) );
#endif /* POLARSSL_ECP_DP_SECP192R1_ENABLED */

#if defined(POLARSSL_ECP_DP_SECP224R1_ENABLED)
        case POLARSSL_ECP_DP_SECP224R1:
            return( ecp_group_read_string( grp, 16,
                        SECP224R1_P, SECP224R1_B,
                        SECP224R1_GX, SECP224R1_GY, SECP224R1_N ) );
#endif /* POLARSSL_ECP_DP_SECP224R1_ENABLED */

#if defined(POLARSSL_ECP_DP_SECP256R1_ENABLED)
        case POLARSSL_ECP_DP_SECP256R1:
            return( ecp_group_read_string( grp, 16,
                        SECP256R1_P, SECP256R1_B,
                        SECP256R1_GX, SECP256R1_GY, SECP256R1_N ) );
#endif /* POLARSSL_ECP_DP_SECP256R1_ENABLED */

#if defined(POLARSSL_ECP_DP_SECP384R1_ENABLED)
        case POLARSSL_ECP_DP_SECP384R1:
            return( ecp_group_read_string( grp, 16,
                        SECP384R1_P, SECP384R1_B,
                        SECP384R1_GX, SECP384R1_GY, SECP384R1_N ) );
#endif /* POLARSSL_ECP_DP_SECP384R1_ENABLED */

#if defined(POLARSSL_ECP_DP_SECP521R1_ENABLED)
        case POLARSSL_ECP_DP_SECP521R1:
            grp->modp = ecp_mod_p521;
            return( ecp_group_read_string( grp, 16,
                        SECP521R1_P, SECP521R1_B,
                        SECP521R1_GX, SECP521R1_GY, SECP521R1_N ) );
#endif /* POLARSSL_ECP_DP_SECP521R1_ENABLED */

        default:
            grp->id = POLARSSL_ECP_DP_NONE;
            return( POLARSSL_ERR_ECP_FEATURE_UNAVAILABLE );
    }
}

/*
 * Set a group from an ECParameters record (RFC 4492)
 */
int ecp_tls_read_group( ecp_group *grp, const unsigned char **buf, size_t len )
{
    uint16_t tls_id;
    const ecp_curve_info *curve_info;

    /*
     * We expect at least three bytes (see below)
     */
    if( len < 3 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    /*
     * First byte is curve_type; only named_curve is handled
     */
    if( *(*buf)++ != POLARSSL_ECP_TLS_NAMED_CURVE )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    /*
     * Next two bytes are the namedcurve value
     */
    tls_id = *(*buf)++;
    tls_id <<= 8;
    tls_id |= *(*buf)++;

    if( ( curve_info = ecp_curve_info_from_tls_id( tls_id ) ) == NULL )
        return( POLARSSL_ERR_ECP_FEATURE_UNAVAILABLE );

    return ecp_use_known_dp( grp, curve_info->grp_id );
}

/*
 * Write the ECParameters record corresponding to a group (RFC 4492)
 */
int ecp_tls_write_group( const ecp_group *grp, size_t *olen,
                         unsigned char *buf, size_t blen )
{
    const ecp_curve_info *curve_info;

    if( ( curve_info = ecp_curve_info_from_grp_id( grp->id ) ) == NULL )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    /*
     * We are going to write 3 bytes (see below)
     */
    *olen = 3;
    if( blen < *olen )
        return( POLARSSL_ERR_ECP_BUFFER_TOO_SMALL );

    /*
     * First byte is curve_type, always named_curve
     */
    *buf++ = POLARSSL_ECP_TLS_NAMED_CURVE;

    /*
     * Next two bytes are the namedcurve value
     */
    buf[0] = curve_info->tls_id >> 8;
    buf[1] = curve_info->tls_id & 0xFF;

    return 0;
}

/*
 * Get the curve info from the TLS identifier
 */
const ecp_curve_info *ecp_curve_info_from_tls_id( uint16_t tls_id )
{
    const ecp_curve_info *curve_info;

    for( curve_info = ecp_curve_list();
         curve_info->grp_id != POLARSSL_ECP_DP_NONE;
         curve_info++ )
    {
        if( curve_info->tls_id == tls_id )
            return( curve_info );
    }

    return( NULL );
}

/*
 * Get the curve info for the internal identifer
 */
const ecp_curve_info *ecp_curve_info_from_grp_id( ecp_group_id grp_id )
{
    const ecp_curve_info *curve_info;

    for( curve_info = ecp_curve_list();
         curve_info->grp_id != POLARSSL_ECP_DP_NONE;
         curve_info++ )
    {
        if( curve_info->grp_id == grp_id )
            return( curve_info );
    }

    return( NULL );
}

/*
 * Fast mod-p functions expect their argument to be in the 0..p^2 range.
 *
 * In order to guarantee that, we need to ensure that operands of
 * mpi_mul_mpi are in the 0..p range. So, after each operation we will
 * bring the result back to this range.
 *
 * The following macros are shortcuts for doing that.
 */

/*
 * Reduce a mpi mod p in-place, general case, to use after mpi_mul_mpi
 */
#define MOD_MUL( N )    MPI_CHK( ecp_modp( &N, grp ) )

/*
 * Reduce a mpi mod p in-place, to use after mpi_sub_mpi
 */
#define MOD_SUB( N )                                \
    while( mpi_cmp_int( &N, 0 ) < 0 )               \
        MPI_CHK( mpi_add_mpi( &N, &N, &grp->P ) )

/*
 * Reduce a mpi mod p in-place, to use after mpi_add_mpi and mpi_mul_int
 */
#define MOD_ADD( N )                                \
    while( mpi_cmp_mpi( &N, &grp->P ) >= 0 )        \
        MPI_CHK( mpi_sub_mpi( &N, &N, &grp->P ) )

/*
 * Normalize jacobian coordinates so that Z == 0 || Z == 1  (GECC 3.2.1)
 */
static int ecp_normalize( const ecp_group *grp, ecp_point *pt )
{
    int ret;
    mpi Zi, ZZi;

    if( mpi_cmp_int( &pt->Z, 0 ) == 0 )
        return( 0 );

    mpi_init( &Zi ); mpi_init( &ZZi );

    /*
     * X = X / Z^2  mod p
     */
    MPI_CHK( mpi_inv_mod( &Zi,      &pt->Z,     &grp->P ) );
    MPI_CHK( mpi_mul_mpi( &ZZi,     &Zi,        &Zi     ) ); MOD_MUL( ZZi );
    MPI_CHK( mpi_mul_mpi( &pt->X,   &pt->X,     &ZZi    ) ); MOD_MUL( pt->X );

    /*
     * Y = Y / Z^3  mod p
     */
    MPI_CHK( mpi_mul_mpi( &pt->Y,   &pt->Y,     &ZZi    ) ); MOD_MUL( pt->Y );
    MPI_CHK( mpi_mul_mpi( &pt->Y,   &pt->Y,     &Zi     ) ); MOD_MUL( pt->Y );

    /*
     * Z = 1
     */
    MPI_CHK( mpi_lset( &pt->Z, 1 ) );

cleanup:

    mpi_free( &Zi ); mpi_free( &ZZi );

    return( ret );
}

/*
 * Normalize jacobian coordinates of an array of points,
 * using Montgomery's trick to perform only one inversion mod P.
 * (See for example Cohen's "A Course in Computational Algebraic Number
 * Theory", Algorithm 10.3.4.)
 *
 * Warning: fails (returning an error) if one of the points is zero!
 * This should never happen, see choice of w in ecp_mul().
 */
static int ecp_normalize_many( const ecp_group *grp,
                               ecp_point T[], size_t t_len )
{
    int ret;
    size_t i;
    mpi *c, u, Zi, ZZi;

    if( t_len < 2 )
        return( ecp_normalize( grp, T ) );

    if( ( c = (mpi *) polarssl_malloc( t_len * sizeof( mpi ) ) ) == NULL )
        return( POLARSSL_ERR_ECP_MALLOC_FAILED );

    mpi_init( &u ); mpi_init( &Zi ); mpi_init( &ZZi );
    for( i = 0; i < t_len; i++ )
        mpi_init( &c[i] );

    /*
     * c[i] = Z_0 * ... * Z_i
     */
    MPI_CHK( mpi_copy( &c[0], &T[0].Z ) );
    for( i = 1; i < t_len; i++ )
    {
        MPI_CHK( mpi_mul_mpi( &c[i], &c[i-1], &T[i].Z ) );
        MOD_MUL( c[i] );
    }

    /*
     * u = 1 / (Z_0 * ... * Z_n) mod P
     */
    MPI_CHK( mpi_inv_mod( &u, &c[t_len-1], &grp->P ) );

    for( i = t_len - 1; ; i-- )
    {
        /*
         * Zi = 1 / Z_i mod p
         * u = 1 / (Z_0 * ... * Z_i) mod P
         */
        if( i == 0 ) {
            MPI_CHK( mpi_copy( &Zi, &u ) );
        }
        else
        {
            MPI_CHK( mpi_mul_mpi( &Zi, &u, &c[i-1] ) ); MOD_MUL( Zi );
            MPI_CHK( mpi_mul_mpi( &u,  &u, &T[i].Z ) ); MOD_MUL( u );
        }

        /*
         * proceed as in normalize()
         */
        MPI_CHK( mpi_mul_mpi( &ZZi,    &Zi,     &Zi     ) ); MOD_MUL( ZZi );
        MPI_CHK( mpi_mul_mpi( &T[i].X, &T[i].X, &ZZi    ) ); MOD_MUL( T[i].X );
        MPI_CHK( mpi_mul_mpi( &T[i].Y, &T[i].Y, &ZZi    ) ); MOD_MUL( T[i].Y );
        MPI_CHK( mpi_mul_mpi( &T[i].Y, &T[i].Y, &Zi     ) ); MOD_MUL( T[i].Y );
        MPI_CHK( mpi_lset( &T[i].Z, 1 ) );

        if( i == 0 )
            break;
    }

cleanup:

    mpi_free( &u ); mpi_free( &Zi ); mpi_free( &ZZi );
    for( i = 0; i < t_len; i++ )
        mpi_free( &c[i] );
    polarssl_free( c );

    return( ret );
}


/*
 * Point doubling R = 2 P, Jacobian coordinates (GECC 3.21)
 */
static int ecp_double_jac( const ecp_group *grp, ecp_point *R,
                           const ecp_point *P )
{
    int ret;
    mpi T1, T2, T3, X, Y, Z;

#if defined(POLARSSL_SELF_TEST)
    dbl_count++;
#endif

    if( mpi_cmp_int( &P->Z, 0 ) == 0 )
        return( ecp_set_zero( R ) );

    mpi_init( &T1 ); mpi_init( &T2 ); mpi_init( &T3 );
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );

    MPI_CHK( mpi_mul_mpi( &T1,  &P->Z,  &P->Z ) );  MOD_MUL( T1 );
    MPI_CHK( mpi_sub_mpi( &T2,  &P->X,  &T1   ) );  MOD_SUB( T2 );
    MPI_CHK( mpi_add_mpi( &T1,  &P->X,  &T1   ) );  MOD_ADD( T1 );
    MPI_CHK( mpi_mul_mpi( &T2,  &T2,    &T1   ) );  MOD_MUL( T2 );
    MPI_CHK( mpi_mul_int( &T2,  &T2,    3     ) );  MOD_ADD( T2 );
    MPI_CHK( mpi_mul_int( &Y,   &P->Y,  2     ) );  MOD_ADD( Y  );
    MPI_CHK( mpi_mul_mpi( &Z,   &Y,     &P->Z ) );  MOD_MUL( Z  );
    MPI_CHK( mpi_mul_mpi( &Y,   &Y,     &Y    ) );  MOD_MUL( Y  );
    MPI_CHK( mpi_mul_mpi( &T3,  &Y,     &P->X ) );  MOD_MUL( T3 );
    MPI_CHK( mpi_mul_mpi( &Y,   &Y,     &Y    ) );  MOD_MUL( Y  );

    /*
     * For Y = Y / 2 mod p, we must make sure that Y is even before
     * using right-shift. No need to reduce mod p afterwards.
     */
    if( mpi_get_bit( &Y, 0 ) == 1 )
        MPI_CHK( mpi_add_mpi( &Y, &Y, &grp->P ) );
    MPI_CHK( mpi_shift_r( &Y,   1             ) );

    MPI_CHK( mpi_mul_mpi( &X,   &T2,    &T2   ) );  MOD_MUL( X  );
    MPI_CHK( mpi_mul_int( &T1,  &T3,    2     ) );  MOD_ADD( T1 );
    MPI_CHK( mpi_sub_mpi( &X,   &X,     &T1   ) );  MOD_SUB( X  );
    MPI_CHK( mpi_sub_mpi( &T1,  &T3,    &X    ) );  MOD_SUB( T1 );
    MPI_CHK( mpi_mul_mpi( &T1,  &T1,    &T2   ) );  MOD_MUL( T1 );
    MPI_CHK( mpi_sub_mpi( &Y,   &T1,    &Y    ) );  MOD_SUB( Y  );

    MPI_CHK( mpi_copy( &R->X, &X ) );
    MPI_CHK( mpi_copy( &R->Y, &Y ) );
    MPI_CHK( mpi_copy( &R->Z, &Z ) );

cleanup:

    mpi_free( &T1 ); mpi_free( &T2 ); mpi_free( &T3 );
    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );

    return( ret );
}

/*
 * Addition or subtraction: R = P + Q or R = P + Q,
 * mixed affine-Jacobian coordinates (GECC 3.22)
 *
 * The coordinates of Q must be normalized (= affine),
 * but those of P don't need to. R is not normalized.
 *
 * If sign >= 0, perform addition, otherwise perform subtraction,
 * taking advantage of the fact that, for Q != 0, we have
 * -Q = (Q.X, -Q.Y, Q.Z)
 */
static int ecp_add_mixed( const ecp_group *grp, ecp_point *R,
                          const ecp_point *P, const ecp_point *Q,
                          signed char sign )
{
    int ret;
    mpi T1, T2, T3, T4, X, Y, Z;

#if defined(POLARSSL_SELF_TEST)
    add_count++;
#endif

    /*
     * Trivial cases: P == 0 or Q == 0
     * (Check Q first, so that we know Q != 0 when we compute -Q.)
     */
    if( mpi_cmp_int( &Q->Z, 0 ) == 0 )
        return( ecp_copy( R, P ) );

    if( mpi_cmp_int( &P->Z, 0 ) == 0 )
    {
        ret = ecp_copy( R, Q );

        /*
         * -R.Y mod P = P - R.Y unless R.Y == 0
         */
        if( ret == 0 && sign < 0)
            if( mpi_cmp_int( &R->Y, 0 ) != 0 )
                ret = mpi_sub_mpi( &R->Y, &grp->P, &R->Y );

        return( ret );
    }

    /*
     * Make sure Q coordinates are normalized
     */
    if( mpi_cmp_int( &Q->Z, 1 ) != 0 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    mpi_init( &T1 ); mpi_init( &T2 ); mpi_init( &T3 ); mpi_init( &T4 );
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );

    MPI_CHK( mpi_mul_mpi( &T1,  &P->Z,  &P->Z ) );  MOD_MUL( T1 );
    MPI_CHK( mpi_mul_mpi( &T2,  &T1,    &P->Z ) );  MOD_MUL( T2 );
    MPI_CHK( mpi_mul_mpi( &T1,  &T1,    &Q->X ) );  MOD_MUL( T1 );
    MPI_CHK( mpi_mul_mpi( &T2,  &T2,    &Q->Y ) );  MOD_MUL( T2 );

    /*
     * For subtraction, -Q.Y should have been used instead of Q.Y,
     * so we replace T2 by -T2, which is P - T2 mod P
     */
    if( sign < 0 )
    {
        MPI_CHK( mpi_sub_mpi( &T2, &grp->P, &T2 ) );
        MOD_SUB( T2 );
    }

    MPI_CHK( mpi_sub_mpi( &T1,  &T1,    &P->X ) );  MOD_SUB( T1 );
    MPI_CHK( mpi_sub_mpi( &T2,  &T2,    &P->Y ) );  MOD_SUB( T2 );

    if( mpi_cmp_int( &T1, 0 ) == 0 )
    {
        if( mpi_cmp_int( &T2, 0 ) == 0 )
        {
            ret = ecp_double_jac( grp, R, P );
            goto cleanup;
        }
        else
        {
            ret = ecp_set_zero( R );
            goto cleanup;
        }
    }

    MPI_CHK( mpi_mul_mpi( &Z,   &P->Z,  &T1   ) );  MOD_MUL( Z  );
    MPI_CHK( mpi_mul_mpi( &T3,  &T1,    &T1   ) );  MOD_MUL( T3 );
    MPI_CHK( mpi_mul_mpi( &T4,  &T3,    &T1   ) );  MOD_MUL( T4 );
    MPI_CHK( mpi_mul_mpi( &T3,  &T3,    &P->X ) );  MOD_MUL( T3 );
    MPI_CHK( mpi_mul_int( &T1,  &T3,    2     ) );  MOD_ADD( T1 );
    MPI_CHK( mpi_mul_mpi( &X,   &T2,    &T2   ) );  MOD_MUL( X  );
    MPI_CHK( mpi_sub_mpi( &X,   &X,     &T1   ) );  MOD_SUB( X  );
    MPI_CHK( mpi_sub_mpi( &X,   &X,     &T4   ) );  MOD_SUB( X  );
    MPI_CHK( mpi_sub_mpi( &T3,  &T3,    &X    ) );  MOD_SUB( T3 );
    MPI_CHK( mpi_mul_mpi( &T3,  &T3,    &T2   ) );  MOD_MUL( T3 );
    MPI_CHK( mpi_mul_mpi( &T4,  &T4,    &P->Y ) );  MOD_MUL( T4 );
    MPI_CHK( mpi_sub_mpi( &Y,   &T3,    &T4   ) );  MOD_SUB( Y  );

    MPI_CHK( mpi_copy( &R->X, &X ) );
    MPI_CHK( mpi_copy( &R->Y, &Y ) );
    MPI_CHK( mpi_copy( &R->Z, &Z ) );

cleanup:

    mpi_free( &T1 ); mpi_free( &T2 ); mpi_free( &T3 ); mpi_free( &T4 );
    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );

    return( ret );
}

/*
 * Addition: R = P + Q, result's coordinates normalized
 */
int ecp_add( const ecp_group *grp, ecp_point *R,
             const ecp_point *P, const ecp_point *Q )
{
    int ret;

    MPI_CHK( ecp_add_mixed( grp, R, P, Q , 1 ) );
    MPI_CHK( ecp_normalize( grp, R ) );

cleanup:
    return( ret );
}

/*
 * Subtraction: R = P - Q, result's coordinates normalized
 */
int ecp_sub( const ecp_group *grp, ecp_point *R,
             const ecp_point *P, const ecp_point *Q )
{
    int ret;

    MPI_CHK( ecp_add_mixed( grp, R, P, Q, -1 ) );
    MPI_CHK( ecp_normalize( grp, R ) );

cleanup:
    return( ret );
}

/*
 * Compute a modified width-w non-adjacent form (NAF) of a number,
 * with a fixed pattern for resistance to simple timing attacks (even SPA),
 * see [1]. (The resulting multiplication algorithm can also been seen as a
 * modification of 2^w-ary multiplication, with signed coefficients, all of
 * them odd.)
 *
 * Input:
 * m must be an odd positive mpi less than w * k bits long
 * x must be an array of k elements
 * w must be less than a certain maximum (currently 8)
 *
 * The result is a sequence x[0], ..., x[k-1] with x[i] in the range
 * - 2^(width - 1) .. 2^(width - 1) - 1 such that
 * m = (2 * x[0] + 1) + 2^width * (2 * x[1] + 1) + ...
 *     + 2^((k-1) * width) * (2 * x[k-1] + 1)
 *
 * Compared to "Algorithm SPA-resistant Width-w NAF with Odd Scalar"
 * p. 335 of the cited reference, here we return only u, not d_w since
 * it is known that the other d_w[j] will be 0.  Moreover, the returned
 * string doesn't actually store u_i but x_i = u_i / 2 since it is known
 * that u_i is odd. Also, since we always select a positive value for d
 * mod 2^w, we don't need to check the sign of u[i-1] when the reference
 * does. Finally, there is an off-by-one error in the reference: the
 * last index should be k-1, not k.
 */
static int ecp_w_naf_fixed( signed char x[], size_t k,
                            unsigned char w, const mpi *m )
{
    int ret;
    unsigned int i, u, mask, carry;
    mpi M;

    mpi_init( &M );

    MPI_CHK( mpi_copy( &M, m ) );
    mask = ( 1 << w ) - 1;
    carry = 1 << ( w - 1 );

    for( i = 0; i < k; i++ )
    {
        u = M.p[0] & mask;

        if( ( u & 1 ) == 0 && i > 0 )
            x[i - 1] -= carry;

        x[i] = u >> 1;
        mpi_shift_r( &M, w );
    }

    /*
     * We should have consumed all bits, unless the input value was too big
     */
    if( mpi_cmp_int( &M, 0 ) != 0 )
        ret = POLARSSL_ERR_ECP_BAD_INPUT_DATA;

cleanup:

    mpi_free( &M );

    return( ret );
}

/*
 * Precompute odd multiples of P up to (2 * t_len - 1) P.
 * The table is filled with T[i] = (2 * i + 1) P.
 */
static int ecp_precompute( const ecp_group *grp,
                           ecp_point T[], size_t t_len,
                           const ecp_point *P )
{
    int ret;
    size_t i;
    ecp_point PP;

    ecp_point_init( &PP );

    MPI_CHK( ecp_add( grp, &PP, P, P ) );

    MPI_CHK( ecp_copy( &T[0], P ) );

    for( i = 1; i < t_len; i++ )
        MPI_CHK( ecp_add_mixed( grp, &T[i], &T[i-1], &PP, +1 ) );

    /*
     * T[0] = P already has normalized coordinates
     */
    MPI_CHK( ecp_normalize_many( grp, T + 1, t_len - 1 ) );

cleanup:

    ecp_point_free( &PP );

    return( ret );
}

/*
 * Randomize jacobian coordinates:
 * (X, Y, Z) -> (l^2 X, l^3 Y, l Z) for random l
 * This is sort of the reverse operation of ecp_normalize().
 */
static int ecp_randomize_coordinates( const ecp_group *grp, ecp_point *pt,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;
    mpi l, ll;
    size_t p_size = (grp->pbits + 7) / 8;
    int count = 0;

    mpi_init( &l ); mpi_init( &ll );

    /* Generate l such that 1 < l < p */
    do
    {
        mpi_fill_random( &l, p_size, f_rng, p_rng );

        while( mpi_cmp_mpi( &l, &grp->P ) >= 0 )
            mpi_shift_r( &l, 1 );

        if( count++ > 10 )
            return( POLARSSL_ERR_ECP_RANDOM_FAILED );
    }
    while( mpi_cmp_int( &l, 1 ) <= 0 );

    /* Z = l * Z */
    MPI_CHK( mpi_mul_mpi( &pt->Z,   &pt->Z,     &l  ) ); MOD_MUL( pt->Z );

    /* X = l^2 * X */
    MPI_CHK( mpi_mul_mpi( &ll,      &l,         &l  ) ); MOD_MUL( ll );
    MPI_CHK( mpi_mul_mpi( &pt->X,   &pt->X,     &ll ) ); MOD_MUL( pt->X );

    /* Y = l^3 * Y */
    MPI_CHK( mpi_mul_mpi( &ll,      &ll,        &l  ) ); MOD_MUL( ll );
    MPI_CHK( mpi_mul_mpi( &pt->Y,   &pt->Y,     &ll ) ); MOD_MUL( pt->Y );

cleanup:
    mpi_free( &l ); mpi_free( &ll );

    return( ret );
}

/*
 * Maximum length of the precomputed table
 */
#define MAX_PRE_LEN     ( 1 << (POLARSSL_ECP_WINDOW_SIZE - 1) )

/*
 * Maximum length of the NAF: ceil( grp->nbits + 1 ) / w
 * (that is: grp->nbits / w + 1)
 * Allow p_bits + 1 bits in case M = grp->N + 1 is one bit longer than N.
 */
#define MAX_NAF_LEN     ( POLARSSL_ECP_MAX_BITS / 2 + 1 )

/*
 * Integer multiplication: R = m * P
 *
 * Based on fixed-pattern width-w NAF, see comments of ecp_w_naf_fixed().
 *
 * This function executes a fixed number of operations for
 * random m in the range 0 .. 2^nbits - 1.
 *
 * As an additional countermeasure against potential timing attacks,
 * we randomize coordinates before each addition. This was suggested as a
 * countermeasure against DPA in 5.3 of [2] (with the obvious adaptation that
 * we use jacobian coordinates, not standard projective coordinates).
 */
int ecp_mul( ecp_group *grp, ecp_point *R,
             const mpi *m, const ecp_point *P,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;
    unsigned char w, m_is_odd, p_eq_g;
    size_t pre_len, naf_len, i, j;
    signed char naf[ MAX_NAF_LEN ];
    ecp_point Q, *T = NULL, S[2];
    mpi M;

    if( mpi_cmp_int( m, 0 ) < 0 || mpi_msb( m ) > grp->nbits )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    mpi_init( &M );
    ecp_point_init( &Q );
    ecp_point_init( &S[0] );
    ecp_point_init( &S[1] );

    /*
     * Check if P == G
     */
    p_eq_g = ( mpi_cmp_int( &P->Z, 1 ) == 0 &&
               mpi_cmp_mpi( &P->Y, &grp->G.Y ) == 0 &&
               mpi_cmp_mpi( &P->X, &grp->G.X ) == 0 );

    /*
     * If P == G, pre-compute a lot of points: this will be re-used later,
     * otherwise, choose window size depending on curve size
     */
    if( p_eq_g )
        w = POLARSSL_ECP_WINDOW_SIZE;
    else
        w = grp->nbits >= 512 ? 6 :
            grp->nbits >= 224 ? 5 :
                                4;

    /*
     * Make sure w is within the limits.
     * The last test ensures that none of the precomputed points is zero,
     * which wouldn't be handled correctly by ecp_normalize_many().
     * It is only useful for very small curves as used in the test suite.
     */
    if( w > POLARSSL_ECP_WINDOW_SIZE )
        w = POLARSSL_ECP_WINDOW_SIZE;
    if( w < 2 || w >= grp->nbits )
        w = 2;

    pre_len = 1 << ( w - 1 );
    naf_len = grp->nbits / w + 1;

    /*
     * Prepare precomputed points: if P == G we want to
     * use grp->T if already initialized, or initiliaze it.
     */
    if( ! p_eq_g || grp->T == NULL )
    {
        if( ( T = polarssl_malloc( pre_len * sizeof( ecp_point ) ) ) == NULL )
        {
            ret = POLARSSL_ERR_ECP_MALLOC_FAILED;
            goto cleanup;
        }

        for( i = 0; i < pre_len; i++ )
            ecp_point_init( &T[i] );

        MPI_CHK( ecp_precompute( grp, T, pre_len, P ) );

        if( p_eq_g )
        {
            grp->T = T;
            grp->T_size = pre_len;
        }
    }
    else
    {
        T = grp->T;

        /* Should never happen, but we want to be extra sure */
        if( pre_len != grp->T_size )
        {
            ret = POLARSSL_ERR_ECP_BAD_INPUT_DATA;
            goto cleanup;
        }
    }

    /*
     * Make sure M is odd (M = m + 1 or M = m + 2)
     * later we'll get m * P by subtracting P or 2 * P to M * P.
     */
    m_is_odd = ( mpi_get_bit( m, 0 ) == 1 );

    MPI_CHK( mpi_copy( &M, m ) );
    MPI_CHK( mpi_add_int( &M, &M, 1 + m_is_odd ) );

    /*
     * Compute the fixed-pattern NAF of M
     */
    MPI_CHK( ecp_w_naf_fixed( naf, naf_len, w, &M ) );

    /*
     * Compute M * P, using a variant of left-to-right 2^w-ary multiplication:
     * at each step we add (2 * naf[i] + 1) P, then multiply by 2^w.
     *
     * If naf[i] >= 0, we have (2 * naf[i] + 1) P == T[ naf[i] ]
     * Otherwise, (2 * naf[i] + 1) P == - ( 2 * ( - naf[i] - 1 ) + 1) P
     *                               == T[ - naf[i] - 1 ]
     */
    MPI_CHK( ecp_set_zero( &Q ) );
    i = naf_len - 1;
    while( 1 )
    {
        /* Countermeasure (see comments above) */
        if( f_rng != NULL )
            ecp_randomize_coordinates( grp, &Q, f_rng, p_rng );

        if( naf[i] < 0 )
        {
            MPI_CHK( ecp_add_mixed( grp, &Q, &Q, &T[ - naf[i] - 1 ], -1 ) );
        }
        else
        {
            MPI_CHK( ecp_add_mixed( grp, &Q, &Q, &T[ naf[i] ], +1 ) );
        }

        if( i == 0 )
            break;
        i--;

        for( j = 0; j < w; j++ )
        {
            MPI_CHK( ecp_double_jac( grp, &Q, &Q ) );
        }
    }

    /*
     * Now get m * P from M * P
     */
    MPI_CHK( ecp_copy( &S[0], P ) );
    MPI_CHK( ecp_add( grp, &S[1], P, P ) );
    MPI_CHK( ecp_sub( grp, R, &Q, &S[m_is_odd] ) );


cleanup:

    if( T != NULL && ! p_eq_g )
    {
        for( i = 0; i < pre_len; i++ )
            ecp_point_free( &T[i] );
        polarssl_free( T );
    }

    ecp_point_free( &S[1] );
    ecp_point_free( &S[0] );
    ecp_point_free( &Q );
    mpi_free( &M );

    return( ret );
}

/*
 * Check that a point is valid as a public key (SEC1 3.2.3.1)
 */
int ecp_check_pubkey( const ecp_group *grp, const ecp_point *pt )
{
    int ret;
    mpi YY, RHS;

    if( mpi_cmp_int( &pt->Z, 0 ) == 0 )
        return( POLARSSL_ERR_ECP_INVALID_KEY );

    /*
     * pt coordinates must be normalized for our checks
     */
    if( mpi_cmp_int( &pt->Z, 1 ) != 0 )
        return( POLARSSL_ERR_ECP_INVALID_KEY );

    if( mpi_cmp_int( &pt->X, 0 ) < 0 ||
        mpi_cmp_int( &pt->Y, 0 ) < 0 ||
        mpi_cmp_mpi( &pt->X, &grp->P ) >= 0 ||
        mpi_cmp_mpi( &pt->Y, &grp->P ) >= 0 )
        return( POLARSSL_ERR_ECP_INVALID_KEY );

    mpi_init( &YY ); mpi_init( &RHS );

    /*
     * YY = Y^2
     * RHS = X (X^2 - 3) + B = X^3 - 3X + B
     */
    MPI_CHK( mpi_mul_mpi( &YY,  &pt->Y,  &pt->Y   ) );  MOD_MUL( YY  );
    MPI_CHK( mpi_mul_mpi( &RHS, &pt->X,  &pt->X   ) );  MOD_MUL( RHS );
    MPI_CHK( mpi_sub_int( &RHS, &RHS,    3        ) );  MOD_SUB( RHS );
    MPI_CHK( mpi_mul_mpi( &RHS, &RHS,    &pt->X   ) );  MOD_MUL( RHS );
    MPI_CHK( mpi_add_mpi( &RHS, &RHS,    &grp->B  ) );  MOD_ADD( RHS );

    if( mpi_cmp_mpi( &YY, &RHS ) != 0 )
        ret = POLARSSL_ERR_ECP_INVALID_KEY;

cleanup:

    mpi_free( &YY ); mpi_free( &RHS );

    return( ret );
}

/*
 * Check that an mpi is valid as a private key (SEC1 3.2)
 */
int ecp_check_privkey( const ecp_group *grp, const mpi *d )
{
    /* We want 1 <= d <= N-1 */
    if ( mpi_cmp_int( d, 1 ) < 0 || mpi_cmp_mpi( d, &grp->N ) >= 0 )
        return( POLARSSL_ERR_ECP_INVALID_KEY );

    return( 0 );
}

/*
 * Generate a keypair (SEC1 3.2.1)
 */
int ecp_gen_keypair( ecp_group *grp, mpi *d, ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    int count = 0;
    size_t n_size = (grp->nbits + 7) / 8;

    /*
     * Generate d such that 1 <= n < N
     */
    do
    {
        mpi_fill_random( d, n_size, f_rng, p_rng );

        while( mpi_cmp_mpi( d, &grp->N ) >= 0 )
            mpi_shift_r( d, 1 );

        if( count++ > 10 )
            return( POLARSSL_ERR_ECP_RANDOM_FAILED );
    }
    while( mpi_cmp_int( d, 1 ) < 0 );

    return( ecp_mul( grp, Q, d, &grp->G, f_rng, p_rng ) );
}

#if defined(POLARSSL_SELF_TEST)

/*
 * Checkup routine
 */
int ecp_self_test( int verbose )
{
    int ret;
    size_t i;
    ecp_group grp;
    ecp_point R, P;
    mpi m;
    unsigned long add_c_prev, dbl_c_prev;
    const char *exponents[] =
    {
        "000000000000000000000000000000000000000000000000", /* zero */
        "000000000000000000000000000000000000000000000001", /* one */
        "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", /* N */
        "5EA6F389A38B8BC81E767753B15AA5569E1782E30ABE7D25", /* random */
        "400000000000000000000000000000000000000000000000",
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "555555555555555555555555555555555555555555555555",
    };

    ecp_group_init( &grp );
    ecp_point_init( &R );
    ecp_point_init( &P );
    mpi_init( &m );

#if defined(POLARSSL_ECP_DP_SECP192R1_ENABLED)
    MPI_CHK( ecp_use_known_dp( &grp, POLARSSL_ECP_DP_SECP192R1 ) );
#else
#if defined(POLARSSL_ECP_DP_SECP224R1_ENABLED)
    MPI_CHK( ecp_use_known_dp( &grp, POLARSSL_ECP_DP_SECP224R1 ) );
#else
#if defined(POLARSSL_ECP_DP_SECP256R1_ENABLED)
    MPI_CHK( ecp_use_known_dp( &grp, POLARSSL_ECP_DP_SECP256R1 ) );
#else
#if defined(POLARSSL_ECP_DP_SECP384R1_ENABLED)
    MPI_CHK( ecp_use_known_dp( &grp, POLARSSL_ECP_DP_SECP384R1 ) );
#else
#if defined(POLARSSL_ECP_DP_SECP521R1_ENABLED)
    MPI_CHK( ecp_use_known_dp( &grp, POLARSSL_ECP_DP_SECP521R1 ) );
#else
#error No curves defines
#endif /* POLARSSL_ECP_DP_SECP512R1_ENABLED */
#endif /* POLARSSL_ECP_DP_SECP384R1_ENABLED */
#endif /* POLARSSL_ECP_DP_SECP256R1_ENABLED */
#endif /* POLARSSL_ECP_DP_SECP224R1_ENABLED */
#endif /* POLARSSL_ECP_DP_SECP192R1_ENABLED */

    if( verbose != 0 )
        printf( "  ECP test #1 (constant op_count, base point G): " );

    /* Do a dummy multiplication first to trigger precomputation */
    MPI_CHK( mpi_lset( &m, 2 ) );
    MPI_CHK( ecp_mul( &grp, &P, &m, &grp.G, NULL, NULL ) );

    add_count = 0;
    dbl_count = 0;
    MPI_CHK( mpi_read_string( &m, 16, exponents[0] ) );
    MPI_CHK( ecp_mul( &grp, &R, &m, &grp.G, NULL, NULL ) );

    for( i = 1; i < sizeof( exponents ) / sizeof( exponents[0] ); i++ )
    {
        add_c_prev = add_count;
        dbl_c_prev = dbl_count;
        add_count = 0;
        dbl_count = 0;

        MPI_CHK( mpi_read_string( &m, 16, exponents[i] ) );
        MPI_CHK( ecp_mul( &grp, &R, &m, &grp.G, NULL, NULL ) );

        if( add_count != add_c_prev || dbl_count != dbl_c_prev )
        {
            if( verbose != 0 )
                printf( "failed (%zu)\n", i );

            ret = 1;
            goto cleanup;
        }
    }

    if( verbose != 0 )
        printf( "passed\n" );

    if( verbose != 0 )
        printf( "  ECP test #2 (constant op_count, other point): " );
    /* We computed P = 2G last time, use it */

    add_count = 0;
    dbl_count = 0;
    MPI_CHK( mpi_read_string( &m, 16, exponents[0] ) );
    MPI_CHK( ecp_mul( &grp, &R, &m, &P, NULL, NULL ) );

    for( i = 1; i < sizeof( exponents ) / sizeof( exponents[0] ); i++ )
    {
        add_c_prev = add_count;
        dbl_c_prev = dbl_count;
        add_count = 0;
        dbl_count = 0;

        MPI_CHK( mpi_read_string( &m, 16, exponents[i] ) );
        MPI_CHK( ecp_mul( &grp, &R, &m, &P, NULL, NULL ) );

        if( add_count != add_c_prev || dbl_count != dbl_c_prev )
        {
            if( verbose != 0 )
                printf( "failed (%zu)\n", i );

            ret = 1;
            goto cleanup;
        }
    }

    if( verbose != 0 )
        printf( "passed\n" );

cleanup:

    if( ret < 0 && verbose != 0 )
        printf( "Unexpected error, return code = %08X\n", ret );

    ecp_group_free( &grp );
    ecp_point_free( &R );
    ecp_point_free( &P );
    mpi_free( &m );

    if( verbose != 0 )
        printf( "\n" );

    return( ret );
}

#endif

#endif
