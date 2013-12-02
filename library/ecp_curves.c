/*
 *  Elliptic curves over GF(p): curve-specific data and functions
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

#if defined(POLARSSL_ECP_C)

#include "polarssl/ecp.h"

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
 * Domain parameters for brainpoolP256r1 (RFC 5639 3.4)
 */
#define BP256R1_P \
    "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"
#define BP256R1_A \
    "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"
#define BP256R1_B \
    "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"
#define BP256R1_GX \
    "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"
#define BP256R1_GY \
    "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"
#define BP256R1_N \
    "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"

/*
 * Domain parameters for brainpoolP384r1 (RFC 5639 3.6)
 */
#define BP384R1_P \
    "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB711" \
    "23ACD3A729901D1A71874700133107EC53"
#define BP384R1_A \
    "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F9" \
    "0F8AA5814A503AD4EB04A8C7DD22CE2826"
#define BP384R1_B \
    "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62" \
    "D57CB4390295DBC9943AB78696FA504C11"
#define BP384R1_GX \
    "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10" \
    "E8E826E03436D646AAEF87B2E247D4AF1E"
#define BP384R1_GY \
    "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129" \
    "280E4646217791811142820341263C5315"
#define BP384R1_N \
    "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425" \
    "A7CF3AB6AF6B7FC3103B883202E9046565"

/*
 * Domain parameters for brainpoolP512r1 (RFC 5639 3.7)
 */
#define BP512R1_P \
    "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308" \
    "717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3"
#define BP512R1_A \
    "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863" \
    "BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA"
#define BP512R1_B \
    "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117" \
    "A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723"
#define BP512R1_GX \
    "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D009" \
    "8EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822"
#define BP512R1_GY \
    "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F81" \
    "11B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892"
#define BP512R1_N \
    "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308" \
    "70553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"

/*
 * Import an ECP group from ASCII strings, general case (A used)
 */
static int ecp_group_read_string_gen( ecp_group *grp, int radix,
                           const char *p, const char *a, const char *b,
                           const char *gx, const char *gy, const char *n)
{
    int ret;

    MPI_CHK( mpi_read_string( &grp->P, radix, p ) );
    MPI_CHK( mpi_read_string( &grp->A, radix, a ) );
    MPI_CHK( mpi_read_string( &grp->B, radix, b ) );
    MPI_CHK( ecp_point_read_string( &grp->G, radix, gx, gy ) );
    MPI_CHK( mpi_read_string( &grp->N, radix, n ) );

    grp->pbits = mpi_msb( &grp->P );
    grp->nbits = mpi_msb( &grp->N );

cleanup:
    if( ret != 0 )
        ecp_group_free( grp );

    return( ret );
}

#if defined(POLARSSL_ECP_NIST_OPTIM)
/* Forward declarations */
int ecp_mod_p192( mpi * );
int ecp_mod_p224( mpi * );
int ecp_mod_p256( mpi * );
int ecp_mod_p384( mpi * );
int ecp_mod_p521( mpi * );
#endif

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
#if defined(POLARSSL_ECP_NIST_OPTIM)
            grp->modp = ecp_mod_p192;
#endif
            return( ecp_group_read_string( grp, 16,
                        SECP192R1_P, SECP192R1_B,
                        SECP192R1_GX, SECP192R1_GY, SECP192R1_N ) );
#endif /* POLARSSL_ECP_DP_SECP192R1_ENABLED */

#if defined(POLARSSL_ECP_DP_SECP224R1_ENABLED)
        case POLARSSL_ECP_DP_SECP224R1:
#if defined(POLARSSL_ECP_NIST_OPTIM)
            grp->modp = ecp_mod_p224;
#endif
            return( ecp_group_read_string( grp, 16,
                        SECP224R1_P, SECP224R1_B,
                        SECP224R1_GX, SECP224R1_GY, SECP224R1_N ) );
#endif /* POLARSSL_ECP_DP_SECP224R1_ENABLED */

#if defined(POLARSSL_ECP_DP_SECP256R1_ENABLED)
        case POLARSSL_ECP_DP_SECP256R1:
#if defined(POLARSSL_ECP_NIST_OPTIM)
            grp->modp = ecp_mod_p256;
#endif
            return( ecp_group_read_string( grp, 16,
                        SECP256R1_P, SECP256R1_B,
                        SECP256R1_GX, SECP256R1_GY, SECP256R1_N ) );
#endif /* POLARSSL_ECP_DP_SECP256R1_ENABLED */

#if defined(POLARSSL_ECP_DP_SECP384R1_ENABLED)
        case POLARSSL_ECP_DP_SECP384R1:
#if defined(POLARSSL_ECP_NIST_OPTIM)
            grp->modp = ecp_mod_p384;
#endif
            return( ecp_group_read_string( grp, 16,
                        SECP384R1_P, SECP384R1_B,
                        SECP384R1_GX, SECP384R1_GY, SECP384R1_N ) );
#endif /* POLARSSL_ECP_DP_SECP384R1_ENABLED */

#if defined(POLARSSL_ECP_DP_SECP521R1_ENABLED)
        case POLARSSL_ECP_DP_SECP521R1:
#if defined(POLARSSL_ECP_NIST_OPTIM)
            grp->modp = ecp_mod_p521;
#endif
            return( ecp_group_read_string( grp, 16,
                        SECP521R1_P, SECP521R1_B,
                        SECP521R1_GX, SECP521R1_GY, SECP521R1_N ) );
#endif /* POLARSSL_ECP_DP_SECP521R1_ENABLED */

#if defined(POLARSSL_ECP_DP_BP256R1_ENABLED)
        case POLARSSL_ECP_DP_BP256R1:
            return( ecp_group_read_string_gen( grp, 16,
                        BP256R1_P, BP256R1_A, BP256R1_B,
                        BP256R1_GX, BP256R1_GY, BP256R1_N ) );
#endif /* POLARSSL_ECP_DP_BP256R1_ENABLED */

#if defined(POLARSSL_ECP_DP_BP384R1_ENABLED)
        case POLARSSL_ECP_DP_BP384R1:
            return( ecp_group_read_string_gen( grp, 16,
                        BP384R1_P, BP384R1_A, BP384R1_B,
                        BP384R1_GX, BP384R1_GY, BP384R1_N ) );
#endif /* POLARSSL_ECP_DP_BP384R1_ENABLED */

#if defined(POLARSSL_ECP_DP_BP512R1_ENABLED)
        case POLARSSL_ECP_DP_BP512R1:
            return( ecp_group_read_string_gen( grp, 16,
                        BP512R1_P, BP512R1_A, BP512R1_B,
                        BP512R1_GX, BP512R1_GY, BP512R1_N ) );
#endif /* POLARSSL_ECP_DP_BP512R1_ENABLED */

        default:
            ecp_group_free( grp );
            return( POLARSSL_ERR_ECP_FEATURE_UNAVAILABLE );
    }
}

#if defined(POLARSSL_ECP_NIST_OPTIM)
/*
 * Fast reduction modulo the primes used by the NIST curves.
 *
 * These functions are critical for speed, but not needed for correct
 * operations. So, we make the choice to heavily rely on the internals of our
 * bignum library, which creates a tight coupling between these functions and
 * our MPI implementation.  However, the coupling between the ECP module and
 * MPI remains loose, since these functions can be deactivated at will.
 */

#if defined(POLARSSL_ECP_DP_SECP192R1_ENABLED)
/*
 * Compared to the way things are presented in FIPS 186-3 D.2,
 * we proceed in columns, from right (least significant chunk) to left,
 * adding chunks to N in place, and keeping a carry for the next chunk.
 * This avoids moving things around in memory, and uselessly adding zeros,
 * compared to the more straightforward, line-oriented approach.
 *
 * For this prime we need to handle data in chunks of 64 bits.
 * Since this is always a multiple of our basic t_uint, we can
 * use a t_uint * to designate such a chunk, and small loops to handle it.
 */

/* Add 64-bit chunks (dst += src) and update carry */
static inline void add64( t_uint *dst, t_uint *src, t_uint *carry )
{
    unsigned char i;
    t_uint c = 0;
    for( i = 0; i < 8 / sizeof( t_uint ); i++, dst++, src++ )
    {
        *dst += c;      c  = ( *dst < c );
        *dst += *src;   c += ( *dst < *src );
    }
    *carry += c;
}

/* Add carry to a 64-bit chunk and update carry */
static inline void carry64( t_uint *dst, t_uint *carry )
{
    unsigned char i;
    for( i = 0; i < 8 / sizeof( t_uint ); i++, dst++ )
    {
        *dst += *carry;
        *carry  = ( *dst < *carry );
    }
}

#define WIDTH       8 / sizeof( t_uint )
#define A( i )      N->p + i * WIDTH
#define ADD( i )    add64( p, A( i ), &c )
#define NEXT        p += WIDTH; carry64( p, &c )
#define LAST        p += WIDTH; *p = c; while( ++p < end ) *p = 0

/*
 * Fast quasi-reduction modulo p192 (FIPS 186-3 D.2.1)
 */
int ecp_mod_p192( mpi *N )
{
    int ret;
    t_uint c = 0;
    t_uint *p, *end;

    /* Make sure we have enough blocks so that A(5) is legal */
    MPI_CHK( mpi_grow( N, 6 * WIDTH ) );

    p = N->p;
    end = p + N->n;

    ADD( 3 ); ADD( 5 );             NEXT; // A0 += A3 + A5
    ADD( 3 ); ADD( 4 ); ADD( 5 );   NEXT; // A1 += A3 + A4 + A5
    ADD( 4 ); ADD( 5 );             LAST; // A2 += A4 + A5

cleanup:
    return( ret );
}

#undef WIDTH
#undef A
#undef ADD
#undef NEXT
#undef LAST
#endif /* POLARSSL_ECP_DP_SECP192R1_ENABLED */

#if defined(POLARSSL_ECP_DP_SECP224R1_ENABLED) ||   \
    defined(POLARSSL_ECP_DP_SECP256R1_ENABLED) ||   \
    defined(POLARSSL_ECP_DP_SECP384R1_ENABLED)
/*
 * The reader is advised to first understand ecp_mod_p192() since the same
 * general structure is used here, but with additional complications:
 * (1) chunks of 32 bits, and (2) subtractions.
 */

/*
 * For these primes, we need to handle data in chunks of 32 bits.
 * This makes it more complicated if we use 64 bits limbs in MPI,
 * which prevents us from using a uniform access method as for p192.
 *
 * So, we define a mini abstraction layer to access 32 bit chunks,
 * load them in 'cur' for work, and store them back from 'cur' when done.
 *
 * While at it, also define the size of N in terms of 32-bit chunks.
 */
#define LOAD32      cur = A( i );

#if defined(POLARSSL_HAVE_INT8)     /* 8 bit */

#define MAX32       N->n / 4
#define A( j )      (uint32_t)( N->p[4*j+0]       ) |  \
                              ( N->p[4*j+1] << 8  ) |  \
                              ( N->p[4*j+2] << 16 ) |  \
                              ( N->p[4*j+3] << 24 )
#define STORE32     N->p[4*i+0] = (t_uint)( cur       );   \
                    N->p[4*i+1] = (t_uint)( cur >> 8  );   \
                    N->p[4*i+2] = (t_uint)( cur >> 16 );   \
                    N->p[4*i+3] = (t_uint)( cur >> 24 );

#elif defined(POLARSSL_HAVE_INT16)  /* 16 bit */

#define MAX32       N->n / 2
#define A( j )      (uint32_t)( N->p[2*j] ) | ( N->p[2*j+1] << 16 )
#define STORE32     N->p[2*i+0] = (t_uint)( cur       );  \
                    N->p[2*i+1] = (t_uint)( cur >> 16 );

#elif defined(POLARSSL_HAVE_INT32)  /* 32 bit */

#define MAX32       N->n
#define A( j )      N->p[j]
#define STORE32     N->p[i] = cur;

#else                               /* 64-bit */

#define MAX32       N->n * 2
#define A( j ) j % 2 ? (uint32_t)( N->p[j/2] >> 32 ) : (uint32_t)( N->p[j/2] )
#define STORE32                                   \
    if( i % 2 ) {                                 \
        N->p[i/2] &= 0x00000000FFFFFFFF;          \
        N->p[i/2] |= ((t_uint) cur) << 32;        \
    } else {                                      \
        N->p[i/2] &= 0xFFFFFFFF00000000;          \
        N->p[i/2] |= (t_uint) cur;                \
    }

#endif /* sizeof( t_uint ) */

/*
 * Helpers for addition and subtraction of chunks, with signed carry.
 */
static inline void add32( uint32_t *dst, uint32_t src, signed char *carry )
{
    *dst += src;
    *carry += ( *dst < src );
}

static inline void sub32( uint32_t *dst, uint32_t src, signed char *carry )
{
    *carry -= ( *dst < src );
    *dst -= src;
}

#define ADD( j )    add32( &cur, A( j ), &c );
#define SUB( j )    sub32( &cur, A( j ), &c );

/*
 * Helpers for the main 'loop'
 * (see fix_negative for the motivation of C)
 */
#define INIT( b )                                           \
    int ret;                                                \
    signed char c = 0, cc;                                  \
    uint32_t cur;                                           \
    size_t i = 0, bits = b;                                 \
    mpi C;                                                  \
    t_uint Cp[ b / 8 / sizeof( t_uint) + 1 ];               \
                                                            \
    C.s = 1;                                                \
    C.n = b / 8 / sizeof( t_uint) + 1;                      \
    C.p = Cp;                                               \
    memset( Cp, 0, C.n * sizeof( t_uint ) );                \
                                                            \
    MPI_CHK( mpi_grow( N, b * 2 / 8 / sizeof( t_uint ) ) ); \
    LOAD32;

#define NEXT                    \
    STORE32; i++; LOAD32;       \
    cc = c; c = 0;              \
    if( cc < 0 )                \
        sub32( &cur, -cc, &c ); \
    else                        \
        add32( &cur, cc, &c );  \

#define LAST                                    \
    STORE32; i++;                               \
    cur = c > 0 ? c : 0; STORE32;               \
    cur = 0; while( ++i < MAX32 ) { STORE32; }  \
    if( c < 0 ) fix_negative( N, c, &C, bits );

/*
 * If the result is negative, we get it in the form
 * c * 2^(bits + 32) + N, with c negative and N positive shorter than 'bits'
 */
static inline int fix_negative( mpi *N, signed char c, mpi *C, size_t bits )
{
    int ret;

    /* C = - c * 2^(bits + 32) */
#if !defined(POLARSSL_HAVE_INT64)
    ((void) bits);
#else
    if( bits == 224 )
        C->p[ C->n - 1 ] = ((t_uint) -c) << 32;
    else
#endif
        C->p[ C->n - 1 ] = (t_uint) -c;

    /* N = - ( C - N ) */
    MPI_CHK( mpi_sub_abs( N, C, N ) );
    N->s = -1;

cleanup:

    return( ret );
}

#if defined(POLARSSL_ECP_DP_SECP224R1_ENABLED)
/*
 * Fast quasi-reduction modulo p224 (FIPS 186-3 D.2.2)
 */
int ecp_mod_p224( mpi *N )
{
    INIT( 224 );

    SUB(  7 ); SUB( 11 );               NEXT; // A0 += -A7 - A11
    SUB(  8 ); SUB( 12 );               NEXT; // A1 += -A8 - A12
    SUB(  9 ); SUB( 13 );               NEXT; // A2 += -A9 - A13
    SUB( 10 ); ADD(  7 ); ADD( 11 );    NEXT; // A3 += -A10 + A7 + A11
    SUB( 11 ); ADD(  8 ); ADD( 12 );    NEXT; // A4 += -A11 + A8 + A12
    SUB( 12 ); ADD(  9 ); ADD( 13 );    NEXT; // A5 += -A12 + A9 + A13
    SUB( 13 ); ADD( 10 );               LAST; // A6 += -A13 + A10

cleanup:
    return( ret );
}
#endif /* POLARSSL_ECP_DP_SECP224R1_ENABLED */

#if defined(POLARSSL_ECP_DP_SECP256R1_ENABLED)
/*
 * Fast quasi-reduction modulo p256 (FIPS 186-3 D.2.3)
 */
int ecp_mod_p256( mpi *N )
{
    INIT( 256 );

    ADD(  8 ); ADD(  9 );
    SUB( 11 ); SUB( 12 ); SUB( 13 ); SUB( 14 );             NEXT; // A0

    ADD(  9 ); ADD( 10 );
    SUB( 12 ); SUB( 13 ); SUB( 14 ); SUB( 15 );             NEXT; // A1

    ADD( 10 ); ADD( 11 );
    SUB( 13 ); SUB( 14 ); SUB( 15 );                        NEXT; // A2

    ADD( 11 ); ADD( 11 ); ADD( 12 ); ADD( 12 ); ADD( 13 );
    SUB( 15 ); SUB(  8 ); SUB(  9 );                        NEXT; // A3

    ADD( 12 ); ADD( 12 ); ADD( 13 ); ADD( 13 ); ADD( 14 );
    SUB(  9 ); SUB( 10 );                                   NEXT; // A4

    ADD( 13 ); ADD( 13 ); ADD( 14 ); ADD( 14 ); ADD( 15 );
    SUB( 10 ); SUB( 11 );                                   NEXT; // A5

    ADD( 14 ); ADD( 14 ); ADD( 15 ); ADD( 15 ); ADD( 14 ); ADD( 13 );
    SUB(  8 ); SUB(  9 );                                   NEXT; // A6

    ADD( 15 ); ADD( 15 ); ADD( 15 ); ADD( 8 );
    SUB( 10 ); SUB( 11 ); SUB( 12 ); SUB( 13 );             LAST; // A7

cleanup:
    return( ret );
}
#endif /* POLARSSL_ECP_DP_SECP256R1_ENABLED */

#if defined(POLARSSL_ECP_DP_SECP384R1_ENABLED)
/*
 * Fast quasi-reduction modulo p384 (FIPS 186-3 D.2.4)
 */
int ecp_mod_p384( mpi *N )
{
    INIT( 384 );

    ADD( 12 ); ADD( 21 ); ADD( 20 );
    SUB( 23 );                                              NEXT; // A0

    ADD( 13 ); ADD( 22 ); ADD( 23 );
    SUB( 12 ); SUB( 20 );                                   NEXT; // A2

    ADD( 14 ); ADD( 23 );
    SUB( 13 ); SUB( 21 );                                   NEXT; // A2

    ADD( 15 ); ADD( 12 ); ADD( 20 ); ADD( 21 );
    SUB( 14 ); SUB( 22 ); SUB( 23 );                        NEXT; // A3

    ADD( 21 ); ADD( 21 ); ADD( 16 ); ADD( 13 ); ADD( 12 ); ADD( 20 ); ADD( 22 );
    SUB( 15 ); SUB( 23 ); SUB( 23 );                        NEXT; // A4

    ADD( 22 ); ADD( 22 ); ADD( 17 ); ADD( 14 ); ADD( 13 ); ADD( 21 ); ADD( 23 );
    SUB( 16 );                                              NEXT; // A5

    ADD( 23 ); ADD( 23 ); ADD( 18 ); ADD( 15 ); ADD( 14 ); ADD( 22 );
    SUB( 17 );                                              NEXT; // A6

    ADD( 19 ); ADD( 16 ); ADD( 15 ); ADD( 23 );
    SUB( 18 );                                              NEXT; // A7

    ADD( 20 ); ADD( 17 ); ADD( 16 );
    SUB( 19 );                                              NEXT; // A8

    ADD( 21 ); ADD( 18 ); ADD( 17 );
    SUB( 20 );                                              NEXT; // A9

    ADD( 22 ); ADD( 19 ); ADD( 18 );
    SUB( 21 );                                              NEXT; // A10

    ADD( 23 ); ADD( 20 ); ADD( 19 );
    SUB( 22 );                                              LAST; // A11

cleanup:
    return( ret );
}
#endif /* POLARSSL_ECP_DP_SECP384R1_ENABLED */

#undef A
#undef LOAD32
#undef STORE32
#undef MAX32
#undef INIT
#undef NEXT
#undef LAST

#endif /* POLARSSL_ECP_DP_SECP224R1_ENABLED ||
          POLARSSL_ECP_DP_SECP256R1_ENABLED ||
          POLARSSL_ECP_DP_SECP384R1_ENABLED */

#if defined(POLARSSL_ECP_DP_SECP521R1_ENABLED)
/*
 * Here we have an actual Mersenne prime, so things are more straightforward.
 * However, chunks are aligned on a 'weird' boundary (521 bits).
 */

/* Size of p521 in terms of t_uint */
#define P521_WIDTH      ( 521 / 8 / sizeof( t_uint ) + 1 )

/* Bits to keep in the most significant t_uint */
#if defined(POLARSSL_HAVE_INT8)
#define P521_MASK       0x01
#else
#define P521_MASK       0x01FF
#endif

/*
 * Fast quasi-reduction modulo p521 (FIPS 186-3 D.2.5)
 * Write N as A1 + 2^521 A0, return A0 + A1
 */
int ecp_mod_p521( mpi *N )
{
    int ret;
    size_t i;
    mpi M;
    t_uint Mp[P521_WIDTH + 1];
    /* Worst case for the size of M is when t_uint is 16 bits:
     * we need to hold bits 513 to 1056, which is 34 limbs, that is
     * P521_WIDTH + 1. Otherwise P521_WIDTH is enough. */

    if( N->n < P521_WIDTH )
        return( 0 );

    /* M = A1 */
    M.s = 1;
    M.n = N->n - ( P521_WIDTH - 1 );
    if( M.n > P521_WIDTH + 1 )
        M.n = P521_WIDTH + 1;
    M.p = Mp;
    memcpy( Mp, N->p + P521_WIDTH - 1, M.n * sizeof( t_uint ) );
    MPI_CHK( mpi_shift_r( &M, 521 % ( 8 * sizeof( t_uint ) ) ) );

    /* N = A0 */
    N->p[P521_WIDTH - 1] &= P521_MASK;
    for( i = P521_WIDTH; i < N->n; i++ )
        N->p[i] = 0;

    /* N = A0 + A1 */
    MPI_CHK( mpi_add_abs( N, N, &M ) );

cleanup:
    return( ret );
}

#undef P521_WIDTH
#undef P521_MASK
#endif /* POLARSSL_ECP_DP_SECP521R1_ENABLED */

#endif /* POLARSSL_ECP_NIST_OPTIM */

#endif
