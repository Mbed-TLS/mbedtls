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

#if defined(_MSC_VER) && !defined(inline)
#define inline _inline
#else
#if defined(__ARMCC_VERSION) && !defined(inline)
#define inline __inline
#endif /* __ARMCC_VERSION */
#endif /*_MSC_VER */

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
 *  - TLS NamedCurve ID (RFC 4492 sec. 5.1.1, RFC 7071 sec. 2)
 *  - size in bits
 *  - readable name
 */
const ecp_curve_info ecp_supported_curves[] =
{
#if defined(POLARSSL_ECP_DP_BP512R1_ENABLED)
    { POLARSSL_ECP_DP_BP512R1,      28,     512,    "brainpool512r1"    },
#endif
#if defined(POLARSSL_ECP_DP_BP384R1_ENABLED)
    { POLARSSL_ECP_DP_BP384R1,      27,     384,    "brainpool384r1"    },
#endif
#if defined(POLARSSL_ECP_DP_BP256R1_ENABLED)
    { POLARSSL_ECP_DP_BP256R1,      26,     256,    "brainpool256r1"    },
#endif
#if defined(POLARSSL_ECP_DP_SECP521R1_ENABLED)
    { POLARSSL_ECP_DP_SECP521R1,    25,     521,    "secp521r1"         },
#endif
#if defined(POLARSSL_ECP_DP_SECP384R1_ENABLED)
    { POLARSSL_ECP_DP_SECP384R1,    24,     384,    "secp384r1"         },
#endif
#if defined(POLARSSL_ECP_DP_SECP256R1_ENABLED)
    { POLARSSL_ECP_DP_SECP256R1,    23,     256,    "secp256r1"         },
#endif
#if defined(POLARSSL_ECP_DP_SECP224R1_ENABLED)
    { POLARSSL_ECP_DP_SECP224R1,    21,     224,    "secp224r1"         },
#endif
#if defined(POLARSSL_ECP_DP_SECP192R1_ENABLED)
    { POLARSSL_ECP_DP_SECP192R1,    19,     192,    "secp192r1"         },
#endif
    { POLARSSL_ECP_DP_NONE,          0,     0,      NULL                },
};

/*
 * List of supported curves and associated info
 */
const ecp_curve_info *ecp_curve_list( void )
{
    return ecp_supported_curves;
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
    mpi_free( &grp->A );
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
 * Copy the contents of a point
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
    buf[0] = (unsigned char) *olen;
    ++*olen;

    return 0;
}

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

/*
 * Import an ECP group from ASCII strings, case A == -3
 */
int ecp_group_read_string( ecp_group *grp, int radix,
                           const char *p, const char *b,
                           const char *gx, const char *gy, const char *n)
{
    int ret;

    MPI_CHK( ecp_group_read_string_gen( grp, radix, p, "00", b, gx, gy, n ) );
    MPI_CHK( mpi_add_int( &grp->A, &grp->P, -3 ) );

cleanup:
    if( ret != 0 )
        ecp_group_free( grp );

    return( ret );
}

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

#if defined(POLARSSL_ECP_NIST_OPTIM)
/* Forward declarations */
static int ecp_mod_p192( mpi * );
static int ecp_mod_p224( mpi * );
static int ecp_mod_p256( mpi * );
static int ecp_mod_p384( mpi * );
static int ecp_mod_p521( mpi * );
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
 * Wrapper around fast quasi-modp functions, with fall-back to mpi_mod_mpi.
 * See the documentation of struct ecp_group.
 *
 * This function is in the critial loop for ecp_mul, so pay attention to perf.
 */
static int ecp_modp( mpi *N, const ecp_group *grp )
{
    int ret;

    if( grp->modp == NULL )
        return( mpi_mod_mpi( N, N, &grp->P ) );

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    if( ( N->s < 0 && mpi_cmp_int( N, 0 ) != 0 ) ||
        mpi_msb( N ) > 2 * grp->pbits )
    {
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );
    }

    MPI_CHK( grp->modp( N ) );

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    while( N->s < 0 && mpi_cmp_int( N, 0 ) != 0 )
        MPI_CHK( mpi_add_mpi( N, N, &grp->P ) );

    while( mpi_cmp_mpi( N, &grp->P ) >= 0 )
        /* we known P, N and the result are positive */
        MPI_CHK( mpi_sub_abs( N, N, &grp->P ) );

cleanup:
    return( ret );
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
 * N->s < 0 is a very fast test, which fails only if N is 0
 */
#define MOD_SUB( N )                                \
    while( N.s < 0 && mpi_cmp_int( &N, 0 ) != 0 )   \
        MPI_CHK( mpi_add_mpi( &N, &N, &grp->P ) )

/*
 * Reduce a mpi mod p in-place, to use after mpi_add_mpi and mpi_mul_int.
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */
#define MOD_ADD( N )                                \
    while( mpi_cmp_mpi( &N, &grp->P ) >= 0 )        \
        MPI_CHK( mpi_sub_abs( &N, &N, &grp->P ) )

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
 * Point doubling R = 2 P, Jacobian coordinates
 *
 * http://www.hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian/doubling/dbl-2007-bl.op3
 * with heavy variable renaming, some reordering and one minor modification
 * (a = 2 * b, c = d - 2a replaced with c = d, c = c - b, c = c - b)
 * in order to use a lot less intermediate variables (6 vs 25).
 */
static int ecp_double_jac( const ecp_group *grp, ecp_point *R,
                           const ecp_point *P )
{
    int ret;
    mpi T1, T2, T3, X3, Y3, Z3;

#if defined(POLARSSL_SELF_TEST)
    dbl_count++;
#endif

    mpi_init( &T1 ); mpi_init( &T2 ); mpi_init( &T3 );
    mpi_init( &X3 ); mpi_init( &Y3 ); mpi_init( &Z3 );

    MPI_CHK( mpi_mul_mpi( &T3,  &P->X,  &P->X   ) ); MOD_MUL( T3 );
    MPI_CHK( mpi_mul_mpi( &T2,  &P->Y,  &P->Y   ) ); MOD_MUL( T2 );
    MPI_CHK( mpi_mul_mpi( &Y3,  &T2,    &T2     ) ); MOD_MUL( Y3 );
    MPI_CHK( mpi_add_mpi( &X3,  &P->X,  &T2     ) ); MOD_ADD( X3 );
    MPI_CHK( mpi_mul_mpi( &X3,  &X3,    &X3     ) ); MOD_MUL( X3 );
    MPI_CHK( mpi_sub_mpi( &X3,  &X3,    &Y3     ) ); MOD_SUB( X3 );
    MPI_CHK( mpi_sub_mpi( &X3,  &X3,    &T3     ) ); MOD_SUB( X3 );
    MPI_CHK( mpi_mul_int( &T1,  &X3,    2       ) ); MOD_ADD( T1 );
    MPI_CHK( mpi_mul_mpi( &Z3,  &P->Z,  &P->Z   ) ); MOD_MUL( Z3 );
    MPI_CHK( mpi_mul_mpi( &X3,  &Z3,    &Z3     ) ); MOD_MUL( X3 );
    MPI_CHK( mpi_mul_int( &T3,  &T3,    3       ) ); MOD_ADD( T3 );
    MPI_CHK( mpi_mul_mpi( &X3,  &X3,    &grp->A ) ); MOD_MUL( X3 );
    MPI_CHK( mpi_add_mpi( &T3,  &T3,    &X3     ) ); MOD_ADD( T3 );
    MPI_CHK( mpi_mul_mpi( &X3,  &T3,    &T3     ) ); MOD_MUL( X3 );
    MPI_CHK( mpi_sub_mpi( &X3,  &X3,    &T1     ) ); MOD_SUB( X3 );
    MPI_CHK( mpi_sub_mpi( &X3,  &X3,    &T1     ) ); MOD_SUB( X3 );
    MPI_CHK( mpi_sub_mpi( &T1,  &T1,    &X3     ) ); MOD_SUB( T1 );
    MPI_CHK( mpi_mul_mpi( &T1,  &T3,    &T1     ) ); MOD_MUL( T1 );
    MPI_CHK( mpi_mul_int( &T3,  &Y3,    8       ) ); MOD_ADD( T3 );
    MPI_CHK( mpi_sub_mpi( &Y3,  &T1,    &T3     ) ); MOD_SUB( Y3 );
    MPI_CHK( mpi_add_mpi( &T1,  &P->Y,  &P->Z   ) ); MOD_ADD( T1 );
    MPI_CHK( mpi_mul_mpi( &T1,  &T1,    &T1     ) ); MOD_MUL( T1 );
    MPI_CHK( mpi_sub_mpi( &T1,  &T1,    &T2     ) ); MOD_SUB( T1 );
    MPI_CHK( mpi_sub_mpi( &Z3,  &T1,    &Z3     ) ); MOD_SUB( Z3 );

    MPI_CHK( mpi_copy( &R->X, &X3 ) );
    MPI_CHK( mpi_copy( &R->Y, &Y3 ) );
    MPI_CHK( mpi_copy( &R->Z, &Z3 ) );

cleanup:
    mpi_free( &T1 ); mpi_free( &T2 ); mpi_free( &T3 );
    mpi_free( &X3 ); mpi_free( &Y3 ); mpi_free( &Z3 );

    return( ret );
}

/*
 * Addition or subtraction: R = P + Q or R = P - Q,
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
    size_t pre_len = 1, naf_len, i, j;
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

    pre_len <<= ( w - 1 );
    naf_len = grp->nbits / w + 1;

    /*
     * Prepare precomputed points: if P == G we want to
     * use grp->T if already initialized, or initiliaze it.
     */
    if( ! p_eq_g || grp->T == NULL )
    {
        T = (ecp_point *) polarssl_malloc( pre_len * sizeof( ecp_point ) );
        if( T == NULL )
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
     * RHS = X (X^2 + A) + B = X^3 + A X + B
     */
    MPI_CHK( mpi_mul_mpi( &YY,  &pt->Y,   &pt->Y  ) );  MOD_MUL( YY  );
    MPI_CHK( mpi_mul_mpi( &RHS, &pt->X,   &pt->X  ) );  MOD_MUL( RHS );
    MPI_CHK( mpi_add_mpi( &RHS, &RHS,     &grp->A ) );  MOD_ADD( RHS );
    MPI_CHK( mpi_mul_mpi( &RHS, &RHS,     &pt->X  ) );  MOD_MUL( RHS );
    MPI_CHK( mpi_add_mpi( &RHS, &RHS,     &grp->B ) );  MOD_ADD( RHS );

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

#if defined(POLARSSL_ECP_NIST_OPTIM)
/*
 * Fast reduction modulo the primes used by the NIST curves.
 *
 * These functions are: critical for speed, but not need for correct
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
static int ecp_mod_p192( mpi *N )
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
#define STORE32     N->p[4*i+0] = (uint8_t)( cur       );   \
                    N->p[4*i+1] = (uint8_t)( cur >> 8  );   \
                    N->p[4*i+2] = (uint8_t)( cur >> 16 );   \
                    N->p[4*i+3] = (uint8_t)( cur >> 24 );

#elif defined(POLARSSL_HAVE_INT16)  /* 16 bit */

#define MAX32       N->n / 2
#define A( j )      (uint32_t)( N->p[2*j] ) | ( N->p[2*j+1] << 16 )
#define STORE32     N->p[2*i+0] = (uint16_t)( cur       );  \
                    N->p[2*i+1] = (uint16_t)( cur >> 16 );

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
        N->p[i/2] |= ((uint64_t) cur) << 32;      \
    } else {                                      \
        N->p[i/2] &= 0xFFFFFFFF00000000;          \
        N->p[i/2] |= (uint64_t) cur;              \
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
static int ecp_mod_p224( mpi *N )
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
static int ecp_mod_p256( mpi *N )
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
static int ecp_mod_p384( mpi *N )
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
static int ecp_mod_p521( mpi *N )
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
    /* exponents especially adapted for secp192r1 */
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

    /* Use secp192r1 if available, or any available curve */
#if defined(POLARSSL_ECP_DP_SECP192R1_ENABLED)
    MPI_CHK( ecp_use_known_dp( &grp, POLARSSL_ECP_DP_SECP192R1 ) );
#else
    MPI_CHK( ecp_use_known_dp( &grp, ecp_curve_list()->grp_id ) );
#endif

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
