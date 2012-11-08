/*
 *  Elliptic curves over GF(p)
 *
 *  Copyright (C) 2012, Brainspark B.V.
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
 */

#include "polarssl/config.h"

#if defined(POLARSSL_ECP_C)

#include "polarssl/ecp.h"

/*
 * Initialize (the components of) a point
 */
void ecp_point_init( ecp_point *pt )
{
    if( pt == NULL )
        return;

    pt->is_zero = 1;
    mpi_init( &pt->X );
    mpi_init( &pt->Y );
}

/*
 * Initialize (the components of) a group
 */
void ecp_group_init( ecp_group *grp )
{
    if( grp == NULL )
        return;

    mpi_init( &grp->P );
    mpi_init( &grp->B );
    ecp_point_init( &grp->G );
    mpi_init( &grp->N );
}

/*
 * Unallocate (the components of) a point
 */
void ecp_point_free( ecp_point *pt )
{
    if( pt == NULL )
        return;

    pt->is_zero = 1;
    mpi_free( &( pt->X ) );
    mpi_free( &( pt->Y ) );
}

/*
 * Unallocate (the components of) a group
 */
void ecp_group_free( ecp_group *grp )
{
    if( grp == NULL )
        return;

    mpi_free( &grp->P );
    mpi_free( &grp->B );
    ecp_point_free( &grp->G );
    mpi_free( &grp->N );
}

/*
 * Set point to zero
 */
void ecp_set_zero( ecp_point *pt )
{
    pt->is_zero = 1;
    mpi_free( &pt->X );
    mpi_free( &pt->Y );
}

/*
 * Copy the contents of Q into P
 */
int ecp_copy( ecp_point *P, const ecp_point *Q )
{
    int ret = 0;

    if( Q->is_zero ) {
        ecp_set_zero( P );
        return( ret );
    }

    P->is_zero = Q->is_zero;
    MPI_CHK( mpi_copy( &P->X, &Q->X ) );
    MPI_CHK( mpi_copy( &P->Y, &Q->Y ) );

cleanup:
    return( ret );
}

/*
 * Import a non-zero point from ASCII strings
 */
int ecp_point_read_string( ecp_point *P, int radix,
                           const char *x, const char *y )
{
    int ret = 0;

    P->is_zero = 0;
    MPI_CHK( mpi_read_string( &P->X, radix, x ) );
    MPI_CHK( mpi_read_string( &P->Y, radix, y ) );

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
    int ret = 0;

    MPI_CHK( mpi_read_string( &grp->P, radix, p ) );
    MPI_CHK( mpi_read_string( &grp->B, radix, b ) );
    MPI_CHK( ecp_point_read_string( &grp->G, radix, gx, gy ) );
    MPI_CHK( mpi_read_string( &grp->N, radix, n ) );

cleanup:
    return( ret );
}

/*
 * Set a group using well-known domain parameters
 */
int ecp_use_known_dp( ecp_group *grp, size_t index )
{
    switch( index )
    {
        case POLARSSL_ECP_DP_SECP192R1:
            return( ecp_group_read_string( grp, 16,
                        POLARSSL_ECP_SECP192R1_P,
                        POLARSSL_ECP_SECP192R1_B,
                        POLARSSL_ECP_SECP192R1_GX,
                        POLARSSL_ECP_SECP192R1_GY,
                        POLARSSL_ECP_SECP192R1_N )
                    );
        case POLARSSL_ECP_DP_SECP224R1:
            return( ecp_group_read_string( grp, 16,
                        POLARSSL_ECP_SECP224R1_P,
                        POLARSSL_ECP_SECP224R1_B,
                        POLARSSL_ECP_SECP224R1_GX,
                        POLARSSL_ECP_SECP224R1_GY,
                        POLARSSL_ECP_SECP224R1_N )
                    );
        case POLARSSL_ECP_DP_SECP256R1:
            return( ecp_group_read_string( grp, 16,
                        POLARSSL_ECP_SECP256R1_P,
                        POLARSSL_ECP_SECP256R1_B,
                        POLARSSL_ECP_SECP256R1_GX,
                        POLARSSL_ECP_SECP256R1_GY,
                        POLARSSL_ECP_SECP256R1_N )
                    );
        case POLARSSL_ECP_DP_SECP384R1:
            return( ecp_group_read_string( grp, 16,
                        POLARSSL_ECP_SECP384R1_P,
                        POLARSSL_ECP_SECP384R1_B,
                        POLARSSL_ECP_SECP384R1_GX,
                        POLARSSL_ECP_SECP384R1_GY,
                        POLARSSL_ECP_SECP384R1_N )
                    );
        case POLARSSL_ECP_DP_SECP521R1:
            return( ecp_group_read_string( grp, 16,
                        POLARSSL_ECP_SECP521R1_P,
                        POLARSSL_ECP_SECP521R1_B,
                        POLARSSL_ECP_SECP521R1_GX,
                        POLARSSL_ECP_SECP521R1_GY,
                        POLARSSL_ECP_SECP521R1_N )
                    );
    }

    return( POLARSSL_ERR_ECP_GENERIC );
}

/*
 * Internal point format used for fast addition/doubling/multiplication:
 * Jacobian coordinates (GECC example 3.20)
 */
typedef struct
{
    mpi X, Y, Z;
}
ecp_ptjac;

/*
 * Convert from affine to Jacobian coordinates
 */
static int ecp_aff_to_jac( ecp_ptjac *jac, ecp_point *aff )
{
    int ret = 0;

    if( aff->is_zero )
    {
        MPI_CHK( mpi_lset( &jac->X, 1 ) );
        MPI_CHK( mpi_lset( &jac->Y, 1 ) );
        MPI_CHK( mpi_lset( &jac->Z, 0 ) );
    }
    else
    {
        MPI_CHK( mpi_copy( &jac->X, &aff->X ) );
        MPI_CHK( mpi_copy( &jac->Y, &aff->Y ) );
        MPI_CHK( mpi_lset( &jac->Z, 1 ) );
    }

cleanup:
    return( ret );
}

/*
 * Convert from Jacobian to affine coordinates
 */
static int ecp_jac_to_aff( const ecp_group *grp,
                           ecp_point *aff, ecp_ptjac *jac )
{
    int ret = 0;
    mpi Zi, ZZi, T;

    if( mpi_cmp_int( &jac->Z, 0 ) == 0 ) {
        ecp_set_zero( aff );
        return( 0 );
    }

    mpi_init( &Zi ); mpi_init( &ZZi ); mpi_init( &T );

    aff->is_zero = 0;

    /*
     * aff.X = jac.X / (jac.Z)^2  mod p
     */
    MPI_CHK( mpi_inv_mod( &Zi, &jac->Z, &grp->P ) );
    MPI_CHK( mpi_mul_mpi( &ZZi, &Zi, &Zi ) );
    MPI_CHK( mpi_mul_mpi( &T, &jac->X, &ZZi ) );
    MPI_CHK( mpi_mod_mpi( &aff->X, &T, &grp->P ) );

    /*
     * aff.Y = jac.Y / (jac.Z)^3  mod p
     */
    MPI_CHK( mpi_mul_mpi( &T, &jac->Y, &ZZi ) );
    MPI_CHK( mpi_mul_mpi( &T, &T, &Zi ) );
    MPI_CHK( mpi_mod_mpi( &aff->Y, &T, &grp->P ) );

cleanup:

    mpi_free( &Zi ); mpi_free( &ZZi ); mpi_free( &T );

    return( ret );
}

/*
 * Addition: R = P + Q, generic case (P != Q, P != 0, Q != 0, R != 0)
 * Cf SEC1 v2 p. 7, item 4
 */
static int ecp_add_generic( const ecp_group *grp, ecp_point *R,
                            const ecp_point *P, const ecp_point *Q )
{
    int ret = 0;
    mpi DX, DY, K, L, LL, X, Y;

    mpi_init( &DX ); mpi_init( &DY ); mpi_init( &K ); mpi_init( &L );
    mpi_init( &LL ); mpi_init( &X ); mpi_init( &Y );

    /*
     * L = (Q.Y - P.Y) / (Q.X - P.X)  mod p
     */
    MPI_CHK( mpi_sub_mpi( &DY, &Q->Y, &P->Y ) );
    MPI_CHK( mpi_sub_mpi( &DX, &Q->X, &P->X ) );
    MPI_CHK( mpi_inv_mod( &K, &DX, &grp->P ) );
    MPI_CHK( mpi_mul_mpi( &K, &K, &DY ) );
    MPI_CHK( mpi_mod_mpi( &L, &K, &grp->P ) );

    /*
     * LL = L^2  mod p
     */
    MPI_CHK( mpi_mul_mpi( &LL, &L, &L ) );
    MPI_CHK( mpi_mod_mpi( &LL, &LL, &grp->P ) );

    /*
     * X  = L^2 - P.X - Q.X
     */
    MPI_CHK( mpi_sub_mpi( &X, &LL, &P->X ) );
    MPI_CHK( mpi_sub_mpi( &X, &X,  &Q->X ) );

    /*
     * Y = L * (P.X - X) - P.Y
     */
    MPI_CHK( mpi_sub_mpi( &Y, &P->X, &X) );
    MPI_CHK( mpi_mul_mpi( &Y, &Y, &L ) );
    MPI_CHK( mpi_sub_mpi( &Y, &Y, &P->Y ) );

    /*
     * R = (X mod p, Y mod p)
     */
    R->is_zero = 0;
    MPI_CHK( mpi_mod_mpi( &R->X, &X, &grp->P ) );
    MPI_CHK( mpi_mod_mpi( &R->Y, &Y, &grp->P ) );

cleanup:

    mpi_free( &DX ); mpi_free( &DY ); mpi_free( &K ); mpi_free( &L );
    mpi_free( &LL ); mpi_free( &X ); mpi_free( &Y );

    return( ret );
}

/*
 * Doubling: R = 2 * P, generic case (P != 0, R != 0)
 * Cf SEC1 v2 p. 7, item 5
 */
static int ecp_double_generic( const ecp_group *grp, ecp_point *R,
                               const ecp_point *P )
{
    int ret = 0;
    mpi LN, LD, K, L, LL, X, Y;

    mpi_init( &LN ); mpi_init( &LD ); mpi_init( &K ); mpi_init( &L );
    mpi_init( &LL ); mpi_init( &X ); mpi_init( &Y );

    /*
     * L = 3 (P.X - 1) (P.X + 1) / (2 P.Y) mod p
     */
    MPI_CHK( mpi_copy( &LD, &P->Y ) );
    MPI_CHK( mpi_shift_l( &LD, 1 ) );
    MPI_CHK( mpi_inv_mod( &K, &LD, &grp->P ) );
    MPI_CHK( mpi_mul_int( &K, &K, 3 ) );
    MPI_CHK( mpi_sub_int( &LN, &P->X, 1 ) );
    MPI_CHK( mpi_mul_mpi( &K, &K, &LN ) );
    MPI_CHK( mpi_add_int( &LN, &P->X, 1 ) );
    MPI_CHK( mpi_mul_mpi( &K, &K, &LN ) );
    MPI_CHK( mpi_mod_mpi( &L, &K, &grp->P ) );

    /*
     * LL = L^2  mod p
     */
    MPI_CHK( mpi_mul_mpi( &LL, &L, &L ) );
    MPI_CHK( mpi_mod_mpi( &LL, &LL, &grp->P ) );

    /*
     * X  = L^2 - 2 * P.X
     */
    MPI_CHK( mpi_sub_mpi( &X, &LL, &P->X ) );
    MPI_CHK( mpi_sub_mpi( &X, &X,  &P->X ) );

    /*
     * Y = L * (P.X - X) - P.Y
     */
    MPI_CHK( mpi_sub_mpi( &Y, &P->X, &X) );
    MPI_CHK( mpi_mul_mpi( &Y, &Y, &L ) );
    MPI_CHK( mpi_sub_mpi( &Y, &Y, &P->Y ) );

    /*
     * R = (X mod p, Y mod p)
     */
    R->is_zero = 0;
    MPI_CHK( mpi_mod_mpi( &R->X, &X, &grp->P ) );
    MPI_CHK( mpi_mod_mpi( &R->Y, &Y, &grp->P ) );

cleanup:

    mpi_free( &LN ); mpi_free( &LD ); mpi_free( &K ); mpi_free( &L );
    mpi_free( &LL ); mpi_free( &X ); mpi_free( &Y );

    return( ret );
}

/*
 * Addition: R = P + Q, cf p. 7 of SEC1 v2
 */
int ecp_add( const ecp_group *grp, ecp_point *R,
             const ecp_point *P, const ecp_point *Q )
{
    int ret = 0;

    if( P->is_zero )
    {
        ret = ecp_copy( R, Q );
    }
    else if( Q->is_zero )
    {
        ret = ecp_copy( R, P );
    }
    else if( mpi_cmp_mpi( &P->X, &Q->X ) != 0 )
    {
        ret = ecp_add_generic( grp, R, P, Q );
    }
    else if( mpi_cmp_int( &P->Y, 0 ) == 0 ||
             mpi_cmp_mpi( &P->Y, &Q->Y ) != 0 )
    {
        ecp_set_zero( R );
    }
    else
    {
        /*
         * P == Q
         */
        ret = ecp_double_generic( grp, R, P );
    }

    return ret;
}

/*
 * Integer multiplication: R = m * P
 * Using Montgomery's Ladder to avoid leaking information about m
 */
int ecp_mul( const ecp_group *grp, ecp_point *R,
             const mpi *m, const ecp_point *P )
{
    int ret = 0;
    size_t pos;
    ecp_point A, B;

    ecp_point_init( &A ); ecp_point_init( &B );

    /*
     * The general method works only for m >= 2
     */
    if( mpi_cmp_int( m, 0 ) == 0 ) {
        ecp_set_zero( R );
        goto cleanup;
    }

    if( mpi_cmp_int( m, 1 ) == 0 ) {
        MPI_CHK( ecp_copy( R, P ) );
        goto cleanup;
    }

    MPI_CHK( ecp_copy( &A, P ) );
    MPI_CHK( ecp_add( grp, &B, P, P ) );

    for( pos = mpi_msb( m ) - 2; ; pos-- )
    {
        if( mpi_get_bit( m, pos ) == 0 )
        {
            MPI_CHK( ecp_add( grp, &B, &A, &B ) );
            MPI_CHK( ecp_add( grp, &A, &A, &A ) ) ;
        }
        else
        {
            MPI_CHK( ecp_add( grp, &A, &A, &B ) );
            MPI_CHK( ecp_add( grp, &B, &B, &B ) ) ;
        }

        if( pos == 0 )
            break;
    }

    MPI_CHK( ecp_copy( R, &A ) );

cleanup:

    ecp_point_free( &A ); ecp_point_free( &B );

    return( ret );
}


#if defined(POLARSSL_SELF_TEST)

/*
 * Checkup routine
 */
int ecp_self_test( int verbose )
{
    return( verbose++ );
}

#endif

#endif
