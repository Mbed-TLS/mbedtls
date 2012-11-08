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
 * Initialize a point in Jacobian coordinates
 */
static void ecp_ptjac_init( ecp_ptjac *P )
{
    mpi_init( &P->X ); mpi_init( &P->Y ); mpi_init( &P->Z );
}

/*
 * Free a point in Jacobian coordinates
 */
static void ecp_ptjac_free( ecp_ptjac *P )
{
    mpi_free( &P->X ); mpi_free( &P->Y ); mpi_free( &P->Z );
}

/*
 * Copy P to R in Jacobian coordinates
 */
static int ecp_ptjac_copy( ecp_ptjac *R, const ecp_ptjac *P )
{
    int ret = 0;

    MPI_CHK( mpi_copy( &R->X, &P->X ) );
    MPI_CHK( mpi_copy( &R->Y, &P->Y ) );
    MPI_CHK( mpi_copy( &R->Z, &P->Z ) );

cleanup:
    return( ret );
}

/*
 * Set P to zero in Jacobian coordinates
 */
static int ecp_ptjac_set_zero( ecp_ptjac *P )
{
    int ret = 0;

    MPI_CHK( mpi_lset( &P->X, 1 ) );
    MPI_CHK( mpi_lset( &P->Y, 1 ) );
    MPI_CHK( mpi_lset( &P->Z, 0 ) );

cleanup:
    return( ret );
}

/*
 * Convert from affine to Jacobian coordinates
 */
static int ecp_aff_to_jac( ecp_ptjac *jac, const ecp_point *aff )
{
    int ret = 0;

    if( aff->is_zero )
        return( ecp_ptjac_set_zero( jac ) );

    MPI_CHK( mpi_copy( &jac->X, &aff->X ) );
    MPI_CHK( mpi_copy( &jac->Y, &aff->Y ) );
    MPI_CHK( mpi_lset( &jac->Z, 1 ) );

cleanup:
    return( ret );
}

/*
 * Convert from Jacobian to affine coordinates
 */
static int ecp_jac_to_aff( const ecp_group *grp,
                           ecp_point *aff, const ecp_ptjac *jac )
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
 * Point doubling R = 2 P, Jacobian coordinates (GECC 3.21)
 */
static int ecp_double_jac( const ecp_group *grp, ecp_ptjac *R,
                           const ecp_ptjac *P )
{
    int ret = 0;
    mpi T1, T2, T3, X, Y, Z;

    if( mpi_cmp_int( &P->Z, 0 ) == 0 )
        return( ecp_ptjac_set_zero( R ) );

    mpi_init( &T1 ); mpi_init( &T2 ); mpi_init( &T3 );
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );

    MPI_CHK( mpi_mul_mpi( &T1,  &P->Z,  &P->Z ) );
    MPI_CHK( mpi_sub_mpi( &T2,  &P->X,  &T1   ) );
    MPI_CHK( mpi_add_mpi( &T1,  &P->X,  &T1   ) );
    MPI_CHK( mpi_mul_mpi( &T2,  &T2,    &T1   ) );
    MPI_CHK( mpi_mul_int( &T2,  &T2,    3     ) );
    MPI_CHK( mpi_copy   ( &Y,   &P->Y         ) );
    MPI_CHK( mpi_shift_l( &Y,   1             ) );
    MPI_CHK( mpi_mul_mpi( &Z,   &Y,     &P->Z ) );
    MPI_CHK( mpi_mul_mpi( &Y,   &Y,     &Y    ) );
    MPI_CHK( mpi_mul_mpi( &T3,  &Y,     &P->X ) );
    MPI_CHK( mpi_mul_mpi( &Y,   &Y,     &Y    ) );
    MPI_CHK( mpi_shift_r( &Y,   1             ) );
    MPI_CHK( mpi_mul_mpi( &X,   &T2,    &T2   ) );
    MPI_CHK( mpi_copy   ( &T1,  &T3           ) );
    MPI_CHK( mpi_shift_l( &T1,  1             ) );
    MPI_CHK( mpi_sub_mpi( &X,   &X,     &T1   ) );
    MPI_CHK( mpi_sub_mpi( &T1,  &T3,    &X    ) );
    MPI_CHK( mpi_mul_mpi( &T1,  &T1,    &T2   ) );
    MPI_CHK( mpi_sub_mpi( &Y,   &T1,    &Y    ) );

    MPI_CHK( mpi_mod_mpi( &R->X, &X, &grp->P ) );
    MPI_CHK( mpi_mod_mpi( &R->Y, &Y, &grp->P ) );
    MPI_CHK( mpi_mod_mpi( &R->Z, &Z, &grp->P ) );

cleanup:

    mpi_free( &T1 ); mpi_free( &T2 ); mpi_free( &T3 );
    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );

    return( ret );
}

/*
 * Addition: R = P + Q, mixed affine-Jacobian coordinates (GECC 3.22)
 */
static int ecp_add_mixed( const ecp_group *grp, ecp_ptjac *R,
                          const ecp_ptjac *P, const ecp_point *Q )
{
    int ret = 0;
    mpi T1, T2, T3, T4, X, Y, Z;

    /*
     * Trivial cases: P == 0 or Q == 0
     */
    if( mpi_cmp_int( &P->Z, 0 ) == 0 )
        return( ecp_aff_to_jac( R, Q ) );

    if( Q->is_zero )
        return( ecp_ptjac_copy( R, P ) );

    mpi_init( &T1 ); mpi_init( &T2 ); mpi_init( &T3 ); mpi_init( &T4 );
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );

    MPI_CHK( mpi_mul_mpi( &T1,  &P->Z,  &P->Z ) );
    MPI_CHK( mpi_mul_mpi( &T2,  &T1,    &P->Z ) );
    MPI_CHK( mpi_mul_mpi( &T1,  &T1,    &Q->X ) );
    MPI_CHK( mpi_mul_mpi( &T2,  &T2,    &Q->Y ) );
    MPI_CHK( mpi_sub_mpi( &T1,  &T1,    &P->X ) );
    MPI_CHK( mpi_sub_mpi( &T2,  &T2,    &P->Y ) );

    if( mpi_cmp_int( &T1, 0 ) == 0 )
    {
        if( mpi_cmp_int( &T2, 0 ) == 0 )
        {
            ret = ecp_double_jac( grp, R, P );
            goto cleanup;
        }
        else
        {
            ret = ecp_ptjac_set_zero( R );
            goto cleanup;
        }
    }

    MPI_CHK( mpi_mul_mpi( &Z,   &P->Z,  &T1   ) );
    MPI_CHK( mpi_mul_mpi( &T3,  &T1,    &T1   ) );
    MPI_CHK( mpi_mul_mpi( &T4,  &T3,    &T1   ) );
    MPI_CHK( mpi_mul_mpi( &T3,  &T3,    &P->X ) );
    MPI_CHK( mpi_mul_int( &T1,  &T3,    2     ) );
    MPI_CHK( mpi_mul_mpi( &X,   &T2,    &T2   ) );
    MPI_CHK( mpi_sub_mpi( &X,   &X,     &T1   ) );
    MPI_CHK( mpi_sub_mpi( &X,   &X,     &T4   ) );
    MPI_CHK( mpi_sub_mpi( &T3,  &T3,    &X    ) );
    MPI_CHK( mpi_mul_mpi( &T3,  &T3,    &T2   ) );
    MPI_CHK( mpi_mul_mpi( &T4,  &T4,    &P->Y ) );
    MPI_CHK( mpi_sub_mpi( &Y,   &T3,    &T4   ) );

    MPI_CHK( mpi_mod_mpi( &R->X, &X, &grp->P ) );
    MPI_CHK( mpi_mod_mpi( &R->Y, &Y, &grp->P ) );
    MPI_CHK( mpi_mod_mpi( &R->Z, &Z, &grp->P ) );

cleanup:

    mpi_free( &T1 ); mpi_free( &T2 ); mpi_free( &T3 ); mpi_free( &T4 );
    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );

    return( ret );
}

/*
 * Addition: R = P + Q, affine wrapper
 */
int ecp_add( const ecp_group *grp, ecp_point *R,
             const ecp_point *P, const ecp_point *Q )
{
    int ret = 0;
    ecp_ptjac J;

    ecp_ptjac_init( &J );

    MPI_CHK( ecp_aff_to_jac( &J, P ) );
    MPI_CHK( ecp_add_mixed( grp, &J, &J, Q ) );
    MPI_CHK( ecp_jac_to_aff( grp, R, &J ) );

cleanup:

    ecp_ptjac_free( &J );

    return( ret );
}

/*
 * Integer multiplication: R = m * P (GECC 5.7, SPA-resistant variant)
 */
int ecp_mul( const ecp_group *grp, ecp_point *R,
             const mpi *m, const ecp_point *P )
{
    int ret = 0;
    size_t pos;
    ecp_ptjac Q[2];

    ecp_ptjac_init( &Q[0] ); ecp_ptjac_init( &Q[1] );

    /*
     * The general method works only for m >= 1
     */
    if( mpi_cmp_int( m, 0 ) == 0 ) {
        ecp_set_zero( R );
        goto cleanup;
    }

    ecp_ptjac_set_zero( &Q[0] );

    for( pos = mpi_msb( m ) - 1 ; ; pos-- )
    {
        MPI_CHK( ecp_double_jac( grp, &Q[0], &Q[0] ) );
        MPI_CHK( ecp_add_mixed( grp, &Q[1], &Q[0], P ) );
        MPI_CHK( ecp_ptjac_copy( &Q[0], &Q[ mpi_get_bit( m, pos ) ] ) );

        if( pos == 0 )
            break;
    }

    MPI_CHK( ecp_jac_to_aff( grp, R, &Q[0] ) );

cleanup:

    ecp_ptjac_free( &Q[0] ); ecp_ptjac_free( &Q[1] );

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
