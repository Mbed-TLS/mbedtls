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
 * Guide to Elliptic Curve Cryptography - Hankerson, Menezes, Vanstone
 */

#include "polarssl/config.h"

#if defined(POLARSSL_ECP_C)

#include "polarssl/ecp.h"

/*
 * Initialize a point
 */
void ecp_point_init( ecp_point *pt )
{
    if( pt == NULL )
        return;

    pt->is_zero = 1;
    mpi_init( &( pt->X ) );
    mpi_init( &( pt->Y ) );
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
    mpi_free( &( pt->X ) );
    mpi_free( &( pt->Y ) );
}

/*
 * Copy the contents of Q into P
 */
int ecp_copy( ecp_point *P, const ecp_point *Q )
{
    int ret = 0;

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
 * Addition: R = P + Q, generic case (P != Q, P != 0, Q != 0, R != 0)
 * Cf SEC1 v2 p. 7, item 4
 */
static int ecp_add_generic( const ecp_group *grp, ecp_point *R,
                            const ecp_point *P, const ecp_point *Q )
{
    int ret = 0;
    mpi DX, DY, K, L, LL, M, X, Y;

    mpi_init( &DX ); mpi_init( &DY ); mpi_init( &K ); mpi_init( &L );
    mpi_init( &LL ); mpi_init( &M ); mpi_init( &X ); mpi_init( &Y );

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
     * M  = L^2 - Q.X
     * X  = L^2 - P.X - Q.X
     */
    MPI_CHK( mpi_mul_mpi( &LL, &L, &L ) );
    MPI_CHK( mpi_mod_mpi( &LL, &LL, &grp->P ) );
    MPI_CHK( mpi_sub_mpi( &M, &LL, &Q->X ) );
    MPI_CHK( mpi_sub_mpi( &X, &M, &P->X ) );

    /*
     * Y = L * (P.X - X) - P.Y = L * (-M) - P.Y
     */
    MPI_CHK( mpi_copy( &Y, &M ) );
    Y.s = - Y.s;
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
    mpi_free( &LL ); mpi_free( &M ); mpi_free( &X ); mpi_free( &Y );

    return( ret );
}

/*
 * Doubling: R = 2 * P, generic case (P != 0, R != 0)
 */
static int ecp_double_generic( const ecp_group *grp, ecp_point *R,
                               const ecp_point *P )
{
    int ret = 0;

    (void) grp;
    (void) R;
    (void) P;

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


#if defined(POLARSSL_SELF_TEST)

/*
 * Return true iff P and Q are the same point
 */
static int ecp_point_eq( const ecp_point *P, const ecp_point *Q )
{
    if( P->is_zero || Q->is_zero )
        return( P->is_zero && Q->is_zero );

    return( mpi_cmp_mpi( &P->X, &Q->X ) == 0 &&
            mpi_cmp_mpi( &P->Y, &Q->Y ) == 0 );
}

/*
 * Checkup routine
 *
 * Data gathered from http://danher6.100webspace.net/ecc/#EFp_interactivo
 * and double-checked using Pari-GP
 */
int ecp_self_test( int verbose )
{
    int ret = 0;
    size_t i;
    ecp_group grp;
    ecp_point O, A, B, C, D, E, F, G, TMP;
    ecp_point add_table[][3] =
    {
        {O, O, O},  {O, A, A},  {A, O, A},
        {A, A, O},  {B, C, O},  {C, B, O},
        {A, D, E},  {D, A, E},  {B, D, F},  {D, B, F},
        {D, D, G},
    };

    ecp_set_zero( &O );
    MPI_CHK( ecp_group_read_string( &grp, 10, "47", "4", "17", "42", "13" ) );
    MPI_CHK( ecp_point_read_string( &A, 10, "13",  "0" ) );
    MPI_CHK( ecp_point_read_string( &B, 10, "14", "11" ) );
    MPI_CHK( ecp_point_read_string( &C, 10, "14", "36" ) );
    MPI_CHK( ecp_point_read_string( &D, 10, "37", "31" ) );
    MPI_CHK( ecp_point_read_string( &E, 10, "34", "14" ) );
    MPI_CHK( ecp_point_read_string( &F, 10, "45",  "7" ) );
    MPI_CHK( ecp_point_read_string( &E, 10, "21", "32" ) );

    if( verbose != 0 )
        printf( "  ECP test #1 (ecp_add): " );

    for( i = 0; i < sizeof( add_table ) / sizeof( add_table[0] ); i++ )
    {
        MPI_CHK( ecp_add( &grp, &TMP, &add_table[i][0], &add_table[i][1] ) );
        if( ! ecp_point_eq( &TMP, &add_table[i][2] ) )
        {
            if( verbose != 0 )
                printf(" failed (%zu)\n", i);

            return( 1 );
        }
    }

cleanup:

    if( ret != 0 && verbose != 0 )
        printf( "Unexpected error, return code = %08X\n", ret );

    ecp_group_free( &grp );
    ecp_point_free( &O ); ecp_point_free( &A ); ecp_point_free( &B );
    ecp_point_free( &C ); ecp_point_free( &D ); ecp_point_free( &E );
    ecp_point_free( &F ); ecp_point_free( &G );

    if( verbose != 0 )
        printf( "\n" );

    return( ret );
}

#endif

#endif
