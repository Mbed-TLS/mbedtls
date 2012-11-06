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

#define dbg(X)  printf(#X " = %s%lu\n", X.s < 0 ? "-" : "", X.p[0])

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

#include "polarssl/error.h"

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
 * Print a point assuming its coordinates are small
 */
static void ecp_point_print( const ecp_point *P )
{
    if( P->is_zero )
        printf( "zero\n" );
    else
        printf( "(%lu, %lu)\n", P->X.p[0], P->Y.p[0] );
}

#define TEST_GROUP_ORDER 13

/*
 * Checkup routine
 *
 * Data for basic tests with small values gathered from
 * http://danher6.100webspace.net/ecc/#EFp_interactivo and double-checked
 * using Pari-GP.
 */
int ecp_self_test( int verbose )
{
    int ret = 0;
    unsigned i;
    ecp_group grp;
    ecp_point O, A, B, C, D, E, F, G, H, TMP;
    ecp_point *add_tbl[][3] =
    {
        { &O, &O, &O }, { &O, &A, &A }, { &A, &O, &A },
        { &A, &A, &O }, { &B, &C, &O }, { &C, &B, &O },
        { &A, &D, &E }, { &D, &A, &E },
        { &B, &D, &F }, { &D, &B, &F },
        { &D, &D, &G }, { &B, &B, &H },
    };
    mpi m;
    ecp_point mul_tbl[TEST_GROUP_ORDER + 1];
    char *mul_tbl_s[TEST_GROUP_ORDER - 1][2] =
    {
        { "17", "42" },
        { "20", "01" },
        { "14", "11" },
        { "34", "33" },
        { "21", "32" },
        { "27", "30" },
        { "27", "17" },
        { "21", "15" },
        { "34", "14" },
        { "14", "36" },
        { "20", "46" },
        { "17", "05" },
    };

    ecp_group_init( &grp );

    ecp_point_init( &O ); ecp_point_init( &A ); ecp_point_init( &B );
    ecp_point_init( &C ); ecp_point_init( &D ); ecp_point_init( &E );
    ecp_point_init( &F ); ecp_point_init( &G ); ecp_point_init( &H );
    ecp_point_init( &TMP );

    mpi_init( &m );

    for( i = 0; i <= TEST_GROUP_ORDER; i++ )
        ecp_point_init( &mul_tbl[i] );

    ecp_set_zero( &O );
    MPI_CHK( ecp_group_read_string( &grp, 10, "47", "4", "17", "42", "13" ) );
    MPI_CHK( ecp_point_read_string( &A, 10, "13", "00" ) );
    MPI_CHK( ecp_point_read_string( &B, 10, "14", "11" ) );
    MPI_CHK( ecp_point_read_string( &C, 10, "14", "36" ) );
    MPI_CHK( ecp_point_read_string( &D, 10, "37", "31" ) );
    MPI_CHK( ecp_point_read_string( &E, 10, "34", "14" ) );
    MPI_CHK( ecp_point_read_string( &F, 10, "45", "07" ) );
    MPI_CHK( ecp_point_read_string( &G, 10, "21", "32" ) );
    MPI_CHK( ecp_point_read_string( &H, 10, "27", "30" ) );

    if( verbose != 0 )
        printf( "  ECP test #1 (ecp_add): " );

    for( i = 0; i < sizeof( add_tbl ) / sizeof( add_tbl[0] ); i++ )
    {
        MPI_CHK( ecp_add( &grp, &TMP, add_tbl[i][0], add_tbl[i][1] ) );
        if( ! ecp_point_eq( &TMP, add_tbl[i][2] ) )
        {
            if( verbose != 0 )
            {
                printf( " failed (%u)\n", i );
                printf( "        GOT: " );
                ecp_point_print( &TMP );
                printf( "   EXPECTED: " );
                ecp_point_print( add_tbl[i][2] );
            }

            return( 1 );
        }
    }

    if (verbose != 0 )
        printf( "passed\n" );

    MPI_CHK( ecp_copy( &mul_tbl[0], &O ) );
    for( i = 1; i <= TEST_GROUP_ORDER - 1; i++ )
        MPI_CHK( ecp_point_read_string( &mul_tbl[i], 10,
                    mul_tbl_s[i-1][0], mul_tbl_s[i-1][1] ) );
    MPI_CHK( ecp_copy( &mul_tbl[TEST_GROUP_ORDER], &O ) );

    if( verbose != 0 )
        printf( "  ECP test #2 (ecp_mul): " );

    for( i = 0; i <= TEST_GROUP_ORDER; i++ )
    {
        MPI_CHK( mpi_lset( &m, i ) );
        MPI_CHK( ecp_mul( &grp, &TMP, &m, &grp.G ) );
        if( ! ecp_point_eq( &TMP, &mul_tbl[i] ) )
        {
            if( verbose != 0 )
            {
                printf( " failed (%u)\n", i );
                printf( "        GOT: " );
                ecp_point_print( &TMP );
                printf( "   EXPECTED: " );
                ecp_point_print( &mul_tbl[i] );
            }

            return( 1 );
        }
    }

    if (verbose != 0 )
        printf( "passed\n" );

cleanup:

    if( ret != 0 && verbose != 0 )
    {
#if defined(POLARSSL_ERROR_C)
        char error_buf[200];
        error_strerror( ret, error_buf, 200 );
        printf( "Unexpected error: %d - %s\n\n", ret, error_buf );
#else
        printf( "Unexpected error: %08X\n", ret );
#endif
    }

    ecp_group_free( &grp ); ecp_point_free( &O ); ecp_point_free( &TMP );

    ecp_point_free( &A ); ecp_point_free( &B ); ecp_point_free( &C );
    ecp_point_free( &D ); ecp_point_free( &E ); ecp_point_free( &F );
    ecp_point_free( &G ); ecp_point_free( &H );

    mpi_free( &m );

    for( i = 0; i <= TEST_GROUP_ORDER; i++ )
        ecp_point_free( &mul_tbl[i] );

    if( verbose != 0 )
        printf( "\n" );

    return( ret );
}

#endif

#endif
