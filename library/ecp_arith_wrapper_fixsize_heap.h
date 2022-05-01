/**
 * \file ecp_arith_wrapper_fixsize_heap.h
 */
/*
 *  Copyright The Mbed TLS Contributors
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
 */

#ifndef MBEDTLS_ECP_ARITH_WRAPPER_FIXSIZE_HEAP_H
#define MBEDTLS_ECP_ARITH_WRAPPER_FIXSIZE_HEAP_H

#include "mbedtls/build_info.h"
#include "mbedtls/ecp.h"

#include "ecp_arith_wrapper_fixsize_heap_typedefs.h"

/*
 *
 * Implementation of internal API
 *
 */

/*
 * Getters
 */
#define getX(pt) ((mbedtls_ecp_mpi_internal*)&((pt)->v.X))
#define getY(pt) ((mbedtls_ecp_mpi_internal*)&((pt)->v.Y))
#define getZ(pt) ((mbedtls_ecp_mpi_internal*)&((pt)->v.Z))

#define getA(grp) ((mbedtls_ecp_mpi_internal   const*)(&((grp)->src->A)))
#define getB(grp) ((mbedtls_ecp_mpi_internal   const*)(&((grp)->src->B)))
#define getG(grp) ((mbedtls_ecp_point_internal const*)(&((grp)->src->G)))

#define getGrp(grp)       ((grp)->src)

/*
 * Temporaries
 */

/* Point */
#define ECP_DECL_TEMP_POINT_TMP(x) x ## _tmp
#define ECP_DECL_TEMP_POINT(x)                                          \
    mbedtls_ecp_point_internal ECP_DECL_TEMP_POINT_TMP(x);              \
    mbedtls_ecp_point_internal * const x = &ECP_DECL_TEMP_POINT_TMP(x); \
    mbedtls_ecp_point_init( (mbedtls_ecp_point*) x )
#define ECP_SETUP_TEMP_POINT(x)                                         \
    MBEDTLS_MPI_CHK( ecp_point_force_single( getGrp(grp),               \
                                  (mbedtls_ecp_point*) x ) )
#define ECP_FREE_TEMP_POINT(x)                                          \
    mbedtls_ecp_point_free( (mbedtls_ecp_point*) x )

/* Single width coordinate                                             */

#define ECP_DECL_TEMP_MPI_TMP(x) x ## _tmp
#define ECP_DECL_TEMP_MPI(x)                                            \
    mbedtls_ecp_mpi_internal ECP_DECL_TEMP_MPI_TMP(x);                  \
    mbedtls_ecp_mpi_internal * const x = &ECP_DECL_TEMP_MPI_TMP(x);     \
    mbedtls_mpi_init( (mbedtls_mpi*) x )
#define ECP_SETUP_TEMP_MPI(x)                                           \
    MBEDTLS_MPI_CHK( mpi_force_single( getGrp(grp),                     \
                                       (mbedtls_mpi*) x ) )
#define ECP_FREE_TEMP_MPI(x)                                            \
    mbedtls_mpi_free( (mbedtls_mpi*) x )

/* Static array of single width coordinates                            */

#define ECP_DECL_TEMP_MPI_STATIC_ARRAY(x,n)                             \
    mbedtls_ecp_mpi_internal (x)[(n)];                                  \
    mpi_init_many( (mbedtls_mpi*) x, (n) )
#define ECP_SETUP_TEMP_MPI_STATIC_ARRAY(x,n)                            \
    MBEDTLS_MPI_CHK( mpi_force_single_many( getGrp(grp),                \
                                            (mbedtls_mpi*) x, (n) ) )
#define ECP_FREE_TEMP_MPI_STATIC_ARRAY(x,n)                             \
    mpi_free_many( (mbedtls_mpi*) x, (n) )

/* Dynamic array of single width coordinates                           */

#define ECP_DECL_TEMP_MPI_DYNAMIC_ARRAY(x)                              \
    mbedtls_ecp_mpi_internal *x = NULL;
#define ECP_SETUP_TEMP_MPI_DYNAMIC_ARRAY(x,n)                           \
    do {                                                                \
        x = mbedtls_calloc( (n), sizeof( mbedtls_mpi ) );               \
        if( x == NULL )                                                 \
        {                                                               \
            ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;                         \
            goto cleanup;                                               \
        }                                                               \
        mpi_init_many( (mbedtls_mpi*) x, (n) );                         \
        MBEDTLS_MPI_CHK( mpi_force_single_many( getGrp(grp),            \
                                               (mbedtls_mpi*) x,        \
                                               (n) ) );                 \
    } while( 0 )
#define ECP_FREE_TEMP_MPI_DYNAMIC_ARRAY(x,n)                            \
    do {                                                                \
        mpi_free_many( (mbedtls_mpi*) x, (n) );                         \
        mbedtls_free( x );                                              \
    } while( 0 )

/*
 * Conversions
 */

/* Input point                                                         */

#define ECP_INTERNAL_INPUT_TMP(x) x ## _tmp
#define ECP_INTERNAL_INPUT(x)  (& ECP_INTERNAL_INPUT_TMP(x))
#define ECP_INTERNAL_INPUT_AS_ORIG(x) \
    ((mbedtls_ecp_point*) ECP_INTERNAL_INPUT(x))
#define ECP_DECL_INTERNAL_INPUT(x) \
    mbedtls_ecp_point_internal ECP_INTERNAL_INPUT_TMP(x);               \
    mbedtls_ecp_point_init( ECP_INTERNAL_INPUT_AS_ORIG(x) )
#define ECP_CONVERT_INPUT(x)                                            \
    MBEDTLS_MPI_CHK( ecp_setup_internal_input( grp,                     \
                  ECP_INTERNAL_INPUT_AS_ORIG(x), x ) )
#define ECP_FREE_INTERNAL_INPUT(x)                                      \
    mbedtls_ecp_point_free( ECP_INTERNAL_INPUT_AS_ORIG(x) )

/* Output point                                                        */

#define ECP_INTERNAL_OUTPUT(x) ((mbedtls_ecp_point_internal *) x)
#define ECP_CONVERT_OUTPUT(x)                                           \
    MBEDTLS_MPI_CHK( ecp_point_force_single( grp, x ) )
#define ECP_DECL_INTERNAL_OUTPUT(x) do {} while(0)
#define ECP_SAVE_INTERNAL_OUTPUT(x) do {} while(0)
#define ECP_FREE_INTERNAL_OUTPUT(x) do {} while(0)

/* In/Out point                                                         */

#define ECP_INTERNAL_INOUT(x) ((mbedtls_ecp_point_internal*) x)
#define ECP_DECL_INTERNAL_INOUT(x) do {} while(0)
#define ECP_CONVERT_INOUT(x)                                             \
    MBEDTLS_MPI_CHK( ecp_point_force_single( grp, x ) )
#define ECP_SAVE_INTERNAL_INOUT(x) do {} while( 0 )
#define ECP_FREE_INTERNAL_INOUT(x) do {} while( 0 )

/* Only needed for internal version of ecp_normalize_jac_many() */
#define ECP_INTERNAL_INOUT_MANY(x) ((mbedtls_ecp_point_internal**) x)
#define ECP_DECL_INTERNAL_INOUT_MANY(x,n) do {} while(0)
#define ECP_CONVERT_INOUT_MANY(x,n)                                     \
    do                                                                  \
    {                                                                   \
        for( unsigned i=0; i < (n); i++ )                               \
            MBEDTLS_MPI_CHK( ecp_point_force_single( grp, (x)[i] ) );   \
    } while( 0 )
#define ECP_SAVE_INTERNAL_INOUT_MANY(x,n) do {} while( 0 )
#define ECP_FREE_INTERNAL_INOUT_MANY(x,n) do {} while( 0 )

#define ECP_INTERNAL_INPUT_MPI_TMP(x) x ## _tmp
#define ECP_INTERNAL_INPUT_MPI(x)  (& ECP_INTERNAL_INPUT_MPI_TMP(x))
#define ECP_INTERNAL_INPUT_MPI_AS_ORIG(x) \
    ((mbedtls_mpi*) ECP_INTERNAL_INPUT_MPI(x))
#define ECP_DECL_INTERNAL_INPUT_MPI(x) \
    mbedtls_ecp_mpi_internal ECP_INTERNAL_INPUT_MPI_TMP(x);                 \
    mbedtls_mpi_init( ECP_INTERNAL_INPUT_MPI_AS_ORIG(x) )
#define ECP_CONVERT_INPUT_MPI(x)                                            \
    MBEDTLS_MPI_CHK( ecp_mpi_setup_internal_input( grp,                     \
                  ECP_INTERNAL_INPUT_MPI_AS_ORIG(x), x ) )
#define ECP_FREE_INTERNAL_INPUT_MPI(x)                                      \
    mbedtls_mpi_free( ECP_INTERNAL_INPUT_MPI_AS_ORIG(x) )

/* Group                                                                */

#define ECP_INTERNAL_GROUP_TMP(x) x ## _tmp
#define ECP_INTERNAL_GROUP(x) & ECP_INTERNAL_GROUP_TMP(x)
#define ECP_DECL_INTERNAL_GROUP(x)                                       \
    mbedtls_ecp_group_internal ECP_INTERNAL_GROUP_TMP(x);                \
    mbedtls_ecp_group_internal_init( ECP_INTERNAL_GROUP(x), x )
#define ECP_CONVERT_GROUP(x)                                             \
    MBEDTLS_MPI_CHK( mbedtls_ecp_group_internal_setup(                   \
                         ECP_INTERNAL_GROUP(x) ) )
#define ECP_SAVE_INTERNAL_GROUP(x) do {} while( 0 )
#define ECP_FREE_INTERNAL_GROUP(x)              \
    mbedtls_ecp_group_internal_free( ECP_INTERNAL_GROUP(x) )

/*
 * Macro wrappers around ECP modular arithmetic
 */

#define ECP_MPI_ADD( X, A, B )                                            \
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mod( grp, &((X)->v),                 \
                                          &((A)->v), &((B)->v) ) )
#define ECP_MPI_SUB( X, A, B )                                            \
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mod( grp, &((X)->v),                 \
                                          &((A)->v), &((B)->v) ) )
#define ECP_MPI_SUB_INT( X, A, c )                                        \
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int_mod( grp, &((X)->v),             \
                                              &((A)->v), c ) )
#define ECP_MPI_MUL( X, A, B )                                            \
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &((X)->v),                 \
                                          &((A)->v), &((B)->v) ) )
#define ECP_MPI_SQR( X, A )                                               \
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mod( grp, &((X)->v),                 \
                                          &((A)->v), &((A)->v) ) )
#define ECP_MPI_MUL_INT( X, A, c )                                        \
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_int_mod( grp, &((X)->v),             \
                                              &((A)->v), c ) )
#define ECP_MPI_INV( d, s )                                               \
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod_internal( grp, &(d)->v,          \
                                                   &(s)->v,               \
                                                   &getGrp(grp)->P ) )
#define ECP_MPI_MOV( X, A )                                               \
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &((X)->v), &((A)->v) ) )
#define ECP_MOV( d, s )                                                   \
    MBEDTLS_MPI_CHK( mbedtls_ecp_copy( (mbedtls_ecp_point*)(d),           \
                                       (mbedtls_ecp_point*) (s) ) )
#define ECP_ZERO( X )                                                     \
    do {                                                                  \
        ECP_MPI_LSET( getX(X), 0 );                                       \
        ECP_MPI_LSET( getY(X), 0 );                                       \
        ECP_MPI_LSET( getZ(X), 1 );                                       \
    } while( 0 )
#define ECP_MPI_SHIFT_L( X, count )                                       \
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l_mod( grp, &((X)->v), count ) )
#define ECP_MPI_LSET( X, c )                                              \
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &((X)->v), c ) )
#define ECP_MPI_CMP_INT( X, c )                                           \
    mbedtls_mpi_cmp_int( &((X)->v), c )
#define ECP_MPI_CMP( X, Y )                                               \
    mbedtls_mpi_cmp_mpi( &((X)->v), &((Y)->v) )
#define ECP_MPI_RAND( X )                                                 \
    MBEDTLS_MPI_CHK( mbedtls_mpi_random( &((X)->v), 2, &getGrp(grp)->P,   \
                                         f_rng, p_rng ) )
#define ECP_MPI_COND_NEG( X, cond )                                       \
    MBEDTLS_MPI_CHK( mbedtls_mpi_cond_neg_mod( grp, &(X)->v, (cond) ) )
#define ECP_MPI_NEG( X ) ECP_MPI_COND_NEG( &((X)->v), 1 )
#define ECP_MPI_VALID( X )  ( (X)->v.p != NULL )
#define ECP_MPI_COND_ASSIGN( X, Y, cond )                                 \
    MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign( &((X)->v),             \
                                                   &((Y)->v), (cond) ) )
#define ECP_MPI_COND_SWAP( X, Y, cond )                                   \
    MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_swap( &((X)->v),               \
                                                 &((Y)->v), (cond) ) )
#define ECP_MPI_REDUCE(x)                                                 \
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_after_add( grp, &(x)->v, &(x)->v ) )

/*
 * Initialization and freeing of instances of internal ECP/MPI types
 */

/* The ECP module frees some coordinates once they are no longer used, but
 * they are always setup as part of an ecp_point_internal_init/setup() call;
 * that's why we 'expose' the free call but no init call for internal MPIs. */

static void mbedtls_ecp_mpi_internal_free( mbedtls_ecp_mpi_internal *x )
{
    mbedtls_mpi_free( (mbedtls_mpi*)( x ) );
}
static void mbedtls_ecp_point_internal_init( mbedtls_ecp_point_internal *x )
{
    mbedtls_ecp_point_init( (mbedtls_ecp_point*)( x ) );
}
static void mbedtls_ecp_point_internal_free( mbedtls_ecp_point_internal *x )
{
    mbedtls_ecp_point_free( (mbedtls_ecp_point*)( x ) );
}

static int ecp_point_force_single( mbedtls_ecp_group const *grp,
                                   mbedtls_ecp_point *pt );
static int mbedtls_ecp_point_internal_setup( mbedtls_ecp_group_internal *grp,
                                             mbedtls_ecp_point_internal *x )
{
    return( ecp_point_force_single( getGrp(grp), (mbedtls_ecp_point*) x ) );
}

/* Only necessary for alt implementations */

#if defined(MBEDTLS_ECP_INTERNAL_ALT)
static int mbedtls_ecp_mpi_internal_to_orig( mbedtls_ecp_group const *grp,
                                             mbedtls_mpi *mpi_orig,
                                             mbedtls_ecp_mpi_internal const *mpi )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) grp);
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( mpi_orig, (mbedtls_mpi const*) mpi ) );
cleanup:
    return( ret );
}

static int mbedtls_ecp_mpi_internal_from_orig( mbedtls_ecp_group const *grp,
                                               mbedtls_ecp_mpi_internal *mpi,
                                               mbedtls_mpi const *mpi_orig )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) grp);

    /* Some coordinates are unused and have their buffer set to NULL. */
    if( mpi->v.p == NULL )
    {
        if( mpi_orig->p != NULL )
            return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
        return( 0 );
    }

    size_t to_copy = mpi_orig->n;
    if( to_copy > mpi->v.n )
        to_copy = mpi->v.n;
    memcpy( mpi->v.p, mpi_orig->p,
            to_copy * sizeof( mbedtls_mpi_uint ) );
    memset( mpi->v.p + to_copy, 0,
            ( mpi->v.n - to_copy ) * sizeof( mbedtls_mpi_uint ) );
    return( 0 );
}

static int mbedtls_ecp_point_internal_to_orig( mbedtls_ecp_group const *grp,
                                             mbedtls_ecp_point *pt_orig,
                                             mbedtls_ecp_point_internal const *pt )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_to_orig( grp,
                         &pt_orig->X, getX(pt) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_to_orig( grp,
                         &pt_orig->Y, getY(pt) ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_to_orig( grp,
                         &pt_orig->Z, getZ(pt) ) );
cleanup:
    return( ret );
}

static int mbedtls_ecp_point_internal_from_orig( mbedtls_ecp_group const *grp,
                                                 mbedtls_ecp_point_internal *pt,
                                                 mbedtls_ecp_point const *pt_orig )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_from_orig(
                         grp, getX(pt), &pt_orig->X ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_from_orig(
                         grp, getY(pt), &pt_orig->Y ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_mpi_internal_from_orig(
                         grp, getZ(pt), &pt_orig->Z ) );

cleanup:
    return( ret );
}
#endif /* MBEDTLS_ECP_INTERNAL_ALT */

/*
 *
 * Implementation details
 *
 */

/*
 * Init / Setup / Free functions
 */

/* Coordinates */

static int mpi_force_size( mbedtls_mpi *X, size_t limbs )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( X, limbs ) );
    if( X->n != limbs )
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
cleanup:
    return( ret );
}

static int mpi_force_single( const mbedtls_ecp_group *grp,
                             mbedtls_mpi *X )
{
    return( mpi_force_size( X, grp->P.n ) );
}

static int mpi_force_double( const mbedtls_ecp_group *grp,
                             mbedtls_mpi *X )
{
    return( mpi_force_size( X, 2 * grp->P.n + 1 ) );
}

static void mpi_init_many( mbedtls_mpi *arr, size_t size )
{
    while( size-- )
        mbedtls_mpi_init( arr++ );
}

static void mpi_free_many( mbedtls_mpi *arr, size_t size )
{
    while( size-- )
        mbedtls_mpi_free( arr++ );
}

static int mpi_force_single_many( mbedtls_ecp_group const *grp,
                                  mbedtls_mpi *X,
                                  size_t size )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    while( size-- )
        MBEDTLS_MPI_CHK( mpi_force_single( grp, X++ ) );
cleanup:
    return( ret );
}

/* Point */

static int ecp_point_force_single( mbedtls_ecp_group const *grp,
                                   mbedtls_ecp_point *pt )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mpi_force_single( grp, &pt->X ) );
    MBEDTLS_MPI_CHK( mpi_force_single( grp, &pt->Y ) );
    MBEDTLS_MPI_CHK( mpi_force_single( grp, &pt->Z ) );
cleanup:
    return( ret );
}

static int ecp_setup_internal_input(
    mbedtls_ecp_group const *grp,
    mbedtls_ecp_point *new,
    mbedtls_ecp_point const *old )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_ecp_copy( new, old ) );
    MBEDTLS_MPI_CHK( ecp_point_force_single( grp, new ) );
cleanup:
    return( ret );
}

/* Coordinate MPI */

#if defined(MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT)
static int ecp_mpi_setup_internal_input(
    mbedtls_ecp_group const *grp,
    mbedtls_mpi *new,
    mbedtls_mpi const *old )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( new, old ) );
    MBEDTLS_MPI_CHK( mpi_force_single( grp, new ) );
cleanup:
    return( ret );
}
#endif /* MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT */

/* Groups */

#define getTmpDouble(grp) (mbedtls_mpi*)&(grp->tmp_single)
#define getTmpSingle(grp) (mbedtls_mpi*)&(grp->tmp_double)

static void mbedtls_ecp_group_internal_init(
    mbedtls_ecp_group_internal *grp, mbedtls_ecp_group *src )
{
    grp->src = src;
    mbedtls_mpi_init( getTmpSingle( grp ) );
    mbedtls_mpi_init( getTmpDouble( grp ) );
}

static void mbedtls_ecp_group_internal_free(
    mbedtls_ecp_group_internal *grp )
{
    mbedtls_mpi_free( getTmpSingle( grp ) );
    mbedtls_mpi_free( getTmpDouble( grp ) );
}

static int mbedtls_ecp_group_internal_setup(
    mbedtls_ecp_group_internal *grp )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mpi_force_single( getGrp(grp), getTmpSingle( grp ) ) );
    MBEDTLS_MPI_CHK( mpi_force_double( getGrp(grp), getTmpDouble( grp ) ) );
cleanup:
    return( ret );
}

/*
 * Modular arithmetic wrappers
 */

/*
 * Wrapper around fast quasi-modp functions, with fall-back to mbedtls_mpi_mod_mpi.
 * See the documentation of struct mbedtls_ecp_group.
 *
 * This function is in the critial loop for mbedtls_ecp_mul, so pay attention to perf.
 */
static int ecp_modp( mbedtls_mpi *dst, mbedtls_mpi *N, const mbedtls_ecp_group *grp )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( grp->modp == NULL )
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( N, N, &grp->P ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_copy( dst, N ) );
        return( 0 );
    }

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    if( ( N->s < 0 && mbedtls_mpi_cmp_int( N, 0 ) != 0 ) ||
        mbedtls_mpi_bitlen( N ) > 2 * grp->pbits )
    {
        return( MBEDTLS_ERR_ECP_BAD_INPUT_DATA );
    }

    MBEDTLS_MPI_CHK( grp->modp( N ) );

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    while( N->s < 0 && mbedtls_mpi_cmp_int( N, 0 ) != 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( N, N, &grp->P ) );

    while( mbedtls_mpi_cmp_mpi( N, &grp->P ) >= 0 )
        /* we known P, N and the result are positive */
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( N, N, &grp->P ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( dst, N ) );

cleanup:
    return( ret );
}

/*
 * Fast mod-p functions expect their argument to be in the 0..p^2 range.
 *
 * In order to guarantee that, we need to ensure that operands of
 * mbedtls_mpi_mul_mpi are in the 0..p range. So, after each operation we will
 * bring the result back to this range.
 *
 * The following macros are shortcuts for doing that.
 */

/*
 * Reduce a mbedtls_mpi mod p in-place, general case, to use after mbedtls_mpi_mul_mpi
 */
#if defined(MBEDTLS_SELF_TEST)
#define INC_MUL_COUNT   mul_count++;
#else
#define INC_MUL_COUNT
#endif

static int mbedtls_mpi_mul_mod( const mbedtls_ecp_group_internal *grp,
                                mbedtls_mpi *X,
                                const mbedtls_mpi *A,
                                const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi * const tmp = (mbedtls_mpi*) getTmpDouble(grp);
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( tmp, A, B ) );
    MBEDTLS_MPI_CHK( ecp_modp( X, tmp, getGrp(grp) ) );

    INC_MUL_COUNT

cleanup:
    return( ret );
}

static int mbedtls_mpi_mod_after_sub( const mbedtls_ecp_group_internal *grp,
                                      mbedtls_mpi *dst, mbedtls_mpi *src )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    while( src->s < 0 && mbedtls_mpi_cmp_int( src, 0 ) != 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( src, src, &getGrp(grp)->P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( dst, src ) );
cleanup:
    return( ret );
}

#if defined(ECP_MPI_NEED_SUB_MOD)
/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_sub_mpi
 * N->s < 0 is a very fast test, which fails only if N is 0
 */
static int mbedtls_mpi_sub_mod( const mbedtls_ecp_group_internal *grp,
                                mbedtls_mpi *X,
                                const mbedtls_mpi *A,
                                const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi * const tmp = (mbedtls_mpi*) getTmpDouble(grp);
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( tmp, A, B ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_after_sub( grp, X, tmp ) );
cleanup:
    return( ret );
}
#endif /* ECP_MPI_NEED_SUB_MOD */

/*
 * Reduce a mbedtls_mpi mod p in-place, to use after mbedtls_mpi_add_mpi and mbedtls_mpi_mul_int.
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */

static int mbedtls_mpi_mod_after_add( const mbedtls_ecp_group_internal *grp,
                                      mbedtls_mpi *dst, mbedtls_mpi *src )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    while( mbedtls_mpi_cmp_mpi( src, &getGrp(grp)->P ) >= 0 )
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_abs( src, src, &getGrp(grp)->P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( dst, src ) );

cleanup:
    return( ret );
}

static int mbedtls_mpi_add_mod( const mbedtls_ecp_group_internal *grp,
                                mbedtls_mpi *X,
                                const mbedtls_mpi *A,
                                const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi * const tmp = (mbedtls_mpi*) getTmpDouble(grp);
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( tmp, A, B ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_after_add( grp, X, tmp ) );
cleanup:
    return( ret );
}

static int mbedtls_mpi_mul_int_mod( const mbedtls_ecp_group_internal *grp,
                                    mbedtls_mpi *X,
                                    const mbedtls_mpi *A,
                                    mbedtls_mpi_uint c )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi * const tmp = (mbedtls_mpi*) getTmpDouble(grp);
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_int( tmp, A, c ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_after_add( grp, X, tmp ) );
cleanup:
    return( ret );
}

static int mbedtls_mpi_sub_int_mod( const mbedtls_ecp_group_internal *grp,
                                    mbedtls_mpi *X,
                                    const mbedtls_mpi *A,
                                    mbedtls_mpi_uint c )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi * const tmp = (mbedtls_mpi*) getTmpDouble(grp);
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( tmp, A, c ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_after_sub( grp, X, tmp ) );
cleanup:
    return( ret );
}

#if defined(ECP_MPI_NEED_SHIFT_L_MOD)
static int mbedtls_mpi_shift_l_mod( const mbedtls_ecp_group_internal *grp,
                                    mbedtls_mpi *X,
                                    size_t count )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi * const tmp = (mbedtls_mpi*) getTmpDouble(grp);
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( tmp, X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( tmp, count ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_after_add( grp, X, tmp ) );
cleanup:
    return( ret );
}
#endif /* ECP_MPI_NEED_SHIFT_L_MOD */

static int mbedtls_mpi_inv_mod_internal( const mbedtls_ecp_group_internal *grp,
                                         mbedtls_mpi *dst,
                                         mbedtls_mpi const *src,
                                         mbedtls_mpi const *P )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi * const tmp = getTmpDouble(grp);

    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( tmp, src, P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( dst, tmp ) );

cleanup:
    return( ret );
}

static int mbedtls_mpi_cond_neg_mod( const mbedtls_ecp_group_internal *grp,
                                     mbedtls_mpi *X,
                                     unsigned cond )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi * const tmp = getTmpSingle(grp);

    unsigned char nonzero =
        mbedtls_mpi_cmp_int( X, 0 ) != 0;

    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi(
                         tmp, &getGrp(grp)->P, X ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_safe_cond_assign(
                         X, tmp, nonzero & (cond) ) );

cleanup:
    return( ret );
}

#endif /* MBEDTLS_ECP_ARITH_WRAPPER_FIXSIZE_HEAP_H */
