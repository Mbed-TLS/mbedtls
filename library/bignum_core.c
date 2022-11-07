/*
 *  Core bignum functions
 *
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

#include "common.h"

#if defined(MBEDTLS_BIGNUM_C)

#include <string.h>

#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"
#include "constant_time_internal.h"

#include "mbedtls/platform.h"

#include "bignum_core.h"
#include "bn_mul.h"
#include "constant_time_internal.h"

size_t mbedtls_mpi_core_clz( mbedtls_mpi_uint a )
{
    size_t j;
    mbedtls_mpi_uint mask = (mbedtls_mpi_uint) 1 << (biL - 1);

    for( j = 0; j < biL; j++ )
    {
        if( a & mask ) break;

        mask >>= 1;
    }

    return( j );
}

size_t mbedtls_mpi_core_bitlen( const mbedtls_mpi_uint *A, size_t A_limbs )
{
    size_t i, j;

    if( A_limbs == 0 )
        return( 0 );

    for( i = A_limbs - 1; i > 0; i-- )
        if( A[i] != 0 )
            break;

    j = biL - mbedtls_mpi_core_clz( A[i] );

    return( ( i * biL ) + j );
}

/* Convert a big-endian byte array aligned to the size of mbedtls_mpi_uint
 * into the storage form used by mbedtls_mpi. */
static mbedtls_mpi_uint mpi_bigendian_to_host_c( mbedtls_mpi_uint a )
{
    uint8_t i;
    unsigned char *a_ptr;
    mbedtls_mpi_uint tmp = 0;

    for( i = 0, a_ptr = (unsigned char *) &a; i < ciL; i++, a_ptr++ )
    {
        tmp <<= CHAR_BIT;
        tmp |= (mbedtls_mpi_uint) *a_ptr;
    }

    return( tmp );
}

static mbedtls_mpi_uint mpi_bigendian_to_host( mbedtls_mpi_uint a )
{
#if defined(__BYTE_ORDER__)

/* Nothing to do on bigendian systems. */
#if ( __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ )
    return( a );
#endif /* __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ */

#if ( __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ )

/* For GCC and Clang, have builtins for byte swapping. */
#if defined(__GNUC__) && defined(__GNUC_PREREQ)
#if __GNUC_PREREQ(4,3)
#define have_bswap
#endif
#endif

#if defined(__clang__) && defined(__has_builtin)
#if __has_builtin(__builtin_bswap32)  &&                 \
    __has_builtin(__builtin_bswap64)
#define have_bswap
#endif
#endif

#if defined(have_bswap)
    /* The compiler is hopefully able to statically evaluate this! */
    switch( sizeof(mbedtls_mpi_uint) )
    {
        case 4:
            return( __builtin_bswap32(a) );
        case 8:
            return( __builtin_bswap64(a) );
    }
#endif
#endif /* __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ */
#endif /* __BYTE_ORDER__ */

    /* Fall back to C-based reordering if we don't know the byte order
     * or we couldn't use a compiler-specific builtin. */
    return( mpi_bigendian_to_host_c( a ) );
}

void mbedtls_mpi_core_bigendian_to_host( mbedtls_mpi_uint *A,
                                         size_t A_limbs )
{
    mbedtls_mpi_uint *cur_limb_left;
    mbedtls_mpi_uint *cur_limb_right;
    if( A_limbs == 0 )
        return;

    /*
     * Traverse limbs and
     * - adapt byte-order in each limb
     * - swap the limbs themselves.
     * For that, simultaneously traverse the limbs from left to right
     * and from right to left, as long as the left index is not bigger
     * than the right index (it's not a problem if limbs is odd and the
     * indices coincide in the last iteration).
     */
    for( cur_limb_left = A, cur_limb_right = A + ( A_limbs - 1 );
         cur_limb_left <= cur_limb_right;
         cur_limb_left++, cur_limb_right-- )
    {
        mbedtls_mpi_uint tmp;
        /* Note that if cur_limb_left == cur_limb_right,
         * this code effectively swaps the bytes only once. */
        tmp             = mpi_bigendian_to_host( *cur_limb_left );
        *cur_limb_left  = mpi_bigendian_to_host( *cur_limb_right );
        *cur_limb_right = tmp;
    }
}

void mbedtls_mpi_core_cond_assign( mbedtls_mpi_uint *X,
                                   const mbedtls_mpi_uint *A,
                                   size_t limbs,
                                   unsigned char assign )
{
    if( X == A )
        return;

    mbedtls_ct_mpi_uint_cond_assign( limbs, X, A, assign );
}

void mbedtls_mpi_core_cond_swap( mbedtls_mpi_uint *X,
                                 mbedtls_mpi_uint *Y,
                                 size_t limbs,
                                 unsigned char swap )
{
    if( X == Y )
        return;

    /* all-bits 1 if swap is 1, all-bits 0 if swap is 0 */
    mbedtls_mpi_uint limb_mask = mbedtls_ct_mpi_uint_mask( swap );

    for( size_t i = 0; i < limbs; i++ )
    {
        mbedtls_mpi_uint tmp = X[i];
        X[i] = ( X[i] & ~limb_mask ) | ( Y[i] & limb_mask );
        Y[i] = ( Y[i] & ~limb_mask ) | (  tmp & limb_mask );
    }
}

int mbedtls_mpi_core_read_le( mbedtls_mpi_uint *X,
                              size_t X_limbs,
                              const unsigned char *input,
                              size_t input_length )
{
    const size_t limbs = CHARS_TO_LIMBS( input_length );

    if( X_limbs < limbs )
        return( MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL );

    if( X != NULL )
    {
        memset( X, 0, X_limbs * ciL );

        for( size_t i = 0; i < input_length; i++ )
        {
            size_t offset = ( ( i % ciL ) << 3 );
            X[i / ciL] |= ( (mbedtls_mpi_uint) input[i] ) << offset;
        }
    }

    return( 0 );
}

int mbedtls_mpi_core_read_be( mbedtls_mpi_uint *X,
                              size_t X_limbs,
                              const unsigned char *input,
                              size_t input_length )
{
    const size_t limbs = CHARS_TO_LIMBS( input_length );

    if( X_limbs < limbs )
        return( MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL );

    /* If X_limbs is 0, input_length must also be 0 (from previous test).
     * Nothing to do. */
    if( X_limbs == 0 )
        return( 0 );

    memset( X, 0, X_limbs * ciL );

    /* memcpy() with (NULL, 0) is undefined behaviour */
    if( input_length != 0 )
    {
        size_t overhead = ( X_limbs * ciL ) - input_length;
        unsigned char *Xp = (unsigned char *) X;
        memcpy( Xp + overhead, input, input_length );
    }

    mbedtls_mpi_core_bigendian_to_host( X, X_limbs );

    return( 0 );
}

int mbedtls_mpi_core_write_le( const mbedtls_mpi_uint *A,
                               size_t A_limbs,
                               unsigned char *output,
                               size_t output_length )
{
    size_t stored_bytes = A_limbs * ciL;
    size_t bytes_to_copy;

    if( stored_bytes < output_length )
    {
        bytes_to_copy = stored_bytes;
    }
    else
    {
        bytes_to_copy = output_length;

        /* The output buffer is smaller than the allocated size of A.
         * However A may fit if its leading bytes are zero. */
        for( size_t i = bytes_to_copy; i < stored_bytes; i++ )
        {
            if( GET_BYTE( A, i ) != 0 )
                return( MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL );
        }
    }

    for( size_t i = 0; i < bytes_to_copy; i++ )
        output[i] = GET_BYTE( A, i );

    if( stored_bytes < output_length )
    {
        /* Write trailing 0 bytes */
        memset( output + stored_bytes, 0, output_length - stored_bytes );
    }

    return( 0 );
}

int mbedtls_mpi_core_write_be( const mbedtls_mpi_uint *X,
                               size_t X_limbs,
                               unsigned char *output,
                               size_t output_length )
{
    size_t stored_bytes;
    size_t bytes_to_copy;
    unsigned char *p;

    stored_bytes = X_limbs * ciL;

    if( stored_bytes < output_length )
    {
        /* There is enough space in the output buffer. Write initial
         * null bytes and record the position at which to start
         * writing the significant bytes. In this case, the execution
         * trace of this function does not depend on the value of the
         * number. */
        bytes_to_copy = stored_bytes;
        p = output + output_length - stored_bytes;
        memset( output, 0, output_length - stored_bytes );
    }
    else
    {
        /* The output buffer is smaller than the allocated size of X.
         * However X may fit if its leading bytes are zero. */
        bytes_to_copy = output_length;
        p = output;
        for( size_t i = bytes_to_copy; i < stored_bytes; i++ )
        {
            if( GET_BYTE( X, i ) != 0 )
                return( MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL );
        }
    }

    for( size_t i = 0; i < bytes_to_copy; i++ )
        p[bytes_to_copy - i - 1] = GET_BYTE( X, i );

    return( 0 );
}

void mbedtls_mpi_core_shift_r( mbedtls_mpi_uint *X, size_t limbs,
                               size_t count )
{
    size_t i, v0, v1;
    mbedtls_mpi_uint r0 = 0, r1;

    v0 = count /  biL;
    v1 = count & (biL - 1);

    if( v0 > limbs || ( v0 == limbs && v1 > 0 ) )
    {
        memset( X, 0, limbs * ciL );
        return;
    }

    /*
     * shift by count / limb_size
     */
    if( v0 > 0 )
    {
        for( i = 0; i < limbs - v0; i++ )
            X[i] = X[i + v0];

        for( ; i < limbs; i++ )
            X[i] = 0;
    }

    /*
     * shift by count % limb_size
     */
    if( v1 > 0 )
    {
        for( i = limbs; i > 0; i-- )
        {
            r1 = X[i - 1] << (biL - v1);
            X[i - 1] >>= v1;
            X[i - 1] |= r0;
            r0 = r1;
        }
    }
}

mbedtls_mpi_uint mbedtls_mpi_core_add( mbedtls_mpi_uint *X,
                                       const mbedtls_mpi_uint *A,
                                       const mbedtls_mpi_uint *B,
                                       size_t limbs )
{
    mbedtls_mpi_uint c = 0;

    for( size_t i = 0; i < limbs; i++ )
    {
        mbedtls_mpi_uint t = c + A[i];
        c = ( t < A[i] );
        t += B[i];
        c += ( t < B[i] );
        X[i] = t;
    }

    return( c );
}

mbedtls_mpi_uint mbedtls_mpi_core_add_if( mbedtls_mpi_uint *X,
                                          const mbedtls_mpi_uint *A,
                                          size_t limbs,
                                          unsigned cond )
{
    mbedtls_mpi_uint c = 0;

    /* all-bits 0 if cond is 0, all-bits 1 if cond is non-0 */
    const mbedtls_mpi_uint mask = mbedtls_ct_mpi_uint_mask( cond );

    for( size_t i = 0; i < limbs; i++ )
    {
        mbedtls_mpi_uint add = mask & A[i];
        mbedtls_mpi_uint t = c + X[i];
        c = ( t < X[i] );
        t += add;
        c += ( t < add );
        X[i] = t;
    }

    return( c );
}

mbedtls_mpi_uint mbedtls_mpi_core_sub( mbedtls_mpi_uint *X,
                                       const mbedtls_mpi_uint *A,
                                       const mbedtls_mpi_uint *B,
                                       size_t limbs )
{
    mbedtls_mpi_uint c = 0;

    for( size_t i = 0; i < limbs; i++ )
    {
        mbedtls_mpi_uint z = ( A[i] < c );
        mbedtls_mpi_uint t = A[i] - c;
        c = ( t < B[i] ) + z;
        X[i] = t - B[i];
    }

    return( c );
}

mbedtls_mpi_uint mbedtls_mpi_core_mla( mbedtls_mpi_uint *d, size_t d_len,
                                       const mbedtls_mpi_uint *s, size_t s_len,
                                       mbedtls_mpi_uint b )
{
    mbedtls_mpi_uint c = 0; /* carry */
    /*
     * It is a documented precondition of this function that d_len >= s_len.
     * If that's not the case, we swap these round: this turns what would be
     * a buffer overflow into an incorrect result.
     */
    if( d_len < s_len )
        s_len = d_len;
    size_t excess_len = d_len - s_len;
    size_t steps_x8 = s_len / 8;
    size_t steps_x1 = s_len & 7;

    while( steps_x8-- )
    {
        MULADDC_X8_INIT
        MULADDC_X8_CORE
        MULADDC_X8_STOP
    }

    while( steps_x1-- )
    {
        MULADDC_X1_INIT
        MULADDC_X1_CORE
        MULADDC_X1_STOP
    }

    while( excess_len-- )
    {
        *d += c;
        c = ( *d < c );
        d++;
    }

    return( c );
}

/*
 * Fast Montgomery initialization (thanks to Tom St Denis).
 */
mbedtls_mpi_uint mbedtls_mpi_core_montmul_init( const mbedtls_mpi_uint *N )
{
    mbedtls_mpi_uint x = N[0];

    x += ( ( N[0] + 2 ) & 4 ) << 1;

    for( unsigned int i = biL; i >= 8; i /= 2 )
        x *= ( 2 - ( N[0] * x ) );

    return( ~x + 1 );
}

void mbedtls_mpi_core_montmul( mbedtls_mpi_uint *X,
                               const mbedtls_mpi_uint *A,
                               const mbedtls_mpi_uint *B,
                               size_t B_limbs,
                               const mbedtls_mpi_uint *N,
                               size_t AN_limbs,
                               mbedtls_mpi_uint mm,
                               mbedtls_mpi_uint *T )
{
    memset( T, 0, ( 2 * AN_limbs + 1 ) * ciL );

    for( size_t i = 0; i < AN_limbs; i++ )
    {
        /* T = (T + u0*B + u1*N) / 2^biL */
        mbedtls_mpi_uint u0 = A[i];
        mbedtls_mpi_uint u1 = ( T[0] + u0 * B[0] ) * mm;

        (void) mbedtls_mpi_core_mla( T, AN_limbs + 2, B, B_limbs, u0 );
        (void) mbedtls_mpi_core_mla( T, AN_limbs + 2, N, AN_limbs, u1 );

        T++;
    }

    /*
     * The result we want is (T >= N) ? T - N : T.
     *
     * For better constant-time properties in this function, we always do the
     * subtraction, with the result in X.
     *
     * We also look to see if there was any carry in the final additions in the
     * loop above.
     */

    mbedtls_mpi_uint carry  = T[AN_limbs];
    mbedtls_mpi_uint borrow = mbedtls_mpi_core_sub( X, T, N, AN_limbs );

    /*
     * Using R as the Montgomery radix (auxiliary modulus) i.e. 2^(biL*AN_limbs):
     *
     * T can be in one of 3 ranges:
     *
     * 1) T < N      : (carry, borrow) = (0, 1): we want T
     * 2) N <= T < R : (carry, borrow) = (0, 0): we want X
     * 3) T >= R     : (carry, borrow) = (1, 1): we want X
     *
     * and (carry, borrow) = (1, 0) can't happen.
     *
     * So the correct return value is already in X if (carry ^ borrow) = 0,
     * but is in (the lower AN_limbs limbs of) T if (carry ^ borrow) = 1.
     */
    mbedtls_ct_mpi_uint_cond_assign( AN_limbs, X, T, (unsigned char) ( carry ^ borrow ) );
}

int mbedtls_mpi_core_get_mont_r2_unsafe( mbedtls_mpi *X,
                                         const mbedtls_mpi *N )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( X, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shift_l( X, N->n * 2 * biL ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( X, X, N ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_shrink( X, N->n ) );

cleanup:
    return( ret );
}

void mbedtls_mpi_core_ct_uint_table_lookup( mbedtls_mpi_uint *dest,
                                            const mbedtls_mpi_uint *table,
                                            size_t limbs,
                                            size_t count,
                                            size_t index )
{
    for( size_t i = 0; i < count; i++, table += limbs )
    {
        unsigned char assign = mbedtls_ct_size_bool_eq( i, index );
        mbedtls_mpi_core_cond_assign( dest, table, limbs, assign );
    }
}

/* Fill X with n_bytes random bytes.
 * X must already have room for those bytes.
 * The ordering of the bytes returned from the RNG is suitable for
 * deterministic ECDSA (see RFC 6979 §3.3 and the specification of
 * mbedtls_mpi_core_random()).
 */
int mbedtls_mpi_core_fill_random(
    mbedtls_mpi_uint *X, size_t X_limbs,
    size_t n_bytes,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const size_t limbs = CHARS_TO_LIMBS( n_bytes );
    const size_t overhead = ( limbs * ciL ) - n_bytes;

    if( X_limbs < limbs )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    memset( X, 0, overhead );
    memset( (unsigned char *) X + limbs * ciL, 0, ( X_limbs - limbs ) * ciL );
    MBEDTLS_MPI_CHK( f_rng( p_rng, (unsigned char *) X + overhead, n_bytes ) );
    mbedtls_mpi_core_bigendian_to_host( X, limbs );

cleanup:
    return( ret );
}

/* BEGIN MERGE SLOT 1 */

/* END MERGE SLOT 1 */

/* BEGIN MERGE SLOT 2 */

/* END MERGE SLOT 2 */

/* BEGIN MERGE SLOT 3 */

/* END MERGE SLOT 3 */

/* BEGIN MERGE SLOT 4 */

/* END MERGE SLOT 4 */

/* BEGIN MERGE SLOT 5 */

/* END MERGE SLOT 5 */

/* BEGIN MERGE SLOT 6 */

/* END MERGE SLOT 6 */

/* BEGIN MERGE SLOT 7 */

/* END MERGE SLOT 7 */

/* BEGIN MERGE SLOT 8 */

/* END MERGE SLOT 8 */

/* BEGIN MERGE SLOT 9 */

/* END MERGE SLOT 9 */

/* BEGIN MERGE SLOT 10 */

/* END MERGE SLOT 10 */

#endif /* MBEDTLS_BIGNUM_C */
