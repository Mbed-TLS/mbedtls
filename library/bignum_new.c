/*
 *  Multi-precision integer library
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

#include "mbedtls/bignum.h"
#include "bignum_core.h"
#include "bn_mul.h"
#include "constant_time_internal.h"

#include <string.h>

void mbedtls_mpi_core_montmul( mbedtls_mpi_uint *X,
                               const mbedtls_mpi_uint *A,
                               const mbedtls_mpi_uint *B,
                               size_t B_len,
                               const mbedtls_mpi_uint *N,
                               size_t n,
                               mbedtls_mpi_uint mm,
                               mbedtls_mpi_uint *T )
{
    memset( T, 0, ( 2 * n + 1 ) * ciL );

    for( size_t i = 0; i < n; i++, T++ )
    {
        mbedtls_mpi_uint u0, u1;
        /* T = (T + u0*B + u1*N) / 2^biL */
        u0 = A[i];
        u1 = ( T[0] + u0 * B[0] ) * mm;

        (void) mbedtls_mpi_core_mla( T, n + 2, B, B_len, u0 );
        (void) mbedtls_mpi_core_mla( T, n + 2, N, n, u1 );
    }

    /* It's possible that the result in T is > N, and so we might need to subtract N */

    mbedtls_mpi_uint carry  = T[n];
    mbedtls_mpi_uint borrow = mbedtls_mpi_core_sub( X, T, N, n );

    /*
     * Both carry and borrow can only be 0 or 1.
     *
     * If carry = 1, the result in T must be > N by definition, and the subtraction
     * using only n limbs will create borrow, but that will have the correct
     * final result.
     *
     * i.e. (carry, borrow) of (1, 1) => return X
     *
     * If carry = 0, then we want to use the result of the subtraction iff
     * borrow = 0.
     *
     * i.e. (carry, borrow) of (0, 0) => return X
     *                         (0, 1) => return T
     *
     * We've confirmed that the unit tests exercise this function with all 3 of
     * the valid (carry, borrow) combinations (listed above), and that we don't
     * see (carry, borrow) = (1, 0).
     *
     * So the correct return value is already in X if (carry ^ borrow) = 0,
     * but is in (the lower n limbs of) T if (carry ^ borrow) = 1.
     */
     mbedtls_ct_mpi_uint_cond_assign( n, X, T, (unsigned char) ( carry ^ borrow ) );
}

/*
 * Fast Montgomery initialization (thanks to Tom St Denis).
 */
mbedtls_mpi_uint mbedtls_mpi_montg_init( mbedtls_mpi_uint m0 )
{
    mbedtls_mpi_uint x = m0;

    x += ( ( m0 + 2 ) & 4 ) << 1;

    for( unsigned int i = biL; i >= 8; i /= 2 )
        x *= ( 2 - ( m0 * x ) );

    return( ~x + 1 );
}

mbedtls_mpi_uint mbedtls_mpi_core_mla( mbedtls_mpi_uint *d, size_t d_len,
                                       const mbedtls_mpi_uint *s, size_t s_len,
                                       mbedtls_mpi_uint b )
{
    mbedtls_mpi_uint c = 0; /* carry */
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
        *d += c; c = ( *d < c ); d++;
    }

    return( c );
}

mbedtls_mpi_uint mbedtls_mpi_core_sub( mbedtls_mpi_uint *d,
                                       const mbedtls_mpi_uint *l,
                                       const mbedtls_mpi_uint *r,
                                       size_t n )
{
    mbedtls_mpi_uint c = 0;

    for( size_t i = 0; i < n; i++ )
    {
        mbedtls_mpi_uint z = ( l[i] < c );
        mbedtls_mpi_uint t = l[i] - c;
        c = ( t < r[i] ) + z;
        d[i] = t - r[i];
    }

    return( c );
}

mbedtls_mpi_uint mbedtls_mpi_core_add_if( mbedtls_mpi_uint *d,
                                          const mbedtls_mpi_uint *r,
                                          size_t n,
                                          unsigned cond )
{
    mbedtls_mpi_uint c = 0, t;
    for( size_t i = 0; i < n; i++ )
    {
        mbedtls_mpi_uint add = cond * r[i];
        t  = c;
        t += d[i]; c  = ( t < d[i] );
        t += add;  c += ( t < add  );
        d[i] = t;
    }
    return( c );
}

#endif /* MBEDTLS_BIGNUM_C */
