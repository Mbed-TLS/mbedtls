/*
 *  Multi-precision integer library, core arithmetic
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
#include "bignum_internal.h"
#include "bignum_core.h"
#include "bn_mul.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "constant_time_internal.h"

#include <limits.h>
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf     printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#define ciL    (sizeof(mbedtls_mpi_uint))         /* chars in limb  */
#define biL    (ciL << 3)               /* bits  in limb  */
#define biH    (ciL << 2)               /* half limb size */

void mbedtls_mpi_core_read_binary( mbedtls_mpi_uint *X, size_t n,
                                   const unsigned char *buf, size_t buflen )
{
    size_t const overhead = ( n * ciL ) - buflen;
    unsigned char *Xp = (unsigned char*) X;
    memset( Xp, 0, overhead );
    if( buflen == 0 )
        return;
    memcpy( Xp + overhead, buf, buflen );
    mbedtls_mpi_core_bigendian_to_host( X, n );
}

void mbedtls_mpi_core_write_binary( const mbedtls_mpi_uint *X,
                                    unsigned char *buf, size_t buflen )
{
    for( size_t i = 0; i < buflen; i++ )
        buf[buflen - i - 1] = GET_BYTE( X, i );
}

mbedtls_mpi_uint mbedtls_mpi_core_sub( mbedtls_mpi_uint *d,
                                       const mbedtls_mpi_uint *l,
                                       const mbedtls_mpi_uint *r,
                                       size_t n )
{
    size_t i;
    mbedtls_mpi_uint c = 0, t, z;

    for( i = 0; i < n; i++ )
    {
        z = ( l[i] <  c );    t = l[i] - c;
        c = ( t < r[i] ) + z; d[i] = t - r[i];
    }

    return( c );
}

mbedtls_mpi_uint mbedtls_mpi_core_add( mbedtls_mpi_uint *d,
                                       const mbedtls_mpi_uint *l,
                                       const mbedtls_mpi_uint *r,
                                       size_t n )
{
    mbedtls_mpi_uint c = 0, t;
    for( size_t i = 0; i < n; i++ )
    {
        t  = c;
        t += l[i]; c  = ( t < l[i] );
        t += r[i]; c += ( t < r[i] );
        d[i] = t;
    }
    return( c );
}

mbedtls_mpi_uint mbedtls_mpi_core_sub_int( mbedtls_mpi_uint *d,
                                           const mbedtls_mpi_uint *l,
                                           mbedtls_mpi_uint c, size_t n )
{
    for( size_t i = 0; i < n; i++ )
    {
        mbedtls_mpi_uint s, t;
        s = l[i];
        t = s - c; c = ( t > s );
        d[i] = t;
    }

    return( c );
}

mbedtls_mpi_uint mbedtls_mpi_core_add_int( mbedtls_mpi_uint *d,
                                           const mbedtls_mpi_uint *l,
                                           mbedtls_mpi_uint c, size_t n )
{
    mbedtls_mpi_uint t;
    for( size_t i = 0; i < n; i++ )
    {
        t = l[i] + c; c = ( t < c );
        d[i] = t;
    }
    return( c );
}

mbedtls_mpi_uint mbedtls_mpi_core_lt( const mbedtls_mpi_uint *l,
                                      const mbedtls_mpi_uint *r,
                                      size_t n )
{
    mbedtls_mpi_uint c = 0, t, z;
    for( size_t i = 0; i < n; i++ )
    {
        z = ( l[i] <  c ); t = l[i] - c;
        c = ( t < r[i] ) + z;
    }
    return( c );
}

mbedtls_mpi_uint mbedtls_mpi_core_mla( mbedtls_mpi_uint *d, size_t d_len,
                                       const mbedtls_mpi_uint *s, size_t s_len,
                                       mbedtls_mpi_uint b )
{
    mbedtls_mpi_uint c = 0; /* carry */
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

void mbedtls_mpi_core_mul( mbedtls_mpi_uint *X,
                           const mbedtls_mpi_uint *A, size_t a,
                           const mbedtls_mpi_uint *B, size_t b )
{
    memset( X, 0, ( a + b ) * ciL );
    for( size_t i=0; i < b; i++ )
        (void) mbedtls_mpi_core_mla( X + i, a + 1, A, a, B[i] );
}

/*
 * Fast Montgomery initialization (thanks to Tom St Denis)
 */
static void mpi_montg_init( mbedtls_mpi_uint *mm, const mbedtls_mpi_uint *N )
{
    mbedtls_mpi_uint x, m0 = *N;
    unsigned int i;

    x  = m0;
    x += ( ( m0 + 2 ) & 4 ) << 1;

    for( i = biL; i >= 8; i /= 2 )
        x *= ( 2 - ( m0 * x ) );

    *mm = ~x + 1;
}

void mbedtls_mpi_core_montmul( mbedtls_mpi_uint *A,
                               const mbedtls_mpi_uint *B,
                               size_t B_len,
                               const mbedtls_mpi_uint *N,
                               size_t n,
                               mbedtls_mpi_uint mm,
                               mbedtls_mpi_uint *T )
{
    memset( T, 0, (2*n+1)*ciL );

    for( size_t i = 0; i < n; i++, T++ )
    {
        mbedtls_mpi_uint u0, u1;
        /* T = (T + u0*B + u1*N) / 2^biL */
        u0 = A[i];
        u1 = ( T[0] + u0 * B[0] ) * mm;

        (void) mbedtls_mpi_core_mla( T, n + 2, B, B_len, u0 );
        (void) mbedtls_mpi_core_mla( T, n + 2, N, n, u1 );
    }

    mbedtls_mpi_uint carry, borrow, fixup;

    carry  = T[n];
    borrow = mbedtls_mpi_core_sub( A, T, N, n );
    fixup  = carry < borrow;
    (void) mbedtls_mpi_core_mla( A, n, N, n, fixup );
}

void mbedtls_mpi_core_add_mod( mbedtls_mpi_uint *X,
                               mbedtls_mpi_uint const *A,
                               mbedtls_mpi_uint const *B,
                               const mbedtls_mpi_uint *N,
                               size_t n )
{
    size_t carry, borrow = 0, fixup;
    carry  = mbedtls_mpi_core_add( X, A, B, n );
    borrow = mbedtls_mpi_core_sub( X, X, N, n );
    fixup  = ( carry < borrow );
    (void) mbedtls_mpi_core_mla( X, n, N, n, fixup );
}

void mbedtls_mpi_core_sub_mod( mbedtls_mpi_uint *X,
                               mbedtls_mpi_uint const *A,
                               mbedtls_mpi_uint const *B,
                               const mbedtls_mpi_uint *N,
                               size_t n )
{
    size_t borrow = mbedtls_mpi_core_sub( X, A, B, n );
    (void) mbedtls_mpi_core_mla( X, n, N, n, borrow );
}

int mbedtls_mpi_core_mod( mbedtls_mpi_uint *X,
                          mbedtls_mpi_uint const *A, size_t A_len,
                          const mbedtls_mpi_uint *N, size_t n,
                          const mbedtls_mpi_uint *RR )
{
    int ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
    mbedtls_mpi_uint *mempool, *T, *acc, mm, one=1;

    MBEDTLS_MPI_CHK( mbedtls_mpi_core_calloc( &mempool, n+2*n+1) );
    acc = mempool;
    T   = mempool + n;

    mpi_montg_init( &mm, N ); /* Compute Montgomery constant */
    A += A_len; /* Jump to end of A */

    /* The basic idea is the following:
     * With R = 2^{n*biL}, split A w.r.t. radix R as
     * A = A0 + R A1 + R^2 A2 + ... = A0 + R(A1 + R(... R(A(n-1) + R*An))...)
     *
     * And calculate the iteration X |-> Ai + R*X via combination of
     * Montgomery multiplication with R^2 and a modular addition. */

    /* Start with top block of A */
    size_t block_size = A_len % n;
    if( block_size == 0 )
        block_size = n;

    A_len -= block_size;
    A     -= block_size;
    memset( acc, 0, n*ciL );
    memcpy( acc, A, block_size * ciL );

    while( A_len >= n )
    {
        A_len -= n;
        A     -= n;
        /* X |-> R*X mod N via Montgomery multiplication with R^2 */
        mbedtls_mpi_core_montmul( acc, RR, n, N, n, mm, T );
        /* Add current block of A */
        mbedtls_mpi_core_add_mod( acc, acc, A, N, n );
    }

    /* At this point, we have quasi-reduced the input to the same number
     * of limbs as the modulus. We get a canonical representative through
     * two inverse Montomgery multiplications by 1 and R^2.
     *
     * TODO: This can be done more efficiently ... one step of Montgomery
     *       reduction should be enough?
     *
     * TODO: Some call-sites seem to be fine with quasi-reduction --
     *       split this out as a separate function? */
    mbedtls_mpi_core_montmul( acc, RR, n, N, n, mm, T );
    mbedtls_mpi_core_montmul( acc, &one, 1, N, n, mm, T );

    memcpy( X, acc, n*ciL ); /* Store result */

cleanup:

    mbedtls_free( mempool );
    return( ret );
}

int mbedtls_mpi_core_crt_fwd( mbedtls_mpi_uint *TP, mbedtls_mpi_uint *TQ,
                              const mbedtls_mpi_uint *P, size_t P_len,
                              const mbedtls_mpi_uint *Q, size_t Q_len,
                              const mbedtls_mpi_uint *T, size_t T_len,
                              const mbedtls_mpi_uint *RP,
                              const mbedtls_mpi_uint *RQ )
{
    int ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_mod( TP, T, T_len, P, P_len, RP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_mod( TQ, T, T_len, Q, Q_len, RQ ) );
cleanup:
    return( ret );
}

int mbedtls_mpi_core_crt_inv( mbedtls_mpi_uint *T,
                              mbedtls_mpi_uint *TP,
                              mbedtls_mpi_uint *TQ,
                              const mbedtls_mpi_uint *P, size_t P_len,
                              const mbedtls_mpi_uint *Q, size_t Q_len,
                              const mbedtls_mpi_uint *RP,
                              const mbedtls_mpi_uint *QinvP )
{
    int ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
    mbedtls_mpi_uint *mempool, *temp, *TQP;
    mbedtls_mpi_uint mmP, carry;
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_calloc( &mempool, P_len + (2*P_len+1)) );
    TQP = mempool;
    temp = TQP + P_len;

    mpi_montg_init( &mmP, P );

    /*
     * T = TQ + [(TP - (TQ mod P)) * (Q^-1 mod P) mod P]*Q
     */

    /* Compute (TQ mod P) within T */
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_mod( TQP, TQ, Q_len, P, P_len, RP ) );
    /* TP - (TQ mod P) */
    mbedtls_mpi_core_sub_mod( TP, TP, TQP, P, P_len );
    /* (TP - (TQ mod P)) * (Q^-1 mod P) mod P */
    mbedtls_mpi_core_montmul( TP, QinvP, P_len, P, P_len, mmP, temp );
    mbedtls_mpi_core_montmul( TP, RP, P_len, P, P_len, mmP, temp );
    /* [(TP - (TQ mod P)) * (Q^-1 mod P) mod P]*Q */
    mbedtls_mpi_core_mul( T, TP, P_len, Q, Q_len );
    /* Final result */
    carry = mbedtls_mpi_core_add( T, T, TQ, Q_len );
    mbedtls_mpi_core_add_int( T + Q_len, T + Q_len, carry, P_len );

cleanup:
    mbedtls_free( mempool );
    return( ret );
}

int mbedtls_mpi_core_inv_mod_prime( mbedtls_mpi_uint *X,
                                    mbedtls_mpi_uint const *A,
                                    size_t A_len,
                                    const mbedtls_mpi_uint *P,
                                    size_t n,
                                    mbedtls_mpi_uint *RR )
{
    int ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
    mbedtls_mpi_uint *P2;
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_calloc( &P2, n ) );

    /* |F_p^x| - 1 = p - 2 */
    (void) mbedtls_mpi_core_sub_int( P2, P, 2, n );
    /* Inversion by power: g^|G| = 1 <=> g^{-1} = g^{|G|-1} */
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_mod( X, A, A_len, P, n, RR ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_core_exp_mod( X, X, P, n, P2, n, RR ) );

cleanup:

    mbedtls_free( P2 );
    return( ret );
}

/*
 * Sliding-window exponentiation: X = A^E mod N  (HAC 14.85)
 */

static size_t mpi_exp_mod_get_window_size( size_t Ebits )
{
    size_t wsize = ( Ebits > 671 ) ? 6 : ( Ebits > 239 ) ? 5 :
                   ( Ebits >  79 ) ? 4 : ( Ebits >  23 ) ? 3 : 1;

#if( MBEDTLS_MPI_WINDOW_SIZE < 6 )
    if( wsize > MBEDTLS_MPI_WINDOW_SIZE )
        wsize = MBEDTLS_MPI_WINDOW_SIZE;
#endif

    return( wsize );
}

int mbedtls_mpi_core_exp_mod( mbedtls_mpi_uint *X,
                              mbedtls_mpi_uint *A,
                              const mbedtls_mpi_uint *N,
                              size_t n,
                              const mbedtls_mpi_uint *E,
                              size_t E_len,
                              const mbedtls_mpi_uint *RR )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    /* heap allocated memory pool */
    mbedtls_mpi_uint *mempool;
    /* pointers to temporaries within memory pool */
    mbedtls_mpi_uint *Wtbl, *Wselect, *temp;
    /* pointers to table entries */
    mbedtls_mpi_uint *Wcur, *Wlast, *W1;

    size_t wsize, welem;
    mbedtls_mpi_uint one = 1, mm;

    mpi_montg_init( &mm, N ); /* Compute Montgomery constant */
    E += E_len;               /* Skip to end of exponent buffer */

    wsize = mpi_exp_mod_get_window_size( E_len * biL );
    welem = 1 << wsize;

    /* Allocate memory pool and set pointers to parts of it */
    const size_t table_limbs   = welem * n;
    const size_t temp_limbs    = 2 * n + 1;
    const size_t wselect_limbs = n;
    const size_t total_limbs   = table_limbs + temp_limbs + wselect_limbs;
    mempool = mbedtls_calloc( total_limbs, ciL );
    if( mempool == NULL )
    {
        ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
        goto cleanup;
    }
    Wtbl    = mempool;
    Wselect = Wtbl    + table_limbs;
    temp    = Wselect + wselect_limbs;

    /*
     * Window precomputation
     */

    /* W[0] = 1 (in Montgomery presentation) */
    memset( Wtbl, 0, n * ciL ); Wtbl[0] = 1;
    mbedtls_mpi_core_montmul( Wtbl, RR, n, N, n, mm, temp );
    Wcur = Wtbl + n;
    /* W[1] = A * R^2 * R^-1 mod N = A * R mod N */
    memcpy( Wcur, A, n * ciL );
    mbedtls_mpi_core_montmul( Wcur, RR, n, N, n, mm, temp );
    W1 = Wcur;
    Wcur += n;
    /* W[i+1] = W[i] * W[1], i >= 2 */
    Wlast = W1;
    for( size_t i=2; i < welem; i++, Wlast += n, Wcur += n )
    {
        memcpy( Wcur, Wlast, n * ciL );
        mbedtls_mpi_core_montmul( Wcur, W1, n, N, n, mm, temp );
    }

    /*
     * Sliding window exponentiation
     */

    /* X = 1 (in Montgomery presentation) initially */
    memcpy( X, Wtbl, n * ciL );

    size_t limb_bits_remaining = 0;
    mbedtls_mpi_uint window = 0;
    size_t window_bits = 0, cur_limb;
    while( 1 )
    {
        size_t window_bits_missing = wsize - window_bits;

        const int no_more_bits =
            ( limb_bits_remaining == 0 ) && ( E_len == 0 );
        const int window_full =
            ( window_bits_missing == 0 );

        /* Clear window if it's full or if we don't have further bits. */
        if( window_full || no_more_bits )
        {
            if( window_bits == 0 )
                break;
            /* Select table entry, square and multiply */
            mbedtls_ct_table_lookup( (unsigned char*) Wselect,
                                     (unsigned char*) Wtbl,
                                     n * ciL, welem, window );
            mbedtls_mpi_core_montmul( X, Wselect, n, N, n, mm, temp );
            window = window_bits = 0;
            continue;
        }

        /* Load next exponent limb if necessary */
        if( limb_bits_remaining == 0 )
        {
            cur_limb = *--E;
            E_len--;
            limb_bits_remaining = biL;
        }

        /* Square */
        mbedtls_mpi_core_montmul( X, X, n, N, n, mm, temp );

        /* Insert next exponent bit into window */
        window   <<= 1;
        window    |= ( cur_limb >> ( biL - 1 ) );
        cur_limb <<= 1;
        window_bits++;
        limb_bits_remaining--;
    }

    /* Convert X back to normal presentation */
    mbedtls_mpi_core_montmul( X, &one, 1, N, n, mm, temp );

    ret = 0;

cleanup:

    mbedtls_free( mempool );
    return( ret );
}

void mbedtls_mpi_core_get_montgomery_constant_safe( mbedtls_mpi_uint *RR,
                                                    mbedtls_mpi_uint const *N,
                                                    size_t n )
{
    /* Start with 2^0=1 */
    memset( RR, 0, n * ciL );
    RR[0] = 1;

    /* Repated doubling and modular reduction -- very slow, but compared
     * to an RSA private key operation it seems acceptable. */
    for( size_t i=0; i < 2*n*biL; i++ )
        mbedtls_mpi_core_add_mod( RR, RR, RR, N, n );
}

/* Convert a big-endian byte array aligned to the size of mbedtls_mpi_uint
 * into the storage form used by mbedtls_mpi. */

static mbedtls_mpi_uint mpi_uint_bigendian_to_host_c( mbedtls_mpi_uint x )
{
    uint8_t i;
    unsigned char *x_ptr;
    mbedtls_mpi_uint tmp = 0;

    for( i = 0, x_ptr = (unsigned char*) &x; i < ciL; i++, x_ptr++ )
    {
        tmp <<= CHAR_BIT;
        tmp |= (mbedtls_mpi_uint) *x_ptr;
    }

    return( tmp );
}

mbedtls_mpi_uint mbedtls_mpi_core_uint_bigendian_to_host( mbedtls_mpi_uint x )
{
#if defined(__BYTE_ORDER__)

/* Nothing to do on bigendian systems. */
#if ( __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ )
    return( x );
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
            return( __builtin_bswap32(x) );
        case 8:
            return( __builtin_bswap64(x) );
    }
#endif
#endif /* __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ */
#endif /* __BYTE_ORDER__ */

    /* Fall back to C-based reordering if we don't know the byte order
     * or we couldn't use a compiler-specific builtin. */
    return( mpi_uint_bigendian_to_host_c( x ) );
}

void mbedtls_mpi_core_bigendian_to_host( mbedtls_mpi_uint * const p, size_t limbs )
{
    mbedtls_mpi_uint *cur_limb_left;
    mbedtls_mpi_uint *cur_limb_right;
    if( limbs == 0 )
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
    for( cur_limb_left = p, cur_limb_right = p + ( limbs - 1 );
         cur_limb_left <= cur_limb_right;
         cur_limb_left++, cur_limb_right-- )
    {
        mbedtls_mpi_uint tmp;
        /* Note that if cur_limb_left == cur_limb_right,
         * this code effectively swaps the bytes only once. */
        tmp             = mbedtls_mpi_core_uint_bigendian_to_host( *cur_limb_left  );
        *cur_limb_left  = mbedtls_mpi_core_uint_bigendian_to_host( *cur_limb_right );
        *cur_limb_right = tmp;
    }
}


#endif /* MBEDTLS_BIGNUM_C */
