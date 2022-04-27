/**
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

#ifndef MBEDTLS_BIGNUM_CORE_H
#define MBEDTLS_BIGNUM_CORE_H

#include "common.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_calloc     calloc
#endif

#define ciL    (sizeof(mbedtls_mpi_uint))         /* chars in limb  */
#define biL    (ciL << 3)                         /* bits  in limb  */
#define biH    (ciL << 2)                         /* half limb size */

/*
 * Convert between bits/chars and number of limbs
 * Divide first in order to avoid potential overflows
 */
#define BITS_TO_LIMBS(i)  ( (i) / biL + ( (i) % biL != 0 ) )
#define CHARS_TO_LIMBS(i) ( (i) / ciL + ( (i) % ciL != 0 ) )

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

/* Get a specific byte, without range checks. */
#define GET_BYTE( X, i )                                        \
    ( ( ( X )[( i ) / ciL] >> ( ( ( i ) % ciL ) * 8 ) ) & 0xff )
#define GET_BYTE_MPI( X, i ) GET_BYTE( (X)->p, i )

#define MPI_CORE(func) mbedtls_mpi_core_ ## func ## _minimal

typedef struct
{
    mbedtls_mpi_uint *p;
    size_t n;
} mbedtls_mpi_buf;

/**
 * \brief Add two known-size large unsigned integers, returning the carry.
 *
 * Calculate l + r where l and r have the same size.
 * This function operates modulo (2^ciL)^n and returns the carry
 * (1 if there was a wraparound, and 0 otherwise).
 *
 * d may be aliased to l or r.
 *
 * \param[out] d        The result of the addition.
 * \param[in] l         The left operand.
 * \param[in] r         The right operand.
 * \param n             Number of limbs of \p d, \p l and \p r.
 *
 * \return              1 if `l + r >= (2^{ciL})^n`, 0 otherwise.
 */
mbedtls_mpi_uint MPI_CORE(add)( mbedtls_mpi_uint *d,
                                const mbedtls_mpi_uint *l,
                                const mbedtls_mpi_uint *r,
                                size_t n );

static inline
int mbedtls_mpi_core_add( mbedtls_mpi_buf d, mbedtls_mpi_buf l, mbedtls_mpi_buf r,
                          mbedtls_mpi_uint *carry )
{
    mbedtls_mpi_uint res;
    if( d.n != l.n || l.n != r.n )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    res = MPI_CORE(add)( d.p, l.p, r.p, d.n );
    if( carry != NULL )
        *carry = res;
    return( 0 );
}

/**
 * \brief Add unsigned integer to known-size large unsigned integers.
 *        Return the carry.
 *
 * \param[out] d        The result of the addition.
 * \param[in] l         The left operand.
 * \param[in] r         The right operand.
 * \param n             Number of limbs of \p d and \p l.
 *
 * \return              1 if `l + r >= (2^{ciL})^n`, 0 otherwise.
 */
mbedtls_mpi_uint MPI_CORE(add_int)( mbedtls_mpi_uint *d,
                                    const mbedtls_mpi_uint *l,
                                    mbedtls_mpi_uint c, size_t n );

static inline
int mbedtls_mpi_core_add_int( mbedtls_mpi_buf d, mbedtls_mpi_buf l,
                              mbedtls_mpi_uint c, mbedtls_mpi_uint *carry )
{
    mbedtls_mpi_uint res;
    if( d.n != l.n )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    res = MPI_CORE(add_int)( d.p, l.p, c, d.n );
    if( carry != NULL )
        *carry = res;
    return( 0 );
}

/**
 * \brief Subtract two known-size large unsigned integers, returning the borrow.
 *
 * Calculate l - r where l and r have the same size.
 * This function operates modulo (2^ciL)^n and returns the carry
 * (1 if there was a wraparound, i.e. if `l < r`, and 0 otherwise).
 *
 * d may be aliased to l or r.
 *
 * \param[out] d        The result of the subtraction.
 * \param[in] l         The left operand.
 * \param[in] r         The right operand.
 * \param n             Number of limbs of \p d, \p l and \p r.
 *
 * \return              1 if `l < r`.
 *                      0 if `l >= r`.
 */
mbedtls_mpi_uint MPI_CORE(sub)( mbedtls_mpi_uint *d,
                                const mbedtls_mpi_uint *l,
                                const mbedtls_mpi_uint *r,
                                size_t n );

static inline
int mbedtls_mpi_core_sub( mbedtls_mpi_buf d, mbedtls_mpi_buf l,
                          mbedtls_mpi_buf r, mbedtls_mpi_uint *borrow )
{
    mbedtls_mpi_uint res;
    if( d.n != l.n || l.n != r.n )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    res = MPI_CORE(sub)( d.p, l.p, r.p, r.n );
    if( borrow != NULL )
        *borrow = res;
    return( 0 );
}

/**
 * \brief Subtract unsigned integer from known-size large unsigned integers.
 *        Return the borrow.
 *
 * \param[out] d        The result of the subtraction.
 * \param[in] l         The left operand.
 * \param[in] r         The unsigned scalar to subtract.
 * \param n             Number of limbs of \p d and \p l.
 *
 * \return              1 if `l < r`.
 *                      0 if `l >= r`.
 */
mbedtls_mpi_uint MPI_CORE(sub_int)( mbedtls_mpi_uint *d,
                                    const mbedtls_mpi_uint *l,
                                    mbedtls_mpi_uint r, size_t n );

static inline
int mbedtls_mpi_core_sub_int( mbedtls_mpi_buf d, mbedtls_mpi_buf l,
                              mbedtls_mpi_uint c, mbedtls_mpi_uint *borrow )
{
    mbedtls_mpi_uint res;
    if( d.n != l.n )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    res = MPI_CORE(sub_int)( d.p, l.p, c, d.n );
    if( borrow != NULL )
        *borrow = res;
    return( 0 );
}

/** Perform a known-size multiply accumulate operation
 *
 * Add \p b * \p s to \p d.
 *
 * \param[in,out] d     The pointer to the (little-endian) array
 *                      representing the bignum to accumulate onto.
 * \param d_len         The number of limbs of \p d. This must be
 *                      at least \p s_len.
 * \param[in] s         The pointer to the (little-endian) array
 *                      representing the bignum to multiply with.
 *                      This may be the same as \p d. Otherwise,
 *                      it must be disjoint from \p d.
 * \param s_len         The number of limbs of \p s.
 * \param b             A scalar to multiply with.
 *
 * \return c            The carry at the end of the operation.
 */
mbedtls_mpi_uint MPI_CORE(mla)( mbedtls_mpi_uint *d, size_t d_len ,
                                const mbedtls_mpi_uint *s, size_t s_len,
                                mbedtls_mpi_uint b );

static inline
int mbedtls_mpi_core_mla( mbedtls_mpi_buf d, mbedtls_mpi_buf s,
                          mbedtls_mpi_uint b, mbedtls_mpi_uint *carry )
{
    mbedtls_mpi_uint res;
    res = MPI_CORE(mla)( d.p, d.n, s.p, s.n, b );
    if( carry != NULL )
        *carry = res;
    return( 0 );
}

void MPI_CORE(mul)( mbedtls_mpi_uint *X,
                    const mbedtls_mpi_uint *A, size_t a,
                    const mbedtls_mpi_uint *B, size_t b );

static inline
int mbedtls_mpi_core_mul( mbedtls_mpi_buf x, mbedtls_mpi_buf a, mbedtls_mpi_buf b )
{
    if( x.n != a.n + b.n )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    MPI_CORE(mul)( x.p, a.p, a.n, b.p, b.n );
    return( 0 );
}

/** Montgomery multiplication: A = A * B * R^-1 mod N  (HAC 14.36)
 *
 * \param[in,out]   A   Big endian presentation of first operand.
 *                      Must have exactly \p n limbs.
 *                      On successful completion, A contains the result of
 *                      the multiplication A * B * R^-1 mod N where
 *                      R = (2^ciL)^n.
 * \param[in]       B   Big endian presentation of second operand.
 *                      Must have exactly \p n limbs.
 * \param[in]       N   Big endian presentation of the modulus.
 *                      This must be odd and have exactly \p n limbs.
 * \param[in]       n   The number of limbs in \p A, \p B, \p N.
 * \param           mm  The Montgomery constant for \p N: -N^-1 mod 2^ciL.
 *                      This can be calculated by `mpi_montg_init()`.
 * \param[in,out]   T   Temporary storage of size at least 2*n+1 limbs.
 *                      Its initial content is unused and
 *                      its final content is indeterminate.
 */
void MPI_CORE(montmul)( mbedtls_mpi_uint *A, const mbedtls_mpi_uint *B,
                        size_t B_len, const mbedtls_mpi_uint *N,
                        size_t n, mbedtls_mpi_uint mm,
                        mbedtls_mpi_uint *T );

static inline
int mbedtls_mpi_core_montmul( mbedtls_mpi_buf a, mbedtls_mpi_buf n,
                              mbedtls_mpi_buf b, mbedtls_mpi_buf t,
                              mbedtls_mpi_uint mm )
{
    if( a.n != n.n || b.n > n.n || t.n != 2*n.n + 1 )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    MPI_CORE(montmul)( a.p, b.p, b.n, n.p, n.n, mm, t.p );
}

/**
 * \brief        Compute (2^{biL})^{2*n} mod N
 *
 * \param RR     The address at which to store the Montgomery constant.
 *               This must point to a writable buffer of \p n * ciL.
 * \param N      The modulus. This must be a readable buffer of length
 *               \p n * ciL.
 * \param n      The number of limbs in \p N and \p RR.
 *
 */
void MPI_CORE(get_montgomery_constant_safe)( mbedtls_mpi_uint *RR,
                                             mbedtls_mpi_uint const *N,
                                             size_t n );

static inline
int mbedtls_mpi_core_get_montgomery_constant_safe( mbedtls_mpi_buf rr,
                                                   mbedtls_mpi_buf n )
{
    if( rr.n != n.n )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    MPI_CORE(get_montgomery_constant_safe)( rr.p, n.p, n.n );
    return( 0 );
}

/**
 * \brief          Perform a modular exponentiation with secret exponent: X = A^E mod N
 *
 * \param X        The destination MPI, as a big endian array of length \p n.
 * \param A        The base MPI, as a big endian array of length \p n.
 * \param N        The modulus, as a big endian array of length \p n.
 * \param n        The number of limbs in \p X, \p A, \p N, \p RR.
 * \param E        The exponent, as a big endian array of length \p E_len.
 * \param E_len    The number of limbs in \p E.
 * \param RR       The precomputed residue of 2^{2*biL} modulo N, as a big
 *                 endian array of length \p n.
 * \return         \c 0 if successful.
 * \return         #MBEDTLS_ERR_MPI_ALLOC_FAILED if a memory allocation failed.
 */
int MPI_CORE(exp_mod)( mbedtls_mpi_uint *X, mbedtls_mpi_uint *A,
                       const mbedtls_mpi_uint *N, size_t n,
                       const mbedtls_mpi_uint *E, size_t E_len,
                       const mbedtls_mpi_uint *RR );

static inline
int mbedtls_mpi_core_exp_mod( mbedtls_mpi_buf x, mbedtls_mpi_buf a,
                              mbedtls_mpi_buf n, mbedtls_mpi_buf e,
                              mbedtls_mpi_buf rr )
{
    if( x.n != n.n || a.n != n.n || rr.n != n.n )
    {
        fprintf( stderr, "BAD! x %u, n %u, a %u, rr %u\n", x.n, n.n, a.n, rr.n );
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    }
    return( MPI_CORE(exp_mod)( x.p, a.p, n.p, n.n, e.p, e.n, rr.p ) );
}

/**
 * \brief        Perform a modular reduction
 *
 * \param X      The destination address at which to store the big endian
 *               presentation of the result of the modular reduction.
 *               This must point to a writable buffer of length \p n * ciL.
 * \param A      The address of the big endian presentation of the input.
 *               This must be a readable buffer of length \p A_len * ciL.
 * \param A_len  The number of limbs in \p A.
 * \param N      The address of the big endian presentation of the modulus.
 *               This must be a readable buffer of length \p n * ciL.
 * \param n      The number of limbs in \p n.
 * \param RR     The adddress of the big endian presentation of the precomputed
 *               Montgomery constant (2^{ciL})^{2*n} mod N.
 *               See MPI_CORE(get_montgomery_constant_safe)().
 *
 * \return       0 on success.
 * \return       MBEDTLS_ERR_MPI_ALLOC_FAILED
 */
int MPI_CORE(mod_reduce)( mbedtls_mpi_uint *X,
                   mbedtls_mpi_uint const *A, size_t A_len,
                   const mbedtls_mpi_uint *N, size_t n,
                   const mbedtls_mpi_uint *RR );

static inline
int mbedtls_mpi_core_mod_reduce( mbedtls_mpi_buf x, mbedtls_mpi_buf a,
                                 mbedtls_mpi_buf n, mbedtls_mpi_buf rr )
{
    if( x.n != n.n || rr.n != n.n )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    return( MPI_CORE(mod_reduce)( x.p, a.p, a.n, n.p, n.n, rr.p ) );
}

int MPI_CORE(crt_fwd)( mbedtls_mpi_uint *TP, mbedtls_mpi_uint *TQ,
                       const mbedtls_mpi_uint *P, size_t P_len,
                       const mbedtls_mpi_uint *Q, size_t Q_len,
                       const mbedtls_mpi_uint *T, size_t T_len,
                       const mbedtls_mpi_uint *RP,
                       const mbedtls_mpi_uint *RQ );

static inline
int mbedtls_mpi_core_crt_fwd( mbedtls_mpi_buf tp,
                              mbedtls_mpi_buf tq,
                              mbedtls_mpi_buf p,
                              mbedtls_mpi_buf q,
                              mbedtls_mpi_buf t,
                              mbedtls_mpi_buf rp,
                              mbedtls_mpi_buf rq )
{
    if( tp.n != p.n || tq.n != q.n || rp.n != p.n || rq.n != q.n )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    return( MPI_CORE(crt_fwd)( tp.p, tq.p, p.p, p.n, q.p, q.n, t.p, t.n, rp.p, rq.p ) );
}

int MPI_CORE(crt_inv)( mbedtls_mpi_uint *T,
                       mbedtls_mpi_uint *TP,
                       mbedtls_mpi_uint *TQ,
                       const mbedtls_mpi_uint *P, size_t P_len,
                       const mbedtls_mpi_uint *Q, size_t Q_len,
                       const mbedtls_mpi_uint *RP,
                       const mbedtls_mpi_uint *QinvP );

static inline
int mbedtls_mpi_core_crt_inv( mbedtls_mpi_buf t,
                              mbedtls_mpi_buf tp,
                              mbedtls_mpi_buf tq,
                              mbedtls_mpi_buf p,
                              mbedtls_mpi_buf q,
                              mbedtls_mpi_buf rp,
                              mbedtls_mpi_buf qinvp )
{
    if( tp.n != p.n || tq.n != q.n || rp.n != p.n || qinvp.n != p.n || t.n != p.n + q.n )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    return( MPI_CORE(crt_inv)( t.p, tp.p, tq.p, p.p, p.n, q.p, q.n, rp.p, qinvp.p ) );
}

/**
 * \brief        Compare to same-size large unsigned integers in constant time.
 *
 * \param l      The left operand.
 * \param r      The right operand.
 * \param n      The number of limbs in \p l and \p r.
 *
 * \return       \c 0 if \p l < \p r
 * \return       \c 1 if \p l >= \p r
 */
mbedtls_mpi_uint MPI_CORE(lt)( const mbedtls_mpi_uint *l,
                               const mbedtls_mpi_uint *r,
                               size_t n );

static inline
int mbedtls_mpi_core_lt( mbedtls_mpi_buf l, mbedtls_mpi_buf r, unsigned *lt )
{
    if( l.n != r.n || lt == NULL )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    *lt = MPI_CORE(lt)( l.p, r.p, l.n );
    return( 0 );
}

/**
 * \brief        Compare to same-size large unsigned integers in constant time.
 *
 * \param l      The left operand.
 * \param r      The right operand.
 * \param n      The number of limbs in \p l and \p r.
 *
 * \return       \c 0 if \p l < \p r
 * \return       \c 1 if \p l >= \p r
 */
static inline int mbedtls_mpi_core_alloc( mbedtls_mpi_uint** p, size_t elems )
{
    *p = mbedtls_calloc( elems, sizeof(mbedtls_mpi_uint) );
    if( *p == NULL )
        return( MBEDTLS_ERR_MPI_ALLOC_FAILED );
    return( 0 );
}

/* TODO: Document */
void MPI_CORE(add_mod)( mbedtls_mpi_uint *X, mbedtls_mpi_uint const *A,
                        mbedtls_mpi_uint const *B, const mbedtls_mpi_uint *N,
                        size_t n );

static inline
int mbedtls_mpi_core_add_mod( mbedtls_mpi_buf x, mbedtls_mpi_buf a,
                              mbedtls_mpi_buf b, mbedtls_mpi_buf n )
{
    if( x.n != n.n || a.n != n.n || b.n != n.n )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    MPI_CORE(add_mod)(x.p,a.p,b.p,n.p,n.n);
    return( 0 );
}

void MPI_CORE(sub_mod)( mbedtls_mpi_uint *X, mbedtls_mpi_uint const *A,
                        mbedtls_mpi_uint const *B, const mbedtls_mpi_uint *N,
                        size_t n );

static inline
int mbedtls_mpi_core_sub_mod( mbedtls_mpi_buf x, mbedtls_mpi_buf a,
                              mbedtls_mpi_buf b, mbedtls_mpi_buf n )
{
    if( x.n != n.n || a.n != n.n || b.n != n.n )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    MPI_CORE(sub_mod)(x.p,a.p,b.p,n.p,n.n);
    return( 0 );
}

/* TODO: Document */
int MPI_CORE(inv_mod_prime)( mbedtls_mpi_uint *X,
                             mbedtls_mpi_uint const *A,
                             const mbedtls_mpi_uint *P, size_t n,
                             mbedtls_mpi_uint *RR );

static inline
int mbedtls_mpi_core_inv_mod_prime( mbedtls_mpi_buf x,
                                    mbedtls_mpi_buf a,
                                    mbedtls_mpi_buf p,
                                    mbedtls_mpi_buf rr )
{
    if( x.n != p.n || a.n != p.n || rr.n != p.n )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    return( MPI_CORE(inv_mod_prime)(x.p,a.p,p.p,p.n,rr.p) );
}

/* TODO: Document */
mbedtls_mpi_uint mbedtls_mpi_core_uint_bigendian_to_host( mbedtls_mpi_uint x );
/* TODO: Document */

void MPI_CORE(bigendian_to_host)( mbedtls_mpi_uint *X, size_t nx );
static inline
int mbedtls_mpi_core_bigendian_to_host( mbedtls_mpi_buf p )
{
    MPI_CORE(bigendian_to_host)(p.p,p.n);
    return( 0 );
}

void MPI_CORE(read_binary)( mbedtls_mpi_uint *X, size_t nx,
                            const unsigned char *buf, size_t buflen );
/* TODO: Document */
static inline
int mbedtls_mpi_core_read_binary( mbedtls_mpi_buf x,
                                  const unsigned char *buf, size_t buflen )
{
    MPI_CORE(read_binary)(x.p,x.n,buf,buflen);
    return( 0 );
}


/* TODO: Document */
void MPI_CORE(write_binary)( const mbedtls_mpi_uint *X,
                             unsigned char *buf, size_t buflen );

static inline
int mbedtls_mpi_core_write_binary( mbedtls_mpi_buf x,
                                   unsigned char *buf, size_t buflen )
{
    if( x.n < CHARS_TO_LIMBS(buflen) )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    MPI_CORE(write_binary)( x.p, buf, buflen );
    return( 0 );
}

int MPI_CORE(random_be)( mbedtls_mpi_uint *X, size_t nx, size_t n_bytes,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

static inline
int mbedtls_mpi_core_random_be( mbedtls_mpi_buf x, size_t n_bytes,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( x.n < CHARS_TO_LIMBS( n_bytes ) )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    if( x.n == 0 )
        return( 0 );
    return( MPI_CORE(random_be)( x.p, x.n, n_bytes, f_rng, p_rng ) );
}

void MPI_CORE(shift_r)( mbedtls_mpi_uint *X, size_t nx, size_t count );

static inline
int mbedtls_mpi_core_shift_r( mbedtls_mpi_buf x, size_t count )
{
    MPI_CORE(shift_r)( x.p, x.n, count );
    return( 0 );
}

#endif /* MBEDTLS_BIGNUM_CORE_H */
