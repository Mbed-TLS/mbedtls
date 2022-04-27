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
int mbedtls_mpi_core_add( mbedtls_mpi_uint *d, size_t nd,
                          const mbedtls_mpi_uint *l, size_t nl,
                          const mbedtls_mpi_uint *r, size_t nr,
                          mbedtls_mpi_uint *carry )
{
    mbedtls_mpi_uint res;
    if( nd != nl || nl != nr )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    res = MPI_CORE(add)( d, l, r, nr );
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
int mbedtls_mpi_core_add_int( mbedtls_mpi_uint *d, size_t nd,
                              const mbedtls_mpi_uint *l, size_t nl,
                              mbedtls_mpi_uint c,
                              mbedtls_mpi_uint *carry )
{
    mbedtls_mpi_uint res;
    if( nd != nl )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    res = MPI_CORE(add_int)( d, l, c, nd );
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
int mbedtls_mpi_core_sub( mbedtls_mpi_uint *d, size_t nd,
                          const mbedtls_mpi_uint *l, size_t nl,
                          const mbedtls_mpi_uint *r, size_t nr,
                          mbedtls_mpi_uint *borrow )
{
    mbedtls_mpi_uint res;
    if( nd != nl || nl != nr )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    res = MPI_CORE(sub)( d, l, r, nr );
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
int mbedtls_mpi_core_sub_int( mbedtls_mpi_uint *d, size_t nd,
                              const mbedtls_mpi_uint *l, size_t nl,
                              mbedtls_mpi_uint c,
                              mbedtls_mpi_uint *borrow )
{
    mbedtls_mpi_uint res;
    if( nd != nl )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    res = MPI_CORE(sub_int)( d, l, c, nd );
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
int mbedtls_mpi_core_mla( mbedtls_mpi_uint *d, size_t nd,
                          const mbedtls_mpi_uint *s, size_t ns,
                          mbedtls_mpi_uint b,
                          mbedtls_mpi_uint *carry )
{
    mbedtls_mpi_uint res;
    res = MPI_CORE(mla)( d, nd, s, ns, b );
    if( carry != NULL )
        *carry = res;
    return( 0 );
}

void MPI_CORE(mul)( mbedtls_mpi_uint *X,
                    const mbedtls_mpi_uint *A, size_t a,
                    const mbedtls_mpi_uint *B, size_t b );

static inline
int mbedtls_mpi_core_mul( mbedtls_mpi_uint *X, size_t nx,
                          const mbedtls_mpi_uint *A, size_t na,
                          const mbedtls_mpi_uint *B, size_t nb )
{
    if( nx != na + nb )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    MPI_CORE(mul)( X, A, na, B, nb );
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
int mbedtls_mpi_core_montmul( mbedtls_mpi_uint *A, size_t na,
                              const mbedtls_mpi_uint *B, size_t nb,
                              const mbedtls_mpi_uint *N, size_t nn,
                              mbedtls_mpi_uint *T, size_t nt,
                              mbedtls_mpi_uint mm )
{
    if( na != nn || nb > nn || nt != 2*nn + 1 )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    MPI_CORE(montmul)( A, B, nb, N, nn, mm, T );
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
int mbedtls_mpi_core_get_montgomery_constant_safe( mbedtls_mpi_uint *RR, size_t nrr,
                                                   mbedtls_mpi_uint const *N, size_t n )
{
    if( nrr != n )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    MPI_CORE(get_montgomery_constant_safe)( RR, N, n );
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
int mbedtls_mpi_core_exp_mod( mbedtls_mpi_uint *X, size_t nx,
                              mbedtls_mpi_uint *A, size_t na,
                              const mbedtls_mpi_uint *N, size_t nn,
                              const mbedtls_mpi_uint *E, size_t ne,
                              const mbedtls_mpi_uint *RR, size_t nrr )
{
    if( nx != nn || na != nn || nrr != nn )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    return( MPI_CORE(exp_mod)( X, A, N, nn, E, ne, RR ) );
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
int mbedtls_mpi_core_mod_reduce( mbedtls_mpi_uint *X, size_t nx,
                                 mbedtls_mpi_uint const *A, size_t na,
                                 const mbedtls_mpi_uint *N, size_t nn,
                                 const mbedtls_mpi_uint *RR, size_t nrr )
{
    if( nx != nn || nrr != nn )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    return( MPI_CORE(mod_reduce)( X, A, na, N, nn, RR ) );
}

int MPI_CORE(crt_fwd)( mbedtls_mpi_uint *TP, mbedtls_mpi_uint *TQ,
                       const mbedtls_mpi_uint *P, size_t P_len,
                       const mbedtls_mpi_uint *Q, size_t Q_len,
                       const mbedtls_mpi_uint *T, size_t T_len,
                       const mbedtls_mpi_uint *RP,
                       const mbedtls_mpi_uint *RQ );

static inline
int mbedtls_mpi_core_crt_fwd(       mbedtls_mpi_uint *TP, size_t ntp,
                                    mbedtls_mpi_uint *TQ, size_t ntq,
                              const mbedtls_mpi_uint *P,  size_t np,
                              const mbedtls_mpi_uint *Q,  size_t nq,
                              const mbedtls_mpi_uint *T,  size_t nt,
                              const mbedtls_mpi_uint *RP, size_t nrp,
                              const mbedtls_mpi_uint *RQ, size_t nrq)
{
    if( ntp != np || ntq != nq || nrp != np || nrq != nq )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    return( MPI_CORE(crt_fwd)( TP, TQ, P, np, Q, nq, T, nt, RP, RQ ) );
}

int MPI_CORE(crt_inv)( mbedtls_mpi_uint *T,
                              mbedtls_mpi_uint *TP,
                              mbedtls_mpi_uint *TQ,
                              const mbedtls_mpi_uint *P, size_t P_len,
                              const mbedtls_mpi_uint *Q, size_t Q_len,
                              const mbedtls_mpi_uint *RP,
                              const mbedtls_mpi_uint *QinvP );

static inline
int mbedtls_mpi_core_crt_inv(       mbedtls_mpi_uint *T,     size_t nt,
                                    mbedtls_mpi_uint *TP,    size_t ntp,
                                    mbedtls_mpi_uint *TQ,    size_t ntq,
                              const mbedtls_mpi_uint *P,     size_t np,
                              const mbedtls_mpi_uint *Q,     size_t nq,
                              const mbedtls_mpi_uint *RP,    size_t nrp,
                              const mbedtls_mpi_uint *QinvP, size_t nqp )
{
    if( ntp != np || ntq != nq || nrp != np || nqp != np || nt != np + nq )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    return( MPI_CORE(crt_inv)( T, TP, TQ, P, np, Q, nq, RP, QinvP ) );
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
int mbedtls_mpi_core_lt( const mbedtls_mpi_uint *l, size_t nl,
                         const mbedtls_mpi_uint *r, size_t nr,
                         unsigned *lt )
{
    if( nl != nr || lt == NULL )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    *lt = MPI_CORE(lt)( l, r, nl );
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
int mbedtls_mpi_core_add_mod( mbedtls_mpi_uint *X,       size_t nx,
                              mbedtls_mpi_uint const *A, size_t na,
                              mbedtls_mpi_uint const *B, size_t nb,
                              const mbedtls_mpi_uint *N, size_t nn )
{
    if( nx != nn || na != nn || nb != nn )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    MPI_CORE(add_mod)(X,A,B,N,nn);
    return( 0 );
}

void MPI_CORE(sub_mod)( mbedtls_mpi_uint *X, mbedtls_mpi_uint const *A,
                        mbedtls_mpi_uint const *B, const mbedtls_mpi_uint *N,
                        size_t n );

static inline
int mbedtls_mpi_core_sub_mod( mbedtls_mpi_uint *X,       size_t nx,
                              mbedtls_mpi_uint const *A, size_t na,
                              mbedtls_mpi_uint const *B, size_t nb,
                              const mbedtls_mpi_uint *N, size_t nn )
{
    if( nx != nn || na != nn || nb != nn )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    MPI_CORE(sub_mod)(X,A,B,N,nn);
    return( 0 );
}

/* TODO: Document */
int MPI_CORE(inv_mod_prime)( mbedtls_mpi_uint *X,
                             mbedtls_mpi_uint const *A,
                             const mbedtls_mpi_uint *P, size_t n,
                             mbedtls_mpi_uint *RR );

static inline
int mbedtls_mpi_core_inv_mod_prime( mbedtls_mpi_uint *X,       size_t nx,
                                    mbedtls_mpi_uint const *A, size_t na,
                                    const mbedtls_mpi_uint *P, size_t np,
                                    mbedtls_mpi_uint *RR,      size_t nrr )
{
    if( nx != np || na != np || nrr != np )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    return( MPI_CORE(inv_mod_prime)(X,A,P,np,RR) );
}

/* TODO: Document */
mbedtls_mpi_uint mbedtls_mpi_core_uint_bigendian_to_host( mbedtls_mpi_uint x );
/* TODO: Document */
void mbedtls_mpi_core_bigendian_to_host( mbedtls_mpi_uint * p, size_t limbs );

/* TODO: Document */
void mbedtls_mpi_core_read_binary( mbedtls_mpi_uint *X, size_t nx,
                                   const unsigned char *buf, size_t buflen );
/* TODO: Document */
void MPI_CORE(write_binary)( const mbedtls_mpi_uint *X,
                             unsigned char *buf, size_t buflen );

static inline
int mbedtls_mpi_core_write_binary( const mbedtls_mpi_uint *X, size_t nx,
                                   unsigned char *buf, size_t buflen )
{
    if( nx < CHARS_TO_LIMBS(buflen) )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    MPI_CORE(write_binary)( X, buf, buflen );
    return( 0 );
}

int MPI_CORE(random_be)( mbedtls_mpi_uint *X, size_t nx,
                         size_t n_bytes,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

static inline
int mbedtls_mpi_core_random_be( mbedtls_mpi_uint *X, size_t nx,
                                size_t n_bytes,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( nx < CHARS_TO_LIMBS( n_bytes ) )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );
    if( nx == 0 )
        return( 0 );
    return( MPI_CORE(random_be)( X, nx, n_bytes, f_rng, p_rng ) );
}

void mbedtls_mpi_core_shift_r( mbedtls_mpi_uint *X, size_t nx, size_t count );

#endif /* MBEDTLS_BIGNUM_CORE_H */
