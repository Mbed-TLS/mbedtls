/**
 * \file bignum.h
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
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
#ifndef POLARSSL_BIGNUM_H
#define POLARSSL_BIGNUM_H

#include <stdio.h>

#define POLARSSL_ERR_MPI_FILE_IO_ERROR                     0x0002
#define POLARSSL_ERR_MPI_BAD_INPUT_DATA                    0x0004
#define POLARSSL_ERR_MPI_INVALID_CHARACTER                 0x0006
#define POLARSSL_ERR_MPI_BUFFER_TOO_SMALL                  0x0008
#define POLARSSL_ERR_MPI_NEGATIVE_VALUE                    0x000A
#define POLARSSL_ERR_MPI_DIVISION_BY_ZERO                  0x000C
#define POLARSSL_ERR_MPI_NOT_ACCEPTABLE                    0x000E

#define MPI_CHK(f) if( ( ret = f ) != 0 ) goto cleanup

/*
 * Define the base integer type, architecture-wise
 */
#if defined(POLARSSL_HAVE_INT8)
typedef unsigned char  t_int;
typedef unsigned short t_dbl;
#else
#if defined(POLARSSL_HAVE_INT16)
typedef unsigned short t_int;
typedef unsigned long  t_dbl;
#else
  typedef unsigned long t_int;
  #if defined(_MSC_VER) && defined(_M_IX86)
  typedef unsigned __int64 t_dbl;
  #else
    #if defined(__amd64__) || defined(__x86_64__)    || \
        defined(__ppc64__) || defined(__powerpc64__) || \
        defined(__ia64__)  || defined(__alpha__)
    typedef unsigned int t_dbl __attribute__((mode(TI)));
    #else
      #if defined(POLARSSL_HAVE_LONGLONG)
      typedef unsigned long long t_dbl;
      #endif
    #endif
  #endif
#endif
#endif

/**
 * \brief          MPI structure
 */
typedef struct
{
    int s;              /*!<  integer sign      */
    int n;              /*!<  total # of limbs  */
    t_int *p;           /*!<  pointer to limbs  */
}
mpi;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Initialize one or more mpi
 */
void mpi_init( mpi *X, ... );

/**
 * \brief          Unallocate one or more mpi
 */
void mpi_free( mpi *X, ... );

/**
 * \brief          Enlarge to the specified number of limbs
 *
 * \param X        MPI to grow
 * \param nblimbs  The target number of limbs
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_grow( mpi *X, int nblimbs );

/**
 * \brief          Copy the contents of Y into X
 *
 * \param X        Destination MPI
 * \param Y        Source MPI
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_copy( mpi *X, const mpi *Y );

/**
 * \brief          Swap the contents of X and Y
 *
 * \param X        First MPI value
 * \param Y        Second MPI value
 */
void mpi_swap( mpi *X, mpi *Y );

/**
 * \brief          Set value from integer
 *
 * \param X        MPI to set
 * \param z        Value to use
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_lset( mpi *X, int z );

/**
 * \brief          Return the number of least significant bits
 *
 * \param X        MPI to use
 */
int mpi_lsb( const mpi *X );

/**
 * \brief          Return the number of most significant bits
 *
 * \param X        MPI to use
 */
int mpi_msb( const mpi *X );

/**
 * \brief          Return the total size in bytes
 *
 * \param X        MPI to use
 */
int mpi_size( const mpi *X );

/**
 * \brief          Import from an ASCII string
 *
 * \param X        Destination MPI
 * \param radix    Input numeric base
 * \param s        Null-terminated string buffer
 *
 * \return         0 if successful, or an POLARSSL_ERR_MPI_XXX error code
 */
int mpi_read_string( mpi *X, int radix, const char *s );

/**
 * \brief          Export into an ASCII string
 *
 * \param X        Source MPI
 * \param radix    Output numeric base
 * \param s        String buffer
 * \param slen     String buffer size
 *
 * \return         0 if successful, or an POLARSSL_ERR_MPI_XXX error code.
 *                 *slen is always updated to reflect the amount
 *                 of data that has (or would have) been written.
 *
 * \note           Call this function with *slen = 0 to obtain the
 *                 minimum required buffer size in *slen.
 */
int mpi_write_string( const mpi *X, int radix, char *s, int *slen );

/**
 * \brief          Read X from an opened file
 *
 * \param X        Destination MPI
 * \param radix    Input numeric base
 * \param fin      Input file handle
 *
 * \return         0 if successful, or an POLARSSL_ERR_MPI_XXX error code
 */
int mpi_read_file( mpi *X, int radix, FILE *fin );

/**
 * \brief          Write X into an opened file, or stdout if fout is NULL
 *
 * \param p        Prefix, can be NULL
 * \param X        Source MPI
 * \param radix    Output numeric base
 * \param fout     Output file handle (can be NULL)
 *
 * \return         0 if successful, or an POLARSSL_ERR_MPI_XXX error code
 *
 * \note           Set fout == NULL to print X on the console.
 */
int mpi_write_file( const char *p, const mpi *X, int radix, FILE *fout );

/**
 * \brief          Import X from unsigned binary data, big endian
 *
 * \param X        Destination MPI
 * \param buf      Input buffer
 * \param buflen   Input buffer size
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_read_binary( mpi *X, const unsigned char *buf, int buflen );

/**
 * \brief          Export X into unsigned binary data, big endian
 *
 * \param X        Source MPI
 * \param buf      Output buffer
 * \param buflen   Output buffer size
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_BUFFER_TOO_SMALL if buf isn't large enough
 */
int mpi_write_binary( const mpi *X, unsigned char *buf, int buflen );

/**
 * \brief          Left-shift: X <<= count
 *
 * \param X        MPI to shift
 * \param count    Amount to shift
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_shift_l( mpi *X, int count );

/**
 * \brief          Right-shift: X >>= count
 *
 * \param X        MPI to shift
 * \param count    Amount to shift
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_shift_r( mpi *X, int count );

/**
 * \brief          Compare unsigned values
 *
 * \param X        Left-hand MPI
 * \param Y        Right-hand MPI
 *
 * \return         1 if |X| is greater than |Y|,
 *                -1 if |X| is lesser  than |Y| or
 *                 0 if |X| is equal to |Y|
 */
int mpi_cmp_abs( const mpi *X, const mpi *Y );

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand MPI
 * \param Y        Right-hand MPI
 *
 * \return         1 if X is greater than Y,
 *                -1 if X is lesser  than Y or
 *                 0 if X is equal to Y
 */
int mpi_cmp_mpi( const mpi *X, const mpi *Y );

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand MPI
 * \param z        The integer value to compare to
 *
 * \return         1 if X is greater than z,
 *                -1 if X is lesser  than z or
 *                 0 if X is equal to z
 */
int mpi_cmp_int( const mpi *X, int z );

/**
 * \brief          Unsigned addition: X = |A| + |B|
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_add_abs( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Unsigned substraction: X = |A| - |B|
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 POLARSSL_ERR_MPI_NEGATIVE_VALUE if B is greater than A
 */
int mpi_sub_abs( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Signed addition: X = A + B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_add_mpi( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Signed substraction: X = A - B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_sub_mpi( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Signed addition: X = A + b
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to add
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_add_int( mpi *X, const mpi *A, int b );

/**
 * \brief          Signed substraction: X = A - b
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to subtract
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_sub_int( mpi *X, const mpi *A, int b );

/**
 * \brief          Baseline multiplication: X = A * B
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_mul_mpi( mpi *X, const mpi *A, const mpi *B );

/**
 * \brief          Baseline multiplication: X = A * b
 *                 Note: b is an unsigned integer type, thus
 *                 Negative values of b are ignored.
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param b        The integer value to multiply with
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_mul_int( mpi *X, const mpi *A, t_int b );

/**
 * \brief          Division by mpi: A = Q * B + R
 *
 * \param Q        Destination MPI for the quotient
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed,
 *                 POLARSSL_ERR_MPI_DIVISION_BY_ZERO if B == 0
 *
 * \note           Either Q or R can be NULL.
 */
int mpi_div_mpi( mpi *Q, mpi *R, const mpi *A, const mpi *B );

/**
 * \brief          Division by int: A = Q * b + R
 *
 * \param Q        Destination MPI for the quotient
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param b        Integer to divide by
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed,
 *                 POLARSSL_ERR_MPI_DIVISION_BY_ZERO if b == 0
 *
 * \note           Either Q or R can be NULL.
 */
int mpi_div_int( mpi *Q, mpi *R, const mpi *A, int b );

/**
 * \brief          Modulo: R = A mod B
 *
 * \param R        Destination MPI for the rest value
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed,
 *                 POLARSSL_ERR_MPI_DIVISION_BY_ZERO if B == 0,
 *                 POLARSSL_ERR_MPI_NEGATIVE_VALUE if B < 0
 */
int mpi_mod_mpi( mpi *R, const mpi *A, const mpi *B );

/**
 * \brief          Modulo: r = A mod b
 *
 * \param r        Destination t_int
 * \param A        Left-hand MPI
 * \param b        Integer to divide by
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed,
 *                 POLARSSL_ERR_MPI_DIVISION_BY_ZERO if b == 0,
 *                 POLARSSL_ERR_MPI_NEGATIVE_VALUE if b < 0
 */
int mpi_mod_int( t_int *r, const mpi *A, int b );

/**
 * \brief          Sliding-window exponentiation: X = A^E mod N
 *
 * \param X        Destination MPI 
 * \param A        Left-hand MPI
 * \param E        Exponent MPI
 * \param N        Modular MPI
 * \param _RR      Speed-up MPI used for recalculations
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed,
 *                 POLARSSL_ERR_MPI_BAD_INPUT_DATA if N is negative or even
 *
 * \note           _RR is used to avoid re-computing R*R mod N across
 *                 multiple calls, which speeds up things a bit. It can
 *                 be set to NULL if the extra performance is unneeded.
 */
int mpi_exp_mod( mpi *X, const mpi *A, const mpi *E, const mpi *N, mpi *_RR );

/**
 * \brief          Greatest common divisor: G = gcd(A, B)
 *
 * \param G        Destination MPI
 * \param A        Left-hand MPI
 * \param B        Right-hand MPI
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed
 */
int mpi_gcd( mpi *G, const mpi *A, const mpi *B );

/**
 * \brief          Modular inverse: X = A^-1 mod N
 *
 * \param X        Destination MPI
 * \param A        Left-hand MPI
 * \param N        Right-hand MPI
 *
 * \return         0 if successful,
 *                 1 if memory allocation failed,
 *                 POLARSSL_ERR_MPI_BAD_INPUT_DATA if N is negative or nil
                   POLARSSL_ERR_MPI_NOT_ACCEPTABLE if A has no inverse mod N
 */
int mpi_inv_mod( mpi *X, const mpi *A, const mpi *N );

/**
 * \brief          Miller-Rabin primality test
 *
 * \param X        MPI to check
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \return         0 if successful (probably prime),
 *                 1 if memory allocation failed,
 *                 POLARSSL_ERR_MPI_NOT_ACCEPTABLE if X is not prime
 */
int mpi_is_prime( mpi *X, int (*f_rng)(void *), void *p_rng );

/**
 * \brief          Prime number generation
 *
 * \param X        Destination MPI
 * \param nbits    Required size of X in bits
 * \param dh_flag  If 1, then (X-1)/2 will be prime too
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \return         0 if successful (probably prime),
 *                 1 if memory allocation failed,
 *                 POLARSSL_ERR_MPI_BAD_INPUT_DATA if nbits is < 3
 */
int mpi_gen_prime( mpi *X, int nbits, int dh_flag,
                   int (*f_rng)(void *), void *p_rng );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mpi_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* bignum.h */
