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

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf      printf
#define mbedtls_calloc      calloc
#define mbedtls_free        free
#endif

#include "bignum_core.h"

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
        tmp             = mpi_bigendian_to_host( *cur_limb_left  );
        *cur_limb_left  = mpi_bigendian_to_host( *cur_limb_right );
        *cur_limb_right = tmp;
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

#endif /* MBEDTLS_BIGNUM_C */
