/**
 *  Internal bignum functions
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

#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/bignum.h"
#include "bignum_core.h"
#include "bignum_mod.h"
#include "bignum_mod_raw.h"
#include "constant_time_internal.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf      printf
#define mbedtls_calloc      calloc
#define mbedtls_free        free
#endif

#define MPI_VALIDATE_RET( cond )                                       \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_MPI_BAD_INPUT_DATA )
#define MPI_VALIDATE( cond )                                           \
    MBEDTLS_INTERNAL_VALIDATE( cond )

#define ciL    (sizeof(mbedtls_mpi_uint))   /* chars in limb  */
#define biL    (ciL << 3)                   /* bits  in limb  */
#define biH    (ciL << 2)                   /* half limb size */

/*
 * Convert between bits/chars and number of limbs
 * Divide first in order to avoid potential overflows
 */
#define BITS_TO_LIMBS(i)  ( (i) / biL + ( (i) % biL != 0 ) )
#define CHARS_TO_LIMBS(i) ( (i) / ciL + ( (i) % ciL != 0 ) )

/*
 * Count leading zero bits in a given integer
 */
size_t mbedtls_mpi_core_clz( const mbedtls_mpi_uint x )
{
    size_t j;
    mbedtls_mpi_uint mask = (mbedtls_mpi_uint) 1 << (biL - 1);

    for( j = 0; j < biL; j++ )
    {
        if( x & mask ) break;

        mask >>= 1;
    }

    return j;
}

/*
 * Return the number of bits
 */
size_t mbedtls_mpi_core_bitlen( const mbedtls_mpi_uint *X, size_t nx )
{
    size_t i, j;

    if( nx == 0 )
        return( 0 );

    for( i = nx - 1; i > 0; i-- )
        if( X[i] != 0 )
            break;

    j = biL - mbedtls_mpi_core_clz( X[i] );

    return( ( i * biL ) + j );
}

/* Get a specific byte, without range checks. */
#define GET_BYTE( X, i )                                \
    ( ( ( X )[( i ) / ciL] >> ( ( ( i ) % ciL ) * 8 ) ) & 0xff )

int mbedtls_mpi_mod_residue_setup( mbedtls_mpi_mod_residue *r,
                                   mbedtls_mpi_mod_modulus *m,
                                   mbedtls_mpi_uint *p,
                                   size_t pn )
{
    if( p == NULL || m == NULL || r == NULL )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    if( pn < m->n || !mbedtls_mpi_core_lt_ct( m->p, p, pn ) )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    r->n = m->n;
    r->p = p;

    return( 0 );
}

void mbedtls_mpi_mod_residue_release( mbedtls_mpi_mod_residue *r )
{
    if ( r == NULL )
        return;

    r->n = 0;
    r->p = NULL;
}

void mbedtls_mpi_mod_modulus_init( mbedtls_mpi_mod_modulus *m )
{
    if ( m == NULL )
        return;

    m->p = NULL;
    m->n = 0;
    m->plen = 0;
    m->ext_rep = MBEDTLS_MPI_MOD_EXT_REP_INVALID;
    m->int_rep = MBEDTLS_MPI_MOD_REP_INVALID;
}

void mbedtls_mpi_mod_modulus_free( mbedtls_mpi_mod_modulus *m )
{
    if ( m == NULL )
        return;

    switch( m->int_rep )
    {
        case MBEDTLS_MPI_MOD_REP_MONTGOMERY:
            mbedtls_free( m->rep.mont ); break;
        case MBEDTLS_MPI_MOD_REP_OPT_RED:
            mbedtls_free( m->rep.ored ); break;
        default:
            break;
    }

    m->p = NULL;
    m->n = 0;
    m->plen = 0;
    m->ext_rep = MBEDTLS_MPI_MOD_EXT_REP_INVALID;
    m->int_rep = MBEDTLS_MPI_MOD_REP_INVALID;
}

int mbedtls_mpi_mod_modulus_setup( mbedtls_mpi_mod_modulus *m,
                                   mbedtls_mpi_uint *p,
                                   size_t pn,
                                   int ext_rep,
                                   int int_rep )
{
    int ret = 0;

    if ( p == NULL || m == NULL )
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    m->p = p;
    m->n = pn;
    m->plen = mbedtls_mpi_core_bitlen( p, pn );

    switch( ext_rep )
    {
        case MBEDTLS_MPI_MOD_EXT_REP_LE:
        case MBEDTLS_MPI_MOD_EXT_REP_BE:
            m->ext_rep = ext_rep; break;
        default:
            ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
            goto exit;
    }

    switch( int_rep )
    {
        case MBEDTLS_MPI_MOD_REP_MONTGOMERY:
            m->int_rep = int_rep;
            m->rep.mont = NULL; break;
        case MBEDTLS_MPI_MOD_REP_OPT_RED:
            m->int_rep = int_rep;
            m->rep.ored = NULL; break;
        default:
            ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
            goto exit;
    }

exit:

    if( ret != 0 )
    {
        mbedtls_mpi_mod_modulus_free( m );
    }

    return( ret );
}

/* Check X to have at least n limbs and set it to 0. */
static int mpi_core_clear( mbedtls_mpi_uint *X,
                           size_t nx,
                           size_t limbs )
{
    if( nx < limbs )
        return( MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL );

    if( X != NULL )
        memset( X, 0, nx * ciL );

    return( 0 );
}

/* Convert a big-endian byte array aligned to the size of mbedtls_mpi_uint
 * into the storage form used by mbedtls_mpi. */
static mbedtls_mpi_uint mpi_bigendian_to_host_c( mbedtls_mpi_uint x )
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

static mbedtls_mpi_uint mpi_bigendian_to_host( mbedtls_mpi_uint x )
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
    return( mpi_bigendian_to_host_c( x ) );
}

void mbedtls_mpi_core_bigendian_to_host( mbedtls_mpi_uint * const X,
                                         size_t limbs )
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
    for( cur_limb_left = X, cur_limb_right = X + ( limbs - 1 );
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

/*
 * Import X from unsigned binary data, little endian
 *
 * The MPI needs to have enough limbs to store the full value (in particular,
 * this function does not skip 0s in the input).
 */
int mbedtls_mpi_core_read_le( mbedtls_mpi_uint *X,
                              size_t nx,
                              const unsigned char *buf,
                              size_t buflen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i;
    size_t const limbs = CHARS_TO_LIMBS( buflen );

    /* Ensure that target MPI has at least the necessary number of limbs */
    MBEDTLS_MPI_CHK( mpi_core_clear( X, nx, limbs ) );

    for( i = 0; i < buflen; i++ )
        X[i / ciL] |= ((mbedtls_mpi_uint) buf[i]) << ((i % ciL) << 3);

cleanup:
    return( ret );
}

/*
 * Import X from unsigned binary data, big endian
 *
 * The MPI needs to have enough limbs to store the full value (in particular,
 * this function does not skip 0s in the input).
 */
int mbedtls_mpi_core_read_be( mbedtls_mpi_uint *X,
                              size_t nx,
                              const unsigned char *buf,
                              size_t buflen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t const limbs = CHARS_TO_LIMBS( buflen );
    size_t overhead;
    unsigned char *Xp;

    MPI_VALIDATE_RET( X != NULL );
    MPI_VALIDATE_RET( buflen == 0 || buf != NULL );

    /* Ensure that target MPI has at least the necessary number of limbs */
    MBEDTLS_MPI_CHK( mpi_core_clear( X, nx, limbs ) );

    overhead = ( nx * ciL ) - buflen;

    /* Avoid calling `memcpy` with NULL source or destination argument,
     * even if buflen is 0. */
    if( buflen != 0 )
    {
        Xp = (unsigned char*) X;
        memcpy( Xp + overhead, buf, buflen );

        mbedtls_mpi_core_bigendian_to_host( X, nx );
    }

cleanup:
    return( ret );
}

/*
 * Export X into unsigned binary data, little endian
 */
int mbedtls_mpi_core_write_le( const mbedtls_mpi_uint *X,
                               size_t nx,
                               unsigned char *buf,
                               size_t buflen )
{
    size_t stored_bytes = nx * ciL;
    size_t bytes_to_copy;
    size_t i;

    if( stored_bytes < buflen )
    {
        bytes_to_copy = stored_bytes;
    }
    else
    {
        bytes_to_copy = buflen;

        /* The output buffer is smaller than the allocated size of X.
         * However X may fit if its leading bytes are zero. */
        for( i = bytes_to_copy; i < stored_bytes; i++ )
        {
            if( GET_BYTE( X, i ) != 0 )
                return( MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL );
        }
    }

    for( i = 0; i < bytes_to_copy; i++ )
        buf[i] = GET_BYTE( X, i );

    if( stored_bytes < buflen )
    {
        /* Write trailing 0 bytes */
        memset( buf + stored_bytes, 0, buflen - stored_bytes );
    }

    return( 0 );
}

/*
 * Export X into unsigned binary data, big endian
 */
int mbedtls_mpi_core_write_be( const mbedtls_mpi_uint *X,
                               size_t nx,
                               unsigned char *buf,
                               size_t buflen )
{
    size_t stored_bytes;
    size_t bytes_to_copy;
    unsigned char *p;
    size_t i;

    MPI_VALIDATE_RET( X != NULL );
    MPI_VALIDATE_RET( buflen == 0 || buf != NULL );

    stored_bytes = nx * ciL;

    if( stored_bytes < buflen )
    {
        /* There is enough space in the output buffer. Write initial
         * null bytes and record the position at which to start
         * writing the significant bytes. In this case, the execution
         * trace of this function does not depend on the value of the
         * number. */
        bytes_to_copy = stored_bytes;
        p = buf + buflen - stored_bytes;
        memset( buf, 0, buflen - stored_bytes );
    }
    else
    {
        /* The output buffer is smaller than the allocated size of X.
         * However X may fit if its leading bytes are zero. */
        bytes_to_copy = buflen;
        p = buf;
        for( i = bytes_to_copy; i < stored_bytes; i++ )
        {
            if( GET_BYTE( X, i ) != 0 )
                return( MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL );
        }
    }

    for( i = 0; i < bytes_to_copy; i++ )
        p[bytes_to_copy - i - 1] = GET_BYTE( X, i );

    return( 0 );
}

int mbedtls_mpi_mod_raw_read( mbedtls_mpi_uint *X,
                              mbedtls_mpi_mod_modulus *m,
                              unsigned char *buf,
                              size_t buflen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if( m->ext_rep == MBEDTLS_MPI_MOD_EXT_REP_LE )
        ret = mbedtls_mpi_core_read_le( X, m->n, buf, buflen );

    else if( m->ext_rep == MBEDTLS_MPI_MOD_EXT_REP_BE )
        ret = mbedtls_mpi_core_read_be( X, m->n, buf, buflen );
    else
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    if( ret != 0 )
        goto cleanup;

    if( !mbedtls_mpi_core_lt_ct( X, m->p, m->n ) )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

cleanup:

    return( ret );
}

int mbedtls_mpi_mod_raw_write( mbedtls_mpi_uint *X,
                               mbedtls_mpi_mod_modulus *m,
                               unsigned char *buf,
                               size_t buflen )
{
    if( m->ext_rep == MBEDTLS_MPI_MOD_EXT_REP_LE )
        return mbedtls_mpi_core_write_le( X, m->n, buf, buflen );

    else if( m->ext_rep == MBEDTLS_MPI_MOD_EXT_REP_BE )
        return mbedtls_mpi_core_write_be( X, m->n, buf, buflen );

    else
        return( MBEDTLS_ERR_MPI_BAD_INPUT_DATA );

    return( 0 );
}

#endif /* MBEDTLS_BIGNUM_C */
