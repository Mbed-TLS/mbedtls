/**
 *  Constant-time functions
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
#include "constant_time.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

#if defined(MBEDTLS_SSL_TLS_C)
#include "ssl_misc.h"
#endif


/* constant-time buffer comparison */
int mbedtls_ssl_safer_memcmp( const void *a, const void *b, size_t n )
{
    size_t i;
    volatile const unsigned char *A = (volatile const unsigned char *) a;
    volatile const unsigned char *B = (volatile const unsigned char *) b;
    volatile unsigned char diff = 0;

    for( i = 0; i < n; i++ )
    {
        /* Read volatile data in order before computing diff.
         * This avoids IAR compiler warning:
         * 'the order of volatile accesses is undefined ..' */
        unsigned char x = A[i], y = B[i];
        diff |= x ^ y;
    }

    return( diff );
}

/* Compare the contents of two buffers in constant time.
 * Returns 0 if the contents are bitwise identical, otherwise returns
 * a non-zero value.
 * This is currently only used by GCM and ChaCha20+Poly1305.
 */
int mbedtls_constant_time_memcmp( const void *v1, const void *v2,
                                  size_t len )
{
    const unsigned char *p1 = (const unsigned char*) v1;
    const unsigned char *p2 = (const unsigned char*) v2;
    size_t i;
    unsigned char diff;

    for( diff = 0, i = 0; i < len; i++ )
        diff |= p1[i] ^ p2[i];

    return( (int)diff );
}

/* constant-time buffer comparison */
unsigned char mbedtls_nist_kw_safer_memcmp( const void *a, const void *b, size_t n )
{
    size_t i;
    volatile const unsigned char *A = (volatile const unsigned char *) a;
    volatile const unsigned char *B = (volatile const unsigned char *) b;
    volatile unsigned char diff = 0;

    for( i = 0; i < n; i++ )
    {
        /* Read volatile data in order before computing diff.
         * This avoids IAR compiler warning:
         * 'the order of volatile accesses is undefined ..' */
        unsigned char x = A[i], y = B[i];
        diff |= x ^ y;
    }

    return( diff );
}

/* constant-time buffer comparison */
int mbedtls_safer_memcmp( const void *a, const void *b, size_t n )
{
    size_t i;
    const unsigned char *A = (const unsigned char *) a;
    const unsigned char *B = (const unsigned char *) b;
    unsigned char diff = 0;

    for( i = 0; i < n; i++ )
        diff |= A[i] ^ B[i];

    return( diff );
}

/** Turn zero-or-nonzero into zero-or-all-bits-one, without branches.
 *
 * \param value     The value to analyze.
 * \return          Zero if \p value is zero, otherwise all-bits-one.
 */
unsigned mbedtls_cf_uint_mask( unsigned value )
{
    /* MSVC has a warning about unary minus on unsigned, but this is
     * well-defined and precisely what we want to do here */
#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4146 )
#endif
    return( - ( ( value | - value ) >> ( sizeof( value ) * 8 - 1 ) ) );
#if defined(_MSC_VER)
#pragma warning( pop )
#endif
}

/*
 * Turn a bit into a mask:
 * - if bit == 1, return the all-bits 1 mask, aka (size_t) -1
 * - if bit == 0, return the all-bits 0 mask, aka 0
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations using masks.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 */
size_t mbedtls_cf_size_mask( size_t bit )
{
    /* MSVC has a warning about unary minus on unsigned integer types,
     * but this is well-defined and precisely what we want to do here. */
#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4146 )
#endif
    return -bit;
#if defined(_MSC_VER)
#pragma warning( pop )
#endif
}

/*
 * Constant-flow mask generation for "less than" comparison:
 * - if x < y,  return all bits 1, that is (size_t) -1
 * - otherwise, return all bits 0, that is 0
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations using masks.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 */
size_t mbedtls_cf_size_mask_lt( size_t x, size_t y )
{
    /* This has the most significant bit set if and only if x < y */
    const size_t sub = x - y;

    /* sub1 = (x < y) ? 1 : 0 */
    const size_t sub1 = sub >> ( sizeof( sub ) * 8 - 1 );

    /* mask = (x < y) ? 0xff... : 0x00... */
    const size_t mask = mbedtls_cf_size_mask( sub1 );

    return( mask );
}

/*
 * Constant-flow mask generation for "greater or equal" comparison:
 * - if x >= y, return all bits 1, that is (size_t) -1
 * - otherwise, return all bits 0, that is 0
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations using masks.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 */
size_t mbedtls_cf_size_mask_ge( size_t x, size_t y )
{
    return( ~mbedtls_cf_size_mask_lt( x, y ) );
}

/*
 * Constant-flow boolean "equal" comparison:
 * return x == y
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations - it can be used in conjunction with
 * mbedtls_ssl_cf_mask_from_bit().
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 */
size_t mbedtls_cf_size_bool_eq( size_t x, size_t y )
{
    /* diff = 0 if x == y, non-zero otherwise */
    const size_t diff = x ^ y;

    /* MSVC has a warning about unary minus on unsigned integer types,
     * but this is well-defined and precisely what we want to do here. */
#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4146 )
#endif

    /* diff_msb's most significant bit is equal to x != y */
    const size_t diff_msb = ( diff | (size_t) -diff );

#if defined(_MSC_VER)
#pragma warning( pop )
#endif

    /* diff1 = (x != y) ? 1 : 0 */
    const size_t diff1 = diff_msb >> ( sizeof( diff_msb ) * 8 - 1 );

    return( 1 ^ diff1 );
}

/** Check whether a size is out of bounds, without branches.
 *
 * This is equivalent to `size > max`, but is likely to be compiled to
 * to code using bitwise operation rather than a branch.
 *
 * \param size      Size to check.
 * \param max       Maximum desired value for \p size.
 * \return          \c 0 if `size <= max`.
 * \return          \c 1 if `size > max`.
 */
unsigned mbedtls_cf_size_gt( size_t size, size_t max )
{
    /* Return the sign bit (1 for negative) of (max - size). */
    return( ( max - size ) >> ( sizeof( size_t ) * 8 - 1 ) );
}

#if defined(MBEDTLS_BIGNUM_C)

/** Decide if an integer is less than the other, without branches.
 *
 * \param x         First integer.
 * \param y         Second integer.
 *
 * \return          1 if \p x is less than \p y, 0 otherwise
 */
unsigned mbedtls_cf_mpi_uint_lt( const mbedtls_mpi_uint x,
        const mbedtls_mpi_uint y )
{
    mbedtls_mpi_uint ret;
    mbedtls_mpi_uint cond;

    /*
     * Check if the most significant bits (MSB) of the operands are different.
     */
    cond = ( x ^ y );
    /*
     * If the MSB are the same then the difference x-y will be negative (and
     * have its MSB set to 1 during conversion to unsigned) if and only if x<y.
     */
    ret = ( x - y ) & ~cond;
    /*
     * If the MSB are different, then the operand with the MSB of 1 is the
     * bigger. (That is if y has MSB of 1, then x<y is true and it is false if
     * the MSB of y is 0.)
     */
    ret |= y & cond;


    ret = ret >> ( sizeof( mbedtls_mpi_uint ) * 8 - 1 );

    return (unsigned) ret;
}

#endif /* MBEDTLS_BIGNUM_C */

/** Choose between two integer values, without branches.
 *
 * This is equivalent to `cond ? if1 : if0`, but is likely to be compiled
 * to code using bitwise operation rather than a branch.
 *
 * \param cond      Condition to test.
 * \param if1       Value to use if \p cond is nonzero.
 * \param if0       Value to use if \p cond is zero.
 * \return          \c if1 if \p cond is nonzero, otherwise \c if0.
 */
unsigned mbedtls_cf_uint_if( unsigned cond, unsigned if1, unsigned if0 )
{
    unsigned mask = mbedtls_cf_uint_mask( cond );
    return( ( mask & if1 ) | (~mask & if0 ) );
}

/**
 * Select between two sign values in constant-time.
 *
 * This is functionally equivalent to second ? a : b but uses only bit
 * operations in order to avoid branches.
 *
 * \param[in] a         The first sign; must be either +1 or -1.
 * \param[in] b         The second sign; must be either +1 or -1.
 * \param[in] second    Must be either 1 (return b) or 0 (return a).
 *
 * \return The selected sign value.
 */
int mbedtls_cf_cond_select_sign( int a, int b, unsigned char second )
{
    /* In order to avoid questions about what we can reasonnably assume about
     * the representations of signed integers, move everything to unsigned
     * by taking advantage of the fact that a and b are either +1 or -1. */
    unsigned ua = a + 1;
    unsigned ub = b + 1;

    /* second was 0 or 1, mask is 0 or 2 as are ua and ub */
    const unsigned mask = second << 1;

    /* select ua or ub */
    unsigned ur = ( ua & ~mask ) | ( ub & mask );

    /* ur is now 0 or 2, convert back to -1 or +1 */
    return( (int) ur - 1 );
}

#if defined(MBEDTLS_BIGNUM_C)

/*
 * Conditionally assign dest = src, without leaking information
 * about whether the assignment was made or not.
 * dest and src must be arrays of limbs of size n.
 * assign must be 0 or 1.
 */
void mbedtls_cf_mpi_uint_cond_assign( size_t n,
                                      mbedtls_mpi_uint *dest,
                                      const mbedtls_mpi_uint *src,
                                      unsigned char assign )
{
    size_t i;

    /* MSVC has a warning about unary minus on unsigned integer types,
     * but this is well-defined and precisely what we want to do here. */
#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4146 )
#endif

    /* all-bits 1 if assign is 1, all-bits 0 if assign is 0 */
    const mbedtls_mpi_uint mask = -assign;

#if defined(_MSC_VER)
#pragma warning( pop )
#endif

    for( i = 0; i < n; i++ )
        dest[i] = ( src[i] & mask ) | ( dest[i] & ~mask );
}

#endif /* MBEDTLS_BIGNUM_C */

/** Shift some data towards the left inside a buffer without leaking
 * the length of the data through side channels.
 *
 * `mbedtls_cf_mem_move_to_left(start, total, offset)` is functionally
 * equivalent to
 * ```
 * memmove(start, start + offset, total - offset);
 * memset(start + offset, 0, total - offset);
 * ```
 * but it strives to use a memory access pattern (and thus total timing)
 * that does not depend on \p offset. This timing independence comes at
 * the expense of performance.
 *
 * \param start     Pointer to the start of the buffer.
 * \param total     Total size of the buffer.
 * \param offset    Offset from which to copy \p total - \p offset bytes.
 */
void mbedtls_cf_mem_move_to_left( void *start,
                                         size_t total,
                                         size_t offset )
{
    volatile unsigned char *buf = start;
    size_t i, n;
    if( total == 0 )
        return;
    for( i = 0; i < total; i++ )
    {
        unsigned no_op = mbedtls_cf_size_gt( total - offset, i );
        /* The first `total - offset` passes are a no-op. The last
         * `offset` passes shift the data one byte to the left and
         * zero out the last byte. */
        for( n = 0; n < total - 1; n++ )
        {
            unsigned char current = buf[n];
            unsigned char next = buf[n+1];
            buf[n] = mbedtls_cf_uint_if( no_op, current, next );
        }
        buf[total-1] = mbedtls_cf_uint_if( no_op, buf[total-1], 0 );
    }
}

/*
 * Constant-flow conditional memcpy:
 *  - if c1 == c2, equivalent to memcpy(dst, src, len),
 *  - otherwise, a no-op,
 * but with execution flow independent of the values of c1 and c2.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 */
void mbedtls_cf_memcpy_if_eq( unsigned char *dst,
                                     const unsigned char *src,
                                     size_t len,
                                     size_t c1, size_t c2 )
{
    /* mask = c1 == c2 ? 0xff : 0x00 */
    const size_t equal = mbedtls_cf_size_bool_eq( c1, c2 );
    const unsigned char mask = (unsigned char) mbedtls_cf_size_mask( equal );

    /* dst[i] = c1 == c2 ? src[i] : dst[i] */
    for( size_t i = 0; i < len; i++ )
        dst[i] = ( src[i] & mask ) | ( dst[i] & ~mask );
}

/*
 * Constant-flow memcpy from variable position in buffer.
 * - functionally equivalent to memcpy(dst, src + offset_secret, len)
 * - but with execution flow independent from the value of offset_secret.
 */
void mbedtls_cf_memcpy_offset(
                                   unsigned char *dst,
                                   const unsigned char *src_base,
                                   size_t offset_secret,
                                   size_t offset_min, size_t offset_max,
                                   size_t len )
{
    size_t offset;

    for( offset = offset_min; offset <= offset_max; offset++ )
    {
        mbedtls_cf_memcpy_if_eq( dst, src_base + offset, len,
                                 offset, offset_secret );
    }
}

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_TLS_CBC)

/*
 * Compute HMAC of variable-length data with constant flow.
 *
 * Only works with MD-5, SHA-1, SHA-256 and SHA-384.
 * (Otherwise, computation of block_size needs to be adapted.)
 */
int mbedtls_cf_hmac(
        mbedtls_md_context_t *ctx,
        const unsigned char *add_data, size_t add_data_len,
        const unsigned char *data, size_t data_len_secret,
        size_t min_data_len, size_t max_data_len,
        unsigned char *output )
{
    /*
     * This function breaks the HMAC abstraction and uses the md_clone()
     * extension to the MD API in order to get constant-flow behaviour.
     *
     * HMAC(msg) is defined as HASH(okey + HASH(ikey + msg)) where + means
     * concatenation, and okey/ikey are the XOR of the key with some fixed bit
     * patterns (see RFC 2104, sec. 2), which are stored in ctx->hmac_ctx.
     *
     * We'll first compute inner_hash = HASH(ikey + msg) by hashing up to
     * minlen, then cloning the context, and for each byte up to maxlen
     * finishing up the hash computation, keeping only the correct result.
     *
     * Then we only need to compute HASH(okey + inner_hash) and we're done.
     */
    const mbedtls_md_type_t md_alg = mbedtls_md_get_type( ctx->md_info );
    /* TLS 1.2 only supports SHA-384, SHA-256, SHA-1, MD-5,
     * all of which have the same block size except SHA-384. */
    const size_t block_size = md_alg == MBEDTLS_MD_SHA384 ? 128 : 64;
    const unsigned char * const ikey = ctx->hmac_ctx;
    const unsigned char * const okey = ikey + block_size;
    const size_t hash_size = mbedtls_md_get_size( ctx->md_info );

    unsigned char aux_out[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_context_t aux;
    size_t offset;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_md_init( &aux );

#define MD_CHK( func_call ) \
    do {                    \
        ret = (func_call);  \
        if( ret != 0 )      \
            goto cleanup;   \
    } while( 0 )

    MD_CHK( mbedtls_md_setup( &aux, ctx->md_info, 0 ) );

    /* After hmac_start() of hmac_reset(), ikey has already been hashed,
     * so we can start directly with the message */
    MD_CHK( mbedtls_md_update( ctx, add_data, add_data_len ) );
    MD_CHK( mbedtls_md_update( ctx, data, min_data_len ) );

    /* For each possible length, compute the hash up to that point */
    for( offset = min_data_len; offset <= max_data_len; offset++ )
    {
        MD_CHK( mbedtls_md_clone( &aux, ctx ) );
        MD_CHK( mbedtls_md_finish( &aux, aux_out ) );
        /* Keep only the correct inner_hash in the output buffer */
        mbedtls_cf_memcpy_if_eq( output, aux_out, hash_size,
                                 offset, data_len_secret );

        if( offset < max_data_len )
            MD_CHK( mbedtls_md_update( ctx, data + offset, 1 ) );
    }

    /* The context needs to finish() before it starts() again */
    MD_CHK( mbedtls_md_finish( ctx, aux_out ) );

    /* Now compute HASH(okey + inner_hash) */
    MD_CHK( mbedtls_md_starts( ctx ) );
    MD_CHK( mbedtls_md_update( ctx, okey, block_size ) );
    MD_CHK( mbedtls_md_update( ctx, output, hash_size ) );
    MD_CHK( mbedtls_md_finish( ctx, output ) );

    /* Done, get ready for next time */
    MD_CHK( mbedtls_md_hmac_reset( ctx ) );

#undef MD_CHK

cleanup:
    mbedtls_md_free( &aux );
    return( ret );
}

#endif /* MBEDTLS_SSL_SOME_SUITES_USE_TLS_CBC */
