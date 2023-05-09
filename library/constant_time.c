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

/*
 * The following functions are implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 */

#include "common.h"
#include "constant_time_internal.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#include "bignum_core.h"
#endif

#if defined(MBEDTLS_SSL_TLS_C)
#include "ssl_misc.h"
#endif

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif

#if defined(MBEDTLS_BASE64_C)
#include "constant_time_invasive.h"
#endif

#include <string.h>
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#define PSA_TO_MBEDTLS_ERR(status) PSA_TO_MBEDTLS_ERR_LIST(status,    \
                                                           psa_to_ssl_errors,              \
                                                           psa_generic_status_to_mbedtls)
#endif

/*
 * Define MBEDTLS_EFFICIENT_UNALIGNED_VOLATILE_ACCESS where assembly is present to
 * perform fast unaligned access to volatile data.
 *
 * This is needed because mbedtls_get_unaligned_uintXX etc don't support volatile
 * memory accesses.
 *
 * Some of these definitions could be moved into alignment.h but for now they are
 * only used here.
 */
#if defined(MBEDTLS_EFFICIENT_UNALIGNED_ACCESS) && defined(MBEDTLS_HAVE_ASM)
#if defined(__arm__) || defined(__thumb__) || defined(__thumb2__) || defined(__aarch64__)
#define MBEDTLS_EFFICIENT_UNALIGNED_VOLATILE_ACCESS
#endif
#endif

#if defined(MBEDTLS_EFFICIENT_UNALIGNED_VOLATILE_ACCESS)
static inline uint32_t mbedtls_get_unaligned_volatile_uint32(volatile const unsigned char *p)
{
    /* This is UB, even where it's safe:
     *    return *((volatile uint32_t*)p);
     * so instead the same thing is expressed in assembly below.
     */
    uint32_t r;
#if defined(__arm__) || defined(__thumb__) || defined(__thumb2__)
    asm volatile ("ldr %0, [%1]" : "=r" (r) : "r" (p) :);
#elif defined(__aarch64__)
    asm volatile ("ldr %w0, [%1]" : "=r" (r) : "r" (p) :);
#endif
    return r;
}
#endif /* MBEDTLS_EFFICIENT_UNALIGNED_VOLATILE_ACCESS */

int mbedtls_ct_memcmp(const void *a,
                      const void *b,
                      size_t n)
{
    size_t i = 0;
    /*
     * `A` and `B` are cast to volatile to ensure that the compiler
     * generates code that always fully reads both buffers.
     * Otherwise it could generate a test to exit early if `diff` has all
     * bits set early in the loop.
     */
    volatile const unsigned char *A = (volatile const unsigned char *) a;
    volatile const unsigned char *B = (volatile const unsigned char *) b;
    uint32_t diff = 0;

#if defined(MBEDTLS_EFFICIENT_UNALIGNED_VOLATILE_ACCESS)
    for (; (i + 4) <= n; i += 4) {
        uint32_t x = mbedtls_get_unaligned_volatile_uint32(A + i);
        uint32_t y = mbedtls_get_unaligned_volatile_uint32(B + i);
        diff |= x ^ y;
    }
#endif

    for (; i < n; i++) {
        /* Read volatile data in order before computing diff.
         * This avoids IAR compiler warning:
         * 'the order of volatile accesses is undefined ..' */
        unsigned char x = A[i], y = B[i];
        diff |= x ^ y;
    }

    return (int) diff;
}

unsigned mbedtls_ct_uint_mask(unsigned value)
{
    /* MSVC has a warning about unary minus on unsigned, but this is
     * well-defined and precisely what we want to do here */
#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4146 )
#endif
    return -((value | -value) >> (sizeof(value) * 8 - 1));
#if defined(_MSC_VER)
#pragma warning( pop )
#endif
}

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)

size_t mbedtls_ct_size_mask(size_t value)
{
    /* MSVC has a warning about unary minus on unsigned integer types,
     * but this is well-defined and precisely what we want to do here. */
#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4146 )
#endif
    return -((value | -value) >> (sizeof(value) * 8 - 1));
#if defined(_MSC_VER)
#pragma warning( pop )
#endif
}

#endif /* MBEDTLS_SSL_SOME_SUITES_USE_MAC */

#if defined(MBEDTLS_BIGNUM_C)

mbedtls_mpi_uint mbedtls_ct_mpi_uint_mask(mbedtls_mpi_uint value)
{
    /* MSVC has a warning about unary minus on unsigned, but this is
     * well-defined and precisely what we want to do here */
#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4146 )
#endif
    return -((value | -value) >> (sizeof(value) * 8 - 1));
#if defined(_MSC_VER)
#pragma warning( pop )
#endif
}

#endif /* MBEDTLS_BIGNUM_C */

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_TLS_CBC)

/** Constant-flow mask generation for "less than" comparison:
 * - if \p x < \p y, return all-bits 1, that is (size_t) -1
 * - otherwise, return all bits 0, that is 0
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations using masks.
 *
 * \param x     The first value to analyze.
 * \param y     The second value to analyze.
 *
 * \return      All-bits-one if \p x is less than \p y, otherwise zero.
 */
static size_t mbedtls_ct_size_mask_lt(size_t x,
                                      size_t y)
{
    /* This has the most significant bit set if and only if x < y */
    const size_t sub = x - y;

    /* sub1 = (x < y) ? 1 : 0 */
    const size_t sub1 = sub >> (sizeof(sub) * 8 - 1);

    /* mask = (x < y) ? 0xff... : 0x00... */
    const size_t mask = mbedtls_ct_size_mask(sub1);

    return mask;
}

size_t mbedtls_ct_size_mask_ge(size_t x,
                               size_t y)
{
    return ~mbedtls_ct_size_mask_lt(x, y);
}

#endif /* MBEDTLS_SSL_SOME_SUITES_USE_TLS_CBC */

#if defined(MBEDTLS_BASE64_C)

/* Return 0xff if low <= c <= high, 0 otherwise.
 *
 * Constant flow with respect to c.
 */
unsigned char mbedtls_ct_uchar_mask_of_range(unsigned char low,
                                             unsigned char high,
                                             unsigned char c)
{
    /* low_mask is: 0 if low <= c, 0x...ff if low > c */
    unsigned low_mask = ((unsigned) c - low) >> 8;
    /* high_mask is: 0 if c <= high, 0x...ff if c > high */
    unsigned high_mask = ((unsigned) high - c) >> 8;
    return ~(low_mask | high_mask) & 0xff;
}

#endif /* MBEDTLS_BASE64_C */

unsigned mbedtls_ct_size_bool_eq(size_t x,
                                 size_t y)
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
    const size_t diff_msb = (diff | (size_t) -diff);

#if defined(_MSC_VER)
#pragma warning( pop )
#endif

    /* diff1 = (x != y) ? 1 : 0 */
    const unsigned diff1 = diff_msb >> (sizeof(diff_msb) * 8 - 1);

    return 1 ^ diff1;
}

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && !defined(MBEDTLS_RSA_ALT)

unsigned mbedtls_ct_size_gt(size_t x, size_t y)
{
    /* Return the sign bit (1 for negative) of (y - x). */
    return (y - x) >> (sizeof(size_t) * 8 - 1);
}

#endif /* MBEDTLS_PKCS1_V15 && MBEDTLS_RSA_C && ! MBEDTLS_RSA_ALT */

#if defined(MBEDTLS_BIGNUM_C)

unsigned mbedtls_ct_mpi_uint_lt(const mbedtls_mpi_uint x,
                                const mbedtls_mpi_uint y)
{
    mbedtls_mpi_uint ret;
    mbedtls_mpi_uint cond;

    /*
     * Check if the most significant bits (MSB) of the operands are different.
     */
    cond = (x ^ y);
    /*
     * If the MSB are the same then the difference x-y will be negative (and
     * have its MSB set to 1 during conversion to unsigned) if and only if x<y.
     */
    ret = (x - y) & ~cond;
    /*
     * If the MSB are different, then the operand with the MSB of 1 is the
     * bigger. (That is if y has MSB of 1, then x<y is true and it is false if
     * the MSB of y is 0.)
     */
    ret |= y & cond;


    ret = ret >> (sizeof(mbedtls_mpi_uint) * 8 - 1);

    return (unsigned) ret;
}

#endif /* MBEDTLS_BIGNUM_C */

unsigned mbedtls_ct_uint_if(unsigned condition,
                            unsigned if1,
                            unsigned if0)
{
    unsigned mask = mbedtls_ct_uint_mask(condition);
    return (mask & if1) | (~mask & if0);
}

#if defined(MBEDTLS_BIGNUM_C)

void mbedtls_ct_mpi_uint_cond_assign(size_t n,
                                     mbedtls_mpi_uint *dest,
                                     const mbedtls_mpi_uint *src,
                                     unsigned char condition)
{
    size_t i;

    /* MSVC has a warning about unary minus on unsigned integer types,
     * but this is well-defined and precisely what we want to do here. */
#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4146 )
#endif

    /* all-bits 1 if condition is 1, all-bits 0 if condition is 0 */
    const mbedtls_mpi_uint mask = -condition;

#if defined(_MSC_VER)
#pragma warning( pop )
#endif

    for (i = 0; i < n; i++) {
        dest[i] = (src[i] & mask) | (dest[i] & ~mask);
    }
}

#endif /* MBEDTLS_BIGNUM_C */

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && !defined(MBEDTLS_RSA_ALT)

void mbedtls_ct_mem_move_to_left(void *start,
                                 size_t total,
                                 size_t offset)
{
    volatile unsigned char *buf = start;
    size_t i, n;
    if (total == 0) {
        return;
    }
    for (i = 0; i < total; i++) {
        unsigned no_op = mbedtls_ct_size_gt(total - offset, i);
        /* The first `total - offset` passes are a no-op. The last
         * `offset` passes shift the data one byte to the left and
         * zero out the last byte. */
        for (n = 0; n < total - 1; n++) {
            unsigned char current = buf[n];
            unsigned char next = buf[n+1];
            buf[n] = mbedtls_ct_uint_if(no_op, current, next);
        }
        buf[total-1] = mbedtls_ct_uint_if(no_op, buf[total-1], 0);
    }
}

#endif /* MBEDTLS_PKCS1_V15 && MBEDTLS_RSA_C && ! MBEDTLS_RSA_ALT */

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)

void mbedtls_ct_memcpy_if_eq(unsigned char *dest,
                             const unsigned char *src,
                             size_t len,
                             size_t c1,
                             size_t c2)
{
    /* mask = c1 == c2 ? 0xff : 0x00 */
    const size_t equal = mbedtls_ct_size_bool_eq(c1, c2);

    /* dest[i] = c1 == c2 ? src[i] : dest[i] */
    size_t i = 0;
#if defined(MBEDTLS_EFFICIENT_UNALIGNED_ACCESS)
    const uint32_t mask32 = (uint32_t) mbedtls_ct_size_mask(equal);
    const unsigned char mask = (unsigned char) mask32 & 0xff;

    for (; (i + 4) <= len; i += 4) {
        uint32_t a = mbedtls_get_unaligned_uint32(src  + i) &  mask32;
        uint32_t b = mbedtls_get_unaligned_uint32(dest + i) & ~mask32;
        mbedtls_put_unaligned_uint32(dest + i, a | b);
    }
#else
    const unsigned char mask = (unsigned char) mbedtls_ct_size_mask(equal);
#endif /* MBEDTLS_EFFICIENT_UNALIGNED_ACCESS */
    for (; i < len; i++) {
        dest[i] = (src[i] & mask) | (dest[i] & ~mask);
    }
}

void mbedtls_ct_memcpy_offset(unsigned char *dest,
                              const unsigned char *src,
                              size_t offset,
                              size_t offset_min,
                              size_t offset_max,
                              size_t len)
{
    size_t offsetval;

    for (offsetval = offset_min; offsetval <= offset_max; offsetval++) {
        mbedtls_ct_memcpy_if_eq(dest, src + offsetval, len,
                                offsetval, offset);
    }
}

#endif /* MBEDTLS_SSL_SOME_SUITES_USE_MAC */

