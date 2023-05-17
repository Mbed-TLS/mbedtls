/**
 *  Constant-time functions
 *
 *  For readability, the static inline definitions are here, and
 *  constant_time_internal.h has only the declarations.
 *
 *  This results in duplicate declarations of the form:
 *      static inline void f() { ... }
 *      static inline void f();
 *  when constant_time_internal.h is included. This appears to behave
 *  exactly as if the declaration-without-definition was not present.
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

#ifndef MBEDTLS_CONSTANT_TIME_IMPL_H
#define MBEDTLS_CONSTANT_TIME_IMPL_H

#include <stddef.h>

#include "common.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif


/* Disable asm under Memsan because it confuses Memsan and generates false errors */
#if defined(MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN)
#define MBEDTLS_CT_NO_ASM
#elif defined(__has_feature)
#if __has_feature(memory_sanitizer)
#define MBEDTLS_CT_NO_ASM
#endif
#endif

/* armcc5 --gnu defines __GNUC__ but doesn't support GNU's extended asm */
#if defined(MBEDTLS_HAVE_ASM) && defined(__GNUC__) && (!defined(__ARMCC_VERSION) || \
    __ARMCC_VERSION >= 6000000) && !defined(MBEDTLS_CT_NO_ASM)
#define MBEDTLS_CT_ASM
#if (defined(__arm__) || defined(__thumb__) || defined(__thumb2__))
#define MBEDTLS_CT_ARM_ASM
#elif defined(__aarch64__)
#define MBEDTLS_CT_AARCH64_ASM
#endif
#endif

#define MBEDTLS_CT_SIZE (sizeof(mbedtls_ct_uint_t) * 8)


/* ============================================================================
 * Core const-time primitives
 */

/** Ensure that the compiler cannot know the value of x (i.e., cannot optimise
 * based on its value) after this function is called.
 *
 * If we are not using assembly, this will be fairly inefficient, so its use
 * should be minimised.
 */
static inline mbedtls_ct_uint_t mbedtls_ct_compiler_opaque(mbedtls_ct_uint_t x)
{
#if defined(MBEDTLS_CT_ASM)
    asm volatile ("" : [x] "+r" (x) :);
    return x;
#else
    volatile mbedtls_ct_uint_t result = x;
    return result;
#endif
}

/* Convert a number into a condition in constant time. */
static inline mbedtls_ct_condition_t mbedtls_ct_bool(mbedtls_ct_uint_t x)
{
    /*
     * Define mask-generation code that, as far as possible, will not use branches or conditional instructions.
     *
     * For some platforms / type sizes, we define assembly to assure this.
     *
     * Otherwise, we define a plain C fallback which (in May 2023) does not get optimised into
     * conditional instructions or branches by trunk clang, gcc, or MSVC v19.
     */
    const mbedtls_ct_uint_t xo = mbedtls_ct_compiler_opaque(x);
#if defined(_MSC_VER)
    /* MSVC has a warning about unary minus on unsigned, but this is
     * well-defined and precisely what we want to do here */
#pragma warning( push )
#pragma warning( disable : 4146 )
#endif
    return (mbedtls_ct_condition_t) (((mbedtls_ct_int_t) ((-xo) | -(xo >> 1))) >>
                                     (MBEDTLS_CT_SIZE - 1));
#if defined(_MSC_VER)
#pragma warning( pop )
#endif
}

static inline mbedtls_ct_uint_t mbedtls_ct_if(mbedtls_ct_condition_t condition,
                                              mbedtls_ct_uint_t if1,
                                              mbedtls_ct_uint_t if0)
{
    mbedtls_ct_condition_t not_mask =
        (mbedtls_ct_condition_t) (~mbedtls_ct_compiler_opaque(condition));
    mbedtls_ct_condition_t mask     =
        (mbedtls_ct_condition_t)   mbedtls_ct_compiler_opaque(condition);
    return (mbedtls_ct_uint_t) ((mask & if1) | (not_mask & if0));
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_lt(mbedtls_ct_uint_t x, mbedtls_ct_uint_t y)
{
    /* Ensure that the compiler cannot optimise the following operations over x and y,
     * even if it knows the value of x and y.
     */
    const mbedtls_ct_uint_t xo = mbedtls_ct_compiler_opaque(x);
    const mbedtls_ct_uint_t yo = mbedtls_ct_compiler_opaque(y);
    /*
     * Check if the most significant bits (MSB) of the operands are different.
     * cond is true iff the MSBs differ.
     */
    mbedtls_ct_condition_t cond = mbedtls_ct_bool((xo ^ yo) >> (MBEDTLS_CT_SIZE - 1));

    /*
     * If the MSB are the same then the difference x-y will be negative (and
     * have its MSB set to 1 during conversion to unsigned) if and only if x<y.
     *
     * If the MSB are different, then the operand with the MSB of 1 is the
     * bigger. (That is if y has MSB of 1, then x<y is true and it is false if
     * the MSB of y is 0.)
     */

    // Select either y, or x - y
    mbedtls_ct_uint_t ret = mbedtls_ct_if(cond, yo, (mbedtls_ct_uint_t) (xo - yo));

    // Extract only the MSB of ret
    ret = ret >> (MBEDTLS_CT_SIZE - 1);

    // Convert to a condition (i.e., all bits set iff non-zero)
    return mbedtls_ct_bool(ret);
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_ne(mbedtls_ct_uint_t x, mbedtls_ct_uint_t y)
{
    /* diff = 0 if x == y, non-zero otherwise */
    const mbedtls_ct_uint_t diff = mbedtls_ct_compiler_opaque(x) ^ y;

    /* all ones if x != y, 0 otherwise */
    return mbedtls_ct_bool(diff);
}

static inline unsigned char mbedtls_ct_uchar_in_range_if(unsigned char low,
                                                         unsigned char high,
                                                         unsigned char c,
                                                         unsigned char t)
{
    const unsigned char co = (const unsigned char) mbedtls_ct_compiler_opaque(c);
    const unsigned char to = (const unsigned char) mbedtls_ct_compiler_opaque(t);

    /* low_mask is: 0 if low <= c, 0x...ff if low > c */
    unsigned low_mask = ((unsigned) co - low) >> 8;
    /* high_mask is: 0 if c <= high, 0x...ff if c > high */
    unsigned high_mask = ((unsigned) high - co) >> 8;

    return (unsigned char) (~(low_mask | high_mask)) & to;
}


/* ============================================================================
 * Everything below here is trivial wrapper functions
 */

static inline mbedtls_ct_condition_t mbedtls_ct_bool_eq(mbedtls_ct_uint_t x,
                                                        mbedtls_ct_uint_t y)
{
    return ~mbedtls_ct_bool_ne(x, y);
}

static inline size_t mbedtls_ct_size_if(mbedtls_ct_condition_t condition,
                                        size_t if1,
                                        size_t if0)
{
    return (size_t) mbedtls_ct_if(condition, (mbedtls_ct_uint_t) if1, (mbedtls_ct_uint_t) if0);
}

static inline unsigned mbedtls_ct_uint_if_new(mbedtls_ct_condition_t condition,
                                          unsigned if1,
                                          unsigned if0)
{
    return (unsigned) mbedtls_ct_if(condition, (mbedtls_ct_uint_t) if1, (mbedtls_ct_uint_t) if0);
}

#if defined(MBEDTLS_BIGNUM_C)

static inline mbedtls_mpi_uint mbedtls_ct_mpi_uint_if(mbedtls_ct_condition_t condition, \
                                                      mbedtls_mpi_uint if1, \
                                                      mbedtls_mpi_uint if0)
{
    return (mbedtls_mpi_uint) mbedtls_ct_if(condition,
                                            (mbedtls_ct_uint_t) if1,
                                            (mbedtls_ct_uint_t) if0);
}

#endif

static inline size_t mbedtls_ct_size_if0(mbedtls_ct_condition_t condition, size_t if1)
{
    return (size_t) (mbedtls_ct_compiler_opaque(condition) & if1);
}

static inline unsigned mbedtls_ct_uint_if0(mbedtls_ct_condition_t condition, unsigned if1)
{
    return (unsigned) (mbedtls_ct_compiler_opaque(condition) & if1);
}

#if defined(MBEDTLS_BIGNUM_C)

static inline mbedtls_mpi_uint mbedtls_ct_mpi_uint_if0(mbedtls_ct_condition_t condition,
                                                       mbedtls_mpi_uint if1)
{
    return (mbedtls_mpi_uint) (mbedtls_ct_compiler_opaque(condition) & if1);
}

#endif /* MBEDTLS_BIGNUM_C */

static inline mbedtls_ct_condition_t mbedtls_ct_bool_gt(mbedtls_ct_uint_t x,
                                                        mbedtls_ct_uint_t y)
{
    return mbedtls_ct_bool_lt(y, x);
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_ge(mbedtls_ct_uint_t x,
                                                        mbedtls_ct_uint_t y)
{
    return ~mbedtls_ct_bool_lt(x, y);
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_le(mbedtls_ct_uint_t x,
                                                        mbedtls_ct_uint_t y)
{
    return ~mbedtls_ct_bool_gt(x, y);
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_xor(mbedtls_ct_condition_t x,
                                                         mbedtls_ct_condition_t y)
{
    return (mbedtls_ct_condition_t) (mbedtls_ct_compiler_opaque(x) ^ mbedtls_ct_compiler_opaque(y));
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_and(mbedtls_ct_condition_t x,
                                                         mbedtls_ct_condition_t y)
{
    return (mbedtls_ct_condition_t) (mbedtls_ct_compiler_opaque(x) & mbedtls_ct_compiler_opaque(y));
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_or(mbedtls_ct_condition_t x,
                                                        mbedtls_ct_condition_t y)
{
    return (mbedtls_ct_condition_t) (mbedtls_ct_compiler_opaque(x) | mbedtls_ct_compiler_opaque(y));
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_not(mbedtls_ct_condition_t x)
{
    return (mbedtls_ct_condition_t) (~mbedtls_ct_compiler_opaque(x));
}

#endif /* MBEDTLS_CONSTANT_TIME_IMPL_H */
