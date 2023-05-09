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

#ifndef MBEDTLS_CONSTANT_TIME_INTERNAL_H
#define MBEDTLS_CONSTANT_TIME_INTERNAL_H

#include "common.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

#if defined(MBEDTLS_SSL_TLS_C)
#include "ssl_misc.h"
#endif

#include <stddef.h>


/** Turn a value into a mask:
 * - if \p value == 0, return the all-bits 0 mask, aka 0
 * - otherwise, return the all-bits 1 mask, aka (unsigned) -1
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations using masks.
 *
 * \param value     The value to analyze.
 *
 * \return          Zero if \p value is zero, otherwise all-bits-one.
 */
unsigned mbedtls_ct_uint_mask(unsigned value);

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)

/** Turn a value into a mask:
 * - if \p value == 0, return the all-bits 0 mask, aka 0
 * - otherwise, return the all-bits 1 mask, aka (size_t) -1
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations using masks.
 *
 * \param value     The value to analyze.
 *
 * \return          Zero if \p value is zero, otherwise all-bits-one.
 */
size_t mbedtls_ct_size_mask(size_t value);

#endif /* MBEDTLS_SSL_SOME_SUITES_USE_MAC */

#if defined(MBEDTLS_BIGNUM_C)

/** Turn a value into a mask:
 * - if \p value == 0, return the all-bits 0 mask, aka 0
 * - otherwise, return the all-bits 1 mask, aka (mbedtls_mpi_uint) -1
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations using masks.
 *
 * \param value     The value to analyze.
 *
 * \return          Zero if \p value is zero, otherwise all-bits-one.
 */
mbedtls_mpi_uint mbedtls_ct_mpi_uint_mask(mbedtls_mpi_uint value);

#endif /* MBEDTLS_BIGNUM_C */

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_TLS_CBC)

/** Constant-flow mask generation for "greater or equal" comparison:
 * - if \p x >= \p y, return all-bits 1, that is (size_t) -1
 * - otherwise, return all bits 0, that is 0
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations using masks.
 *
 * \param x     The first value to analyze.
 * \param y     The second value to analyze.
 *
 * \return      All-bits-one if \p x is greater or equal than \p y,
 *              otherwise zero.
 */
size_t mbedtls_ct_size_mask_ge(size_t x,
                               size_t y);

#endif /* MBEDTLS_SSL_SOME_SUITES_USE_TLS_CBC */

/** Constant-flow boolean "equal" comparison:
 * return x == y
 *
 * This is equivalent to \p x == \p y, but is likely to be compiled
 * to code using bitwise operation rather than a branch.
 *
 * \param x     The first value to analyze.
 * \param y     The second value to analyze.
 *
 * \return      1 if \p x equals to \p y, otherwise 0.
 */
unsigned mbedtls_ct_size_bool_eq(size_t x,
                                 size_t y);

#if defined(MBEDTLS_BIGNUM_C)

/** Decide if an integer is less than the other, without branches.
 *
 * This is equivalent to \p x < \p y, but is likely to be compiled
 * to code using bitwise operation rather than a branch.
 *
 * \param x     The first value to analyze.
 * \param y     The second value to analyze.
 *
 * \return      1 if \p x is less than \p y, otherwise 0.
 */
unsigned mbedtls_ct_mpi_uint_lt(const mbedtls_mpi_uint x,
                                const mbedtls_mpi_uint y);

/**
 * \brief          Check if one unsigned MPI is less than another in constant
 *                 time.
 *
 * \param A        The left-hand MPI. This must point to an array of limbs
 *                 with the same allocated length as \p B.
 * \param B        The right-hand MPI. This must point to an array of limbs
 *                 with the same allocated length as \p A.
 * \param limbs    The number of limbs in \p A and \p B.
 *                 This must not be 0.
 *
 * \return         The result of the comparison:
 *                 \c 1 if \p A is less than \p B.
 *                 \c 0 if \p A is greater than or equal to \p B.
 */
unsigned mbedtls_mpi_core_lt_ct(const mbedtls_mpi_uint *A,
                                const mbedtls_mpi_uint *B,
                                size_t limbs);
#endif /* MBEDTLS_BIGNUM_C */

/** Choose between two integer values without branches.
 *
 * This is equivalent to `condition ? if1 : if0`, but is likely to be compiled
 * to code using bitwise operation rather than a branch.
 *
 * \param condition     Condition to test.
 * \param if1           Value to use if \p condition is nonzero.
 * \param if0           Value to use if \p condition is zero.
 *
 * \return  \c if1 if \p condition is nonzero, otherwise \c if0.
 */
unsigned mbedtls_ct_uint_if(unsigned condition,
                            unsigned if1,
                            unsigned if0);

#if defined(MBEDTLS_BIGNUM_C)

/** Conditionally assign a value without branches.
 *
 * This is equivalent to `if ( condition ) dest = src`, but is likely
 * to be compiled to code using bitwise operation rather than a branch.
 *
 * \param n             \p dest and \p src must be arrays of limbs of size n.
 * \param dest          The MPI to conditionally assign to. This must point
 *                      to an initialized MPI.
 * \param src           The MPI to be assigned from. This must point to an
 *                      initialized MPI.
 * \param condition     Condition to test, must be 0 or 1.
 */
void mbedtls_ct_mpi_uint_cond_assign(size_t n,
                                     mbedtls_mpi_uint *dest,
                                     const mbedtls_mpi_uint *src,
                                     unsigned char condition);

#endif /* MBEDTLS_BIGNUM_C */

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)

/** Conditional memcpy without branches.
 *
 * This is equivalent to `if ( c1 == c2 ) memcpy(dest, src, len)`, but is likely
 * to be compiled to code using bitwise operation rather than a branch.
 *
 * \param dest      The pointer to conditionally copy to.
 * \param src       The pointer to copy from. Shouldn't overlap with \p dest.
 * \param len       The number of bytes to copy.
 * \param c1        The first value to analyze in the condition.
 * \param c2        The second value to analyze in the condition.
 */
void mbedtls_ct_memcpy_if_eq(unsigned char *dest,
                             const unsigned char *src,
                             size_t len,
                             size_t c1, size_t c2);

/** Copy data from a secret position with constant flow.
 *
 * This function copies \p len bytes from \p src_base + \p offset_secret to \p
 * dst, with a code flow and memory access pattern that does not depend on \p
 * offset_secret, but only on \p offset_min, \p offset_max and \p len.
 * Functionally equivalent to `memcpy(dst, src + offset_secret, len)`.
 *
 * \note                This function reads from \p dest, but the value that
 *                      is read does not influence the result and this
 *                      function's behavior is well-defined regardless of the
 *                      contents of the buffers. This may result in false
 *                      positives from static or dynamic analyzers, especially
 *                      if \p dest is not initialized.
 *
 * \param dest          The destination buffer. This must point to a writable
 *                      buffer of at least \p len bytes.
 * \param src           The base of the source buffer. This must point to a
 *                      readable buffer of at least \p offset_max + \p len
 *                      bytes. Shouldn't overlap with \p dest.
 * \param offset        The offset in the source buffer from which to copy.
 *                      This must be no less than \p offset_min and no greater
 *                      than \p offset_max.
 * \param offset_min    The minimal value of \p offset.
 * \param offset_max    The maximal value of \p offset.
 * \param len           The number of bytes to copy.
 */
void mbedtls_ct_memcpy_offset(unsigned char *dest,
                              const unsigned char *src,
                              size_t offset,
                              size_t offset_min,
                              size_t offset_max,
                              size_t len);

#endif /* MBEDTLS_SSL_SOME_SUITES_USE_MAC */

#if defined(MBEDTLS_BASE64_C)

/** Constant-flow char selection
 *
 * \param low   Bottom of range
 * \param high  Top of range
 * \param c     Value to compare to range
 * \param t     Value to return, if in range
 *
 * \return      \p t if \p low <= \p c <= \p high, 0 otherwise.
 */
static inline unsigned char mbedtls_ct_uchar_in_range_if(unsigned char low,
                                                         unsigned char high,
                                                         unsigned char c,
                                                         unsigned char t)
{
    /* low_mask is: 0 if low <= c, 0x...ff if low > c */
    unsigned low_mask = ((unsigned) c - low) >> 8;
    /* high_mask is: 0 if c <= high, 0x...ff if c > high */
    unsigned high_mask = ((unsigned) high - c) >> 8;
    return (unsigned char)
           mbedtls_ct_uint_if(~mbedtls_ct_mpi_uint_mask(low_mask | high_mask), t, 0);
}

#endif /* MBEDTLS_BASE64_C */


#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && !defined(MBEDTLS_RSA_ALT)

/** Constant-flow "greater than" comparison:
 * return x > y
 *
 * This is equivalent to \p x > \p y, but is likely to be compiled
 * to code using bitwise operation rather than a branch.
 *
 * \param x     The first value to analyze.
 * \param y     The second value to analyze.
 *
 * \return      1 if \p x greater than \p y, otherwise 0.
 */
unsigned mbedtls_ct_size_gt(size_t x, size_t y);

/** Shift some data towards the left inside a buffer.
 *
 * `mbedtls_ct_mem_move_to_left(start, total, offset)` is functionally
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
void mbedtls_ct_mem_move_to_left(void *start,
                                 size_t total,
                                 size_t offset);

#endif /* defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && !defined(MBEDTLS_RSA_ALT) */

#endif /* MBEDTLS_CONSTANT_TIME_INTERNAL_H */
