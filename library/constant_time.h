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

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

#if defined(MBEDTLS_SSL_TLS_C)
#include "ssl_misc.h"
#endif

#include <stddef.h>


/** Constant-time buffer comparison without branches.
 *
 * This is equivalent to the standard memncmp function, but is likely to be
 * compiled to code using bitwise operation rather than a branch.
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations using masks.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 *
 * \param a     Pointer to the first buffer.
 * \param b     Pointer to the second buffer.
 * \param n     The number of bytes to compare in the buffer.
 *
 * \return      Zero if the content of the two buffer is the same,
 *              otherwise non-zero.
 */
int mbedtls_cf_memcmp( const void *a,
                       const void *b,
                       size_t n );

/** Turn a value into a mask:
 * - if \p value == 0, return the all-bits 0 mask, aka 0
 * - otherwise, return the all-bits 1 mask, aka (size_t) -1
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations using masks.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 *
 * \param value     The value to analyze.
 *
 * \return          Zero if \p value is zero, otherwise all-bits-one.
 */
unsigned mbedtls_cf_uint_mask( unsigned value );

/** Turn a value into a mask:
 * - if \p value == 0, return the all-bits 0 mask, aka 0
 * - otherwise, return the all-bits 1 mask, aka (size_t) -1
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations using masks.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 *
 * \param value     The value to analyze.
 *
 * \return          Zero if \p value is zero, otherwise all-bits-one.
 */
size_t mbedtls_cf_size_mask( size_t value );

#if defined(MBEDTLS_BIGNUM_C)

/** Turn a value into a mask:
 * - if \p value == 0, return the all-bits 0 mask, aka 0
 * - otherwise, return the all-bits 1 mask, aka (size_t) -1
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations using masks.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 *
 * \param value     The value to analyze.
 *
 * \return          Zero if \p value is zero, otherwise all-bits-one.
 */
mbedtls_mpi_uint mbedtls_cf_mpi_uint_mask( mbedtls_mpi_uint value );

#endif /* MBEDTLS_BIGNUM_C */

/** Constant-flow mask generation for "greater or equal" comparison:
 * - if \p x >= \p y, return all-bits 1, that is (size_t) -1
 * - otherwise, return all bits 0, that is 0
 *
 * This function can be used to write constant-time code by replacing branches
 * with bit operations using masks.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 *
 * \param x     The first value to analyze.
 * \param y     The second value to analyze.
 *
 * \return      All-bits-one if \p x is greater or equal than \p y,
 *              otherwise zero.
 */
size_t mbedtls_cf_size_mask_ge( size_t x,
                                size_t y );

/** Constant-flow boolean "equal" comparison:
 * return x == y
 *
 * This is equivalent to \p x == \p y, but is likely to be compiled
 * to code using bitwise operation rather than a branch.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 *
 * \param x     The first value to analyze.
 * \param y     The second value to analyze.
 *
 * \return      1 if \p x equals to \p y, otherwise 0.
 */
unsigned mbedtls_cf_size_bool_eq( size_t x,
                                  size_t y );

/** Constant-flow "greater than" comparison:
 * return x > y
 *
 * This is equivalent to \p x > \p y, but is likely to be compiled
 * to code using bitwise operation rather than a branch.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 *
 * \param x     The first value to analyze.
 * \param y     The second value to analyze.
 *
 * \return      1 if \p x greater than \p y, otherwise 0.
 */
unsigned mbedtls_cf_size_gt( size_t x,
                             size_t y );

#if defined(MBEDTLS_BIGNUM_C)

/** Decide if an integer is less than the other, without branches.
 *
 * This is equivalent to \p x < \p y, but is likely to be compiled
 * to code using bitwise operation rather than a branch.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 *
 * \param x     The first value to analyze.
 * \param y     The second value to analyze.
 *
 * \return      1 if \p x is less than \p y, otherwise 0.
 */
unsigned mbedtls_cf_mpi_uint_lt( const mbedtls_mpi_uint x,
                                 const mbedtls_mpi_uint y );

#endif /* MBEDTLS_BIGNUM_C */

/** Choose between two integer values without branches.
 *
 * This is equivalent to `condition ? if1 : if0`, but is likely to be compiled
 * to code using bitwise operation rather than a branch.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 *
 * \param condition     Condition to test.
 * \param if1           Value to use if \p condition is nonzero.
 * \param if0           Value to use if \p condition is zero.
 *
 * \return  \c if1 if \p condition is nonzero, otherwise \c if0.
 */
unsigned mbedtls_cf_uint_if( unsigned condition,
                             unsigned if1,
                             unsigned if0 );

/** Choose between two integer values without branches.
 *
 * This is equivalent to `condition ? if1 : if0`, but is likely to be compiled
 * to code using bitwise operation rather than a branch.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 *
 * \param condition     Condition to test.
 * \param if1           Value to use if \p condition is nonzero.
 * \param if0           Value to use if \p condition is zero.
 *
 * \return  \c if1 if \p condition is nonzero, otherwise \c if0.
 */
size_t mbedtls_cf_size_if( unsigned condition,
                           size_t if1,
                           size_t if0 );

/** Select between two sign values witout branches.
 *
 * This is functionally equivalent to `condition ? if1 : if0` but uses only bit
 * operations in order to avoid branches.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 *
 * \param condition     Condition to test.
 * \param if1           The first sign; must be either +1 or -1.
 * \param if0           The second sign; must be either +1 or -1.
 *
 * \return  \c if1 if \p condition is nonzero, otherwise \c if0. */
int mbedtls_cf_cond_select_sign( unsigned char condition,
                                 int if1,
                                 int if0 );

#if defined(MBEDTLS_BIGNUM_C)

/** Conditionally assign a value without branches.
 *
 * This is equivalent to `if ( condition ) dest = src`, but is likely
 * to be compiled to code using bitwise operation rather than a branch.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 *
 * \param n             \p dest and \p src must be arrays of limbs of size n.
 * \param dest          The MPI to conditionally assign to. This must point
 *                      to an initialized MPI.
 * \param src           The MPI to be assigned from. This must point to an
 *                      initialized MPI.
 * \param condition     Condition to test, must be 0 or 1.
 */
void mbedtls_cf_mpi_uint_cond_assign( size_t n,
                                      mbedtls_mpi_uint *dest,
                                      const mbedtls_mpi_uint *src,
                                      unsigned char condition );

#endif /* MBEDTLS_BIGNUM_C */


/** Shift some data towards the left inside a buffer.
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
                                  size_t offset );

/** Conditional memcpy without branches.
 *
 * This is equivalent to `if ( c1 == c2 ) memcpy(dst, src, len)`, but is likely
 * to be compiled to code using bitwise operation rather than a branch.
 *
 * This function is implemented without using comparison operators, as those
 * might be translated to branches by some compilers on some platforms.
 *
 * \param dest      The pointer to conditionally copy to.
 * \param src       The pointer to copy from.
 * \param len       The number of bytes to copy.
 * \param c1        The first value to analyze in the condition.
 * \param c2        The second value to analyze in the condition.
 */
void mbedtls_cf_memcpy_if_eq( unsigned char *dest,
                              const unsigned char *src,
                              size_t len,
                              size_t c1, size_t c2 );

/** Copy data from a secret position with constant flow.
 *
 * This function copies \p len bytes from \p src_base + \p offset_secret to \p
 * dst, with a code flow and memory access pattern that does not depend on \p
 * offset_secret, but only on \p offset_min, \p offset_max and \p len.
 * Functionally equivalent to memcpy(dst, src + offset_secret, len).
 *
 * \param dst           The destination buffer. This must point to a writable
 *                      buffer of at least \p len bytes.
 * \param src_base      The base of the source buffer. This must point to a
 *                      readable buffer of at least \p offset_max + \p len
 *                      bytes.
 * \param offset_secret The offset in the source buffer from which to copy.
 *                      This must be no less than \p offset_min and no greater
 *                      than \p offset_max.
 * \param offset_min    The minimal value of \p offset_secret.
 * \param offset_max    The maximal value of \p offset_secret.
 * \param len           The number of bytes to copy.
 */
void mbedtls_cf_memcpy_offset( unsigned char *dst,
                               const unsigned char *src_base,
                               size_t offset_secret,
                               size_t offset_min,
                               size_t offset_max,
                               size_t len );

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_TLS_CBC)

/** Compute the HMAC of variable-length data with constant flow.
 *
 * This function computes the HMAC of the concatenation of \p add_data and \p
 * data, and does with a code flow and memory access pattern that does not
 * depend on \p data_len_secret, but only on \p min_data_len and \p
 * max_data_len. In particular, this function always reads exactly \p
 * max_data_len bytes from \p data.
 *
 * \param ctx               The HMAC context. It must have keys configured
 *                          with mbedtls_md_hmac_starts() and use one of the
 *                          following hashes: SHA-384, SHA-256, SHA-1 or MD-5.
 *                          It is reset using mbedtls_md_hmac_reset() after
 *                          the computation is complete to prepare for the
 *                          next computation.
 * \param add_data          The additional data prepended to \p data. This
 *                          must point to a readable buffer of \p add_data_len
 *                          bytes.
 * \param add_data_len      The length of \p add_data in bytes.
 * \param data              The data appended to \p add_data. This must point
 *                          to a readable buffer of \p max_data_len bytes.
 * \param data_len_secret   The length of the data to process in \p data.
 *                          This must be no less than \p min_data_len and no
 *                          greater than \p max_data_len.
 * \param min_data_len      The minimal length of \p data in bytes.
 * \param max_data_len      The maximal length of \p data in bytes.
 * \param output            The HMAC will be written here. This must point to
 *                          a writable buffer of sufficient size to hold the
 *                          HMAC value.
 *
 * \retval 0 on success.
 * \retval MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED
 *         The hardware accelerator failed.
 */
int mbedtls_cf_hmac( mbedtls_md_context_t *ctx,
                     const unsigned char *add_data,
                     size_t add_data_len,
                     const unsigned char *data,
                     size_t data_len_secret,
                     size_t min_data_len,
                     size_t max_data_len,
                     unsigned char *output );

#endif /* MBEDTLS_SSL_SOME_SUITES_USE_TLS_CBC */

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && !defined(MBEDTLS_RSA_ALT)

/** This function performs the unpadding part of a PKCS#1 v1.5 decryption
 *  operation (RSAES-PKCS1-v1_5-DECRYPT).
 *
 * \note           The output buffer length \c output_max_len should be
 *                 as large as the size \p ctx->len of \p ctx->N, for example,
 *                 128 Bytes if RSA-1024 is used, to be able to hold an
 *                 arbitrary decrypted message. If it is not large enough to
 *                 hold the decryption of the particular ciphertext provided,
 *                 the function returns #MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE.
 *
 * \param ilen           The length of the ciphertext.
 * \param olen           The address at which to store the length of
 *                       the plaintext. This must not be \c NULL.
 * \param output         The buffer used to hold the plaintext. This must
 *                       be a writable buffer of length \p output_max_len Bytes.
 * \param output_max_len The length in Bytes of the output buffer \p output.
 * \param buf            The input buffer for the unpadding operation.
 *
 * \return         \c 0 on success.
 * \return         An \c MBEDTLS_ERR_RSA_XXX error code on failure.
 */
int mbedtls_cf_rsaes_pkcs1_v15_unpadding( size_t ilen,
                                          size_t *olen,
                                          unsigned char *output,
                                          size_t output_max_len,
                                          unsigned char *buf );

#endif /* MBEDTLS_PKCS1_V15 && MBEDTLS_RSA_C && ! MBEDTLS_RSA_ALT */
