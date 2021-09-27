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

int mbedtls_ssl_safer_memcmp( const void *a, const void *b, size_t n );

int mbedtls_constant_time_memcmp( const void *v1, const void *v2, size_t len );

unsigned char mbedtls_nist_kw_safer_memcmp( const void *a, const void *b, size_t n );

int mbedtls_safer_memcmp( const void *a, const void *b, size_t n );


unsigned mbedtls_cf_uint_mask( unsigned value );

size_t mbedtls_cf_size_mask( size_t bit );

size_t mbedtls_cf_size_mask_lt( size_t x, size_t y );

size_t mbedtls_cf_size_mask_ge( size_t x, size_t y );

size_t mbedtls_cf_size_bool_eq( size_t x, size_t y );

unsigned mbedtls_cf_size_gt( size_t size, size_t max );

#if defined(MBEDTLS_BIGNUM_C)

unsigned mbedtls_cf_mpi_uint_lt( const mbedtls_mpi_uint x,
                                 const mbedtls_mpi_uint y );

#endif /* MBEDTLS_BIGNUM_C */

unsigned mbedtls_cf_uint_if( unsigned cond, unsigned if1, unsigned if0 );

size_t mbedtls_cf_size_if( unsigned cond, size_t if1, size_t if0 );

int mbedtls_cf_cond_select_sign( int a, int b, unsigned char second );

#if defined(MBEDTLS_BIGNUM_C)

void mbedtls_cf_mpi_uint_cond_assign( size_t n,
                                      mbedtls_mpi_uint *dest,
                                      const mbedtls_mpi_uint *src,
                                      unsigned char assign );

#endif /* MBEDTLS_BIGNUM_C */

void mbedtls_cf_mem_move_to_left( void *start,
                                  size_t total,
                                  size_t offset );

void mbedtls_cf_memcpy_if_eq( unsigned char *dst,
                              const unsigned char *src,
                              size_t len,
                              size_t c1, size_t c2 );

/** Copy data from a secret position with constant flow.
 *
 * This function copies \p len bytes from \p src_base + \p offset_secret to \p
 * dst, with a code flow and memory access pattern that does not depend on \p
 * offset_secret, but only on \p offset_min, \p offset_max and \p len.
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
                               size_t offset_min, size_t offset_max,
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
int mbedtls_ssl_cf_hmac(
        mbedtls_md_context_t *ctx,
        const unsigned char *add_data, size_t add_data_len,
        const unsigned char *data, size_t data_len_secret,
        size_t min_data_len, size_t max_data_len,
        unsigned char *output );

#endif /* MBEDTLS_SSL_SOME_SUITES_USE_TLS_CBC */
