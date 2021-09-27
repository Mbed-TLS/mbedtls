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
