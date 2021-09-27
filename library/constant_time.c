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
