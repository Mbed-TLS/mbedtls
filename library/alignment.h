/**
 * \file alignment.h
 *
 * \brief Utility code for dealing with unaligned memory accesses
 */
/*
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

#ifndef MBEDTLS_LIBRARY_ALIGNMENT_H
#define MBEDTLS_LIBRARY_ALIGNMENT_H

#include <stdint.h>

/** MBEDTLS_ALLOW_UNALIGNED_ACCESS is defined for architectures where unaligned
 * memory accesses are safe and performant.
 *
 * Unaligned accesses must be made via the UNALIGNED_UINT32_T type
 * defined here.
 *
 * This list is incomplete.
 */
#if defined(__i386__) || defined(__amd64__) || defined( __x86_64__) \
    || defined(__ARM_FEATURE_UNALIGNED) \
    || defined(__aarch64__) \
    || defined(__ARM_ARCH_8__) || defined(__ARM_ARCH_8A__) || defined(__ARM_ARCH_8M__) \
    || defined(__ARM_ARCH_7A__)
#if (defined(__GNUC__) && __GNUC__ >= 4) \
    || (defined(__clang__) && __has_attribute(aligned)) \
    || (defined(__ARMCC_VERSION) && __ARMCC_VERSION >= 5000000 )
    /* GCC, Clang and armcc */
#define MBEDTLS_ALLOW_UNALIGNED_ACCESS
__attribute__((aligned(1))) typedef uint32_t mbedtls_unaligned_uint32_t;
#define UNALIGNED_UINT32_T mbedtls_unaligned_uint32_t
#elif defined(_MSC_VER)
    /* MSVC */
#define MBEDTLS_ALLOW_UNALIGNED_ACCESS
#define UNALIGNED_UINT32_T __declspec(align(1)) uint32_t
#elif (defined __ICCARM__)
    /* IAR - this is disabled until we have the opportunity to test it */
#undef MBEDTLS_ALLOW_UNALIGNED_ACCESS
#define UNALIGNED_UINT32_T _Pragma("data_alignment = 1") uint32_t
#endif
#endif


/** Byte Reading Macros
 *
 * Given a multi-byte integer \p x, MBEDTLS_BYTE_n retrieves the n-th
 * byte from x, where byte 0 is the least significant byte.
 */
#define MBEDTLS_BYTE_0( x ) ( (uint8_t) (   ( x )         & 0xff ) )
#define MBEDTLS_BYTE_1( x ) ( (uint8_t) ( ( ( x ) >> 8  ) & 0xff ) )
#define MBEDTLS_BYTE_2( x ) ( (uint8_t) ( ( ( x ) >> 16 ) & 0xff ) )
#define MBEDTLS_BYTE_3( x ) ( (uint8_t) ( ( ( x ) >> 24 ) & 0xff ) )
#define MBEDTLS_BYTE_4( x ) ( (uint8_t) ( ( ( x ) >> 32 ) & 0xff ) )
#define MBEDTLS_BYTE_5( x ) ( (uint8_t) ( ( ( x ) >> 40 ) & 0xff ) )
#define MBEDTLS_BYTE_6( x ) ( (uint8_t) ( ( ( x ) >> 48 ) & 0xff ) )
#define MBEDTLS_BYTE_7( x ) ( (uint8_t) ( ( ( x ) >> 56 ) & 0xff ) )

/**
 * Get the unsigned 32 bits integer corresponding to four bytes in
 * big-endian order (MSB first).
 *
 * \param   data    Base address of the memory to get the four bytes from.
 * \param   offset  Offset from \p data of the first and most significant
 *                  byte of the four bytes to build the 32 bits unsigned
 *                  integer from.
 */
#ifndef MBEDTLS_GET_UINT32_BE
#define MBEDTLS_GET_UINT32_BE( data , offset )                  \
    (                                                           \
          ( (uint32_t) ( data )[( offset )    ] << 24 )         \
        | ( (uint32_t) ( data )[( offset ) + 1] << 16 )         \
        | ( (uint32_t) ( data )[( offset ) + 2] <<  8 )         \
        | ( (uint32_t) ( data )[( offset ) + 3]       )         \
    )
#endif

/**
 * Put in memory a 32 bits unsigned integer in big-endian order.
 *
 * \param   n       32 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 32
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p data where to put the most significant
 *                  byte of the 32 bits unsigned integer \p n.
 */
#ifndef MBEDTLS_PUT_UINT32_BE
#define MBEDTLS_PUT_UINT32_BE( n, data, offset )                \
{                                                               \
    ( data )[( offset )    ] = MBEDTLS_BYTE_3( n );             \
    ( data )[( offset ) + 1] = MBEDTLS_BYTE_2( n );             \
    ( data )[( offset ) + 2] = MBEDTLS_BYTE_1( n );             \
    ( data )[( offset ) + 3] = MBEDTLS_BYTE_0( n );             \
}
#endif

/**
 * Get the unsigned 32 bits integer corresponding to four bytes in
 * little-endian order (LSB first).
 *
 * \param   data    Base address of the memory to get the four bytes from.
 * \param   offset  Offset from \p data of the first and least significant
 *                  byte of the four bytes to build the 32 bits unsigned
 *                  integer from.
 */
#ifndef MBEDTLS_GET_UINT32_LE
#define MBEDTLS_GET_UINT32_LE( data, offset )                   \
    (                                                           \
          ( (uint32_t) ( data )[( offset )    ]       )         \
        | ( (uint32_t) ( data )[( offset ) + 1] <<  8 )         \
        | ( (uint32_t) ( data )[( offset ) + 2] << 16 )         \
        | ( (uint32_t) ( data )[( offset ) + 3] << 24 )         \
    )
#endif

/**
 * Put in memory a 32 bits unsigned integer in little-endian order.
 *
 * \param   n       32 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 32
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p data where to put the least significant
 *                  byte of the 32 bits unsigned integer \p n.
 */
#ifndef MBEDTLS_PUT_UINT32_LE
#define MBEDTLS_PUT_UINT32_LE( n, data, offset )                \
{                                                               \
    ( data )[( offset )    ] = MBEDTLS_BYTE_0( n );             \
    ( data )[( offset ) + 1] = MBEDTLS_BYTE_1( n );             \
    ( data )[( offset ) + 2] = MBEDTLS_BYTE_2( n );             \
    ( data )[( offset ) + 3] = MBEDTLS_BYTE_3( n );             \
}
#endif

/**
 * Get the unsigned 16 bits integer corresponding to two bytes in
 * little-endian order (LSB first).
 *
 * \param   data    Base address of the memory to get the two bytes from.
 * \param   offset  Offset from \p data of the first and least significant
 *                  byte of the two bytes to build the 16 bits unsigned
 *                  integer from.
 */
#ifndef MBEDTLS_GET_UINT16_LE
#define MBEDTLS_GET_UINT16_LE( data, offset )                   \
    (                                                           \
          ( (uint16_t) ( data )[( offset )    ]       )         \
        | ( (uint16_t) ( data )[( offset ) + 1] <<  8 )         \
    )
#endif

/**
 * Put in memory a 16 bits unsigned integer in little-endian order.
 *
 * \param   n       16 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 16
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p data where to put the least significant
 *                  byte of the 16 bits unsigned integer \p n.
 */
#ifndef MBEDTLS_PUT_UINT16_LE
#define MBEDTLS_PUT_UINT16_LE( n, data, offset )                \
{                                                               \
    ( data )[( offset )    ] = MBEDTLS_BYTE_0( n );             \
    ( data )[( offset ) + 1] = MBEDTLS_BYTE_1( n );             \
}
#endif

/**
 * Get the unsigned 16 bits integer corresponding to two bytes in
 * big-endian order (MSB first).
 *
 * \param   data    Base address of the memory to get the two bytes from.
 * \param   offset  Offset from \p data of the first and most significant
 *                  byte of the two bytes to build the 16 bits unsigned
 *                  integer from.
 */
#ifndef MBEDTLS_GET_UINT16_BE
#define MBEDTLS_GET_UINT16_BE( data, offset )                   \
    (                                                           \
          ( (uint16_t) ( data )[( offset )    ] << 8 )          \
        | ( (uint16_t) ( data )[( offset ) + 1]      )          \
    )
#endif

/**
 * Put in memory a 16 bits unsigned integer in big-endian order.
 *
 * \param   n       16 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 16
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p data where to put the most significant
 *                  byte of the 16 bits unsigned integer \p n.
 */
#ifndef MBEDTLS_PUT_UINT16_BE
#define MBEDTLS_PUT_UINT16_BE( n, data, offset )                \
{                                                               \
    ( data )[( offset )    ] = MBEDTLS_BYTE_1( n );             \
    ( data )[( offset ) + 1] = MBEDTLS_BYTE_0( n );             \
}
#endif

/**
 * Get the unsigned 24 bits integer corresponding to three bytes in
 * big-endian order (MSB first).
 *
 * \param   data    Base address of the memory to get the three bytes from.
 * \param   offset  Offset from \p data of the first and most significant
 *                  byte of the three bytes to build the 24 bits unsigned
 *                  integer from.
 */
#ifndef MBEDTLS_GET_UINT24_BE
#define MBEDTLS_GET_UINT24_BE( data , offset )                  \
    (                                                           \
          ( (uint32_t) ( data )[( offset )    ] << 16 )         \
        | ( (uint32_t) ( data )[( offset ) + 1] << 8  )         \
        | ( (uint32_t) ( data )[( offset ) + 2]       )         \
    )
#endif

/**
 * Put in memory a 24 bits unsigned integer in big-endian order.
 *
 * \param   n       24 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 24
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p data where to put the most significant
 *                  byte of the 24 bits unsigned integer \p n.
 */
#ifndef MBEDTLS_PUT_UINT24_BE
#define MBEDTLS_PUT_UINT24_BE( n, data, offset )                \
{                                                               \
    ( data )[( offset )    ] = MBEDTLS_BYTE_2( n );             \
    ( data )[( offset ) + 1] = MBEDTLS_BYTE_1( n );             \
    ( data )[( offset ) + 2] = MBEDTLS_BYTE_0( n );             \
}
#endif

/**
 * Get the unsigned 24 bits integer corresponding to three bytes in
 * little-endian order (LSB first).
 *
 * \param   data    Base address of the memory to get the three bytes from.
 * \param   offset  Offset from \p data of the first and least significant
 *                  byte of the three bytes to build the 24 bits unsigned
 *                  integer from.
 */
#ifndef MBEDTLS_GET_UINT24_LE
#define MBEDTLS_GET_UINT24_LE( data, offset )                   \
    (                                                           \
          ( (uint32_t) ( data )[( offset )    ]       )         \
        | ( (uint32_t) ( data )[( offset ) + 1] <<  8 )         \
        | ( (uint32_t) ( data )[( offset ) + 2] << 16 )         \
    )
#endif

/**
 * Put in memory a 24 bits unsigned integer in little-endian order.
 *
 * \param   n       24 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 24
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p data where to put the least significant
 *                  byte of the 24 bits unsigned integer \p n.
 */
#ifndef MBEDTLS_PUT_UINT24_LE
#define MBEDTLS_PUT_UINT24_LE( n, data, offset )                \
{                                                               \
    ( data )[( offset )    ] = MBEDTLS_BYTE_0( n );             \
    ( data )[( offset ) + 1] = MBEDTLS_BYTE_1( n );             \
    ( data )[( offset ) + 2] = MBEDTLS_BYTE_2( n );             \
}
#endif

/**
 * Get the unsigned 64 bits integer corresponding to eight bytes in
 * big-endian order (MSB first).
 *
 * \param   data    Base address of the memory to get the eight bytes from.
 * \param   offset  Offset from \p data of the first and most significant
 *                  byte of the eight bytes to build the 64 bits unsigned
 *                  integer from.
 */
#ifndef MBEDTLS_GET_UINT64_BE
#define MBEDTLS_GET_UINT64_BE( data, offset )                   \
    (                                                           \
          ( (uint64_t) ( data )[( offset )    ] << 56 )         \
        | ( (uint64_t) ( data )[( offset ) + 1] << 48 )         \
        | ( (uint64_t) ( data )[( offset ) + 2] << 40 )         \
        | ( (uint64_t) ( data )[( offset ) + 3] << 32 )         \
        | ( (uint64_t) ( data )[( offset ) + 4] << 24 )         \
        | ( (uint64_t) ( data )[( offset ) + 5] << 16 )         \
        | ( (uint64_t) ( data )[( offset ) + 6] <<  8 )         \
        | ( (uint64_t) ( data )[( offset ) + 7]       )         \
    )
#endif

/**
 * Put in memory a 64 bits unsigned integer in big-endian order.
 *
 * \param   n       64 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 64
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p data where to put the most significant
 *                  byte of the 64 bits unsigned integer \p n.
 */
#ifndef MBEDTLS_PUT_UINT64_BE
#define MBEDTLS_PUT_UINT64_BE( n, data, offset )                \
{                                                               \
    ( data )[( offset )    ] = MBEDTLS_BYTE_7( n );             \
    ( data )[( offset ) + 1] = MBEDTLS_BYTE_6( n );             \
    ( data )[( offset ) + 2] = MBEDTLS_BYTE_5( n );             \
    ( data )[( offset ) + 3] = MBEDTLS_BYTE_4( n );             \
    ( data )[( offset ) + 4] = MBEDTLS_BYTE_3( n );             \
    ( data )[( offset ) + 5] = MBEDTLS_BYTE_2( n );             \
    ( data )[( offset ) + 6] = MBEDTLS_BYTE_1( n );             \
    ( data )[( offset ) + 7] = MBEDTLS_BYTE_0( n );             \
}
#endif

/**
 * Get the unsigned 64 bits integer corresponding to eight bytes in
 * little-endian order (LSB first).
 *
 * \param   data    Base address of the memory to get the eight bytes from.
 * \param   offset  Offset from \p data of the first and least significant
 *                  byte of the eight bytes to build the 64 bits unsigned
 *                  integer from.
 */
#ifndef MBEDTLS_GET_UINT64_LE
#define MBEDTLS_GET_UINT64_LE( data, offset )                   \
    (                                                           \
          ( (uint64_t) ( data )[( offset ) + 7] << 56 )         \
        | ( (uint64_t) ( data )[( offset ) + 6] << 48 )         \
        | ( (uint64_t) ( data )[( offset ) + 5] << 40 )         \
        | ( (uint64_t) ( data )[( offset ) + 4] << 32 )         \
        | ( (uint64_t) ( data )[( offset ) + 3] << 24 )         \
        | ( (uint64_t) ( data )[( offset ) + 2] << 16 )         \
        | ( (uint64_t) ( data )[( offset ) + 1] <<  8 )         \
        | ( (uint64_t) ( data )[( offset )    ]       )         \
    )
#endif

/**
 * Put in memory a 64 bits unsigned integer in little-endian order.
 *
 * \param   n       64 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 64
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p data where to put the least significant
 *                  byte of the 64 bits unsigned integer \p n.
 */
#ifndef MBEDTLS_PUT_UINT64_LE
#define MBEDTLS_PUT_UINT64_LE( n, data, offset )                \
{                                                               \
    ( data )[( offset )    ] = MBEDTLS_BYTE_0( n );             \
    ( data )[( offset ) + 1] = MBEDTLS_BYTE_1( n );             \
    ( data )[( offset ) + 2] = MBEDTLS_BYTE_2( n );             \
    ( data )[( offset ) + 3] = MBEDTLS_BYTE_3( n );             \
    ( data )[( offset ) + 4] = MBEDTLS_BYTE_4( n );             \
    ( data )[( offset ) + 5] = MBEDTLS_BYTE_5( n );             \
    ( data )[( offset ) + 6] = MBEDTLS_BYTE_6( n );             \
    ( data )[( offset ) + 7] = MBEDTLS_BYTE_7( n );             \
}
#endif

#endif /* MBEDTLS_LIBRARY_ALIGNMENT_H */
