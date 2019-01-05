/**
 * \file common.h
 *
 * \brief Common functions and macros used by MPS
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_MPS_COMMON_H
#define MBEDTLS_MPS_COMMON_H

#include <stdint.h>

/**
 * \name SECTION:       Common types
 *
 * Various common types used throughout MPS.
 * \{
 */

/** \brief   The enumeration of record content types recognized by MPS.
 *
 * \note     Not all of these are visible on the MPS boundary. For example,
 *           ACK messages are handled by MPS internally and are never signalled
 *           to the user.
 *
 * \note     The values are aligned to the ContentType field in [D]TLS records.
 */

typedef enum
{
    MBEDTLS_MPS_MSG_NONE = 0,        /*!< This is a placeholder to indicate
                                      *   that no record is currently open
                                      *   for reading or writing.             */
    MBEDTLS_MPS_MSG_APP=23,         /*!< This represents application data.    */
    MBEDTLS_MPS_MSG_HS=22,          /*!< This represents handshake messages.  */
    MBEDTLS_MPS_MSG_ALERT=21,       /*!< This represents alert messages.      */
    MBEDTLS_MPS_MSG_CCS=20,         /*!< This represents CCS messages.        */
    MBEDTLS_MPS_MSG_ACK=19          /*!< This represents ACK messages
                                     *   (used in DTLS 1.3 only).             */
} mbedtls_mps_msg_type_t;

/** \brief   The type of buffer sizes and offsets used in MPS structures.
 *
 *           This is an unsigned integer type that should be large enough to
 *           hold the length of any buffer resp. message processed by MPS.
 *
 *           The reason to pick a value as small as possible here is
 *           to reduce the size of MPS structures.
 *
 * \warning  Care has to be taken when using a narrower type
 *           than ::mbedtls_mps_stored_size_t here because of
 *           potential truncation during conversion.
 *
 */
typedef uint16_t mbedtls_mps_stored_size_t;
#define MBEDTLS_MPS_OFFSET_MAX ( (mbedtls_mps_stored_size_t) -1u )

/* \brief The type of buffer sizes and offsets used in the MPS API
 *        and implementation.
 *
 *        This must be at least as wide as ::mbedtls_writer_size_t but
 *        may be chosen to be strictly larger if more suitable for the
 *        target architecture.
 *
 *        For example, in a test build for ARM Thumb, using uint_fast16_t
 *        instead of uint16_t reduced the code size from 1060 Byte to 962 Byte,
 *        so almost 10%.
 */
typedef uint_fast16_t mbedtls_mps_size_t;

#if (mbedtls_mps_size_t) -1u > (mbedtls_mps_stored_size_t) -1u
#error "Misconfiguration of mbedtls_mps_size_t and mbedtls_mps_stored_size_t."
#endif

/* \} SECTION: Common types */

/**
 * \name SECTION:       Parsing and writing macros
 *
 * Macros to be used for parsing various types of fiellds.
 * \{
 */

#define MPS_READ_UINT8_LE( src, dst )                            \
    do                                                           \
    {                                                            \
        *( dst ) = ( (uint8_t*) ( src ) )[0];                    \
    } while( 0 )

#define MPS_WRITE_UINT8_LE( src, dst )                           \
    do                                                           \
    {                                                            \
        *( dst ) = ( (uint8_t*) ( src ) )[0];                    \
    } while( 0 )

#define MPS_READ_UINT16_LE( src, dst )                           \
    do                                                           \
    {                                                            \
        *( dst ) =                                               \
            ( ( (uint16_t) ( (uint8_t*) ( src ) )[0] ) << 8 ) +  \
            ( ( (uint16_t) ( (uint8_t*) ( src ) )[1] ) << 0 );   \
    } while( 0 )

#define MPS_WRITE_UINT16_LE( src, dst )                          \
    do                                                           \
    {                                                            \
        *( (uint8_t*) ( dst ) + 0 ) = ( *( src ) >> 8 ) & 0xFF;  \
        *( (uint8_t*) ( dst ) + 1 ) = ( *( src ) >> 0 ) & 0xFF;  \
    } while( 0 )


#define MPS_WRITE_UINT24_LE( dst, src )                          \
    do                                                           \
    {                                                            \
        *( (uint8_t*) ( dst ) + 0 ) = ( *( src ) >> 16 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 1 ) = ( *( src ) >>  8 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 2 ) = ( *( src ) >>  0 ) & 0xFF; \
    } while( 0 )

#define MPS_READ_UINT24_LE( dst, src )                           \
    do                                                           \
    {                                                            \
        *(dst) =                                                 \
            ( ( (uint32_t) ( (uint8_t*) ( src ) )[0] ) << 16 ) + \
            ( ( (uint32_t) ( (uint8_t*) ( src ) )[1] ) <<  8 ) + \
            ( ( (uint32_t) ( (uint8_t*) ( src ) )[2] ) <<  0 );  \
    } while( 0 )

#define MPS_WRITE_UINT32_LE( dst, src )                          \
    do                                                           \
    {                                                            \
        *( (uint8_t*) ( dst ) + 2 ) = ( *( src ) >> 24 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 3 ) = ( *( src ) >> 16 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 4 ) = ( *( src ) >>  8 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 5 ) = ( *( src ) >>  0 ) & 0xFF; \
    } while( 0 )

#define MPS_READ_UINT32_LE( dst, src )                           \
    do                                                           \
    {                                                            \
        *( dst ) =                                               \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[2] ) << 24 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[3] ) << 16 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[4] ) <<  8 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[5] ) <<  0 );  \
    } while( 0 )

#define MPS_WRITE_UINT48_LE( src, dst )                          \
    do                                                           \
    {                                                            \
        *( (uint8_t*) ( dst ) + 0 ) = ( *( src ) >> 40 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 1 ) = ( *( src ) >> 32 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 2 ) = ( *( src ) >> 24 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 3 ) = ( *( src ) >> 16 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 4 ) = ( *( src ) >>  8 ) & 0xFF; \
        *( (uint8_t*) ( dst ) + 5 ) = ( *( src ) >>  0 ) & 0xFF; \
    } while( 0 )

#define MPS_READ_UINT48_LE( src, dst )                           \
    do                                                           \
    {                                                            \
        *( dst ) =                                               \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[0] ) << 40 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[1] ) << 32 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[2] ) << 24 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[3] ) << 16 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[4] ) <<  8 ) + \
            ( ( (uint64_t) ( (uint8_t*) ( src ) )[5] ) <<  0 );  \
    } while( 0 )

/* \} name SECTION: Parsing and writing macros */

#endif /* MBEDTLS_MPS_COMMON_H */
