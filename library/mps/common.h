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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/**
 * \file common.h
 *
 * \brief Common functions and macros used by MPS
 */

#ifndef MBEDTLS_MPS_COMMON_H
#define MBEDTLS_MPS_COMMON_H

#include <stdio.h>

/**
 * \name SECTION:       MPS Configuration
 *
 * \{
 */

/*! This flag enables/disables assertions on the internal state of MPS.
 *
 *  Assertions are sanity checks that should never trigger when MPS
 *  is used within the bounds of its API and preconditions.
 *
 *  Enabling this increases security by limiting the scope of
 *  potential bugs, but comes at the cost of increased code size.
 *
 *  Note: So far, there is no guiding principle as to what
 *  expected conditions merit an assertion, and which don't.
 *
 *  Comment this to disable assertions.
 */
#define MBEDTLS_MPS_ENABLE_ASSERTIONS

/*! This flag controls whether tracing for MPS should be enabled. */
//#define MBEDTLS_MPS_TRACE

#if defined(MBEDTLS_MPS_ENABLE_ASSERTIONS)

#define MBEDTLS_MPS_ASSERT_RAW( cond, string )                   \
    do                                                           \
    {                                                            \
        if( !(cond) )                                            \
        {                                                        \
            TRACE( trace_error, string );                        \
            RETURN( MBEDTLS_ERR_MPS_INTERNAL_ERROR );            \
        }                                                        \
    } while( 0 )

#else /* MBEDTLS_MPS_ENABLE_ASSERTIONS */

#define MBEDTLS_MPS_ASSERT_RAW( cond, string ) do {} while( 0 )

#endif /* MBEDTLS_MPS_ENABLE_ASSERTIONS */

/* \} name SECTION: MPS Configuration */

/**
 * \name SECTION:       Common types
 *
 * Various common types used throughout MPS.
 * \{
 */

/** \brief   The type of buffer sizes and offsets used in MPS structures.
 *
 *           This is an unsigned integer type that should be large enough to
 *           hold the length of any buffer resp. message processed by MPS.
 *
 *           The reason to pick a value as small as possible here is
 *           to reduce the size of MPS structures.
 *
 * \warning  Care has to be taken when using a narrower type
 *           than ::mbedtls_mps_size_t here because of
 *           potential truncation during conversion.
 *
 * \warning  Handshake messages in TLS may be up to 2^24 ~ 16Mb in size.
 *           If mbedtls_mps_[opt_]stored_size_t is smaller than that, the
 *           maximum handshake message is restricted accordingly.
 *
 * For now, we use the default type of size_t throughout, and the use of
 * smaller types or different types for ::mbedtls_mps_size_t and
 * ::mbedtls_mps_stored_size_t is not yet supported.
 *
 */
typedef size_t mbedtls_mps_stored_size_t;
#define MBEDTLS_MPS_SIZE_MAX  ( (mbedtls_mps_size_t) -1 )

/** \brief The type of buffer sizes and offsets used in the MPS API
 *         and implementation.
 *
 *         This must be at least as wide as ::mbedtls_stored_size_t but
 *         may be chosen to be strictly larger if more suitable for the
 *         target architecture.
 *
 *         For example, in a test build for ARM Thumb, using uint_fast16_t
 *         instead of uint16_t reduced the code size from 1060 Byte to 962 Byte,
 *         so almost 10%.
 */
typedef size_t mbedtls_mps_size_t;

#if (mbedtls_mps_size_t) -1 > (mbedtls_mps_stored_size_t) -1
#error "Misconfiguration of mbedtls_mps_size_t and mbedtls_mps_stored_size_t."
#endif

/* \} SECTION: Common types */


#endif /* MBEDTLS_MPS_COMMON_H */
