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
 * \file trace.h
 *
 * \brief Tracing module for MPS
 */

#ifndef MBEDTLS_MPS_TRACE_H
#define MBEDTLS_MPS_TRACE_H

#include "common.h"

#include "../common.h"

#include "trace.h"
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf    printf
#define mbedtls_vsnprintf vsnprintf
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_MPS_TRACE)

/*
 * Adapt this to enable/disable tracing output
 * from the various layers of the MPS.
 */

#define TRACE_ENABLE_LAYER_1
#define TRACE_ENABLE_LAYER_2
#define TRACE_ENABLE_LAYER_3
#define TRACE_ENABLE_LAYER_4
#define TRACE_ENABLE_READER
#define TRACE_ENABLE_WRITER

/*
 * To use the existing trace module, only change
 * TRACE_ENABLE_XXX above, but don't modify the
 * rest of this file.
 */

typedef enum
{
    trace_comment,
    trace_call,
    trace_error,
    trace_return
} trace_type;

#define TRACE_BIT_LAYER_1 1
#define TRACE_BIT_LAYER_2 2
#define TRACE_BIT_LAYER_3 3
#define TRACE_BIT_LAYER_4 4
#define TRACE_BIT_WRITER  5
#define TRACE_BIT_READER  6

#if defined(TRACE_ENABLE_LAYER_1)
#define TRACE_MASK_LAYER_1 (1u << TRACE_BIT_LAYER_1 )
#else
#define TRACE_MASK_LAYER_1 0
#endif

#if defined(TRACE_ENABLE_LAYER_2)
#define TRACE_MASK_LAYER_2 (1u << TRACE_BIT_LAYER_2 )
#else
#define TRACE_MASK_LAYER_2 0
#endif

#if defined(TRACE_ENABLE_LAYER_3)
#define TRACE_MASK_LAYER_3 (1u << TRACE_BIT_LAYER_3 )
#else
#define TRACE_MASK_LAYER_3 0
#endif

#if defined(TRACE_ENABLE_LAYER_4)
#define TRACE_MASK_LAYER_4 (1u << TRACE_BIT_LAYER_4 )
#else
#define TRACE_MASK_LAYER_4 0
#endif

#if defined(TRACE_ENABLE_READER)
#define TRACE_MASK_READER (1u << TRACE_BIT_READER )
#else
#define TRACE_MASK_READER 0
#endif

#if defined(TRACE_ENABLE_WRITER)
#define TRACE_MASK_WRITER (1u << TRACE_BIT_WRITER )
#else
#define TRACE_MASK_WRITER 0
#endif

#define TRACE_MASK ( TRACE_MASK_LAYER_1 |           \
                     TRACE_MASK_LAYER_2 |           \
                     TRACE_MASK_LAYER_3 |           \
                     TRACE_MASK_LAYER_4 |           \
                     TRACE_MASK_READER  |           \
                     TRACE_MASK_WRITER )

/* We have to avoid globals because E-ACSL chokes on them...
 * Wrap everything in stub functions. */
int  trace_get_depth( void );
void trace_inc_depth( void );
void trace_dec_depth( void );

void trace_color( int id );
void trace_indent( int level, trace_type ty );

void trace_print_msg( int id, int line, const char *format, ... );

#define TRACE( type, ... )                                  \
    do {                                                    \
        if( ! ( TRACE_MASK & ( 1u << trace_id ) ) )         \
            break;                                          \
        trace_indent( trace_get_depth(), type );            \
        trace_color( trace_id );                            \
        trace_print_msg( trace_id, __LINE__, __VA_ARGS__ ); \
        trace_color( 0 );                                   \
    } while( 0 )

#define TRACE_INIT( ... )                                   \
    do {                                                    \
        if( ! ( TRACE_MASK & ( 1u << trace_id ) ) )         \
            break;                                          \
        TRACE( trace_call, __VA_ARGS__ );                   \
        trace_inc_depth();                                  \
    } while( 0 )

#define TRACE_END( val )                                    \
    do {                                                    \
        if( ! ( TRACE_MASK & ( 1u << trace_id ) ) )         \
            break;                                          \
        TRACE( trace_return, "%d (-%#04x)",                 \
               (int) (val), -((unsigned)(val)) );           \
        trace_dec_depth();                                  \
    } while( 0 )

#define RETURN( val )                           \
    do {                                        \
        /* Breaks tail recursion. */            \
        int ret__ = val;                        \
        TRACE_END( ret__ );                     \
        return( ret__ );                        \
    } while( 0 )

#else /* MBEDTLS_MPS_TRACE */

#define TRACE( type, ... ) do { } while( 0 )
#define TRACE_INIT( ... )  do { } while( 0 )
#define TRACE_END          do { } while( 0 )

#define RETURN( val ) return( val );

#endif /* MBEDTLS_MPS_TRACE */

#endif /* MBEDTLS_MPS_TRACE_H */
