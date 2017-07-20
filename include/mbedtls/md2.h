/**
 * \file md2.h
 *
 * \brief MD2 message digest algorithm (hash function)
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
#ifndef MBEDTLS_MD2_H
#define MBEDTLS_MD2_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#if !defined(MBEDTLS_MD2_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          MD2 context structure
 */
typedef struct
{
    unsigned char cksum[16];    /*!< checksum of the data block */
    unsigned char state[48];    /*!< intermediate digest state  */
    unsigned char buffer[16];   /*!< data block being processed */
    size_t left;                /*!< amount of data in buffer   */
}
mbedtls_md2_context;

/**
 * \brief          Initialize MD2 context
 *
 * \param ctx      MD2 context to be initialized
 */
void mbedtls_md2_init( mbedtls_md2_context *ctx );

/**
 * \brief          Clear MD2 context
 *
 * \param ctx      MD2 context to be cleared
 */
void mbedtls_md2_free( mbedtls_md2_context *ctx );

/**
 * \brief          Clone (the state of) an MD2 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_md2_clone( mbedtls_md2_context *dst,
                        const mbedtls_md2_context *src );

/**
 * \brief          MD2 context setup
 *
 * \param ctx      context to be initialized
 *
 * \return         0 if successful
 */
int mbedtls_md2_starts_ext( mbedtls_md2_context *ctx );

/**
 * \brief          MD2 process buffer
 *
 * \param ctx      MD2 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \return         0 if successful
 */
int mbedtls_md2_update_ext( mbedtls_md2_context *ctx,
                            const unsigned char *input,
                            size_t ilen );

/**
 * \brief          MD2 final digest
 *
 * \param ctx      MD2 context
 * \param output   MD2 checksum result
 *
 * \return         0 if successful
 */
int mbedtls_md2_finish_ext( mbedtls_md2_context *ctx,
                            unsigned char output[16] );

/**
 * \brief          MD2 process data block (internal use only)
 *
 * \param ctx      MD2 context
 *
 * \return         0 if successful
 */
int mbedtls_internal_md2_process( mbedtls_md2_context *ctx );

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#if defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_DEPRECATED      __attribute__((deprecated))
#else
#define MBEDTLS_DEPRECATED
#endif
/**
 * \brief          MD2 context setup
 *
 * \deprecated     Superseded by mbedtls_md2_starts_ext() in 2.5.0
 *
 * \param ctx      context to be initialized
 */
MBEDTLS_DEPRECATED static inline void mbedtls_md2_starts(
                                                    mbedtls_md2_context *ctx )
{
    mbedtls_md2_starts_ext( ctx );
}

/**
 * \brief          MD2 process buffer
 *
 * \deprecated     Superseded by mbedtls_md2_update_ext() in 2.5.0
 *
 * \param ctx      MD2 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 */
MBEDTLS_DEPRECATED static inline void mbedtls_md2_update(
                                                mbedtls_md2_context *ctx,
                                                const unsigned char *input,
                                                size_t ilen )
{
    mbedtls_md2_update_ext( ctx, input, ilen );
}

/**
 * \brief          MD2 final digest
 *
 * \deprecated     Superseded by mbedtls_md2_finish_ext() in 2.5.0
 *
 * \param ctx      MD2 context
 * \param output   MD2 checksum result
 */
MBEDTLS_DEPRECATED static inline void mbedtls_md2_finish(
                                                    mbedtls_md2_context *ctx,
                                                    unsigned char output[16] )
{
    mbedtls_md2_finish_ext( ctx, output );
}

/**
 * \brief          MD2 process data block (internal use only)
 *
 * \deprecated     Superseded by mbedtls_internal_md2_process() in 2.5.0
 *
 * \param ctx      MD2 context
 */
MBEDTLS_DEPRECATED static inline void mbedtls_md2_process(
                                                    mbedtls_md2_context *ctx )
{
    mbedtls_internal_md2_process( ctx );
}

#undef MBEDTLS_DEPRECATED
#endif /* !MBEDTLS_DEPRECATED_REMOVED */

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_MD2_ALT */
#include "md2_alt.h"
#endif /* MBEDTLS_MD2_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Output = MD2( input buffer )
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   MD2 checksum result
 */
int mbedtls_md2_ext( const unsigned char *input,
                     size_t ilen,
                     unsigned char output[16] );

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#if defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_DEPRECATED      __attribute__((deprecated))
#else
#define MBEDTLS_DEPRECATED
#endif
/**
 * \brief          Output = MD2( input buffer )
 *
 * \deprecated     Superseded by mbedtls_md2() in 2.5.0
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   MD2 checksum result
 */
MBEDTLS_DEPRECATED static inline void mbedtls_md2( const unsigned char *input,
                                                   size_t ilen,
                                                   unsigned char output[16] )
{
    mbedtls_md2_ext( input, ilen, output );
}

#undef MBEDTLS_DEPRECATED
#endif /* !MBEDTLS_DEPRECATED_REMOVED */

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_md2_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_md2.h */
