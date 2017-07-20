/**
 * \file md5.h
 *
 * \brief MD5 message digest algorithm (hash function)
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
#ifndef MBEDTLS_MD5_H
#define MBEDTLS_MD5_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdint.h>

#if !defined(MBEDTLS_MD5_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          MD5 context structure
 */
typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[4];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
}
mbedtls_md5_context;

/**
 * \brief          Initialize MD5 context
 *
 * \param ctx      MD5 context to be initialized
 */
void mbedtls_md5_init( mbedtls_md5_context *ctx );

/**
 * \brief          Clear MD5 context
 *
 * \param ctx      MD5 context to be cleared
 */
void mbedtls_md5_free( mbedtls_md5_context *ctx );

/**
 * \brief          Clone (the state of) an MD5 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_md5_clone( mbedtls_md5_context *dst,
                        const mbedtls_md5_context *src );

/**
 * \brief          MD5 context setup
 *
 * \param ctx      context to be initialized
 *
 * \return         0 if successful
 */
int mbedtls_md5_starts_ext( mbedtls_md5_context *ctx );

/**
 * \brief          MD5 process buffer
 *
 * \param ctx      MD5 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \return         0 if successful
 */
int mbedtls_md5_update_ext( mbedtls_md5_context *ctx,
                            const unsigned char *input,
                            size_t ilen );

/**
 * \brief          MD5 final digest
 *
 * \param ctx      MD5 context
 * \param output   MD5 checksum result
 *
 * \return         0 if successful
 */
int mbedtls_md5_finish_ext( mbedtls_md5_context *ctx,
                            unsigned char output[16] );

/**
 * \brief          MD5 process data block (internal use only)
 *
 * \param ctx      MD5 context
 * \param data     buffer holding one block of data
 *
 * \return         0 if successful
 */
int mbedtls_internal_md5_process( mbedtls_md5_context *ctx,
                                  const unsigned char data[64] );

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#if defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_DEPRECATED      __attribute__((deprecated))
#else
#define MBEDTLS_DEPRECATED
#endif
/**
 * \brief          MD5 context setup
 *
 * \deprecated     Superseded by mbedtls_md5_starts_ext() in 2.5.0
 *
 * \param ctx      context to be initialized
 */
MBEDTLS_DEPRECATED static inline void mbedtls_md5_starts(
                                                    mbedtls_md5_context *ctx )
{
    mbedtls_md5_starts_ext( ctx );
}

/**
 * \brief          MD5 process buffer
 *
 * \deprecated     Superseded by mbedtls_md5_update_ext() in 2.5.0
 *
 * \param ctx      MD5 context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 */
MBEDTLS_DEPRECATED static inline void mbedtls_md5_update(
                                                    mbedtls_md5_context *ctx,
                                                    const unsigned char *input,
                                                    size_t ilen )
{
    mbedtls_md5_update_ext( ctx, input, ilen );
}

/**
 * \brief          MD5 final digest
 *
 * \deprecated     Superseded by mbedtls_md5_finish_ext() in 2.5.0
 *
 * \param ctx      MD5 context
 * \param output   MD5 checksum result
 */
MBEDTLS_DEPRECATED static inline void mbedtls_md5_finish(
                                                    mbedtls_md5_context *ctx,
                                                    unsigned char output[16] )
{
    mbedtls_md5_finish_ext( ctx, output );
}

/**
 * \brief          MD5 process data block (internal use only)
 *
 * \deprecated     Superseded by mbedtls_internal_md5_process() in 2.5.0
 *
 * \param ctx      MD5 context
 * \param data     buffer holding one block of data
 */
MBEDTLS_DEPRECATED static inline void mbedtls_md5_process(
                                                mbedtls_md5_context *ctx,
                                                const unsigned char data[64] )
{
    mbedtls_internal_md5_process( ctx, data );
}

#undef MBEDTLS_DEPRECATED
#endif /* !MBEDTLS_DEPRECATED_REMOVED */

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_MD5_ALT */
#include "md5_alt.h"
#endif /* MBEDTLS_MD5_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Output = MD5( input buffer )
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   MD5 checksum result
 *
 * \return         0 if successful
 */
int mbedtls_md5_ext( const unsigned char *input,
                     size_t ilen,
                     unsigned char output[16] );

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#if defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_DEPRECATED      __attribute__((deprecated))
#else
#define MBEDTLS_DEPRECATED
#endif
/**
 * \brief          Output = MD5( input buffer )
 *
 * \deprecated     Superseded by mbedtls_md5_ext() in 2.5.0
 *
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 * \param output   MD5 checksum result
 */
MBEDTLS_DEPRECATED static inline void mbedtls_md5( const unsigned char *input,
                                                   size_t ilen,
                                                   unsigned char output[16] )
{
    mbedtls_md5_ext( input, ilen, output );
}

#undef MBEDTLS_DEPRECATED
#endif /* !MBEDTLS_DEPRECATED_REMOVED */

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_md5_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_md5.h */
