 /**
 * \file md_internal.h
 *
 * \brief This file contains the generic message-digest wrapper.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 */
/*
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_MD_INTERNAL_H
#define MBEDTLS_MD_INTERNAL_H

#if defined(MBEDTLS_MD2_C)
#include "mbedtls/md2.h"
#endif

#if defined(MBEDTLS_MD4_C)
#include "mbedtls/md4.h"
#endif

#if defined(MBEDTLS_MD5_C)
#include "mbedtls/md5.h"
#endif

#if defined(MBEDTLS_RIPEMD160_C)
#include "mbedtls/ripemd160.h"
#endif

#if defined(MBEDTLS_SHA1_C)
#include "mbedtls/sha1.h"
#endif

#if defined(MBEDTLS_SHA256_C)
#include "mbedtls/sha256.h"
#endif

#if defined(MBEDTLS_SHA512_C)
#include "mbedtls/sha512.h"
#endif

#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_MD_WRAPPER MBEDTLS_ALWAYS_INLINE static inline

/*
 * Message-digest information macro definition
 */

/* Dummy definition to keep check-names.sh happy - don't uncomment */
//#define MBEDTLS_MD_INFO_SHA256

/* SHA-256 */
static inline void mbedtls_md_sha256_init_free_dummy( void* ctx )
{
    /* Zero-initialization can be skipped. */
    ((void) ctx);
}
#define MBEDTLS_MD_INFO_SHA256_TYPE         MBEDTLS_MD_SHA256
#define MBEDTLS_MD_INFO_SHA256_CTX_TYPE     mbedtls_sha256_context
#if defined(MBEDTLS_MD_SINGLE_HASH) && !defined(MBEDTLS_SHA256_ALT)
/* mbedtls_md_sha256_init() only zeroizes, which is redundant
 * because mbedtls_md_context is zeroized in mbedtls_md_init(),
 * and the mbedtls_sha256_context is embedded in mbedtls_md_context_t. */
#define MBEDTLS_MD_INFO_SHA256_INIT_FUNC    mbedtls_md_sha256_init_free_dummy
#else
#define MBEDTLS_MD_INFO_SHA256_INIT_FUNC    mbedtls_sha256_init
#endif /* MBEDTLS_MD_SINGLE_HASH && !MBEDTLS_SHA256_ALT */
#define MBEDTLS_MD_INFO_SHA256_NAME         "SHA256"
#define MBEDTLS_MD_INFO_SHA256_SIZE         32
#define MBEDTLS_MD_INFO_SHA256_BLOCKSIZE    64
#define MBEDTLS_MD_INFO_SHA256_STARTS_FUNC  mbedtls_sha256_starts_wrap
#define MBEDTLS_MD_INFO_SHA256_UPDATE_FUNC  mbedtls_sha224_update_wrap
#define MBEDTLS_MD_INFO_SHA256_FINISH_FUNC  mbedtls_sha224_finish_wrap
#define MBEDTLS_MD_INFO_SHA256_DIGEST_FUNC  mbedtls_sha256_wrap
#define MBEDTLS_MD_INFO_SHA256_ALLOC_FUNC   mbedtls_sha224_ctx_alloc
#if defined(MBEDTLS_MD_SINGLE_HASH) && !defined(MBEDTLS_SHA256_ALT)
/* mbedtls_md_sha256_free() only zeroizes, which is redundant
 * because mbedtls_md_context is zeroized in mbedtls_md_init(),
 * and the mbedtls_sha256_context is embedded in mbedtls_md_context_t. */
#define MBEDTLS_MD_INFO_SHA256_FREE_FUNC    mbedtls_md_sha256_init_free_dummy
#else
#define MBEDTLS_MD_INFO_SHA256_FREE_FUNC    mbedtls_sha224_ctx_free
#endif /* MBEDTLS_MD_SINGLE_HASH && !MBEDTLS_SHA256_ALT */
#define MBEDTLS_MD_INFO_SHA256_CLONE_FUNC   mbedtls_sha224_clone_wrap
#define MBEDTLS_MD_INFO_SHA256_PROCESS_FUNC mbedtls_sha224_process_wrap

/*
 * Helper macros to extract fields from ciphersuites.
 */

#define MBEDTLS_MD_INFO_CTX_TYPE_T( MD )     MD ## _CTX_TYPE
#define MBEDTLS_MD_INFO_INIT_FUNC_T( MD )    MD ## _INIT_FUNC
#define MBEDTLS_MD_INFO_TYPE_T( MD )         MD ## _TYPE
#define MBEDTLS_MD_INFO_NAME_T( MD )         MD ## _NAME
#define MBEDTLS_MD_INFO_SIZE_T( MD )         MD ## _SIZE
#define MBEDTLS_MD_INFO_BLOCKSIZE_T( MD )    MD ## _BLOCKSIZE
#define MBEDTLS_MD_INFO_STARTS_FUNC_T( MD )  MD ## _STARTS_FUNC
#define MBEDTLS_MD_INFO_UPDATE_FUNC_T( MD )  MD ## _UPDATE_FUNC
#define MBEDTLS_MD_INFO_FINISH_FUNC_T( MD )  MD ## _FINISH_FUNC
#define MBEDTLS_MD_INFO_DIGEST_FUNC_T( MD )  MD ## _DIGEST_FUNC
#define MBEDTLS_MD_INFO_ALLOC_FUNC_T( MD )   MD ## _ALLOC_FUNC
#define MBEDTLS_MD_INFO_FREE_FUNC_T( MD )    MD ## _FREE_FUNC
#define MBEDTLS_MD_INFO_CLONE_FUNC_T( MD )   MD ## _CLONE_FUNC
#define MBEDTLS_MD_INFO_PROCESS_FUNC_T( MD ) MD ## _PROCESS_FUNC

/* Wrapper around MBEDTLS_MD_INFO_{FIELD}_T() which makes sure that
 * the argument is macro-expanded before concatenated with the
 * field name. This allows to call these macros as
 *    MBEDTLS_MD_INFO_{FIELD}( MBEDTLS_MD_SINGLE_HASH ).
 * where MBEDTLS_MD_SINGLE_HASH expands to MBEDTLS_MD_INFO_{DIGEST}. */
#define MBEDTLS_MD_INFO_CTX_TYPE( MD )     MBEDTLS_MD_INFO_CTX_TYPE_T( MD )
#define MBEDTLS_MD_INFO_INIT_FUNC( MD )    MBEDTLS_MD_INFO_INIT_FUNC_T( MD )
#define MBEDTLS_MD_INFO_TYPE( MD )         MBEDTLS_MD_INFO_TYPE_T( MD )
#define MBEDTLS_MD_INFO_NAME( MD )         MBEDTLS_MD_INFO_NAME_T( MD )
#define MBEDTLS_MD_INFO_SIZE( MD )         MBEDTLS_MD_INFO_SIZE_T( MD )
#define MBEDTLS_MD_INFO_BLOCKSIZE( MD )    MBEDTLS_MD_INFO_BLOCKSIZE_T( MD )
#define MBEDTLS_MD_INFO_STARTS_FUNC( MD )  MBEDTLS_MD_INFO_STARTS_FUNC_T( MD )
#define MBEDTLS_MD_INFO_UPDATE_FUNC( MD )  MBEDTLS_MD_INFO_UPDATE_FUNC_T( MD )
#define MBEDTLS_MD_INFO_FINISH_FUNC( MD )  MBEDTLS_MD_INFO_FINISH_FUNC_T( MD )
#define MBEDTLS_MD_INFO_DIGEST_FUNC( MD )  MBEDTLS_MD_INFO_DIGEST_FUNC_T( MD )
#define MBEDTLS_MD_INFO_ALLOC_FUNC( MD )   MBEDTLS_MD_INFO_ALLOC_FUNC_T( MD )
#define MBEDTLS_MD_INFO_FREE_FUNC( MD )    MBEDTLS_MD_INFO_FREE_FUNC_T( MD )
#define MBEDTLS_MD_INFO_CLONE_FUNC( MD )   MBEDTLS_MD_INFO_CLONE_FUNC_T( MD )
#define MBEDTLS_MD_INFO_PROCESS_FUNC( MD ) MBEDTLS_MD_INFO_PROCESS_FUNC_T( MD )

/**
 * Message digest information.
 * Allows message digest functions to be called in a generic way.
 */

typedef int mbedtls_md_starts_func_t( void *ctx );
typedef int mbedtls_md_update_func_t( void *ctx,
                                       const unsigned char *input,
                                       size_t ilen );
typedef int mbedtls_md_finish_func_t( void *ctx, unsigned char *output );
typedef int mbedtls_md_digest_func_t( const unsigned char *input,
                                       size_t ilen,
                                       unsigned char *output );
typedef void* mbedtls_md_ctx_alloc_func_t( void );
typedef void mbedtls_md_ctx_free_func_t( void *ctx );
typedef void mbedtls_md_clone_func_t( void *st, const void *src );
typedef int mbedtls_md_process_func_t( void *ctx,
                                          const unsigned char *input );

#if !defined(MBEDTLS_MD_SINGLE_HASH)
struct mbedtls_md_info_t
{
    /** Digest identifier */
    mbedtls_md_type_t type;

    /** Name of the message digest */
    const char * name;

    /** Output length of the digest function in bytes */
    int size;

    /** Block length of the digest function in bytes */
    int block_size;

    /** Digest initialisation function */
    mbedtls_md_starts_func_t *starts_func;

    /** Digest update function */
    mbedtls_md_update_func_t *update_func;

    /** Digest finalisation function */
    mbedtls_md_finish_func_t *finish_func;

    /** Generic digest function */
    mbedtls_md_digest_func_t *digest_func;

    /** Allocate a new context */
    mbedtls_md_ctx_alloc_func_t *ctx_alloc_func;

    /** Free the given context */
    mbedtls_md_ctx_free_func_t *ctx_free_func;

    /** Clone state from a context */
    mbedtls_md_clone_func_t *clone_func;

    /** Internal use only */
    mbedtls_md_process_func_t *process_func;
};

/**
 * \brief   This macro builds an instance of ::mbedtls_md_info_t
 *          from an \c MBEDTLS_MD_INFO_XXX identifier.
 */
#define MBEDTLS_MD_INFO( MD )                  \
    { MBEDTLS_MD_INFO_TYPE( MD ),              \
      MBEDTLS_MD_INFO_NAME( MD ),              \
      MBEDTLS_MD_INFO_SIZE( MD ),              \
      MBEDTLS_MD_INFO_BLOCKSIZE( MD ),         \
      MBEDTLS_MD_INFO_STARTS_FUNC(  MD ),      \
      MBEDTLS_MD_INFO_UPDATE_FUNC( MD ),       \
      MBEDTLS_MD_INFO_FINISH_FUNC( MD ),       \
      MBEDTLS_MD_INFO_DIGEST_FUNC( MD ),       \
      MBEDTLS_MD_INFO_ALLOC_FUNC( MD ),        \
      MBEDTLS_MD_INFO_FREE_FUNC( MD ),         \
      MBEDTLS_MD_INFO_CLONE_FUNC( MD ),        \
      MBEDTLS_MD_INFO_PROCESS_FUNC( MD ) }

#endif /* !MBEDTLS_MD_SINGLE_HASH */

/*
 *
 * Definitions of MD information structures for various digests.
 *
 */

/*
 * MD-2
 */

#if defined(MBEDTLS_MD2_C)

MBEDTLS_MD_WRAPPER int mbedtls_md2_starts_wrap( void *ctx )
{
    return( mbedtls_md2_starts_ret( (mbedtls_md2_context *) ctx ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_md2_update_wrap( void *ctx, const unsigned char *input,
                             size_t ilen )
{
    return( mbedtls_md2_update_ret( (mbedtls_md2_context *) ctx, input, ilen ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_md2_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_md2_finish_ret( (mbedtls_md2_context *) ctx, output ) );
}

MBEDTLS_MD_WRAPPER void* mbedtls_md2_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_md2_context ) );

    if( ctx != NULL )
        mbedtls_md2_init( (mbedtls_md2_context *) ctx );

    return( ctx );
}

MBEDTLS_MD_WRAPPER void mbedtls_md2_ctx_free( void *ctx )
{
    mbedtls_md2_free( (mbedtls_md2_context *) ctx );
    mbedtls_free( ctx );
}

MBEDTLS_MD_WRAPPER void mbedtls_md2_clone_wrap( void *dst, const void *src )
{
    mbedtls_md2_clone( (mbedtls_md2_context *) dst,
                 (const mbedtls_md2_context *) src );
}

MBEDTLS_MD_WRAPPER int mbedtls_md2_process_wrap( void *ctx, const unsigned char *data )
{
    ((void) data);

    return( mbedtls_internal_md2_process( (mbedtls_md2_context *) ctx ) );
}

#endif /* MBEDTLS_MD2_C */

/*
 * MD-4
 */

#if defined(MBEDTLS_MD4_C)

MBEDTLS_MD_WRAPPER int mbedtls_md4_starts_wrap( void *ctx )
{
    return( mbedtls_md4_starts_ret( (mbedtls_md4_context *) ctx ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_md4_update_wrap( void *ctx, const unsigned char *input,
                             size_t ilen )
{
    return( mbedtls_md4_update_ret( (mbedtls_md4_context *) ctx, input, ilen ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_md4_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_md4_finish_ret( (mbedtls_md4_context *) ctx, output ) );
}

MBEDTLS_MD_WRAPPER void* mbedtls_md4_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_md4_context ) );

    if( ctx != NULL )
        mbedtls_md4_init( (mbedtls_md4_context *) ctx );

    return( ctx );
}

MBEDTLS_MD_WRAPPER void mbedtls_md4_ctx_free( void *ctx )
{
    mbedtls_md4_free( (mbedtls_md4_context *) ctx );
    mbedtls_free( ctx );
}

MBEDTLS_MD_WRAPPER void mbedtls_md4_clone_wrap( void *dst, const void *src )
{
    mbedtls_md4_clone( (mbedtls_md4_context *) dst,
                       (const mbedtls_md4_context *) src );
}

MBEDTLS_MD_WRAPPER int mbedtls_md4_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedtls_internal_md4_process( (mbedtls_md4_context *) ctx, data ) );
}

#endif /* MBEDTLS_MD4_C */

/*
 * MD-5
 */

#if defined(MBEDTLS_MD5_C)

MBEDTLS_MD_WRAPPER int mbedtls_md5_starts_wrap( void *ctx )
{
    return( mbedtls_md5_starts_ret( (mbedtls_md5_context *) ctx ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_md5_update_wrap( void *ctx, const unsigned char *input,
                             size_t ilen )
{
    return( mbedtls_md5_update_ret( (mbedtls_md5_context *) ctx, input, ilen ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_md5_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_md5_finish_ret( (mbedtls_md5_context *) ctx, output ) );
}

MBEDTLS_MD_WRAPPER void* mbedtls_md5_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_md5_context ) );

    if( ctx != NULL )
        mbedtls_md5_init( (mbedtls_md5_context *) ctx );

    return( ctx );
}

MBEDTLS_MD_WRAPPER void mbedtls_md5_ctx_free( void *ctx )
{
    mbedtls_md5_free( (mbedtls_md5_context *) ctx );
    mbedtls_free( ctx );
}

MBEDTLS_MD_WRAPPER void mbedtls_md5_clone_wrap( void *dst, const void *src )
{
    mbedtls_md5_clone( (mbedtls_md5_context *) dst,
                       (const mbedtls_md5_context *) src );
}

MBEDTLS_MD_WRAPPER int mbedtls_md5_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedtls_internal_md5_process( (mbedtls_md5_context *) ctx, data ) );
}

#endif /* MBEDTLS_MD5_C */

/*
 * RIPEMD-160
 */

#if defined(MBEDTLS_RIPEMD160_C)

MBEDTLS_MD_WRAPPER int mbedtls_ripemd160_starts_wrap( void *ctx )
{
    return( mbedtls_ripemd160_starts_ret( (mbedtls_ripemd160_context *) ctx ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_ripemd160_update_wrap( void *ctx, const unsigned char *input,
                                   size_t ilen )
{
    return( mbedtls_ripemd160_update_ret( (mbedtls_ripemd160_context *) ctx,
                                          input, ilen ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_ripemd160_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_ripemd160_finish_ret( (mbedtls_ripemd160_context *) ctx,
                                          output ) );
}

MBEDTLS_MD_WRAPPER void* mbedtls_ripemd160_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_ripemd160_context ) );

    if( ctx != NULL )
        mbedtls_ripemd160_init( (mbedtls_ripemd160_context *) ctx );

    return( ctx );
}

MBEDTLS_MD_WRAPPER void mbedtls_ripemd160_ctx_free( void *ctx )
{
    mbedtls_ripemd160_free( (mbedtls_ripemd160_context *) ctx );
    mbedtls_free( ctx );
}

MBEDTLS_MD_WRAPPER void mbedtls_ripemd160_clone_wrap( void *dst, const void *src )
{
    mbedtls_ripemd160_clone( (mbedtls_ripemd160_context *) dst,
                       (const mbedtls_ripemd160_context *) src );
}

MBEDTLS_MD_WRAPPER int mbedtls_ripemd160_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedtls_internal_ripemd160_process(
                                (mbedtls_ripemd160_context *) ctx, data ) );
}

#endif /* MBEDTLS_RIPEMD160_C */

/*
 * SHA-1
 */

#if defined(MBEDTLS_SHA1_C)

MBEDTLS_MD_WRAPPER int mbedtls_sha1_starts_wrap( void *ctx )
{
    return( mbedtls_sha1_starts_ret( (mbedtls_sha1_context *) ctx ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_sha1_update_wrap( void *ctx, const unsigned char *input,
                              size_t ilen )
{
    return( mbedtls_sha1_update_ret( (mbedtls_sha1_context *) ctx,
                                     input, ilen ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_sha1_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_sha1_finish_ret( (mbedtls_sha1_context *) ctx, output ) );
}

MBEDTLS_MD_WRAPPER void* mbedtls_sha1_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_sha1_context ) );

    if( ctx != NULL )
        mbedtls_sha1_init( (mbedtls_sha1_context *) ctx );

    return( ctx );
}

MBEDTLS_MD_WRAPPER void mbedtls_sha1_clone_wrap( void *dst, const void *src )
{
    mbedtls_sha1_clone( (mbedtls_sha1_context *) dst,
                  (const mbedtls_sha1_context *) src );
}

MBEDTLS_MD_WRAPPER void mbedtls_sha1_ctx_free( void *ctx )
{
    mbedtls_sha1_free( (mbedtls_sha1_context *) ctx );
    mbedtls_free( ctx );
}

MBEDTLS_MD_WRAPPER int mbedtls_sha1_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedtls_internal_sha1_process( (mbedtls_sha1_context *) ctx,
                                           data ) );
}

#endif /* MBEDTLS_SHA1_C */

/*
 * SHA-224 and SHA-256
 */

#if defined(MBEDTLS_SHA256_C)

#if !defined(MBEDTLS_SHA256_NO_SHA224)
MBEDTLS_MD_WRAPPER int mbedtls_sha224_starts_wrap( void *ctx )
{
    return( mbedtls_sha256_starts_ret( (mbedtls_sha256_context *) ctx, 1 ) );
}
#endif /* !MBEDTLS_SHA256_NO_SHA224 */

MBEDTLS_MD_WRAPPER int mbedtls_sha224_update_wrap( void *ctx, const unsigned char *input,
                                size_t ilen )
{
    return( mbedtls_sha256_update_ret( (mbedtls_sha256_context *) ctx,
                                       input, ilen ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_sha224_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_sha256_finish_ret( (mbedtls_sha256_context *) ctx,
                                       output ) );
}

#if !defined(MBEDTLS_SHA256_NO_SHA224)
MBEDTLS_MD_WRAPPER int mbedtls_sha224_wrap( const unsigned char *input, size_t ilen,
                        unsigned char *output )
{
    return( mbedtls_sha256_ret( input, ilen, output, 1 ) );
}
#endif /* !MBEDTLS_SHA256_NO_SHA224 */

MBEDTLS_MD_WRAPPER void* mbedtls_sha224_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_sha256_context ) );

    if( ctx != NULL )
        mbedtls_sha256_init( (mbedtls_sha256_context *) ctx );

    return( ctx );
}

MBEDTLS_MD_WRAPPER void mbedtls_sha224_ctx_free( void *ctx )
{
    mbedtls_sha256_free( (mbedtls_sha256_context *) ctx );
    mbedtls_free( ctx );
}

MBEDTLS_MD_WRAPPER void mbedtls_sha224_clone_wrap( void *dst, const void *src )
{
    mbedtls_sha256_clone( (mbedtls_sha256_context *) dst,
                    (const mbedtls_sha256_context *) src );
}

MBEDTLS_MD_WRAPPER int mbedtls_sha224_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedtls_internal_sha256_process( (mbedtls_sha256_context *) ctx,
                                             data ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_sha256_starts_wrap( void *ctx )
{
    return( mbedtls_sha256_starts_ret( (mbedtls_sha256_context *) ctx, 0 ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_sha256_wrap( const unsigned char *input, size_t ilen,
                        unsigned char *output )
{
    return( mbedtls_sha256_ret( input, ilen, output, 0 ) );
}

#endif /* MBEDTLS_SHA256_C */

/*
 * SHA-384 and SHA-512
 */

#if defined(MBEDTLS_SHA512_C)

MBEDTLS_MD_WRAPPER int mbedtls_sha384_starts_wrap( void *ctx )
{
    return( mbedtls_sha512_starts_ret( (mbedtls_sha512_context *) ctx, 1 ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_sha384_update_wrap( void *ctx, const unsigned char *input,
                               size_t ilen )
{
    return( mbedtls_sha512_update_ret( (mbedtls_sha512_context *) ctx,
                                       input, ilen ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_sha384_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_sha512_finish_ret( (mbedtls_sha512_context *) ctx,
                                       output ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_sha384_wrap( const unsigned char *input, size_t ilen,
                        unsigned char *output )
{
    return( mbedtls_sha512_ret( input, ilen, output, 1 ) );
}

MBEDTLS_MD_WRAPPER void* mbedtls_sha384_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_sha512_context ) );

    if( ctx != NULL )
        mbedtls_sha512_init( (mbedtls_sha512_context *) ctx );

    return( ctx );
}

MBEDTLS_MD_WRAPPER void mbedtls_sha384_ctx_free( void *ctx )
{
    mbedtls_sha512_free( (mbedtls_sha512_context *) ctx );
    mbedtls_free( ctx );
}

MBEDTLS_MD_WRAPPER void mbedtls_sha384_clone_wrap( void *dst, const void *src )
{
    mbedtls_sha512_clone( (mbedtls_sha512_context *) dst,
                    (const mbedtls_sha512_context *) src );
}

MBEDTLS_MD_WRAPPER int mbedtls_sha384_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedtls_internal_sha512_process( (mbedtls_sha512_context *) ctx,
                                             data ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_sha512_starts_wrap( void *ctx )
{
    return( mbedtls_sha512_starts_ret( (mbedtls_sha512_context *) ctx, 0 ) );
}

MBEDTLS_MD_WRAPPER int mbedtls_sha512_wrap( const unsigned char *input, size_t ilen,
                        unsigned char *output )
{
    return( mbedtls_sha512_ret( input, ilen, output, 0 ) );
}

#endif /* MBEDTLS_SHA512_C */

/*
 * Getter functions for MD info structure.
 */

#if !defined(MBEDTLS_MD_SINGLE_HASH)

MBEDTLS_ALWAYS_INLINE static inline mbedtls_md_type_t mbedtls_md_info_type(
    mbedtls_md_handle_t info )
{
    return( info->type );
}

MBEDTLS_ALWAYS_INLINE static inline const char * mbedtls_md_info_name(
    mbedtls_md_handle_t info )
{
    return( info->name );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_size(
    mbedtls_md_handle_t info )
{
    return( info->size );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_block_size(
    mbedtls_md_handle_t info )
{
    return( info->block_size );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_starts(
    mbedtls_md_handle_t info,
    void *ctx )
{
    return( info->starts_func( ctx ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_update(
    mbedtls_md_handle_t info,
    void *ctx,
    const unsigned char *input,
    size_t ilen )
{
    return( info->update_func( ctx, input, ilen ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_finish(
    mbedtls_md_handle_t info,
    void *ctx,
    unsigned char *output )
{
    return( info->finish_func( ctx, output ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_digest(
    mbedtls_md_handle_t info,
    const unsigned char *input,
    size_t ilen,
    unsigned char *output )
{
    return( info->digest_func( input, ilen, output ) );
}

MBEDTLS_ALWAYS_INLINE static inline void* mbedtls_md_info_ctx_alloc(
    mbedtls_md_handle_t info )
{
    return( info->ctx_alloc_func() );
}

MBEDTLS_ALWAYS_INLINE static inline void mbedtls_md_info_ctx_free(
    mbedtls_md_handle_t info,
    void *ctx )
{
    info->ctx_free_func( ctx );
}

MBEDTLS_ALWAYS_INLINE static inline void mbedtls_md_info_clone(
    mbedtls_md_handle_t info,
    void *dst,
    const void *src )
{
    info->clone_func( dst, src );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_process(
    mbedtls_md_handle_t info,
    void *ctx,
    const unsigned char *input )
{
    return( info->process_func( ctx, input ) );
}

#else /* !MBEDTLS_MD_SINGLE_HASH */

MBEDTLS_ALWAYS_INLINE static inline mbedtls_md_type_t mbedtls_md_info_type(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_TYPE( MBEDTLS_MD_SINGLE_HASH ) );
}

MBEDTLS_ALWAYS_INLINE static inline const char * mbedtls_md_info_name(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_NAME( MBEDTLS_MD_SINGLE_HASH ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_size(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_SIZE( MBEDTLS_MD_SINGLE_HASH ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_block_size(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_BLOCKSIZE( MBEDTLS_MD_SINGLE_HASH ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_starts(
    mbedtls_md_handle_t info,
    void *ctx )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_STARTS_FUNC( MBEDTLS_MD_SINGLE_HASH )( ctx ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_update(
    mbedtls_md_handle_t info,
    void *ctx,
    const unsigned char *input,
    size_t ilen )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_UPDATE_FUNC( MBEDTLS_MD_SINGLE_HASH )
            ( ctx, input, ilen ) );
}

MBEDTLS_ALWAYS_INLINE static inline void mbedtls_md_info_init(
    mbedtls_md_handle_t info,
    void *ctx )
{
    ((void) info);
    MBEDTLS_MD_INFO_INIT_FUNC( MBEDTLS_MD_SINGLE_HASH )( ctx );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_finish(
    mbedtls_md_handle_t info,
    void *ctx,
    unsigned char *output )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_FINISH_FUNC( MBEDTLS_MD_SINGLE_HASH )
            ( ctx, output ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_digest(
    mbedtls_md_handle_t info,
    const unsigned char *input,
    size_t ilen,
    unsigned char *output )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_DIGEST_FUNC( MBEDTLS_MD_SINGLE_HASH )
            ( input, ilen, output ) );
}

MBEDTLS_ALWAYS_INLINE static inline void* mbedtls_md_info_ctx_alloc(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_ALLOC_FUNC( MBEDTLS_MD_SINGLE_HASH )() );
}

MBEDTLS_ALWAYS_INLINE static inline void mbedtls_md_info_ctx_free(
    mbedtls_md_handle_t info,
    void *ctx )
{
    ((void) info);
    MBEDTLS_MD_INFO_FREE_FUNC( MBEDTLS_MD_SINGLE_HASH )( ctx );
}

MBEDTLS_ALWAYS_INLINE static inline void mbedtls_md_info_clone(
    mbedtls_md_handle_t info,
    void *dst,
    const void *src )
{
    ((void) info);
    MBEDTLS_MD_INFO_CLONE_FUNC( MBEDTLS_MD_SINGLE_HASH )( dst, src );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_md_info_process(
    mbedtls_md_handle_t info,
    void *ctx,
    const unsigned char *input )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_PROCESS_FUNC( MBEDTLS_MD_SINGLE_HASH )
            ( ctx, input ) );
}

#endif /* MBEDTLS_MD_SINGLE_HASH */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_MD_INTERNAL_H */
