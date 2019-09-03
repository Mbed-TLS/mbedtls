/**
 * \file mbedtls_md.c
 *
 * \brief Generic message digest wrapper for mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_MD_C)

#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include <string.h>

#if defined(MBEDTLS_FS_IO)
#include <stdio.h>
#endif

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

/*
 * Message-digest information macro definition
 */

/* SHA-256 */
#define MBEDTLS_MD_INFO_SHA256_TYPE         MBEDTLS_MD_SHA256
#define MBEDTLS_MD_INFO_SHA256_NAME         "SHA256"
#define MBEDTLS_MD_INFO_SHA256_SIZE         32
#define MBEDTLS_MD_INFO_SHA256_BLOCKSIZE    64
#define MBEDTLS_MD_INFO_SHA256_STARTS_FUNC  sha256_starts_wrap
#define MBEDTLS_MD_INFO_SHA256_UPDATE_FUNC  sha224_update_wrap
#define MBEDTLS_MD_INFO_SHA256_FINISH_FUNC  sha224_finish_wrap
#define MBEDTLS_MD_INFO_SHA256_DIGEST_FUNC  sha256_wrap
#define MBEDTLS_MD_INFO_SHA256_ALLOC_FUNC   sha224_ctx_alloc
#define MBEDTLS_MD_INFO_SHA256_FREE_FUNC    sha224_ctx_free
#define MBEDTLS_MD_INFO_SHA256_CLONE_FUNC   sha224_clone_wrap
#define MBEDTLS_MD_INFO_SHA256_PROCESS_FUNC sha224_process_wrap

/*
 * Helper macros to extract fields from ciphersuites.
 */

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

/* Wrapper around MBEDTLS_MD_INFO_XXX_T() which makes sure that
 * the argument is macro-expanded before concatenated with the
 * field name. This allows to call these macros as
 *    MBEDTLS_MD_INFO_XXX( MBEDTLS_SSL_CONF_SINGLE_HASH ).
 * where MBEDTLS_SSL_CONF_SINGLE_HASH expands to MBEDTLS_MD_INFO_XXX. */
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

static int md2_starts_wrap( void *ctx )
{
    return( mbedtls_md2_starts_ret( (mbedtls_md2_context *) ctx ) );
}

static int md2_update_wrap( void *ctx, const unsigned char *input,
                             size_t ilen )
{
    return( mbedtls_md2_update_ret( (mbedtls_md2_context *) ctx, input, ilen ) );
}

static int md2_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_md2_finish_ret( (mbedtls_md2_context *) ctx, output ) );
}

static void *md2_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_md2_context ) );

    if( ctx != NULL )
        mbedtls_md2_init( (mbedtls_md2_context *) ctx );

    return( ctx );
}

static void md2_ctx_free( void *ctx )
{
    mbedtls_md2_free( (mbedtls_md2_context *) ctx );
    mbedtls_free( ctx );
}

static void md2_clone_wrap( void *dst, const void *src )
{
    mbedtls_md2_clone( (mbedtls_md2_context *) dst,
                 (const mbedtls_md2_context *) src );
}

static int md2_process_wrap( void *ctx, const unsigned char *data )
{
    ((void) data);

    return( mbedtls_internal_md2_process( (mbedtls_md2_context *) ctx ) );
}

#if !defined(MBEDTLS_MD_SINGLE_HASH)
const mbedtls_md_info_t mbedtls_md2_info = {
    MBEDTLS_MD_MD2,
    "MD2",
    16,
    16,
    md2_starts_wrap,
    md2_update_wrap,
    md2_finish_wrap,
    mbedtls_md2_ret,
    md2_ctx_alloc,
    md2_ctx_free,
    md2_clone_wrap,
    md2_process_wrap,
};
#endif /* !MBEDTLS_MD_SINGLE_HASH */

#endif /* MBEDTLS_MD2_C */

/*
 * MD-4
 */

#if defined(MBEDTLS_MD4_C)

static int md4_starts_wrap( void *ctx )
{
    return( mbedtls_md4_starts_ret( (mbedtls_md4_context *) ctx ) );
}

static int md4_update_wrap( void *ctx, const unsigned char *input,
                             size_t ilen )
{
    return( mbedtls_md4_update_ret( (mbedtls_md4_context *) ctx, input, ilen ) );
}

static int md4_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_md4_finish_ret( (mbedtls_md4_context *) ctx, output ) );
}

static void *md4_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_md4_context ) );

    if( ctx != NULL )
        mbedtls_md4_init( (mbedtls_md4_context *) ctx );

    return( ctx );
}

static void md4_ctx_free( void *ctx )
{
    mbedtls_md4_free( (mbedtls_md4_context *) ctx );
    mbedtls_free( ctx );
}

static void md4_clone_wrap( void *dst, const void *src )
{
    mbedtls_md4_clone( (mbedtls_md4_context *) dst,
                       (const mbedtls_md4_context *) src );
}

static int md4_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedtls_internal_md4_process( (mbedtls_md4_context *) ctx, data ) );
}

#if !defined(MBEDTLS_MD_SINGLE_HASH)
const mbedtls_md_info_t mbedtls_md4_info = {
    MBEDTLS_MD_MD4,
    "MD4",
    16,
    64,
    md4_starts_wrap,
    md4_update_wrap,
    md4_finish_wrap,
    mbedtls_md4_ret,
    md4_ctx_alloc,
    md4_ctx_free,
    md4_clone_wrap,
    md4_process_wrap,
};
#endif /* MBEDTLS_MD_SINGLE_HASH */

#endif /* MBEDTLS_MD4_C */

/*
 * MD-5
 */

#if defined(MBEDTLS_MD5_C)

static int md5_starts_wrap( void *ctx )
{
    return( mbedtls_md5_starts_ret( (mbedtls_md5_context *) ctx ) );
}

static int md5_update_wrap( void *ctx, const unsigned char *input,
                             size_t ilen )
{
    return( mbedtls_md5_update_ret( (mbedtls_md5_context *) ctx, input, ilen ) );
}

static int md5_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_md5_finish_ret( (mbedtls_md5_context *) ctx, output ) );
}

static void *md5_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_md5_context ) );

    if( ctx != NULL )
        mbedtls_md5_init( (mbedtls_md5_context *) ctx );

    return( ctx );
}

static void md5_ctx_free( void *ctx )
{
    mbedtls_md5_free( (mbedtls_md5_context *) ctx );
    mbedtls_free( ctx );
}

static void md5_clone_wrap( void *dst, const void *src )
{
    mbedtls_md5_clone( (mbedtls_md5_context *) dst,
                       (const mbedtls_md5_context *) src );
}

static int md5_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedtls_internal_md5_process( (mbedtls_md5_context *) ctx, data ) );
}

#if !defined(MBEDTLS_MD_SINGLE_HASH)
const mbedtls_md_info_t mbedtls_md5_info = {
    MBEDTLS_MD_MD5,
    "MD5",
    16,
    64,
    md5_starts_wrap,
    md5_update_wrap,
    md5_finish_wrap,
    mbedtls_md5_ret,
    md5_ctx_alloc,
    md5_ctx_free,
    md5_clone_wrap,
    md5_process_wrap,
};
#endif /* MBEDTLS_MD_SINGLE_HASH */

#endif /* MBEDTLS_MD5_C */

/*
 * RIPEMD-160
 */

#if defined(MBEDTLS_RIPEMD160_C)

static int ripemd160_starts_wrap( void *ctx )
{
    return( mbedtls_ripemd160_starts_ret( (mbedtls_ripemd160_context *) ctx ) );
}

static int ripemd160_update_wrap( void *ctx, const unsigned char *input,
                                   size_t ilen )
{
    return( mbedtls_ripemd160_update_ret( (mbedtls_ripemd160_context *) ctx,
                                          input, ilen ) );
}

static int ripemd160_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_ripemd160_finish_ret( (mbedtls_ripemd160_context *) ctx,
                                          output ) );
}

static void *ripemd160_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_ripemd160_context ) );

    if( ctx != NULL )
        mbedtls_ripemd160_init( (mbedtls_ripemd160_context *) ctx );

    return( ctx );
}

static void ripemd160_ctx_free( void *ctx )
{
    mbedtls_ripemd160_free( (mbedtls_ripemd160_context *) ctx );
    mbedtls_free( ctx );
}

static void ripemd160_clone_wrap( void *dst, const void *src )
{
    mbedtls_ripemd160_clone( (mbedtls_ripemd160_context *) dst,
                       (const mbedtls_ripemd160_context *) src );
}

static int ripemd160_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedtls_internal_ripemd160_process(
                                (mbedtls_ripemd160_context *) ctx, data ) );
}

#if !defined(MBEDTLS_MD_SINGLE_HASH)
const mbedtls_md_info_t mbedtls_ripemd160_info = {
    MBEDTLS_MD_RIPEMD160,
    "RIPEMD160",
    20,
    64,
    ripemd160_starts_wrap,
    ripemd160_update_wrap,
    ripemd160_finish_wrap,
    mbedtls_ripemd160_ret,
    ripemd160_ctx_alloc,
    ripemd160_ctx_free,
    ripemd160_clone_wrap,
    ripemd160_process_wrap,
};
#endif /* !MBEDTLS_MD_SINGLE_HASH */

#endif /* MBEDTLS_RIPEMD160_C */

/*
 * SHA-1
 */

#if defined(MBEDTLS_SHA1_C)

static int sha1_starts_wrap( void *ctx )
{
    return( mbedtls_sha1_starts_ret( (mbedtls_sha1_context *) ctx ) );
}

static int sha1_update_wrap( void *ctx, const unsigned char *input,
                              size_t ilen )
{
    return( mbedtls_sha1_update_ret( (mbedtls_sha1_context *) ctx,
                                     input, ilen ) );
}

static int sha1_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_sha1_finish_ret( (mbedtls_sha1_context *) ctx, output ) );
}

static void *sha1_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_sha1_context ) );

    if( ctx != NULL )
        mbedtls_sha1_init( (mbedtls_sha1_context *) ctx );

    return( ctx );
}

static void sha1_clone_wrap( void *dst, const void *src )
{
    mbedtls_sha1_clone( (mbedtls_sha1_context *) dst,
                  (const mbedtls_sha1_context *) src );
}

static void sha1_ctx_free( void *ctx )
{
    mbedtls_sha1_free( (mbedtls_sha1_context *) ctx );
    mbedtls_free( ctx );
}

static int sha1_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedtls_internal_sha1_process( (mbedtls_sha1_context *) ctx,
                                           data ) );
}

#if !defined(MBEDTLS_MD_SINGLE_HASH)
const mbedtls_md_info_t mbedtls_sha1_info = {
    MBEDTLS_MD_SHA1,
    "SHA1",
    20,
    64,
    sha1_starts_wrap,
    sha1_update_wrap,
    sha1_finish_wrap,
    mbedtls_sha1_ret,
    sha1_ctx_alloc,
    sha1_ctx_free,
    sha1_clone_wrap,
    sha1_process_wrap,
};
#endif /* !MBEDTLS_MD_SINGLE_HASH */

#endif /* MBEDTLS_SHA1_C */

/*
 * SHA-224 and SHA-256
 */

#if defined(MBEDTLS_SHA256_C)

#if !defined(MBEDTLS_SHA256_NO_SHA224)
static int sha224_starts_wrap( void *ctx )
{
    return( mbedtls_sha256_starts_ret( (mbedtls_sha256_context *) ctx, 1 ) );
}
#endif /* !MBEDTLS_SHA256_NO_SHA224 */

static int sha224_update_wrap( void *ctx, const unsigned char *input,
                                size_t ilen )
{
    return( mbedtls_sha256_update_ret( (mbedtls_sha256_context *) ctx,
                                       input, ilen ) );
}

static int sha224_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_sha256_finish_ret( (mbedtls_sha256_context *) ctx,
                                       output ) );
}

#if !defined(MBEDTLS_SHA256_NO_SHA224)
static int sha224_wrap( const unsigned char *input, size_t ilen,
                        unsigned char *output )
{
    return( mbedtls_sha256_ret( input, ilen, output, 1 ) );
}
#endif /* !MBEDTLS_SHA256_NO_SHA224 */

static void *sha224_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_sha256_context ) );

    if( ctx != NULL )
        mbedtls_sha256_init( (mbedtls_sha256_context *) ctx );

    return( ctx );
}

static void sha224_ctx_free( void *ctx )
{
    mbedtls_sha256_free( (mbedtls_sha256_context *) ctx );
    mbedtls_free( ctx );
}

static void sha224_clone_wrap( void *dst, const void *src )
{
    mbedtls_sha256_clone( (mbedtls_sha256_context *) dst,
                    (const mbedtls_sha256_context *) src );
}

static int sha224_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedtls_internal_sha256_process( (mbedtls_sha256_context *) ctx,
                                             data ) );
}

#if !defined(MBEDTLS_MD_SINGLE_HASH)
#if !defined(MBEDTLS_SHA256_NO_SHA224)
const mbedtls_md_info_t mbedtls_sha224_info = {
    MBEDTLS_MD_SHA224,
    "SHA224",
    28,
    64,
    sha224_starts_wrap,
    sha224_update_wrap,
    sha224_finish_wrap,
    sha224_wrap,
    sha224_ctx_alloc,
    sha224_ctx_free,
    sha224_clone_wrap,
    sha224_process_wrap,
};
#endif /* !MBEDTLS_SHA256_NO_SHA224 */
#endif /* !MBEDTLS_MD_SINGLE_HASH */

static int sha256_starts_wrap( void *ctx )
{
    return( mbedtls_sha256_starts_ret( (mbedtls_sha256_context *) ctx, 0 ) );
}

static int sha256_wrap( const unsigned char *input, size_t ilen,
                        unsigned char *output )
{
    return( mbedtls_sha256_ret( input, ilen, output, 0 ) );
}

#if !defined(MBEDTLS_MD_SINGLE_HASH)
const mbedtls_md_info_t mbedtls_sha256_info =
    MBEDTLS_MD_INFO( MBEDTLS_MD_INFO_SHA256 );
#endif /* !MBEDTLS_MD_SINGLE_HASH */

#endif /* MBEDTLS_SHA256_C */

/*
 * SHA-384 and SHA-512
 */

#if defined(MBEDTLS_SHA512_C)

static int sha384_starts_wrap( void *ctx )
{
    return( mbedtls_sha512_starts_ret( (mbedtls_sha512_context *) ctx, 1 ) );
}

static int sha384_update_wrap( void *ctx, const unsigned char *input,
                               size_t ilen )
{
    return( mbedtls_sha512_update_ret( (mbedtls_sha512_context *) ctx,
                                       input, ilen ) );
}

static int sha384_finish_wrap( void *ctx, unsigned char *output )
{
    return( mbedtls_sha512_finish_ret( (mbedtls_sha512_context *) ctx,
                                       output ) );
}

static int sha384_wrap( const unsigned char *input, size_t ilen,
                        unsigned char *output )
{
    return( mbedtls_sha512_ret( input, ilen, output, 1 ) );
}

static void *sha384_ctx_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_sha512_context ) );

    if( ctx != NULL )
        mbedtls_sha512_init( (mbedtls_sha512_context *) ctx );

    return( ctx );
}

static void sha384_ctx_free( void *ctx )
{
    mbedtls_sha512_free( (mbedtls_sha512_context *) ctx );
    mbedtls_free( ctx );
}

static void sha384_clone_wrap( void *dst, const void *src )
{
    mbedtls_sha512_clone( (mbedtls_sha512_context *) dst,
                    (const mbedtls_sha512_context *) src );
}

static int sha384_process_wrap( void *ctx, const unsigned char *data )
{
    return( mbedtls_internal_sha512_process( (mbedtls_sha512_context *) ctx,
                                             data ) );
}

#if !defined(MBEDTLS_MD_SINGLE_HASH)
const mbedtls_md_info_t mbedtls_sha384_info = {
    MBEDTLS_MD_SHA384,
    "SHA384",
    48,
    128,
    sha384_starts_wrap,
    sha384_update_wrap,
    sha384_finish_wrap,
    sha384_wrap,
    sha384_ctx_alloc,
    sha384_ctx_free,
    sha384_clone_wrap,
    sha384_process_wrap,
};
#endif /* MBEDTLS_MD_SINGLE_HASH */

static int sha512_starts_wrap( void *ctx )
{
    return( mbedtls_sha512_starts_ret( (mbedtls_sha512_context *) ctx, 0 ) );
}

static int sha512_wrap( const unsigned char *input, size_t ilen,
                        unsigned char *output )
{
    return( mbedtls_sha512_ret( input, ilen, output, 0 ) );
}

#if !defined(MBEDTLS_MD_SINGLE_HASH)
const mbedtls_md_info_t mbedtls_sha512_info = {
    MBEDTLS_MD_SHA512,
    "SHA512",
    64,
    128,
    sha512_starts_wrap,
    sha384_update_wrap,
    sha384_finish_wrap,
    sha512_wrap,
    sha384_ctx_alloc,
    sha384_ctx_free,
    sha384_clone_wrap,
    sha384_process_wrap,
};
#endif /* MBEDTLS_MD_SINGLE_HASH */

#endif /* MBEDTLS_SHA512_C */

/*
 * Getter functions for MD info structure.
 */

#if !defined(MBEDTLS_MD_SINGLE_HASH)

static inline mbedtls_md_type_t mbedtls_md_info_type(
    mbedtls_md_handle_t info )
{
    return( info->type );
}

static inline const char * mbedtls_md_info_name(
    mbedtls_md_handle_t info )
{
    return( info->name );
}

static inline int mbedtls_md_info_size(
    mbedtls_md_handle_t info )
{
    return( info->size );
}

static inline int mbedtls_md_info_block_size(
    mbedtls_md_handle_t info )
{
    return( info->block_size );
}

static inline mbedtls_md_starts_func_t *mbedtls_md_info_starts_func(
    mbedtls_md_handle_t info )
{
    return( info->starts_func );
}

static inline mbedtls_md_update_func_t *mbedtls_md_info_update_func(
    mbedtls_md_handle_t info )
{
    return( info->update_func );
}

static inline mbedtls_md_finish_func_t *mbedtls_md_info_finish_func(
    mbedtls_md_handle_t info )
{
    return( info->finish_func );
}

static inline mbedtls_md_digest_func_t *mbedtls_md_info_digest_func(
    mbedtls_md_handle_t info )
{
    return( info->digest_func );
}

static inline mbedtls_md_ctx_alloc_func_t *mbedtls_md_info_ctx_alloc_func(
    mbedtls_md_handle_t info )
{
    return( info->ctx_alloc_func );
}

static inline mbedtls_md_ctx_free_func_t *mbedtls_md_info_ctx_free_func(
    mbedtls_md_handle_t info )
{
    return( info->ctx_free_func );
}

static inline mbedtls_md_clone_func_t *mbedtls_md_info_clone_func(
    mbedtls_md_handle_t info )
{
    return( info->clone_func );
}

static inline mbedtls_md_process_func_t *mbedtls_md_info_process_func(
    mbedtls_md_handle_t info )
{
    return( info->process_func );
}

#else /* !MBEDTLS_MD_SINGLE_HASH */

static inline mbedtls_md_type_t mbedtls_md_info_type(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_TYPE( MBEDTLS_MD_SINGLE_HASH ) );
}

static inline const char * mbedtls_md_info_name(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_NAME( MBEDTLS_MD_SINGLE_HASH ) );
}

static inline int mbedtls_md_info_size(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_SIZE( MBEDTLS_MD_SINGLE_HASH ) );
}

static inline int mbedtls_md_info_block_size(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_BLOCKSIZE( MBEDTLS_MD_SINGLE_HASH ) );
}

static inline mbedtls_md_starts_func_t *mbedtls_md_info_starts_func(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_STARTS_FUNC( MBEDTLS_MD_SINGLE_HASH ) );
}

static inline mbedtls_md_update_func_t *mbedtls_md_info_update_func(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_UPDATE_FUNC( MBEDTLS_MD_SINGLE_HASH ) );
}

static inline mbedtls_md_finish_func_t *mbedtls_md_info_finish_func(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_FINISH_FUNC( MBEDTLS_MD_SINGLE_HASH ) );
}

static inline mbedtls_md_digest_func_t *mbedtls_md_info_digest_func(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_DIGEST_FUNC( MBEDTLS_MD_SINGLE_HASH ) );
}

static inline mbedtls_md_ctx_alloc_func_t *mbedtls_md_info_ctx_alloc_func(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_ALLOC_FUNC( MBEDTLS_MD_SINGLE_HASH ) );
}

static inline mbedtls_md_ctx_free_func_t *mbedtls_md_info_ctx_free_func(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_FREE_FUNC( MBEDTLS_MD_SINGLE_HASH ) );
}

static inline mbedtls_md_clone_func_t *mbedtls_md_info_clone_func(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_CLONE_FUNC( MBEDTLS_MD_SINGLE_HASH ) );
}

static inline mbedtls_md_process_func_t *mbedtls_md_info_process_func(
    mbedtls_md_handle_t info )
{
    ((void) info);
    return( MBEDTLS_MD_INFO_PROCESS_FUNC( MBEDTLS_MD_SINGLE_HASH ) );
}

#endif /* MBEDTLS_MD_SINGLE_HASH */

#if !defined(MBEDTLS_MD_SINGLE_HASH)

/*
 * Reminder: update profiles in x509_crt.c when adding a new hash!
 */
static const int supported_digests[] = {

#if defined(MBEDTLS_SHA512_C)
        MBEDTLS_MD_SHA512,
        MBEDTLS_MD_SHA384,
#endif

#if defined(MBEDTLS_SHA256_C)
        MBEDTLS_MD_SHA256,
#if !defined(MBEDTLS_SHA256_NO_SHA224)
        MBEDTLS_MD_SHA224,
#endif
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA1_C)
        MBEDTLS_MD_SHA1,
#endif

#if defined(MBEDTLS_RIPEMD160_C)
        MBEDTLS_MD_RIPEMD160,
#endif

#if defined(MBEDTLS_MD5_C)
        MBEDTLS_MD_MD5,
#endif

#if defined(MBEDTLS_MD4_C)
        MBEDTLS_MD_MD4,
#endif

#if defined(MBEDTLS_MD2_C)
        MBEDTLS_MD_MD2,
#endif

        MBEDTLS_MD_NONE
};

const int *mbedtls_md_list( void )
{
    return( supported_digests );
}

mbedtls_md_handle_t mbedtls_md_info_from_string( const char *md_name )
{
    if( NULL == md_name )
        return( NULL );

    /* Get the appropriate digest information */
#if defined(MBEDTLS_MD2_C)
    if( !strcmp( "MD2", md_name ) )
        return mbedtls_md_info_from_type( MBEDTLS_MD_MD2 );
#endif
#if defined(MBEDTLS_MD4_C)
    if( !strcmp( "MD4", md_name ) )
        return mbedtls_md_info_from_type( MBEDTLS_MD_MD4 );
#endif
#if defined(MBEDTLS_MD5_C)
    if( !strcmp( "MD5", md_name ) )
        return mbedtls_md_info_from_type( MBEDTLS_MD_MD5 );
#endif
#if defined(MBEDTLS_RIPEMD160_C)
    if( !strcmp( "RIPEMD160", md_name ) )
        return mbedtls_md_info_from_type( MBEDTLS_MD_RIPEMD160 );
#endif
#if defined(MBEDTLS_SHA1_C)
    if( !strcmp( "SHA1", md_name ) || !strcmp( "SHA", md_name ) )
        return mbedtls_md_info_from_type( MBEDTLS_MD_SHA1 );
#endif
#if defined(MBEDTLS_SHA256_C)
#if !defined(MBEDTLS_SHA256_NO_SHA224)
    if( !strcmp( "SHA224", md_name ) )
        return mbedtls_md_info_from_type( MBEDTLS_MD_SHA224 );
#endif
    if( !strcmp( "SHA256", md_name ) )
        return mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
    if( !strcmp( "SHA384", md_name ) )
        return mbedtls_md_info_from_type( MBEDTLS_MD_SHA384 );
    if( !strcmp( "SHA512", md_name ) )
        return mbedtls_md_info_from_type( MBEDTLS_MD_SHA512 );
#endif
    return( NULL );
}

mbedtls_md_handle_t mbedtls_md_info_from_type( mbedtls_md_type_t md_type )
{
    switch( md_type )
    {
#if defined(MBEDTLS_MD2_C)
        case MBEDTLS_MD_MD2:
            return( &mbedtls_md2_info );
#endif
#if defined(MBEDTLS_MD4_C)
        case MBEDTLS_MD_MD4:
            return( &mbedtls_md4_info );
#endif
#if defined(MBEDTLS_MD5_C)
        case MBEDTLS_MD_MD5:
            return( &mbedtls_md5_info );
#endif
#if defined(MBEDTLS_RIPEMD160_C)
        case MBEDTLS_MD_RIPEMD160:
            return( &mbedtls_ripemd160_info );
#endif
#if defined(MBEDTLS_SHA1_C)
        case MBEDTLS_MD_SHA1:
            return( &mbedtls_sha1_info );
#endif
#if defined(MBEDTLS_SHA256_C)
#if !defined(MBEDTLS_SHA256_NO_SHA224)
        case MBEDTLS_MD_SHA224:
            return( &mbedtls_sha224_info );
#endif
        case MBEDTLS_MD_SHA256:
            return( &mbedtls_sha256_info );
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA512_C)
        case MBEDTLS_MD_SHA384:
            return( &mbedtls_sha384_info );
        case MBEDTLS_MD_SHA512:
            return( &mbedtls_sha512_info );
#endif
        default:
            return( NULL );
    }
}

#else /* MBEDTLS_MD_SINGLE_HASH */

const int *mbedtls_md_list( void )
{
    static int single_hash[2] =
        { MBEDTLS_MD_INFO_TYPE( MBEDTLS_MD_SINGLE_HASH ),
          MBEDTLS_MD_INVALID_HANDLE };

    return( single_hash );
}

mbedtls_md_handle_t mbedtls_md_info_from_string( const char *md_name )
{
    static const char * const hash_name =
        MBEDTLS_MD_INFO_NAME( MBEDTLS_MD_SINGLE_HASH );

    if( md_name != NULL && strcmp( hash_name, md_name ) == 0 )
        return( MBEDTLS_MD_UNIQUE_VALID_HANDLE );

    return( MBEDTLS_MD_INVALID_HANDLE );
}

mbedtls_md_handle_t mbedtls_md_info_from_type( mbedtls_md_type_t md_type )
{
    static const mbedtls_md_type_t hash_type =
        MBEDTLS_MD_INFO_TYPE( MBEDTLS_MD_SINGLE_HASH );

    if( hash_type == md_type )
        return( MBEDTLS_MD_UNIQUE_VALID_HANDLE );

    return( MBEDTLS_MD_INVALID_HANDLE );
}

#endif /* MBEDTLS_MD_SINGLE_HASH */

void mbedtls_md_init( mbedtls_md_context_t *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_md_context_t ) );
}

void mbedtls_md_free( mbedtls_md_context_t *ctx )
{
    if( ctx == NULL || mbedtls_md_get_handle( ctx ) == MBEDTLS_MD_INVALID_HANDLE )
        return;

    if( ctx->md_ctx != NULL )
    {
        mbedtls_md_info_ctx_free_func(
            mbedtls_md_get_handle( ctx ) )( ctx->md_ctx );
    }

    if( ctx->hmac_ctx != NULL )
    {
        mbedtls_platform_zeroize( ctx->hmac_ctx,
            2 * mbedtls_md_info_block_size( mbedtls_md_get_handle( ctx ) ) );
        mbedtls_free( ctx->hmac_ctx );
    }

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_md_context_t ) );
}

int mbedtls_md_clone( mbedtls_md_context_t *dst,
                      const mbedtls_md_context_t *src )
{
    if( dst == NULL || mbedtls_md_get_handle( dst ) == MBEDTLS_MD_INVALID_HANDLE ||
        src == NULL || mbedtls_md_get_handle( src ) == MBEDTLS_MD_INVALID_HANDLE ||
        mbedtls_md_get_handle( dst ) != mbedtls_md_get_handle( src ) )
    {
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );
    }

    mbedtls_md_info_clone_func( mbedtls_md_get_handle( dst ) )
        ( dst->md_ctx, src->md_ctx );
    return( 0 );
}

#if ! defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_md_init_ctx( mbedtls_md_context_t *ctx, mbedtls_md_handle_t md_info )
{
    return mbedtls_md_setup( ctx, md_info, 1 );
}
#endif

int mbedtls_md_setup( mbedtls_md_context_t *ctx, mbedtls_md_handle_t md_info, int hmac )
{
    if( md_info == MBEDTLS_MD_INVALID_HANDLE || ctx == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    ctx->md_ctx = mbedtls_md_info_ctx_alloc_func( md_info )();
    if( ctx->md_ctx == NULL )
        return( MBEDTLS_ERR_MD_ALLOC_FAILED );

    if( hmac != 0 )
    {
        ctx->hmac_ctx = mbedtls_calloc( 2,
                           mbedtls_md_info_block_size( md_info ) );
        if( ctx->hmac_ctx == NULL )
        {
            mbedtls_md_info_ctx_free_func( md_info )( ctx->md_ctx );
            return( MBEDTLS_ERR_MD_ALLOC_FAILED );
        }
    }

#if !defined(MBEDTLS_MD_SINGLE_HASH)
    ctx->md_info = md_info;
#endif

    return( 0 );
}

int mbedtls_md_starts( mbedtls_md_context_t *ctx )
{
    mbedtls_md_handle_t md_info;
    if( ctx == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    md_info = mbedtls_md_get_handle( ctx );
    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    return( mbedtls_md_info_starts_func( md_info )( ctx->md_ctx ) );
}

int mbedtls_md_update( mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen )
{
    mbedtls_md_handle_t md_info;
    if( ctx == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    md_info = mbedtls_md_get_handle( ctx );
    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    return( mbedtls_md_info_update_func( md_info )( ctx->md_ctx,
                                                    input, ilen ) );
}

int mbedtls_md_finish( mbedtls_md_context_t *ctx, unsigned char *output )
{
    mbedtls_md_handle_t md_info;
    if( ctx == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    md_info = mbedtls_md_get_handle( ctx );
    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    return( mbedtls_md_info_finish_func( md_info )( ctx->md_ctx,
                                                    output ) );
}

int mbedtls_md( mbedtls_md_handle_t md_info, const unsigned char *input, size_t ilen,
            unsigned char *output )
{
    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    return( mbedtls_md_info_digest_func( md_info )(
                input, ilen, output) );
}

#if defined(MBEDTLS_FS_IO)
int mbedtls_md_file( mbedtls_md_handle_t md_info, const char *path, unsigned char *output )
{
    int ret;
    FILE *f;
    size_t n;
    mbedtls_md_context_t ctx;
    unsigned char buf[1024];

    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( MBEDTLS_ERR_MD_FILE_IO_ERROR );

    mbedtls_md_init( &ctx );

    if( ( ret = mbedtls_md_setup( &ctx, md_info, 0 ) ) != 0 )
        goto cleanup;

    ret = mbedtls_md_info_starts_func( md_info )( ctx.md_ctx );
    if( ret != 0 )
        goto cleanup;

    while( ( n = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
    {
        ret = mbedtls_md_info_update_func( md_info )( ctx.md_ctx,
                                                          buf, n );
        if( ret != 0 )
            goto cleanup;
    }

    if( ferror( f ) != 0 )
    {
        ret = MBEDTLS_ERR_MD_FILE_IO_ERROR;
    }
    else
    {
        ret = mbedtls_md_info_finish_func( md_info )( ctx.md_ctx,
                                                          output );
    }

cleanup:
    mbedtls_platform_zeroize( buf, sizeof( buf ) );
    fclose( f );
    mbedtls_md_free( &ctx );

    return( ret );
}
#endif /* MBEDTLS_FS_IO */

int mbedtls_md_hmac_starts( mbedtls_md_context_t *ctx, const unsigned char *key, size_t keylen )
{
    int ret;
    unsigned char sum[MBEDTLS_MD_MAX_SIZE];
    unsigned char *ipad, *opad;
    size_t i;

    mbedtls_md_starts_func_t *starts;
    mbedtls_md_update_func_t *update;
    mbedtls_md_finish_func_t *finish;

    mbedtls_md_handle_t md_info;

    if( ctx == NULL || ctx->hmac_ctx == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    md_info = mbedtls_md_get_handle( ctx );
    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    starts = mbedtls_md_info_starts_func( md_info );
    update = mbedtls_md_info_update_func( md_info );
    finish = mbedtls_md_info_finish_func( md_info );

    if( keylen > (size_t) mbedtls_md_info_block_size( md_info ) )
    {
        if( ( ret = starts( ctx->md_ctx ) ) != 0 )
            goto cleanup;

        if( ( ret = update( ctx->md_ctx, key, keylen ) ) )
            goto cleanup;

        if( ( ret = finish( ctx->md_ctx, sum ) ) != 0 )
            goto cleanup;

        keylen = mbedtls_md_info_size( md_info );
        key = sum;
    }

    ipad = (unsigned char *) ctx->hmac_ctx;
    opad = (unsigned char *) ctx->hmac_ctx +
        mbedtls_md_info_block_size( md_info );

    memset( ipad, 0x36, mbedtls_md_info_block_size( md_info ) );
    memset( opad, 0x5C, mbedtls_md_info_block_size( md_info ) );

    for( i = 0; i < keylen; i++ )
    {
        ipad[i] = (unsigned char)( ipad[i] ^ key[i] );
        opad[i] = (unsigned char)( opad[i] ^ key[i] );
    }

    if( ( ret = starts( ctx->md_ctx ) ) != 0 )
        goto cleanup;

    if( ( ret = update( ctx->md_ctx, ipad,
           mbedtls_md_info_block_size( md_info ) ) ) != 0 )
    {
        goto cleanup;
    }

cleanup:
    mbedtls_platform_zeroize( sum, sizeof( sum ) );

    return( ret );
}

int mbedtls_md_hmac_update( mbedtls_md_context_t *ctx,
                            const unsigned char *input, size_t ilen )
{
    mbedtls_md_handle_t md_info;

    if( ctx == NULL || ctx->hmac_ctx == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    md_info = mbedtls_md_get_handle( ctx );
    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    return( mbedtls_md_info_update_func( md_info )(
                ctx->md_ctx, input, ilen ) );
}

int mbedtls_md_hmac_finish( mbedtls_md_context_t *ctx, unsigned char *output )
{
    int ret;
    unsigned char tmp[MBEDTLS_MD_MAX_SIZE];
    unsigned char *opad;

    mbedtls_md_starts_func_t *starts;
    mbedtls_md_update_func_t *update;
    mbedtls_md_finish_func_t *finish;

    mbedtls_md_handle_t md_info;

    if( ctx == NULL || ctx->hmac_ctx == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    md_info = mbedtls_md_get_handle( ctx );
    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    starts = mbedtls_md_info_starts_func( md_info );
    update = mbedtls_md_info_update_func( md_info );
    finish = mbedtls_md_info_finish_func( md_info );

    opad = (unsigned char *) ctx->hmac_ctx +
        mbedtls_md_info_block_size( md_info );

    if( ( ret = finish( ctx->md_ctx, tmp ) ) != 0 )
        return( ret );

    if( ( ret = starts( ctx->md_ctx ) ) != 0 )
        return( ret );

    if( ( ret = update( ctx->md_ctx, opad,
                        mbedtls_md_info_block_size( md_info ) ) ) != 0 )
    {
        return( ret );
    }

    if( ( ret = update( ctx->md_ctx, tmp,
                        mbedtls_md_info_size( md_info ) ) ) != 0 )
    {
        return( ret );
    }

    if( ( ret = finish( ctx->md_ctx, output ) ) != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_md_hmac_reset( mbedtls_md_context_t *ctx )
{
    int ret;
    unsigned char *ipad;

    mbedtls_md_handle_t md_info;

    if( ctx == NULL || ctx->hmac_ctx == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    md_info = mbedtls_md_get_handle( ctx );
    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    ipad = (unsigned char *) ctx->hmac_ctx;

    ret = mbedtls_md_info_starts_func( md_info )( ctx->md_ctx );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_md_info_update_func( md_info )(
        ctx->md_ctx, ipad,
        mbedtls_md_info_block_size( md_info ) );
    return( ret );
}

int mbedtls_md_hmac( mbedtls_md_handle_t md_info,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *input, size_t ilen,
                     unsigned char *output )
{
    mbedtls_md_context_t ctx;
    int ret;

    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    mbedtls_md_init( &ctx );

    if( ( ret = mbedtls_md_setup( &ctx, md_info, 1 ) ) != 0 )
        goto cleanup;

    if( ( ret = mbedtls_md_hmac_starts( &ctx, key, keylen ) ) != 0 )
        goto cleanup;
    if( ( ret = mbedtls_md_hmac_update( &ctx, input, ilen ) ) != 0 )
        goto cleanup;
    if( ( ret = mbedtls_md_hmac_finish( &ctx, output ) ) != 0 )
        goto cleanup;

cleanup:
    mbedtls_md_free( &ctx );

    return( ret );
}

int mbedtls_md_process( mbedtls_md_context_t *ctx, const unsigned char *data )
{
    mbedtls_md_handle_t md_info;
    if( ctx == NULL )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    md_info = mbedtls_md_get_handle( ctx );
    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( MBEDTLS_ERR_MD_BAD_INPUT_DATA );

    return( mbedtls_md_info_process_func( md_info )(
                ctx->md_ctx, data ) );
}

unsigned char mbedtls_md_get_size( mbedtls_md_handle_t md_info )
{
    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( 0 );

    return mbedtls_md_info_size( md_info );
}

mbedtls_md_type_t mbedtls_md_get_type( mbedtls_md_handle_t md_info )
{
    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( MBEDTLS_MD_NONE );

    return mbedtls_md_info_type( md_info );
}

const char *mbedtls_md_get_name( mbedtls_md_handle_t md_info )
{
    if( md_info == MBEDTLS_MD_INVALID_HANDLE )
        return( NULL );

    return mbedtls_md_info_name( md_info );
}

#endif /* MBEDTLS_MD_C */
