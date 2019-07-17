/**
 * \file md_internal.h
 *
 * \brief Message digest wrappers.
 *
 * \warning This in an internal header. Do not include directly.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 */
/*
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
#ifndef MBEDTLS_MD_WRAP_H
#define MBEDTLS_MD_WRAP_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "md.h"

#ifdef __cplusplus
extern "C" {
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
#define MBEDTLS_MD_INFO_ALLOC_FUNC_T( MD )    MD ## _ALLOC_FUNC
#define MBEDTLS_MD_INFO_FREE_FUNC_T( MD ) MD ## _FREE_FUNC
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

/*
 * Getter functions for MD info structure.
 */

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

#if defined(MBEDTLS_MD2_C)
extern const mbedtls_md_info_t mbedtls_md2_info;
#endif
#if defined(MBEDTLS_MD4_C)
extern const mbedtls_md_info_t mbedtls_md4_info;
#endif
#if defined(MBEDTLS_MD5_C)
extern const mbedtls_md_info_t mbedtls_md5_info;
#endif
#if defined(MBEDTLS_RIPEMD160_C)
extern const mbedtls_md_info_t mbedtls_ripemd160_info;
#endif
#if defined(MBEDTLS_SHA1_C)
extern const mbedtls_md_info_t mbedtls_sha1_info;
#endif
#if defined(MBEDTLS_SHA256_C)
#if !defined(MBEDTLS_SHA256_NO_SHA224)
extern const mbedtls_md_info_t mbedtls_sha224_info;
#endif
extern const mbedtls_md_info_t mbedtls_sha256_info;
#endif
#if defined(MBEDTLS_SHA512_C)
extern const mbedtls_md_info_t mbedtls_sha384_info;
extern const mbedtls_md_info_t mbedtls_sha512_info;
#endif

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_MD_WRAP_H */
