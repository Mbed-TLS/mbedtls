/**
 * \file pk_internal.h
 *
 * \brief Public Key abstraction layer: wrapper functions
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

#ifndef MBEDTLS_PK_WRAP_H
#define MBEDTLS_PK_WRAP_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "pk.h"

/* Parameter validation macros based on platform_util.h */
#define MBEDTLS_PK_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_PK_BAD_INPUT_DATA )
#define MBEDTLS_PK_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

/*
 * PK information macro definitions
 */

/*
 * Each PK type that can be used with MBEDTLS_PK_SINGLE_TYPE needs to have
 * the following MBEDTLS_PK_INFO_{FIELD} definitions, plus a dummy one for the
 * base name. For now, only ECKEY with MBEDTLS_USE_TINYCRYPT is defined.
 *
 * For optional functions that are omitted, we need both the _FUNC field
 * defined to NULL, and an extra macro _OMIT defined to 1.
 */

#if defined(MBEDTLS_USE_TINYCRYPT)
/* Dummy definition to keep check-names.sh happy - don't uncomment */
//#define MBEDTLS_PK_INFO_ECKEY

#define MBEDTLS_PK_INFO_ECKEY_CONTEXT           mbedtls_uecc_keypair
#define MBEDTLS_PK_INFO_ECKEY_TYPE              MBEDTLS_PK_ECKEY
#define MBEDTLS_PK_INFO_ECKEY_NAME              "EC"
#define MBEDTLS_PK_INFO_ECKEY_GET_BITLEN        mbedtls_uecc_eckey_get_bitlen
#define MBEDTLS_PK_INFO_ECKEY_CAN_DO            mbedtls_uecc_eckey_can_do
#define MBEDTLS_PK_INFO_ECKEY_VERIFY_FUNC       mbedtls_uecc_eckey_verify_wrap
#define MBEDTLS_PK_INFO_ECKEY_SIGN_FUNC         mbedtls_uecc_eckey_sign_wrap
#define MBEDTLS_PK_INFO_ECKEY_DECRYPT_FUNC      NULL
#define MBEDTLS_PK_INFO_ECKEY_DECRYPT_OMIT      1
#define MBEDTLS_PK_INFO_ECKEY_ENCRYPT_FUNC      NULL
#define MBEDTLS_PK_INFO_ECKEY_ENCRYPT_OMIT      1
#define MBEDTLS_PK_INFO_ECKEY_CHECK_PAIR_FUNC   mbedtls_uecc_eckey_check_pair
#define MBEDTLS_PK_INFO_ECKEY_CTX_ALLOC_FUNC    mbedtls_uecc_eckey_alloc_wrap
#define MBEDTLS_PK_INFO_ECKEY_CTX_FREE_FUNC     mbedtls_uecc_eckey_free_wrap
#define MBEDTLS_PK_INFO_ECKEY_DEBUG_FUNC        NULL
#define MBEDTLS_PK_INFO_ECKEY_DEBUG_OMIT        1
#endif /* MBEDTLS_USE_TINYCRYPT */

/*
 * Helper macros to extract fields from PK types
 */
#define MBEDTLS_PK_INFO_CONTEXT_T( PK )         PK ## _CONTEXT
#define MBEDTLS_PK_INFO_TYPE_T( PK )            PK ## _TYPE
#define MBEDTLS_PK_INFO_NAME_T( PK )            PK ## _NAME
#define MBEDTLS_PK_INFO_GET_BITLEN_T( PK )      PK ## _GET_BITLEN
#define MBEDTLS_PK_INFO_CAN_DO_T( PK )          PK ## _CAN_DO
#define MBEDTLS_PK_INFO_VERIFY_FUNC_T( PK )     PK ## _VERIFY_FUNC
#define MBEDTLS_PK_INFO_VERIFY_OMIT_T( PK )     PK ## _VERIFY_OMIT
#define MBEDTLS_PK_INFO_SIGN_FUNC_T( PK )       PK ## _SIGN_FUNC
#define MBEDTLS_PK_INFO_SIGN_OMIT_T( PK )       PK ## _SIGN_OMIT
#define MBEDTLS_PK_INFO_DECRYPT_FUNC_T( PK )    PK ## _DECRYPT_FUNC
#define MBEDTLS_PK_INFO_DECRYPT_OMIT_T( PK )    PK ## _DECRYPT_OMIT
#define MBEDTLS_PK_INFO_ENCRYPT_FUNC_T( PK )    PK ## _ENCRYPT_FUNC
#define MBEDTLS_PK_INFO_ENCRYPT_OMIT_T( PK )    PK ## _ENCRYPT_OMIT
#define MBEDTLS_PK_INFO_CHECK_PAIR_FUNC_T( PK ) PK ## _CHECK_PAIR_FUNC
#define MBEDTLS_PK_INFO_CHECK_PAIR_OMIT_T( PK ) PK ## _CHECK_PAIR_OMIT
#define MBEDTLS_PK_INFO_CTX_ALLOC_FUNC_T( PK )  PK ## _CTX_ALLOC_FUNC
#define MBEDTLS_PK_INFO_CTX_FREE_FUNC_T( PK )   PK ## _CTX_FREE_FUNC
#define MBEDTLS_PK_INFO_DEBUG_FUNC_T( PK )      PK ## _DEBUG_FUNC
#define MBEDTLS_PK_INFO_DEBUG_OMIT_T( PK )      PK ## _DEBUG_OMIT

/* Wrappers around MBEDTLS_PK_INFO_{FIELD}_T() which makes sure that
 * the argument is macro-expanded before concatenated with the
 * field name. This allows to call these macros as
 *    MBEDTLS_PK_INFO_{FIELD}( MBEDTLS_PK_SINGLE_TYPE ).
 * where MBEDTLS_PK_SINGLE_TYPE expands to MBEDTLS_PK_INFO_{TYPE}. */
#define MBEDTLS_PK_INFO_CONTEXT( PK )         MBEDTLS_PK_INFO_CONTEXT_T( PK )
#define MBEDTLS_PK_INFO_TYPE( PK )            MBEDTLS_PK_INFO_TYPE_T( PK )
#define MBEDTLS_PK_INFO_NAME( PK )            MBEDTLS_PK_INFO_NAME_T( PK )
#define MBEDTLS_PK_INFO_GET_BITLEN( PK )      MBEDTLS_PK_INFO_GET_BITLEN_T( PK )
#define MBEDTLS_PK_INFO_CAN_DO( PK )          MBEDTLS_PK_INFO_CAN_DO_T( PK )
#define MBEDTLS_PK_INFO_VERIFY_FUNC( PK )     MBEDTLS_PK_INFO_VERIFY_FUNC_T( PK )
#define MBEDTLS_PK_INFO_VERIFY_OMIT( PK )     MBEDTLS_PK_INFO_VERIFY_OMIT_T( PK )
#define MBEDTLS_PK_INFO_SIGN_FUNC( PK )       MBEDTLS_PK_INFO_SIGN_FUNC_T( PK )
#define MBEDTLS_PK_INFO_SIGN_OMIT( PK )       MBEDTLS_PK_INFO_SIGN_OMIT_T( PK )
#define MBEDTLS_PK_INFO_DECRYPT_FUNC( PK )    MBEDTLS_PK_INFO_DECRYPT_FUNC_T( PK )
#define MBEDTLS_PK_INFO_DECRYPT_OMIT( PK )    MBEDTLS_PK_INFO_DECRYPT_OMIT_T( PK )
#define MBEDTLS_PK_INFO_ENCRYPT_FUNC( PK )    MBEDTLS_PK_INFO_ENCRYPT_FUNC_T( PK )
#define MBEDTLS_PK_INFO_ENCRYPT_OMIT( PK )    MBEDTLS_PK_INFO_ENCRYPT_OMIT_T( PK )
#define MBEDTLS_PK_INFO_CHECK_PAIR_FUNC( PK ) MBEDTLS_PK_INFO_CHECK_PAIR_FUNC_T( PK )
#define MBEDTLS_PK_INFO_CHECK_PAIR_OMIT( PK ) MBEDTLS_PK_INFO_CHECK_PAIR_OMIT_T( PK )
#define MBEDTLS_PK_INFO_CTX_ALLOC_FUNC( PK )  MBEDTLS_PK_INFO_CTX_ALLOC_FUNC_T( PK )
#define MBEDTLS_PK_INFO_CTX_FREE_FUNC( PK )   MBEDTLS_PK_INFO_CTX_FREE_FUNC_T( PK )
#define MBEDTLS_PK_INFO_DEBUG_FUNC( PK )      MBEDTLS_PK_INFO_DEBUG_FUNC_T( PK )
#define MBEDTLS_PK_INFO_DEBUG_OMIT( PK )      MBEDTLS_PK_INFO_DEBUG_OMIT_T( PK )

#if !defined(MBEDTLS_PK_SINGLE_TYPE)
struct mbedtls_pk_info_t
{
    /** Public key type */
    mbedtls_pk_type_t type;

    /** Type name */
    const char *name;

    /** Get key size in bits (must be valid)*/
    size_t (*get_bitlen)( const void * );

    /** Tell if the context implements this type (e.g. ECKEY can do ECDSA)
     * (must be valid) */
    int (*can_do)( mbedtls_pk_type_t type );

    /** Verify signature (may be NULL) */
    int (*verify_func)( void *ctx, mbedtls_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        const unsigned char *sig, size_t sig_len );

    /** Make signature (may be NULL)*/
    int (*sign_func)( void *ctx, mbedtls_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      unsigned char *sig, size_t *sig_len,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /** Verify signature (restartable) (may be NULL) */
    int (*verify_rs_func)( void *ctx, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len,
                           void *rs_ctx );

    /** Make signature (restartable) (may be NULL) */
    int (*sign_rs_func)( void *ctx, mbedtls_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng, void *rs_ctx );
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    /** Decrypt message (may be NULL) */
    int (*decrypt_func)( void *ctx, const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen, size_t osize,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );

    /** Encrypt message (may be NULL ) */
    int (*encrypt_func)( void *ctx, const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen, size_t osize,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );

    /** Check public-private key pair (may be NULL) */
    int (*check_pair_func)( const void *pub, const void *prv );

    /** Allocate a new context (must be valid) */
    void * (*ctx_alloc_func)( void );

    /** Free the given context (must be valid) */
    void (*ctx_free_func)( void *ctx );

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /** Allocate the restart context (may be NULL)*/
    void * (*rs_alloc_func)( void );

    /** Free the restart context (may be NULL) */
    void (*rs_free_func)( void *rs_ctx );
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    /** Interface with the debug module (may be NULL) */
    void (*debug_func)( const void *ctx, mbedtls_pk_debug_item *items );

};

/**
 * \brief   This macro builds an instance of ::mbedtls_pk_info_t
 *          from an \c MBEDTLS_PK_INFO_{TYPE} identifier.
 */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
#define MBEDTLS_PK_INFO( PK )                           \
{                                                       \
    MBEDTLS_PK_INFO_TYPE( PK ),              \
    MBEDTLS_PK_INFO_NAME( PK ),              \
    MBEDTLS_PK_INFO_GET_BITLEN( PK ),        \
    MBEDTLS_PK_INFO_CAN_DO( PK ),            \
    MBEDTLS_PK_INFO_VERIFY_FUNC( PK ),       \
    MBEDTLS_PK_INFO_SIGN_FUNC( PK ),         \
    NULL,                                               \
    NULL,                                               \
    MBEDTLS_PK_INFO_DECRYPT_FUNC( PK ),      \
    MBEDTLS_PK_INFO_ENCRYPT_FUNC( PK ),      \
    MBEDTLS_PK_INFO_CHECK_PAIR_FUNC( PK ),   \
    MBEDTLS_PK_INFO_CTX_ALLOC_FUNC( PK ),    \
    MBEDTLS_PK_INFO_CTX_FREE_FUNC( PK ),     \
    NULL,                                               \
    NULL,                                               \
    MBEDTLS_PK_INFO_DEBUG_FUNC( PK ),        \
}
#else /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
#define MBEDTLS_PK_INFO( PK )                           \
{                                                       \
    MBEDTLS_PK_INFO_TYPE( PK ),              \
    MBEDTLS_PK_INFO_NAME( PK ),              \
    MBEDTLS_PK_INFO_GET_BITLEN( PK ),        \
    MBEDTLS_PK_INFO_CAN_DO( PK ),            \
    MBEDTLS_PK_INFO_VERIFY_FUNC( PK ),       \
    MBEDTLS_PK_INFO_SIGN_FUNC( PK ),         \
    MBEDTLS_PK_INFO_DECRYPT_FUNC( PK ),      \
    MBEDTLS_PK_INFO_ENCRYPT_FUNC( PK ),      \
    MBEDTLS_PK_INFO_CHECK_PAIR_FUNC( PK ),   \
    MBEDTLS_PK_INFO_CTX_ALLOC_FUNC( PK ),    \
    MBEDTLS_PK_INFO_CTX_FREE_FUNC( PK ),     \
    MBEDTLS_PK_INFO_DEBUG_FUNC( PK ),        \
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
#endif /* MBEDTLS_PK_SINGLE_TYPE */

/*
 * Macros to access pk_info
 */
#if defined(MBEDTLS_PK_SINGLE_TYPE)
#define MBEDTLS_PK_CTX_INFO( ctx )      MBEDTLS_PK_UNIQUE_VALID_HANDLE
#else
#define MBEDTLS_PK_CTX_INFO( ctx )      ( (ctx)->pk_info )
#endif
#define MBEDTLS_PK_CTX_IS_VALID( ctx )  \
    ( MBEDTLS_PK_CTX_INFO( (ctx) ) != MBEDTLS_PK_INVALID_HANDLE )

/*
 * Access to members of the pk_info structure. When a single PK type is
 * hardcoded, these should have zero runtime cost; otherwise, the usual
 * dynamic dispatch based on pk_info is used.
 *
 * For function members, don't make a getter, but a function that directly
 * calls the method, so that we can entirely get rid of function pointers
 * when hardcoding a single PK - some compilers optimize better that way.
 *
 * Not implemented for members that are only present in builds with
 * MBEDTLS_ECP_RESTARTABLE for now, as the main target for this is builds
 * with MBEDTLS_USE_TINYCRYPT, which don't have MBEDTLS_ECP_RESTARTABLE.
 */
#if defined(MBEDTLS_PK_SINGLE_TYPE)

/* temporary: forward declarations */
size_t mbedtls_uecc_eckey_get_bitlen( const void *ctx );
int mbedtls_uecc_eckey_check_pair( const void *pub, const void *prv );
int mbedtls_uecc_eckey_can_do( mbedtls_pk_type_t type );
int mbedtls_uecc_eckey_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len );
int mbedtls_uecc_eckey_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

MBEDTLS_ALWAYS_INLINE static inline mbedtls_pk_type_t mbedtls_pk_info_type(
    mbedtls_pk_handle_t info )
{
    (void) info;
    return( MBEDTLS_PK_INFO_TYPE( MBEDTLS_PK_SINGLE_TYPE ) );
}

MBEDTLS_ALWAYS_INLINE static inline const char * mbedtls_pk_info_name(
    mbedtls_pk_handle_t info )
{
    (void) info;
    return( MBEDTLS_PK_INFO_NAME( MBEDTLS_PK_SINGLE_TYPE ) );
}

MBEDTLS_ALWAYS_INLINE static inline size_t mbedtls_pk_info_get_bitlen(
    mbedtls_pk_handle_t info, const void *ctx )
{
    (void) info;
    return( MBEDTLS_PK_INFO_GET_BITLEN( MBEDTLS_PK_SINGLE_TYPE )( ctx ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_can_do(
    mbedtls_pk_handle_t info, mbedtls_pk_type_t type )
{
    (void) info;
    return( MBEDTLS_PK_INFO_CAN_DO( MBEDTLS_PK_SINGLE_TYPE )( type ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_verify_func(
    mbedtls_pk_handle_t info, void *ctx, mbedtls_md_type_t md_alg,
    const unsigned char *hash, size_t hash_len,
    const unsigned char *sig, size_t sig_len )
{
    (void) info;
#if MBEDTLS_PK_INFO_VERIFY_OMIT( MBEDTLS_PK_SINGLE_TYPE )
    (void) ctx;
    (void) md_alg;
    (void) hash;
    (void) hash_len;
    (void) sig;
    (void) sig_len;
    return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
#else
    return( MBEDTLS_PK_INFO_VERIFY_FUNC( MBEDTLS_PK_SINGLE_TYPE )(
                ctx, md_alg, hash, hash_len, sig, sig_len ) );
#endif
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_sign_func(
    mbedtls_pk_handle_t info, void *ctx, mbedtls_md_type_t md_alg,
    const unsigned char *hash, size_t hash_len,
    unsigned char *sig, size_t *sig_len,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng )
{
    (void) info;
#if MBEDTLS_PK_INFO_SIGN_OMIT( MBEDTLS_PK_SINGLE_TYPE )
    (void) ctx;
    (void) md_alg;
    (void) hash;
    (void) hash_len;
    (void) sig;
    (void) sig_len;
    (void) f_rng;
    (void) p_rng;
    return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
#else
    return( MBEDTLS_PK_INFO_SIGN_FUNC( MBEDTLS_PK_SINGLE_TYPE )(
                ctx, md_alg, hash, hash_len, sig, sig_len, f_rng, p_rng ) );
#endif
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_decrypt_func(
    mbedtls_pk_handle_t info, void *ctx,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng )
{
    (void) info;
#if MBEDTLS_PK_INFO_DECRYPT_OMIT( MBEDTLS_PK_SINGLE_TYPE )
    (void) ctx;
    (void) input;
    (void) ilen;
    (void) output;
    (void) olen;
    (void) osize;
    (void) f_rng;
    (void) p_rng;
    return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
#else
    return( MBEDTLS_PK_INFO_DECRYPT_FUNC( MBEDTLS_PK_SINGLE_TYPE )(
                ctx, input, ilen, output, olen, osize, f_rng, p_rng ) );
#endif
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_encrypt_func(
    mbedtls_pk_handle_t info, void *ctx,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng )
{
    (void) info;
#if MBEDTLS_PK_INFO_ENCRYPT_OMIT( MBEDTLS_PK_SINGLE_TYPE )
    (void) ctx;
    (void) input;
    (void) ilen;
    (void) output;
    (void) olen;
    (void) osize;
    (void) f_rng;
    (void) p_rng;
    return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
#else
    return( MBEDTLS_PK_INFO_ENCRYPT_FUNC( MBEDTLS_PK_SINGLE_TYPE )(
                ctx, input, ilen, output, olen, osize, f_rng, p_rng ) );
#endif
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_check_pair_func(
    mbedtls_pk_handle_t info, const void *pub, const void *prv )
{
    (void) info;
#if MBEDTLS_PK_INFO_CHECK_PAIR_OMIT( MBEDTLS_PK_SINGLE_TYPE )
    (void) pub;
    (void) prv;
    return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
#else
    return( MBEDTLS_PK_INFO_CHECK_PAIR_FUNC( MBEDTLS_PK_SINGLE_TYPE )(
                pub, prv ) );
#endif
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_debug_func(
    mbedtls_pk_handle_t info,
    const void *ctx, mbedtls_pk_debug_item *items )
{
    (void) info;
#if MBEDTLS_PK_INFO_DEBUG_OMIT( MBEDTLS_PK_SINGLE_TYPE )
    (void) ctx;
    (void) items;
    return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
#else
    return( MBEDTLS_PK_INFO_DEBUG_FUNC( MBEDTLS_PK_SINGLE_TYPE )( ctx, items ) );
#endif
}

#else /* MBEDTLS_PK_SINGLE_TYPE */

MBEDTLS_ALWAYS_INLINE static inline mbedtls_pk_type_t mbedtls_pk_info_type(
    mbedtls_pk_handle_t info )
{
    return( info->type );
}

MBEDTLS_ALWAYS_INLINE static inline const char * mbedtls_pk_info_name(
    mbedtls_pk_handle_t info )
{
    return( info->name );
}

MBEDTLS_ALWAYS_INLINE static inline size_t mbedtls_pk_info_get_bitlen(
    mbedtls_pk_handle_t info, const void *ctx )
{
    return( info->get_bitlen( ctx ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_can_do(
    mbedtls_pk_handle_t info, mbedtls_pk_type_t type )
{
    return( info->can_do( type ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_verify_func(
    mbedtls_pk_handle_t info, void *ctx, mbedtls_md_type_t md_alg,
    const unsigned char *hash, size_t hash_len,
    const unsigned char *sig, size_t sig_len )
{
    if( info->verify_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( info->verify_func( ctx, md_alg, hash, hash_len, sig, sig_len ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_sign_func(
    mbedtls_pk_handle_t info, void *ctx, mbedtls_md_type_t md_alg,
    const unsigned char *hash, size_t hash_len,
    unsigned char *sig, size_t *sig_len,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng )
{
    if( info->sign_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( info->sign_func( ctx, md_alg, hash, hash_len, sig, sig_len,
                             f_rng, p_rng ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_decrypt_func(
    mbedtls_pk_handle_t info, void *ctx,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng )
{
    if( info->decrypt_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( info->decrypt_func( ctx, input, ilen, output, olen, osize,
                                f_rng, p_rng ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_encrypt_func(
    mbedtls_pk_handle_t info, void *ctx,
    const unsigned char *input, size_t ilen,
    unsigned char *output, size_t *olen, size_t osize,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng )
{
    if( info->encrypt_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( info->encrypt_func( ctx, input, ilen, output, olen, osize,
                                f_rng, p_rng ) );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_check_pair_func(
    mbedtls_pk_handle_t info, const void *pub, const void *prv )
{
    if( info->check_pair_func == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    return( info->check_pair_func( pub, prv ) );
}

MBEDTLS_ALWAYS_INLINE static inline void *mbedtls_pk_info_ctx_alloc_func(
    mbedtls_pk_handle_t info )
{
    return( info->ctx_alloc_func( ) );
}

MBEDTLS_ALWAYS_INLINE static inline void mbedtls_pk_info_ctx_free_func(
    mbedtls_pk_handle_t info, void *ctx )
{
    info->ctx_free_func( ctx );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_pk_info_debug_func(
    mbedtls_pk_handle_t info,
    const void *ctx, mbedtls_pk_debug_item *items )
{
    if( info->debug_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    info->debug_func( ctx, items );
    return( 0 );
}
#endif /* MBEDTLS_PK_SINGLE_TYPE */

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
/* Container for RSA-alt */
typedef struct
{
    void *key;
    mbedtls_pk_rsa_alt_decrypt_func decrypt_func;
    mbedtls_pk_rsa_alt_sign_func sign_func;
    mbedtls_pk_rsa_alt_key_len_func key_len_func;
} mbedtls_rsa_alt_context;
#endif

#if !defined(MBEDTLS_PK_SINGLE_TYPE)
#if defined(MBEDTLS_RSA_C)
extern const mbedtls_pk_info_t mbedtls_rsa_info;
#endif

#if defined(MBEDTLS_ECP_C)
extern const mbedtls_pk_info_t mbedtls_eckey_info;
extern const mbedtls_pk_info_t mbedtls_eckeydh_info;
#endif

#if defined(MBEDTLS_ECDSA_C)
extern const mbedtls_pk_info_t mbedtls_ecdsa_info;
#endif

#if defined(MBEDTLS_USE_TINYCRYPT)
extern const mbedtls_pk_info_t mbedtls_uecc_eckey_info;
#endif

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
extern const mbedtls_pk_info_t mbedtls_rsa_alt_info;
#endif
#endif /* MBEDTLS_PK_SINGLE_TYPE */

#endif /* MBEDTLS_PK_WRAP_H */
