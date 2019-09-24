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
#define MBEDTLS_PK_INFO_ECKEY_GET_BITLEN        uecc_eckey_get_bitlen
#define MBEDTLS_PK_INFO_ECKEY_CAN_DO            uecc_eckey_can_do
#define MBEDTLS_PK_INFO_ECKEY_VERIFY_FUNC       uecc_eckey_verify_wrap
#define MBEDTLS_PK_INFO_ECKEY_SIGN_FUNC         uecc_eckey_sign_wrap
#define MBEDTLS_PK_INFO_ECKEY_DECRYPT_FUNC      NULL
#define MBEDTLS_PK_INFO_ECKEY_DECRYPT_OMIT      1
#define MBEDTLS_PK_INFO_ECKEY_ENCRYPT_FUNC      NULL
#define MBEDTLS_PK_INFO_ECKEY_ENCRYPT_OMIT      1
#define MBEDTLS_PK_INFO_ECKEY_CHECK_PAIR_FUNC   uecc_eckey_check_pair
#define MBEDTLS_PK_INFO_ECKEY_CTX_ALLOC_FUNC    uecc_eckey_alloc_wrap
#define MBEDTLS_PK_INFO_ECKEY_CTX_FREE_FUNC     uecc_eckey_free_wrap
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
