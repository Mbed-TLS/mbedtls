/*
 *  Public Key abstraction layer
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

#if defined(MBEDTLS_PK_C)
#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/pk_info.h"

#include "mbedtls/bignum.h"

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif
#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif
#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif

#include <limits.h>

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/*
 * Initialise a mbedtls_pk_context
 */
void mbedtls_pk_init( mbedtls_pk_context *ctx )
{
    if( ctx == NULL )
        return;

    ctx->pk_info = NULL;
    ctx->pk_ctx = NULL;
}

/*
 * Free (the components of) a mbedtls_pk_context
 */
void mbedtls_pk_free( mbedtls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return;

    ctx->pk_info->ctx_free_func( ctx->pk_ctx );

    mbedtls_zeroize( ctx, sizeof( mbedtls_pk_context ) );
}

/*
 * Get pk_info structure from type
 */
const mbedtls_pk_info_t * mbedtls_pk_info_from_type( mbedtls_pk_type_t pk_type )
{
    switch( pk_type ) {
#if defined(MBEDTLS_RSA_C)
        case MBEDTLS_PK_RSA:
            return( &mbedtls_rsa_info );
#endif
#if defined(MBEDTLS_ECP_C)
        case MBEDTLS_PK_ECKEY:
            return( &mbedtls_eckey_info );
        case MBEDTLS_PK_ECKEY_DH:
            return( &mbedtls_eckeydh_info );
#endif
#if defined(MBEDTLS_ECDSA_C)
        case MBEDTLS_PK_ECDSA:
            return( &mbedtls_ecdsa_info );
#endif
        /* MBEDTLS_PK_RSA_ALT omitted on purpose */
        /* MBEDTLS_PK_OPAQUE omitted on purpose: they can't be built by parsing */
        default:
            return( NULL );
    }
}

/*
 * Initialise context
 */
int mbedtls_pk_setup( mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info )
{
    if( ctx == NULL || info == NULL || ctx->pk_info != NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( info->ctx_alloc_func != NULL )
    {
        if( ( ctx->pk_ctx = info->ctx_alloc_func( ) ) == NULL )
            return( MBEDTLS_ERR_PK_ALLOC_FAILED );
    }

    ctx->pk_info = info;

    return( 0 );
}

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
/*
 * Initialize an RSA-alt context
 */
int mbedtls_pk_setup_rsa_alt( mbedtls_pk_context *ctx, void * key,
                         mbedtls_pk_rsa_alt_decrypt_func decrypt_func,
                         mbedtls_pk_rsa_alt_sign_func sign_func,
                         mbedtls_pk_rsa_alt_key_len_func key_len_func )
{
    mbedtls_rsa_alt_context *rsa_alt;
    const mbedtls_pk_info_t *info = &mbedtls_rsa_alt_info;

    if( ctx == NULL || ctx->pk_info != NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->pk_ctx = info->ctx_alloc_func() ) == NULL )
        return( MBEDTLS_ERR_PK_ALLOC_FAILED );

    ctx->pk_info = info;

    rsa_alt = (mbedtls_rsa_alt_context *) ctx->pk_ctx;

    rsa_alt->key = key;
    rsa_alt->decrypt_func = decrypt_func;
    rsa_alt->sign_func = sign_func;
    rsa_alt->key_len_func = key_len_func;

    return( 0 );
}
#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

/*
 * Tell if a PK can do the operations of the given type
 */
int mbedtls_pk_can_do( const mbedtls_pk_context *ctx, mbedtls_pk_type_t type )
{
    /* null or NONE context can't do anything */
    if( ctx == NULL || ctx->pk_info == NULL )
        return( 0 );

    return( ctx->pk_info->can_do( ctx->pk_ctx, type ) );
}

/*
 * Helper for mbedtls_pk_sign and mbedtls_pk_verify
 */
static inline int pk_hashlen_helper( mbedtls_md_type_t md_alg, size_t *hash_len )
{
    const mbedtls_md_info_t *md_info;

    if( *hash_len != 0 )
        return( 0 );

    if( ( md_info = mbedtls_md_info_from_type( md_alg ) ) == NULL )
        return( -1 );

    *hash_len = mbedtls_md_get_size( md_info );
    return( 0 );
}

/*
 * Verify a signature
 */
int mbedtls_pk_verify( mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len )
{
    if( ctx == NULL || ctx->pk_info == NULL ||
        pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->verify_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->verify_func( ctx->pk_ctx, md_alg, hash, hash_len,
                                       sig, sig_len ) );
}

/*
 * Verify a signature with options
 */
int mbedtls_pk_verify_ext( mbedtls_pk_type_t type, const void *options,
                   mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ! mbedtls_pk_can_do( ctx, type ) )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    if( type == MBEDTLS_PK_RSASSA_PSS )
    {
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PKCS1_V21)
        int ret;
        const mbedtls_pk_rsassa_pss_options *pss_opts;

#if defined(MBEDTLS_HAVE_INT64)
        if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len )
            return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
#endif /* MBEDTLS_HAVE_INT64 */

        if( options == NULL )
            return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

        pss_opts = (const mbedtls_pk_rsassa_pss_options *) options;

        if( sig_len < mbedtls_pk_get_len( ctx ) )
            return( MBEDTLS_ERR_RSA_VERIFY_FAILED );

        ret = mbedtls_rsa_rsassa_pss_verify_ext( mbedtls_pk_rsa( *ctx ),
                NULL, NULL, MBEDTLS_RSA_PUBLIC,
                md_alg, (unsigned int) hash_len, hash,
                pss_opts->mgf1_hash_id,
                pss_opts->expected_salt_len,
                sig );
        if( ret != 0 )
            return( ret );

        if( sig_len > mbedtls_pk_get_len( ctx ) )
            return( MBEDTLS_ERR_PK_SIG_LEN_MISMATCH );

        return( 0 );
#else
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );
#endif /* MBEDTLS_RSA_C && MBEDTLS_PKCS1_V21 */
    }

    /* General case: no options */
    if( options != NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    return( mbedtls_pk_verify( ctx, md_alg, hash, hash_len, sig, sig_len ) );
}

/*
 * Make a signature
 */
int mbedtls_pk_sign( mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx == NULL || ctx->pk_info == NULL ||
        pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->sign_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->sign_func( ctx->pk_ctx, md_alg, hash, hash_len,
                                     sig, sig_len, f_rng, p_rng ) );
}

/*
 * Decrypt message
 */
int mbedtls_pk_decrypt( mbedtls_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->decrypt_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->decrypt_func( ctx->pk_ctx, input, ilen,
                output, olen, osize, f_rng, p_rng ) );
}

/*
 * Encrypt message
 */
int mbedtls_pk_encrypt( mbedtls_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->encrypt_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( ctx->pk_info->encrypt_func( ctx->pk_ctx, input, ilen,
                output, olen, osize, f_rng, p_rng ) );
}

/*
 * Check public-private key pair
 */
int mbedtls_pk_check_pair( const mbedtls_pk_context *pub, const mbedtls_pk_context *prv )
{
    if( pub == NULL || pub->pk_info == NULL ||
        prv == NULL || prv->pk_info == NULL )
    {
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
    }

    if( pub->pk_info == prv->pk_info && pub->pk_ctx == prv->pk_ctx )
        return( 0 );

    if( prv->pk_info->check_pair_func == NULL )
    {
        return( MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE );
    }

    if( prv->pk_info->type == MBEDTLS_PK_RSA_ALT )
    {
        if( pub->pk_info->type != MBEDTLS_PK_RSA )
            return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
    }
    else if( prv->pk_info->type != MBEDTLS_PK_OPAQUE )
    {
        if( pub->pk_info != prv->pk_info )
            return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
    }

    return( prv->pk_info->check_pair_func( pub, prv->pk_ctx ) );
}

/*
 * Get key size in bits
 */
size_t mbedtls_pk_get_bitlen( const mbedtls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( 0 );

    return( ctx->pk_info->get_bitlen( ctx->pk_ctx ) );
}

/*
 * Maximum signature size
 */
size_t mbedtls_pk_signature_size( const mbedtls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->signature_size_func == NULL )
        return( 0 );

    return( ctx->pk_info->signature_size_func( ctx->pk_ctx ) );
}

/*
 * Export debug information
 */
int mbedtls_pk_debug( const mbedtls_pk_context *ctx, mbedtls_pk_debug_item *items )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->debug_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    ctx->pk_info->debug_func( ctx->pk_ctx, items );
    return( 0 );
}

/*
 * Access the PK type name
 */
const char *mbedtls_pk_get_name( const mbedtls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( "invalid PK" );

    return( ctx->pk_info->name );
}

/*
 * Access the PK type.
 * For an opaque key pair object, this does not give any information on the
 * underlying cryptographic material.
 */
mbedtls_pk_type_t mbedtls_pk_get_type( const mbedtls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDTLS_PK_NONE );

    return( ctx->pk_info->type );
}



#if defined(MBEDTLS_ASYNC_C)

mbedtls_async_context_t *mbedtls_pk_async_alloc( mbedtls_pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( NULL );

    if( ctx->pk_info->async_alloc_func == NULL )
        return( mbedtls_async_alloc( &mbedtls_async_synchronous_info ) );

    return( ctx->pk_info->async_alloc_func( ctx->pk_ctx ) );
}

static int mbedtls_pk_async_sign_internal(
    mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
    const unsigned char *hash, size_t hash_len,
    unsigned char *sig, size_t *sig_len, size_t sig_size,
    mbedtls_async_context_t *async_ctx,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ctx->pk_info->async_start_func == NULL || async_ctx == NULL )
    {
        if( ctx->pk_info->signature_size_func == NULL )
            return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
        if( sig_size < ctx->pk_info->signature_size_func( ctx->pk_ctx ) )
            return( MBEDTLS_ERR_PK_SIG_LEN_MISMATCH );
        return( mbedtls_pk_sign( ctx, md_alg, hash, hash_len,
                                 sig, sig_len, f_rng, p_rng ) );
    }

    if( pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    return( ctx->pk_info->async_start_func( ctx->pk_ctx, async_ctx,
                                            MBEDTLS_ASYNC_OP_PK_SIGN,
                                            md_alg, hash, hash_len,
                                            sig, sig_size,
                                            f_rng, p_rng ) );
}

int mbedtls_pk_async_sign( mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           unsigned char *sig, size_t sig_size,
                           mbedtls_async_context_t *async_ctx,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng )
{
    size_t sig_len;
    int ret = mbedtls_async_set_started( async_ctx,
                                         MBEDTLS_ASYNC_OP_PK_SIGN );
    if( ret != 0 )
        return( ret );
    ret = mbedtls_pk_async_sign_internal( ctx, md_alg, hash, hash_len,
                                          sig, &sig_len, sig_size,
                                          async_ctx, f_rng, p_rng );
    if( ret != MBEDTLS_ERR_ASYNC_IN_PROGRESS )
        (void) mbedtls_async_set_completed( async_ctx, ret, sig_len );
    return( ret );
}

#endif /* MBEDTLS_ASYNC_C */


#endif /* MBEDTLS_PK_C */
