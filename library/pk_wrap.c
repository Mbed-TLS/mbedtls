/*
 *  Public Key abstraction layer: wrapper functions
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
#include "mbedtls/pk_internal.h"

/* Even if RSA not activated, for the sake of RSA-alt */
#include "mbedtls/rsa.h"

#include <string.h>

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
#include "mbedtls/platform_util.h"
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#include "mbedtls/x509.h"
#include "mbedtls/asn1.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include <limits.h>
#include <stdint.h>

#if defined(MBEDTLS_RSA_C)
static int rsa_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_RSA ||
            type == MBEDTLS_PK_RSASSA_PSS );
}

static size_t rsa_get_bitlen( const void *ctx )
{
    const mbedtls_rsa_context * rsa = (const mbedtls_rsa_context *) ctx;
    return( 8 * mbedtls_rsa_get_len( rsa ) );
}

static int rsa_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len )
{
    int ret;
    mbedtls_rsa_context * rsa = (mbedtls_rsa_context *) ctx;
    size_t rsa_len = mbedtls_rsa_get_len( rsa );

#if SIZE_MAX > UINT_MAX
    if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
#endif /* SIZE_MAX > UINT_MAX */

    if( sig_len < rsa_len )
        return( MBEDTLS_ERR_RSA_VERIFY_FAILED );

    if( ( ret = mbedtls_rsa_pkcs1_verify( rsa, NULL, NULL,
                                  MBEDTLS_RSA_PUBLIC, md_alg,
                                  (unsigned int) hash_len, hash, sig ) ) != 0 )
        return( ret );

    /* The buffer contains a valid signature followed by extra data.
     * We have a special error code for that so that so that callers can
     * use mbedtls_pk_verify() to check "Does the buffer start with a
     * valid signature?" and not just "Does the buffer contain a valid
     * signature?". */
    if( sig_len > rsa_len )
        return( MBEDTLS_ERR_PK_SIG_LEN_MISMATCH );

    return( 0 );
}

static int rsa_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedtls_rsa_context * rsa = (mbedtls_rsa_context *) ctx;

#if SIZE_MAX > UINT_MAX
    if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
#endif /* SIZE_MAX > UINT_MAX */

    *sig_len = mbedtls_rsa_get_len( rsa );

    return( mbedtls_rsa_pkcs1_sign( rsa, f_rng, p_rng, MBEDTLS_RSA_PRIVATE,
                md_alg, (unsigned int) hash_len, hash, sig ) );
}

static int rsa_decrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedtls_rsa_context * rsa = (mbedtls_rsa_context *) ctx;

    if( ilen != mbedtls_rsa_get_len( rsa ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    return( mbedtls_rsa_pkcs1_decrypt( rsa, f_rng, p_rng,
                MBEDTLS_RSA_PRIVATE, olen, input, output, osize ) );
}

static int rsa_encrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedtls_rsa_context * rsa = (mbedtls_rsa_context *) ctx;
    *olen = mbedtls_rsa_get_len( rsa );

    if( *olen > osize )
        return( MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE );

    return( mbedtls_rsa_pkcs1_encrypt( rsa, f_rng, p_rng, MBEDTLS_RSA_PUBLIC,
                                       ilen, input, output ) );
}

static int rsa_check_pair_wrap( const void *pub, const void *prv )
{
    return( mbedtls_rsa_check_pub_priv( (const mbedtls_rsa_context *) pub,
                                (const mbedtls_rsa_context *) prv ) );
}

static void *rsa_alloc_wrap( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_rsa_context ) );

    if( ctx != NULL )
        mbedtls_rsa_init( (mbedtls_rsa_context *) ctx, 0, 0 );

    return( ctx );
}

static void rsa_free_wrap( void *ctx )
{
    mbedtls_rsa_free( (mbedtls_rsa_context *) ctx );
    mbedtls_free( ctx );
}

static void rsa_debug( const void *ctx, mbedtls_pk_debug_item *items )
{
    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.N";
    items->value = &( ((mbedtls_rsa_context *) ctx)->N );

    items++;

    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.E";
    items->value = &( ((mbedtls_rsa_context *) ctx)->E );
}

const mbedtls_pk_info_t mbedtls_rsa_info = {
    MBEDTLS_PK_RSA,
    "RSA",
    rsa_get_bitlen,
    rsa_can_do,
    rsa_verify_wrap,
    rsa_sign_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    rsa_decrypt_wrap,
    rsa_encrypt_wrap,
    rsa_check_pair_wrap,
    rsa_alloc_wrap,
    rsa_free_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    rsa_debug,
};
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECP_C)
/*
 * Generic EC key
 */
static int eckey_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_ECKEY ||
            type == MBEDTLS_PK_ECKEY_DH ||
            type == MBEDTLS_PK_ECDSA );
}

static size_t eckey_get_bitlen( const void *ctx )
{
    return( ((mbedtls_ecp_keypair *) ctx)->grp.pbits );
}

#if defined(MBEDTLS_ECDSA_C)
/* Forward declarations */
static int ecdsa_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len );

static int ecdsa_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

static int eckey_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    mbedtls_ecdsa_context ecdsa;

    mbedtls_ecdsa_init( &ecdsa );

    if( ( ret = mbedtls_ecdsa_from_keypair( &ecdsa, ctx ) ) == 0 )
        ret = ecdsa_verify_wrap( &ecdsa, md_alg, hash, hash_len, sig, sig_len );

    mbedtls_ecdsa_free( &ecdsa );

    return( ret );
}

static int eckey_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret;
    mbedtls_ecdsa_context ecdsa;

    mbedtls_ecdsa_init( &ecdsa );

    if( ( ret = mbedtls_ecdsa_from_keypair( &ecdsa, ctx ) ) == 0 )
        ret = ecdsa_sign_wrap( &ecdsa, md_alg, hash, hash_len, sig, sig_len,
                               f_rng, p_rng );

    mbedtls_ecdsa_free( &ecdsa );

    return( ret );
}

#if defined(MBEDTLS_ECP_RESTARTABLE)
/* Forward declarations */
static int ecdsa_verify_rs_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len,
                       void *rs_ctx );

static int ecdsa_sign_rs_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                   void *rs_ctx );

/*
 * Restart context for ECDSA operations with ECKEY context
 *
 * We need to store an actual ECDSA context, as we need to pass the same to
 * the underlying ecdsa function, so we can't create it on the fly every time.
 */
typedef struct
{
    mbedtls_ecdsa_restart_ctx ecdsa_rs;
    mbedtls_ecdsa_context ecdsa_ctx;
} eckey_restart_ctx;

static void *eckey_rs_alloc( void )
{
    eckey_restart_ctx *rs_ctx;

    void *ctx = mbedtls_calloc( 1, sizeof( eckey_restart_ctx ) );

    if( ctx != NULL )
    {
        rs_ctx = ctx;
        mbedtls_ecdsa_restart_init( &rs_ctx->ecdsa_rs );
        mbedtls_ecdsa_init( &rs_ctx->ecdsa_ctx );
    }

    return( ctx );
}

static void eckey_rs_free( void *ctx )
{
    eckey_restart_ctx *rs_ctx;

    if( ctx == NULL)
        return;

    rs_ctx = ctx;
    mbedtls_ecdsa_restart_free( &rs_ctx->ecdsa_rs );
    mbedtls_ecdsa_free( &rs_ctx->ecdsa_ctx );

    mbedtls_free( ctx );
}

static int eckey_verify_rs_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len,
                       void *rs_ctx )
{
    int ret;
    eckey_restart_ctx *rs = rs_ctx;

    /* Should never happen */
    if( rs == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    /* set up our own sub-context if needed (that is, on first run) */
    if( rs->ecdsa_ctx.grp.pbits == 0 )
        MBEDTLS_MPI_CHK( mbedtls_ecdsa_from_keypair( &rs->ecdsa_ctx, ctx ) );

    MBEDTLS_MPI_CHK( ecdsa_verify_rs_wrap( &rs->ecdsa_ctx,
                                           md_alg, hash, hash_len,
                                           sig, sig_len, &rs->ecdsa_rs ) );

cleanup:
    return( ret );
}

static int eckey_sign_rs_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                       void *rs_ctx )
{
    int ret;
    eckey_restart_ctx *rs = rs_ctx;

    /* Should never happen */
    if( rs == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    /* set up our own sub-context if needed (that is, on first run) */
    if( rs->ecdsa_ctx.grp.pbits == 0 )
        MBEDTLS_MPI_CHK( mbedtls_ecdsa_from_keypair( &rs->ecdsa_ctx, ctx ) );

    MBEDTLS_MPI_CHK( ecdsa_sign_rs_wrap( &rs->ecdsa_ctx, md_alg,
                                         hash, hash_len, sig, sig_len,
                                         f_rng, p_rng, &rs->ecdsa_rs ) );

cleanup:
    return( ret );
}
#endif /* MBEDTLS_ECP_RESTARTABLE */
#endif /* MBEDTLS_ECDSA_C */

static int eckey_check_pair( const void *pub, const void *prv )
{
    return( mbedtls_ecp_check_pub_priv( (const mbedtls_ecp_keypair *) pub,
                                (const mbedtls_ecp_keypair *) prv ) );
}

static void *eckey_alloc_wrap( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_ecp_keypair ) );

    if( ctx != NULL )
        mbedtls_ecp_keypair_init( ctx );

    return( ctx );
}

static void eckey_free_wrap( void *ctx )
{
    mbedtls_ecp_keypair_free( (mbedtls_ecp_keypair *) ctx );
    mbedtls_free( ctx );
}

static void eckey_debug( const void *ctx, mbedtls_pk_debug_item *items )
{
    items->type = MBEDTLS_PK_DEBUG_ECP;
    items->name = "eckey.Q";
    items->value = &( ((mbedtls_ecp_keypair *) ctx)->Q );
}

const mbedtls_pk_info_t mbedtls_eckey_info = {
    MBEDTLS_PK_ECKEY,
    "EC",
    eckey_get_bitlen,
    eckey_can_do,
#if defined(MBEDTLS_ECDSA_C)
    eckey_verify_wrap,
    eckey_sign_wrap,
#if defined(MBEDTLS_ECP_RESTARTABLE)
    eckey_verify_rs_wrap,
    eckey_sign_rs_wrap,
#endif
#else /* MBEDTLS_ECDSA_C */
    NULL,
    NULL,
#endif /* MBEDTLS_ECDSA_C */
    NULL,
    NULL,
    eckey_check_pair,
    eckey_alloc_wrap,
    eckey_free_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    eckey_rs_alloc,
    eckey_rs_free,
#endif
    eckey_debug,
};

/*
 * EC key restricted to ECDH
 */
static int eckeydh_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_ECKEY ||
            type == MBEDTLS_PK_ECKEY_DH );
}

const mbedtls_pk_info_t mbedtls_eckeydh_info = {
    MBEDTLS_PK_ECKEY_DH,
    "EC_DH",
    eckey_get_bitlen,         /* Same underlying key structure */
    eckeydh_can_do,
    NULL,
    NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    NULL,
    NULL,
    eckey_check_pair,
    eckey_alloc_wrap,       /* Same underlying key structure */
    eckey_free_wrap,        /* Same underlying key structure */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    eckey_debug,            /* Same underlying key structure */
};
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_ECDSA_C)
static int ecdsa_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_ECDSA );
}

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static psa_status_t mbedtls_psa_get_free_key_slot( psa_key_slot_t *key )
{
    for( psa_key_slot_t slot = 1; slot <= 32; slot++ )
    {
        if( psa_get_key_information( slot, NULL, NULL )  == PSA_ERROR_EMPTY_SLOT )
        {
            *key = slot;
            return( PSA_SUCCESS );
        }
    }
    return( PSA_ERROR_INSUFFICIENT_MEMORY );
}

static psa_algorithm_t translate_md_to_psa( mbedtls_md_type_t md_alg )
{
    switch( md_alg )
    {
#if defined(MBEDTLS_MD2_C)
    case MBEDTLS_MD_MD2:
        return( PSA_ALG_MD2 );
#endif
#if defined(MBEDTLS_MD4_C)
    case MBEDTLS_MD_MD4:
        return( PSA_ALG_MD4 );
#endif
#if defined(MBEDTLS_MD5_C)
    case MBEDTLS_MD_MD5:
        return( PSA_ALG_MD5 );
#endif
#if defined(MBEDTLS_SHA1_C)
    case MBEDTLS_MD_SHA1:
        return( PSA_ALG_SHA_1 );
#endif
#if defined(MBEDTLS_SHA256_C)
    case MBEDTLS_MD_SHA224:
        return( PSA_ALG_SHA_224 );
    case MBEDTLS_MD_SHA256:
        return( PSA_ALG_SHA_256 );
#endif
#if defined(MBEDTLS_SHA512_C)
    case MBEDTLS_MD_SHA384:
        return( PSA_ALG_SHA_384 );
    case MBEDTLS_MD_SHA512:
        return( PSA_ALG_SHA_512 );
#endif
#if defined(MBEDTLS_RIPEMD160_C)
    case MBEDTLS_MD_RIPEMD160:
        return( PSA_ALG_RIPEMD160 );
#endif
    case MBEDTLS_MD_NONE:  // Intentional fallthrough
    default:
        return( 0 );
    }
}

/*
 * Convert a signature from an ASN.1 sequence of two integers
 * to a raw {r,s} buffer. Note: upon a successful call, the caller
 * takes ownership of the sig->p buffer.
 */
static int extract_ecdsa_sig( unsigned char **p, const unsigned char *end,
                              mbedtls_asn1_buf *sig )
{
    int ret;
    size_t len_signature;
    size_t len_partial;
    int tag_type;
    if( ( end - *p ) < 1 )
    {
        return( MBEDTLS_ERR_X509_INVALID_SIGNATURE +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );
    }
    tag_type = **p;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len_partial,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_SIGNATURE + ret );
    }

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len_partial, MBEDTLS_ASN1_INTEGER ) )
            != 0 )
        return( ret );

    if( **p == '\0' )
    {
        ( *p )++;
        len_partial--;
    }

    sig->p = mbedtls_calloc( 2, len_partial );
    if( sig->p == NULL )
        return( MBEDTLS_ERR_ASN1_ALLOC_FAILED );

    memcpy( sig->p, *p, len_partial );
    len_signature = len_partial;
    ( *p ) += len_partial;
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len_partial,
                                      MBEDTLS_ASN1_INTEGER ) ) != 0 )
    {
        mbedtls_free( sig->p );
        sig->p = NULL;
        return( ret );
    }

    if( **p == '\0' )
    {
        ( *p )++;
        len_partial--;
    }

    memcpy( sig->p + len_partial, *p, len_partial );
    len_signature += len_partial;
    sig->tag = tag_type;
    sig->len = len_signature;
    ( *p ) += len_partial;
    return( 0 );
}

static psa_ecc_curve_t mbedtls_ecc_group_to_psa( mbedtls_ecp_group_id grpid )
{
    switch( grpid )
    {
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP192R1:
            return( PSA_ECC_CURVE_SECP192R1 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP224R1:
            return( PSA_ECC_CURVE_SECP224R1 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP256R1:
            return( PSA_ECC_CURVE_SECP256R1 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP384R1:
            return( PSA_ECC_CURVE_SECP384R1 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
        case MBEDTLS_ECP_DP_SECP521R1:
            return( PSA_ECC_CURVE_SECP521R1 );
#endif
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
        case MBEDTLS_ECP_DP_BP256R1:
            return( PSA_ECC_CURVE_BRAINPOOL_P256R1 );
#endif
#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
        case MBEDTLS_ECP_DP_BP384R1:
            return( PSA_ECC_CURVE_BRAINPOOL_P384R1 );
#endif
#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
        case MBEDTLS_ECP_DP_BP512R1:
            return( PSA_ECC_CURVE_BRAINPOOL_P512R1 );
#endif
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
        case MBEDTLS_ECP_DP_CURVE25519:
            return( PSA_ECC_CURVE_CURVE25519 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
        case MBEDTLS_ECP_DP_SECP192K1:
            return( PSA_ECC_CURVE_SECP192K1 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
        case MBEDTLS_ECP_DP_SECP224K1:
            return( PSA_ECC_CURVE_SECP224K1 );
#endif
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
        case MBEDTLS_ECP_DP_SECP256K1:
            return( PSA_ECC_CURVE_SECP256K1 );
#endif
#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
        case MBEDTLS_ECP_DP_CURVE448:
            return( PSA_ECC_CURVE_CURVE448 );
#endif
        default:
            return( 0 );
    }
}

static int ecdsa_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    psa_key_slot_t key_slot;
    psa_key_policy_t policy;
    psa_key_type_t psa_type;
    mbedtls_pk_context key;
    mbedtls_asn1_buf signature;
    int key_len;
    const int buf_len = 30 + 2 * MBEDTLS_ECP_MAX_BYTES; // Equivalent of ECP_PUB_DER_MAX_BYTES
    unsigned char buf[buf_len];
    unsigned char *p = (unsigned char*) sig;
    mbedtls_pk_info_t pk_info = mbedtls_eckey_info;
    psa_algorithm_t psa_sig_md = PSA_ALG_ECDSA( translate_md_to_psa( md_alg ) );
    psa_ecc_curve_t curve = mbedtls_ecc_group_to_psa ( ( (mbedtls_ecdsa_context *) ctx )->grp.id );

    memset( &signature, 0, sizeof( mbedtls_asn1_buf ) );
    key.pk_info = &pk_info;
    key.pk_ctx = ctx;
    psa_crypto_init();

    psa_type = PSA_KEY_TYPE_ECC_PUBLIC_KEY( curve );

    if( extract_ecdsa_sig( &p, p + sig_len, &signature ) != 0 )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    key_len = mbedtls_pk_write_pubkey_der( &key, buf, buf_len );
    if( key_len <= 0 )
    {
        ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        goto cleanup;
    }

    if( mbedtls_psa_get_free_key_slot( &key_slot ) != PSA_SUCCESS )
    {
        ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
        goto cleanup;
    }
    psa_key_policy_init( &policy );
    psa_key_policy_set_usage( &policy, PSA_KEY_USAGE_VERIFY, psa_sig_md );
    if( psa_set_key_policy( key_slot, &policy ) != PSA_SUCCESS )
    {
        ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
        goto cleanup;
    }

    if( psa_import_key( key_slot, psa_type, buf+buf_len-key_len, key_len )
         != PSA_SUCCESS )
    {
        ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        goto cleanup;
    }

    if( psa_asymmetric_verify( key_slot, psa_sig_md,
                               hash, hash_len,
                               signature.p, signature.len )
         != PSA_SUCCESS )
    {
         psa_destroy_key( key_slot );
         ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
         goto cleanup;
    }
    ret = 0;
    psa_destroy_key( key_slot );

    cleanup:
    mbedtls_free( signature.p );
    return( ret );
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int ecdsa_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    ((void) md_alg);

    ret = mbedtls_ecdsa_read_signature( (mbedtls_ecdsa_context *) ctx,
                                hash, hash_len, sig, sig_len );

    if( ret == MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH )
        return( MBEDTLS_ERR_PK_SIG_LEN_MISMATCH );

    return( ret );
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

static int ecdsa_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return( mbedtls_ecdsa_write_signature( (mbedtls_ecdsa_context *) ctx,
                md_alg, hash, hash_len, sig, sig_len, f_rng, p_rng ) );
}

#if defined(MBEDTLS_ECP_RESTARTABLE)
static int ecdsa_verify_rs_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len,
                       void *rs_ctx )
{
    int ret;
    ((void) md_alg);

    ret = mbedtls_ecdsa_read_signature_restartable(
            (mbedtls_ecdsa_context *) ctx,
            hash, hash_len, sig, sig_len,
            (mbedtls_ecdsa_restart_ctx *) rs_ctx );

    if( ret == MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH )
        return( MBEDTLS_ERR_PK_SIG_LEN_MISMATCH );

    return( ret );
}

static int ecdsa_sign_rs_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                   void *rs_ctx )
{
    return( mbedtls_ecdsa_write_signature_restartable(
                (mbedtls_ecdsa_context *) ctx,
                md_alg, hash, hash_len, sig, sig_len, f_rng, p_rng,
                (mbedtls_ecdsa_restart_ctx *) rs_ctx ) );

}
#endif /* MBEDTLS_ECP_RESTARTABLE */

static void *ecdsa_alloc_wrap( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_ecdsa_context ) );

    if( ctx != NULL )
        mbedtls_ecdsa_init( (mbedtls_ecdsa_context *) ctx );

    return( ctx );
}

static void ecdsa_free_wrap( void *ctx )
{
    mbedtls_ecdsa_free( (mbedtls_ecdsa_context *) ctx );
    mbedtls_free( ctx );
}

#if defined(MBEDTLS_ECP_RESTARTABLE)
static void *ecdsa_rs_alloc( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_ecdsa_restart_ctx ) );

    if( ctx != NULL )
        mbedtls_ecdsa_restart_init( ctx );

    return( ctx );
}

static void ecdsa_rs_free( void *ctx )
{
    mbedtls_ecdsa_restart_free( ctx );
    mbedtls_free( ctx );
}
#endif /* MBEDTLS_ECP_RESTARTABLE */

const mbedtls_pk_info_t mbedtls_ecdsa_info = {
    MBEDTLS_PK_ECDSA,
    "ECDSA",
    eckey_get_bitlen,     /* Compatible key structures */
    ecdsa_can_do,
    ecdsa_verify_wrap,
    ecdsa_sign_wrap,
#if defined(MBEDTLS_ECP_RESTARTABLE)
    ecdsa_verify_rs_wrap,
    ecdsa_sign_rs_wrap,
#endif
    NULL,
    NULL,
    eckey_check_pair,   /* Compatible key structures */
    ecdsa_alloc_wrap,
    ecdsa_free_wrap,
#if defined(MBEDTLS_ECP_RESTARTABLE)
    ecdsa_rs_alloc,
    ecdsa_rs_free,
#endif
    eckey_debug,        /* Compatible key structures */
};
#endif /* MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
/*
 * Support for alternative RSA-private implementations
 */

static int rsa_alt_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_RSA );
}

static size_t rsa_alt_get_bitlen( const void *ctx )
{
    const mbedtls_rsa_alt_context *rsa_alt = (const mbedtls_rsa_alt_context *) ctx;

    return( 8 * rsa_alt->key_len_func( rsa_alt->key ) );
}

static int rsa_alt_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedtls_rsa_alt_context *rsa_alt = (mbedtls_rsa_alt_context *) ctx;

#if SIZE_MAX > UINT_MAX
    if( UINT_MAX < hash_len )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
#endif /* SIZE_MAX > UINT_MAX */

    *sig_len = rsa_alt->key_len_func( rsa_alt->key );

    return( rsa_alt->sign_func( rsa_alt->key, f_rng, p_rng, MBEDTLS_RSA_PRIVATE,
                md_alg, (unsigned int) hash_len, hash, sig ) );
}

static int rsa_alt_decrypt_wrap( void *ctx,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output, size_t *olen, size_t osize,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    mbedtls_rsa_alt_context *rsa_alt = (mbedtls_rsa_alt_context *) ctx;

    ((void) f_rng);
    ((void) p_rng);

    if( ilen != rsa_alt->key_len_func( rsa_alt->key ) )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    return( rsa_alt->decrypt_func( rsa_alt->key,
                MBEDTLS_RSA_PRIVATE, olen, input, output, osize ) );
}

#if defined(MBEDTLS_RSA_C)
static int rsa_alt_check_pair( const void *pub, const void *prv )
{
    unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
    unsigned char hash[32];
    size_t sig_len = 0;
    int ret;

    if( rsa_alt_get_bitlen( prv ) != rsa_get_bitlen( pub ) )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    memset( hash, 0x2a, sizeof( hash ) );

    if( ( ret = rsa_alt_sign_wrap( (void *) prv, MBEDTLS_MD_NONE,
                                   hash, sizeof( hash ),
                                   sig, &sig_len, NULL, NULL ) ) != 0 )
    {
        return( ret );
    }

    if( rsa_verify_wrap( (void *) pub, MBEDTLS_MD_NONE,
                         hash, sizeof( hash ), sig, sig_len ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    return( 0 );
}
#endif /* MBEDTLS_RSA_C */

static void *rsa_alt_alloc_wrap( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_rsa_alt_context ) );

    if( ctx != NULL )
        memset( ctx, 0, sizeof( mbedtls_rsa_alt_context ) );

    return( ctx );
}

static void rsa_alt_free_wrap( void *ctx )
{
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_rsa_alt_context ) );
    mbedtls_free( ctx );
}

const mbedtls_pk_info_t mbedtls_rsa_alt_info = {
    MBEDTLS_PK_RSA_ALT,
    "RSA-alt",
    rsa_alt_get_bitlen,
    rsa_alt_can_do,
    NULL,
    rsa_alt_sign_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    rsa_alt_decrypt_wrap,
    NULL,
#if defined(MBEDTLS_RSA_C)
    rsa_alt_check_pair,
#else
    NULL,
#endif
    rsa_alt_alloc_wrap,
    rsa_alt_free_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    NULL,
};

#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

#endif /* MBEDTLS_PK_C */
