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

#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
#include "mbedtls/rsa.h"
#endif
#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif
#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif
#if defined(MBEDTLS_USE_TINYCRYPT)
#include "tinycrypt/ecc.h"
#include "tinycrypt/ecc_dsa.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#endif /* MBEDTLS_USE_TINYCRYPT */

#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include <string.h>
#include <limits.h>
#include <stdint.h>

/* Parameter validation macros based on platform_util.h */
#define PK_VALIDATE_RET( cond )    \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_PK_BAD_INPUT_DATA )
#define PK_VALIDATE( cond )        \
    MBEDTLS_INTERNAL_VALIDATE( cond )

/*
 * Internal wrappers around RSA functions
 */
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

/*
 * Internal wrappers around ECC functions - based on ECP module
 */
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

/*
 * Internal wrappers around ECC functions - based on TinyCrypt
 */
#if defined(MBEDTLS_USE_TINYCRYPT)
/*
 * An ASN.1 encoded signature is a sequence of two ASN.1 integers. Parse one of
 * those integers and convert it to the fixed-length encoding.
 */
static int extract_ecdsa_sig_int( unsigned char **from, const unsigned char *end,
                                  unsigned char *to, size_t to_len )
{
    int ret;
    size_t unpadded_len, padding_len;

    if( ( ret = mbedtls_asn1_get_tag( from, end, &unpadded_len,
                                      MBEDTLS_ASN1_INTEGER ) ) != 0 )
    {
        return( ret );
    }

    while( unpadded_len > 0 && **from == 0x00 )
    {
        ( *from )++;
        unpadded_len--;
    }

    if( unpadded_len > to_len || unpadded_len == 0 )
        return( MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    padding_len = to_len - unpadded_len;
    memset( to, 0x00, padding_len );
    mbedtls_platform_memcpy( to + padding_len, *from, unpadded_len );
    ( *from ) += unpadded_len;

    return( 0 );
}

/*
 * Convert a signature from an ASN.1 sequence of two integers
 * to a raw {r,s} buffer. Note: the provided sig buffer must be at least
 * twice as big as int_size.
 */
static int extract_ecdsa_sig( unsigned char **p, const unsigned char *end,
                              unsigned char *sig, size_t int_size )
{
    int ret;
    size_t tmp_size;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &tmp_size,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( ret );

    /* Extract r */
    if( ( ret = extract_ecdsa_sig_int( p, end, sig, int_size ) ) != 0 )
        return( ret );
    /* Extract s */
    if( ( ret = extract_ecdsa_sig_int( p, end, sig + int_size, int_size ) ) != 0 )
        return( ret );

    return( 0 );
}

static size_t uecc_eckey_get_bitlen( const void *ctx )
{
    (void) ctx;
    return( (size_t) ( NUM_ECC_BYTES * 8 ) );
}

static int uecc_eckey_check_pair( const void *pub, const void *prv )
{
    const mbedtls_uecc_keypair *uecc_pub =
        (const mbedtls_uecc_keypair *) pub;
    const mbedtls_uecc_keypair *uecc_prv =
        (const mbedtls_uecc_keypair *) prv;

    if( mbedtls_platform_memcmp( uecc_pub->public_key,
                uecc_prv->public_key,
                2 * NUM_ECC_BYTES ) == 0 )
    {
        return( 0 );
    }

    return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
}

static int uecc_eckey_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_ECDSA ||
            type == MBEDTLS_PK_ECKEY );
}

static int uecc_eckey_verify_wrap( void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    uint8_t signature[2*NUM_ECC_BYTES];
    unsigned char *p;
    const struct uECC_Curve_t * uecc_curve = uECC_secp256r1();
    const mbedtls_uecc_keypair *keypair = (const mbedtls_uecc_keypair *) ctx;

    ((void) md_alg);
    p = (unsigned char*) sig;

    ret = extract_ecdsa_sig( &p, sig + sig_len, signature, NUM_ECC_BYTES );
    if( ret != 0 )
        return( ret );

    ret = uECC_verify( keypair->public_key, hash,
                       (unsigned) hash_len, signature, uecc_curve );
    if( ret == 0 )
        return( MBEDTLS_ERR_PK_HW_ACCEL_FAILED );

    return( 0 );
}

/*
 * Simultaneously convert and move raw MPI from the beginning of a buffer
 * to an ASN.1 MPI at the end of the buffer.
 * See also mbedtls_asn1_write_mpi().
 *
 * p: pointer to the end of the output buffer
 * start: start of the output buffer, and also of the mpi to write at the end
 * n_len: length of the mpi to read from start
 *
 * Warning:
 * The total length of the output buffer must be smaller than 128 Bytes.
 */
static int asn1_write_mpibuf( unsigned char **p, unsigned char *start,
                              size_t n_len )
{
    size_t len = 0;

    if( (size_t)( *p - start ) < n_len )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    len = n_len;
    *p -= len;
    memmove( *p, start, len );

    /* ASN.1 DER encoding requires minimal length, so skip leading 0s.
     * Neither r nor s should be 0, but as a failsafe measure, still detect
     * that rather than overflowing the buffer in case of an error. */
    while( len > 0 && **p == 0x00 )
    {
        ++(*p);
        --len;
    }

    /* this is only reached if the signature was invalid */
    if( len == 0 )
        return( MBEDTLS_ERR_PK_HW_ACCEL_FAILED );

    /* if the msb is 1, ASN.1 requires that we prepend a 0.
     * Neither r nor s can be 0, so we can assume len > 0 at all times. */
    if( **p & 0x80 )
    {
        if( *p - start < 1 )
            return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

        *--(*p) = 0x00;
        len += 1;
    }

    /* The ASN.1 length encoding is just a single Byte containing the length,
     * as we assume that the total buffer length is smaller than 128 Bytes. */
    *--(*p) = len;
    *--(*p) = MBEDTLS_ASN1_INTEGER;
    len += 2;

    return( (int) len );
}

/* Transcode signature from uECC format to ASN.1 sequence.
 * See ecdsa_signature_to_asn1 in ecdsa.c, but with byte buffers instead of
 * MPIs, and in-place.
 *
 * [in/out] sig: the signature pre- and post-transcoding
 * [in/out] sig_len: signature length pre- and post-transcoding
 * [int] buf_len: the available size the in/out buffer
 *
 * Warning: buf_len must be smaller than 128 Bytes.
 */
static int pk_ecdsa_sig_asn1_from_uecc( unsigned char *sig, size_t *sig_len,
                                        size_t buf_len )
{
    int ret;
    size_t len = 0;
    const size_t rs_len = *sig_len / 2;
    unsigned char *p = sig + buf_len;

    MBEDTLS_ASN1_CHK_ADD( len, asn1_write_mpibuf( &p, sig + rs_len, rs_len ) );
    MBEDTLS_ASN1_CHK_ADD( len, asn1_write_mpibuf( &p, sig, rs_len ) );

    /* The ASN.1 length encoding is just a single Byte containing the length,
     * as we assume that the total buffer length is smaller than 128 Bytes. */
    *--p = len;
    *--p = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
    len += 2;

    memmove( sig, p, len );
    *sig_len = len;

    return( 0 );
}

static int uecc_eckey_sign_wrap( void *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    const mbedtls_uecc_keypair *keypair = (const mbedtls_uecc_keypair *) ctx;
    const struct uECC_Curve_t * uecc_curve = uECC_secp256r1();
    int ret;

    /*
     * RFC-4492 page 20:
     *
     *     Ecdsa-Sig-Value ::= SEQUENCE {
     *         r       INTEGER,
     *         s       INTEGER
     *     }
     *
     * Size is at most
     *    1 (tag) + 1 (len) + 1 (initial 0) + NUM_ECC_BYTES for each of r and s,
     *    twice that + 1 (tag) + 2 (len) for the sequence
     *
     * (The ASN.1 length encodings are all 1-Byte encodings because
     *  the total size is smaller than 128 Bytes).
     */
     #define MAX_SECP256R1_ECDSA_SIG_LEN ( 3 + 2 * ( 3 + NUM_ECC_BYTES ) )

    ret = uECC_sign( keypair->private_key, hash, hash_len, sig, uecc_curve );
    /* TinyCrypt uses 0 to signal errors. */
    if( ret == 0 )
        return( MBEDTLS_ERR_PK_HW_ACCEL_FAILED );

    *sig_len = 2 * NUM_ECC_BYTES;

    /* uECC owns its rng function pointer */
    (void) f_rng;
    (void) p_rng;
    (void) md_alg;

    return( pk_ecdsa_sig_asn1_from_uecc( sig, sig_len,
                                         MAX_SECP256R1_ECDSA_SIG_LEN ) );

    #undef MAX_SECP256R1_ECDSA_SIG_LEN
}

#if !defined(MBEDTLS_PK_SINGLE_TYPE)
static void *uecc_eckey_alloc_wrap( void )
{
    return( mbedtls_calloc( 1, sizeof( mbedtls_uecc_keypair ) ) );
}

static void uecc_eckey_free_wrap( void *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_uecc_keypair ) );
    mbedtls_free( ctx );
}
#endif /* MBEDTLS_PK_SINGLE_TYPE */

#if !defined(MBEDTLS_PK_SINGLE_TYPE)
const mbedtls_pk_info_t mbedtls_uecc_eckey_info =
                        MBEDTLS_PK_INFO( MBEDTLS_PK_INFO_ECKEY );
#endif
#endif /* MBEDTLS_USE_TINYCRYPT */

/*
 * Internal wrappers around ECDSA functions
 */
#if defined(MBEDTLS_ECDSA_C)
static int ecdsa_can_do( mbedtls_pk_type_t type )
{
    return( type == MBEDTLS_PK_ECDSA );
}

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

/*
 * Internal wrappers for RSA-alt support
 */
#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
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

    mbedtls_platform_memset( hash, 0x2a, sizeof( hash ) );

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
        mbedtls_platform_memset( ctx, 0, sizeof( mbedtls_rsa_alt_context ) );

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

MBEDTLS_ALWAYS_INLINE static inline mbedtls_pk_type_t pk_info_type(
    mbedtls_pk_handle_t info )
{
    (void) info;
    return( MBEDTLS_PK_INFO_TYPE( MBEDTLS_PK_SINGLE_TYPE ) );
}

MBEDTLS_ALWAYS_INLINE static inline const char * pk_info_name(
    mbedtls_pk_handle_t info )
{
    (void) info;
    return( MBEDTLS_PK_INFO_NAME( MBEDTLS_PK_SINGLE_TYPE ) );
}

MBEDTLS_ALWAYS_INLINE static inline size_t pk_info_get_bitlen(
    mbedtls_pk_handle_t info, const void *ctx )
{
    (void) info;
    return( MBEDTLS_PK_INFO_GET_BITLEN( MBEDTLS_PK_SINGLE_TYPE )( ctx ) );
}

MBEDTLS_ALWAYS_INLINE static inline int pk_info_can_do(
    mbedtls_pk_handle_t info, mbedtls_pk_type_t type )
{
    (void) info;
    return( MBEDTLS_PK_INFO_CAN_DO( MBEDTLS_PK_SINGLE_TYPE )( type ) );
}

MBEDTLS_ALWAYS_INLINE static inline int pk_info_verify_func(
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

MBEDTLS_ALWAYS_INLINE static inline int pk_info_sign_func(
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

MBEDTLS_ALWAYS_INLINE static inline int pk_info_decrypt_func(
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

MBEDTLS_ALWAYS_INLINE static inline int pk_info_encrypt_func(
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

MBEDTLS_ALWAYS_INLINE static inline int pk_info_check_pair_func(
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

MBEDTLS_ALWAYS_INLINE static inline int pk_info_debug_func(
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

MBEDTLS_ALWAYS_INLINE static inline mbedtls_pk_type_t pk_info_type(
    mbedtls_pk_handle_t info )
{
    return( info->type );
}

MBEDTLS_ALWAYS_INLINE static inline const char * pk_info_name(
    mbedtls_pk_handle_t info )
{
    return( info->name );
}

MBEDTLS_ALWAYS_INLINE static inline size_t pk_info_get_bitlen(
    mbedtls_pk_handle_t info, const void *ctx )
{
    return( info->get_bitlen( ctx ) );
}

MBEDTLS_ALWAYS_INLINE static inline int pk_info_can_do(
    mbedtls_pk_handle_t info, mbedtls_pk_type_t type )
{
    return( info->can_do( type ) );
}

MBEDTLS_ALWAYS_INLINE static inline int pk_info_verify_func(
    mbedtls_pk_handle_t info, void *ctx, mbedtls_md_type_t md_alg,
    const unsigned char *hash, size_t hash_len,
    const unsigned char *sig, size_t sig_len )
{
    if( info->verify_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    return( info->verify_func( ctx, md_alg, hash, hash_len, sig, sig_len ) );
}

MBEDTLS_ALWAYS_INLINE static inline int pk_info_sign_func(
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

MBEDTLS_ALWAYS_INLINE static inline int pk_info_decrypt_func(
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

MBEDTLS_ALWAYS_INLINE static inline int pk_info_encrypt_func(
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

MBEDTLS_ALWAYS_INLINE static inline int pk_info_check_pair_func(
    mbedtls_pk_handle_t info, const void *pub, const void *prv )
{
    if( info->check_pair_func == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    return( info->check_pair_func( pub, prv ) );
}

MBEDTLS_ALWAYS_INLINE static inline void *pk_info_ctx_alloc_func(
    mbedtls_pk_handle_t info )
{
    return( info->ctx_alloc_func( ) );
}

MBEDTLS_ALWAYS_INLINE static inline void pk_info_ctx_free_func(
    mbedtls_pk_handle_t info, void *ctx )
{
    info->ctx_free_func( ctx );
}

MBEDTLS_ALWAYS_INLINE static inline int pk_info_debug_func(
    mbedtls_pk_handle_t info,
    const void *ctx, mbedtls_pk_debug_item *items )
{
    if( info->debug_func == NULL )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    info->debug_func( ctx, items );
    return( 0 );
}

#endif /* MBEDTLS_PK_SINGLE_TYPE */

/*
 * Initialise a mbedtls_pk_context
 */
void mbedtls_pk_init( mbedtls_pk_context *ctx )
{
    PK_VALIDATE( ctx != NULL );

#if !defined(MBEDTLS_PK_SINGLE_TYPE)
    ctx->pk_info = MBEDTLS_PK_INVALID_HANDLE;
    ctx->pk_ctx = NULL;
#else
    memset( ctx, 0, sizeof( mbedtls_pk_context ) );
#endif
}

/*
 * Free (the components of) a mbedtls_pk_context
 */
void mbedtls_pk_free( mbedtls_pk_context *ctx )
{
    if( ctx == NULL )
        return;

#if !defined(MBEDTLS_PK_SINGLE_TYPE)
    if( MBEDTLS_PK_CTX_IS_VALID( ctx ) )
        pk_info_ctx_free_func( MBEDTLS_PK_CTX_INFO( ctx ), ctx->pk_ctx );
#endif

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_pk_context ) );
}

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
/*
 * Initialize a restart context
 */
void mbedtls_pk_restart_init( mbedtls_pk_restart_ctx *ctx )
{
    PK_VALIDATE( ctx != NULL );
    ctx->pk_info = NULL;
    ctx->rs_ctx = NULL;
}

/*
 * Free the components of a restart context
 */
void mbedtls_pk_restart_free( mbedtls_pk_restart_ctx *ctx )
{
    if( ctx == NULL || !MBEDTLS_PK_CTX_IS_VALID( ctx ) ||
        ctx->pk_info->rs_free_func == NULL )
    {
        return;
    }

    ctx->pk_info->rs_free_func( ctx->rs_ctx );

    ctx->pk_info = MBEDTLS_PK_INVALID_HANDLE;
    ctx->rs_ctx = NULL;
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

/*
 * Get pk_info structure from type
 */
mbedtls_pk_handle_t mbedtls_pk_info_from_type( mbedtls_pk_type_t pk_type )
{
#if defined(MBEDTLS_PK_SINGLE_TYPE)
    if( pk_type == MBEDTLS_PK_INFO_TYPE( MBEDTLS_PK_SINGLE_TYPE ) )
        return( MBEDTLS_PK_UNIQUE_VALID_HANDLE );

    return( MBEDTLS_PK_INVALID_HANDLE );

#else /* MBEDTLS_PK_SINGLE_TYPE */

    switch( pk_type ) {
#if defined(MBEDTLS_RSA_C)
        case MBEDTLS_PK_RSA:
            return( &mbedtls_rsa_info );
#endif
#if defined(MBEDTLS_ECP_C)
        case MBEDTLS_PK_ECKEY_DH:
            return( &mbedtls_eckeydh_info );
#endif
#if defined(MBEDTLS_ECDSA_C)
        case MBEDTLS_PK_ECDSA:
            return( &mbedtls_ecdsa_info );
#endif
#if defined(MBEDTLS_USE_TINYCRYPT)
        case MBEDTLS_PK_ECKEY:
            return( &mbedtls_uecc_eckey_info );
#else /* MBEDTLS_USE_TINYCRYPT */
#if defined(MBEDTLS_ECP_C)
        case MBEDTLS_PK_ECKEY:
            return( &mbedtls_eckey_info );
#endif
#endif /* MBEDTLS_USE_TINYCRYPT */
        /* MBEDTLS_PK_RSA_ALT omitted on purpose */
        default:
            return( NULL );
    }
#endif /* MBEDTLS_PK_SINGLE_TYPE */
}

/*
 * Initialise context
 */
int mbedtls_pk_setup( mbedtls_pk_context *ctx, mbedtls_pk_handle_t info )
{
    PK_VALIDATE_RET( ctx != NULL );
    if( info == MBEDTLS_PK_INVALID_HANDLE )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

#if !defined(MBEDTLS_PK_SINGLE_TYPE)
    if( ctx->pk_info != NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    ctx->pk_info = info;

    if( ( ctx->pk_ctx = pk_info_ctx_alloc_func( info ) ) == NULL )
        return( MBEDTLS_ERR_PK_ALLOC_FAILED );
#else
    (void) ctx;
#endif

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
    mbedtls_pk_handle_t info = &mbedtls_rsa_alt_info;

    PK_VALIDATE_RET( ctx != NULL );
    if( MBEDTLS_PK_CTX_IS_VALID( ctx ) )
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
    /* A context with null pk_info is not set up yet and can't do anything.
     * For backward compatibility, also accept NULL instead of a context
     * pointer. */
    if( ctx == NULL || !MBEDTLS_PK_CTX_IS_VALID( ctx ) )
        return( 0 );

    return( pk_info_can_do( MBEDTLS_PK_CTX_INFO( ctx ), type ) );
}

/*
 * Helper for mbedtls_pk_sign and mbedtls_pk_verify
 */
static inline int pk_hashlen_helper( mbedtls_md_type_t md_alg, size_t *hash_len )
{
    mbedtls_md_handle_t md_info;

    if( *hash_len != 0 )
        return( 0 );

    if( ( md_info = mbedtls_md_info_from_type( md_alg ) ) ==
        MBEDTLS_MD_INVALID_HANDLE )
    {
        return( -1 );
    }

    *hash_len = mbedtls_md_get_size( md_info );
    return( 0 );
}

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
/*
 * Helper to set up a restart context if needed
 */
static int pk_restart_setup( mbedtls_pk_restart_ctx *ctx,
                             mbedtls_pk_handle_t info )
{
    /* Don't do anything if already set up or invalid */
    if( ctx == NULL || MBEDTLS_PK_CTX_IS_VALID( ctx ) )
        return( 0 );

    /* Should never happen when we're called */
    if( info->rs_alloc_func == NULL || info->rs_free_func == NULL )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->rs_ctx = info->rs_alloc_func() ) == NULL )
        return( MBEDTLS_ERR_PK_ALLOC_FAILED );

    ctx->pk_info = info;

    return( 0 );
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

/*
 * Verify a signature (restartable)
 */
int mbedtls_pk_verify_restartable( mbedtls_pk_context *ctx,
               mbedtls_md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len,
               mbedtls_pk_restart_ctx *rs_ctx )
{
    PK_VALIDATE_RET( ctx != NULL );
    PK_VALIDATE_RET( ( md_alg == MBEDTLS_MD_NONE && hash_len == 0 ) ||
                     hash != NULL );
    PK_VALIDATE_RET( sig != NULL );

    if( !MBEDTLS_PK_CTX_IS_VALID( ctx ) ||
        pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /* optimization: use non-restartable version if restart disabled */
    if( rs_ctx != NULL &&
        mbedtls_ecp_restart_is_enabled() &&
        ctx->pk_info->verify_rs_func != NULL )
    {
        int ret;

        if( ( ret = pk_restart_setup( rs_ctx, ctx->pk_info ) ) != 0 )
            return( ret );

        ret = ctx->pk_info->verify_rs_func( ctx->pk_ctx,
                   md_alg, hash, hash_len, sig, sig_len, rs_ctx->rs_ctx );

        if( ret != MBEDTLS_ERR_ECP_IN_PROGRESS )
            mbedtls_pk_restart_free( rs_ctx );

        return( ret );
    }
#else /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    (void) rs_ctx;
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    return( pk_info_verify_func( MBEDTLS_PK_CTX_INFO( ctx ),
                ctx->pk_ctx, md_alg, hash, hash_len, sig, sig_len ) );
}

/*
 * Verify a signature
 */
int mbedtls_pk_verify( mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len )
{
    return( mbedtls_pk_verify_restartable( ctx, md_alg, hash, hash_len,
                                           sig, sig_len, NULL ) );
}

/*
 * Verify a signature with options
 */
int mbedtls_pk_verify_ext( mbedtls_pk_type_t type, const void *options,
                   mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len )
{
    PK_VALIDATE_RET( ctx != NULL );
    PK_VALIDATE_RET( ( md_alg == MBEDTLS_MD_NONE && hash_len == 0 ) ||
                     hash != NULL );
    PK_VALIDATE_RET( sig != NULL );

    if( !MBEDTLS_PK_CTX_IS_VALID( ctx ) )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( ! mbedtls_pk_can_do( ctx, type ) )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );

    if( type == MBEDTLS_PK_RSASSA_PSS )
    {
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PKCS1_V21)
        int ret;
        const mbedtls_pk_rsassa_pss_options *pss_opts;

#if SIZE_MAX > UINT_MAX
        if( md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len )
            return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
#endif /* SIZE_MAX > UINT_MAX */

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
 * Make a signature (restartable)
 */
int mbedtls_pk_sign_restartable( mbedtls_pk_context *ctx,
             mbedtls_md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
             mbedtls_pk_restart_ctx *rs_ctx )
{
    PK_VALIDATE_RET( ctx != NULL );
    PK_VALIDATE_RET( ( md_alg == MBEDTLS_MD_NONE && hash_len == 0 ) ||
                     hash != NULL );
    PK_VALIDATE_RET( sig != NULL );

    if( !MBEDTLS_PK_CTX_IS_VALID( ctx ) ||
        pk_hashlen_helper( md_alg, &hash_len ) != 0 )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /* optimization: use non-restartable version if restart disabled */
    if( rs_ctx != NULL &&
        mbedtls_ecp_restart_is_enabled() &&
        ctx->pk_info->sign_rs_func != NULL )
    {
        int ret;

        if( ( ret = pk_restart_setup( rs_ctx, ctx->pk_info ) ) != 0 )
            return( ret );

        ret = ctx->pk_info->sign_rs_func( ctx->pk_ctx, md_alg,
                hash, hash_len, sig, sig_len, f_rng, p_rng, rs_ctx->rs_ctx );

        if( ret != MBEDTLS_ERR_ECP_IN_PROGRESS )
            mbedtls_pk_restart_free( rs_ctx );

        return( ret );
    }
#else /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    (void) rs_ctx;
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

    return( pk_info_sign_func( MBEDTLS_PK_CTX_INFO( ctx ), ctx->pk_ctx,
                md_alg, hash, hash_len, sig, sig_len, f_rng, p_rng ) );
}

/*
 * Make a signature
 */
int mbedtls_pk_sign( mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return( mbedtls_pk_sign_restartable( ctx, md_alg, hash, hash_len,
                                         sig, sig_len, f_rng, p_rng, NULL ) );
}

/*
 * Decrypt message
 */
int mbedtls_pk_decrypt( mbedtls_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    PK_VALIDATE_RET( ctx != NULL );
    PK_VALIDATE_RET( input != NULL || ilen == 0 );
    PK_VALIDATE_RET( output != NULL || osize == 0 );
    PK_VALIDATE_RET( olen != NULL );

    if( !MBEDTLS_PK_CTX_IS_VALID( ctx ) )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    return( pk_info_decrypt_func( MBEDTLS_PK_CTX_INFO( ctx ), ctx->pk_ctx,
                input, ilen, output, olen, osize, f_rng, p_rng ) );
}

/*
 * Encrypt message
 */
int mbedtls_pk_encrypt( mbedtls_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    PK_VALIDATE_RET( ctx != NULL );
    PK_VALIDATE_RET( input != NULL || ilen == 0 );
    PK_VALIDATE_RET( output != NULL || osize == 0 );
    PK_VALIDATE_RET( olen != NULL );

    if( !MBEDTLS_PK_CTX_IS_VALID( ctx ) )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    return( pk_info_encrypt_func( MBEDTLS_PK_CTX_INFO( ctx ), ctx->pk_ctx,
                input, ilen, output, olen, osize, f_rng, p_rng ) );
}

/*
 * Check public-private key pair
 */
int mbedtls_pk_check_pair( const mbedtls_pk_context *pub, const mbedtls_pk_context *prv )
{
    PK_VALIDATE_RET( pub != NULL );
    PK_VALIDATE_RET( prv != NULL );

    if( !MBEDTLS_PK_CTX_IS_VALID( pub ) || !MBEDTLS_PK_CTX_IS_VALID( prv ) )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
    if( pk_info_type( prv->pk_info ) == MBEDTLS_PK_RSA_ALT )
    {
        if( pk_info_type( pub->pk_info ) != MBEDTLS_PK_RSA )
            return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
    }
    else
#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */
    {
        if( MBEDTLS_PK_CTX_INFO( pub ) != MBEDTLS_PK_CTX_INFO( prv ) )
            return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
    }

    return( pk_info_check_pair_func( MBEDTLS_PK_CTX_INFO( prv ),
                pub->pk_ctx, prv->pk_ctx ) );
}

/*
 * Get key size in bits
 */
size_t mbedtls_pk_get_bitlen( const mbedtls_pk_context *ctx )
{
    /* For backward compatibility, accept NULL or a context that
     * isn't set up yet, and return a fake value that should be safe. */
    if( ctx == NULL || !MBEDTLS_PK_CTX_IS_VALID( ctx ) )
        return( 0 );

    return( pk_info_get_bitlen( MBEDTLS_PK_CTX_INFO( ctx ), ctx->pk_ctx ) );
}

/*
 * Export debug information
 */
int mbedtls_pk_debug( const mbedtls_pk_context *ctx, mbedtls_pk_debug_item *items )
{
    PK_VALIDATE_RET( ctx != NULL );
    if( !MBEDTLS_PK_CTX_IS_VALID( ctx ) )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    return( pk_info_debug_func( MBEDTLS_PK_CTX_INFO( ctx ), ctx->pk_ctx, items ) );
}

/*
 * Access the PK type name
 */
const char *mbedtls_pk_get_name( const mbedtls_pk_context *ctx )
{
    if( ctx == NULL || !MBEDTLS_PK_CTX_IS_VALID( ctx ) )
        return( "invalid PK" );

    return( pk_info_name( MBEDTLS_PK_CTX_INFO( ctx ) ) );
}

/*
 * Access the PK type
 */
mbedtls_pk_type_t mbedtls_pk_get_type( const mbedtls_pk_context *ctx )
{
    if( ctx == NULL || !MBEDTLS_PK_CTX_IS_VALID( ctx ) )
        return( MBEDTLS_PK_NONE );

    return( pk_info_type( MBEDTLS_PK_CTX_INFO( ctx ) ) );
}

#endif /* MBEDTLS_PK_C */
