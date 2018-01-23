/*
 *  Generic wrapper for Cryptoki (PKCS#11) support
 *
 *  Copyright (C) 2017, ARM Limited, All Rights Reserved
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

#if defined(MBEDTLS_PKCS11_CLIENT_C)

#include <stdint.h>
#include <string.h>
#include <pkcs11.h>

#include "mbedtls/pkcs11_client.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif



#if defined(MBEDTLS_PK_C)
#include "mbedtls/pk.h"
#include "mbedtls/pk_info.h"

#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/oid.h"
#endif

#define ARRAY_LENGTH( a ) ( sizeof( a ) / sizeof( *( a ) ) )

typedef struct {
    mbedtls_pk_type_t key_type; /**< key type */
    CK_SESSION_HANDLE hSession; /**< session handle */
    CK_OBJECT_HANDLE hPublicKey; /**< public key handle (must not be null) */
    CK_OBJECT_HANDLE hPrivateKey; /**< private key handle (may be null) */
    uint16_t bit_length; /**< key length in bits */
} mbedtls_pk_pkcs11_context_t;

static int pkcs11_err_to_mbedtls_pk_err( CK_RV rv )
{
    switch( rv )
    {
    case CKR_OK:
        return( 0 );
    case CKR_HOST_MEMORY:
        return( MBEDTLS_ERR_PK_ALLOC_FAILED );
    case CKR_ARGUMENTS_BAD:
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
    case CKR_KEY_FUNCTION_NOT_PERMITTED:
        return( MBEDTLS_ERR_PK_NOT_PERMITTED );
    case CKR_MECHANISM_INVALID:
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );
    case CKR_MECHANISM_PARAM_INVALID:
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
    case CKR_OBJECT_HANDLE_INVALID:
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
    case CKR_SIGNATURE_INVALID:
        return( MBEDTLS_ERR_PK_INVALID_SIGNATURE );
    case CKR_SIGNATURE_LEN_RANGE:
        return( MBEDTLS_ERR_PK_SIG_LEN_MISMATCH );
    case CKR_TEMPLATE_INCOMPLETE:
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
    case CKR_BUFFER_TOO_SMALL:
        return( MBEDTLS_ERR_PK_BUFFER_TOO_SMALL );
    default:
        return( MBEDTLS_ERR_PK_FILE_IO_ERROR );
    }
}

static size_t pkcs11_pk_get_bitlen( const void *ctx_arg )
{
    const mbedtls_pk_pkcs11_context_t *ctx = ctx_arg;
    return( ctx->bit_length );
}

static int pkcs11_pk_can_do( const void *ctx_arg, mbedtls_pk_type_t type )
{
    const mbedtls_pk_pkcs11_context_t *ctx = ctx_arg;
    return ctx->key_type == mbedtls_pk_representation_type( type );
}

static void *pkcs11_pk_alloc( )
{
    return( mbedtls_calloc( 1, sizeof( mbedtls_pk_pkcs11_context_t ) ) );
}

static void pkcs11_pk_free( void *ctx )
{
    mbedtls_free( ctx );
}

static size_t pkcs11_pk_signature_size( const void *ctx_arg )
{
    const mbedtls_pk_pkcs11_context_t *ctx = ctx_arg;
    switch( ctx->key_type )
    {
    case MBEDTLS_PK_RSA:
        return( ( ctx->bit_length + 7 ) / 8 );
    case MBEDTLS_PK_ECKEY:
        return( MBEDTLS_ECDSA_MAX_SIG_LEN( ctx->bit_length ) );
    default:
        return( 0 );
    }
}

static int pkcs11_sign( void *ctx_arg,
                        mbedtls_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        unsigned char *sig, size_t *sig_len,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng )
{
    mbedtls_pk_pkcs11_context_t *ctx = ctx_arg;
    CK_RV rv;
    CK_MECHANISM mechanism = {0, NULL_PTR, 0};
    CK_ULONG ck_sig_len;

    /* This function takes size_t arguments but the underlying layer
       takes unsigned long. Either type may be smaller than the other.
       Legitimate values won't overflow either type but we still need
       to check for overflow for robustness. */
    if( hash_len > (CK_ULONG)( -1 ) )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
    (void) f_rng;
    (void) p_rng;

    switch( ctx->key_type )
    {
#if defined(MBEDTLS_ECDSA_C)
    case MBEDTLS_PK_ECKEY:
        ck_sig_len = MBEDTLS_ECDSA_MAX_SIG_LEN( ctx->bit_length );
        mechanism.mechanism = CKM_ECDSA;
        break;
#endif /* MBEDTLS_ECDSA_C */
    default:
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );
    }

    rv = C_SignInit( ctx->hSession, &mechanism, ctx->hPrivateKey );
    if( rv != CKR_OK )
        goto exit;
    rv = C_Sign( ctx->hSession, (CK_BYTE_PTR) hash, hash_len,
                 sig, &ck_sig_len );
    if( rv != CKR_OK )
        goto exit;

    if( mechanism.mechanism == CKM_ECDSA )
    {
        /* The signature from the token contains r and s concatenated,
         * each in the form of a big-endian byte sequence, with r and s
         * having the same length as the base point.
         *
         * A standard ECDSA signature is encoded in ASN.1:
         *   SEQUENCE {
         *     r INTEGER,
         *     s INTEGER
         *   }
         *
         * Perform the conversion using existing utility functions,
         * with temporary bignums.
         */
        uint16_t byte_len = ( ( ctx->bit_length + 7 ) / 8 );
        size_t sig_size = MBEDTLS_ECDSA_MAX_SIG_LEN( ctx->bit_length );
        mbedtls_mpi r, s;
        mbedtls_mpi_init( &r );
        mbedtls_mpi_init( &s );
        rv = CKR_OK;
        if( ck_sig_len != 2 * byte_len )
        {
            /* Bad data from the token */
            rv = CKR_GENERAL_ERROR;
            goto ecdsa_exit;
        }
        if( mbedtls_mpi_read_binary( &r, sig, byte_len ) != 0 ||
            mbedtls_mpi_read_binary( &s, sig + byte_len, byte_len ) != 0 )
        {
            rv = CKR_HOST_MEMORY;
            goto ecdsa_exit;
        }
        /* The signature buffer is guaranteed to have enough room for
           the encoded signature by the pk_sign interface. */
        if( mbedtls_ecdsa_signature_to_asn1( &r, &s, sig, sig_len, sig_size ) != 0 )
        {
            rv = CKR_GENERAL_ERROR;
            goto ecdsa_exit;
        }
    ecdsa_exit:
        mbedtls_mpi_free( &r );
        mbedtls_mpi_free( &s );
        if( rv != CKR_OK )
            goto exit;
    }
    else
    {
        *sig_len = ck_sig_len;
    }

exit:
    if( rv != CKR_OK )
        memset( sig, 0, ck_sig_len );
    return( pkcs11_err_to_mbedtls_pk_err( rv ) );
}

static int pkcs11_verify( void *ctx_arg,
                        mbedtls_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        const unsigned char *sig, size_t sig_len)
{
    mbedtls_pk_pkcs11_context_t *ctx = ctx_arg;
    CK_RV rv;
    CK_MECHANISM mechanism = {0, NULL_PTR, 0};
    unsigned char *decoded_sig = NULL;
    size_t decoded_sig_len;

    /* This function takes size_t arguments but the underlying layer
       takes unsigned long. Either type may be smaller than the other.
       Legitimate values won't overflow either type but we still need
       to check for overflow for robustness. */
    if( hash_len > (CK_ULONG)( -1 ) )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    switch( ctx->key_type )
    {
#if defined(MBEDTLS_RSA_C)
    case MBEDTLS_PK_RSA:
        switch( md_alg )
        {
        case MBEDTLS_MD_MD5:
            mechanism.mechanism = CKM_MD5_RSA_PKCS;
            break;
        case MBEDTLS_MD_SHA1:
            mechanism.mechanism = CKM_SHA1_RSA_PKCS;
            break;
        case MBEDTLS_MD_SHA256:
            mechanism.mechanism = CKM_SHA256_RSA_PKCS;
            break;
        case MBEDTLS_MD_SHA384:
            mechanism.mechanism = CKM_SHA384_RSA_PKCS;
            break;
        case MBEDTLS_MD_SHA512:
            mechanism.mechanism = CKM_SHA512_RSA_PKCS;
            break;
        default:
            return( MBEDTLS_ERR_PK_INVALID_ALG );
        }
        break;
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECDSA_C)
    case MBEDTLS_PK_ECKEY:
        mechanism.mechanism = CKM_ECDSA;
        break;
#endif /* MBEDTLS_ECDSA_C */
    default:
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );
    }
    if( mechanism.mechanism == CKM_ECDSA )
    {
        uint16_t byte_len = ( ( ctx->bit_length + 7 ) / 8 );
        decoded_sig = mbedtls_calloc( 1, 2 * byte_len );
        if( decoded_sig == NULL )
        {
            return( MBEDTLS_ERR_PK_ALLOC_FAILED );
        }
        if( mbedtls_ecdsa_signature_to_raw( sig, sig_len, byte_len,
                                    decoded_sig, 2 * byte_len,
                                    &decoded_sig_len ) != 0 )
        {
            rv = CKR_GENERAL_ERROR;
            goto exit;
        }
    }
    rv = C_VerifyInit( ctx->hSession, &mechanism, ctx->hPublicKey );
    if( rv != CKR_OK )
        goto exit;
    rv = C_Verify( ctx->hSession, (CK_BYTE_PTR) hash, hash_len,
           decoded_sig, decoded_sig_len );
    if( rv != CKR_OK )
        goto exit;

exit:
    mbedtls_free(decoded_sig);
    return( pkcs11_err_to_mbedtls_pk_err( rv ) );
}

static const mbedtls_pk_info_t mbedtls_pk_pkcs11_info =
    MBEDTLS_PK_OPAQUE_INFO_1( "pkcs11"
                              , pkcs11_pk_get_bitlen
                              , pkcs11_pk_can_do //can_do
                              , pkcs11_pk_signature_size
                              , pkcs11_verify
                              , pkcs11_sign
                              , NULL //pkcs11_decrypt
                              , NULL //pkcs11_encrypt
                              , NULL //check_pair_func
                              , pkcs11_pk_alloc
                              , pkcs11_pk_free
                              , NULL //debug_func
        );

int mbedtls_pk_setup_pkcs11( mbedtls_pk_context *ctx,
                             CK_SESSION_HANDLE hSession,
                             CK_OBJECT_HANDLE hPublicKey,
                             CK_OBJECT_HANDLE hPrivateKey )
{
    CK_OBJECT_CLASS public_key_class = -1, private_key_class = -1;
    CK_KEY_TYPE public_key_type = -1, private_key_type = -1;
    mbedtls_pk_type_t can_do;
    CK_ATTRIBUTE attributes[] = {
        {CKA_CLASS, &public_key_class, sizeof( public_key_class )},
        {CKA_KEY_TYPE, &public_key_type, sizeof( public_key_type )},
    };
    CK_RV rv;
    uint16_t key_size = 0;

    rv = C_GetAttributeValue( hSession, hPublicKey,
                              attributes, ARRAY_LENGTH( attributes ) );
    if( rv != CKR_OK )
        return( pkcs11_err_to_mbedtls_pk_err( rv ) );
    if( public_key_class != CKO_PUBLIC_KEY )
        return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );

    if( hPrivateKey != CK_INVALID_HANDLE )
    {
        attributes[0].pValue = &private_key_class;
        attributes[1].pValue = &private_key_type;
        rv = C_GetAttributeValue( hSession, hPrivateKey,
                                  attributes, ARRAY_LENGTH( attributes ) );
        if( rv != CKR_OK )
            return( pkcs11_err_to_mbedtls_pk_err( rv ) );
        if( private_key_class != CKO_PRIVATE_KEY )
            return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
        if( public_key_type != private_key_type )
            return( MBEDTLS_ERR_PK_BAD_INPUT_DATA );
    }

    switch( public_key_type ) {
#if defined(MBEDTLS_ECDSA_C)
    case CKK_ECDSA:
        can_do = MBEDTLS_PK_ECKEY;
        {
            unsigned char ecParams[16];
            mbedtls_asn1_buf params_asn1;
            mbedtls_ecp_group_id grp_id;
            const mbedtls_ecp_curve_info *curve_info;
            attributes[0].type = CKA_EC_PARAMS;
            attributes[0].pValue = ecParams;
            attributes[0].ulValueLen = sizeof( ecParams );
            rv = C_GetAttributeValue( hSession, hPublicKey, attributes, 1 );
            if( rv != CKR_OK )
                return( pkcs11_err_to_mbedtls_pk_err( rv ) );
            params_asn1.tag = ecParams[0];
            params_asn1.len = ecParams[1];
            params_asn1.p = ecParams + 2;
            if( mbedtls_oid_get_ec_grp( &params_asn1, &grp_id ) != 0 )
                return( MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE );
            curve_info = mbedtls_ecp_curve_info_from_grp_id( grp_id );
            if( curve_info == NULL )
                return( MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE );
            key_size = curve_info->bit_size;
        }
        break;
#endif /* MBEDTLS_ECDSA_C */
    default:
        can_do = MBEDTLS_PK_OPAQUE;
        break;
    }

    {
        int ret = mbedtls_pk_setup( ctx, &mbedtls_pk_pkcs11_info );
        if( ret != 0 )
            return( MBEDTLS_ERR_PK_ALLOC_FAILED );
    }
    {
        mbedtls_pk_pkcs11_context_t *pkcs11_ctx = ctx->pk_ctx;
        pkcs11_ctx->key_type = can_do;
        pkcs11_ctx->bit_length = key_size;
        pkcs11_ctx->hSession = hSession;
        pkcs11_ctx->hPublicKey = hPublicKey;
        pkcs11_ctx->hPrivateKey = hPrivateKey;
    }
    return( 0 );
}

#if defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECDSA_C)
static int mpi_to_ck( const mbedtls_mpi *mpi,
                      CK_ATTRIBUTE *attr, CK_ATTRIBUTE_TYPE at,
                      unsigned char **p, size_t len )
{
    if( mbedtls_mpi_write_binary( mpi, *p, len ) != 0 )
        return( 0 );
    attr->type = at;
    attr->pValue = *p;
    attr->ulValueLen = len;
    *p += len;
    return( 1 );
}
#define MPI_TO_CK( mpi, attr, at, p, len )                            \
    do                                                                \
    {                                                                 \
        if( !mpi_to_ck( ( mpi ), ( attr ), ( at ), ( p ), ( len ) ) ) \
        {                                                             \
            rv = CKR_ARGUMENTS_BAD;                                   \
            goto exit;                                                \
        }                                                             \
    }                                                                 \
    while( 0 )
#endif /* defined(MBEDTLS_RSA_C) || defined(MBEDTLS_ECDSA_C) */

#define CK_BOOL( x ) ( ( x ) ? CK_TRUE : CK_FALSE )

int mbedtls_pk_import_to_pkcs11( const mbedtls_pk_context *ctx,
                                 uint32_t flags,
                                 CK_SESSION_HANDLE hSession,
                                 CK_OBJECT_HANDLE *hPublicKey,
                                 CK_OBJECT_HANDLE *hPrivateKey )
{
    CK_OBJECT_CLASS cko_private_key = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS cko_public_key = CKO_PUBLIC_KEY;
    CK_KEY_TYPE ck_key_type;
    CK_BBOOL ck_sensitive = CK_BOOL( flags & MBEDTLS_PK_FLAG_SENSITIVE );
    CK_BBOOL ck_extractable = CK_BOOL( flags & MBEDTLS_PK_FLAG_EXTRACTABLE );
    CK_BBOOL ck_sign = CK_BOOL( flags & MBEDTLS_PK_FLAG_SIGN );
    CK_BBOOL ck_verify = CK_BOOL( flags & MBEDTLS_PK_FLAG_VERIFY );
    CK_BBOOL ck_decrypt = CK_BOOL( flags & MBEDTLS_PK_FLAG_DECRYPT );
    CK_BBOOL ck_encrypt = CK_BOOL( flags & MBEDTLS_PK_FLAG_ENCRYPT );
    CK_BBOOL ck_token = CK_BOOL( flags & MBEDTLS_PKCS11_FLAG_TOKEN );
    CK_ATTRIBUTE public_attributes[] = {
        {CKA_CLASS, &cko_public_key, sizeof( cko_public_key )},
        {CKA_KEY_TYPE, &ck_key_type, sizeof( ck_key_type )},
        {CKA_TOKEN, &ck_token, sizeof( ck_token )},
        {CKA_ENCRYPT, &ck_encrypt, sizeof( ck_encrypt )},
        {CKA_VERIFY, &ck_verify, sizeof( ck_verify )},
#define COMMON_PUBLIC_ATTRIBUTES 5 // number of attributes above
        {-1, NULL, 0},
        {-1, NULL, 0},
    };
    CK_ATTRIBUTE private_attributes[] = {
        {CKA_CLASS, &cko_private_key, sizeof( cko_private_key )},
        {CKA_KEY_TYPE, &ck_key_type, sizeof( ck_key_type )},
        {CKA_TOKEN, &ck_token, sizeof( ck_token )},
        {CKA_DECRYPT, &ck_decrypt, sizeof( ck_decrypt )},
        {CKA_SIGN, &ck_sign, sizeof( ck_sign )},
        {CKA_SENSITIVE, &ck_sensitive, sizeof( ck_sensitive )},
        {CKA_EXTRACTABLE, &ck_extractable, sizeof( ck_extractable )},
#define COMMON_PRIVATE_ATTRIBUTES 7 // number of attributes above
        {-1, NULL, 0},
        {-1, NULL, 0},
        {-1, NULL, 0},
        {-1, NULL, 0},
        {-1, NULL, 0},
        {-1, NULL, 0},
        {-1, NULL, 0},
        {-1, NULL, 0},
    };
    CK_ATTRIBUTE *public_end = public_attributes + COMMON_PUBLIC_ATTRIBUTES;
    CK_ATTRIBUTE *private_end = private_attributes + COMMON_PRIVATE_ATTRIBUTES;
#undef COMMON_PUBLIC_ATTRIBUTES
#undef COMMON_PRIVATE_ATTRIBUTES
    unsigned char *data = NULL;
    CK_RV rv;

    if( hPublicKey != NULL )
        *hPublicKey = CK_INVALID_HANDLE;
    if( hPrivateKey != NULL )
        *hPrivateKey = CK_INVALID_HANDLE;

    /* Prepare the data-dependent key attributes */
    switch( mbedtls_pk_representation_type( mbedtls_pk_get_type( ctx ) ) )
    {
#if defined(MBEDTLS_ECDSA_C)
        case MBEDTLS_PK_ECKEY:
        {
            const mbedtls_ecp_keypair *ec = mbedtls_pk_ec( *ctx );
            unsigned char *p;
            size_t curve_bytes = ( ec->grp.pbits + 7 ) / 8;
            size_t point_bytes = 4 + 2 * curve_bytes; // overapproximation
            int format = MBEDTLS_ECP_PF_UNCOMPRESSED;
            int ret;
            data = mbedtls_calloc( 1,
                                   MBEDTLS_OID_EC_GRP_MAX_SIZE +
                                   ( hPublicKey == NULL ? 0 : point_bytes ) +
                                   ( hPrivateKey == NULL ? 0 : curve_bytes ) );
            if( data == NULL )
            {
                rv = CKR_HOST_MEMORY;
                goto exit;
            }
            p = data;
            ck_key_type = CKK_ECDSA;
            /* Convert the group identifier */
            ret = mbedtls_ecp_ansi_write_group( &ec->grp, p,
                                                MBEDTLS_OID_EC_GRP_MAX_SIZE );
            if( ret < 0 )
            {
                rv = CKR_GENERAL_ERROR;
                goto exit;
            }
            public_end->type = CKA_EC_PARAMS;
            public_end->pValue = p;
            public_end->ulValueLen = ret;
            p += ret;
            *private_end++ = *public_end++;
            if( hPublicKey != NULL )
            {
                /* Convert the public point */
                ret = mbedtls_ecp_ansi_write_point( ec, format, p, point_bytes );
                if( ret < 0 )
                {
                    rv = CKR_GENERAL_ERROR;
                    goto exit;
                }
                public_end->type = CKA_EC_POINT;
                public_end->pValue = p;
                public_end->ulValueLen = ret;
                p += ret;
                public_end++;
            }
            if( hPrivateKey != NULL )
            {
                /* Convert the private value */
                MPI_TO_CK( &ec->d, private_end++, CKA_VALUE, &p, curve_bytes );
            }
        }
        break;
#endif /* MBEDTLS_ECDSA_C */
    default:
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );
    }

    if( hPublicKey != NULL )
    {
        *hPublicKey = CK_INVALID_HANDLE;
        rv = C_CreateObject( hSession,
                             public_attributes,
                             public_end - public_attributes,
                             hPublicKey );
        if( rv != CKR_OK )
            goto exit;
    }

    if( hPrivateKey != NULL )
    {
        rv = C_CreateObject( hSession,
                             private_attributes,
                             private_end - private_attributes,
                             hPrivateKey );
        if( rv != CKR_OK )
            goto exit;
    }

exit:
    if( rv != CKR_OK )
    {
        /* In case an error happened, destroy any object that we
           created. In case C_DestroyObject failed, we report the original
           error, but *hPublicKey may contain a valid handle if
           creating the private key failed and then destroying the public key
           also failed (e.g. because the token disconnected). */
        if( hPublicKey != NULL && *hPublicKey != CK_INVALID_HANDLE )
        {
            if( C_DestroyObject( hSession, *hPublicKey ) == CKR_OK )
                *hPublicKey = CK_INVALID_HANDLE;
        }
        if( hPrivateKey != NULL && *hPrivateKey != CK_INVALID_HANDLE )
        {
            if( C_DestroyObject( hSession, *hPrivateKey ) == CKR_OK )
                *hPrivateKey = CK_INVALID_HANDLE;
        }
    }
    mbedtls_free( data );
    return( pkcs11_err_to_mbedtls_pk_err( rv ) );
}

#endif /* MBEDTLS_PK_C */



#endif /* MBEDTLS_PKCS11_CLIENT_C */
