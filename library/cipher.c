/**
 * \file cipher.c
 * 
 * \brief Generic cipher wrapper for PolarSSL
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "polarssl/config.h"

#if defined(POLARSSL_CIPHER_C)

#include "polarssl/cipher.h"
#include "polarssl/cipher_wrap.h"

#include <stdlib.h>

#if defined _MSC_VER && !defined strcasecmp
#define strcasecmp _stricmp
#endif

static const int supported_ciphers[] = {

#if defined(POLARSSL_AES_C)
        POLARSSL_CIPHER_AES_128_CBC,
        POLARSSL_CIPHER_AES_192_CBC,
        POLARSSL_CIPHER_AES_256_CBC,
#endif /* defined(POLARSSL_AES_C) */

#if defined(POLARSSL_CAMELLIA_C)
        POLARSSL_CIPHER_CAMELLIA_128_CBC,
        POLARSSL_CIPHER_CAMELLIA_192_CBC,
        POLARSSL_CIPHER_CAMELLIA_256_CBC,
#endif /* defined(POLARSSL_CAMELLIA_C) */

#if defined(POLARSSL_DES_C)
        POLARSSL_CIPHER_DES_CBC,
        POLARSSL_CIPHER_DES_EDE_CBC,
        POLARSSL_CIPHER_DES_EDE3_CBC,
#endif /* defined(POLARSSL_DES_C) */

        0
};

const int *cipher_list( void )
{
    return supported_ciphers;
}

const cipher_info_t *cipher_info_from_type( cipher_type_t cipher_type )
{
    /* Find static cipher information */
    switch ( cipher_type )
    {
#if defined(POLARSSL_AES_C)
        case POLARSSL_CIPHER_AES_128_CBC:
            return &aes_128_cbc_info;
        case POLARSSL_CIPHER_AES_192_CBC:
            return &aes_192_cbc_info;
        case POLARSSL_CIPHER_AES_256_CBC:
            return &aes_256_cbc_info;
#endif

#if defined(POLARSSL_CAMELLIA_C)
        case POLARSSL_CIPHER_CAMELLIA_128_CBC:
            return &camellia_128_cbc_info;
        case POLARSSL_CIPHER_CAMELLIA_192_CBC:
            return &camellia_192_cbc_info;
        case POLARSSL_CIPHER_CAMELLIA_256_CBC:
            return &camellia_256_cbc_info;
#endif

#if defined(POLARSSL_DES_C)
        case POLARSSL_CIPHER_DES_CBC:
            return &des_cbc_info;
        case POLARSSL_CIPHER_DES_EDE_CBC:
            return &des_ede_cbc_info;
        case POLARSSL_CIPHER_DES_EDE3_CBC:
            return &des_ede3_cbc_info;
#endif

        default:
            return NULL;
    }
}

const cipher_info_t *cipher_info_from_string( const char *cipher_name )
{
    if( NULL == cipher_name )
        return NULL;

    /* Get the appropriate digest information */
#if defined(POLARSSL_CAMELLIA_C)
    if( !strcasecmp( "CAMELLIA-128-CBC", cipher_name ) )
        return cipher_info_from_type( POLARSSL_CIPHER_CAMELLIA_128_CBC );
    if( !strcasecmp( "CAMELLIA-192-CBC", cipher_name ) )
        return cipher_info_from_type( POLARSSL_CIPHER_CAMELLIA_192_CBC );
    if( !strcasecmp( "CAMELLIA-256-CBC", cipher_name ) )
        return cipher_info_from_type( POLARSSL_CIPHER_CAMELLIA_256_CBC );
#endif
#if defined(POLARSSL_AES_C)
    if( !strcasecmp( "AES-128-CBC", cipher_name ) )
        return cipher_info_from_type( POLARSSL_CIPHER_AES_128_CBC );
    if( !strcasecmp( "AES-192-CBC", cipher_name ) )
        return cipher_info_from_type( POLARSSL_CIPHER_AES_192_CBC );
    if( !strcasecmp( "AES-256-CBC", cipher_name ) )
        return cipher_info_from_type( POLARSSL_CIPHER_AES_256_CBC );
#endif
#if defined(POLARSSL_DES_C)
    if( !strcasecmp( "DES-CBC", cipher_name ) )
        return cipher_info_from_type( POLARSSL_CIPHER_DES_CBC );
    if( !strcasecmp( "DES-EDE-CBC", cipher_name ) )
        return cipher_info_from_type( POLARSSL_CIPHER_DES_EDE_CBC );
    if( !strcasecmp( "DES-EDE3-CBC", cipher_name ) )
        return cipher_info_from_type( POLARSSL_CIPHER_DES_EDE3_CBC );
#endif
    return NULL;
}

int cipher_init_ctx( cipher_context_t *ctx, const cipher_info_t *cipher_info )
{
    if( NULL == cipher_info || NULL == ctx )
        return 1;

    memset( ctx, 0, sizeof( ctx ) );

    if( NULL == ( ctx->cipher_ctx = cipher_info->ctx_alloc_func() ) )
        return 2;

    ctx->cipher_info = cipher_info;

    return 0;
}

int cipher_free_ctx( cipher_context_t *ctx )
{
    if( ctx == NULL || ctx->cipher_info == NULL )
        return 1;

    ctx->cipher_info->ctx_free_func( ctx->cipher_ctx );

    return 0;
}

int cipher_setkey( cipher_context_t *ctx, const unsigned char *key,
        int key_length, const operation_t operation )
{
    if( NULL == ctx || NULL == ctx->cipher_info )
        return 1;

    ctx->key_length = key_length;
    ctx->operation = operation;

    if (POLARSSL_ENCRYPT == operation)
        return ctx->cipher_info->setkey_enc_func( ctx->cipher_ctx, key,
                ctx->key_length );

    if (POLARSSL_DECRYPT == operation)
        return ctx->cipher_info->setkey_dec_func( ctx->cipher_ctx, key,
                ctx->key_length );

    return 1;
}

int cipher_reset( cipher_context_t *ctx, const unsigned char *iv )
{
    if( NULL == ctx || NULL == ctx->cipher_info || NULL == iv )
        return 1;

    ctx->unprocessed_len = 0;

    memcpy( ctx->iv, iv, cipher_get_iv_size( ctx ) );

    return 0;
}

int cipher_update( cipher_context_t *ctx, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t *olen )
{
    size_t copy_len = 0;

    if( NULL == ctx || NULL == ctx->cipher_info || NULL == olen ||
        input == output )
    {
        return 1;
    }

    *olen = 0;

    if( ctx->cipher_info->mode == POLARSSL_MODE_CBC )
    {
        /*
         * If there is not enough data for a full block, cache it.
         */
        if( ( ctx->operation == POLARSSL_DECRYPT &&
                ilen + ctx->unprocessed_len <= cipher_get_block_size( ctx ) ) ||
             ( ctx->operation == POLARSSL_ENCRYPT &&
                ilen + ctx->unprocessed_len < cipher_get_block_size( ctx ) ) )
        {
            memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ), input,
                    ilen );

            ctx->unprocessed_len += ilen;
            return 0;
        }

        /*
         * Process cached data first
         */
        if( ctx->unprocessed_len != 0 )
        {
            copy_len = cipher_get_block_size( ctx ) - ctx->unprocessed_len;

            memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ), input,
                    copy_len );

            if( 0 != ctx->cipher_info->cbc_func( ctx->cipher_ctx,
                    ctx->operation, cipher_get_block_size( ctx ), ctx->iv,
                    ctx->unprocessed_data, output) )
            {
                return 1;
            }

            *olen += cipher_get_block_size( ctx );
            output += cipher_get_block_size( ctx );
            ctx->unprocessed_len = 0;

            input += copy_len;
            ilen -= copy_len;
        }

        /*
         * Cache final, incomplete block
         */
        if( 0 != ilen )
        {
            copy_len = ilen % cipher_get_block_size( ctx );
            if( copy_len == 0 && ctx->operation == POLARSSL_DECRYPT )
                copy_len = cipher_get_block_size(ctx);

            memcpy( ctx->unprocessed_data, &( input[ilen - copy_len] ),
                    copy_len );

            ctx->unprocessed_len += copy_len;
            ilen -= copy_len;
        }

        /*
         * Process remaining full blocks
         */
        if( ilen )
        {
            if( 0 != ctx->cipher_info->cbc_func( ctx->cipher_ctx,
                    ctx->operation, ilen, ctx->iv, input, output ) )
            {
                return 1;
            }
            *olen += ilen;
        }

        return 0;
    }

    return 1;
}

static void add_pkcs_padding( unsigned char *output, size_t output_len,
        size_t data_len )
{
    size_t padding_len = output_len - data_len;
    unsigned char i = 0;

    for( i = 0; i < padding_len; i++ )
        output[data_len + i] = (unsigned char) padding_len;
}

static int get_pkcs_padding( unsigned char *input, unsigned char input_len,
        size_t *data_len)
{
    int i = 0;
    unsigned char padding_len = 0;

    if( NULL == input || NULL == data_len )
        return 1;

    padding_len = input[input_len - 1];

    if( padding_len > input_len )
        return 2;

    for( i = input_len - padding_len; i < input_len; i++ )
        if( input[i] != padding_len )
            return 2;

    *data_len = input_len - padding_len;

    return 0;
}

int cipher_finish( cipher_context_t *ctx, unsigned char *output, size_t *olen)
{
    if( NULL == ctx || NULL == ctx->cipher_info || NULL == olen )
        return 1;

    *olen = 0;

    if( POLARSSL_MODE_CBC == ctx->cipher_info->mode )
    {
        if( POLARSSL_ENCRYPT == ctx->operation )
        {
            add_pkcs_padding( ctx->unprocessed_data, cipher_get_iv_size( ctx ),
                    ctx->unprocessed_len );
        }
        else if ( cipher_get_block_size( ctx ) != ctx->unprocessed_len )
        {
            /* For decrypt operations, expect a full block */
            return 1;
        }

        /* cipher block */
        if( 0 != ctx->cipher_info->cbc_func( ctx->cipher_ctx, ctx->operation,
                cipher_get_block_size( ctx ), ctx->iv, ctx->unprocessed_data,
                output ) )
        {
            return 1;
        }

        /* Set output size for decryption */
        if( POLARSSL_DECRYPT == ctx->operation )
            return get_pkcs_padding( output, cipher_get_block_size( ctx ), olen );

        /* Set output size for encryption */
        *olen = cipher_get_block_size( ctx );
        return 0;
    }

    return 1;
}

#if defined(POLARSSL_SELF_TEST)

#include <stdio.h>

#define ASSERT(x) if (!(x)) { \
        printf( "failed with %i at %s\n", value, (#x) ); \
    return( 1 ); \
}
/*
 * Checkup routine
 */

int cipher_self_test( int verbose )
{
    ((void) verbose);

    return( 0 );
}

#endif

#endif
