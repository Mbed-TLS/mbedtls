/**
 * \file md.c
 *
 * \brief Generic message digest wrapper for mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright (C) 2006-2014, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
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

#if !defined(POLARSSL_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_MD_C)

#include "mbedtls/md.h"
#include "mbedtls/md_wrap.h"

#if defined(POLARSSL_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

#include <string.h>

#if defined(_MSC_VER) && !defined strcasecmp && !defined(EFIX64) && \
    !defined(EFI32)
#define strcasecmp  _stricmp
#endif

/* Implementation that should never be optimized out by the compiler */
static void polarssl_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

static const int supported_digests[] = {

#if defined(POLARSSL_SHA512_C)
        POLARSSL_MD_SHA512,
        POLARSSL_MD_SHA384,
#endif

#if defined(POLARSSL_SHA256_C)
        POLARSSL_MD_SHA256,
        POLARSSL_MD_SHA224,
#endif

#if defined(POLARSSL_SHA1_C)
        POLARSSL_MD_SHA1,
#endif

#if defined(POLARSSL_RIPEMD160_C)
        POLARSSL_MD_RIPEMD160,
#endif

#if defined(POLARSSL_MD5_C)
        POLARSSL_MD_MD5,
#endif

#if defined(POLARSSL_MD4_C)
        POLARSSL_MD_MD4,
#endif

#if defined(POLARSSL_MD2_C)
        POLARSSL_MD_MD2,
#endif

        POLARSSL_MD_NONE
};

const int *md_list( void )
{
    return( supported_digests );
}

const md_info_t *md_info_from_string( const char *md_name )
{
    if( NULL == md_name )
        return( NULL );

    /* Get the appropriate digest information */
#if defined(POLARSSL_MD2_C)
    if( !strcasecmp( "MD2", md_name ) )
        return md_info_from_type( POLARSSL_MD_MD2 );
#endif
#if defined(POLARSSL_MD4_C)
    if( !strcasecmp( "MD4", md_name ) )
        return md_info_from_type( POLARSSL_MD_MD4 );
#endif
#if defined(POLARSSL_MD5_C)
    if( !strcasecmp( "MD5", md_name ) )
        return md_info_from_type( POLARSSL_MD_MD5 );
#endif
#if defined(POLARSSL_RIPEMD160_C)
    if( !strcasecmp( "RIPEMD160", md_name ) )
        return md_info_from_type( POLARSSL_MD_RIPEMD160 );
#endif
#if defined(POLARSSL_SHA1_C)
    if( !strcasecmp( "SHA1", md_name ) || !strcasecmp( "SHA", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA1 );
#endif
#if defined(POLARSSL_SHA256_C)
    if( !strcasecmp( "SHA224", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA224 );
    if( !strcasecmp( "SHA256", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA256 );
#endif
#if defined(POLARSSL_SHA512_C)
    if( !strcasecmp( "SHA384", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA384 );
    if( !strcasecmp( "SHA512", md_name ) )
        return md_info_from_type( POLARSSL_MD_SHA512 );
#endif
    return( NULL );
}

const md_info_t *md_info_from_type( md_type_t md_type )
{
    switch( md_type )
    {
#if defined(POLARSSL_MD2_C)
        case POLARSSL_MD_MD2:
            return( &md2_info );
#endif
#if defined(POLARSSL_MD4_C)
        case POLARSSL_MD_MD4:
            return( &md4_info );
#endif
#if defined(POLARSSL_MD5_C)
        case POLARSSL_MD_MD5:
            return( &md5_info );
#endif
#if defined(POLARSSL_RIPEMD160_C)
        case POLARSSL_MD_RIPEMD160:
            return( &ripemd160_info );
#endif
#if defined(POLARSSL_SHA1_C)
        case POLARSSL_MD_SHA1:
            return( &sha1_info );
#endif
#if defined(POLARSSL_SHA256_C)
        case POLARSSL_MD_SHA224:
            return( &sha224_info );
        case POLARSSL_MD_SHA256:
            return( &sha256_info );
#endif
#if defined(POLARSSL_SHA512_C)
        case POLARSSL_MD_SHA384:
            return( &sha384_info );
        case POLARSSL_MD_SHA512:
            return( &sha512_info );
#endif
        default:
            return( NULL );
    }
}

void md_init( md_context_t *ctx )
{
    memset( ctx, 0, sizeof( md_context_t ) );
}

void md_free( md_context_t *ctx )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return;

    if( ctx->md_ctx != NULL )
        ctx->md_info->ctx_free_func( ctx->md_ctx );

    if( ctx->hmac_ctx != NULL )
    {
        polarssl_zeroize( ctx->hmac_ctx, 2 * ctx->md_info->block_size );
        polarssl_free( ctx->hmac_ctx );
    }

    polarssl_zeroize( ctx, sizeof( md_context_t ) );
}

int md_init_ctx( md_context_t *ctx, const md_info_t *md_info )
{
    if( md_info == NULL || ctx == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    memset( ctx, 0, sizeof( md_context_t ) );

    if( ( ctx->md_ctx = md_info->ctx_alloc_func() ) == NULL )
        return( POLARSSL_ERR_MD_ALLOC_FAILED );

    ctx->hmac_ctx = polarssl_malloc( 2 * md_info->block_size );
    if( ctx->hmac_ctx == NULL )
    {
        md_info->ctx_free_func( ctx->md_ctx );
        return( POLARSSL_ERR_MD_ALLOC_FAILED );
    }

    ctx->md_info = md_info;

    md_info->starts_func( ctx->md_ctx );

    return( 0 );
}

int md_starts( md_context_t *ctx )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->starts_func( ctx->md_ctx );

    return( 0 );
}

int md_update( md_context_t *ctx, const unsigned char *input, size_t ilen )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->update_func( ctx->md_ctx, input, ilen );

    return( 0 );
}

int md_finish( md_context_t *ctx, unsigned char *output )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->finish_func( ctx->md_ctx, output );

    return( 0 );
}

int md( const md_info_t *md_info, const unsigned char *input, size_t ilen,
            unsigned char *output )
{
    if( md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    md_info->digest_func( input, ilen, output );

    return( 0 );
}

int md_file( const md_info_t *md_info, const char *path, unsigned char *output )
{
#if defined(POLARSSL_FS_IO)
    int ret;
#endif

    if( md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

#if defined(POLARSSL_FS_IO)
    ret = md_info->file_func( path, output );
    if( ret != 0 )
        return( POLARSSL_ERR_MD_FILE_IO_ERROR + ret );

    return( ret );
#else
    ((void) path);
    ((void) output);

    return( POLARSSL_ERR_MD_FEATURE_UNAVAILABLE );
#endif /* POLARSSL_FS_IO */
}

int md_hmac_starts( md_context_t *ctx, const unsigned char *key, size_t keylen )
{
    unsigned char sum[POLARSSL_MD_MAX_SIZE];
    unsigned char *ipad, *opad;
    size_t i;

    if( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    if( keylen > (size_t) ctx->md_info->block_size )
    {
        ctx->md_info->starts_func( ctx->md_ctx );
        ctx->md_info->update_func( ctx->md_ctx, key, keylen );
        ctx->md_info->finish_func( ctx->md_ctx, sum );

        keylen = ctx->md_info->size;
        key = sum;
    }

    ipad = (unsigned char *) ctx->hmac_ctx;
    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    memset( ipad, 0x36, ctx->md_info->block_size );
    memset( opad, 0x5C, ctx->md_info->block_size );

    for( i = 0; i < keylen; i++ )
    {
        ipad[i] = (unsigned char)( ipad[i] ^ key[i] );
        opad[i] = (unsigned char)( opad[i] ^ key[i] );
    }

    polarssl_zeroize( sum, sizeof( sum ) );

    ctx->md_info->starts_func( ctx->md_ctx );
    ctx->md_info->update_func( ctx->md_ctx, ipad, ctx->md_info->block_size );

    return( 0 );
}

int md_hmac_update( md_context_t *ctx, const unsigned char *input, size_t ilen )
{
    if( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->update_func( ctx->md_ctx, input, ilen );

    return( 0 );
}

int md_hmac_finish( md_context_t *ctx, unsigned char *output )
{
    unsigned char tmp[POLARSSL_MD_MAX_SIZE];
    unsigned char *opad;

    if( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    opad = (unsigned char *) ctx->hmac_ctx + ctx->md_info->block_size;

    ctx->md_info->finish_func( ctx->md_ctx, tmp );
    ctx->md_info->starts_func( ctx->md_ctx );
    ctx->md_info->update_func( ctx->md_ctx, opad, ctx->md_info->block_size );
    ctx->md_info->update_func( ctx->md_ctx, tmp, ctx->md_info->size );
    ctx->md_info->finish_func( ctx->md_ctx, output );

    return( 0 );
}

int md_hmac_reset( md_context_t *ctx )
{
    unsigned char *ipad;

    if( ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ipad = (unsigned char *) ctx->hmac_ctx;

    ctx->md_info->starts_func( ctx->md_ctx );
    ctx->md_info->update_func( ctx->md_ctx, ipad, ctx->md_info->block_size );

    return( 0 );
}

int md_hmac( const md_info_t *md_info, const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char *output )
{
    md_context_t ctx;
    int ret;

    if( md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    md_init( &ctx );

    if( ( ret = md_init_ctx( &ctx, md_info ) ) != 0 )
        return( ret );

    md_hmac_starts( &ctx, key, keylen );
    md_hmac_update( &ctx, input, ilen );
    md_hmac_finish( &ctx, output );

    md_free( &ctx );

    return( 0 );
}

int md_process( md_context_t *ctx, const unsigned char *data )
{
    if( ctx == NULL || ctx->md_info == NULL )
        return( POLARSSL_ERR_MD_BAD_INPUT_DATA );

    ctx->md_info->process_func( ctx->md_ctx, data );

    return( 0 );
}

unsigned char md_get_size( const md_info_t *md_info )
{
    if( md_info == NULL )
        return( 0 );

    return md_info->size;
}

md_type_t md_get_type( const md_info_t *md_info )
{
    if( md_info == NULL )
        return( POLARSSL_MD_NONE );

    return md_info->type;
}

const char *md_get_name( const md_info_t *md_info )
{
    if( md_info == NULL )
        return( NULL );

    return md_info->name;
}

#endif /* POLARSSL_MD_C */
