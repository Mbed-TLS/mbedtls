/**
 * \file md_wrap.c

 * \brief Generic message digest wrapper for PolarSSL
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

#if defined(POLARSSL_MD_C)

#include "polarssl/md_wrap.h"
#include "polarssl/md2.h"
#include "polarssl/md4.h"
#include "polarssl/md5.h"
#include "polarssl/sha1.h"
#include "polarssl/sha2.h"
#include "polarssl/sha4.h"

#include <string.h>
#include <stdlib.h>

#if defined(POLARSSL_MD2_C)

static void md2_starts_wrap( void *ctx )
{
    md2_starts( (md2_context *) ctx );
}

static void md2_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    md2_update( (md2_context *) ctx, input, ilen );
}

static void md2_finish_wrap( void *ctx, unsigned char *output )
{
    md2_finish( (md2_context *) ctx, output );
}

static void md2_hmac_starts_wrap( void *ctx, const unsigned char *key, int keylen )
{
    md2_hmac_starts( (md2_context *) ctx, key, keylen );
}

static void md2_hmac_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    md2_hmac_update( (md2_context *) ctx, input, ilen );
}

static void md2_hmac_finish_wrap( void *ctx, unsigned char *output )
{
    md2_hmac_finish( (md2_context *) ctx, output );
}

static void md2_hmac_reset_wrap( void *ctx )
{
    md2_hmac_reset( (md2_context *) ctx );
}

static void * md2_ctx_alloc( void )
{
    return malloc( sizeof( md2_context ) );
}

static void md2_ctx_free( void *ctx )
{
    free( ctx );
}

const md_info_t md2_info = {
    .type = POLARSSL_MD_MD2,
    .name = "MD2",
    .size = 16,
    .starts_func = md2_starts_wrap,
    .update_func = md2_update_wrap,
    .finish_func = md2_finish_wrap,
    .digest_func = md2,
    .file_func = md2_file,
    .hmac_starts_func = md2_hmac_starts_wrap,
    .hmac_update_func = md2_hmac_update_wrap,
    .hmac_finish_func = md2_hmac_finish_wrap,
    .hmac_reset_func = md2_hmac_reset_wrap,
    .hmac_func = md2_hmac,
    .ctx_alloc_func = md2_ctx_alloc,
    .ctx_free_func = md2_ctx_free,
};

#endif

#if defined(POLARSSL_MD4_C)

void md4_starts_wrap( void *ctx )
{
    md4_starts( (md4_context *) ctx );
}

void md4_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    md4_update( (md4_context *) ctx, input, ilen );
}

void md4_finish_wrap( void *ctx, unsigned char *output )
{
    md4_finish( (md4_context *) ctx, output );
}

void md4_hmac_starts_wrap( void *ctx, const unsigned char *key, int keylen )
{
    md4_hmac_starts( (md4_context *) ctx, key, keylen );
}

void md4_hmac_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    md4_hmac_update( (md4_context *) ctx, input, ilen );
}

void md4_hmac_finish_wrap( void *ctx, unsigned char *output )
{
    md4_hmac_finish( (md4_context *) ctx, output );
}

void md4_hmac_reset_wrap( void *ctx )
{
    md4_hmac_reset( (md4_context *) ctx );
}

void *md4_ctx_alloc( void )
{
    return malloc( sizeof( md4_context ) );
}

void md4_ctx_free( void *ctx )
{
    free( ctx );
}

const md_info_t md4_info = {
    .type = POLARSSL_MD_MD4,
    .name = "MD4",
    .size = 16,
    .starts_func = md4_starts_wrap,
    .update_func = md4_update_wrap,
    .finish_func = md4_finish_wrap,
    .digest_func = md4,
    .file_func = md4_file,
    .hmac_starts_func = md4_hmac_starts_wrap,
    .hmac_update_func = md4_hmac_update_wrap,
    .hmac_finish_func = md4_hmac_finish_wrap,
    .hmac_reset_func = md4_hmac_reset_wrap,
    .hmac_func = md4_hmac,
    .ctx_alloc_func = md4_ctx_alloc,
    .ctx_free_func = md4_ctx_free,
};

#endif

#if defined(POLARSSL_MD5_C)

static void md5_starts_wrap( void *ctx )
{
    md5_starts( (md5_context *) ctx );
}

static void md5_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    md5_update( (md5_context *) ctx, input, ilen );
}

static void md5_finish_wrap( void *ctx, unsigned char *output )
{
    md5_finish( (md5_context *) ctx, output );
}

static void md5_hmac_starts_wrap( void *ctx, const unsigned char *key, int keylen )
{
    md5_hmac_starts( (md5_context *) ctx, key, keylen );
}

static void md5_hmac_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    md5_hmac_update( (md5_context *) ctx, input, ilen );
}

static void md5_hmac_finish_wrap( void *ctx, unsigned char *output )
{
    md5_hmac_finish( (md5_context *) ctx, output );
}

static void md5_hmac_reset_wrap( void *ctx )
{
    md5_hmac_reset( (md5_context *) ctx );
}

static void * md5_ctx_alloc( void )
{
    return malloc( sizeof( md5_context ) );
}

static void md5_ctx_free( void *ctx )
{
    free( ctx );
}

const md_info_t md5_info = {
    .type = POLARSSL_MD_MD5,
    .name = "MD5",
    .size = 16,
    .starts_func = md5_starts_wrap,
    .update_func = md5_update_wrap,
    .finish_func = md5_finish_wrap,
    .digest_func = md5,
    .file_func = md5_file,
    .hmac_starts_func = md5_hmac_starts_wrap,
    .hmac_update_func = md5_hmac_update_wrap,
    .hmac_finish_func = md5_hmac_finish_wrap,
    .hmac_reset_func = md5_hmac_reset_wrap,
    .hmac_func = md5_hmac,
    .ctx_alloc_func = md5_ctx_alloc,
    .ctx_free_func = md5_ctx_free,
};

#endif

#if defined(POLARSSL_SHA1_C)

void sha1_starts_wrap( void *ctx )
{
    sha1_starts( (sha1_context *) ctx );
}

void sha1_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    sha1_update( (sha1_context *) ctx, input, ilen );
}

void sha1_finish_wrap( void *ctx, unsigned char *output )
{
    sha1_finish( (sha1_context *) ctx, output );
}

void sha1_hmac_starts_wrap( void *ctx, const unsigned char *key, int keylen )
{
    sha1_hmac_starts( (sha1_context *) ctx, key, keylen );
}

void sha1_hmac_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    sha1_hmac_update( (sha1_context *) ctx, input, ilen );
}

void sha1_hmac_finish_wrap( void *ctx, unsigned char *output )
{
    sha1_hmac_finish( (sha1_context *) ctx, output );
}

void sha1_hmac_reset_wrap( void *ctx )
{
    sha1_hmac_reset( (sha1_context *) ctx );
}

void * sha1_ctx_alloc( void )
{
    return malloc( sizeof( sha1_context ) );
}

void sha1_ctx_free( void *ctx )
{
    free( ctx );
}

const md_info_t sha1_info = {
    .type = POLARSSL_MD_SHA1,
    .name = "SHA1",
    .size = 20,
    .starts_func = sha1_starts_wrap,
    .update_func = sha1_update_wrap,
    .finish_func = sha1_finish_wrap,
    .digest_func = sha1,
    .file_func = sha1_file,
    .hmac_starts_func = sha1_hmac_starts_wrap,
    .hmac_update_func = sha1_hmac_update_wrap,
    .hmac_finish_func = sha1_hmac_finish_wrap,
    .hmac_reset_func = sha1_hmac_reset_wrap,
    .hmac_func = sha1_hmac,
    .ctx_alloc_func = sha1_ctx_alloc,
    .ctx_free_func = sha1_ctx_free,
};

#endif

/*
 * Wrappers for generic message digests
 */
#if defined(POLARSSL_SHA2_C)

void sha224_starts_wrap( void *ctx )
{
    sha2_starts( (sha2_context *) ctx, 1 );
}

void sha224_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    sha2_update( (sha2_context *) ctx, input, ilen );
}

void sha224_finish_wrap( void *ctx, unsigned char *output )
{
    sha2_finish( (sha2_context *) ctx, output );
}

void sha224_wrap( const unsigned char *input, int ilen,
                    unsigned char *output )
{
    sha2( input, ilen, output, 1 );
}

int sha224_file_wrap( const char *path, unsigned char *output )
{
    return sha2_file( path, output, 1 );
}

void sha224_hmac_starts_wrap( void *ctx, const unsigned char *key, int keylen )
{
    sha2_hmac_starts( (sha2_context *) ctx, key, keylen, 1 );
}

void sha224_hmac_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    sha2_hmac_update( (sha2_context *) ctx, input, ilen );
}

void sha224_hmac_finish_wrap( void *ctx, unsigned char *output )
{
    sha2_hmac_finish( (sha2_context *) ctx, output );
}

void sha224_hmac_reset_wrap( void *ctx )
{
    sha2_hmac_reset( (sha2_context *) ctx );
}

void sha224_hmac_wrap( const unsigned char *key, int keylen,
        const unsigned char *input, int ilen,
        unsigned char *output )
{
    sha2_hmac( key, keylen, input, ilen, output, 1 );
}

void * sha224_ctx_alloc( void )
{
    return malloc( sizeof( sha2_context ) );
}

void sha224_ctx_free( void *ctx )
{
    free( ctx );
}

const md_info_t sha224_info = {
    .type = POLARSSL_MD_SHA224,
    .name = "SHA224",
    .size = 28,
    .starts_func = sha224_starts_wrap,
    .update_func = sha224_update_wrap,
    .finish_func = sha224_finish_wrap,
    .digest_func = sha224_wrap,
    .file_func = sha224_file_wrap,
    .hmac_starts_func = sha224_hmac_starts_wrap,
    .hmac_update_func = sha224_hmac_update_wrap,
    .hmac_finish_func = sha224_hmac_finish_wrap,
    .hmac_reset_func = sha224_hmac_reset_wrap,
    .hmac_func = sha224_hmac_wrap,
    .ctx_alloc_func = sha224_ctx_alloc,
    .ctx_free_func = sha224_ctx_free,
};

void sha256_starts_wrap( void *ctx )
{
    sha2_starts( (sha2_context *) ctx, 0 );
}

void sha256_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    sha2_update( (sha2_context *) ctx, input, ilen );
}

void sha256_finish_wrap( void *ctx, unsigned char *output )
{
    sha2_finish( (sha2_context *) ctx, output );
}

void sha256_wrap( const unsigned char *input, int ilen,
                    unsigned char *output )
{
    sha2( input, ilen, output, 0 );
}

int sha256_file_wrap( const char *path, unsigned char *output )
{
    return sha2_file( path, output, 0 );
}

void sha256_hmac_starts_wrap( void *ctx, const unsigned char *key, int keylen )
{
    sha2_hmac_starts( (sha2_context *) ctx, key, keylen, 0 );
}

void sha256_hmac_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    sha2_hmac_update( (sha2_context *) ctx, input, ilen );
}

void sha256_hmac_finish_wrap( void *ctx, unsigned char *output )
{
    sha2_hmac_finish( (sha2_context *) ctx, output );
}

void sha256_hmac_reset_wrap( void *ctx )
{
    sha2_hmac_reset( (sha2_context *) ctx );
}

void sha256_hmac_wrap( const unsigned char *key, int keylen,
        const unsigned char *input, int ilen,
        unsigned char *output )
{
    sha2_hmac( key, keylen, input, ilen, output, 0 );
}

void * sha256_ctx_alloc( void )
{
    return malloc( sizeof( sha2_context ) `);
}

void sha256_ctx_free( void *ctx )
{
    free( ctx );
}

const md_info_t sha256_info = {
    .type = POLARSSL_MD_SHA256,
    .name = "SHA256",
    .size = 32,
    .starts_func = sha256_starts_wrap,
    .update_func = sha256_update_wrap,
    .finish_func = sha256_finish_wrap,
    .digest_func = sha256_wrap,
    .file_func = sha256_file_wrap,
    .hmac_starts_func = sha256_hmac_starts_wrap,
    .hmac_update_func = sha256_hmac_update_wrap,
    .hmac_finish_func = sha256_hmac_finish_wrap,
    .hmac_reset_func = sha256_hmac_reset_wrap,
    .hmac_func = sha256_hmac_wrap,
    .ctx_alloc_func = sha256_ctx_alloc,
    .ctx_free_func = sha256_ctx_free,
};

#endif

#if defined(POLARSSL_SHA4_C)

void sha384_starts_wrap( void *ctx )
{
    sha4_starts( (sha4_context *) ctx, 1 );
}

void sha384_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    sha4_update( (sha4_context *) ctx, input, ilen );
}

void sha384_finish_wrap( void *ctx, unsigned char *output )
{
    sha4_finish( (sha4_context *) ctx, output );
}

void sha384_wrap( const unsigned char *input, int ilen,
                    unsigned char *output )
{
    sha4( input, ilen, output, 1 );
}

int sha384_file_wrap( const char *path, unsigned char *output )
{
    return sha4_file( path, output, 1 );
}

void sha384_hmac_starts_wrap( void *ctx, const unsigned char *key, int keylen )
{
    sha4_hmac_starts( (sha4_context *) ctx, key, keylen, 1 );
}

void sha384_hmac_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    sha4_hmac_update( (sha4_context *) ctx, input, ilen );
}

void sha384_hmac_finish_wrap( void *ctx, unsigned char *output )
{
    sha4_hmac_finish( (sha4_context *) ctx, output );
}

void sha384_hmac_reset_wrap( void *ctx )
{
    sha4_hmac_reset( (sha4_context *) ctx );
}

void sha384_hmac_wrap( const unsigned char *key, int keylen,
        const unsigned char *input, int ilen,
        unsigned char *output )
{
    sha4_hmac( key, keylen, input, ilen, output, 1 );
}

void * sha384_ctx_alloc( void )
{
    return malloc( sizeof( sha4_context ) );
}

void sha384_ctx_free( void *ctx )
{
    free( ctx );
}

const md_info_t sha384_info = {
        .type = POLARSSL_MD_SHA384,
        .name = "SHA384",
        .size = 48,
        .starts_func = sha384_starts_wrap,
        .update_func = sha384_update_wrap,
        .finish_func = sha384_finish_wrap,
        .digest_func = sha384_wrap,
        .file_func = sha384_file_wrap,
        .hmac_starts_func = sha384_hmac_starts_wrap,
        .hmac_update_func = sha384_hmac_update_wrap,
        .hmac_finish_func = sha384_hmac_finish_wrap,
        .hmac_reset_func = sha384_hmac_reset_wrap,
        .hmac_func = sha384_hmac_wrap,
        .ctx_alloc_func = sha384_ctx_alloc,
        .ctx_free_func = sha384_ctx_free,
};

void sha512_starts_wrap( void *ctx )
{
    sha4_starts( (sha4_context *) ctx, 0 );
}

void sha512_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    sha4_update( (sha4_context *) ctx, input, ilen );
}

void sha512_finish_wrap( void *ctx, unsigned char *output )
{
    sha4_finish( (sha4_context *) ctx, output );
}

void sha512_wrap( const unsigned char *input, int ilen,
                    unsigned char *output )
{
    sha4( input, ilen, output, 0 );
}

int sha512_file_wrap( const char *path, unsigned char *output )
{
    return sha4_file( path, output, 0 );
}

void sha512_hmac_starts_wrap( void *ctx, const unsigned char *key, int keylen )
{
    sha4_hmac_starts( (sha4_context *) ctx, key, keylen, 0 );
}

void sha512_hmac_update_wrap( void *ctx, const unsigned char *input, int ilen )
{
    sha4_hmac_update( (sha4_context *) ctx, input, ilen );
}

void sha512_hmac_finish_wrap( void *ctx, unsigned char *output )
{
    sha4_hmac_finish( (sha4_context *) ctx, output );
}

void sha512_hmac_reset_wrap( void *ctx )
{
    sha4_hmac_reset( (sha4_context *) ctx );
}

void sha512_hmac_wrap( const unsigned char *key, int keylen,
        const unsigned char *input, int ilen,
        unsigned char *output )
{
    sha4_hmac( key, keylen, input, ilen, output, 0 );
}

void * sha512_ctx_alloc( void )
{
    return malloc( sizeof( sha4_context ) );
}

void sha512_ctx_free( void *ctx )
{
    free( ctx );
}

const md_info_t sha512_info = {
    .type = POLARSSL_MD_SHA512,
    .name = "SHA512",
    .size = 64,
    .starts_func = sha512_starts_wrap,
    .update_func = sha512_update_wrap,
    .finish_func = sha512_finish_wrap,
    .digest_func = sha512_wrap,
    .file_func = sha512_file_wrap,
    .hmac_starts_func = sha512_hmac_starts_wrap,
    .hmac_update_func = sha512_hmac_update_wrap,
    .hmac_finish_func = sha512_hmac_finish_wrap,
    .hmac_reset_func = sha512_hmac_reset_wrap,
    .hmac_func = sha512_hmac_wrap,
    .ctx_alloc_func = sha512_ctx_alloc,
    .ctx_free_func = sha512_ctx_free,
};

#endif

#endif
