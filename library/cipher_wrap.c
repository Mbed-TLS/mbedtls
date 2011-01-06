/**
 * \file md_wrap.c
 * 
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

#if defined(POLARSSL_CIPHER_C)

#include "polarssl/cipher_wrap.h"
#include "polarssl/aes.h"
#include "polarssl/camellia.h"
#include "polarssl/des.h"

#include <string.h>
#include <stdlib.h>

#if defined(POLARSSL_AES_C)

int aes_crypt_cbc_wrap( void *ctx, operation_t operation, int length,
        unsigned char *iv, const unsigned char *input, unsigned char *output )
{
    return aes_crypt_cbc( (aes_context *) ctx, operation, length, iv, input, output );
}

int aes_setkey_dec_wrap( void *ctx, const unsigned char *key, int key_length )
{
    return aes_setkey_dec( (aes_context *) ctx, key, key_length );
}

int aes_setkey_enc_wrap( void *ctx, const unsigned char *key, int key_length )
{
    return aes_setkey_enc( (aes_context *) ctx, key, key_length );
}

static void * aes_ctx_alloc( void )
{
    return malloc( sizeof( aes_context ) );
}

static void aes_ctx_free( void *ctx )
{
    free( ctx );
}

const cipher_info_t aes_128_cbc_info = {
    .type = POLARSSL_CIPHER_AES_128_CBC,
    .cipher = POLARSSL_CIPHER_ID_AES,
    .mode = POLARSSL_MODE_CBC,
    .key_length = 128,
    .name = "AES-128-CBC",
    .iv_size = 16,
    .block_size = 16,
    .cbc_func = aes_crypt_cbc_wrap,
    .setkey_enc_func = aes_setkey_enc_wrap,
    .setkey_dec_func = aes_setkey_dec_wrap,
    .ctx_alloc_func = aes_ctx_alloc,
    .ctx_free_func = aes_ctx_free
};

const cipher_info_t aes_192_cbc_info = {
    .type = POLARSSL_CIPHER_AES_192_CBC,
    .cipher = POLARSSL_CIPHER_ID_AES,
    .mode = POLARSSL_MODE_CBC,
    .key_length = 192,
    .name = "AES-192-CBC",
    .iv_size = 16,
    .block_size = 16,
    .cbc_func = aes_crypt_cbc_wrap,
    .setkey_enc_func = aes_setkey_enc_wrap,
    .setkey_dec_func = aes_setkey_dec_wrap,
    .ctx_alloc_func = aes_ctx_alloc,
    .ctx_free_func = aes_ctx_free
};

const cipher_info_t aes_256_cbc_info = {
    .type = POLARSSL_CIPHER_AES_256_CBC,
    .cipher = POLARSSL_CIPHER_ID_AES,
    .mode = POLARSSL_MODE_CBC,
    .key_length = 256,
    .name = "AES-256-CBC",
    .iv_size = 16,
    .block_size = 16,
    .cbc_func = aes_crypt_cbc_wrap,
    .setkey_enc_func = aes_setkey_enc_wrap,
    .setkey_dec_func = aes_setkey_dec_wrap,
    .ctx_alloc_func = aes_ctx_alloc,
    .ctx_free_func = aes_ctx_free
};
#endif

#if defined(POLARSSL_CAMELLIA_C)

int camellia_crypt_cbc_wrap( void *ctx, operation_t operation, int length,
        unsigned char *iv, const unsigned char *input, unsigned char *output )
{
    return camellia_crypt_cbc( (camellia_context *) ctx, operation, length, iv, input, output );
}

int camellia_setkey_dec_wrap( void *ctx, const unsigned char *key, int key_length )
{
    return camellia_setkey_dec( (camellia_context *) ctx, key, key_length );
}

int camellia_setkey_enc_wrap( void *ctx, const unsigned char *key, int key_length )
{
    return camellia_setkey_enc( (camellia_context *) ctx, key, key_length );
}

static void * camellia_ctx_alloc( void )
{
    return malloc( sizeof( camellia_context ) );
}

static void camellia_ctx_free( void *ctx )
{
    free( ctx );
}

const cipher_info_t camellia_128_cbc_info = {
    .type = POLARSSL_CIPHER_CAMELLIA_128_CBC,
    .cipher = POLARSSL_CIPHER_ID_CAMELLIA,
    .mode = POLARSSL_MODE_CBC,
    .key_length = 128,
    .name = "CAMELLIA-128-CBC",
    .iv_size = 16,
    .block_size = 16,
    .cbc_func = camellia_crypt_cbc_wrap,
    .setkey_enc_func = camellia_setkey_enc_wrap,
    .setkey_dec_func = camellia_setkey_dec_wrap,
    .ctx_alloc_func = camellia_ctx_alloc,
    .ctx_free_func = camellia_ctx_free
};

const cipher_info_t camellia_192_cbc_info = {
    .type = POLARSSL_CIPHER_CAMELLIA_192_CBC,
    .cipher = POLARSSL_CIPHER_ID_CAMELLIA,
    .mode = POLARSSL_MODE_CBC,
    .key_length = 192,
    .name = "CAMELLIA-192-CBC",
    .iv_size = 16,
    .block_size = 16,
    .cbc_func = camellia_crypt_cbc_wrap,
    .setkey_enc_func = camellia_setkey_enc_wrap,
    .setkey_dec_func = camellia_setkey_dec_wrap,
    .ctx_alloc_func = camellia_ctx_alloc,
    .ctx_free_func = camellia_ctx_free
};

const cipher_info_t camellia_256_cbc_info = {
    .type = POLARSSL_CIPHER_CAMELLIA_256_CBC,
    .cipher = POLARSSL_CIPHER_ID_CAMELLIA,
    .mode = POLARSSL_MODE_CBC,
    .key_length = 256,
    .name = "CAMELLIA-256-CBC",
    .iv_size = 16,
    .block_size = 16,
    .cbc_func = camellia_crypt_cbc_wrap,
    .setkey_enc_func = camellia_setkey_enc_wrap,
    .setkey_dec_func = camellia_setkey_dec_wrap,
    .ctx_alloc_func = camellia_ctx_alloc,
    .ctx_free_func = camellia_ctx_free
};
#endif

#if defined(POLARSSL_DES_C)

int des_crypt_cbc_wrap( void *ctx, operation_t operation, int length,
        unsigned char *iv, const unsigned char *input, unsigned char *output )
{
    return des_crypt_cbc( (des_context *) ctx, operation, length, iv, input, output );
}

int des3_crypt_cbc_wrap( void *ctx, operation_t operation, int length,
        unsigned char *iv, const unsigned char *input, unsigned char *output )
{
    return des3_crypt_cbc( (des3_context *) ctx, operation, length, iv, input, output );
}

int des_setkey_dec_wrap( void *ctx, const unsigned char *key, int key_length )
{
    return des_setkey_dec( (des_context *) ctx, key );
}

int des_setkey_enc_wrap( void *ctx, const unsigned char *key, int key_length )
{
    return des_setkey_enc( (des_context *) ctx, key );
}

int des3_set2key_dec_wrap( void *ctx, const unsigned char *key, int key_length )
{
    return des3_set2key_dec( (des3_context *) ctx, key );
}

int des3_set2key_enc_wrap( void *ctx, const unsigned char *key, int key_length )
{
    return des3_set2key_enc( (des3_context *) ctx, key );
}

int des3_set3key_dec_wrap( void *ctx, const unsigned char *key, int key_length )
{
    return des3_set3key_dec( (des3_context *) ctx, key );
}

int des3_set3key_enc_wrap( void *ctx, const unsigned char *key, int key_length )
{
    return des3_set3key_enc( (des3_context *) ctx, key );
}

static void * des_ctx_alloc( void )
{
    return malloc( sizeof( des_context ) );
}

static void * des3_ctx_alloc( void )
{
    return malloc( sizeof( des3_context ) );
}

static void des_ctx_free( void *ctx )
{
    free( ctx );
}

const cipher_info_t des_cbc_info = {
    .type = POLARSSL_CIPHER_DES_CBC,
    .cipher = POLARSSL_CIPHER_ID_DES,
    .mode = POLARSSL_MODE_CBC,
    .key_length = POLARSSL_KEY_LENGTH_DES,
    .name = "DES-CBC",
    .iv_size = 8,
    .block_size = 8,
    .cbc_func = des_crypt_cbc_wrap,
    .setkey_enc_func = des_setkey_enc_wrap,
    .setkey_dec_func = des_setkey_dec_wrap,
    .ctx_alloc_func = des_ctx_alloc,
    .ctx_free_func = des_ctx_free
};

const cipher_info_t des_ede_cbc_info = {
    .type = POLARSSL_CIPHER_DES_EDE_CBC,
    .cipher = POLARSSL_CIPHER_ID_DES,
    .mode = POLARSSL_MODE_CBC,
    .key_length = POLARSSL_KEY_LENGTH_DES_EDE,
    .name = "DES-EDE-CBC",
    .iv_size = 16,
    .block_size = 16,
    .cbc_func = des3_crypt_cbc_wrap,
    .setkey_enc_func = des3_set2key_enc_wrap,
    .setkey_dec_func = des3_set2key_dec_wrap,
    .ctx_alloc_func = des3_ctx_alloc,
    .ctx_free_func = des_ctx_free
};

const cipher_info_t des_ede3_cbc_info = {
    .type = POLARSSL_CIPHER_DES_EDE3_CBC,
    .cipher = POLARSSL_CIPHER_ID_DES,
    .mode = POLARSSL_MODE_CBC,
    .key_length = POLARSSL_KEY_LENGTH_DES_EDE3,
    .name = "DES-EDE3-CBC",
    .iv_size = 8,
    .block_size = 8,
    .cbc_func = des3_crypt_cbc_wrap,
    .setkey_enc_func = des3_set3key_enc_wrap,
    .setkey_dec_func = des3_set3key_dec_wrap,
    .ctx_alloc_func = des3_ctx_alloc,
    .ctx_free_func = des_ctx_free
};
#endif

#endif
