/*
 *  Threefish implementation
 *
 *  Copyright (C) 2016, ARM Limited, All Rights Reserved
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
/*
 *  The Threefish block cipher was designed in 2008 as part of the Skein hash
 *  function. Threefish was created and analyzed by: Niels Ferguson,
 *  Stefan Lucks, Bruce Schneier, Doug Whiting, Mihir Bellare, Tadayoshi Kohno,
 *  Jon Callas, and Jesse Walker.
 *
 *  https://www.schneier.com/academic/paperfiles/skein1.3.pdf
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_THREEFISH_C)

#include "mbedtls/threefish.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if !defined(MBEDTLS_BLOWFISH_ALT)

#define THREEFISH_KEY_SCHED_CONST 0x1BD11BDAA9FC1A22L

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = (unsigned char*)v; while( n-- ) *p++ = 0;
}

/*
 * Encrypt one data block
 */
static int threefish_enc( mbedtls_threefish_context *ctx,
                          const unsigned char *input,
                          const unsigned char *output )
{
    (void) ctx;
    (void) input;
    (void) output;

    return( 0 );
}

/*
 * Decrypt one data block
 */
static int threefish_dec( mbedtls_threefish_context *ctx,
                          const unsigned char *input,
                          const unsigned char *output )
{
    (void) ctx;
    (void) input;
    (void) output;

    return( 0 );
}

void mbedtls_threefish_init( mbedtls_threefish_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_threefish_context ) );
}

void mbedtls_threefish_free( mbedtls_threefish_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_zeroize( ctx, sizeof( mbedtls_threefish_context ) );
}

int mbedtls_threefish_setkey( mbedtls_threefish_context *ctx,
                              const unsigned char *key, unsigned int keybits )
{
    unsigned int i;

    switch( keybits )
    {
        case  256:
        case  512:
        case 1024:
            ctx->keybits = keybits;
            break;

        default:
            return( MBEDTLS_ERR_THREEFISH_INVALID_KEY_LENGTH );
    }

    memcpy( ctx->key, key, keybits >> 3 );

    /* Calculate key parity */
    ctx->key[keybits >> 6] = THREEFISH_KEY_SCHED_CONST;
    for( i = 0; i < ( keybits >> 6 ); i++ )
    {
        ctx->key[keybits >> 6] ^= ctx->key[i];
    }

    return( 0 );
}

int mbedtls_threefish_settweak( mbedtls_threefish_context *ctx,
                                const unsigned char *tweak )
{
    memcpy( ctx->tweak, tweak, 16 );

    /* Calculate tweak parity */
    ctx->tweak[2] = ctx->tweak[0] ^ ctx->tweak[1];

    return( 0 );
}

/*
 * Threefish-ECB block encryption/decryption
 */
int mbedtls_threefish_crypt_ecb( mbedtls_threefish_context *ctx,
                                 int mode, const unsigned char *input,
                                 unsigned char *output )
{
    int ret;

    if( mode == MBEDTLS_THREEFISH_DECRYPT )
    {
        ret = threefish_dec( ctx, input, output );
    }
    else /* MBEDTLS_THREEFISH_ENCRYPT */
    {
        ret = threefish_enc( ctx, input, output );
    }

    return( ret );
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * Threefish-CBC block encryption/decryption
 */
int mbedtls_threefish_crypt_cbc( mbedtls_threefish_context *ctx,
                                 int mode, size_t length, unsigned char *iv,
                                 const unsigned char *input,
                                 unsigned char *output )
{
    size_t i;
    size_t block_size = ctx->keybits >> 3;
    unsigned char temp[128];

    if( length % block_size )
        return( MBEDTLS_ERR_THREEFISH_INVALID_INPUT_LENGTH );

    if( mode == MBEDTLS_THREEFISH_DECRYPT )
    {
        while( length > 0 )
        {
            memcpy( temp, input, block_size );
            mbedtls_threefish_crypt_ecb( ctx, mode, input, output );

            for( i = 0; i < block_size; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, block_size );

            input  += block_size;
            output += block_size;
            length -= block_size;
        }
    }
    else /* MBEDTLS_THREEFISH_ENCRYPT */
    {
        while( length > 0 )
        {
            for( i = 0; i < block_size; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            mbedtls_threefish_crypt_ecb( ctx, mode, output, output );
            memcpy( iv, output, block_size );

            input  += block_size;
            output += block_size;
            length -= block_size;
        }
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/*
 * Threefish-CFB block encryption/decryption
 */
int mbedtls_threefish_crypt_cfb( mbedtls_threefish_context *ctx,
                                 int mode, size_t length, size_t *iv_off,
                                 unsigned char *iv, const unsigned char *input,
                                 unsigned char *output )
{
    int c;
    size_t n = *iv_off;
    size_t block_size = ctx->keybits >> 3;

    if( mode == MBEDTLS_THREEFISH_DECRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_threefish_crypt_ecb( ctx, MBEDTLS_THREEFISH_ENCRYPT,
                                             iv, iv );

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char)c;

            n = ( n + 1 ) % block_size;
        }
    }
    else /* MBEDTLS_THREEFISH_ENCRYPT */
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_threefish_crypt_ecb( ctx, MBEDTLS_THREEFISH_ENCRYPT,
                                             iv, iv );

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = ( n + 1 ) % block_size;
        }
    }

    *iv_off = n;

    return( 0 );
}
#endif /*MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/*
 * Threefish-CTR block encryption/decryption
 */
int mbedtls_threefish_crypt_ctr( mbedtls_threefish_context *ctx,
                                 size_t length, size_t *nc_off,
                                 unsigned char *nonce_counter,
                                 unsigned char *stream_block,
                                 const unsigned char *input,
                                 unsigned char *output )
{
    int c, i;
    size_t n = *nc_off;
    size_t block_size = ctx->keybits >> 3;

    while( length-- )
    {
        if( n == 0 )
        {
            mbedtls_threefish_crypt_ecb( ctx, MBEDTLS_THREEFISH_ENCRYPT,
                                         nonce_counter, stream_block );

            for( i = block_size; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;
        }
        c = *input++;
        *output++ = (unsigned char)( c ^ stream_block[n] );

        n = ( n + 1 ) % block_size;
    }

    *nc_off = n;

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#endif /* !MBEDTLS_THREEFISH_ALT */

#if defined(MBEDTLS_SELF_TEST)
/*
 * Checkup routine
 */
int mbedtls_threefish_self_test( int verbose )
{
    (void) verbose;
    return( 0 );
}
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_THREEFISH_C */
