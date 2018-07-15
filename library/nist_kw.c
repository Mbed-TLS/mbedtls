/*
 *  Implementation of NIST SP 800-38F key wrapping, supporting KW and KWP modes
 *  only
 *
 *  Copyright (C) 2018, Arm Limited (or its affiliates), All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */
/*
 * Definition of Key Wrapping:
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf
 * RFC 3394 "Advanced Encryption Standard (AES) Key Wrap Algorithm"
 * RFC 5649 "Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm"
 *
 * Note: RFC 3394 defines different methodology for intermediate operations for
 * the wrapping and unwrapping operation than the definition in NIST SP 800-38F.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_NIST_KW_C)

#include "mbedtls/nist_kw.h"
#include "mbedtls/platform_util.h"

#include <stdint.h>
#include <string.h>

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

#if !defined(MBEDTLS_NIST_KW_ALT)

#define KW_SEMIBLOCK_LENGTH    8
#define MIN_SEMIBLOCKS_COUNT   3

/* constant-time buffer comparison */
static inline unsigned char mbedtls_nist_kw_safer_memcmp( const void *a, const void *b, size_t n )
{
    size_t i;
    volatile const unsigned char *A = (volatile const unsigned char *) a;
    volatile const unsigned char *B = (volatile const unsigned char *) b;
    volatile unsigned char diff = 0;

    for( i = 0; i < n; i++ )
    {
        /* Read volatile data in order before computing diff.
         * This avoids IAR compiler warning:
         * 'the order of volatile accesses is undefined ..' */
        unsigned char x = A[i], y = B[i];
        diff |= x ^ y;
    }

    return( diff );
}

/*! The 64-bit default integrity check value (ICV) for KW mode. */
static const unsigned char NIST_KW_ICV1[] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
/*! The 32-bit default integrity check value (ICV) for KWP mode. */
static const  unsigned char NIST_KW_ICV2[] = {0xA6, 0x59, 0x59, 0xA6};

#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
do {                                                    \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
} while( 0 )
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
do {                                                    \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
} while( 0 )
#endif

/*
 * Initialize context
 */
void mbedtls_nist_kw_init( mbedtls_nist_kw_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_nist_kw_context ) );
}

int mbedtls_nist_kw_setkey( mbedtls_nist_kw_context *ctx,
                            mbedtls_cipher_id_t cipher,
                            const unsigned char *key,
                            unsigned int keybits,
                            const int is_wrap )
{
    int ret;
    const mbedtls_cipher_info_t *cipher_info;

    cipher_info = mbedtls_cipher_info_from_values( cipher,
                                                   keybits,
                                                   MBEDTLS_MODE_ECB );
    if( cipher_info == NULL )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    if( cipher_info->block_size != 16 )
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );

    /*
     * SP 800-38F currently defines AES cipher as the only block cipher allowed:
     * "For KW and KWP, the underlying block cipher shall be approved, and the
     *  block size shall be 128 bits. Currently, the AES block cipher, with key
     *  lengths of 128, 192, or 256 bits, is the only block cipher that fits
     *  this profile."
     *  Currently we don't support other 128 bit block ciphers for key wrapping,
     *  such as Camellia and Aria.
     */
    if( cipher != MBEDTLS_CIPHER_ID_AES )
        return( MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE );

    mbedtls_cipher_free( &ctx->cipher_ctx );

    if( ( ret = mbedtls_cipher_setup( &ctx->cipher_ctx, cipher_info ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_cipher_setkey( &ctx->cipher_ctx, key, keybits,
                                       is_wrap ? MBEDTLS_ENCRYPT :
                                                 MBEDTLS_DECRYPT )
                                                                   ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

/*
 * Free context
 */
void mbedtls_nist_kw_free( mbedtls_nist_kw_context *ctx )
{
    mbedtls_cipher_free( &ctx->cipher_ctx );
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_nist_kw_context ) );
}

/*
 * Helper function for Xoring the uint64_t "t" with the encrypted A.
 * Defined in NIST SP 800-38F section 6.1
 */
static void calc_a_xor_t( unsigned char A[KW_SEMIBLOCK_LENGTH], uint64_t t )
{
    size_t i = 0;
    for( i = 0; i < sizeof( t ); i++ )
    {
        A[i] ^= ( t >> ( ( sizeof( t ) - 1 - i ) * 8 ) ) & 0xff;
    }
}

/*
 * KW-AE as defined in SP 800-38F section 6.2
 * KWP-AE as defined in SP 800-38F section 6.3
 */
int mbedtls_nist_kw_wrap( mbedtls_nist_kw_context *ctx,
                          mbedtls_nist_kw_mode_t mode,
                          const unsigned char *input, size_t in_len,
                          unsigned char *output, size_t *out_len, size_t out_size )
{
    int ret = 0;
    size_t semiblocks = 0;
    size_t s;
    size_t olen, padlen = 0;
    uint64_t t = 0;
    unsigned char outbuff[KW_SEMIBLOCK_LENGTH * 2];
    unsigned char inbuff[KW_SEMIBLOCK_LENGTH * 2];
    unsigned char *R2 = output + KW_SEMIBLOCK_LENGTH;
    unsigned char *A = output;

    *out_len = 0;
    /*
     * Generate the String to work on
     */
    if( mode == MBEDTLS_KW_MODE_KW )
    {
        if( out_size < in_len + KW_SEMIBLOCK_LENGTH )
        {
            return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
        }

        /*
         * According to SP 800-38F Table 1, the plaintext length for KW
         * must be between 2 to 2^54-1 semiblocks inclusive.
         */
        if( in_len < 16 ||
#if SIZE_MAX > 0x1FFFFFFFFFFFFF8
            in_len > 0x1FFFFFFFFFFFFF8 ||
#endif
            in_len % KW_SEMIBLOCK_LENGTH != 0 )
        {
            return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
        }

        memcpy( output, NIST_KW_ICV1, KW_SEMIBLOCK_LENGTH );
        memmove( output + KW_SEMIBLOCK_LENGTH, input, in_len );
    }
    else
    {
        if( in_len % 8 != 0 )
        {
            padlen = ( 8 - ( in_len % 8 ) );
        }

        if( out_size < in_len + KW_SEMIBLOCK_LENGTH + padlen )
        {
            return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
        }

        /*
         * According to SP 800-38F Table 1, the plaintext length for KWP
         * must be between 1 and 2^32-1 octets inclusive.
         */
        if( in_len < 1
#if SIZE_MAX > 0xFFFFFFFF
            || in_len > 0xFFFFFFFF
#endif
          )
        {
            return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
        }

        memcpy( output, NIST_KW_ICV2, KW_SEMIBLOCK_LENGTH / 2 );
        PUT_UINT32_BE( ( in_len & 0xffffffff ), output,
                       KW_SEMIBLOCK_LENGTH / 2 );

        memcpy( output + KW_SEMIBLOCK_LENGTH, input, in_len );
        memset( output + KW_SEMIBLOCK_LENGTH + in_len, 0, padlen );
    }
    semiblocks = ( ( in_len + padlen ) / KW_SEMIBLOCK_LENGTH ) + 1;

    s = 6 * ( semiblocks - 1 );

    if( mode == MBEDTLS_KW_MODE_KWP
        && in_len <= KW_SEMIBLOCK_LENGTH )
    {
        memcpy( inbuff, output, 16 );
        ret = mbedtls_cipher_update( &ctx->cipher_ctx,
                                     inbuff, 16, output, &olen );
        if( ret != 0 )
            goto cleanup;
    }
    else
    {
        /*
         * Do the wrapping function W, as defined in RFC 3394 section 2.2.1
         */
        if( semiblocks < MIN_SEMIBLOCKS_COUNT )
        {
            ret = MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
            goto cleanup;
        }

        /* Calculate intermediate values */
        for( t = 1; t <= s; t++ )
        {
            memcpy( inbuff, A, KW_SEMIBLOCK_LENGTH );
            memcpy( inbuff + KW_SEMIBLOCK_LENGTH, R2, KW_SEMIBLOCK_LENGTH );

            ret = mbedtls_cipher_update( &ctx->cipher_ctx,
                                         inbuff, 16, outbuff, &olen );
            if( ret != 0 )
                goto cleanup;

            memcpy( A, outbuff, KW_SEMIBLOCK_LENGTH );
            calc_a_xor_t( A, t );

            memcpy( R2, outbuff + KW_SEMIBLOCK_LENGTH, KW_SEMIBLOCK_LENGTH );
            R2 += KW_SEMIBLOCK_LENGTH;
            if( R2 >= output + ( semiblocks * KW_SEMIBLOCK_LENGTH ) )
                R2 = output + KW_SEMIBLOCK_LENGTH;
        }
    }

    *out_len = semiblocks * KW_SEMIBLOCK_LENGTH;

cleanup:

    if( ret != 0)
    {
        memset( output, 0, semiblocks * KW_SEMIBLOCK_LENGTH );
    }
    mbedtls_platform_zeroize( inbuff, KW_SEMIBLOCK_LENGTH * 2 );
    mbedtls_platform_zeroize( outbuff, KW_SEMIBLOCK_LENGTH * 2 );
    mbedtls_cipher_finish( &ctx->cipher_ctx, NULL, &olen );
    return( ret );
}

/*
 * W-1 function as defined in RFC 3394 section 2.2.2
 * This function assumes the following:
 * 1. Output buffer is at least of size ( semiblocks - 1 ) * KW_SEMIBLOCK_LENGTH.
 * 2. The input buffer is of size semiblocks * KW_SEMIBLOCK_LENGTH.
 * 3. Minimal number of semiblocks is 3.
 * 4. A is a buffer to hold the first semiblock of the input buffer.
 */
static int unwrap( mbedtls_nist_kw_context *ctx,
                   const unsigned char *input, size_t semiblocks,
                   unsigned char A[KW_SEMIBLOCK_LENGTH],
                   unsigned char *output, size_t* out_len )
{
    int ret = 0;
    const size_t s = 6 * ( semiblocks - 1 );
    size_t olen;
    uint64_t t = 0;
    unsigned char outbuff[KW_SEMIBLOCK_LENGTH * 2];
    unsigned char inbuff[KW_SEMIBLOCK_LENGTH * 2];
    unsigned char *R = output + ( semiblocks - 2 ) * KW_SEMIBLOCK_LENGTH;
    *out_len = 0;

    if( semiblocks < MIN_SEMIBLOCKS_COUNT )
    {
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    memcpy( A, input, KW_SEMIBLOCK_LENGTH );
    memmove( output, input + KW_SEMIBLOCK_LENGTH, ( semiblocks - 1 ) * KW_SEMIBLOCK_LENGTH );

    /* Calculate intermediate values */
    for( t = s; t >= 1; t-- )
    {
        calc_a_xor_t( A, t );

        memcpy( inbuff, A, KW_SEMIBLOCK_LENGTH );
        memcpy( inbuff + KW_SEMIBLOCK_LENGTH, R, KW_SEMIBLOCK_LENGTH );

        ret = mbedtls_cipher_update( &ctx->cipher_ctx,
                                     inbuff, 16, outbuff, &olen );
        if( ret != 0 )
            goto cleanup;

        memcpy( A, outbuff, KW_SEMIBLOCK_LENGTH );

        /* Set R as LSB64 of outbuff */
        memcpy( R, outbuff + KW_SEMIBLOCK_LENGTH, KW_SEMIBLOCK_LENGTH );

        if( R == output )
            R = output + ( semiblocks - 2 ) * KW_SEMIBLOCK_LENGTH;
        else
            R -= KW_SEMIBLOCK_LENGTH;
    }

    *out_len = ( semiblocks - 1 ) * KW_SEMIBLOCK_LENGTH;

cleanup:
    if( ret != 0)
        memset( output, 0, ( semiblocks - 1 ) * KW_SEMIBLOCK_LENGTH );
    mbedtls_platform_zeroize( inbuff, sizeof( inbuff )  );
    mbedtls_platform_zeroize( outbuff, sizeof( outbuff ) );

    return( ret );
}

/*
 * KW-AD as defined in SP 800-38F section 6.2
 * KWP-AD as defined in SP 800-38F section 6.3
 */
int mbedtls_nist_kw_unwrap( mbedtls_nist_kw_context *ctx,
                            mbedtls_nist_kw_mode_t mode,
                            const unsigned char *input, size_t in_len,
                            unsigned char *output, size_t *out_len, size_t out_size )
{
    int ret = 0;
    size_t i, olen;
    unsigned char A[KW_SEMIBLOCK_LENGTH];
    unsigned char diff, bad_padding = 0;

    *out_len = 0;
    if( out_size < in_len - KW_SEMIBLOCK_LENGTH )
    {
        return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
    }

    if( mode == MBEDTLS_KW_MODE_KW )
    {
        /*
         * According to SP 800-38F Table 1, the ciphertext length for KW
         * must be between 3 to 2^54 semiblocks inclusive.
         */
        if( in_len < 24 ||
#if SIZE_MAX > 0x200000000000000
            in_len > 0x200000000000000 ||
#endif
            in_len % KW_SEMIBLOCK_LENGTH != 0 )
        {
            return( MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
        }

        ret = unwrap( ctx, input, in_len / KW_SEMIBLOCK_LENGTH,
                      A, output, out_len );
        if( ret != 0 )
            goto cleanup;

        /* Check ICV in "constant-time" */
        diff = mbedtls_nist_kw_safer_memcmp( NIST_KW_ICV1, A, KW_SEMIBLOCK_LENGTH );

        if( diff != 0 )
        {
            ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
            goto cleanup;
        }

    }
    else if( mode == MBEDTLS_KW_MODE_KWP )
    {
        size_t padlen = 0;
        uint32_t Plen;
        /*
         * According to SP 800-38F Table 1, the ciphertext length for KWP
         * must be between 2 to 2^29 semiblocks inclusive.
         */
        if( in_len < KW_SEMIBLOCK_LENGTH * 2 ||
#if SIZE_MAX > 0x100000000
            in_len > 0x100000000 ||
#endif
            in_len % KW_SEMIBLOCK_LENGTH != 0 )
        {
            return(  MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA );
        }

        if( in_len == KW_SEMIBLOCK_LENGTH * 2 )
        {
            unsigned char outbuff[KW_SEMIBLOCK_LENGTH * 2];
            ret = mbedtls_cipher_update( &ctx->cipher_ctx,
                                         input, 16, outbuff, &olen );
            if( ret != 0 )
                goto cleanup;

            memcpy( A, outbuff, KW_SEMIBLOCK_LENGTH );
            memcpy( output, outbuff + KW_SEMIBLOCK_LENGTH, KW_SEMIBLOCK_LENGTH );
            mbedtls_platform_zeroize( outbuff, sizeof( outbuff ) );
            *out_len = KW_SEMIBLOCK_LENGTH;
        }
        else
        {
            /* in_len >=  KW_SEMIBLOCK_LENGTH * 3 */
            ret = unwrap( ctx, input, in_len / KW_SEMIBLOCK_LENGTH,
                          A, output, out_len );
            if( ret != 0 )
                goto cleanup;
        }

        /* Check ICV in "constant-time" */
        diff = mbedtls_nist_kw_safer_memcmp( NIST_KW_ICV2, A, KW_SEMIBLOCK_LENGTH / 2 );

        if( diff != 0 )
        {
            ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
        }

        GET_UINT32_BE( Plen, A, KW_SEMIBLOCK_LENGTH / 2 );

        /*
         * Plen is the length of the plaintext, when the input is valid.
         * If Plen is larger than the plaintext and padding, padlen will be
         * larger than 8, because of the type wrap around.
         */
        padlen = in_len - KW_SEMIBLOCK_LENGTH - Plen;
        if ( padlen > 7 )
        {
            padlen &= 7;
            ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
        }

        /* Check padding in "constant-time" */
        for( diff = 0, i = 0; i < KW_SEMIBLOCK_LENGTH; i++ )
        {
             if( i >= KW_SEMIBLOCK_LENGTH - padlen )
                 diff |= output[*out_len - KW_SEMIBLOCK_LENGTH + i];
             else
                 bad_padding |= output[*out_len - KW_SEMIBLOCK_LENGTH + i];
        }

        if( diff != 0 )
        {
            ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
        }

        if( ret != 0 )
        {
            goto cleanup;
        }
        memset( output + Plen, 0, padlen );
        *out_len = Plen;
    }
    else
    {
        ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        goto cleanup;
    }

cleanup:
    if( ret != 0 )
    {
        memset( output, 0, *out_len );
        *out_len = 0;
    }

    mbedtls_platform_zeroize( &bad_padding, sizeof( bad_padding) );
    mbedtls_platform_zeroize( &diff, sizeof( diff ) );
    mbedtls_platform_zeroize( A, sizeof( A ) );
    mbedtls_cipher_finish( &ctx->cipher_ctx, NULL, &olen );
    return( ret );
}

#endif /* !MBEDTLS_NIST_KW_ALT */

#endif /* MBEDTLS_NIST_KW_C */
