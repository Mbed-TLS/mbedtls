/*
 *  NIST SP800-38B compliant CMAC implementation
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

/*
 * Definition of CMAC:
 * http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
 * RFC 4493 "The AES-CMAC Algorithm"
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CMAC_C)

#include "mbedtls/cmac.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/*
 * Initialize context
 */
void mbedtls_cmac_init( mbedtls_cmac_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_cmac_context ) );
}

/*
 * Multiply by u in GF(2^128)
 *
 * As explained in the paper, this can be achieved as
 * If MSB(p) = 0, then p = (p << 1)
 * If MSB(p) = 1, then p = (p << 1) ^ Rb
 * with Rb = 0x87
 *
 * Input and output MUST not point to the same buffer
 */
static void cmac_multiply_by_u( unsigned char *output,
                                const unsigned char *input )
{
    const unsigned char Rb = 0x87; /* block size 16 only */
    unsigned char mask;
    unsigned char overflow = 0;
    int i;

    for( i = 15; i >= 0; i-- )
    {
        output[i] = input[i] << 1 | overflow;
        overflow = input[i] >> 7;
    }

    /* mask = ( input[0] >> 7 ) ? 0xff : 0x00
     * using bit operations to avoid branches */
    /* MSVC has a warning about unary minus on unsigned, but this is
     * well-defined and precisely what we want to do here */
#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning( disable : 4146 )
#endif
    mask = - ( input[0] >> 7 );
#if defined(_MSC_VER)
#pragma warning( pop )
#endif

    output[15] ^= Rb & mask;
}

/*
 * Generate subkeys
 */
static int cmac_generate_subkeys( mbedtls_cmac_context *ctx )
{
    int ret;
    unsigned char L[16];
    size_t olen;

    /* Calculate Ek(0) */
    memset( L, 0, 16 );
    if( ( ret = mbedtls_cipher_update( &ctx->cipher_ctx,
                                       L, 16, L, &olen ) ) != 0 )
    {
        return( ret );
    }

    /*
     * Generate K1 and K2
     */
    cmac_multiply_by_u( ctx->K1, L );
    cmac_multiply_by_u( ctx->K2, ctx->K1 );

    mbedtls_zeroize( L, sizeof( L ) );

    return( 0 );
}

/*
 * Set key and prepare context for use
 */
int mbedtls_cmac_setkey( mbedtls_cmac_context *ctx,
                         mbedtls_cipher_id_t cipher,
                         const unsigned char *key,
                         unsigned int keybits )
{
    int ret;
    const mbedtls_cipher_info_t *cipher_info;

    cipher_info = mbedtls_cipher_info_from_values( cipher, keybits,
                                                   MBEDTLS_MODE_ECB );
    if( cipher_info == NULL )
        return( MBEDTLS_ERR_CMAC_BAD_INPUT );

    if( cipher_info->block_size != 16 )
        return( MBEDTLS_ERR_CMAC_BAD_INPUT );

    mbedtls_cipher_free( &ctx->cipher_ctx );

    if( ( ret = mbedtls_cipher_setup( &ctx->cipher_ctx, cipher_info ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_cipher_setkey( &ctx->cipher_ctx, key, keybits,
                                       MBEDTLS_ENCRYPT ) ) != 0 )
    {
        return( ret );
    }

    return( cmac_generate_subkeys( ctx ) );
}

/*
 * Free context
 */
void mbedtls_cmac_free( mbedtls_cmac_context *ctx )
{
    mbedtls_cipher_free( &ctx->cipher_ctx );
    mbedtls_zeroize( ctx, sizeof( mbedtls_cmac_context ) );
}

/*
 * Create padded last block from (partial) last block.
 *
 * We can't use the padding option from the cipher layer, as it only works for
 * CBC and we use ECB mode, and anyway we need to XOR K1 or K2 in addition.
 */
static void cmac_pad( unsigned char padded_block[16],
                      const unsigned char *last_block,
                      size_t length )
{
    size_t j;

    for( j = 0; j < 16; j++ )
    {
        if( j < length )
            padded_block[j] = last_block[j];
        else if( j == length )
            padded_block[j] = 0x80;
        else
            padded_block[j] = 0x00;
    }
}

/*
 * XOR 128-bit
 * Here, macro results in smaller compiled code than static inline function
 */
#define XOR_128( o, i1, i2 )                                                \
    for( i = 0; i < 16; i++ )                                               \
        ( o )[i] = ( i1 )[i] ^ ( i2 )[i];

/*
 * Update the CMAC state using an input block x
 */
#define UPDATE_CMAC( x )                                                    \
do {                                                                        \
    XOR_128( state, ( x ), state );                                         \
    if( ( ret = mbedtls_cipher_update( &ctx->cipher_ctx,                    \
                                       state, 16, state, &olen ) ) != 0 )   \
        return( ret );                                                      \
} while( 0 )

/*
 * Generate tag on complete message
 */
int mbedtls_cmac_generate( mbedtls_cmac_context *ctx,
                           const unsigned char *input, size_t in_len,
                           unsigned char *tag, size_t tag_len )

{
    unsigned char state[16];
    unsigned char M_last[16];
    int     n, i, j, ret, needs_padding;
    size_t olen;

    /*
     * Check in_len requirements: SP800-38B A
     * 4 is a worst case bottom limit
     */
    if( tag_len < 4 || tag_len > 16 || tag_len % 2 != 0 )
        return( MBEDTLS_ERR_CMAC_BAD_INPUT );

    if( in_len == 0 )
        needs_padding = 1;
    else
        needs_padding = in_len % 16 != 0;

    n = in_len / 16 + needs_padding;

    /* Calculate last block */
    if( needs_padding )
    {
        cmac_pad( M_last, input + 16 * ( n - 1 ), in_len % 16 );
        XOR_128( M_last, M_last, ctx->K2 );
    }
    else
    {
        /* Last block is complete block */
        XOR_128( M_last, input + 16 * ( n - 1 ), ctx->K1 );
    }

    memset( state, 0, 16 );

    for( j = 0; j < n - 1; j++ )
        UPDATE_CMAC( input + 16 * j );

    UPDATE_CMAC( M_last );

    memcpy( tag, state, 16 );

    return( 0 );
}

#undef XOR_128
#undef UPDATE_CMAC

/*
 * Verify tag on complete message
 */
int mbedtls_cmac_verify( mbedtls_cmac_context *ctx,
                         const unsigned char *input, size_t in_len,
                         const unsigned char *tag, size_t tag_len )
{
    int ret;
    unsigned char check_tag[16];
    unsigned char i;
    int diff;

    if( ( ret = mbedtls_cmac_generate( ctx, input, in_len,
                                       check_tag, tag_len ) ) != 0 )
    {
        return ret;
    }

    /* Check tag in "constant-time" */
    for( diff = 0, i = 0; i < tag_len; i++ )
        diff |= tag[i] ^ check_tag[i];

    if( diff != 0 )
        return( MBEDTLS_ERR_CMAC_VERIFY_FAILED );

    return( 0 );
}

/*
 * PRF based on CMAC with AES-128
 * TODO: add reference to the standard
 * TODO: do we need to take a cmac_context as an argument here?
 */
int mbedtls_aes_cmac_prf_128( mbedtls_cmac_context *ctx,
                              const unsigned char *key, size_t key_length,
                              const unsigned char *input, size_t in_len,
                              unsigned char *tag )
{
    int ret;
    unsigned char zero_key[16];
    unsigned char int_key[16];

    if( key_length == 16 )
    {
        /* Use key as is */
        memcpy( int_key, key, 16 );
    }
    else
    {
        mbedtls_cmac_context zero_ctx;

        /* Key is AES_CMAC(0, key) */
        mbedtls_cmac_init( &zero_ctx );
        memset( zero_key, 0, 16 );
        ret = mbedtls_cmac_setkey( &zero_ctx, MBEDTLS_CIPHER_ID_AES,
                                   zero_key, 8 * sizeof zero_key );
        if( ret != 0 )
            return( ret );

        ret = mbedtls_cmac_generate( &zero_ctx, key, key_length, int_key, 16 );
        if( ret != 0 )
            return( ret );
    }

    ret = mbedtls_cmac_setkey( ctx, MBEDTLS_CIPHER_ID_AES,
                               int_key, 8 * sizeof int_key );
    if( ret != 0 )
        return( ret );

    mbedtls_zeroize( int_key, sizeof( int_key ) );

    return( mbedtls_cmac_generate( ctx, input, in_len, tag, 16 ) );
}

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
/*
 * Examples 1 to 4 from SP800-38B corrected Appendix D.1
 * http://csrc.nist.gov/publications/nistpubs/800-38B/Updated_CMAC_Examples.pdf
 */

#define NB_CMAC_TESTS 4
#define NB_PRF_TESTS 3

/* Key */
static const unsigned char key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

/* Assume we don't need to test Ek0 as this is a function of the cipher */

/* Subkey K1 */
static const unsigned char K1[] = {
    0xfb, 0xee, 0xd6, 0x18, 0x35, 0x71, 0x33, 0x66,
    0x7c, 0x85, 0xe0, 0x8f, 0x72, 0x36, 0xa8, 0xde
};

/* Subkey K2 */
static const unsigned char K2[] = {
    0xf7, 0xdd, 0xac, 0x30, 0x6a, 0xe2, 0x66, 0xcc,
    0xf9, 0x0b, 0xc1, 0x1e, 0xe4, 0x6d, 0x51, 0x3b
};

/* All Messages */
static const unsigned char M[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

static const unsigned char T[NB_CMAC_TESTS][16] = {
    {
        0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
        0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46
    },
    {
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
        0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
    },
    {
        0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
        0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27
    },
    {
        0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
        0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe
    }
};

/* Sizes in bytes */
static const size_t Mlen[NB_CMAC_TESTS] = {
    0,
    16,
    40,
    64
};

/* PRF K */
static const unsigned char PRFK[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0xed, 0xcb
};

/* Sizes in bytes */
static const size_t PRFKlen[NB_PRF_TESTS] = {
    18,
    16,
    10
};

/* PRF M */
static const unsigned char PRFM[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13
};

static const unsigned char PRFT[NB_PRF_TESTS][16] = {
    {
        0x84, 0xa3, 0x48, 0xa4, 0xa4, 0x5d, 0x23, 0x5b,
        0xab, 0xff, 0xfc, 0x0d, 0x2b, 0x4d, 0xa0, 0x9a
    },
    {
        0x98, 0x0a, 0xe8, 0x7b, 0x5f, 0x4c, 0x9c, 0x52,
        0x14, 0xf5, 0xb6, 0xa8, 0x45, 0x5e, 0x4c, 0x2d
    },
    {
        0x29, 0x0d, 0x9e, 0x11, 0x2e, 0xdb, 0x09, 0xee,
        0x14, 0x1f, 0xcf, 0x64, 0xc0, 0xb7, 0x2f, 0x3d
    }
};


int mbedtls_cmac_self_test( int verbose )
{
    mbedtls_cmac_context ctx;
    unsigned char tag[16];
    int i;
    int ret;

    mbedtls_cmac_init( &ctx );

    if( mbedtls_cmac_setkey( &ctx, MBEDTLS_CIPHER_ID_AES, key, 8 * sizeof key ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "  CMAC: setup failed\n" );

        return( 1 );
    }

    if( ( memcmp( ctx.K1, K1, 16 ) != 0 ) ||
        ( memcmp( ctx.K2, K2, 16 ) != 0 ) )
    {
        if( verbose != 0 )
            mbedtls_printf( "  CMAC: subkey generation failed\n" );

        return( 1 );
    }

    for( i = 0; i < NB_CMAC_TESTS; i++ )
    {
        mbedtls_printf( "  AES-128-CMAC #%u: ", i );

        ret = mbedtls_cmac_generate( &ctx, M, Mlen[i], tag, 16 );
        if( ret != 0 ||
            memcmp( tag, T[i], 16 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            return( 1 );
        }

        ret = mbedtls_cmac_verify( &ctx, M, Mlen[i], T[i], 16 );
        if( ret != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            return( 1 );
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    for( i = 0; i < NB_PRF_TESTS; i++ )
    {
        mbedtls_printf( "  AES-CMAC-128-PRF #%u: ", i );

        mbedtls_aes_cmac_prf_128( &ctx, PRFK, PRFKlen[i], PRFM, 20, tag );

        if( ret != 0 ||
            memcmp( tag, PRFT[i], 16 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            return( 1 );
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    mbedtls_cmac_free( &ctx );

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( 0 );
}

#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

#endif /* MBEDTLS_CMAC_C */
