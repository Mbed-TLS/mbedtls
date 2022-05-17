/*
 *  FIPS-202 compliant SHA3 implementation
 *
 *  Copyright The Mbed TLS Contributors
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
 */
/*
 *  The SHA-3 Secure Hash Standard was published by NIST in 2015.
 *
 *  https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf
 */

#include "common.h"

#if defined(MBEDTLS_SHA3_C)

#include "mbedtls/sha3.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf printf
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

/*
 * List of supported SHA-3 families
 */
static mbedtls_sha3_family_functions sha3_families[] = {
    { MBEDTLS_SHA3_224,      1152, 224, 0x06 },
    { MBEDTLS_SHA3_256,      1088, 256, 0x06 },
    { MBEDTLS_SHA3_384,       832, 384, 0x06 },
    { MBEDTLS_SHA3_512,       576, 512, 0x06 },
    { MBEDTLS_SHA3_NONE, 0, 0, 0 }
};

static const uint64_t rc[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

static const uint8_t rho[24] = {
    1, 62, 28, 27, 36, 44,  6, 55, 20,
    3, 10, 43, 25, 39, 41, 45, 15,
    21,  8, 18,  2, 61, 56, 14
};

static const uint8_t pi[24] = {
    10,  7, 11, 17, 18, 3,  5, 16,  8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22,  9,  6, 1,
};

#define ROT64( x , y ) ( ( ( x ) << ( y ) ) | ( ( x ) >> ( 64U - ( y ) ) ) )
#define ABSORB( ctx, idx, v ) do { ctx->state[( idx ) >> 3] ^= ( ( uint64_t ) ( v ) ) << ( ( ( idx ) & 0x7 ) << 3 ); } while( 0 )
#define SQUEEZE( ctx, idx ) ( ( uint8_t )( ctx->state[( idx ) >> 3] >> ( ( ( idx ) & 0x7 ) << 3 ) ) )
#define SWAP( x, y ) do { uint64_t tmp = ( x ); ( x ) = ( y ); ( y ) = tmp; } while( 0 )

/* The permutation function.  */
static void keccak_f1600(mbedtls_sha3_context *ctx)
{
    uint64_t lane[5];
    uint64_t *s = ctx->state;
    int i;

    for( int round = 0; round < 24; round++ )
    {
        uint64_t t;

        /* Theta */
        lane[0] = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20];
        lane[1] = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21];
        lane[2] = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22];
        lane[3] = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23];
        lane[4] = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];

        t = lane[4] ^ ROT64( lane[1], 1 );
        s[0] ^= t; s[5] ^= t; s[10] ^= t; s[15] ^= t; s[20] ^= t;

        t = lane[0] ^ ROT64( lane[2], 1 );
        s[1] ^= t; s[6] ^= t; s[11] ^= t; s[16] ^= t; s[21] ^= t;

        t = lane[1] ^ ROT64( lane[3], 1 );
        s[2] ^= t; s[7] ^= t; s[12] ^= t; s[17] ^= t; s[22] ^= t;

        t = lane[2] ^ ROT64( lane[4], 1 );
        s[3] ^= t; s[8] ^= t; s[13] ^= t; s[18] ^= t; s[23] ^= t;

        t = lane[3] ^ ROT64( lane[0], 1 );
        s[4] ^= t; s[9] ^= t; s[14] ^= t; s[19] ^= t; s[24] ^= t;

        /* Rho */
        for( i = 1; i < 25; i++ )
            s[i] = ROT64( s[i], rho[i-1] );

        /* Pi */
        t = s[1];
        for( i = 0; i < 24; i++ )
            SWAP( s[pi[i]], t );

        /* Chi */
        lane[0] = s[0]; lane[1] = s[1]; lane[2] = s[2]; lane[3] = s[3]; lane[4] = s[4];
        s[0] ^= (~lane[1]) & lane[2];
        s[1] ^= (~lane[2]) & lane[3];
        s[2] ^= (~lane[3]) & lane[4];
        s[3] ^= (~lane[4]) & lane[0];
        s[4] ^= (~lane[0]) & lane[1];

        lane[0] = s[5]; lane[1] = s[6]; lane[2] = s[7]; lane[3] = s[8]; lane[4] = s[9];
        s[5] ^= (~lane[1]) & lane[2];
        s[6] ^= (~lane[2]) & lane[3];
        s[7] ^= (~lane[3]) & lane[4];
        s[8] ^= (~lane[4]) & lane[0];
        s[9] ^= (~lane[0]) & lane[1];

        lane[0] = s[10]; lane[1] = s[11]; lane[2] = s[12]; lane[3] = s[13]; lane[4] = s[14];
        s[10] ^= (~lane[1]) & lane[2];
        s[11] ^= (~lane[2]) & lane[3];
        s[12] ^= (~lane[3]) & lane[4];
        s[13] ^= (~lane[4]) & lane[0];
        s[14] ^= (~lane[0]) & lane[1];

        lane[0] = s[15]; lane[1] = s[16]; lane[2] = s[17]; lane[3] = s[18]; lane[4] = s[19];
        s[15] ^= (~lane[1]) & lane[2];
        s[16] ^= (~lane[2]) & lane[3];
        s[17] ^= (~lane[3]) & lane[4];
        s[18] ^= (~lane[4]) & lane[0];
        s[19] ^= (~lane[0]) & lane[1];

        lane[0] = s[20]; lane[1] = s[21]; lane[2] = s[22]; lane[3] = s[23]; lane[4] = s[24];
        s[20] ^= (~lane[1]) & lane[2];
        s[21] ^= (~lane[2]) & lane[3];
        s[22] ^= (~lane[3]) & lane[4];
        s[23] ^= (~lane[4]) & lane[0];
        s[24] ^= (~lane[0]) & lane[1];

        /* Iota */
        s[0] ^= rc[round];
    }
}

void mbedtls_sha3_init( mbedtls_sha3_context *ctx )
{
    if( ctx == NULL )
        return;

    memset( ctx, 0, sizeof( mbedtls_sha3_context ) );
}

void mbedtls_sha3_free( mbedtls_sha3_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_sha3_context ) );
}

void mbedtls_sha3_clone( mbedtls_sha3_context *dst,
                                    const mbedtls_sha3_context *src )
{
    if ( dst == NULL || src == NULL )
        return;

    *dst = *src;
}

/*
 * SHA-3 context setup
 */
int mbedtls_sha3_starts( mbedtls_sha3_context *ctx, mbedtls_sha3_id id )
{
    mbedtls_sha3_family_functions *p = NULL;
    if( ctx == NULL )
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );

    for( p = sha3_families; p->id != MBEDTLS_SHA3_NONE; p++ )
    {
        if( p->id == id )
            break;
    }

    if( p == NULL || p->id == MBEDTLS_SHA3_NONE )
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );

    ctx->id = id;
    ctx->r = p->r;
    ctx->olen = p->olen / 8;
    ctx->xor_byte = p->xor_byte;
    ctx->max_block_size = ctx->r / 8;

    return( 0 );
}

/*
 * SHA-3 process buffer
 */
int mbedtls_sha3_update( mbedtls_sha3_context *ctx,
                                   const uint8_t *input,
                                   size_t ilen )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );

    if( ilen == 0 || input == NULL )
        return( 0 );

    while( ilen-- > 0 )
    {
        ABSORB( ctx, ctx->index, *input++ );
        if( ( ctx->index = ( ctx->index + 1) % ctx->max_block_size ) == 0 )
            keccak_f1600( ctx );
    }

    return( 0 );
}

int mbedtls_sha3_finish( mbedtls_sha3_context *ctx,
                              uint8_t *output, size_t olen )
{
    if( ctx == NULL || output == NULL )
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );

    /* Catch SHA-3 families, with fixed output length */
    if( ctx->olen > 0 )
    {
        if ( ctx->olen > olen )
            return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
        olen = ctx->olen;
    }

    ABSORB( ctx, ctx->index, ctx->xor_byte );
    ABSORB( ctx, ctx->max_block_size - 1, 0x80 );
    keccak_f1600( ctx );
    ctx->index = 0;

    while( olen-- > 0 )
    {
        *output++ = SQUEEZE( ctx, ctx->index );

        if( ( ctx->index = ( ctx->index + 1) % ctx->max_block_size ) == 0 )
            keccak_f1600( ctx );
    }

    return( 0 );
}

/*
 * output = SHA3( input buffer )
 */
int mbedtls_sha3( mbedtls_sha3_id id, const uint8_t *input,
                                size_t ilen, uint8_t *output, size_t olen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_sha3_context ctx;

    mbedtls_sha3_init( &ctx );

    /* Sanity checks are performed in every mbedtls_sha3_xxx() */
    if( ( ret = mbedtls_sha3_starts( &ctx, id ) ) != 0 )
        goto exit;

    if( ( ret = mbedtls_sha3_update( &ctx, input, ilen ) ) != 0 )
        goto exit;

    if( ( ret = mbedtls_sha3_finish( &ctx, output, olen ) ) != 0 )
        goto exit;

exit:
    mbedtls_sha3_free( &ctx );

    return( ret );
}

#endif /* MBEDTLS_SHA3_C */
