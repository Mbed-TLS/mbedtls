/**
 * \file sha3.c
 *
 * \brief SHA-3 cryptographic hash functions
 *        (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
 *
 * \author Daniel King <damaki.gh@gmail.com>
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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

#if defined(MBEDTLS_SHA3_C)

#include "mbedtls/sha3.h"

#include <stddef.h>
#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#include "mbedtls/platform_util.h"

#if !defined(MBEDTLS_SHA3_ALT)



/**************** Keccak-f[1600] permutation ****************/

#define KECCAKF_STATE_SIZE_BITS  ( 1600 )
#define KECCAKF_STATE_SIZE_BYTES ( 1600 / 8 )

#define ROTL64( x, amount ) \
    ( (uint64_t) ( x ) << ( amount ) | (uint64_t) ( x ) >> ( 64 - ( amount ) ) )

static const uint64_t round_constants[24] =
{
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808AULL,
    0x8000000080008000ULL,
    0x000000000000808BULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008AULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000AULL,
    0x000000008000808BULL,
    0x800000000000008BULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800AULL,
    0x800000008000000AULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL
};

/**
 * \brief               Keccak Theta round operation.
 *
 *                      This function implements the algorithm specified in
 *                      Section 3.2.1 of NIST FIPS PUB 202.
 *
 * \param in_state      The Keccak state to transform.
 * \param out_state     The transformed state is written here.
 */
static void mbedtls_keccakf_theta( uint64_t in_state[5][5],
                                   uint64_t out_state[5][5] )
{
    uint64_t cl;
    uint64_t cr;
    uint64_t d;

    cl = ( in_state[4][0] ^ in_state[4][1] ^ in_state[4][2] ^
           in_state[4][3] ^ in_state[4][4] );
    cr = ( in_state[1][0] ^ in_state[1][1] ^ in_state[1][2] ^
           in_state[1][3] ^ in_state[1][4] );
    d = cl ^ ROTL64( cr, 1 );
    out_state[0][0] = in_state[0][0] ^ d;
    out_state[0][1] = in_state[0][1] ^ d;
    out_state[0][2] = in_state[0][2] ^ d;
    out_state[0][3] = in_state[0][3] ^ d;
    out_state[0][4] = in_state[0][4] ^ d;

    cl = ( in_state[0][0] ^ in_state[0][1] ^ in_state[0][2] ^
           in_state[0][3] ^ in_state[0][4] );
    cr = ( in_state[2][0] ^ in_state[2][1] ^ in_state[2][2] ^
           in_state[2][3] ^ in_state[2][4] );
    d = cl ^ ROTL64( cr, 1 );
    out_state[1][0] = in_state[1][0] ^ d;
    out_state[1][1] = in_state[1][1] ^ d;
    out_state[1][2] = in_state[1][2] ^ d;
    out_state[1][3] = in_state[1][3] ^ d;
    out_state[1][4] = in_state[1][4] ^ d;

    cl = ( in_state[1][0] ^ in_state[1][1] ^ in_state[1][2] ^
           in_state[1][3] ^ in_state[1][4] );
    cr = ( in_state[3][0] ^ in_state[3][1] ^ in_state[3][2] ^
           in_state[3][3] ^ in_state[3][4] );
    d = cl ^ ROTL64( cr, 1 );
    out_state[2][0] = in_state[2][0] ^ d;
    out_state[2][1] = in_state[2][1] ^ d;
    out_state[2][2] = in_state[2][2] ^ d;
    out_state[2][3] = in_state[2][3] ^ d;
    out_state[2][4] = in_state[2][4] ^ d;

    cl = ( in_state[2][0] ^ in_state[2][1] ^ in_state[2][2] ^
           in_state[2][3] ^ in_state[2][4] );
    cr = ( in_state[4][0] ^ in_state[4][1] ^ in_state[4][2] ^
           in_state[4][3] ^ in_state[4][4] );
    d = cl ^ ROTL64( cr, 1 );
    out_state[3][0] = in_state[3][0] ^ d;
    out_state[3][1] = in_state[3][1] ^ d;
    out_state[3][2] = in_state[3][2] ^ d;
    out_state[3][3] = in_state[3][3] ^ d;
    out_state[3][4] = in_state[3][4] ^ d;

    cl = ( in_state[3][0] ^ in_state[3][1] ^ in_state[3][2] ^
           in_state[3][3] ^ in_state[3][4] );
    cr = ( in_state[0][0] ^ in_state[0][1] ^ in_state[0][2] ^
           in_state[0][3] ^ in_state[0][4] );
    d = cl ^ ROTL64( cr, 1 );
    out_state[4][0] = in_state[4][0] ^ d;
    out_state[4][1] = in_state[4][1] ^ d;
    out_state[4][2] = in_state[4][2] ^ d;
    out_state[4][3] = in_state[4][3] ^ d;
    out_state[4][4] = in_state[4][4] ^ d;
}

/**
 * \brief               Keccak Rho round operation.
 *
 *                      This function implements the algorithm specified in
 *                      Section 3.2.2 of NIST FIPS PUB 202.
 *
 * \param in_state      The Keccak state to transform.
 * \param out_state     The transformed state is written here.
 */
static void mbedtls_keccakf_rho( uint64_t in_state[5][5],
                                 uint64_t out_state[5][5] )
{
    out_state[0][0] =         in_state[0][0];
    out_state[0][1] = ROTL64( in_state[0][1], 36 );
    out_state[0][2] = ROTL64( in_state[0][2], 3  );
    out_state[0][3] = ROTL64( in_state[0][3], 41 );
    out_state[0][4] = ROTL64( in_state[0][4], 18 );

    out_state[1][0] = ROTL64( in_state[1][0], 1  );
    out_state[1][1] = ROTL64( in_state[1][1], 44 );
    out_state[1][2] = ROTL64( in_state[1][2], 10 );
    out_state[1][3] = ROTL64( in_state[1][3], 45 );
    out_state[1][4] = ROTL64( in_state[1][4], 2  );

    out_state[2][0] = ROTL64( in_state[2][0], 62 );
    out_state[2][1] = ROTL64( in_state[2][1], 6  );
    out_state[2][2] = ROTL64( in_state[2][2], 43 );
    out_state[2][3] = ROTL64( in_state[2][3], 15 );
    out_state[2][4] = ROTL64( in_state[2][4], 61 );

    out_state[3][0] = ROTL64( in_state[3][0], 28 );
    out_state[3][1] = ROTL64( in_state[3][1], 55 );
    out_state[3][2] = ROTL64( in_state[3][2], 25 );
    out_state[3][3] = ROTL64( in_state[3][3], 21 );
    out_state[3][4] = ROTL64( in_state[3][4], 56 );

    out_state[4][0] = ROTL64( in_state[4][0], 27 );
    out_state[4][1] = ROTL64( in_state[4][1], 20 );
    out_state[4][2] = ROTL64( in_state[4][2], 39 );
    out_state[4][3] = ROTL64( in_state[4][3], 8  );
    out_state[4][4] = ROTL64( in_state[4][4], 14 );
}

/**
 * \brief               Keccak Pi round operation.
 *
 *                      This function implements the algorithm specified in
 *                      Section 3.2.3 of NIST FIPS PUB 202.
 *
 * \param in_state      The Keccak state to transform.
 * \param out_state     The transformed state is written here.
 */
static void mbedtls_keccakf_pi( uint64_t in_state[5][5],
                                uint64_t out_state[5][5] )
{
    out_state[0][0] = in_state[0][0];
    out_state[0][1] = in_state[3][0];
    out_state[0][2] = in_state[1][0];
    out_state[0][3] = in_state[4][0];
    out_state[0][4] = in_state[2][0];

    out_state[1][0] = in_state[1][1];
    out_state[1][1] = in_state[4][1];
    out_state[1][2] = in_state[2][1];
    out_state[1][3] = in_state[0][1];
    out_state[1][4] = in_state[3][1];

    out_state[2][0] = in_state[2][2];
    out_state[2][1] = in_state[0][2];
    out_state[2][2] = in_state[3][2];
    out_state[2][3] = in_state[1][2];
    out_state[2][4] = in_state[4][2];

    out_state[3][0] = in_state[3][3];
    out_state[3][1] = in_state[1][3];
    out_state[3][2] = in_state[4][3];
    out_state[3][3] = in_state[2][3];
    out_state[3][4] = in_state[0][3];

    out_state[4][0] = in_state[4][4];
    out_state[4][1] = in_state[2][4];
    out_state[4][2] = in_state[0][4];
    out_state[4][3] = in_state[3][4];
    out_state[4][4] = in_state[1][4];
}

/**
 * \brief               Keccak Chi and Iota round operations.
 *
 *                      This function implements the algorithm specified in
 *                      Sections 3.2.4 and 3.2.5 of NIST FIPS PUB 202.
 *
 *                      The Iota operation is merged into the Chi operation
 *                      to reduce unnecessary overhead.
 *
 * \param in_state      The Keccak state to transform.
 * \param out_state     The transformed state is written here.
 * \param round_index   The index of the current round in the interval [0,23].
 */
static void mbedtls_keccakf_chi_iota( uint64_t in_state[5][5],
                                      uint64_t out_state[5][5],
                                      size_t round_index )
{
    /* iota step */
    out_state[0][0] = in_state[0][0] ^ ( ~in_state[1][0] & in_state[2][0] )
                                     ^ round_constants[round_index];

    /* chi step */
    out_state[0][1] = in_state[0][1] ^ ( ~in_state[1][1] & in_state[2][1] );
    out_state[0][2] = in_state[0][2] ^ ( ~in_state[1][2] & in_state[2][2] );
    out_state[0][3] = in_state[0][3] ^ ( ~in_state[1][3] & in_state[2][3] );
    out_state[0][4] = in_state[0][4] ^ ( ~in_state[1][4] & in_state[2][4] );

    out_state[2][0] = in_state[2][0] ^ ( ~in_state[3][0] & in_state[4][0] );
    out_state[2][1] = in_state[2][1] ^ ( ~in_state[3][1] & in_state[4][1] );
    out_state[2][2] = in_state[2][2] ^ ( ~in_state[3][2] & in_state[4][2] );
    out_state[2][3] = in_state[2][3] ^ ( ~in_state[3][3] & in_state[4][3] );
    out_state[2][4] = in_state[2][4] ^ ( ~in_state[3][4] & in_state[4][4] );

    out_state[4][0] = in_state[4][0] ^ ( ~in_state[0][0] & in_state[1][0] );
    out_state[4][1] = in_state[4][1] ^ ( ~in_state[0][1] & in_state[1][1] );
    out_state[4][2] = in_state[4][2] ^ ( ~in_state[0][2] & in_state[1][2] );
    out_state[4][3] = in_state[4][3] ^ ( ~in_state[0][3] & in_state[1][3] );
    out_state[4][4] = in_state[4][4] ^ ( ~in_state[0][4] & in_state[1][4] );

    out_state[1][0] = in_state[1][0] ^ ( ~in_state[2][0] & in_state[3][0] );
    out_state[1][1] = in_state[1][1] ^ ( ~in_state[2][1] & in_state[3][1] );
    out_state[1][2] = in_state[1][2] ^ ( ~in_state[2][2] & in_state[3][2] );
    out_state[1][3] = in_state[1][3] ^ ( ~in_state[2][3] & in_state[3][3] );
    out_state[1][4] = in_state[1][4] ^ ( ~in_state[2][4] & in_state[3][4] );

    out_state[3][0] = in_state[3][0] ^ ( ~in_state[4][0] & in_state[0][0] );
    out_state[3][1] = in_state[3][1] ^ ( ~in_state[4][1] & in_state[0][1] );
    out_state[3][2] = in_state[3][2] ^ ( ~in_state[4][2] & in_state[0][2] );
    out_state[3][3] = in_state[3][3] ^ ( ~in_state[4][3] & in_state[0][3] );
    out_state[3][4] = in_state[3][4] ^ ( ~in_state[4][4] & in_state[0][4] );
}

/**
 * \brief               Initialize a Keccak-f[1600] context.
 *
 *                      This function should always be called first.
 *                      It prepares the context for other
 *                      mbedtls_keccakf_xxx functions.
 *
 * \param ctx           The Keccak-f[1600] context to initialize.
 */
static void mbedtls_keccakf_init( mbedtls_keccakf_context *ctx )
{
    memset( &ctx->state, 0, sizeof( ctx->state ) );
    memset( &ctx->temp, 0, sizeof( ctx->temp ) );
}

/**
 * \brief               Free and clear the internal structures of \p ctx.
 *
 *                      This function can be called at any time after
 *                      mbedtls_keccakf_init().
 *
 * \param ctx           The Keccak-f[1600] context to clear.
 */
static void mbedtls_keccakf_free( mbedtls_keccakf_context *ctx )
{
    if( ctx != NULL )
    {
        mbedtls_platform_zeroize( &ctx->state, sizeof( ctx->state ) );
        mbedtls_platform_zeroize( &ctx->temp, sizeof( ctx->temp ) );
    }
}

/**
 * \brief               Apply the Keccak permutation.
 *
 *                      This function implements the algorithm specified in
 *                      Section 3.3 of NIST FIPS PUB 202.
 *
 * \param ctx           The Keccak-f[1600] context to permute.
 */
static void mbedtls_keccakf_permute( mbedtls_keccakf_context *ctx )
{
    size_t i;
    for( i = 0; i < 24; i++ )
    {
        mbedtls_keccakf_theta   ( ctx->state, ctx->temp );
        mbedtls_keccakf_rho     ( ctx->temp , ctx->state );
        mbedtls_keccakf_pi      ( ctx->state, ctx->temp );
        mbedtls_keccakf_chi_iota( ctx->temp , ctx->state, i );
    }
}

/**
 * \brief               XOR binary bits into the Keccak state.
 *
 *                      The bytes are XORed starting from the beginning of the
 *                      Keccak state.
 *
 * \param ctx           The Keccak-f[1600] context.
 * \param data          Buffer containing the bytes to XOR into the Keccak state.
 * \param size_bits     The number of bits to XOR into the state.
 *
 * \pre size <= KECCAKF_STATE_SIZE_BITS
 */
static void mbedtls_keccakf_xor_binary( mbedtls_keccakf_context *ctx,
                                        const unsigned char *data,
                                        unsigned size_bits )
{
    unsigned char x = 0;
    unsigned char y = 0;
    unsigned remaining_bits = size_bits;
    unsigned data_offset = 0;

    /* process whole lanes */
    while( remaining_bits >= 64 )
    {
        ctx->state[x][y] ^= ( (uint64_t) data[data_offset] |
                              (uint64_t) data[data_offset + 1] << 8  |
                              (uint64_t) data[data_offset + 2] << 16 |
                              (uint64_t) data[data_offset + 3] << 24 |
                              (uint64_t) data[data_offset + 4] << 32 |
                              (uint64_t) data[data_offset + 5] << 40 |
                              (uint64_t) data[data_offset + 6] << 48 |
                              (uint64_t) data[data_offset + 7] << 56 );

        x = ( x + 1 ) % 5;
        if( x == 0 )
        {
            y = y + 1;
        }

        data_offset    += 8;
        remaining_bits -= 64;
    }

    /* process last (partial) lane */
    if( remaining_bits > 0 )
    {
        uint64_t lane = ctx->state[x][y];
        unsigned char shift = 0;

        /* whole bytes */
        while( remaining_bits >= 8 )
        {
            lane ^= (uint64_t) data[data_offset] << shift;

            data_offset++;
            shift          += 8;
            remaining_bits -= 8;
        }

        /* final bits */
        if( remaining_bits > 0 )
        {
            /* mask away higher bits to avoid accidentally XORIng them */
            unsigned char mask = ( 1 << remaining_bits ) - 1;
            unsigned char byte = data[data_offset] & mask;

            lane ^= (uint64_t) byte << ( shift * 8 );
        }

        ctx->state[x][y] = lane;
    }
}

/**
 * \brief               Read bytes from the Keccak state.
 *
 *                      The bytes are read starting from the beginning of the
 *                      Keccak state.
 *
 * \param ctx           The Keccak-f[1600] context.
 * \param data          Output buffer.
 * \param size          The number of bytes to read from the Keccak state.
 *
 * \pre size <= KECCAKF_STATE_SIZE_BYTES
 */
static void mbedtls_keccakf_read_binary( const mbedtls_keccakf_context *ctx,
                                         unsigned char *data,
                                         unsigned size )
{
    unsigned char x = 0;
    unsigned char y = 0;
    unsigned i;
    unsigned remaining_bytes = size;
    unsigned data_offset = 0;

    /* process whole lanes */
    while( remaining_bytes >= 8 )
    {
        const uint64_t lane = ctx->state[x][y];

        data[data_offset    ] = (uint8_t) lane;
        data[data_offset + 1] = (uint8_t) ( lane >> 8 );
        data[data_offset + 2] = (uint8_t) ( lane >> 16 );
        data[data_offset + 3] = (uint8_t) ( lane >> 24 );
        data[data_offset + 4] = (uint8_t) ( lane >> 32 );
        data[data_offset + 5] = (uint8_t) ( lane >> 40 );
        data[data_offset + 6] = (uint8_t) ( lane >> 48 );
        data[data_offset + 7] = (uint8_t) ( lane >> 56 );

        x = ( x + 1 ) % 5;
        if( x == 0 )
        {
            y = y + 1;
        }

        data_offset     += 8;
        remaining_bytes -= 8;
    }

    /* Process last (partial) lane */
    if( remaining_bytes > 0 )
    {
        const uint64_t lane = ctx->state[x][y];

        for( i = 0; i < remaining_bytes; i++ )
        {
            data[data_offset + i] = (uint8_t) ( lane >> ( i * 8 ) );
        }
    }
}



/**************** Keccak[c] sponge ****************/

#define SPONGE_STATE_UNINIT           ( 0 )
#define SPONGE_STATE_ABSORBING        ( 1 )
#define SPONGE_STATE_READY_TO_SQUEEZE ( 2 )
#define SPONGE_STATE_SQUEEZING        ( 3 )

/** Pad the queue with zeros.
 *
 * Fill in the queue with 0 or more 0-valued bits and mix it into the
 * Keccak-f state. This is equivalent to padding the input with zeros
 * to reach the next block boundary.
 *
 * \pre         ctx                != NULL
 * \pre         ctx->queue_len     <  ctx->rate
 * \pre         ctx->rate          < KECCAKF_STATE_SIZE_BITS
 * \pre         ctx->queue_len % 8 == 0
 * \pre         ctx->rate % 8      == 0
 * \pre         ctx->suffix_len    <= 8
 */
static void mbedtls_keccak_sponge_pad( mbedtls_keccak_sponge_context *ctx )
{
    if( ctx->queue_len > 0 )
    {
        size_t queue_free_bytes = ( ctx->rate - ctx->queue_len ) / 8;
        memset( &ctx->queue[ctx->queue_len / 8], 0, queue_free_bytes );
        ctx->queue_len = 0;
        mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx, ctx->queue, ctx->rate );
        mbedtls_keccakf_permute( &ctx->keccakf_ctx );
    }
}

/**
 * \brief       Absorbs the suffix bits into the context.
 *
 * \pre         ctx                != NULL
 * \pre         ctx->queue_len     <  ctx->rate
 * \pre         ctx->rate          < KECCAKF_STATE_SIZE_BITS
 * \pre         ctx->queue_len % 8 == 0
 * \pre         ctx->rate % 8      == 0
 * \pre         ctx->suffix_len    <= 8
 *
 * \param ctx   The sponge context. Must not be NULL.
 */
static void mbedtls_keccak_sponge_absorb_suffix(
    mbedtls_keccak_sponge_context *ctx )
{
    if( ctx->suffix_len > 0 )
    {
        ctx->queue[ctx->queue_len / 8] = ctx->suffix;
        ctx->queue_len += ctx->suffix_len;
    }

    if( ctx->queue_len >= ctx->rate )
    {
        ctx->queue_len = 0;

        mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx, ctx->queue, ctx->rate );
        mbedtls_keccakf_permute( &ctx->keccakf_ctx );
    }
}

/**
 * \brief       Finish the absorption phase and switch to the absorbing phase.
 *
 *              This function absorbs the suffix bits into the sponge state,
 *              adds the padding bits (using the pad10*1 rule), and finally
 *              generates the first block of output bits.
 *
 * \pre         ctx                != NULL
 * \pre         ctx->queue_len     <  ctx->rate
 * \pre         ctx->rate          < KECCAKF_STATE_SIZE_BITS
 * \pre         ctx->queue_len % 8 == 0
 * \pre         ctx->rate % 8      == 0
 * \pre         ctx->suffix_len    <= 8
 *
 * \param ctx   The sponge context. Must not be NULL.
 */
static void mbedtls_keccak_sponge_finalize(
    mbedtls_keccak_sponge_context *ctx )
{
    unsigned bits_free_in_queue;

    mbedtls_keccak_sponge_absorb_suffix( ctx );

    bits_free_in_queue = ctx->rate - ctx->queue_len;

    /* Add padding (pad10*1 rule). This adds at least 2 bits */
    /* Note that there might only be 1 bit free if there was 1 byte free in
     * the queue before the suffix was added, and the suffix length is 7 bits.
     */
    if( bits_free_in_queue >= 2 )
    {
        /* Set first bit */
        ctx->queue[ctx->queue_len / 8] &=
            ( (unsigned char) ( 1 << ( ctx->queue_len % 8 ) ) ) - 1;
        ctx->queue[ctx->queue_len / 8] |=
            (unsigned char) ( 1 << ( ctx->queue_len % 8 ) );

        /* Add zeroes (if necessary) */
        if( bits_free_in_queue >= 8 )
        {
            memset( &ctx->queue[( ctx->queue_len / 8 ) + 1],
                    0,
                    ( ctx->rate - ctx->queue_len ) / 8 );
        }

        /* Add last bit */
        ctx->queue[( ctx->rate - 1 ) / 8] |= 0x80U;
    }
    else
    {
        /* Only 1 free bit in the block, but we need to add 2 bits, so the
         * second bit spills over to another block.
         */

        /* Add first bit to complete the first block */
        ctx->queue[ctx->queue_len / 8] |= 0x80U;

        mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx, ctx->queue, ctx->rate );
        mbedtls_keccakf_permute( &ctx->keccakf_ctx );

        /* Set the next block to complete the padding */
        memset( ctx->queue, 0, ctx->rate / 8 );
        ctx->queue[( ctx->rate - 1 ) / 8] |= 0x80U;
    }

    mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx, ctx->queue, ctx->rate );
    mbedtls_keccakf_permute( &ctx->keccakf_ctx );

    ctx->state = SPONGE_STATE_SQUEEZING;

    /* Get initial output data into the queue */
    mbedtls_keccakf_read_binary( &ctx->keccakf_ctx,
                                 ctx->queue, ctx->rate / 8 );
    ctx->queue_len = ctx->rate;
}

/**
 * \brief               Initialize a Keccak sponge context.
 *
 * \param ctx           The context to initialize.
 */
static void mbedtls_keccak_sponge_init( mbedtls_keccak_sponge_context *ctx )
{
    mbedtls_keccakf_init( &ctx->keccakf_ctx );
    memset( ctx->queue, 0, sizeof( ctx->queue ) );
    ctx->queue_len  = 0;
    ctx->rate       = 0;
    ctx->suffix_len = 0;
    ctx->state      = SPONGE_STATE_UNINIT;
    ctx->suffix     = 0;
}

/**
 * \brief               Clean a Keccak sponge context.
 *
 * \param ctx           The context to clean.
 */
static void mbedtls_keccak_sponge_free( mbedtls_keccak_sponge_context *ctx )
{
    if( ctx != NULL )
    {
        mbedtls_keccakf_free( &ctx->keccakf_ctx );
        mbedtls_platform_zeroize( ctx->queue, sizeof( ctx->queue ) );
        ctx->queue_len  = 0;
        ctx->rate       = 0;
        ctx->suffix_len = 0;
        ctx->state      = SPONGE_STATE_UNINIT;
        ctx->suffix     = 0;
    }
}

/**
 * \brief               Clone (the state of) a Keccak Sponge context.
 *
 * \param dst           The destination context.
 * \param src           The context to clone.
 */
static void mbedtls_keccak_sponge_clone(
    mbedtls_keccak_sponge_context *dst,
    const mbedtls_keccak_sponge_context *src )
{
    *dst = *src;
}

/**
 * \brief               Comfigure the sponge context to start streaming.
 *
 *                      This function prepares the context to calculate
 *                      Keccak[_c_](_M_ || _S_, _d_) where:
 *                      - The capacity _c_ is specified as \p capacity.
 *                      - The message _M_ will be fed piecewise through
 *                        later successive calls to
 *                        mbedtls_keccak_sponge_absorb().
 *                      - The suffix _S_ consists of the \p suffix_len
 *                        low-order bits of \p suffix (the first bit of _S_
 *                        `suffix & 1`, the second bit `suffix >> 1 & 1`,
 *                        etc.).
 *                      - The output length _d_ is the total size
 *                        of the output that will be extracted through
 *                        later successive calls to
 *                        mbedtls_keccak_sponge_squeeze().
 *
 * \note                You must call mbedtls_keccak_sponge_init() before
 *                      calling this function, and you may no longer call
 *                      it after calling mbedtls_keccak_sponge_absorb() or
 *                      mbedtls_keccak_sponge_squeeze().
 *
 * \note                This function \b MUST be called after calling
 *                      mbedtls_keccak_sponge_init() and before calling the
 *                      absorb or squeeze functions. If this function has not
 *                      been called then the absorb/squeeze functions will
 *                      return #MBEDTLS_ERR_SHA3_BAD_STATE.
 *
 * \param ctx           The sponge context to set up.
 * \param capacity      The sponge's capacity parameter. This determines the
 *                      security of the sponge. The capacity should be double
 *                      the required security (in bits). For example, if 128 bits
 *                      of security are required then \p capacity should be set
 *                      to 256. This must be a multiple of 8. Must be less than
 *                      1600.
 * \param suffix        A byte containing the suffix bits that are absorbed
 *                      before the padding rule is applied.
 * \param suffix_len    The length (in bits) of the suffix.
 *                      8 is the maximum value.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_SHA3_BAD_INPUT_DATA
 *                      \p capacity is out of range or not a multiple of 8,
 *                      or \p suffix_len is greater than 8.
 * \retval #MBEDTLS_ERR_SHA3_BAD_STATE
 *                      This function was called without a prior call to
 *                      mbedtls_keccak_sponge_init() or after calling
 *                      mbedtls_keccak_sponge_absorb() or
 *                      mbedtls_keccak_sponge_squeeze(),
 */
static int mbedtls_keccak_sponge_starts( mbedtls_keccak_sponge_context *ctx,
                                         size_t capacity,
                                         unsigned char suffix,
                                         size_t suffix_len  )
{
    if( capacity == 0 ||
        capacity >= KECCAKF_STATE_SIZE_BITS ||
        capacity % 8 != 0 )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }
    else if( suffix_len > 8 )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }
    else if( ctx->state != SPONGE_STATE_UNINIT )
    {
        return( MBEDTLS_ERR_SHA3_BAD_STATE );
    }
    else
    {
        ctx->rate = KECCAKF_STATE_SIZE_BITS - capacity;
        ctx->suffix_len = suffix_len;
        ctx->suffix =
            suffix & ( (unsigned char) ( 1 << suffix_len ) - 1 );
    }

    return( 0 );
}

/**
 * \brief               Process input bits into the sponge.
 *
 * \note                This function can be called multiple times to stream
 *                      a large amount of data.
 *
 * \param ctx           The sponge context.
 * \param data          The buffer containing the bits to input into the sponge.
 * \param size          The number of bytes to input.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_SHA3_BAD_STATE
 *                      mbedtls_keccak_sponge_starts() has not been called
 *                      on \p ctx.
 * \retval #MBEDTLS_ERR_SHA3_BAD_STATE
 *                      The sponge can no longer accept data for absorption.
 *                      This occurs when mbedtls_keccak_sponge_squeeze() has
 *                      been previously called.
 *                      Alternatively, mbedtls_keccak_sponge_starts() has
 *                      not yet been called to set up the context.
 */
static int mbedtls_keccak_sponge_absorb( mbedtls_keccak_sponge_context *ctx,
                                         const unsigned char* data,
                                         size_t size )
{
    size_t data_offset = 0;
    size_t remaining_bytes = size;
    size_t rate_bytes;

    if( ctx->rate == 0 || ctx->rate >= KECCAKF_STATE_SIZE_BITS )
    {
        return( MBEDTLS_ERR_SHA3_BAD_STATE );
    }
    else if( ctx->state > SPONGE_STATE_ABSORBING )
    {
        return( MBEDTLS_ERR_SHA3_BAD_STATE );
    }

    if( remaining_bytes > 0 )
    {
        rate_bytes = ctx->rate / 8;

        /* Check if there are leftover bytes in the queue from previous
         * invocations */
        if( ctx->queue_len > 0 )
        {
            size_t queue_free_bytes = ( ctx->rate - ctx->queue_len ) / 8;

            if( remaining_bytes >= queue_free_bytes )
            {
                /* Enough data to fill the queue */
                memcpy( &ctx->queue[ctx->queue_len / 8],
                        data,
                        queue_free_bytes );

                ctx->queue_len = 0;

                data_offset     += queue_free_bytes;
                remaining_bytes -= queue_free_bytes;

                mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx,
                                            ctx->queue, ctx->rate );
                mbedtls_keccakf_permute( &ctx->keccakf_ctx );
            }
            else
            {
                /* Not enough data to completely fill the queue.
                 * Store this data with the other leftovers
                 */
                memcpy( &ctx->queue[ctx->queue_len / 8],
                        data,
                        remaining_bytes );

                ctx->queue_len += remaining_bytes * 8;
                remaining_bytes = 0;
            }
        }

        /* Process whole blocks */
        while( remaining_bytes >= rate_bytes )
        {
            mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx,
                                        &data[data_offset], ctx->rate );
            mbedtls_keccakf_permute( &ctx->keccakf_ctx );

            data_offset     += rate_bytes;
            remaining_bytes -= rate_bytes;
        }

        /* Store leftovers in the queue */
        if( remaining_bytes > 0 )
        {
            memcpy( ctx->queue, &data[data_offset], remaining_bytes );
            ctx->queue_len = remaining_bytes * 8;
        }
    }

    return( 0 );
}

/**
 * \brief               Get output bytes from the sponge.
 *
 * \note                This function can be called multiple times to generate
 *                      arbitrary-length output.
 *
 *                      After calling this function it is no longer possible
 *                      to absorb bits into the sponge state.
 *
 * \param ctx           The sponge context.
 * \param data          The buffer to where output bytes are stored.
 * \param size          The number of output bytes to produce.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_SHA3_BAD_STATE
 *                      mbedtls_keccak_sponge_starts() has not been called
 *                      on \p ctx.
 * \retval #MBEDTLS_ERR_SHA3_BAD_STATE
 *                      mbedtls_keccak_sponge_starts() has not yet been called
 *                      to set up the context.
 */
static int mbedtls_keccak_sponge_squeeze( mbedtls_keccak_sponge_context *ctx,
                                          unsigned char* data,
                                          size_t size )
{
    size_t queue_offset;
    size_t data_offset = 0;
    size_t queue_len_bytes;
    size_t rate_bytes;

    if( ctx->rate == 0 || ctx->rate >= KECCAKF_STATE_SIZE_BITS )
    {
        return( MBEDTLS_ERR_SHA3_BAD_STATE );
    }
    else if( ctx->state > SPONGE_STATE_SQUEEZING )
    {
        return( MBEDTLS_ERR_SHA3_BAD_STATE );
    }

    if( ctx->state < SPONGE_STATE_SQUEEZING )
    {
        mbedtls_keccak_sponge_finalize( ctx );
    }

    if( size > 0 )
    {
        rate_bytes      = ctx->rate / 8;
        queue_offset    = ( ctx->rate - ctx->queue_len ) / 8;
        queue_len_bytes = ctx->queue_len / 8;

        /* Consume data from the queue */
        if( size < queue_len_bytes )
        {
            /* Not enough output requested to empty the queue */
            memcpy( data, &ctx->queue[queue_offset], size );

            ctx->queue_len -= size * 8;
            size = 0;
        }
        else
        {
            /* Consume all data from the output queue */

            memcpy( data, &ctx->queue[queue_offset], queue_len_bytes );

            data_offset += queue_len_bytes;
            size        -= queue_len_bytes;

            ctx->queue_len = 0;
        }

        /* Process whole blocks */
        while( size >= rate_bytes )
        {
            mbedtls_keccakf_permute( &ctx->keccakf_ctx );
            mbedtls_keccakf_read_binary( &ctx->keccakf_ctx,
                                         &data[data_offset], rate_bytes );

            data_offset += rate_bytes;
            size        -= rate_bytes;
        }

        /* Process last (partial) block */
        if( size > 0 )
        {
            mbedtls_keccakf_permute( &ctx->keccakf_ctx );
            mbedtls_keccakf_read_binary( &ctx->keccakf_ctx,
                                         ctx->queue, rate_bytes );

            memcpy( &data[data_offset], ctx->queue, size );

            ctx->queue_len = ctx->rate - ( size  * 8 );
        }

        if( ctx->queue_len == 0 )
        {
            /* Generate next block of output for future calls */
            mbedtls_keccakf_permute( &ctx->keccakf_ctx );
            mbedtls_keccakf_read_binary( &ctx->keccakf_ctx,
                                         ctx->queue, rate_bytes );

            ctx->queue_len = ctx->rate;
        }
    }

    return( 0 );
}

/**
 * \brief               Absorb data through the sponge to capacity.
 *                      For internal use only.
 *
 * \note                You must call mbedtls_keccak_sponge_starts() before
 *                      calling this function. You must not call this function
 *                      after calling mbedtls_keccak_sponge_squeeze().
 *
 * \warning             This function does not protect against being called
 *                      in an invalid state. If in doubt, call
 *                      mbedtls_keccak_sponge_absorb() instead.
 *
 * \param ctx           The sponge context.
 * \param input         The buffer containing bytes to absorb. This function
 *                      reads 1600 - c bits (200 - ceiling(c/8) bytes) where
 *                      where c is the capacity set by
 *                      mbedtls_keccak_sponge_starts().
 *
 * \retval 0            Success.
 */
static int mbedtls_keccak_sponge_process( mbedtls_keccak_sponge_context *ctx,
                                          const unsigned char *input )
{
    mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx, input, ctx->rate );
    mbedtls_keccakf_permute( &ctx->keccakf_ctx );

    return( 0 );
}



/**************** SHA-3 hash functions ****************/

void mbedtls_sha3_init( mbedtls_sha3_context *ctx )
{
    if( ctx != NULL )
    {
        mbedtls_keccak_sponge_init( &ctx->sponge_ctx );
    }
}

void mbedtls_sha3_free( mbedtls_sha3_context *ctx )
{
    if( ctx != NULL )
    {
        mbedtls_keccak_sponge_free( &ctx->sponge_ctx );
    }
}

void mbedtls_sha3_clone( mbedtls_sha3_context *dst,
                         const mbedtls_sha3_context *src )
{
    mbedtls_keccak_sponge_clone( &dst->sponge_ctx, &src->sponge_ctx );
}

int mbedtls_sha3_starts( mbedtls_sha3_context *ctx, mbedtls_sha3_type_t type )
{
    unsigned bits;
    if( ctx == NULL )
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );

    switch( type )
    {
        case MBEDTLS_SHA3_224:
            bits = 224;
            break;
        case MBEDTLS_SHA3_256:
            bits = 256;
            break;
        case MBEDTLS_SHA3_384:
            bits = 384;
            break;
        case MBEDTLS_SHA3_512:
            bits = 512;
            break;
        default:
            return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    return( mbedtls_keccak_sponge_starts( &ctx->sponge_ctx,
                                          bits * 2, 0x02U, 2 ) );
}

int mbedtls_sha3_update( mbedtls_sha3_context *ctx,
                         const unsigned char* input,
                         size_t size )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    return( mbedtls_keccak_sponge_absorb( &ctx->sponge_ctx, input, size ) );
}

int mbedtls_sha3_finish( mbedtls_sha3_context *ctx, unsigned char* output )
{
    int ret;
    unsigned short capacity;
    if( ctx == NULL )
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    capacity = KECCAKF_STATE_SIZE_BITS - ctx->sponge_ctx.rate;
    ret = mbedtls_keccak_sponge_squeeze( &ctx->sponge_ctx,
                                         output, capacity / 16 );
    mbedtls_keccak_sponge_free( &ctx->sponge_ctx );
    return( ret );
}

int mbedtls_sha3_process( mbedtls_sha3_context *ctx,
                          const unsigned char* input )
{
    if( ctx == NULL || input == NULL )
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    return( mbedtls_keccak_sponge_process( &ctx->sponge_ctx, input ) );
}



/**************** SHAKE extendable-output functions ****************/

void mbedtls_shake_init( mbedtls_shake_context *ctx )
{
    if( ctx != NULL )
        mbedtls_keccak_sponge_init( &ctx->sponge_ctx );
}

void mbedtls_shake_free( mbedtls_shake_context *ctx )
{
    if( ctx != NULL )
        mbedtls_keccak_sponge_free( &ctx->sponge_ctx );
}

void mbedtls_shake_clone( mbedtls_shake_context *dst,
                          const mbedtls_shake_context *src )
{
    mbedtls_keccak_sponge_clone( &dst->sponge_ctx, &src->sponge_ctx );
}

int mbedtls_shake_starts( mbedtls_shake_context *ctx,
                          mbedtls_shake_type_t type )
{
    unsigned bits;
    if( ctx == NULL )
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );

    switch( type )
    {
        case MBEDTLS_SHAKE128:
            bits = 128;
            break;
        case MBEDTLS_SHAKE256:
            bits = 256;
            break;
        default:
            return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    return( mbedtls_keccak_sponge_starts( &ctx->sponge_ctx,
                                          bits * 2, 0x0FU, 4 ) );
}

int mbedtls_shake_update( mbedtls_shake_context *ctx,
                          const unsigned char* input,
                          size_t size )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    return( mbedtls_keccak_sponge_absorb( &ctx->sponge_ctx, input, size ) );
}

int mbedtls_shake_output( mbedtls_shake_context *ctx,
                          unsigned char* output,
                          size_t olen )
{
    if( ctx == NULL )
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    return( mbedtls_keccak_sponge_squeeze( &ctx->sponge_ctx, output, olen ) );
}



/**************** cSHAKE generalized XOF family ****************/

/** \brief Apply the encode_string function from SP800-185 and
 *         feed the result to a cSHAKE context.
 *
 * This function feeds encode_string(S) = left_encode(len(S)) || S
 * to the cSHAKE context.
 *
 * \param ctx           The cSHAKE context.
 * \param string        The byte string S to encode.
 * \param byte_len      The length of \p input in bytes.
 *
 * \retval 0            Success.
 */
static int mbedtls_cshake_encode_string( mbedtls_shake_context *ctx,
                                         const unsigned char *string,
                                         size_t byte_len )
{
    int ret;
    unsigned char encoded_len[sizeof( byte_len ) + 1];
    if( byte_len == 0 )
    {
        encoded_len[0] = 1;
        encoded_len[1] = 0;
    }
    else
    {
        size_t x_remaining, i;
        /* Calculate n: byte size of x where x is the bit length of
         * string. x = byte_len * 8, but don't do this calculation
         * explicitly because it might overflow. */
        encoded_len[0] = 1;
        for( x_remaining = byte_len >> 5; x_remaining != 0; x_remaining >>= 8 )
            encoded_len[0] += 1;
        /* x_n is the least significant digit of x in base 256. */
        encoded_len[encoded_len[0]] = 0xff & ( byte_len << 3 );
        /* Calculate the other base-256 digits of x (the ones that can
         * be extracted from byte_len = x / 8). */
        for( i = 1; i < encoded_len[0]; i++ )
            encoded_len[encoded_len[0] - i] =
                0xff & ( byte_len >> ( 8 * i - 3 ) );
    }
    ret = mbedtls_keccak_sponge_absorb( &ctx->sponge_ctx,
                                        encoded_len, encoded_len[0] + 1 );
    if( ret != 0 )
        return( ret );
    return( mbedtls_keccak_sponge_absorb( &ctx->sponge_ctx, string, byte_len ) );
}

int mbedtls_cshake_starts( mbedtls_shake_context *ctx,
                           mbedtls_shake_type_t type,
                           const unsigned char *function_name,
                           size_t function_name_len,
                           const unsigned char *customization,
                           size_t customization_len )
{
    int ret;
    unsigned bits;
    unsigned char prefix[2]; /* left_encode(w) */

    if( ctx == NULL )
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );

    if( function_name_len == 0 && customization_len == 0 )
        return( mbedtls_shake_starts( ctx, type ) );

    switch( type )
    {
        case MBEDTLS_SHAKE128:
            bits = 128;
            break;
        case MBEDTLS_SHAKE256:
            bits = 256;
            break;
        default:
            return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    ret = mbedtls_keccak_sponge_starts( &ctx->sponge_ctx, bits * 2, 0U, 2 );
    if( ret != 0 )
        return( ret );

    /* Input left_encode(w) where w = padding width = byte rate */
    prefix[0] = 1;
    prefix[1] = KECCAKF_STATE_SIZE_BYTES - bits / 4;
    ret = mbedtls_keccak_sponge_absorb( &ctx->sponge_ctx, prefix, 2 );
    if( ret != 0 )
        return( ret );

    /* Input left-encoded function name */
    ret = mbedtls_cshake_encode_string( ctx, function_name, function_name_len );
    if( ret != 0 )
        return( ret );

    /* Input left-encoded customization string */
    ret = mbedtls_cshake_encode_string( ctx, customization, customization_len );
    if( ret != 0 )
        return( ret );

    mbedtls_keccak_sponge_pad( &ctx->sponge_ctx );
    return( 0 );
}



/**************** Derived functions ****************/

#endif /* MBEDTLS_SHA3_ALT */

int mbedtls_sha3( mbedtls_sha3_type_t type,
                  const unsigned char* input,
                  size_t ilen,
                  unsigned char* output )
{
    mbedtls_sha3_context ctx;
    int result;

    mbedtls_sha3_init( &ctx );

    result = mbedtls_sha3_starts( &ctx, type );
    if( 0 != result )
    {
        goto cleanup;
    }

    result = mbedtls_sha3_update( &ctx, input, ilen );
    if( 0 != result )
    {
        goto cleanup;
    }

    result = mbedtls_sha3_finish( &ctx, output );

cleanup:
    mbedtls_sha3_free( &ctx );

    return( result );
}

int mbedtls_shake( mbedtls_shake_type_t type,
                   const unsigned char* input,
                   size_t ilen,
                   unsigned char* output,
                   size_t olen )
{
    mbedtls_shake_context ctx;
    int result;

    mbedtls_shake_init( &ctx );

    result = mbedtls_shake_starts( &ctx, type );
    if( 0 != result )
    {
        goto cleanup;
    }

    result = mbedtls_shake_update( &ctx, input, ilen );
    if( 0 != result )
    {
        goto cleanup;
    }

    result = mbedtls_shake_output( &ctx, output, olen );

cleanup:
    mbedtls_shake_free( &ctx );

    return( result );
}

int mbedtls_cshake( mbedtls_shake_type_t type,
                    const unsigned char *function_name,
                    size_t function_name_len,
                    const unsigned char *customization,
                    size_t customization_len,
                    const unsigned char* input,
                    size_t ilen,
                    unsigned char* output,
                    size_t olen )
{
    mbedtls_shake_context ctx;
    int res;

    mbedtls_shake_init( &ctx );

    res = mbedtls_cshake_starts( &ctx, type,
                                 function_name, function_name_len,
                                 customization, customization_len );
    if( res != 0 )
        goto cleanup;

    res = mbedtls_shake_update( &ctx, input, ilen );
    if( res != 0 )
        goto cleanup;

    res = mbedtls_shake_output( &ctx, output, olen );

cleanup:
    mbedtls_shake_free( &ctx );
    return( res );
}



/**************** Self-tests ****************/

#if defined(MBEDTLS_SELF_TEST)

static const unsigned char test_data[2][4] =
{
    "",
    "abc",
};

static const size_t test_data_len[2] =
{
    0, /* "" */
    3  /* "abc" */
};

static const unsigned char test_hash_sha3_224[2][28] =
{
    { /* "" */
        0x6B, 0x4E, 0x03, 0x42, 0x36, 0x67, 0xDB, 0xB7,
        0x3B, 0x6E, 0x15, 0x45, 0x4F, 0x0E, 0xB1, 0xAB,
        0xD4, 0x59, 0x7F, 0x9A, 0x1B, 0x07, 0x8E, 0x3F,
        0x5B, 0x5A, 0x6B, 0xC7
    },
    { /* "abc" */
        0xE6, 0x42, 0x82, 0x4C, 0x3F, 0x8C, 0xF2, 0x4A,
        0xD0, 0x92, 0x34, 0xEE, 0x7D, 0x3C, 0x76, 0x6F,
        0xC9, 0xA3, 0xA5, 0x16, 0x8D, 0x0C, 0x94, 0xAD,
        0x73, 0xB4, 0x6F, 0xDF
    }
};

static const unsigned char test_hash_sha3_256[2][32] =
{
    { /* "" */
        0xA7, 0xFF, 0xC6, 0xF8, 0xBF, 0x1E, 0xD7, 0x66,
        0x51, 0xC1, 0x47, 0x56, 0xA0, 0x61, 0xD6, 0x62,
        0xF5, 0x80, 0xFF, 0x4D, 0xE4, 0x3B, 0x49, 0xFA,
        0x82, 0xD8, 0x0A, 0x4B, 0x80, 0xF8, 0x43, 0x4A
    },
    { /* "abc" */
        0x3A, 0x98, 0x5D, 0xA7, 0x4F, 0xE2, 0x25, 0xB2,
        0x04, 0x5C, 0x17, 0x2D, 0x6B, 0xD3, 0x90, 0xBD,
        0x85, 0x5F, 0x08, 0x6E, 0x3E, 0x9D, 0x52, 0x5B,
        0x46, 0xBF, 0xE2, 0x45, 0x11, 0x43, 0x15, 0x32
    }
};

static const unsigned char test_hash_sha3_384[2][48] =
{
    { /* "" */
        0x0C, 0x63, 0xA7, 0x5B, 0x84, 0x5E, 0x4F, 0x7D,
        0x01, 0x10, 0x7D, 0x85, 0x2E, 0x4C, 0x24, 0x85,
        0xC5, 0x1A, 0x50, 0xAA, 0xAA, 0x94, 0xFC, 0x61,
        0x99, 0x5E, 0x71, 0xBB, 0xEE, 0x98, 0x3A, 0x2A,
        0xC3, 0x71, 0x38, 0x31, 0x26, 0x4A, 0xDB, 0x47,
        0xFB, 0x6B, 0xD1, 0xE0, 0x58, 0xD5, 0xF0, 0x04
    },
    { /* "abc" */
        0xEC, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6F, 0xC9,
        0x26, 0x45, 0x9F, 0x58, 0xE2, 0xC6, 0xAD, 0x8D,
        0xF9, 0xB4, 0x73, 0xCB, 0x0F, 0xC0, 0x8C, 0x25,
        0x96, 0xDA, 0x7C, 0xF0, 0xE4, 0x9B, 0xE4, 0xB2,
        0x98, 0xD8, 0x8C, 0xEA, 0x92, 0x7A, 0xC7, 0xF5,
        0x39, 0xF1, 0xED, 0xF2, 0x28, 0x37, 0x6D, 0x25
    }
};

static const unsigned char test_hash_sha3_512[2][64] =
{
    { /* "" */
        0xA6, 0x9F, 0x73, 0xCC, 0xA2, 0x3A, 0x9A, 0xC5,
        0xC8, 0xB5, 0x67, 0xDC, 0x18, 0x5A, 0x75, 0x6E,
        0x97, 0xC9, 0x82, 0x16, 0x4F, 0xE2, 0x58, 0x59,
        0xE0, 0xD1, 0xDC, 0xC1, 0x47, 0x5C, 0x80, 0xA6,
        0x15, 0xB2, 0x12, 0x3A, 0xF1, 0xF5, 0xF9, 0x4C,
        0x11, 0xE3, 0xE9, 0x40, 0x2C, 0x3A, 0xC5, 0x58,
        0xF5, 0x00, 0x19, 0x9D, 0x95, 0xB6, 0xD3, 0xE3,
        0x01, 0x75, 0x85, 0x86, 0x28, 0x1D, 0xCD, 0x26
    },
    { /* "abc" */
        0xB7, 0x51, 0x85, 0x0B, 0x1A, 0x57, 0x16, 0x8A,
        0x56, 0x93, 0xCD, 0x92, 0x4B, 0x6B, 0x09, 0x6E,
        0x08, 0xF6, 0x21, 0x82, 0x74, 0x44, 0xF7, 0x0D,
        0x88, 0x4F, 0x5D, 0x02, 0x40, 0xD2, 0x71, 0x2E,
        0x10, 0xE1, 0x16, 0xE9, 0x19, 0x2A, 0xF3, 0xC9,
        0x1A, 0x7E, 0xC5, 0x76, 0x47, 0xE3, 0x93, 0x40,
        0x57, 0x34, 0x0B, 0x4C, 0xF4, 0x08, 0xD5, 0xA5,
        0x65, 0x92, 0xF8, 0x27, 0x4E, 0xEC, 0x53, 0xF0
    }
};

static const unsigned char long_kat_hash_sha3_224[28] =
{
    0xD6, 0x93, 0x35, 0xB9, 0x33, 0x25, 0x19, 0x2E,
    0x51, 0x6A, 0x91, 0x2E, 0x6D, 0x19, 0xA1, 0x5C,
    0xB5, 0x1C, 0x6E, 0xD5, 0xC1, 0x52, 0x43, 0xE7,
    0xA7, 0xFD, 0x65, 0x3C
};

static const unsigned char long_kat_hash_sha3_256[32] =
{
    0x5C, 0x88, 0x75, 0xAE, 0x47, 0x4A, 0x36, 0x34,
    0xBA, 0x4F, 0xD5, 0x5E, 0xC8, 0x5B, 0xFF, 0xD6,
    0x61, 0xF3, 0x2A, 0xCA, 0x75, 0xC6, 0xD6, 0x99,
    0xD0, 0xCD, 0xCB, 0x6C, 0x11, 0x58, 0x91, 0xC1
};

static const unsigned char long_kat_hash_sha3_384[48] =
{
    0xEE, 0xE9, 0xE2, 0x4D, 0x78, 0xC1, 0x85, 0x53,
    0x37, 0x98, 0x34, 0x51, 0xDF, 0x97, 0xC8, 0xAD,
    0x9E, 0xED, 0xF2, 0x56, 0xC6, 0x33, 0x4F, 0x8E,
    0x94, 0x8D, 0x25, 0x2D, 0x5E, 0x0E, 0x76, 0x84,
    0x7A, 0xA0, 0x77, 0x4D, 0xDB, 0x90, 0xA8, 0x42,
    0x19, 0x0D, 0x2C, 0x55, 0x8B, 0x4B, 0x83, 0x40
};

static const unsigned char long_kat_hash_sha3_512[64] =
{
    0x3C, 0x3A, 0x87, 0x6D, 0xA1, 0x40, 0x34, 0xAB,
    0x60, 0x62, 0x7C, 0x07, 0x7B, 0xB9, 0x8F, 0x7E,
    0x12, 0x0A, 0x2A, 0x53, 0x70, 0x21, 0x2D, 0xFF,
    0xB3, 0x38, 0x5A, 0x18, 0xD4, 0xF3, 0x88, 0x59,
    0xED, 0x31, 0x1D, 0x0A, 0x9D, 0x51, 0x41, 0xCE,
    0x9C, 0xC5, 0xC6, 0x6E, 0xE6, 0x89, 0xB2, 0x66,
    0xA8, 0xAA, 0x18, 0xAC, 0xE8, 0x28, 0x2A, 0x0E,
    0x0D, 0xB5, 0x96, 0xC9, 0x0B, 0x0A, 0x7B, 0x87
};

static int mbedtls_sha3_kat_test( int verbose,
                                  const char* type_name,
                                  mbedtls_sha3_type_t type,
                                  int test_num )
{
    uint8_t hash[64];
    int result;

    result = mbedtls_sha3( type,
                           test_data[test_num], test_data_len[test_num],
                           hash );
    if( result != 0 )
    {
        if( verbose != 0 )
        {
            mbedtls_printf( "  %s test %d error code: %d\n",
                            type_name, test_num, result );
        }

        return( result );
    }

    switch( type )
    {
        case MBEDTLS_SHA3_224:
            result = memcmp( hash, test_hash_sha3_224[test_num], 28 );
            break;
        case MBEDTLS_SHA3_256:
            result = memcmp( hash, test_hash_sha3_256[test_num], 32 );
            break;
        case MBEDTLS_SHA3_384:
            result = memcmp( hash, test_hash_sha3_384[test_num], 48 );
            break;
        case MBEDTLS_SHA3_512:
            result = memcmp( hash, test_hash_sha3_512[test_num], 64 );
            break;
    }

    if( 0 != result )
    {
        if( verbose != 0 )
        {
            mbedtls_printf( "  %s test %d failed\n", type_name, test_num );
        }

        return( -1 );
    }

    if( verbose != 0 )
    {
        mbedtls_printf( "  %s test %d passed\n", type_name, test_num );
    }

    return( 0 );
}

static int mbedtls_sha3_long_kat_test( int verbose,
                                       const char* type_name,
                                       mbedtls_sha3_type_t type )
{
    mbedtls_sha3_context ctx;
    unsigned char buffer[1000];
    unsigned char hash[64];
    int i;
    int result = 0;

    memset( buffer, 'a', 1000 );

    if( verbose != 0 )
    {
        mbedtls_printf( "  %s long KAT test ", type_name );
    }

    mbedtls_sha3_init( &ctx );

    result = mbedtls_sha3_starts( &ctx, type );
    if( result != 0 )
    {
        if( verbose != 0 )
        {
            mbedtls_printf( "setup failed\n " );
        }
    }

    /* Process 1,000,000 (one million) 'a' characters */
    for( i = 0; i < 1000; i++ )
    {
        result = mbedtls_sha3_update( &ctx, buffer, 1000 );
        if( result != 0 )
        {
            if( verbose != 0 )
            {
                mbedtls_printf( "update error code: %i\n", result );
            }

            goto cleanup;
        }
    }

    result = mbedtls_sha3_finish( &ctx, hash );
    if( result != 0 )
    {
        if( verbose != 0 )
        {
            mbedtls_printf( "finish error code: %d\n", result );
        }

        goto cleanup;
    }

    switch( type )
    {
        case MBEDTLS_SHA3_224:
            result = memcmp( hash, long_kat_hash_sha3_224, 28 );
            break;
        case MBEDTLS_SHA3_256:
            result = memcmp( hash, long_kat_hash_sha3_256, 32 );
            break;
        case MBEDTLS_SHA3_384:
            result = memcmp( hash, long_kat_hash_sha3_384, 48 );
            break;
        case MBEDTLS_SHA3_512:
            result = memcmp( hash, long_kat_hash_sha3_512, 64 );
            break;
    }

    if( result != 0 )
    {
        if( verbose != 0 )
        {
            mbedtls_printf( "failed\n" );
        }
    }

    if( verbose != 0 )
    {
        mbedtls_printf( "passed\n" );
    }

cleanup:
    mbedtls_sha3_free( &ctx );
    return( result );
}

int mbedtls_sha3_self_test( int verbose )
{
    int i;

    /* Known Answer Tests (KAT) */
    for( i = 0; i < 2; i++ )
    {
        if( 0 != mbedtls_sha3_kat_test( verbose,
                                        "SHA3-224", MBEDTLS_SHA3_224, i ) )
            return( -1 );

        if( 0 != mbedtls_sha3_kat_test( verbose,
                                        "SHA3-256", MBEDTLS_SHA3_256, i ) )
            return( -1 );

        if( 0 != mbedtls_sha3_kat_test( verbose,
                                        "SHA3-384", MBEDTLS_SHA3_384, i ) )
            return( -1 );

        if( 0 != mbedtls_sha3_kat_test( verbose,
                                        "SHA3-512", MBEDTLS_SHA3_512, i ) )
            return( -1 );
    }

    /* Long KAT tests */
    if( 0 != mbedtls_sha3_long_kat_test( verbose,
                                         "SHA3-224", MBEDTLS_SHA3_224 ) )
        return( -1 );

    if( 0 != mbedtls_sha3_long_kat_test( verbose,
                                         "SHA3-256", MBEDTLS_SHA3_256 ) )
        return( -1 );

    if( 0 != mbedtls_sha3_long_kat_test( verbose,
                                         "SHA3-384", MBEDTLS_SHA3_384 ) )
        return( -1 );

    if( 0 != mbedtls_sha3_long_kat_test( verbose,
                                         "SHA3-512", MBEDTLS_SHA3_512 ) )
        return( -1 );

    if( verbose != 0 )
    {
        mbedtls_printf( "\n" );
    }

    return( 0 );
}

static const unsigned char shake128_test_input[2][16] =
{
    {
        0xD4, 0xD6, 0x7B, 0x00, 0xCA, 0x51, 0x39, 0x77,
        0x91, 0xB8, 0x12, 0x05, 0xD5, 0x58, 0x2C, 0x0A
    },
    {
        0xCC, 0x0A, 0x93, 0x9D, 0x40, 0xFE, 0xFD, 0xC6,
        0xC9, 0x9A, 0xCF, 0xA3, 0x7D, 0xE1, 0x0D, 0xF6
    }
};

static const unsigned char shake128_test_output[2][16] =
{
    {
        0xD0, 0xAC, 0xFB, 0x2A, 0x14, 0x92, 0x8C, 0xAF,
        0x8C, 0x16, 0x8A, 0xE5, 0x14, 0x92, 0x5E, 0x4E
    },
    {
        0xB7, 0x0B, 0x72, 0x4A, 0x91, 0xBA, 0x86, 0x5E,
        0xF4, 0x34, 0xF8, 0x50, 0x48, 0x50, 0x48, 0x91
    }
};

static const unsigned char shake256_test_input[2][32] =
{
    {
        0xEF, 0x89, 0x6C, 0xDC, 0xB3, 0x63, 0xA6, 0x15,
        0x91, 0x78, 0xA1, 0xBB, 0x1C, 0x99, 0x39, 0x46,
        0xC5, 0x04, 0x02, 0x09, 0x5C, 0xDA, 0xEA, 0x4F,
        0xD4, 0xD4, 0x19, 0xAA, 0x47, 0x32, 0x1C, 0x88
    },
    {
        0x76, 0x89, 0x1A, 0x7B, 0xCC, 0x6C, 0x04, 0x49,
        0x00, 0x35, 0xB7, 0x43, 0x15, 0x2F, 0x64, 0xA8,
        0xDD, 0x2E, 0xA1, 0x8A, 0xB4, 0x72, 0xB8, 0xD3,
        0x6E, 0xCF, 0x45, 0x85, 0x8D, 0x0B, 0x00, 0x46
    }
};

static const unsigned char shake256_test_output[2][32] =
{
    {
        0x7A, 0xBB, 0xA4, 0xE8, 0xB8, 0xDD, 0x76, 0x6B,
        0xBA, 0xBE, 0x98, 0xF8, 0xF1, 0x69, 0xCB, 0x62,
        0x08, 0x67, 0x4D, 0xE1, 0x9A, 0x51, 0xD7, 0x3C,
        0x92, 0xB7, 0xDC, 0x04, 0xA4, 0xB5, 0xEE, 0x3D
    },
    {
        0xE8, 0x44, 0x7D, 0xF8, 0x7D, 0x01, 0xBE, 0xEB,
        0x72, 0x4C, 0x9A, 0x2A, 0x38, 0xAB, 0x00, 0xFC,
        0xC2, 0x4E, 0x9B, 0xD1, 0x78, 0x60, 0xE6, 0x73,
        0xB0, 0x21, 0x22, 0x2D, 0x62, 0x1A, 0x78, 0x10
    }
};

int mbedtls_shake_self_test( int verbose )
{
    uint8_t output[32];
    int i;
    int result;

    for( i = 0; i < 2; i++ )
    {
        if( verbose != 0 )
        {
            mbedtls_printf( "  SHAKE128 test %d ", i );
        }

        result = mbedtls_shake( MBEDTLS_SHAKE128,
                                shake128_test_input[i], 16,
                                output, 16 );
        if( result != 0 )
        {
            if( verbose != 0 )
            {
                mbedtls_printf( "error code: %d\n", result );
            }
            return( -1 );
        }
        if( 0 != memcmp( shake128_test_output[i], output, 16 ) )
        {
            if( verbose != 0 )
            {
                mbedtls_printf( "failed\n" );
            }
            return( -1 );
        }

        if( verbose != 0 )
        {
            mbedtls_printf( "passed\n" );
            mbedtls_printf( "  SHAKE256 test %d ", i );
        }

        result = mbedtls_shake( MBEDTLS_SHAKE256,
                                shake256_test_input[i], 32,
                                output, 32 );
        if( result != 0 )
        {
            if( verbose != 0 )
            {
                mbedtls_printf( "error code: %d\n", result );
            }
            return( -1 );
        }
        if( 0 != memcmp( shake256_test_output[i], output, 32 ) )
        {
            if( verbose != 0 )
            {
                mbedtls_printf( "failed\n" );
            }
            return( -1 );
        }

        if( verbose != 0 )
        {
            mbedtls_printf( "passed\n" );
        }
    }

    if( verbose != 0 )
    {
        mbedtls_printf( "\n" );
    }

    return( 0 );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_SHA3_C */
