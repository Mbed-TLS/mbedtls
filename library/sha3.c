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

#define KECCAKF_STATE_SIZE_BITS  ( 1600U )
#define KECCAKF_STATE_SIZE_BYTES ( 1600U / 8U )

#define ROTL64( x, amount ) \
    ( (uint64_t) ( x << amount) | ( x >> ( 64 - amount ) ) )

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
static inline void mbedtls_keccakf_theta( uint64_t in_state[5][5],
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
static inline void mbedtls_keccakf_rho( uint64_t in_state[5][5],
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
static inline void mbedtls_keccakf_pi( uint64_t in_state[5][5],
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
static inline void mbedtls_keccakf_chi_iota( uint64_t in_state[5][5],
                                             uint64_t out_state[5][5],
                                             size_t round_index )
{
    /* iota step */
    out_state[0][0] = in_state[0][0] ^ ( ( ~in_state[1][0] ) & in_state[2][0] )
                                     ^ round_constants[ round_index ];

    out_state[0][1] = in_state[0][1] ^ ( ( ~in_state[1][1] ) & in_state[2][1] );
    out_state[0][2] = in_state[0][2] ^ ( ( ~in_state[1][2] ) & in_state[2][2] );
    out_state[0][3] = in_state[0][3] ^ ( ( ~in_state[1][3] ) & in_state[2][3] );
    out_state[0][4] = in_state[0][4] ^ ( ( ~in_state[1][4] ) & in_state[2][4] );

    out_state[2][0] = in_state[2][0] ^ ( ( ~in_state[3][0] ) & in_state[4][0] );
    out_state[2][1] = in_state[2][1] ^ ( ( ~in_state[3][1] ) & in_state[4][1] );
    out_state[2][2] = in_state[2][2] ^ ( ( ~in_state[3][2] ) & in_state[4][2] );
    out_state[2][3] = in_state[2][3] ^ ( ( ~in_state[3][3] ) & in_state[4][3] );
    out_state[2][4] = in_state[2][4] ^ ( ( ~in_state[3][4] ) & in_state[4][4] );

    out_state[4][0] = in_state[4][0] ^ ( ( ~in_state[0][0] ) & in_state[1][0] );
    out_state[4][1] = in_state[4][1] ^ ( ( ~in_state[0][1] ) & in_state[1][1] );
    out_state[4][2] = in_state[4][2] ^ ( ( ~in_state[0][2] ) & in_state[1][2] );
    out_state[4][3] = in_state[4][3] ^ ( ( ~in_state[0][3] ) & in_state[1][3] );
    out_state[4][4] = in_state[4][4] ^ ( ( ~in_state[0][4] ) & in_state[1][4] );

    out_state[1][0] = in_state[1][0] ^ ( ( ~in_state[2][0] ) & in_state[3][0] );
    out_state[1][1] = in_state[1][1] ^ ( ( ~in_state[2][1] ) & in_state[3][1] );
    out_state[1][2] = in_state[1][2] ^ ( ( ~in_state[2][2] ) & in_state[3][2] );
    out_state[1][3] = in_state[1][3] ^ ( ( ~in_state[2][3] ) & in_state[3][3] );
    out_state[1][4] = in_state[1][4] ^ ( ( ~in_state[2][4] ) & in_state[3][4] );

    out_state[3][0] = in_state[3][0] ^ ( ( ~in_state[4][0] ) & in_state[0][0] );
    out_state[3][1] = in_state[3][1] ^ ( ( ~in_state[4][1] ) & in_state[0][1] );
    out_state[3][2] = in_state[3][2] ^ ( ( ~in_state[4][2] ) & in_state[0][2] );
    out_state[3][3] = in_state[3][3] ^ ( ( ~in_state[4][3] ) & in_state[0][3] );
    out_state[3][4] = in_state[3][4] ^ ( ( ~in_state[4][4] ) & in_state[0][4] );
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
    if( ctx != NULL )
    {
        mbedtls_platform_zeroize( &ctx->state, sizeof( ctx->state ) );
        mbedtls_platform_zeroize( &ctx->temp, sizeof( ctx->temp ) );
    }
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
 * \param ctx           The Keccak-f[1600] context to permute.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_SHA3_BAD_INPUT_DATA
 *                      \p ctx is \c NULL.
 */
static int mbedtls_keccakf_permute( mbedtls_keccakf_context *ctx )
{
    size_t i;

    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    for( i = 0U; i < 24U; i++ )
    {
        mbedtls_keccakf_theta   ( ctx->state, ctx->temp );
        mbedtls_keccakf_rho     ( ctx->temp , ctx->state );
        mbedtls_keccakf_pi      ( ctx->state, ctx->temp );
        mbedtls_keccakf_chi_iota( ctx->temp , ctx->state, i );
    }

    return( 0 );
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
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_SHA3_BAD_INPUT_DATA
 *                      \p ctx or \p data is \c NULL,
 *                      or \p size_bits is larger than 1600.
 */
static int mbedtls_keccakf_xor_binary( mbedtls_keccakf_context *ctx,
                                       const unsigned char *data,
                                       size_t size_bits )
{
    size_t x = 0U;
    size_t y = 0U;
    size_t remaining_bits = size_bits;
    size_t data_offset = 0U;

    if( ( ctx == NULL ) || ( data == NULL ) ||
        ( size_bits > KECCAKF_STATE_SIZE_BITS ) )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    /* process whole lanes */
    while( remaining_bits >= 64U )
    {
        ctx->state[x][y] ^=
            (uint64_t)              data[data_offset]               |
            (uint64_t) ( (uint64_t) data[data_offset + 1U] << 8U  ) |
            (uint64_t) ( (uint64_t) data[data_offset + 2U] << 16U ) |
            (uint64_t) ( (uint64_t) data[data_offset + 3U] << 24U ) |
            (uint64_t) ( (uint64_t) data[data_offset + 4U] << 32U ) |
            (uint64_t) ( (uint64_t) data[data_offset + 5U] << 40U ) |
            (uint64_t) ( (uint64_t) data[data_offset + 6U] << 48U ) |
            (uint64_t) ( (uint64_t) data[data_offset + 7U] << 56U );

        x = ( x + 1U ) % 5U;
        if( x == 0U )
        {
            y = y + 1U;
        }

        data_offset    += 8U;
        remaining_bits -= 64U;
    }

    /* process last (partial) lane */
    if( remaining_bits > 0U )
    {
        uint64_t lane = ctx->state[x][y];
        uint64_t shift = 0U;

        /* whole bytes */
        while( remaining_bits >= 8U )
        {
            lane ^= (uint64_t) ( (uint64_t) data[data_offset] << shift );

            data_offset++;
            shift          += 8U;
            remaining_bits -= 8U;
        }

        /* final bits */
        if( remaining_bits > 0U )
        {
            /* mask away higher bits to avoid accidentally XORIng them */
            unsigned char mask = ( (uint64_t) ( 1U << remaining_bits ) - 1U );
            unsigned char byte = data[data_offset] & mask;

            lane ^= (uint64_t) ( (uint64_t) byte << ( shift * 8U ) );
        }

        ctx->state[x][y] = lane;
    }

    return( 0 );
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
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_SHA3_BAD_INPUT_DATA
 *                      \p ctx or \p data is \c NULL,
 *                      or \p size is larger than 20.
 */
static int mbedtls_keccakf_read_binary( mbedtls_keccakf_context *ctx,
                                        unsigned char *data,
                                        size_t size )
{
    size_t x = 0U;
    size_t y = 0U;
    size_t i;
    size_t remaining_bytes = size;
    size_t data_offset = 0U;

    if( ( ctx == NULL ) || ( data == NULL ) ||
        ( size > KECCAKF_STATE_SIZE_BYTES ) )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    /* process whole lanes */
    while( remaining_bytes >= 8U )
    {
        const uint64_t lane = ctx->state[x][y];

        data[data_offset     ] = (uint8_t) lane;
        data[data_offset + 1U] = (uint8_t) ( lane >> 8U  );
        data[data_offset + 2U] = (uint8_t) ( lane >> 16U );
        data[data_offset + 3U] = (uint8_t) ( lane >> 24U );
        data[data_offset + 4U] = (uint8_t) ( lane >> 32U );
        data[data_offset + 5U] = (uint8_t) ( lane >> 40U );
        data[data_offset + 6U] = (uint8_t) ( lane >> 48U );
        data[data_offset + 7U] = (uint8_t) ( lane >> 56U );

        x = ( x + 1U ) % 5U;
        if( x == 0U )
        {
            y = y + 1U;
        }

        data_offset     += 8U;
        remaining_bytes -= 8U;
    }

    /* Process last (partial) lane */
    if( remaining_bytes > 0U )
    {
        const uint64_t lane = ctx->state[x][y];

        for( i = 0U; i < remaining_bytes; i++ )
        {
            data[data_offset + i] = (uint8_t) ( lane >> ( i * 8U ) );
        }
    }

    return( 0 );
}



/**************** Keccak[c] sponge ****************/

#define SPONGE_STATE_UNINIT           ( 0 )
#define SPONGE_STATE_ABSORBING        ( 1 )
#define SPONGE_STATE_READY_TO_SQUEEZE ( 2 )
#define SPONGE_STATE_SQUEEZING        ( 3 )

/**
 * \brief       Absorbs the suffix bits into the context.
 *
 * \pre         ctx                != NULL
 * \pre         ctx->queue_len     <  ctx->rate
 * \pre         ctx->queue_len % 8 == 0
 * \pre         ctx->rate % 8      == 0
 * \pre         ctx->suffix_len    <= 8
 *
 * \param ctx   The sponge context. Must not be NULL.
 */
static void mbedtls_keccak_sponge_absorb_suffix(
    mbedtls_keccak_sponge_context *ctx )
{
    if( ctx->suffix_len > 0U )
    {
        ctx->queue[ctx->queue_len / 8U] = ctx->suffix;
        ctx->queue_len += ctx->suffix_len;
    }

    if( ctx->queue_len >= ctx->rate )
    {
        ctx->queue_len = 0U;

        (void) mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx,
                                           ctx->queue, ctx->rate );
        (void) mbedtls_keccakf_permute( &ctx->keccakf_ctx );
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
 * \pre         ctx->queue_len % 8 == 0
 * \pre         ctx->rate % 8      == 0
 * \pre         ctx->suffix_len    <= 8
 *
 * \param ctx   The sponge context. Must not be NULL.
 */
static void mbedtls_keccak_sponge_finalize(
    mbedtls_keccak_sponge_context *ctx )
{
    size_t bits_free_in_queue;

    mbedtls_keccak_sponge_absorb_suffix( ctx );

    bits_free_in_queue = ctx->rate - ctx->queue_len;

    /* Add padding (pad10*1 rule). This adds at least 2 bits */
    /* Note that there might only be 1 bit free if there was 1 byte free in
     * the queue before the suffix was added, and the suffix length is 7 bits.
     */
    if( bits_free_in_queue >= 2U )
    {
        /* Set first bit */
        ctx->queue[ctx->queue_len / 8U] &=
            ( (unsigned char) ( 1U << ( ctx->queue_len % 8U ) ) ) - 1U;
        ctx->queue[ctx->queue_len / 8U] |=
            (unsigned char) ( 1U << ( ctx->queue_len % 8U ) );

        /* Add zeroes (if necessary) */
        if( bits_free_in_queue >= 8U )
        {
            memset( &ctx->queue[( ctx->queue_len / 8U ) + 1U],
                    0,
                    ( ctx->rate - ctx->queue_len ) / 8U );
        }

        /* Add last bit */
        ctx->queue[( ctx->rate - 1U ) / 8U] |= 0x80U;
    }
    else
    {
        /* Only 1 free bit in the block, but we need to add 2 bits, so the
         * second bit spills over to another block.
         */

        /* Add first bit to complete the first block */
        ctx->queue[ctx->queue_len / 8U] |= 0x80U;

        (void) mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx,
                                           ctx->queue, ctx->rate );
        (void) mbedtls_keccakf_permute( &ctx->keccakf_ctx );

        /* Set the next block to complete the padding */
        memset( ctx->queue, 0, ctx->rate / 8U );
        ctx->queue[( ctx->rate - 1U ) / 8U] |= 0x80U;
    }

    (void) mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx,
                                       ctx->queue, ctx->rate );
    (void) mbedtls_keccakf_permute( &ctx->keccakf_ctx );

    ctx->state = SPONGE_STATE_SQUEEZING;

    /* Get initial output data into the queue */
    (void) mbedtls_keccakf_read_binary( &ctx->keccakf_ctx,
                                        ctx->queue, ctx->rate / 8U );
    ctx->queue_len = ctx->rate;
}

/**
 * \brief               Initialize a Keccak sponge context.
 *
 * \param ctx           The context to initialize.
 */
static void mbedtls_keccak_sponge_init( mbedtls_keccak_sponge_context *ctx )
{
    if( ctx != NULL )
    {
        mbedtls_keccakf_init( &ctx->keccakf_ctx );
        mbedtls_platform_zeroize( ctx->queue, sizeof( ctx->queue ) );
        ctx->queue_len  = 0U;
        ctx->rate       = 0U;
        ctx->suffix_len = 0U;
        ctx->state      = SPONGE_STATE_UNINIT;
        ctx->suffix     = 0U;
    }
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
        ctx->queue_len  = 0U;
        ctx->rate       = 0U;
        ctx->suffix_len = 0U;
        ctx->state      = SPONGE_STATE_UNINIT;
        ctx->suffix     = 0U;
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
 *                      \p ctx is \c NULL,
 *                      or \p capacity is out of range or not a multiple of 8,
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
    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }
    else if( ( capacity == 0U ) ||
             ( capacity >= KECCAKF_STATE_SIZE_BITS ) ||
             ( ( capacity % 8U ) != 0U ) )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }
    else if( suffix_len > 8U )
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
            suffix & ( (unsigned char) ( 1U << suffix_len ) - 1U );
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
 * \retval #MBEDTLS_ERR_SHA3_BAD_INPUT_DATA
 *                      \p ctx or \p data is \c NULL.
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
    size_t data_offset = 0U;
    size_t remaining_bytes = size;
    size_t rate_bytes;

    if( ( ctx == NULL ) || ( data == NULL ) )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }
    else if( ctx->rate == 0U )
    {
        return( MBEDTLS_ERR_SHA3_BAD_STATE );
    }
    else if( ctx->state > SPONGE_STATE_ABSORBING )
    {
        return( MBEDTLS_ERR_SHA3_BAD_STATE );
    }

    if( remaining_bytes > 0U )
    {
        rate_bytes = ctx->rate / 8U;

        /* Check if there are leftover bytes in the queue from previous
         * invocations */
        if( ctx->queue_len > 0U )
        {
            size_t queue_free_bytes = ( ctx->rate - ctx->queue_len ) / 8U;

            if( remaining_bytes >= queue_free_bytes )
            {
                /* Enough data to fill the queue */
                memcpy( &ctx->queue[ctx->queue_len / 8U],
                        data,
                        queue_free_bytes );

                ctx->queue_len = 0U;

                data_offset     += queue_free_bytes;
                remaining_bytes -= queue_free_bytes;

                (void) mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx,
                                                   ctx->queue, ctx->rate );
                (void) mbedtls_keccakf_permute( &ctx->keccakf_ctx );
            }
            else
            {
                /* Not enough data to completely fill the queue.
                 * Store this data with the other leftovers
                 */
                memcpy( &ctx->queue[ctx->queue_len / 8U],
                        data,
                        remaining_bytes );

                ctx->queue_len += remaining_bytes * 8U;
                remaining_bytes = 0U;
            }
        }

        /* Process whole blocks */
        while( remaining_bytes >= rate_bytes )
        {
            (void) mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx,
                                               &data[data_offset], ctx->rate );
            (void) mbedtls_keccakf_permute( &ctx->keccakf_ctx );

            data_offset     += rate_bytes;
            remaining_bytes -= rate_bytes;
        }

        /* Store leftovers in the queue */
        if( remaining_bytes > 0U )
        {
            memcpy( ctx->queue, &data[data_offset], remaining_bytes );
            ctx->queue_len = remaining_bytes * 8U;
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
 * \retval #MBEDTLS_ERR_SHA3_BAD_INPUT_DATA
 *                      \p ctx or \p data is \c NULL.
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
    size_t data_offset = 0U;
    size_t queue_len_bytes;
    size_t rate_bytes;

    if( ( ctx == NULL ) || ( data == NULL ) )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }
    else if( ctx->rate == 0U )
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

    if( size > 0U )
    {
        rate_bytes      = ctx->rate / 8U;
        queue_offset    = ( ctx->rate - ctx->queue_len ) / 8U;
        queue_len_bytes = ctx->queue_len / 8U;

        /* Consume data from the queue */
        if( size < queue_len_bytes )
        {
            /* Not enough output requested to empty the queue */
            memcpy( data, &ctx->queue[queue_offset], size );

            ctx->queue_len -= size * 8U;
            size = 0U;
        }
        else
        {
            /* Consume all data from the output queue */

            memcpy( data, &ctx->queue[queue_offset], queue_len_bytes );

            data_offset += queue_len_bytes;
            size        -= queue_len_bytes;

            ctx->queue_len = 0U;
        }

        /* Process whole blocks */
        while( size >= rate_bytes )
        {
            (void) mbedtls_keccakf_permute( &ctx->keccakf_ctx );
            (void) mbedtls_keccakf_read_binary( &ctx->keccakf_ctx,
                                                &data[data_offset],
                                                rate_bytes );

            data_offset += rate_bytes;
            size        -= rate_bytes;
        }

        /* Process last (partial) block */
        if( size > 0U )
        {
            (void) mbedtls_keccakf_permute( &ctx->keccakf_ctx );
            (void) mbedtls_keccakf_read_binary( &ctx->keccakf_ctx,
                                                ctx->queue,
                                                rate_bytes );

            memcpy( &data[data_offset], ctx->queue, size );

            ctx->queue_len = ctx->rate - ( size  * 8U );
        }

        if( ctx->queue_len == 0U )
        {
            /* Generate next block of output for future calls */
            (void) mbedtls_keccakf_permute( &ctx->keccakf_ctx );
            (void) mbedtls_keccakf_read_binary( &ctx->keccakf_ctx,
                                                ctx->queue,
                                                rate_bytes );

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
 * \retval #MBEDTLS_ERR_SHA3_BAD_INPUT_DATA
 *                      \p ctx or \p input is \c NULL.
 */
static int mbedtls_keccak_sponge_process( mbedtls_keccak_sponge_context *ctx,
                                   const unsigned char *input )
{
    if( ( ctx == NULL ) || ( input == NULL ) )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    (void) mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx, input, ctx->rate );
    (void) mbedtls_keccakf_permute( &ctx->keccakf_ctx );

    return( 0 );
}

static int mbedtls_convert_sponge_result( int ret )
{
    return( ret );
}



/**************** SHA-3 hash functions ****************/

void mbedtls_sha3_init( mbedtls_sha3_context *ctx )
{
    if( ctx != NULL )
    {
        mbedtls_keccak_sponge_init( &ctx->sponge_ctx );
        ctx->digest_size = 0U;
    }
}

void mbedtls_sha3_free( mbedtls_sha3_context *ctx )
{
    if( ctx != NULL )
    {
        mbedtls_keccak_sponge_free( &ctx->sponge_ctx );
        ctx->digest_size = 0U;
    }
}

void mbedtls_sha3_clone( mbedtls_sha3_context *dst,
                         const mbedtls_sha3_context *src )
{
    mbedtls_keccak_sponge_clone( &dst->sponge_ctx, &src->sponge_ctx );
    dst->digest_size = src->digest_size;
    dst->block_size  = src->block_size;
}

int mbedtls_sha3_starts( mbedtls_sha3_context *ctx, mbedtls_sha3_type_t type )
{
    int sponge_ret;

    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    switch( type )
    {
        case MBEDTLS_SHA3_224:
            ctx->digest_size = 224U / 8U;
            ctx->block_size  = KECCAKF_STATE_SIZE_BYTES - ( 28U * 2U );
            sponge_ret = mbedtls_keccak_sponge_starts( &ctx->sponge_ctx,
                                                       224U * 2U, 0x02U, 2U );
            break;

        case MBEDTLS_SHA3_256:
            ctx->digest_size = 256U / 8U;
            ctx->block_size  = KECCAKF_STATE_SIZE_BYTES - ( 32U * 2U );
            sponge_ret = mbedtls_keccak_sponge_starts( &ctx->sponge_ctx,
                                                       256U * 2U, 0x02U, 2U );
            break;

        case MBEDTLS_SHA3_384:
            ctx->digest_size = 384U / 8U;
            ctx->block_size  = KECCAKF_STATE_SIZE_BYTES - ( 48U * 2U );
            sponge_ret = mbedtls_keccak_sponge_starts( &ctx->sponge_ctx,
                                                       384U * 2U, 0x02U, 2U );

            break;
        case MBEDTLS_SHA3_512:
            ctx->digest_size = 512U / 8U;
            ctx->block_size  = KECCAKF_STATE_SIZE_BYTES - ( 64U * 2U );
            sponge_ret = mbedtls_keccak_sponge_starts( &ctx->sponge_ctx,
                                                       512U * 2U, 0x02U, 2U );
            break;

        default:
            return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    return( mbedtls_convert_sponge_result( sponge_ret ) );
}

int mbedtls_sha3_update( mbedtls_sha3_context *ctx,
                         const unsigned char* input,
                         size_t size )
{
    int sponge_ret;

    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    sponge_ret = mbedtls_keccak_sponge_absorb( &ctx->sponge_ctx, input, size );

    return( mbedtls_convert_sponge_result( sponge_ret ) );
}

int mbedtls_sha3_finish( mbedtls_sha3_context *ctx, unsigned char* output )
{
    int sponge_ret;

    if( ( ctx == NULL ) || ( output == NULL ) )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    sponge_ret = mbedtls_keccak_sponge_squeeze( &ctx->sponge_ctx,
                                                output, ctx->digest_size );
    mbedtls_keccak_sponge_free( &ctx->sponge_ctx );

    return( mbedtls_convert_sponge_result( sponge_ret ) );
}

int mbedtls_sha3_process( mbedtls_sha3_context *ctx,
                          const unsigned char* input )
{
    int sponge_ret;

    if( ( ctx == NULL ) || ( input == NULL ) )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    sponge_ret = mbedtls_keccak_sponge_process( &ctx->sponge_ctx, input );

    return( mbedtls_convert_sponge_result( sponge_ret ) );
}



/**************** SHAKE extendable-output functions ****************/

void mbedtls_shake_init( mbedtls_shake_context *ctx )
{
    if( ctx != NULL )
    {
        mbedtls_keccak_sponge_init( &ctx->sponge_ctx );
    }
}

void mbedtls_shake_free( mbedtls_shake_context *ctx )
{
    if( ctx != NULL )
    {
        mbedtls_keccak_sponge_free( &ctx->sponge_ctx );
    }
}

void mbedtls_shake_clone( mbedtls_shake_context *dst,
                          const mbedtls_shake_context *src )
{
    mbedtls_keccak_sponge_clone( &dst->sponge_ctx, &src->sponge_ctx );
}

int mbedtls_shake_starts( mbedtls_shake_context *ctx,
                          mbedtls_shake_type_t type )
{
    int sponge_ret;

    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    switch( type )
    {
        case MBEDTLS_SHAKE128:
            ctx->block_size  = KECCAKF_STATE_SIZE_BYTES - 32U;
            sponge_ret = mbedtls_keccak_sponge_starts( &ctx->sponge_ctx,
                                                       256U, 0x0FU, 4U );
            break;

        case MBEDTLS_SHAKE256:
            ctx->block_size  = KECCAKF_STATE_SIZE_BYTES - 64U;
            sponge_ret = mbedtls_keccak_sponge_starts( &ctx->sponge_ctx,
                                                       512U, 0x0FU, 4U );
            break;

        default:
            return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    return( mbedtls_convert_sponge_result( sponge_ret ) );
}

int mbedtls_shake_update( mbedtls_shake_context *ctx,
                          const unsigned char* input,
                          size_t size )
{
    int sponge_ret;

    if( ctx == NULL )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    sponge_ret = mbedtls_keccak_sponge_absorb( &ctx->sponge_ctx,
                                               input, size );

    return( mbedtls_convert_sponge_result( sponge_ret ) );
}

int mbedtls_shake_output( mbedtls_shake_context *ctx,
                          unsigned char* output,
                          size_t olen )
{
    int sponge_ret;

    if( ( ctx == NULL ) || ( output == NULL ) )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    sponge_ret = mbedtls_keccak_sponge_squeeze( &ctx->sponge_ctx,
                                                output, olen );

    return( mbedtls_convert_sponge_result( sponge_ret ) );
}

int mbedtls_shake_process( mbedtls_shake_context *ctx,
                           const unsigned char* input )
{
    int sponge_ret;

    if( ( ctx == NULL ) || ( input == NULL ) )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    sponge_ret = mbedtls_keccak_sponge_process( &ctx->sponge_ctx, input );

    return( mbedtls_convert_sponge_result( sponge_ret ) );
}



/**************** Derived functions ****************/

#endif /* MBEDTLS_SHA3_ALT */

int mbedtls_sha3( const unsigned char* input,
                  size_t ilen,
                  mbedtls_sha3_type_t type,
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

int mbedtls_shake( const unsigned char* input,
                   size_t ilen,
                   mbedtls_shake_type_t type,
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



/**************** Self-tests ****************/

#ifdef MBEDTLS_SELF_TEST

static const unsigned char test_data[2][4] =
{
    "",
    "abc",
};

static const size_t test_data_len[2] =
{
    0U, /* "" */
    3U  /* "abc" */
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
                                  size_t test_num )
{
    uint8_t hash[64];
    int result;

    result = mbedtls_sha3( test_data[test_num], test_data_len[test_num],
                           type, hash );
    if( result != 0 )
    {
        if( verbose != 0 )
        {
            mbedtls_printf( "  %s test %zi error code: %i\n",
                            type_name, test_num, result );
        }

        return( result );
    }

    switch( type )
    {
        case MBEDTLS_SHA3_224:
            result = memcmp( hash, test_hash_sha3_224[test_num], 28U );
            break;
        case MBEDTLS_SHA3_256:
            result = memcmp( hash, test_hash_sha3_256[test_num], 32U );
            break;
        case MBEDTLS_SHA3_384:
            result = memcmp( hash, test_hash_sha3_384[test_num], 48U );
            break;
        case MBEDTLS_SHA3_512:
            result = memcmp( hash, test_hash_sha3_512[test_num], 64U );
            break;
    }

    if( 0 != result )
    {
        if( verbose != 0 )
        {
            mbedtls_printf( "  %s test %zi failed\n", type_name, test_num );
        }

        return( -1 );
    }

    if( verbose != 0 )
    {
        mbedtls_printf( "  %s test %zi passed\n", type_name, test_num );
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
    size_t i;
    int result = 0;

    memset( buffer, 'a', 1000U );

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
    for( i = 0U; i < 1000; i++ )
    {
        result = mbedtls_sha3_update( &ctx, buffer, 1000U );
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
            mbedtls_printf( "finish error code: %i\n", result );
        }

        goto cleanup;
    }

    switch( type )
    {
        case MBEDTLS_SHA3_224:
            result = memcmp( hash, long_kat_hash_sha3_224, 28U );
            break;
        case MBEDTLS_SHA3_256:
            result = memcmp( hash, long_kat_hash_sha3_256, 32U );
            break;
        case MBEDTLS_SHA3_384:
            result = memcmp( hash, long_kat_hash_sha3_384, 48U );
            break;
        case MBEDTLS_SHA3_512:
            result = memcmp( hash, long_kat_hash_sha3_512, 64U );
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
    size_t i;

    /* Known Answer Tests (KAT) */
    for( i = 0U; i < 2U; i++ )
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
    size_t i;
    int result;

    for( i = 0U; i < 2U; i++ )
    {
        if( verbose != 0 )
        {
            mbedtls_printf( "  SHAKE128 test %zi ", i );
        }

        result = mbedtls_shake( shake128_test_input[i], 16U,
                                MBEDTLS_SHAKE128,
                                output, 16U );
        if( result != 0 )
        {
            if( verbose != 0 )
            {
                mbedtls_printf( "error code: %i\n", result );
            }
            return( -1 );
        }
        if( 0 != memcmp( shake128_test_output[i], output, 16U ) )
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
            mbedtls_printf( "  SHAKE256 test %zi ", i );
        }

        result = mbedtls_shake( shake256_test_input[i], 32U,
                                MBEDTLS_SHAKE256,
                                output, 32U );
        if( result != 0 )
        {
            if( verbose != 0 )
            {
                mbedtls_printf( "error code: %i\n", result );
            }
            return( -1 );
        }
        if( 0 != memcmp( shake256_test_output[i], output, 32U ) )
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
