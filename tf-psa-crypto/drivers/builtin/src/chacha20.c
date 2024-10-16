/**
 * \file chacha20.c
 *
 * \brief ChaCha20 cipher.
 *
 * \author Daniel King <damaki.gh@gmail.com>
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_CHACHA20_C)

#include "mbedtls/chacha20.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <stddef.h>
#include <string.h>

#include "mbedtls/platform.h"

#define CHACHA20_CTR_INDEX (12U)

#define CHACHA20_BLOCK_SIZE_BYTES (4U * 16U)

/*
 * The Neon implementation can be configured to process multiple blocks in parallel; increasing the
 * number of blocks gains a lot of performance, but adds on average around 250 bytes of code size
 * for each additional block.
 *
 * This is controlled by setting MBEDTLS_CHACHA20_NEON_MULTIBLOCK in the range [0..6] (0 selects
 * the scalar implementation; 1 selects single-block Neon; 2..6 select multi-block Neon).
 *
 * The default (i.e., if MBEDTLS_CHACHA20_NEON_MULTIBLOCK is not set) selects the fastest variant
 * which has better code size than the scalar implementation (based on testing for Aarch64 on clang
 * and gcc).
 *
 * Size & performance notes for Neon implementation from informal tests on Aarch64
 * (applies to both gcc and clang except as noted):
 *   - When single-block is selected, this saves around 400-550 bytes of code-size c.f. the scalar
 *     implementation
 *   - Multi-block Neon is smaller and faster than scalar (up to 2 blocks for gcc, 3 for clang)
 *   - Code size increases consistently with number of blocks
 *   - Performance increases with number of blocks (except at 5 which is slightly slower than 4)
 *   - Performance is within a few % for gcc vs clang at all settings
 *   - Performance at 4 blocks roughly matches our hardware accelerated AES-GCM impl with
 *     better code size
 *   - Performance is worse at 7 or more blocks, due to running out of Neon registers
 */

#if !defined(MBEDTLS_HAVE_NEON_INTRINSICS)
// Select scalar implementation if Neon not available
    #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK 0
#elif !defined(MBEDTLS_CHACHA20_NEON_MULTIBLOCK)
// By default, select the best performing option that is smaller than the scalar implementation.
    #if defined(MBEDTLS_COMPILER_IS_GCC)
        #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK 2
    #else
        #define MBEDTLS_CHACHA20_NEON_MULTIBLOCK 3
    #endif
#endif

#if MBEDTLS_CHACHA20_NEON_MULTIBLOCK != 0
// Tested on all combinations of Armv7 arm/thumb2; Armv8 arm/thumb2/aarch64; Armv8 aarch64_be on
// clang 14, gcc 11, and some more recent versions.

// Define rotate-left operations that rotate within each 32-bit element in a 128-bit vector.
static inline uint32x4_t chacha20_neon_vrotlq_16_u32(uint32x4_t v)
{
    return vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v)));
}

static inline uint32x4_t chacha20_neon_vrotlq_12_u32(uint32x4_t v)
{
    uint32x4_t x = vshlq_n_u32(v, 12);
    return vsriq_n_u32(x, v, 20);
}

static inline uint32x4_t chacha20_neon_vrotlq_8_u32(uint32x4_t v)
{
    uint32x4_t result;
#if defined(MBEDTLS_ARCH_IS_ARM64)
    // This implementation is slightly faster, but only supported on 64-bit Arm
    // Table look-up which results in an 8-bit rotate-left within each 32-bit element
    const uint8_t    tbl_rotl8[16] = { 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14 };
    const uint8x16_t vrotl8_tbl = vld1q_u8(tbl_rotl8);
    result = vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(v), vrotl8_tbl));
#else
    uint32x4_t a = vshlq_n_u32(v, 8);
    result = vsriq_n_u32(a, v, 24);
#endif
    return result;
}

static inline uint32x4_t chacha20_neon_vrotlq_7_u32(uint32x4_t v)
{
    uint32x4_t x = vshlq_n_u32(v, 7);
    return vsriq_n_u32(x, v, 25);
}

// Increment the 32-bit element within v that corresponds to the ChaCha20 counter
static inline uint32x4_t chacha20_neon_inc_counter(uint32x4_t v)
{
    const uint32_t inc_const_scalar[4] = { 1, 0, 0, 0 };
    const uint32x4_t inc_const = vld1q_u32(inc_const_scalar);
    return vaddq_u32(v, inc_const);
}

typedef struct {
    uint32x4_t a, b, c, d;
} chacha20_neon_regs_t;

static inline chacha20_neon_regs_t chacha20_neon_singlepass(chacha20_neon_regs_t r)
{
    for (unsigned i = 0; i < 2; i++) {
        r.a = vaddq_u32(r.a, r.b);                    // r.a += b
        r.d = veorq_u32(r.d, r.a);                    // r.d ^= a
        r.d = chacha20_neon_vrotlq_16_u32(r.d);       // r.d <<<= 16

        r.c = vaddq_u32(r.c, r.d);                    // r.c += d
        r.b = veorq_u32(r.b, r.c);                    // r.b ^= c
        r.b = chacha20_neon_vrotlq_12_u32(r.b);       // r.b <<<= 12

        r.a = vaddq_u32(r.a, r.b);                    // r.a += b
        r.d = veorq_u32(r.d, r.a);                    // r.d ^= a
        r.d = chacha20_neon_vrotlq_8_u32(r.d);        // r.d <<<= 8

        r.c = vaddq_u32(r.c, r.d);                    // r.c += d
        r.b = veorq_u32(r.b, r.c);                    // r.b ^= c
        r.b = chacha20_neon_vrotlq_7_u32(r.b);        // r.b <<<= 7

        if (i == 0) {
            // re-order b, c and d for the diagonal rounds
            r.b = vextq_u32(r.b, r.b, 1);                 // r.b now holds positions 5,6,7,4
            r.c = vextq_u32(r.c, r.c, 2);                 // 10, 11, 8, 9
            r.d = vextq_u32(r.d, r.d, 3);                 // 15, 12, 13, 14
        } else {
            // restore element order in b, c, d
            r.b = vextq_u32(r.b, r.b, 3);
            r.c = vextq_u32(r.c, r.c, 2);
            r.d = vextq_u32(r.d, r.d, 1);
        }
    }

    return r;
}

static inline void chacha20_neon_finish_block(chacha20_neon_regs_t r,
                                              chacha20_neon_regs_t r_original,
                                              uint8_t **output,
                                              const uint8_t **input)
{
    r.a = vaddq_u32(r.a, r_original.a);
    r.b = vaddq_u32(r.b, r_original.b);
    r.c = vaddq_u32(r.c, r_original.c);
    r.d = vaddq_u32(r.d, r_original.d);

    vst1q_u8(*output + 0,  veorq_u8(vld1q_u8(*input + 0),  vreinterpretq_u8_u32(r.a)));
    vst1q_u8(*output + 16, veorq_u8(vld1q_u8(*input + 16), vreinterpretq_u8_u32(r.b)));
    vst1q_u8(*output + 32, veorq_u8(vld1q_u8(*input + 32), vreinterpretq_u8_u32(r.c)));
    vst1q_u8(*output + 48, veorq_u8(vld1q_u8(*input + 48), vreinterpretq_u8_u32(r.d)));

    *input += CHACHA20_BLOCK_SIZE_BYTES;
    *output += CHACHA20_BLOCK_SIZE_BYTES;
}

// Prevent gcc from rolling up the (manually unrolled) interleaved block loops
MBEDTLS_OPTIMIZE_FOR_PERFORMANCE
static inline uint32x4_t chacha20_neon_blocks(chacha20_neon_regs_t r_original,
                                              uint8_t *output,
                                              const uint8_t *input,
                                              size_t blocks)
{
    // Assuming 32 regs, with 4 for original values plus 4 for scratch, with 4 regs per block,
    // we should be able to process up to 24/4 = 6 blocks simultaneously.
    // Testing confirms that perf indeed increases with more blocks, and then falls off after 6.

    for (;;) {
        chacha20_neon_regs_t r[6];

        // It's essential to unroll these loops to benefit from interleaving multiple blocks.
        // If MBEDTLS_CHACHA20_NEON_MULTIBLOCK < 6, gcc and clang will optimise away the unused bits
        r[0] = r_original;
        r[1] = r_original;
        r[2] = r_original;
        r[3] = r_original;
        r[4] = r_original;
        r[5] = r_original;
        r[1].d = chacha20_neon_inc_counter(r[0].d);
        r[2].d = chacha20_neon_inc_counter(r[1].d);
        r[3].d = chacha20_neon_inc_counter(r[2].d);
        r[4].d = chacha20_neon_inc_counter(r[3].d);
        r[5].d = chacha20_neon_inc_counter(r[4].d);

        for (unsigned i = 0; i < 10; i++) {
            r[0] = chacha20_neon_singlepass(r[0]);
            r[1] = chacha20_neon_singlepass(r[1]);
            r[2] = chacha20_neon_singlepass(r[2]);
            r[3] = chacha20_neon_singlepass(r[3]);
            r[4] = chacha20_neon_singlepass(r[4]);
            r[5] = chacha20_neon_singlepass(r[5]);
        }

        chacha20_neon_finish_block(r[0], r_original, &output, &input);
        r_original.d = chacha20_neon_inc_counter(r_original.d);
        if (--blocks == 0) {
            return r_original.d;
        }
#if MBEDTLS_CHACHA20_NEON_MULTIBLOCK >= 2
        chacha20_neon_finish_block(r[1], r_original, &output, &input);
        r_original.d = chacha20_neon_inc_counter(r_original.d);
        if (--blocks == 0) {
            return r_original.d;
        }
#endif
#if MBEDTLS_CHACHA20_NEON_MULTIBLOCK >= 3
        chacha20_neon_finish_block(r[2], r_original, &output, &input);
        r_original.d = chacha20_neon_inc_counter(r_original.d);
        if (--blocks == 0) {
            return r_original.d;
        }
#endif
#if MBEDTLS_CHACHA20_NEON_MULTIBLOCK >= 4
        chacha20_neon_finish_block(r[3], r_original, &output, &input);
        r_original.d = chacha20_neon_inc_counter(r_original.d);
        if (--blocks == 0) {
            return r_original.d;
        }
#endif
#if MBEDTLS_CHACHA20_NEON_MULTIBLOCK >= 5
        chacha20_neon_finish_block(r[4], r_original, &output, &input);
        r_original.d = chacha20_neon_inc_counter(r_original.d);
        if (--blocks == 0) {
            return r_original.d;
        }
#endif
#if MBEDTLS_CHACHA20_NEON_MULTIBLOCK >= 6
        chacha20_neon_finish_block(r[5], r_original, &output, &input);
        r_original.d = chacha20_neon_inc_counter(r_original.d);
        if (--blocks == 0) {
            return r_original.d;
        }
#endif
    }
}

#else

#define ROTL32(value, amount) \
    ((uint32_t) ((value) << (amount)) | ((value) >> (32 - (amount))))

/**
 * \brief           ChaCha20 quarter round operation.
 *
 *                  The quarter round is defined as follows (from RFC 7539):
 *                      1.  a += b; d ^= a; d <<<= 16;
 *                      2.  c += d; b ^= c; b <<<= 12;
 *                      3.  a += b; d ^= a; d <<<= 8;
 *                      4.  c += d; b ^= c; b <<<= 7;
 *
 * \param state     ChaCha20 state to modify.
 * \param a         The index of 'a' in the state.
 * \param b         The index of 'b' in the state.
 * \param c         The index of 'c' in the state.
 * \param d         The index of 'd' in the state.
 */
static inline void chacha20_quarter_round(uint32_t state[16],
                                          size_t a,
                                          size_t b,
                                          size_t c,
                                          size_t d)
{
    /* a += b; d ^= a; d <<<= 16; */
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = ROTL32(state[d], 16);

    /* c += d; b ^= c; b <<<= 12 */
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = ROTL32(state[b], 12);

    /* a += b; d ^= a; d <<<= 8; */
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = ROTL32(state[d], 8);

    /* c += d; b ^= c; b <<<= 7; */
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = ROTL32(state[b], 7);
}

/**
 * \brief           Perform the ChaCha20 inner block operation.
 *
 *                  This function performs two rounds: the column round and the
 *                  diagonal round.
 *
 * \param state     The ChaCha20 state to update.
 */
static void chacha20_inner_block(uint32_t state[16])
{
    chacha20_quarter_round(state, 0, 4, 8,  12);
    chacha20_quarter_round(state, 1, 5, 9,  13);
    chacha20_quarter_round(state, 2, 6, 10, 14);
    chacha20_quarter_round(state, 3, 7, 11, 15);

    chacha20_quarter_round(state, 0, 5, 10, 15);
    chacha20_quarter_round(state, 1, 6, 11, 12);
    chacha20_quarter_round(state, 2, 7, 8,  13);
    chacha20_quarter_round(state, 3, 4, 9,  14);
}

/**
 * \brief               Generates a keystream block.
 *
 * \param initial_state The initial ChaCha20 state (key, nonce, counter).
 * \param keystream     Generated keystream bytes are written to this buffer.
 */
static void chacha20_block(const uint32_t initial_state[16],
                           unsigned char keystream[64])
{
    uint32_t working_state[16];
    size_t i;

    memcpy(working_state,
           initial_state,
           CHACHA20_BLOCK_SIZE_BYTES);

    for (i = 0U; i < 10U; i++) {
        chacha20_inner_block(working_state);
    }

    working_state[0] += initial_state[0];
    working_state[1] += initial_state[1];
    working_state[2] += initial_state[2];
    working_state[3] += initial_state[3];
    working_state[4] += initial_state[4];
    working_state[5] += initial_state[5];
    working_state[6] += initial_state[6];
    working_state[7] += initial_state[7];
    working_state[8] += initial_state[8];
    working_state[9] += initial_state[9];
    working_state[10] += initial_state[10];
    working_state[11] += initial_state[11];
    working_state[12] += initial_state[12];
    working_state[13] += initial_state[13];
    working_state[14] += initial_state[14];
    working_state[15] += initial_state[15];

    for (i = 0U; i < 16; i++) {
        size_t offset = i * 4U;

        MBEDTLS_PUT_UINT32_LE(working_state[i], keystream, offset);
    }

    mbedtls_platform_zeroize(working_state, sizeof(working_state));
}

#endif

void mbedtls_chacha20_init(mbedtls_chacha20_context *ctx)
{
    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_chacha20_context));
}

void mbedtls_chacha20_free(mbedtls_chacha20_context *ctx)
{
    if (ctx != NULL) {
        mbedtls_platform_zeroize(ctx, sizeof(mbedtls_chacha20_context));
    }
}

int mbedtls_chacha20_setkey(mbedtls_chacha20_context *ctx,
                            const unsigned char key[32])
{
    /* ChaCha20 constants - the string "expand 32-byte k" */
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;

    /* Set key */
    if (MBEDTLS_IS_BIG_ENDIAN) {
        ctx->state[4]  = MBEDTLS_GET_UINT32_LE(key, 0);
        ctx->state[5]  = MBEDTLS_GET_UINT32_LE(key, 4);
        ctx->state[6]  = MBEDTLS_GET_UINT32_LE(key, 8);
        ctx->state[7]  = MBEDTLS_GET_UINT32_LE(key, 12);
        ctx->state[8]  = MBEDTLS_GET_UINT32_LE(key, 16);
        ctx->state[9]  = MBEDTLS_GET_UINT32_LE(key, 20);
        ctx->state[10] = MBEDTLS_GET_UINT32_LE(key, 24);
        ctx->state[11] = MBEDTLS_GET_UINT32_LE(key, 28);
    } else {
        memcpy(&ctx->state[4], key, 32);
    }

    return 0;
}

int mbedtls_chacha20_starts(mbedtls_chacha20_context *ctx,
                            const unsigned char nonce[12],
                            uint32_t counter)
{
    /* Counter */
    ctx->state[12] = counter;

    /* Nonce */
    if (MBEDTLS_IS_BIG_ENDIAN) {
        ctx->state[13] = MBEDTLS_GET_UINT32_LE(nonce, 0);
        ctx->state[14] = MBEDTLS_GET_UINT32_LE(nonce, 4);
        ctx->state[15] = MBEDTLS_GET_UINT32_LE(nonce, 8);
    } else {
        memcpy(&ctx->state[13], nonce, 12);
    }

    /* Initially, there's no keystream bytes available */
    ctx->keystream_bytes_used = 0U;

    return 0;
}

int mbedtls_chacha20_update(mbedtls_chacha20_context *ctx,
                            size_t size,
                            const unsigned char *input,
                            unsigned char *output)
{
    size_t offset = 0U;

    /* Use leftover keystream bytes, if available */
    while (size > 0U && ctx->keystream_bytes_used > 0U &&
           ctx->keystream_bytes_used < CHACHA20_BLOCK_SIZE_BYTES) {
        output[offset] = input[offset] ^ ctx->keystream8[ctx->keystream_bytes_used];

        ctx->keystream_bytes_used = (ctx->keystream_bytes_used + 1) % CHACHA20_BLOCK_SIZE_BYTES;
        offset++;
        size--;
    }

#if MBEDTLS_CHACHA20_NEON_MULTIBLOCK != 0
    /* Load state into NEON registers */
    chacha20_neon_regs_t state;
    state.a = vld1q_u32(&ctx->state[0]);
    state.b = vld1q_u32(&ctx->state[4]);
    state.c = vld1q_u32(&ctx->state[8]);
    state.d = vld1q_u32(&ctx->state[12]);

    /* Process full blocks */
    if (size >= CHACHA20_BLOCK_SIZE_BYTES) {
        size_t blocks = size / CHACHA20_BLOCK_SIZE_BYTES;
        state.d = chacha20_neon_blocks(state, output + offset, input + offset, blocks);

        offset += CHACHA20_BLOCK_SIZE_BYTES * blocks;
        size   -= CHACHA20_BLOCK_SIZE_BYTES * blocks;
    }

    /* Last (partial) block */
    if (size > 0U) {
        /* Generate new keystream block and increment counter */
        memset(ctx->keystream8, 0, CHACHA20_BLOCK_SIZE_BYTES);
        state.d = chacha20_neon_blocks(state, ctx->keystream8, ctx->keystream8, 1);

        mbedtls_xor_no_simd(output + offset, input + offset, ctx->keystream8, size);

        ctx->keystream_bytes_used = size;
    }

    /* Capture state */
    vst1q_u32(&ctx->state[12], state.d);
#else
    /* Process full blocks */
    while (size >= CHACHA20_BLOCK_SIZE_BYTES) {
        /* Generate new keystream block and increment counter */
        chacha20_block(ctx->state, ctx->keystream8);
        ctx->state[CHACHA20_CTR_INDEX]++;

        mbedtls_xor(output + offset, input + offset, ctx->keystream8, 64U);

        offset += CHACHA20_BLOCK_SIZE_BYTES;
        size   -= CHACHA20_BLOCK_SIZE_BYTES;
    }

    /* Last (partial) block */
    if (size > 0U) {
        /* Generate new keystream block and increment counter */
        chacha20_block(ctx->state, ctx->keystream8);
        ctx->state[CHACHA20_CTR_INDEX]++;

        mbedtls_xor(output + offset, input + offset, ctx->keystream8, size);

        ctx->keystream_bytes_remaining = CHACHA20_BLOCK_SIZE_BYTES - size;

    }
#endif

    return 0;
}

int mbedtls_chacha20_crypt(const unsigned char key[32],
                           const unsigned char nonce[12],
                           uint32_t counter,
                           size_t data_len,
                           const unsigned char *input,
                           unsigned char *output)
{
    mbedtls_chacha20_context ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_chacha20_init(&ctx);

    ret = mbedtls_chacha20_setkey(&ctx, key);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_chacha20_starts(&ctx, nonce, counter);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_chacha20_update(&ctx, data_len, input, output);

cleanup:
    mbedtls_chacha20_free(&ctx);
    return ret;
}

#if defined(MBEDTLS_SELF_TEST)

static const unsigned char test_keys[2][32] =
{
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    },
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    }
};

static const unsigned char test_nonces[2][12] =
{
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    },
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02
    }
};

static const uint32_t test_counters[2] =
{
    0U,
    1U
};

static const unsigned char test_input[2][375] =
{
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    },
    {
        0x41, 0x6e, 0x79, 0x20, 0x73, 0x75, 0x62, 0x6d,
        0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x74,
        0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x49, 0x45,
        0x54, 0x46, 0x20, 0x69, 0x6e, 0x74, 0x65, 0x6e,
        0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x74,
        0x68, 0x65, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x72,
        0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x20, 0x66,
        0x6f, 0x72, 0x20, 0x70, 0x75, 0x62, 0x6c, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61,
        0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x6f, 0x72,
        0x20, 0x70, 0x61, 0x72, 0x74, 0x20, 0x6f, 0x66,
        0x20, 0x61, 0x6e, 0x20, 0x49, 0x45, 0x54, 0x46,
        0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65,
        0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x20,
        0x6f, 0x72, 0x20, 0x52, 0x46, 0x43, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x73,
        0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74,
        0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x77, 0x69,
        0x74, 0x68, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65,
        0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
        0x20, 0x6f, 0x66, 0x20, 0x61, 0x6e, 0x20, 0x49,
        0x45, 0x54, 0x46, 0x20, 0x61, 0x63, 0x74, 0x69,
        0x76, 0x69, 0x74, 0x79, 0x20, 0x69, 0x73, 0x20,
        0x63, 0x6f, 0x6e, 0x73, 0x69, 0x64, 0x65, 0x72,
        0x65, 0x64, 0x20, 0x61, 0x6e, 0x20, 0x22, 0x49,
        0x45, 0x54, 0x46, 0x20, 0x43, 0x6f, 0x6e, 0x74,
        0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e,
        0x22, 0x2e, 0x20, 0x53, 0x75, 0x63, 0x68, 0x20,
        0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e,
        0x74, 0x73, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75,
        0x64, 0x65, 0x20, 0x6f, 0x72, 0x61, 0x6c, 0x20,
        0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e,
        0x74, 0x73, 0x20, 0x69, 0x6e, 0x20, 0x49, 0x45,
        0x54, 0x46, 0x20, 0x73, 0x65, 0x73, 0x73, 0x69,
        0x6f, 0x6e, 0x73, 0x2c, 0x20, 0x61, 0x73, 0x20,
        0x77, 0x65, 0x6c, 0x6c, 0x20, 0x61, 0x73, 0x20,
        0x77, 0x72, 0x69, 0x74, 0x74, 0x65, 0x6e, 0x20,
        0x61, 0x6e, 0x64, 0x20, 0x65, 0x6c, 0x65, 0x63,
        0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63, 0x20, 0x63,
        0x6f, 0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x63, 0x61,
        0x74, 0x69, 0x6f, 0x6e, 0x73, 0x20, 0x6d, 0x61,
        0x64, 0x65, 0x20, 0x61, 0x74, 0x20, 0x61, 0x6e,
        0x79, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x6f,
        0x72, 0x20, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x2c,
        0x20, 0x77, 0x68, 0x69, 0x63, 0x68, 0x20, 0x61,
        0x72, 0x65, 0x20, 0x61, 0x64, 0x64, 0x72, 0x65,
        0x73, 0x73, 0x65, 0x64, 0x20, 0x74, 0x6f
    }
};

static const unsigned char test_output[2][375] =
{
    {
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
        0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
        0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
        0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
        0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
        0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
        0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
        0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
    },
    {
        0xa3, 0xfb, 0xf0, 0x7d, 0xf3, 0xfa, 0x2f, 0xde,
        0x4f, 0x37, 0x6c, 0xa2, 0x3e, 0x82, 0x73, 0x70,
        0x41, 0x60, 0x5d, 0x9f, 0x4f, 0x4f, 0x57, 0xbd,
        0x8c, 0xff, 0x2c, 0x1d, 0x4b, 0x79, 0x55, 0xec,
        0x2a, 0x97, 0x94, 0x8b, 0xd3, 0x72, 0x29, 0x15,
        0xc8, 0xf3, 0xd3, 0x37, 0xf7, 0xd3, 0x70, 0x05,
        0x0e, 0x9e, 0x96, 0xd6, 0x47, 0xb7, 0xc3, 0x9f,
        0x56, 0xe0, 0x31, 0xca, 0x5e, 0xb6, 0x25, 0x0d,
        0x40, 0x42, 0xe0, 0x27, 0x85, 0xec, 0xec, 0xfa,
        0x4b, 0x4b, 0xb5, 0xe8, 0xea, 0xd0, 0x44, 0x0e,
        0x20, 0xb6, 0xe8, 0xdb, 0x09, 0xd8, 0x81, 0xa7,
        0xc6, 0x13, 0x2f, 0x42, 0x0e, 0x52, 0x79, 0x50,
        0x42, 0xbd, 0xfa, 0x77, 0x73, 0xd8, 0xa9, 0x05,
        0x14, 0x47, 0xb3, 0x29, 0x1c, 0xe1, 0x41, 0x1c,
        0x68, 0x04, 0x65, 0x55, 0x2a, 0xa6, 0xc4, 0x05,
        0xb7, 0x76, 0x4d, 0x5e, 0x87, 0xbe, 0xa8, 0x5a,
        0xd0, 0x0f, 0x84, 0x49, 0xed, 0x8f, 0x72, 0xd0,
        0xd6, 0x62, 0xab, 0x05, 0x26, 0x91, 0xca, 0x66,
        0x42, 0x4b, 0xc8, 0x6d, 0x2d, 0xf8, 0x0e, 0xa4,
        0x1f, 0x43, 0xab, 0xf9, 0x37, 0xd3, 0x25, 0x9d,
        0xc4, 0xb2, 0xd0, 0xdf, 0xb4, 0x8a, 0x6c, 0x91,
        0x39, 0xdd, 0xd7, 0xf7, 0x69, 0x66, 0xe9, 0x28,
        0xe6, 0x35, 0x55, 0x3b, 0xa7, 0x6c, 0x5c, 0x87,
        0x9d, 0x7b, 0x35, 0xd4, 0x9e, 0xb2, 0xe6, 0x2b,
        0x08, 0x71, 0xcd, 0xac, 0x63, 0x89, 0x39, 0xe2,
        0x5e, 0x8a, 0x1e, 0x0e, 0xf9, 0xd5, 0x28, 0x0f,
        0xa8, 0xca, 0x32, 0x8b, 0x35, 0x1c, 0x3c, 0x76,
        0x59, 0x89, 0xcb, 0xcf, 0x3d, 0xaa, 0x8b, 0x6c,
        0xcc, 0x3a, 0xaf, 0x9f, 0x39, 0x79, 0xc9, 0x2b,
        0x37, 0x20, 0xfc, 0x88, 0xdc, 0x95, 0xed, 0x84,
        0xa1, 0xbe, 0x05, 0x9c, 0x64, 0x99, 0xb9, 0xfd,
        0xa2, 0x36, 0xe7, 0xe8, 0x18, 0xb0, 0x4b, 0x0b,
        0xc3, 0x9c, 0x1e, 0x87, 0x6b, 0x19, 0x3b, 0xfe,
        0x55, 0x69, 0x75, 0x3f, 0x88, 0x12, 0x8c, 0xc0,
        0x8a, 0xaa, 0x9b, 0x63, 0xd1, 0xa1, 0x6f, 0x80,
        0xef, 0x25, 0x54, 0xd7, 0x18, 0x9c, 0x41, 0x1f,
        0x58, 0x69, 0xca, 0x52, 0xc5, 0xb8, 0x3f, 0xa3,
        0x6f, 0xf2, 0x16, 0xb9, 0xc1, 0xd3, 0x00, 0x62,
        0xbe, 0xbc, 0xfd, 0x2d, 0xc5, 0xbc, 0xe0, 0x91,
        0x19, 0x34, 0xfd, 0xa7, 0x9a, 0x86, 0xf6, 0xe6,
        0x98, 0xce, 0xd7, 0x59, 0xc3, 0xff, 0x9b, 0x64,
        0x77, 0x33, 0x8f, 0x3d, 0xa4, 0xf9, 0xcd, 0x85,
        0x14, 0xea, 0x99, 0x82, 0xcc, 0xaf, 0xb3, 0x41,
        0xb2, 0x38, 0x4d, 0xd9, 0x02, 0xf3, 0xd1, 0xab,
        0x7a, 0xc6, 0x1d, 0xd2, 0x9c, 0x6f, 0x21, 0xba,
        0x5b, 0x86, 0x2f, 0x37, 0x30, 0xe3, 0x7c, 0xfd,
        0xc4, 0xfd, 0x80, 0x6c, 0x22, 0xf2, 0x21
    }
};

static const size_t test_lengths[2] =
{
    64U,
    375U
};

/* Make sure no other definition is already present. */
#undef ASSERT

#define ASSERT(cond, args)            \
    do                                  \
    {                                   \
        if (!(cond))                \
        {                               \
            if (verbose != 0)          \
            mbedtls_printf args;    \
                                        \
            return -1;               \
        }                               \
    }                                   \
    while (0)

int mbedtls_chacha20_self_test(int verbose)
{
    unsigned char output[381];
    unsigned i;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    for (i = 0U; i < 2U; i++) {
        if (verbose != 0) {
            mbedtls_printf("  ChaCha20 test %u ", i);
        }

        ret = mbedtls_chacha20_crypt(test_keys[i],
                                     test_nonces[i],
                                     test_counters[i],
                                     test_lengths[i],
                                     test_input[i],
                                     output);

        ASSERT(0 == ret, ("error code: %i\n", ret));

        ASSERT(0 == memcmp(output, test_output[i], test_lengths[i]),
               ("failed (output)\n"));

        if (verbose != 0) {
            mbedtls_printf("passed\n");
        }
    }

    if (verbose != 0) {
        mbedtls_printf("\n");
    }

    return 0;
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* !MBEDTLS_CHACHA20_C */
