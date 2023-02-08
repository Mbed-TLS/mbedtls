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
#include "mbedtls/platform.h"
#endif /* MBEDTLS_SELF_TEST */

/*
 * List of supported SHA-3 families
 */
static mbedtls_sha3_family_functions sha3_families[] = {
    { MBEDTLS_SHA3_SHAKE128, 1344,   0, 0x1F },
    { MBEDTLS_SHA3_SHAKE256, 1088,   0, 0x1F },
    { MBEDTLS_SHA3_224,      1152, 224, 0x06 },
    { MBEDTLS_SHA3_256,      1088, 256, 0x06 },
    { MBEDTLS_SHA3_384,       832, 384, 0x06 },
    { MBEDTLS_SHA3_512,       576, 512, 0x06 },
    { MBEDTLS_SHA3_CSHAKE128, 1344,  0, 0x04 },
    { MBEDTLS_SHA3_CSHAKE256, 1088,  0, 0x04 },
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

#define ROT64(x, y) (((x) << (y)) | ((x) >> (64U - (y))))
#define ABSORB(ctx, idx, v) do { ctx->state[(idx) >> 3] ^= ((uint64_t) (v)) << (((idx) & 0x7) << 3); \
} while (0)
#define SQUEEZE(ctx, idx) ((uint8_t) (ctx->state[(idx) >> 3] >> (((idx) & 0x7) << 3)))
#define SWAP(x, y) do { uint64_t tmp = (x); (x) = (y); (y) = tmp; } while (0)

/* The permutation function.  */
static void keccak_f1600(mbedtls_sha3_context *ctx)
{
    uint64_t lane[5];
    uint64_t *s = ctx->state;
    int i;

    for (int round = 0; round < 24; round++) {
        uint64_t t;

        /* Theta */
        lane[0] = s[0] ^ s[5] ^ s[10] ^ s[15] ^ s[20];
        lane[1] = s[1] ^ s[6] ^ s[11] ^ s[16] ^ s[21];
        lane[2] = s[2] ^ s[7] ^ s[12] ^ s[17] ^ s[22];
        lane[3] = s[3] ^ s[8] ^ s[13] ^ s[18] ^ s[23];
        lane[4] = s[4] ^ s[9] ^ s[14] ^ s[19] ^ s[24];

        t = lane[4] ^ ROT64(lane[1], 1);
        s[0] ^= t; s[5] ^= t; s[10] ^= t; s[15] ^= t; s[20] ^= t;

        t = lane[0] ^ ROT64(lane[2], 1);
        s[1] ^= t; s[6] ^= t; s[11] ^= t; s[16] ^= t; s[21] ^= t;

        t = lane[1] ^ ROT64(lane[3], 1);
        s[2] ^= t; s[7] ^= t; s[12] ^= t; s[17] ^= t; s[22] ^= t;

        t = lane[2] ^ ROT64(lane[4], 1);
        s[3] ^= t; s[8] ^= t; s[13] ^= t; s[18] ^= t; s[23] ^= t;

        t = lane[3] ^ ROT64(lane[0], 1);
        s[4] ^= t; s[9] ^= t; s[14] ^= t; s[19] ^= t; s[24] ^= t;

        /* Rho */
        for (i = 1; i < 25; i++) {
            s[i] = ROT64(s[i], rho[i-1]);
        }

        /* Pi */
        t = s[1];
        for (i = 0; i < 24; i++) {
            SWAP(s[pi[i]], t);
        }

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

static uint8_t left_encode(uint8_t *encbuf, size_t value)
{
    uint8_t n = 0;

    /* Compute length of value in bytes */
    for (size_t v = value; v > 0 && n < sizeof(size_t); n++, v >>= 8) {
        ;
    }

    if (n == 0) {
        n = 1;
    }

    encbuf[0] = (uint8_t) n;
    for (int i = 1; i <= n; i++) {
        encbuf[i] = (uint8_t) (value >> (8 * (n - i)));
    }

    return n + 1;
}

static void keccak_pad(mbedtls_sha3_context *ctx)
{
    if ((ctx->index % ctx->max_block_size) != 0) {
        uint8_t b = 0;
        ctx->index = ctx->r / 8 - 1;
        mbedtls_sha3_update(ctx, &b, 1);
    }
}
void mbedtls_sha3_init(mbedtls_sha3_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    memset(ctx, 0, sizeof(mbedtls_sha3_context));
}

void mbedtls_sha3_free(mbedtls_sha3_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_sha3_context));
}

void mbedtls_sha3_clone(mbedtls_sha3_context *dst,
                        const mbedtls_sha3_context *src)
{
    if (dst == NULL || src == NULL) {
        return;
    }

    *dst = *src;
}

/*
 * SHA-3 context setup
 */
int mbedtls_sha3_starts(mbedtls_sha3_context *ctx, mbedtls_sha3_id id)
{
    mbedtls_sha3_family_functions *p = NULL;
    if (ctx == NULL) {
        return MBEDTLS_ERR_SHA3_BAD_INPUT_DATA;
    }

    for (p = sha3_families; p->id != MBEDTLS_SHA3_NONE; p++) {
        if (p->id == id) {
            break;
        }
    }

    if (p == NULL || p->id == MBEDTLS_SHA3_NONE) {
        return MBEDTLS_ERR_SHA3_BAD_INPUT_DATA;
    }

    ctx->id = id;
    ctx->r = p->r;
    ctx->olen = p->olen / 8;
    ctx->xor_byte = p->xor_byte;
    ctx->max_block_size = ctx->r / 8;

    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->index = 0;
    ctx->finished = 0;

    return 0;
}

/*
 * SHA-3 starts with name and customization (for CSHAKE)
 */
/* If this function receives an id != CSHAKE, it fallsback to mbedtls_sha3_starts() */
int mbedtls_sha3_starts_cshake(mbedtls_sha3_context *ctx, mbedtls_sha3_id id,
                              const char *name, size_t name_len,
                              const char *custom, size_t custom_len)
{
    int ret = 0;
    size_t encbuf_len = 0;
    uint8_t encbuf[sizeof(size_t) + 1];

    /* If name and custom are NULL, the context equals to SHAKE version */
    /* If name or custom are NOT NULL and id is not EQUAL to CSHAKE, it fallsback to SHA-3 */
    if (((name == NULL || name_len == 0) &&
         (custom == NULL || custom_len == 0)) ||
        (id != MBEDTLS_SHA3_CSHAKE128 && id != MBEDTLS_SHA3_CSHAKE256)) {
        if (id == MBEDTLS_SHA3_CSHAKE128) {
            return mbedtls_sha3_starts(ctx, MBEDTLS_SHA3_SHAKE128);
        } else if (id == MBEDTLS_SHA3_CSHAKE256) {
            return mbedtls_sha3_starts(ctx, MBEDTLS_SHA3_SHAKE256);
        }
        /* If other id is provided, silently start the context */
        return mbedtls_sha3_starts(ctx, id);
    }

    if (name == NULL) {
        name_len = 0;
    }
    if (custom == NULL) {
        custom_len = 0;
    }

    /* At this point, name or custom are not NULL, we start the context with id CSHAKE */
    if ((ret = mbedtls_sha3_starts(ctx, id)) != 0) {
        return ret;
    }

    encbuf_len = left_encode(encbuf, ctx->r / 8);
    mbedtls_sha3_update(ctx, encbuf, encbuf_len);

    encbuf_len = left_encode(encbuf, name_len * 8);
    mbedtls_sha3_update(ctx, encbuf, encbuf_len);
    if (name != NULL && name_len > 0) {
        mbedtls_sha3_update(ctx, (const uint8_t *) name, name_len);
    }

    encbuf_len = left_encode(encbuf, custom_len * 8);
    mbedtls_sha3_update(ctx, encbuf, encbuf_len);
    if (custom != NULL && custom_len > 0) {
        mbedtls_sha3_update(ctx, (const uint8_t *) custom, custom_len);
    }

    keccak_pad(ctx);

    return 0;
}

/*
 * SHA-3 process buffer
 */
int mbedtls_sha3_update(mbedtls_sha3_context *ctx,
                        const uint8_t *input,
                        size_t ilen)
{
    if (ctx == NULL) {
        return MBEDTLS_ERR_SHA3_BAD_INPUT_DATA;
    }

    if (ilen == 0 || input == NULL) {
        return 0;
    }

    while (ilen-- > 0) {
        ABSORB(ctx, ctx->index, *input++);
        if ((ctx->index = (ctx->index + 1) % ctx->max_block_size) == 0) {
            keccak_f1600(ctx);
        }
    }

    return 0;
}

int mbedtls_sha3_finish(mbedtls_sha3_context *ctx,
                        uint8_t *output, size_t olen)
{
    if (ctx == NULL) {
        return MBEDTLS_ERR_SHA3_BAD_INPUT_DATA;
    }

    if (olen == 0 || output == NULL) {
        return 0;
    }
    /* Catch SHA-3 families, with fixed output length */
    if (ctx->olen > 0) {
        if (ctx->olen > olen) {
            return MBEDTLS_ERR_SHA3_BAD_INPUT_DATA;
        }
        olen = ctx->olen;
    }

    if (ctx->finished == 0) {
        ABSORB(ctx, ctx->index, ctx->xor_byte);
        ABSORB(ctx, ctx->max_block_size - 1, 0x80);
        keccak_f1600(ctx);
        ctx->index = 0;
        ctx->finished = 1;
    }

    while (olen-- > 0) {
        *output++ = SQUEEZE(ctx, ctx->index);

        if ((ctx->index = (ctx->index + 1) % ctx->max_block_size) == 0) {
            keccak_f1600(ctx);
        }
    }

    return 0;
}

int mbedtls_sha3_cshake(mbedtls_sha3_id id,
                        const uint8_t *input, size_t ilen,
                        const char *name, size_t name_len,
                        const char *custom, size_t custom_len,
                        uint8_t *output, size_t olen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_sha3_context ctx;

    mbedtls_sha3_init(&ctx);

    if ((ret = mbedtls_sha3_starts_cshake(&ctx, id, name, name_len,
                                custom, custom_len)) != 0) {
        goto exit;
    }

    if ((ret = mbedtls_sha3_update(&ctx, input, ilen)) != 0) {
        goto exit;
    }

    if ((ret = mbedtls_sha3_finish(&ctx, output, olen)) != 0) {
        goto exit;
    }

exit:
    mbedtls_sha3_free(&ctx);

    return ret;
}

/*
 * output = SHA3( input buffer )
 */
int mbedtls_sha3(mbedtls_sha3_id id,
                 const uint8_t *input,
                 size_t ilen,
                 uint8_t *output,
                 size_t olen)
{
    return mbedtls_sha3_cshake(id, input, ilen,
                                NULL, 0, NULL, 0, output, olen);
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

static int mbedtls_sha3_kat_test(int verbose,
                                 const char *type_name,
                                 mbedtls_sha3_id id,
                                 int test_num)
{
    uint8_t hash[64];
    int result;

    result = mbedtls_sha3(id,
                          test_data[test_num], test_data_len[test_num],
                          hash, sizeof(hash));
    if (result != 0) {
        if (verbose != 0) {
            mbedtls_printf("  %s test %d error code: %d\n",
                           type_name, test_num, result);
        }

        return result;
    }

    switch (id) {
        case MBEDTLS_SHA3_224:
            result = memcmp(hash, test_hash_sha3_224[test_num], 28);
            break;
        case MBEDTLS_SHA3_256:
            result = memcmp(hash, test_hash_sha3_256[test_num], 32);
            break;
        case MBEDTLS_SHA3_384:
            result = memcmp(hash, test_hash_sha3_384[test_num], 48);
            break;
        case MBEDTLS_SHA3_512:
            result = memcmp(hash, test_hash_sha3_512[test_num], 64);
            break;
        default:
            break;
    }

    if (0 != result) {
        if (verbose != 0) {
            mbedtls_printf("  %s test %d failed\n", type_name, test_num);
        }

        return -1;
    }

    if (verbose != 0) {
        mbedtls_printf("  %s test %d passed\n", type_name, test_num);
    }

    return 0;
}

static int mbedtls_sha3_long_kat_test(int verbose,
                                      const char *type_name,
                                      mbedtls_sha3_id id)
{
    mbedtls_sha3_context ctx;
    unsigned char buffer[1000];
    unsigned char hash[64];
    int i;
    int result = 0;

    memset(buffer, 'a', 1000);

    if (verbose != 0) {
        mbedtls_printf("  %s long KAT test ", type_name);
    }

    mbedtls_sha3_init(&ctx);

    result = mbedtls_sha3_starts(&ctx, id);
    if (result != 0) {
        if (verbose != 0) {
            mbedtls_printf("setup failed\n ");
        }
    }

    /* Process 1,000,000 (one million) 'a' characters */
    for (i = 0; i < 1000; i++) {
        result = mbedtls_sha3_update(&ctx, buffer, 1000);
        if (result != 0) {
            if (verbose != 0) {
                mbedtls_printf("update error code: %i\n", result);
            }

            goto cleanup;
        }
    }

    result = mbedtls_sha3_finish(&ctx, hash, sizeof(hash));
    if (result != 0) {
        if (verbose != 0) {
            mbedtls_printf("finish error code: %d\n", result);
        }

        goto cleanup;
    }

    switch (id) {
        case MBEDTLS_SHA3_224:
            result = memcmp(hash, long_kat_hash_sha3_224, 28);
            break;
        case MBEDTLS_SHA3_256:
            result = memcmp(hash, long_kat_hash_sha3_256, 32);
            break;
        case MBEDTLS_SHA3_384:
            result = memcmp(hash, long_kat_hash_sha3_384, 48);
            break;
        case MBEDTLS_SHA3_512:
            result = memcmp(hash, long_kat_hash_sha3_512, 64);
            break;
        default:
            break;
    }

    if (result != 0) {
        if (verbose != 0) {
            mbedtls_printf("failed\n");
        }
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

cleanup:
    mbedtls_sha3_free(&ctx);
    return result;
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

static int mbedtls_shake_self_test(int verbose)
{
    uint8_t output[32];
    int i;
    int result;

    for (i = 0; i < 2; i++) {
        if (verbose != 0) {
            mbedtls_printf("  SHAKE128 test %d ", i);
        }

        result = mbedtls_sha3(MBEDTLS_SHA3_SHAKE128,
                              shake128_test_input[i], 16,
                              output, 16);
        if (result != 0) {
            if (verbose != 0) {
                mbedtls_printf("error code: %d\n", result);
            }
            return -1;
        }
        if (0 != memcmp(shake128_test_output[i], output, 16)) {
            if (verbose != 0) {
                mbedtls_printf("failed\n");
            }
            return -1;
        }

        if (verbose != 0) {
            mbedtls_printf("passed\n");
            mbedtls_printf("  SHAKE256 test %d ", i);
        }

        result = mbedtls_sha3(MBEDTLS_SHA3_SHAKE256,
                              shake256_test_input[i], 32,
                              output, 32);
        if (result != 0) {
            if (verbose != 0) {
                mbedtls_printf("error code: %d\n", result);
            }
            return -1;
        }
        if (0 != memcmp(shake256_test_output[i], output, 32)) {
            if (verbose != 0) {
                mbedtls_printf("failed\n");
            }
            return -1;
        }

        if (verbose != 0) {
            mbedtls_printf("passed\n");
        }
    }

    if (verbose != 0) {
        mbedtls_printf("\n");
    }

    return 0;
}

static const unsigned char cshake_test_customization[15] =
    "email signature";

static const unsigned char cshake128_test_output[2][16] =
{
    {
        0xcb, 0x7f, 0xc0, 0x3a, 0x6a, 0xd2, 0x25, 0xd0,
        0x42, 0xba, 0x48, 0xdb, 0x49, 0x7e, 0x09, 0x96
    },
    {
        0x79, 0x51, 0x27, 0xb7, 0x1d, 0x4a, 0x55, 0x34,
        0x00, 0xe9, 0xa5, 0x65, 0x8f, 0xbc, 0x38, 0x1e
    }
};

static const unsigned char cshake256_test_output[2][32] =
{
    {
        0xa4, 0x32, 0xb6, 0x58, 0x06, 0xe2, 0x24, 0x0e,
        0xb0, 0xd7, 0x32, 0x46, 0x4a, 0xb6, 0x22, 0x39,
        0x04, 0x5c, 0x2c, 0x3e, 0xdc, 0xab, 0x4e, 0x39,
        0xab, 0xb0, 0x78, 0xc8, 0x99, 0xaf, 0xae, 0xcd
    },
    {
        0xb4, 0x25, 0xb4, 0xc5, 0xef, 0x1f, 0xec, 0xa1,
        0x16, 0x8b, 0x88, 0xbe, 0x51, 0x0c, 0xc4, 0x1d,
        0x44, 0x0a, 0x06, 0x16, 0xd6, 0x81, 0x9c, 0x45,
        0x75, 0xeb, 0xcf, 0x2e, 0x15, 0xe4, 0x32, 0x06
    }
};

static int mbedtls_cshake_self_test(int verbose)
{
    uint8_t output[32];
    int i;
    int result;

    for (i = 0; i < 2; i++) {
        if (verbose != 0) {
            mbedtls_printf("  cSHAKE128 test %d ", i);
        }

        result = mbedtls_sha3_cshake(MBEDTLS_SHA3_CSHAKE128,
                                     shake128_test_input[i], 16,
                                     NULL, 0,
                                     (const char *) cshake_test_customization,
                                     sizeof(cshake_test_customization),
                                     output, 16);
        if (result != 0) {
            if (verbose != 0) {
                mbedtls_printf("error code: %d\n", result);
            }
            return -1;
        }
        if (0 != memcmp(cshake128_test_output[i], output, 16)) {
            if (verbose != 0) {
                mbedtls_printf("failed\n");
            }
            return -1;
        }

        if (verbose != 0) {
            mbedtls_printf("passed\n");
            mbedtls_printf("  cSHAKE256 test %d ", i);
        }

        result = mbedtls_sha3_cshake(MBEDTLS_SHA3_CSHAKE256,
                                     shake256_test_input[i], 32,
                                     NULL, 0,
                                     (const char *) cshake_test_customization,
                                     sizeof(cshake_test_customization),
                                     output, 32);
        if (result != 0) {
            if (verbose != 0) {
                mbedtls_printf("error code: %d\n", result);
            }
            return -1;
        }
        if (0 != memcmp(cshake256_test_output[i], output, 32)) {
            if (verbose != 0) {
                mbedtls_printf("failed\n");
            }
            return -1;
        }

        if (verbose != 0) {
            mbedtls_printf("passed\n");
        }
    }

    if (verbose != 0) {
        mbedtls_printf("\n");
    }

    return 0;
}
int mbedtls_sha3_self_test(int verbose)
{
    int i;

    /* SHA3 Known Answer Tests (KAT) */
    for (i = 0; i < 2; i++) {
        if (0 != mbedtls_sha3_kat_test(verbose,
                                       "SHA3-224", MBEDTLS_SHA3_224, i)) {
            return 1;
        }

        if (0 != mbedtls_sha3_kat_test(verbose,
                                       "SHA3-256", MBEDTLS_SHA3_256, i)) {
            return 1;
        }

        if (0 != mbedtls_sha3_kat_test(verbose,
                                       "SHA3-384", MBEDTLS_SHA3_384, i)) {
            return 1;
        }

        if (0 != mbedtls_sha3_kat_test(verbose,
                                       "SHA3-512", MBEDTLS_SHA3_512, i)) {
            return 1;
        }
    }

    /* SHA3 long KAT tests */
    if (0 != mbedtls_sha3_long_kat_test(verbose,
                                        "SHA3-224", MBEDTLS_SHA3_224)) {
        return 1;
    }

    if (0 != mbedtls_sha3_long_kat_test(verbose,
                                        "SHA3-256", MBEDTLS_SHA3_256)) {
        return 1;
    }

    if (0 != mbedtls_sha3_long_kat_test(verbose,
                                        "SHA3-384", MBEDTLS_SHA3_384)) {
        return 1;
    }

    if (0 != mbedtls_sha3_long_kat_test(verbose,
                                        "SHA3-512", MBEDTLS_SHA3_512)) {
        return 1;
    }

    if (verbose != 0) {
        mbedtls_printf("\n");
    }


    /* SHAKE and cSHAKE tests */
    if (0 != mbedtls_shake_self_test(verbose)) {
        return 1;
    }
    if (0 != mbedtls_cshake_self_test(verbose)) {
        return 1;
    }

    return 0;
}
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_SHA3_C */
