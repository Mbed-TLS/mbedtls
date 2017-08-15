/*
 *  An implementation of the CHACHA8 algorithm
 *
 *  Copyright (C) 20017, Mobica Limited, All Rights Reserved
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
 */


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CHACHA8_C)

#include "mbedtls/chacha8.h"

#include <string.h>
#include <stdint.h>
#include <mbedtls/chacha8.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#if !defined(MBEDTLS_CHACHA8_ALT)

#define MBEDTLS_CHACHA8_ROTATE(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define MBEDTLS_CHACHA8_PLUS(v,w) ((uint32_t)((v) + (w)))
#define MBEDTLS_CHACHA8_PLUSONE(v) (MBEDTLS_CHACHA8_PLUS((v),1))

#define MBEDTLS_CHACHA8_QUARTERROUND(a, b, c, d)                \
  x[a] += x[b]; x[d] = MBEDTLS_CHACHA8_ROTATE(x[d] ^ x[a], 16); \
  x[c] += x[d]; x[b] = MBEDTLS_CHACHA8_ROTATE(x[b] ^ x[c], 12); \
  x[a] += x[b]; x[d] = MBEDTLS_CHACHA8_ROTATE(x[d] ^ x[a],  8); \
  x[c] += x[d]; x[b] = MBEDTLS_CHACHA8_ROTATE(x[b] ^ x[c],  7);

#define MBEDTLS_CHACHA8_U8TO32_LITTLE(p)                              \
  (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | \
   ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))

#define MBEDTLS_CHACHA8_U32TO8_LITTLE(p, v)\
{                          \
(p)[0] = (v >> 0) & 0xff;  \
(p)[1] = (v >> 8) & 0xff;  \
(p)[2] = (v >> 16) & 0xff; \
(p)[3] = (v >> 24) & 0xff; \
}



#define MBEDTLS_CHACHA8_KEYSTREAM_SEGMENT_SIZE 64

static void chacha8_wordtobyte(uint8_t output[64], const uint32_t input[16])
{
    uint32_t x[16];
    int i;

    for (i = 0;i < 16;++i) {
        x[i] = input[i];
    }

    for (i = 8;i > 0;i -= 2)
    {
        MBEDTLS_CHACHA8_QUARTERROUND( 0, 4, 8,12)
        MBEDTLS_CHACHA8_QUARTERROUND( 1, 5, 9,13)
        MBEDTLS_CHACHA8_QUARTERROUND( 2, 6,10,14)
        MBEDTLS_CHACHA8_QUARTERROUND( 3, 7,11,15)
        MBEDTLS_CHACHA8_QUARTERROUND( 0, 5,10,15)
        MBEDTLS_CHACHA8_QUARTERROUND( 1, 6,11,12)
        MBEDTLS_CHACHA8_QUARTERROUND( 2, 7, 8,13)
        MBEDTLS_CHACHA8_QUARTERROUND( 3, 4, 9,14)
    }

    for (i = 0; i < 16; ++i)
    {
        x[i] += input[i];
    }
    for (i = 0; i < 16; ++i)
    {
        MBEDTLS_CHACHA8_U32TO8_LITTLE(output + 4 * i, x[i]);
    }
}

/* sigma contains the ChaCha constants */
static const char mbedtls_chacha8_sigma[16] = "expand 32-byte k";
static const char mbedtls_chacha8_tau[16] = "expand 16-byte k";


/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n )
{
    volatile unsigned char *p = (unsigned char*)v; while( n-- ) *p++ = 0;
}

void mbedtls_chacha8_init( mbedtls_chacha8_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_chacha8_context ) );
}

void mbedtls_chacha8_free( mbedtls_chacha8_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_zeroize( ctx, sizeof( mbedtls_chacha8_context ) );
}

void mbedtls_chacha8_reset_keystream_state( mbedtls_chacha8_context *ctx )
{
    ctx->keystream_buffer_offset = 0;
    ctx->unused_keystream_number_bytes = 0;
}

/*
 * SALSA20 set IV
 */
void mbedtls_chacha8_set_iv( mbedtls_chacha8_context *ctx, const unsigned char *iv )
{
    // ivsetup (IV - initialization vector) - fixed size input.
    // this is typicaly required to be random or pseudorandom
    ctx->internal_state[12] = 0;
    ctx->internal_state[13] = 0;
    ctx->internal_state[14] = MBEDTLS_CHACHA8_U8TO32_LITTLE(iv + 0);
    ctx->internal_state[15] = MBEDTLS_CHACHA8_U8TO32_LITTLE(iv + 4);
}

/*
 * CHACHA8 key schedule
 */
void mbedtls_chacha8_setup( mbedtls_chacha8_context *ctx, const unsigned char *key,
                 unsigned int keylen )
{
    const char *constants;

    ctx->internal_state[4] = MBEDTLS_CHACHA8_U8TO32_LITTLE(key + 0);
    ctx->internal_state[5] = MBEDTLS_CHACHA8_U8TO32_LITTLE(key + 4);
    ctx->internal_state[6] = MBEDTLS_CHACHA8_U8TO32_LITTLE(key + 8);
    ctx->internal_state[7] = MBEDTLS_CHACHA8_U8TO32_LITTLE(key + 12);

    if (keylen == 256) { /* recommended */
        key += 16;
        constants = mbedtls_chacha8_sigma;
    } else { /* kbits == 128 */
        constants = mbedtls_chacha8_tau;
    }

    ctx->internal_state[8] = MBEDTLS_CHACHA8_U8TO32_LITTLE(key + 0);
    ctx->internal_state[9] = MBEDTLS_CHACHA8_U8TO32_LITTLE(key + 4);
    ctx->internal_state[10] = MBEDTLS_CHACHA8_U8TO32_LITTLE(key + 8);
    ctx->internal_state[11] = MBEDTLS_CHACHA8_U8TO32_LITTLE(key + 12);
    ctx->internal_state[0] = MBEDTLS_CHACHA8_U8TO32_LITTLE(constants + 0);
    ctx->internal_state[1] = MBEDTLS_CHACHA8_U8TO32_LITTLE(constants + 4);
    ctx->internal_state[2] = MBEDTLS_CHACHA8_U8TO32_LITTLE(constants + 8);
    ctx->internal_state[3] = MBEDTLS_CHACHA8_U8TO32_LITTLE(constants + 12);

    ctx->unused_keystream_number_bytes = 0;
    ctx->keystream_buffer_offset = 0;
}


/*
 * CHACHA8 cipher function
 */
int mbedtls_chacha8_crypt( mbedtls_chacha8_context *ctx, size_t length, const unsigned char *input,
                unsigned char *output)
{
    uint32_t lByte;

    unsigned char keystream_segment[MBEDTLS_CHACHA8_KEYSTREAM_SEGMENT_SIZE];

    uint32_t number_bytes_crypted = 0;
    uint32_t segment_start_offset = 0;
    uint32_t number_of_bytes_this_run = 0;

    while (number_bytes_crypted < length)
    {
        memset(keystream_segment, 0x00, MBEDTLS_CHACHA8_KEYSTREAM_SEGMENT_SIZE);
        number_of_bytes_this_run = (length - number_bytes_crypted) < MBEDTLS_CHACHA8_KEYSTREAM_SEGMENT_SIZE ?
                                            length - number_bytes_crypted :
                                   MBEDTLS_CHACHA8_KEYSTREAM_SEGMENT_SIZE;

        mbedtls_chacha8_get_keystream_slice(ctx, keystream_segment, number_of_bytes_this_run);

        for (lByte = 0; lByte < number_of_bytes_this_run; ++lByte)
        {
            output[segment_start_offset + lByte] = input[segment_start_offset + lByte] ^ keystream_segment[lByte];
        }

        number_bytes_crypted += number_of_bytes_this_run;
        segment_start_offset += number_of_bytes_this_run;
    }

    return( 0 );
}

void mbedtls_chacha8_generate_keystream_block( mbedtls_chacha8_context *ctx )
{

    unsigned char output[MBEDTLS_CHACHA8_KEYSTREAM_SEGMENT_SIZE];
    int i;

    for (;;)
    {
        chacha8_wordtobyte(output, ctx->internal_state);
        ctx->internal_state[12] = MBEDTLS_CHACHA8_PLUSONE(ctx->internal_state[12]);
        for (i = 0; i < MBEDTLS_CHACHA8_KEYSTREAM_SEGMENT_SIZE; ++i)
        {
            ctx->current_keystream_buffer[i] = output[i];
        }
        ctx->unused_keystream_number_bytes = MBEDTLS_CHACHA8_KEYSTREAM_SEGMENT_SIZE;
        return;
    }
}

int mbedtls_chacha8_get_keystream_slice( mbedtls_chacha8_context *ctx, unsigned char *keystream_segment, const uint32_t number_of_bytes_this_run)
{
    uint32_t number_of_bytes_yet_to_fill;

    if (NULL == keystream_segment)
    {
        return -1;
    }

    memset(keystream_segment, 0x00, MBEDTLS_CHACHA8_KEYSTREAM_SEGMENT_SIZE);
    number_of_bytes_yet_to_fill = number_of_bytes_this_run;

    if (ctx->unused_keystream_number_bytes > 0)
    {
        /* Use part of the keystream present in the context */

        const uint32_t number_of_bytes_to_copy_from_internal_buffer = ctx->unused_keystream_number_bytes < number_of_bytes_this_run ?
                                                                      ctx->unused_keystream_number_bytes :
                                                                      number_of_bytes_this_run;

        memcpy(keystream_segment, ctx->current_keystream_buffer + ctx->keystream_buffer_offset, number_of_bytes_to_copy_from_internal_buffer);

        ctx->unused_keystream_number_bytes -= number_of_bytes_to_copy_from_internal_buffer;
        ctx->keystream_buffer_offset = ctx->unused_keystream_number_bytes;

        number_of_bytes_yet_to_fill -= number_of_bytes_to_copy_from_internal_buffer;
    }

    if (number_of_bytes_yet_to_fill > 0)
    {
        /* We've depleted the keystream store in the context but still need more. Generate a fresh block. */
        mbedtls_chacha8_generate_keystream_block(ctx);

        /* And copy the required number as above */
        memcpy(keystream_segment, ctx->current_keystream_buffer, number_of_bytes_yet_to_fill);
        ctx->unused_keystream_number_bytes = MBEDTLS_CHACHA8_KEYSTREAM_SEGMENT_SIZE - number_of_bytes_yet_to_fill;
        if (ctx->unused_keystream_number_bytes > 0)
        {
            ctx->keystream_buffer_offset = number_of_bytes_yet_to_fill;
        }
    }
    return  0;
}



#endif /* !MBEDTLS_CHACHA8_ALT */

#if defined(MBEDTLS_SELF_TEST)
/*
 * CHACHA test vectors as provided by Dan Bernstein
 */
static const unsigned char chacha_test_key[32] =
{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f
};
static const unsigned char chacha8_test_nonce[8] =
{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a
};
static const unsigned char chacha8_test_input[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e,
};
static const unsigned char chacha8_test_output[] = {
        0xc6, 0xcc, 0x3f, 0x46, 0x31, 0x78, 0x65, 0xb5, 0x80, 0x79, 0xe1, 0x9b, 0xbb, 0xce, 0x55, 0xf4,
        0xa6, 0x6a, 0xee, 0xe7, 0xa5, 0x0c, 0xa8, 0xad, 0x47, 0xb5, 0xa5, 0x58, 0x43, 0x38, 0x92, 0x70,
        0xb6, 0xb0, 0x0f, 0xd6, 0x0d, 0xfd, 0x3e, 0xfa, 0x34, 0x9a, 0x40, 0x7c, 0xec, 0xe3, 0xb8, 0x7f,
        0x74, 0x73, 0xfd, 0x0b, 0x6b, 0x3f, 0x66, 0x58, 0x50, 0x26, 0x5a, 0x27, 0x17, 0x40, 0x32, 0x8f,
        0x30, 0x6f, 0x9b, 0xf7, 0xa8, 0xe0, 0xc9, 0x68, 0xda, 0xf2, 0x43, 0x00, 0x14, 0x26, 0x4a, 0x87,
        0x6a, 0x4d, 0xff, 0xbe, 0x64, 0xce, 0x36, 0xb2, 0x41, 0xdf, 0xbe, 0x35, 0x44, 0x3f, 0x26, 0xa2,
        0x7b, 0x78, 0x06, 0x47, 0xe8, 0x38, 0x04, 0x93, 0x91, 0x55, 0x19, 0xc0, 0xad, 0xfb, 0x95, 0xaf,
        0xf7, 0xfe,
};

/*
 * Checkup routine
 */
int mbedtls_chacha8_self_test( int verbose )
{
    int ret = 0;
    size_t len = sizeof(chacha8_test_input);
    unsigned char ibuf[len];
    unsigned char obuf[len];
    mbedtls_chacha8_context ctx;

    mbedtls_chacha8_init( &ctx );

    if( verbose != 0 )
        mbedtls_printf( "  CHACHA8 test #%d: ", 1 );

    memcpy( ibuf, chacha8_test_input, len );

    mbedtls_chacha8_setup(&ctx, chacha_test_key, len);
    mbedtls_chacha8_set_iv(&ctx, chacha8_test_nonce);
    mbedtls_chacha8_crypt(&ctx, len, ibuf, obuf);

    if( memcmp( obuf, chacha8_test_output, len ) != 0)
    {
        if( verbose != 0 )
            mbedtls_printf( "failed\n" );

        ret = 1;
        goto exit;
    }

    if( verbose != 0 )
        mbedtls_printf( "passed\n" );

    mbedtls_printf( "\n" );

exit:
    mbedtls_chacha8_free( &ctx );

    return( ret );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_CHACHA8_C */
