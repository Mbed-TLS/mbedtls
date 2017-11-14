/*
 *  An implementation of the SALSA20 algorithm
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
 */


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_SALSA20_C)

#include "mbedtls/salsa20.h"

#include <string.h>
#include <mbedtls/salsa20.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#if !defined(MBEDTLS_SALSA20_ALT)

#define SALSA20_U8TO32_LITTLE(p) (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) <<  8) | \
                         ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
#define SALSA20_U32TO8_LITTLE(p, v) \
    do \
    { \
        (p)[0] = v; \
        (p)[1] = v >>  8; \
        (p)[2] = v >> 16; \
        (p)[3] = v >> 24; \
    } while (0)
#define SALSA20_ROTL32(v, n) (uint32_t)(((v) << (n)) | ((v) >> (32 - (n))))

#define SALSA20_SIGMA "expand 32-byte k"
#define SALSA20_TAU "expand 16-byte k"

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n )
{
    volatile unsigned char *p = (unsigned char*)v; while( n-- ) *p++ = 0;
}

void mbedtls_salsa20_init( mbedtls_salsa20_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_salsa20_context ) );
}

void mbedtls_salsa20_free( mbedtls_salsa20_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_zeroize( ctx, sizeof( mbedtls_salsa20_context ) );
}

void mbedtls_salsa20_reset_keystream_state( mbedtls_salsa20_context *ctx )
{
    ctx->keystream_buffer_offset = 0;
    ctx->unused_keystream_number_bytes = 0;
}

/*
 * SALSA20 key schedule
 */
void mbedtls_salsa20_setup( mbedtls_salsa20_context *ctx, const unsigned char *key,
                 const uint32_t keylen_bits )
{
    const char *constants;

    ctx->internal_state[1] = SALSA20_U8TO32_LITTLE(key + 0);
    ctx->internal_state[2] = SALSA20_U8TO32_LITTLE(key + 4);
    ctx->internal_state[3] = SALSA20_U8TO32_LITTLE(key + 8);
    ctx->internal_state[4] = SALSA20_U8TO32_LITTLE(key + 12);

    if (256 == keylen_bits)
    {
        key += 16;
        constants = SALSA20_SIGMA;
    }
    else
    {
        constants = SALSA20_TAU;
    }
    ctx->internal_state[11] = SALSA20_U8TO32_LITTLE(key + 0);
    ctx->internal_state[12] = SALSA20_U8TO32_LITTLE(key + 4);
    ctx->internal_state[13] = SALSA20_U8TO32_LITTLE(key + 8);
    ctx->internal_state[14] = SALSA20_U8TO32_LITTLE(key + 12);
    ctx->internal_state[0] = SALSA20_U8TO32_LITTLE(constants + 0);
    ctx->internal_state[5] = SALSA20_U8TO32_LITTLE(constants + 4);
    ctx->internal_state[10] = SALSA20_U8TO32_LITTLE(constants + 8);
    ctx->internal_state[15] = SALSA20_U8TO32_LITTLE(constants + 12);

    mbedtls_salsa20_reset_keystream_state( ctx );
}

/*
 * SALSA20 set IV
 */
void mbedtls_salsa20_set_iv( mbedtls_salsa20_context *ctx, const unsigned char *iv )
{
    ctx->internal_state[6] = SALSA20_U8TO32_LITTLE(iv + 0);
    ctx->internal_state[7] = SALSA20_U8TO32_LITTLE(iv + 4);
    ctx->internal_state[8] = 0;
    ctx->internal_state[9] = 0;
}

/*
 * SALSA20 cipher function
 */
#define SALSA20_KEYSTREAM_SEGMENT_SIZE 64
int mbedtls_salsa20_crypt( mbedtls_salsa20_context *ctx, size_t length, const unsigned char *input,
                unsigned char *output)
{
    unsigned char keystream_segment[SALSA20_KEYSTREAM_SEGMENT_SIZE];

    uint32_t number_bytes_crypted = 0;
    uint32_t segment_start_offset = 0;
    uint32_t number_of_bytes_this_run = 0;
    uint32_t lByte;

    while(number_bytes_crypted < length)
    {
        memset(keystream_segment, 0x00, SALSA20_KEYSTREAM_SEGMENT_SIZE);

        number_of_bytes_this_run = (length - number_bytes_crypted) < SALSA20_KEYSTREAM_SEGMENT_SIZE ? length - number_bytes_crypted : SALSA20_KEYSTREAM_SEGMENT_SIZE;

        mbedtls_salsa20_get_keystream_slice(ctx, keystream_segment, number_of_bytes_this_run);

        for ( lByte = 0; lByte < number_of_bytes_this_run; ++lByte )
        {
            output[segment_start_offset + lByte] = input[segment_start_offset + lByte] ^ keystream_segment[lByte];
        }

        number_bytes_crypted += number_of_bytes_this_run;
        segment_start_offset += number_of_bytes_this_run;
    }
    return 0;
}

int mbedtls_salsa20_get_keystream_slice( mbedtls_salsa20_context *ctx, unsigned char *keystream_segment, const uint32_t number_of_bytes_this_run)
{
    uint32_t number_of_bytes_yet_to_fill = number_of_bytes_this_run;

    if(NULL == keystream_segment)
    {
        return -1;
    }

    memset(keystream_segment, 0x00, SALSA20_KEYSTREAM_SEGMENT_SIZE);

    if(ctx->unused_keystream_number_bytes > 0)
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

    if( number_of_bytes_yet_to_fill > 0 )
    {
        /* We've depleted the keystream store in the context but still need more. Generate a fresh block. */
        mbedtls_salsa20_generate_keystream_block(ctx);

        /* And copy the required number as above */
        memcpy(keystream_segment, ctx->current_keystream_buffer, number_of_bytes_yet_to_fill);
        ctx->unused_keystream_number_bytes = SALSA20_KEYSTREAM_SEGMENT_SIZE - number_of_bytes_yet_to_fill;
        if(ctx->unused_keystream_number_bytes > 0)
        {
            ctx->keystream_buffer_offset = number_of_bytes_yet_to_fill;
        }
    }

    return 0;
}

#define SALSA20_ROTATE(v,c) (SALSA20_ROTL32(v,c))
#define SALSA20_XOR(v,w) ((v) ^ (w))
#define SALSA20_PLUS(v,w) ((uint32_t)((v) + (w)))
#define SALSA20_PLUSONE(v) (SALSA20_PLUS((v),1))

static void salsa20_wordtobyte(unsigned char output[64],const uint32_t input[16])
{
    uint32_t x[16];
    int i;

    for (i = 0;i < 16;++i)
    {
        x[i] = input[i];
    }
    for (i = 20;i > 0;i -= 2)
    {
        x[ 4] = SALSA20_XOR(x[ 4],SALSA20_ROTATE(SALSA20_PLUS(x[ 0],x[12]), 7));
        x[ 8] = SALSA20_XOR(x[ 8],SALSA20_ROTATE(SALSA20_PLUS(x[ 4],x[ 0]), 9));
        x[12] = SALSA20_XOR(x[12],SALSA20_ROTATE(SALSA20_PLUS(x[ 8],x[ 4]),13));
        x[ 0] = SALSA20_XOR(x[ 0],SALSA20_ROTATE(SALSA20_PLUS(x[12],x[ 8]),18));
        x[ 9] = SALSA20_XOR(x[ 9],SALSA20_ROTATE(SALSA20_PLUS(x[ 5],x[ 1]), 7));
        x[13] = SALSA20_XOR(x[13],SALSA20_ROTATE(SALSA20_PLUS(x[ 9],x[ 5]), 9));
        x[ 1] = SALSA20_XOR(x[ 1],SALSA20_ROTATE(SALSA20_PLUS(x[13],x[ 9]),13));
        x[ 5] = SALSA20_XOR(x[ 5],SALSA20_ROTATE(SALSA20_PLUS(x[ 1],x[13]),18));
        x[14] = SALSA20_XOR(x[14],SALSA20_ROTATE(SALSA20_PLUS(x[10],x[ 6]), 7));
        x[ 2] = SALSA20_XOR(x[ 2],SALSA20_ROTATE(SALSA20_PLUS(x[14],x[10]), 9));
        x[ 6] = SALSA20_XOR(x[ 6],SALSA20_ROTATE(SALSA20_PLUS(x[ 2],x[14]),13));
        x[10] = SALSA20_XOR(x[10],SALSA20_ROTATE(SALSA20_PLUS(x[ 6],x[ 2]),18));
        x[ 3] = SALSA20_XOR(x[ 3],SALSA20_ROTATE(SALSA20_PLUS(x[15],x[11]), 7));
        x[ 7] = SALSA20_XOR(x[ 7],SALSA20_ROTATE(SALSA20_PLUS(x[ 3],x[15]), 9));
        x[11] = SALSA20_XOR(x[11],SALSA20_ROTATE(SALSA20_PLUS(x[ 7],x[ 3]),13));
        x[15] = SALSA20_XOR(x[15],SALSA20_ROTATE(SALSA20_PLUS(x[11],x[ 7]),18));
        x[ 1] = SALSA20_XOR(x[ 1],SALSA20_ROTATE(SALSA20_PLUS(x[ 0],x[ 3]), 7));
        x[ 2] = SALSA20_XOR(x[ 2],SALSA20_ROTATE(SALSA20_PLUS(x[ 1],x[ 0]), 9));
        x[ 3] = SALSA20_XOR(x[ 3],SALSA20_ROTATE(SALSA20_PLUS(x[ 2],x[ 1]),13));
        x[ 0] = SALSA20_XOR(x[ 0],SALSA20_ROTATE(SALSA20_PLUS(x[ 3],x[ 2]),18));
        x[ 6] = SALSA20_XOR(x[ 6],SALSA20_ROTATE(SALSA20_PLUS(x[ 5],x[ 4]), 7));
        x[ 7] = SALSA20_XOR(x[ 7],SALSA20_ROTATE(SALSA20_PLUS(x[ 6],x[ 5]), 9));
        x[ 4] = SALSA20_XOR(x[ 4],SALSA20_ROTATE(SALSA20_PLUS(x[ 7],x[ 6]),13));
        x[ 5] = SALSA20_XOR(x[ 5],SALSA20_ROTATE(SALSA20_PLUS(x[ 4],x[ 7]),18));
        x[11] = SALSA20_XOR(x[11],SALSA20_ROTATE(SALSA20_PLUS(x[10],x[ 9]), 7));
        x[ 8] = SALSA20_XOR(x[ 8],SALSA20_ROTATE(SALSA20_PLUS(x[11],x[10]), 9));
        x[ 9] = SALSA20_XOR(x[ 9],SALSA20_ROTATE(SALSA20_PLUS(x[ 8],x[11]),13));
        x[10] = SALSA20_XOR(x[10],SALSA20_ROTATE(SALSA20_PLUS(x[ 9],x[ 8]),18));
        x[12] = SALSA20_XOR(x[12],SALSA20_ROTATE(SALSA20_PLUS(x[15],x[14]), 7));
        x[13] = SALSA20_XOR(x[13],SALSA20_ROTATE(SALSA20_PLUS(x[12],x[15]), 9));
        x[14] = SALSA20_XOR(x[14],SALSA20_ROTATE(SALSA20_PLUS(x[13],x[12]),13));
        x[15] = SALSA20_XOR(x[15],SALSA20_ROTATE(SALSA20_PLUS(x[14],x[13]),18));
    }
    for (i = 0;i < 16;++i)
    {
        x[i] = SALSA20_PLUS(x[i],input[i]);
    }
    for (i = 0;i < 16;++i)
    {
        SALSA20_U32TO8_LITTLE(output + 4 * i,x[i]);
    }
}


void mbedtls_salsa20_generate_keystream_block( mbedtls_salsa20_context *ctx )
{
    unsigned char output[SALSA20_KEYSTREAM_SEGMENT_SIZE];
    int i;

    for (;;)
    {
        salsa20_wordtobyte(output,ctx->internal_state);
        ctx->internal_state[8] = SALSA20_PLUSONE(ctx->internal_state[8]);
        if (!ctx->internal_state[8])
        {
            ctx->internal_state[9] = SALSA20_PLUSONE(ctx->internal_state[9]);
        }
            for (i = 0;i < SALSA20_KEYSTREAM_SEGMENT_SIZE;++i)
            {
                ctx->current_keystream_buffer[i] = output[i];
            }
            ctx->unused_keystream_number_bytes = SALSA20_KEYSTREAM_SEGMENT_SIZE;
            return;
    }
}

#endif /* !MBEDTLS_SALSA20_ALT */

#if defined(MBEDTLS_SELF_TEST)
/*
 * SALSA20 test vectors as provided by Dan Bernstein
 */

static const unsigned int mbedtls_salsa20_test_bits[] =
{
    128,
    128,
    128,
    256,
    256,
    256
};

static const unsigned char mbedtls_salsa20_test_key[][32] =
{
    { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x53, 0xA6, 0xF9, 0x4C, 0x9F, 0xF2, 0x45, 0x98, 0xEB, 0x3E, 0x91, 0xE4, 0x37, 0x8A, 0xDD },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x53, 0xA6, 0xF9, 0x4C, 0x9F, 0xF2, 0x45, 0x98, 0xEB, 0x3E, 0x91, 0xE4, 0x37, 0x8A, 0xDD, 0x30, 0x83, 0xD6, 0x29, 0x7C, 0xCF, 0x22, 0x75, 0xC8, 0x1B, 0x6E, 0xC1, 0x14, 0x67, 0xBA, 0x0D },
    { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

static const unsigned char mbedtls_salsa20_test_iv[][8] =
{
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x0D, 0x74, 0xDB, 0x42, 0xA9, 0x10, 0x77, 0xDE },
    { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x0D, 0x74, 0xDB, 0x42, 0xA9, 0x10, 0x77, 0xDE },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

static const unsigned char mbedtls_salsa20_test_pt[][8] =
{
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

static const unsigned char mbedtls_salsa20_test_ct[][8] =
{
    { 0x4D, 0xFA, 0x5E, 0x48, 0x1D, 0xA2, 0x3E, 0xA0 },
    { 0x05, 0xE1, 0xE7, 0xBE, 0xB6, 0x97, 0xD9, 0x99 },
    { 0xB6, 0x6C, 0x1E, 0x44, 0x46, 0xDD, 0x95, 0x57 },
    { 0xF5, 0xFA, 0xD5, 0x3F, 0x79, 0xF9, 0xDF, 0x58 },
    { 0xE3, 0xBE, 0x8F, 0xDD, 0x8B, 0xEC, 0xA2, 0xE3 },
    { 0x2A, 0xBA, 0x3D, 0xC4, 0x5B, 0x49, 0x47, 0x00 }
};

/*
 * Checkup routine
 */
int mbedtls_salsa20_self_test( int verbose )
{
    int i, ret = 0;
    unsigned char ibuf[8];
    unsigned char obuf[8];
    int amount = sizeof(mbedtls_salsa20_test_bits) / sizeof(unsigned int);

    mbedtls_salsa20_context ctx;

    mbedtls_salsa20_init( &ctx );

    mbedtls_printf("%d", amount);

    for( i = 0; i < amount; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  SALSA20 test #%d: ", i + 1 );

        memcpy( ibuf, mbedtls_salsa20_test_pt[i], 8 );

        mbedtls_salsa20_setup( &ctx, mbedtls_salsa20_test_key[i], mbedtls_salsa20_test_bits[i] );
        mbedtls_salsa20_set_iv( &ctx, mbedtls_salsa20_test_iv[i] );
        mbedtls_salsa20_crypt( &ctx, 8, ibuf, obuf );

        if( memcmp( obuf, mbedtls_salsa20_test_ct[i], 8 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            ret = 1;
            goto exit;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );

exit:
    mbedtls_salsa20_free( &ctx );

    return( ret );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_SALSA20_C */
