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
 * Multiplication by u in the Galois field of GF(2^n)
 *
 * As explained in the paper, this can computed:
 * If MSB(p) = 0, then p = (p << 1)
 * If MSB(p) = 1, then p = (p << 1) ^ R_n
 * with R_64 = 0x1B and  R_128 = 0x87
 *
 * Input and output MUST not point to the same buffer
 * Block size must be 8 byes or 16 bytes.
 */
static int cmac_multiply_by_u( unsigned char *output,
                               const unsigned char *input,
							   size_t blocksize)
{

    const unsigned char R_128 = 0x87;
    const unsigned char R_64 = 0x1B;
    unsigned char R_n, mask;
    unsigned char overflow = 0x00;
    int i, starting_index;

    starting_index = blocksize -1;

    if(blocksize == 16){
        R_n = R_128;
    } else if(blocksize == 8) {
        R_n = R_64;
    } else {
        return MBEDTLS_ERR_CMAC_BAD_INPUT;
    }


    for( i = starting_index; i >= 0; i-- )
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

    output[starting_index] ^= R_n & mask;
    return 0;
}

/*
 * Generate subkeys
 */
static int cmac_generate_subkeys( mbedtls_cmac_context *ctx )
{
    int ret, keybytes;
    unsigned char *L;
    size_t olen, block_size;

    ret = 0;
    block_size = ctx->cipher_ctx.cipher_info->block_size;

    L = mbedtls_calloc(block_size, sizeof(unsigned char));

    /* Calculate Ek(0) */
    memset( L, 0, block_size );
    if( ( ret = mbedtls_cipher_update( &ctx->cipher_ctx,
                                       L, block_size, L, &olen ) ) != 0 )
    {
        goto exit;
    }

    /*
     * Generate K1 and K2
     */
    if( ( ret = cmac_multiply_by_u( ctx->K1, L , block_size) ) != 0 )
        goto exit;
    if( ( cmac_multiply_by_u( ctx->K2, ctx->K1 , block_size) ) != 0 )
        goto exit;

    exit:
        mbedtls_zeroize( L, sizeof( L ) );
		free(L);
        return ret;
}

/*
 * Set key and prepare context for use
 */
int mbedtls_cmac_setkey( mbedtls_cmac_context *ctx,
                         mbedtls_cipher_id_t cipher,
                         const unsigned char *key,
                         unsigned int keybits )
{
    int ret, blocksize;
    const mbedtls_cipher_info_t *cipher_info;

    cipher_info = mbedtls_cipher_info_from_values( cipher, keybits,
                                                   MBEDTLS_MODE_ECB );
    if( cipher_info == NULL )
        return( MBEDTLS_ERR_CMAC_BAD_INPUT );

    ctx->K1 = mbedtls_calloc( cipher_info->block_size, sizeof( unsigned char ) );
    ctx->K2 = mbedtls_calloc( cipher_info->block_size, sizeof( unsigned char ) );

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
	int block_size;
	block_size = ctx->cipher_ctx.cipher_info->block_size;

    mbedtls_cipher_free( &ctx->cipher_ctx );

    mbedtls_zeroize(ctx->K1, block_size * sizeof( unsigned char ) );
    mbedtls_zeroize(ctx->K2, block_size * sizeof( unsigned char ) );
    mbedtls_free( ctx->K1 );
    mbedtls_free( ctx->K2 );
}

/*
 * Create padded last block from (partial) last block.
 *
 * We can't use the padding option from the cipher layer, as it only works for
 * CBC and we use ECB mode, and anyway we need to XOR K1 or K2 in addition.
 */
static void cmac_pad( unsigned char padded_block[16],
		              size_t padded_block_len,
                      const unsigned char *last_block,
                      size_t last_block_len )
{
    size_t j;

    for( j = 0; j < padded_block_len; j++ )
    {
        if( j < last_block_len )
            padded_block[j] = last_block[j];
        else if( j == last_block_len )
            padded_block[j] = 0x80;
        else
            padded_block[j] = 0x00;
    }
}

/*
 * XOR Block
 * Here, macro results in smaller compiled code than static inline function
 */
#define XOR_BLOCK( o, i1, i2 )                                                \
    for( i = 0; i < block_size; i++ )                                         \
        ( o )[i] = ( i1 )[i] ^ ( i2 )[i];

/*
 * Update the CMAC state using an input block x
 */
#define UPDATE_CMAC( x )                                                    \
do {                                                                        \
    XOR_BLOCK( state, ( x ), state );                                       \
    if( ( ret = mbedtls_cipher_update( &ctx->cipher_ctx,                    \
                                       state, block_size,                   \
                                       state, &olen ) ) != 0 )              \
        return( ret );                                                      \
} while( 0 )

/*
 * Generate tag on complete message
 */
int mbedtls_cmac_generate( mbedtls_cmac_context *ctx,
                           const unsigned char *input, size_t in_len,
                           unsigned char *tag, size_t tag_len )

{

    unsigned char *state;
    unsigned char *M_last;
    int     n, i, j, ret, needs_padding;
    size_t olen, block_size;


    ret = 0;
    block_size = ctx->cipher_ctx.cipher_info->block_size;

    state = mbedtls_calloc(block_size,  sizeof(unsigned char) );
    M_last = mbedtls_calloc(block_size, sizeof(unsigned char) );

    /*
     * Check in_len requirements: SP800-38B A
     * 4 is a worst case bottom limit
     */
    if( tag_len < 4 || tag_len > block_size || tag_len % 2 != 0 )
        return( MBEDTLS_ERR_CMAC_BAD_INPUT );

    if( in_len == 0 )
        needs_padding = 1;
    else
        needs_padding = in_len % block_size != 0;

    n = in_len / block_size + needs_padding;

    /* Calculate last block */
    if( needs_padding )
    {
        cmac_pad( M_last, block_size, input + block_size * ( n - 1 ), in_len % block_size );
        XOR_BLOCK( M_last, M_last, ctx->K2 );
    }
    else
    {
        /* Last block is complete block */
        XOR_BLOCK( M_last, input + block_size * ( n - 1 ), ctx->K1 );
    }

    memset( state, 0, block_size );

    for( j = 0; j < n - 1; j++ )
        UPDATE_CMAC( input + block_size * j );

    UPDATE_CMAC( M_last );

    memcpy( tag, state, tag_len );

    exit:
        free(state);
        free(M_last);
        return( ret );
}

#undef XOR_BLOCK
#undef UPDATE_CMAC

/*
 * Verify tag on complete message
 */
int mbedtls_cmac_verify( mbedtls_cmac_context *ctx,
                         const unsigned char *input, size_t in_len,
                         const unsigned char *tag, size_t tag_len )
{
    int ret;
    unsigned char *check_tag;
    unsigned char i;
    int diff;

    check_tag = mbedtls_calloc(ctx->cipher_ctx.cipher_info->block_size,
                                sizeof(unsigned char) );

    if( ( ret = mbedtls_cmac_generate( ctx, input, in_len,
                                       check_tag, tag_len ) ) != 0 )
    {
        goto exit;
    }

    /* Check tag in "constant-time" */
    for( diff = 0, i = 0; i < tag_len; i++ )
        diff |= tag[i] ^ check_tag[i];

    if( diff != 0 )
        ret = MBEDTLS_ERR_CMAC_VERIFY_FAILED;
        goto exit;

    exit:
	    free(check_tag);
        return ret;
}

/*
 * PRF based on CMAC with AES-128
 * See RFC 4615
 */
int mbedtls_aes_cmac_prf_128( const unsigned char *key, size_t key_length,
                              const unsigned char *input, size_t in_len,
                              unsigned char *tag )
{
    int ret;
    mbedtls_cmac_context ctx;
    unsigned char zero_key[16];
    unsigned char int_key[16];

    mbedtls_cmac_init(&ctx);

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
            goto exit;

        ret = mbedtls_cmac_generate( &zero_ctx, key, key_length, int_key, 16 );
        if( ret != 0 )
            goto exit;
    }

    ret = mbedtls_cmac_setkey( &ctx, MBEDTLS_CIPHER_ID_AES,
                               int_key, 8 * sizeof int_key );
    if( ret != 0 )
        goto exit;

    mbedtls_zeroize( int_key, sizeof( int_key ) );

    ret =  mbedtls_cmac_generate( &ctx, input, in_len, tag, 16 );

    exit:
	     mbedtls_cmac_free(&ctx);
	     return( ret );


}

#ifdef MBEDTLS_SELF_TEST
/*
 * CMAC test data from SP800-38B Appendix D.1 (corrected)
 * http://csrc.nist.gov/publications/nistpubs/800-38B/Updated_CMAC_Examples.pdf
 *
 * AES-CMAC-PRF-128 test data from RFC 4615
 * https://tools.ietf.org/html/rfc4615#page-4
 */

#define NB_CMAC_TESTS_PER_KEY 4
#define NB_PRF_TESTS 3
#define AES_BLOCK_SIZE 16
#define DES3_BLOCK_SIZE 8

#if defined(MBEDTLS_AES_C) || defined(MBEDTLS_DES_C)
/* All CMAC test inputs are truncated from the same 64 byte buffer. */
static const unsigned char test_message[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
#endif /* defined(MBEDTLS_AES_C) || defined(MBEDTLS_DES_C) */

#ifdef MBEDTLS_AES_C
/* Truncation point of message for AES CMAC tests  */
static const size_t aes_message_lengths[NB_CMAC_TESTS_PER_KEY] = {
    0,
    16,
    40,
    64
};

/* AES 128 CMAC Test Data */
static const unsigned char aes_128_key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const unsigned char aes_128_subkeys[2][AES_BLOCK_SIZE] = {
    {
        0xfb, 0xee, 0xd6, 0x18, 0x35, 0x71, 0x33, 0x66,
        0x7c, 0x85, 0xe0, 0x8f, 0x72, 0x36, 0xa8, 0xde
    },
    {
        0xf7, 0xdd, 0xac, 0x30, 0x6a, 0xe2, 0x66, 0xcc,
        0xf9, 0x0b, 0xc1, 0x1e, 0xe4, 0x6d, 0x51, 0x3b
    }
};
static const unsigned char aes_128_expected_result[NB_CMAC_TESTS_PER_KEY][AES_BLOCK_SIZE] = {
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

/* AES 192 CMAC Test Data */
static const unsigned char aes_192_key[] = {
		0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
		0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
		0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
};
static const unsigned char aes_192_subkeys[2][AES_BLOCK_SIZE] = {
    {
        0x44, 0x8a, 0x5b, 0x1c, 0x93, 0x51, 0x4b, 0x27,
        0x3e, 0xe6, 0x43, 0x9d, 0xd4, 0xda, 0xa2, 0x96
    },
    {
        0x89, 0x14, 0xb6, 0x39, 0x26, 0xa2, 0x96, 0x4e,
        0x7d, 0xcc, 0x87, 0x3b, 0xa9, 0xb5, 0x45, 0x2c
    }
};
static const unsigned char aes_192_expected_result[NB_CMAC_TESTS_PER_KEY][AES_BLOCK_SIZE] = {
    {
        0xd1, 0x7d, 0xdf, 0x46, 0xad, 0xaa, 0xcd, 0xe5,
        0x31, 0xca, 0xc4, 0x83, 0xde, 0x7a, 0x93, 0x67
    },
    {
        0x9e, 0x99, 0xa7, 0xbf, 0x31, 0xe7, 0x10, 0x90,
        0x06, 0x62, 0xf6, 0x5e, 0x61, 0x7c, 0x51, 0x84
    },
    {
        0x8a, 0x1d, 0xe5, 0xbe, 0x2e, 0xb3, 0x1a, 0xad,
        0x08, 0x9a, 0x82, 0xe6, 0xee, 0x90, 0x8b, 0x0e
    },
    {
        0xa1, 0xd5, 0xdf, 0x0e, 0xed, 0x79, 0x0f, 0x79,
        0x4d, 0x77, 0x58, 0x96, 0x59, 0xf3, 0x9a, 0x11
    }
};

/* AES 256 CMAC Test Data */
static const unsigned char aes_256_key[] = {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};
static const unsigned char aes_256_subkeys[2][AES_BLOCK_SIZE] = {
    {
        0xca, 0xd1, 0xed, 0x03, 0x29, 0x9e, 0xed, 0xac,
        0x2e, 0x9a, 0x99, 0x80, 0x86, 0x21, 0x50, 0x2f
    },
    {
        0x95, 0xa3, 0xda, 0x06, 0x53, 0x3d, 0xdb, 0x58,
        0x5d, 0x35, 0x33, 0x01, 0x0c, 0x42, 0xa0, 0xd9
    }
};
static const unsigned char aes_256_expected_result[NB_CMAC_TESTS_PER_KEY][AES_BLOCK_SIZE] = {
    {
        0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e,
        0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67, 0xd9, 0x83
    },
    {
        0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82,
        0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3, 0x5c
    },
    {
        0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2,
        0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6
    },
    {
        0xe1, 0x99, 0x21, 0x90, 0x54, 0x9f, 0x6e, 0xd5,
        0x69, 0x6a, 0x2c, 0x05, 0x6c, 0x31, 0x54, 0x10
    }
};
#endif /* MBEDTLS_AES_C */

#ifdef MBEDTLS_DES_C
/* Truncation point of message for 3DES CMAC tests  */
static const size_t des3_message_lengths[NB_CMAC_TESTS_PER_KEY] = {
    0,
    8,
    20,
    32
};

/* 3DES 2 Key CMAC Test Data */
static const unsigned char des3_2key_key[] = {
		0x4c, 0xf1, 0x51, 0x34, 0xa2, 0x85, 0x0d, 0xd5,
		0x8a, 0x3d, 0x10, 0xba, 0x80, 0x57, 0x0d, 0x38,
		0x4c, 0xf1, 0x51, 0x34, 0xa2, 0x85, 0x0d, 0xd5
};
static const unsigned char des3_2key_subkeys[2][8] = {
    {
        0x8e, 0xcf, 0x37, 0x3e, 0xd7, 0x1a, 0xfa, 0xef
    },
    {
        0x1d, 0x9e, 0x6e, 0x7d, 0xae, 0x35, 0xf5, 0xc5
    }
};
static const unsigned char T_3des_2key[NB_CMAC_TESTS_PER_KEY][DES3_BLOCK_SIZE] = {
    {
        0xbd, 0x2e, 0xbf, 0x9a, 0x3b, 0xa0, 0x03, 0x61
    },
    {
        0x4f, 0xf2, 0xab, 0x81, 0x3c, 0x53, 0xce, 0x83
    },
    {
        0x62, 0xdd, 0x1b, 0x47, 0x19, 0x02, 0xbd, 0x4e
    },
    {
        0x31, 0xb1, 0xe4, 0x31, 0xda, 0xbc, 0x4e, 0xb8
    }
};

/* 3DES 3 Key CMAC Test Data */
static const unsigned char des3_3key_key[] = {
		0x8a, 0xa8, 0x3b, 0xf8, 0xcb, 0xda, 0x10, 0x62,
		0x0b, 0xc1, 0xbf, 0x19, 0xfb, 0xb6, 0xcd, 0x58,
		0xbc, 0x31, 0x3d, 0x4a, 0x37, 0x1c, 0xa8, 0xb5
};
static const unsigned char des3_3key_subkeys[2][8] = {
    {
        0x91, 0x98, 0xe9, 0xd3, 0x14, 0xe6, 0x53, 0x5f
    },
    {
        0x23, 0x31, 0xd3, 0xa6, 0x29, 0xcc, 0xa6, 0xa5
    }
};
static const unsigned char T_3des_3key[NB_CMAC_TESTS_PER_KEY][DES3_BLOCK_SIZE] = {
    {
        0xb7, 0xa6, 0x88, 0xe1, 0x22, 0xff, 0xaf, 0x95
    },
    {
        0x8e, 0x8f, 0x29, 0x31, 0x36, 0x28, 0x37, 0x97
    },
    {
        0x74, 0x3d, 0xdb, 0xe0, 0xce, 0x2d, 0xc2, 0xed
    },
    {
        0x33, 0xe6, 0xb1, 0x09, 0x24, 0x00, 0xea, 0xe5
    }
};

#endif /* MBEDTLS_DES_C */

#ifdef MBEDTLS_AES_C
/* AES AES-CMAC-PRF-128 Test Data */
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
#endif /* MBEDTLS_AES_C */

int test_cmac_with_cipher(int verbose,
		                  const unsigned char* testname,
		                  const unsigned char* key,
		                  int keybits,
		                  const unsigned char* messages,
		                  size_t message_lengths[4],
						  const unsigned char* subkeys,
						  const unsigned char* expected_result,
						  mbedtls_cipher_id_t cipher_id,
						  int block_size)
{
	const int num_tests = 4;
	mbedtls_cmac_context ctx;
    int i, ret;
    unsigned char* tag;

    tag = mbedtls_calloc( block_size, sizeof( unsigned char ) );
    mbedtls_cmac_init( &ctx );

    if( ( ret = mbedtls_cmac_setkey( &ctx, cipher_id, key, keybits ) ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "  CMAC: setup failed\n" );
        goto exit;
    }

    if( ( ret = memcmp( ctx.K1, subkeys, block_size ) != 0 ) ||
        ( ret = memcmp( ctx.K2, &subkeys[block_size], block_size ) != 0 ) )
    {
        if( verbose != 0 )
            mbedtls_printf( "  CMAC: subkey generation failed\n" );
        goto exit;
    }

    for( i = 0; i < num_tests; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  %s CMAC #%u: ", testname, i +1 );

        if( ( ret = mbedtls_cmac_generate( &ctx, messages, message_lengths[i], tag, block_size ) ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );
            goto exit;
        }
        if( ( ret = memcmp( tag, &expected_result[i * block_size], block_size ) ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );
            goto exit;
        }

        if( ( ret = mbedtls_cmac_verify( &ctx, messages, message_lengths[i], &expected_result[i * block_size], block_size ) != 0 ) )
        {
                if( verbose != 0 )
                    mbedtls_printf( "failed\n" );
                goto exit;
        }
        mbedtls_printf( "passed\n" );
    }
    exit:
        free( tag );
        mbedtls_cmac_free( &ctx );
        return( ret );
}

#ifdef MBEDTLS_AES_C
int test_aes128_cmac_prf( verbose ) {
    int i;
    int ret;
    unsigned char tag[16];
    for( i = 0; i < NB_PRF_TESTS; i++ )
    {
        mbedtls_printf( "  AES CMAC 128 PRF #%u: ", i );
        ret = mbedtls_aes_cmac_prf_128( PRFK, PRFKlen[i], PRFM, 20, tag );
        if( ret != 0 ||
            memcmp( tag, PRFT[i], 16 ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            return( ret );
        } else if( verbose != 0 )
        {
            mbedtls_printf( "passed\n" );
        }
    }
    return( ret );
}
#endif /* MBEDTLS_AES_C */

int mbedtls_cmac_self_test( int verbose )
{
    int ret;
    
#ifdef MBEDTLS_AES_C
    test_cmac_with_cipher(verbose,
                             "AES 128",
                              aes_128_key,
                              128,
                              test_message,
                              aes_message_lengths,
                              aes_128_subkeys,
                              aes_128_expected_result,
                              MBEDTLS_CIPHER_ID_AES,
                              AES_BLOCK_SIZE );

    test_cmac_with_cipher(verbose,
                             "AES 192",
                              aes_192_key,
                              192,
                              test_message,
                              aes_message_lengths,
                              aes_192_subkeys,
                              aes_192_expected_result,
                              MBEDTLS_CIPHER_ID_AES,
                              AES_BLOCK_SIZE );

    test_cmac_with_cipher(verbose,
                             "AES 256",
                              aes_256_key,
                              256,
                              test_message,
                              aes_message_lengths,
                              aes_256_subkeys,
                              aes_256_expected_result,
                              MBEDTLS_CIPHER_ID_AES,
                              AES_BLOCK_SIZE );
#endif /* MBEDTLS_AES_C */

#ifdef MBEDTLS_DES_C
    test_cmac_with_cipher(verbose,
                             "3DES 2 key",
                              des3_2key_key,
                              192,
                              test_message,
                              des3_message_lengths,
                              des3_2key_subkeys,
                              T_3des_2key,
                              MBEDTLS_CIPHER_ID_3DES,
                              DES3_BLOCK_SIZE );

    test_cmac_with_cipher(verbose,
                             "3DES 3 key",
                              des3_3key_key,
                              192,
                              test_message,
                              des3_message_lengths,
                              des3_3key_subkeys,
                              T_3des_3key,
                              MBEDTLS_CIPHER_ID_3DES,
                              DES3_BLOCK_SIZE );
#endif /* MBEDTLS_DES_C */

#ifdef MBEDTLS_AES_C
    test_aes128_cmac_prf( verbose );
#endif /* MBEDTLS_AES_C */

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( 0 );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_CMAC_C */
