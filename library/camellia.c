/*
 *  Camellia implementation
 *
 *  Copyright (C) 2009       Paul Bakker
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  The Camellia block cipher was designed by NTT and Mitsubishi Electric
 *  Corporation.
 *
 *  http://info.isl.ntt.co.jp/crypt/eng/camellia/dl/01espec.pdf
 */

#include "polarssl/config.h"

#if defined(POLARSSL_CAMELLIA_C)

#include "polarssl/camellia.h"

#include <string.h>

#include <stdio.h> /* TEMP */
int verbose = 0;


/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
	| ( (unsigned long) (b)[(i) + 1] << 16 )        \
	| ( (unsigned long) (b)[(i) + 2] <<  8 )        \
	| ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

static const unsigned char SIGMA_CHARS[6][8] =
{
	{ 0xa0, 0x9e, 0x66, 0x7f, 0x3b, 0xcc, 0x90, 0x8b },
	{ 0xb6, 0x7a, 0xe8, 0x58, 0x4c, 0xaa, 0x73, 0xb2 },
	{ 0xc6, 0xef, 0x37, 0x2f, 0xe9, 0x4f, 0x82, 0xbe },
	{ 0x54, 0xff, 0x53, 0xa5, 0xf1, 0xd3, 0x6f, 0x1c },
	{ 0x10, 0xe5, 0x27, 0xfa, 0xde, 0x68, 0x2d, 0x1d },
	{ 0xb0, 0x56, 0x88, 0xc2, 0xb3, 0xe6, 0xc1, 0xfd }
};

static const unsigned char FSb[256] =
{
	112,130, 44,236,179, 39,192,229,228,133, 87, 53,234, 12,174, 65,
	 35,239,107,147, 69, 25,165, 33,237, 14, 79, 78, 29,101,146,189,
	134,184,175,143,124,235, 31,206, 62, 48,220, 95, 94,197, 11, 26,
	166,225, 57,202,213, 71, 93, 61,217,  1, 90,214, 81, 86,108, 77,
	139, 13,154,102,251,204,176, 45,116, 18, 43, 32,240,177,132,153,
	223, 76,203,194, 52,126,118,  5,109,183,169, 49,209, 23,  4,215,
	 20, 88, 58, 97,222, 27, 17, 28, 50, 15,156, 22, 83, 24,242, 34,
	254, 68,207,178,195,181,122,145, 36,  8,232,168, 96,252,105, 80,
	170,208,160,125,161,137, 98,151, 84, 91, 30,149,224,255,100,210,
	 16,196,  0, 72,163,247,117,219,138,  3,230,218,  9, 63,221,148,
	135, 92,131,  2,205, 74,144, 51,115,103,246,243,157,127,191,226,
	 82,155,216, 38,200, 55,198, 59,129,150,111, 75, 19,190, 99, 46,
	233,121,167,140,159,110,188,142, 41,245,249,182, 47,253,180, 89,
	120,152,  6,106,231, 70,113,186,212, 37,171, 66,136,162,141,250,
	114,  7,185, 85,248,238,172, 10, 54, 73, 42,104, 60, 56,241,164,
	 64, 40,211,123,187,201, 67,193, 21,227,173,244,119,199,128,158
};

#define SBOX1(n) FSb[(n)]
#define SBOX2(n) (unsigned char)((FSb[(n)] >> 7 ^ FSb[(n)] << 1) & 0xff)
#define SBOX3(n) (unsigned char)((FSb[(n)] >> 1 ^ FSb[(n)] << 7) & 0xff)
#define SBOX4(n) FSb[((n) << 1 ^ (n) >> 7) &0xff]

static const unsigned char shifts[2][4][4] =
{
	{
		{ 1, 1, 1, 1 },	/* KL */
		{ 0, 0, 0, 0 }, /* KR */
		{ 1, 1, 1, 1 }, /* KA */
		{ 0, 0, 0, 0 }  /* KB */
	},
	{
		{ 1, 0, 1, 1 },	/* KL */
		{ 1, 1, 0, 1 }, /* KR */
		{ 1, 1, 1, 0 }, /* KA */
		{ 1, 1, 0, 1 }  /* KB */
	}
};

static const char indexes[2][4][20] =
{
	{
		{  0,  1,  2,  3,  8,  9, 10, 11, 38, 39,
		  36, 37, 23, 20, 21, 22, 27, -1, -1, 26 },	/* KL -> RK */
		{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 },	/* KR -> RK */
		{  4,  5,  6,  7, 12, 13, 14, 15, 16, 17,
		  18, 19, -1, 24, 25, -1, 31, 28, 29, 30 },	/* KA -> RK */
		{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 }	/* KB -> RK */
	},
	{
		{  0,  1,  2,  3, 61, 62, 63, 60, -1, -1,
		  -1, -1, 27, 24, 25, 26, 35, 32, 33, 34 },	/* KL -> RK */
		{ -1, -1, -1, -1,  8,  9, 10, 11, 16, 17,
		  18, 19, -1, -1, -1, -1, 39, 36, 37, 38 },	/* KR -> RK */
		{ -1, -1, -1, -1, 12, 13, 14, 15, 58, 59,
		  56, 57, 31, 28, 29, 30, -1, -1, -1, -1 },	/* KA -> RK */
		{  4,  5,  6,  7, 65, 66, 67, 64, 20, 21,
		  22, 23, -1, -1, -1, -1, 43, 40, 41, 42 }	/* KB -> RK */
	}
};

static const char transposes[2][20] =
{
	{
		21, 22, 23, 20,
		-1, -1, -1, -1,
		18, 19, 16, 17,
		11,  8,  9, 10,
		15, 12, 13, 14
	},
	{
		25, 26, 27, 24,
		29, 30, 31, 28,
		18, 19, 16, 17,
		-1, -1, -1, -1,
		-1, -1, -1, -1
	}
};

/* Shift macro for smaller than 32 bits (!) */
#define ROTL(DEST, SRC, SHIFT)						\
{									\
	(DEST)[0] = (SRC)[0] << (SHIFT) ^ (SRC)[1] >> (32 - (SHIFT));	\
	(DEST)[1] = (SRC)[1] << (SHIFT) ^ (SRC)[2] >> (32 - (SHIFT));	\
	(DEST)[2] = (SRC)[2] << (SHIFT) ^ (SRC)[3] >> (32 - (SHIFT));	\
	(DEST)[3] = (SRC)[3] << (SHIFT) ^ (SRC)[0] >> (32 - (SHIFT));	\
}

#define FL(XL, XR, KL, KR)						\
{									\
	(XR) = ((((XL) & (KL)) << 1) | (((XL) & (KL)) >> 31)) ^ (XR);	\
	(XL) = ((XR) | (KR)) ^ (XL);					\
}
	
#define FLInv(YL, YR, KL, KR)						\
{									\
	(YL) = ((YR) | (KR)) ^ (YL);					\
	(YR) = ((((YL) & (KL)) << 1) | (((YL) & (KL)) >> 31)) ^ (YR);	\
}
	
#define SHIFT_AND_PLACE(INDEX, OFFSET)					\
{									\
    TK[0] = KC[(OFFSET) * 4 + 0];					\
    TK[1] = KC[(OFFSET) * 4 + 1];					\
    TK[2] = KC[(OFFSET) * 4 + 2];					\
    TK[3] = KC[(OFFSET) * 4 + 3];					\
									\
    for ( i = 1; i <= 4; i++ )						\
    	if (shifts[(INDEX)][(OFFSET)][i -1])				\
	    	ROTL(TK + i * 4, TK, (15 * i) % 32);			\
    									\
    for ( i = 0; i < 20; i++ )						\
    	if (indexes[(INDEX)][(OFFSET)][i] != -1) {			\
		RK[indexes[(INDEX)][(OFFSET)][i]] = TK[ i ];		\
	}								\
}

void camellia_feistel(unsigned long x[2], unsigned long k[2], unsigned long z[2])
{
	unsigned char t[8];
	if (verbose >= 2)
		printf("FEISTEL: X: %08x%08x K: %08x%08x ", x[0], x[1], k[0], k[1]);

	t[0] = SBOX1(((x[0] ^ k[0]) >> 24) & 0xFF);
	t[1] = SBOX2(((x[0] ^ k[0]) >> 16) & 0xFF);
	t[2] = SBOX3(((x[0] ^ k[0]) >>  8) & 0xFF);
	t[3] = SBOX4(((x[0] ^ k[0])      ) & 0xFF);
	t[4] = SBOX2(((x[1] ^ k[1]) >> 24) & 0xFF);
	t[5] = SBOX3(((x[1] ^ k[1]) >> 16) & 0xFF);
	t[6] = SBOX4(((x[1] ^ k[1]) >>  8) & 0xFF);
	t[7] = SBOX1(((x[1] ^ k[1])      ) & 0xFF);

	z[0] ^= ((t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7]) << 24) |
	        ((t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7]) << 16) |
	        ((t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7]) <<  8) |
	        ((t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6])      );
	z[1] ^= ((t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7]) << 24) |
	        ((t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7]) << 16) |
		((t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7]) <<  8) |
		((t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6])      );

	if (verbose >= 2)
		printf("Z: %08x%08x\n", z[0], z[1]);
}

/*
 * Camellia key schedule (encryption)
 */
void camellia_setkey_enc( camellia_context *ctx, unsigned char *key, int keysize )
{
    int i, idx;
    unsigned long *RK;
    unsigned char t[64];

    RK = ctx->rk;

    memset(t, 0, 64);
    memset(RK, 0, sizeof(ctx->rk));

    switch( keysize )
    {
        case 128: ctx->nr = 3; idx = 0; break;
        case 192:
	case 256: ctx->nr = 4; idx = 1; break;
        default : return;
    }

    for( i = 0; i < keysize / 8; ++i)
	    t[i] = key[i];

    if (keysize == 192) {
	    for (i = 0; i < 8; i++)
		    t[24 + i] = ~t[16 + i];
    }

    if (verbose >= 2)
    	printf("\nKey schedule (enc)\n");

    /*
     * Prepare SIGMA values
     */
    unsigned long SIGMA[6][2];
    for (i = 0; i < 6; i++) {
    	GET_ULONG_BE(SIGMA[i][0], SIGMA_CHARS[i], 0);
    	GET_ULONG_BE(SIGMA[i][1], SIGMA_CHARS[i], 4);
    }

    /*
     * Key storage in KC
     * Order: KL, KR, KA, KB
     */
    unsigned long KC[16];
    memset(KC, 0, sizeof(KC));

    /* Store KL, KR */
    for (i = 0; i < 8; i++)
    	GET_ULONG_BE(KC[i], t, i * 4);

    /* Generate KA */
    for( i = 0; i < 4; ++i)
    	KC[8 + i] = KC[i] ^ KC[4 + i];

    camellia_feistel(KC + 8, SIGMA[0], KC + 10);
    camellia_feistel(KC + 10, SIGMA[1], KC + 8);

    for( i = 0; i < 4; ++i)
    	KC[8 + i] ^= KC[i];

    camellia_feistel(KC + 8, SIGMA[2], KC + 10);
    camellia_feistel(KC + 10, SIGMA[3], KC + 8);

    if (keysize > 128) {
	    /* Generate KB */
	    for( i = 0; i < 4; ++i)
		    KC[12 + i] = KC[4 + i] ^ KC[8 + i];

	    camellia_feistel(KC + 12, SIGMA[4], KC + 14);
	    camellia_feistel(KC + 14, SIGMA[5], KC + 12);
    }

    /*
     * Generating subkeys
     */ 
    unsigned long TK[20];

    /* Manipulating KL */
    SHIFT_AND_PLACE(idx, 0);

    /* Manipulating KR */
    if (keysize > 128) {
	    SHIFT_AND_PLACE(idx, 1);
    }

    /* Manipulating KA */
    SHIFT_AND_PLACE(idx, 2);

    /* Manipulating KB */
    if (keysize > 128) {
	    SHIFT_AND_PLACE(idx, 3);
    }

    /* Do transpositions */
    for ( i = 0; i < 20; i++ ) {
	    if (transposes[idx][i] != -1) {
		    RK[32 + 12 * idx + i] = RK[transposes[idx][i]];
	    }
    }

    if (verbose >= 3)
	    for (i = 0; i < 26 + 8 * idx; ++i)
		    printf("RK[%d]: %08x%08x\n", i * 2, ctx->rk[i * 2 + 0], ctx->rk[i * 2 + 1]);
}

/*
 * Camellia key schedule (decryption)
 */
void camellia_setkey_dec( camellia_context *ctx, unsigned char *key, int keysize )
{
    int i, idx;
    camellia_context cty;
    unsigned long *RK;
    unsigned long *SK;

    switch( keysize )
    {
        case 128: ctx->nr = 3; idx = 0; break;
        case 192:
        case 256: ctx->nr = 4; idx = 1; break;
        default : return;
    }

    RK = ctx->rk;

    camellia_setkey_enc(&cty, key, keysize);

    SK = cty.rk + 24 * 2 + 8 * idx * 2;

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

    for (i = 22 + 8 * idx, SK -= 6; i > 0; i--, SK -= 4)
    {
    	*RK++ = *SK++;
    	*RK++ = *SK++;
    }

    SK -= 2;

    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;
    *RK++ = *SK++;

    memset( &cty, 0, sizeof( camellia_context ) );

    if (verbose >= 3)
	    for (i = 0; i < 26 + 8 * idx; ++i)
		printf("RK[%d]: %08x%08x\n", i * 2, ctx->rk[i * 2 + 0], ctx->rk[i * 2 + 1]);
	    	
}

/*
 * Camellia-ECB block encryption/decryption
 */
void camellia_crypt_ecb( camellia_context *ctx,
                    int mode,
                    unsigned char input[16],
                    unsigned char output[16] )
{
    int i, NR;
    unsigned long *RK, X[4], Y[4], T;

    NR = ctx->nr;
    RK = ctx->rk;

    if (verbose >= 2)
    	printf("\nCrypt\n");

    GET_ULONG_BE( X[0], input,  0 );
    GET_ULONG_BE( X[1], input,  4 );
    GET_ULONG_BE( X[2], input,  8 );
    GET_ULONG_BE( X[3], input, 12 );

    X[0] ^= *RK++;
    X[1] ^= *RK++;
    X[2] ^= *RK++;
    X[3] ^= *RK++;

    while (NR) {
    	--NR;
	camellia_feistel(X, RK, X + 2);
	RK += 2;
	camellia_feistel(X + 2, RK, X);
	RK += 2;
	camellia_feistel(X, RK, X + 2);
	RK += 2;
	camellia_feistel(X + 2, RK, X);
	RK += 2;
	camellia_feistel(X, RK, X + 2);
	RK += 2;
	camellia_feistel(X + 2, RK, X);
	RK += 2;

	if (NR) {
		FL(X[0], X[1], RK[0], RK[1]);
		RK += 2;
		FLInv(X[2], X[3], RK[0], RK[1]);
		RK += 2;
	}
    }

    X[2] ^= *RK++;
    X[3] ^= *RK++;
    X[0] ^= *RK++;
    X[1] ^= *RK++;

    PUT_ULONG_BE( X[2], output,  0 );
    PUT_ULONG_BE( X[3], output,  4 );
    PUT_ULONG_BE( X[0], output,  8 );
    PUT_ULONG_BE( X[1], output, 12 );
}

/*
 * Camellia-CBC buffer encryption/decryption
 */
void camellia_crypt_cbc( camellia_context *ctx,
                    int mode,
                    int length,
                    unsigned char iv[16],
                    unsigned char *input,
                    unsigned char *output )
{
    int i;
    unsigned char temp[16];

    if( mode == CAMELLIA_DECRYPT )
    {
        while( length > 0 )
        {
            memcpy( temp, input, 16 );
            camellia_crypt_ecb( ctx, mode, input, output );

            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
    else
    {
        while( length > 0 )
        {
            for( i = 0; i < 16; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            camellia_crypt_ecb( ctx, mode, output, output );
            memcpy( iv, output, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
}

/*
 * Camellia-CFB128 buffer encryption/decryption
 */
void camellia_crypt_cfb128( camellia_context *ctx,
                       int mode,
                       int length,
                       int *iv_off,
                       unsigned char iv[16],
                       unsigned char *input,
                       unsigned char *output )
{
    int c, n = *iv_off;

    if( mode == CAMELLIA_DECRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
                camellia_crypt_ecb( ctx, CAMELLIA_ENCRYPT, iv, iv );

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char) c;

            n = (n + 1) & 0x0F;
        }
    }
    else
    {
        while( length-- )
        {
            if( n == 0 )
                camellia_crypt_ecb( ctx, CAMELLIA_ENCRYPT, iv, iv );

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = (n + 1) & 0x0F;
        }
    }

    *iv_off = n;
}

#if defined(POLARSSL_SELF_TEST)

#include <stdio.h>

/*
 * Camellia test vectors from:
 *
 * http://info.isl.ntt.co.jp/crypt/eng/camellia/technology.html:
 *   http://info.isl.ntt.co.jp/crypt/eng/camellia/dl/cryptrec/intermediate.txt
 *   http://info.isl.ntt.co.jp/crypt/eng/camellia/dl/cryptrec/t_camellia.txt
 *   					(For each bitlength: Key 0, Nr 39)
 */
#define CAMELLIA_TESTS_ECB	2

static const unsigned char camellia_test_ecb_key[3][CAMELLIA_TESTS_ECB][32] =
{
	{
	    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 },
	    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
	},
	{
	    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 },
	    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
	},
	{
	    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff },
	    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
	},
};

static const unsigned char camellia_test_ecb_plain[CAMELLIA_TESTS_ECB][16] =
{
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 },
    { 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

static const unsigned char camellia_test_ecb_cipher[3][CAMELLIA_TESTS_ECB][16] =
{
	{
	    { 0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
	      0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43 },
	    { 0x38, 0x3C, 0x6C, 0x2A, 0xAB, 0xEF, 0x7F, 0xDE,
	      0x25, 0xCD, 0x47, 0x0B, 0xF7, 0x74, 0xA3, 0x31 }
	},
	{
	    { 0xb4, 0x99, 0x34, 0x01, 0xb3, 0xe9, 0x96, 0xf8,
	      0x4e, 0xe5, 0xce, 0xe7, 0xd7, 0x9b, 0x09, 0xb9 },
	    { 0xD1, 0x76, 0x3F, 0xC0, 0x19, 0xD7, 0x7C, 0xC9,
	      0x30, 0xBF, 0xF2, 0xA5, 0x6F, 0x7C, 0x93, 0x64 }
	},
	{
	    { 0x9a, 0xcc, 0x23, 0x7d, 0xff, 0x16, 0xd7, 0x6c,
	      0x20, 0xef, 0x7c, 0x91, 0x9e, 0x3a, 0x75, 0x09 },
	    { 0x05, 0x03, 0xFB, 0x10, 0xAB, 0x24, 0x1E, 0x7C,
	      0xF4, 0x5D, 0x8C, 0xDE, 0xEE, 0x47, 0x43, 0x35 }
	}
};

#define CAMELLIA_TESTS_CBC	3

static const unsigned char camellia_test_cbc_key[3][32] =
{
	    { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
	      0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C }
	,
	    { 0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52,
	      0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
	      0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B }
	,
	    { 0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
	      0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
	      0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
	      0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4 }
};

static const unsigned char camellia_test_cbc_iv[16] =

    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F }
;

static const unsigned char camellia_test_cbc_plain[CAMELLIA_TESTS_CBC][16] =
{
    { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
      0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A },
    { 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
      0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51 },
    { 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11,
      0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF }

};

static const unsigned char camellia_test_cbc_cipher[3][CAMELLIA_TESTS_CBC][16] =
{
	{
	    { 0x16, 0x07, 0xCF, 0x49, 0x4B, 0x36, 0xBB, 0xF0,
	      0x0D, 0xAE, 0xB0, 0xB5, 0x03, 0xC8, 0x31, 0xAB },
	    { 0xA2, 0xF2, 0xCF, 0x67, 0x16, 0x29, 0xEF, 0x78,
	      0x40, 0xC5, 0xA5, 0xDF, 0xB5, 0x07, 0x48, 0x87 },
	    { 0x0F, 0x06, 0x16, 0x50, 0x08, 0xCF, 0x8B, 0x8B,
	      0x5A, 0x63, 0x58, 0x63, 0x62, 0x54, 0x3E, 0x54 }
	},
	{
	    { 0x2A, 0x48, 0x30, 0xAB, 0x5A, 0xC4, 0xA1, 0xA2,
	      0x40, 0x59, 0x55, 0xFD, 0x21, 0x95, 0xCF, 0x93 },
	    { 0x5D, 0x5A, 0x86, 0x9B, 0xD1, 0x4C, 0xE5, 0x42,
	      0x64, 0xF8, 0x92, 0xA6, 0xDD, 0x2E, 0xC3, 0xD5 },
	    { 0x37, 0xD3, 0x59, 0xC3, 0x34, 0x98, 0x36, 0xD8,
	      0x84, 0xE3, 0x10, 0xAD, 0xDF, 0x68, 0xC4, 0x49 }
	},
	{
	    { 0xE6, 0xCF, 0xA3, 0x5F, 0xC0, 0x2B, 0x13, 0x4A,
	      0x4D, 0x2C, 0x0B, 0x67, 0x37, 0xAC, 0x3E, 0xDA },
	    { 0x36, 0xCB, 0xEB, 0x73, 0xBD, 0x50, 0x4B, 0x40,
	      0x70, 0xB1, 0xB7, 0xDE, 0x2B, 0x21, 0xEB, 0x50 },
	    { 0xE3, 0x1A, 0x60, 0x55, 0x29, 0x7D, 0x96, 0xCA,
	      0x33, 0x30, 0xCD, 0xF1, 0xB1, 0x86, 0x0A, 0x83 }
	}
};


/*
 * Checkup routine
 */
int camellia_self_test( int verbose )
{
    int i, j, u, v, offset;
    unsigned char key[32];
    unsigned char buf[64];
    unsigned char prv[16];
    unsigned char src[16];
    unsigned char dst[16];
    unsigned char iv[16];
    camellia_context ctx;

    memset( key, 0, 32 );

    for (j = 0; j < 6; j++) {
    	u = j >> 1;
	v = j & 1;

	if( verbose != 0 )
		printf( "  CAMELLIA-ECB-%3d (%s): ", 128 + u * 64,
				(v == CAMELLIA_DECRYPT) ? "dec" : "enc");

	for (i = 0; i < CAMELLIA_TESTS_ECB; i++ ) {
		memcpy( key, camellia_test_ecb_key[u][i], 16 + 8 * u);

		if (v == CAMELLIA_DECRYPT) {
			camellia_setkey_dec(&ctx, key, 128 + u * 64);
			memcpy(src, camellia_test_ecb_cipher[u][i], 16);
			memcpy(dst, camellia_test_ecb_plain[i], 16);
		} else { /* CAMELLIA_ENCRYPT */
			camellia_setkey_enc(&ctx, key, 128 + u * 64);
			memcpy(src, camellia_test_ecb_plain[i], 16);
			memcpy(dst, camellia_test_ecb_cipher[u][i], 16);
		}

		camellia_crypt_ecb(&ctx, v, src, buf);

		if( memcmp( buf, dst, 16 ) != 0 )
		{
			if( verbose != 0 )
				printf( "failed\n" );

			return( 1 );
		}
	}

	if( verbose != 0 )
		printf( "passed\n" );
    }

    if( verbose != 0 )
        printf( "\n" );

    /*
     * CBC mode
     */
    for( j = 0; j < 6; j++ )
    {
        u = j >> 1;
        v = j  & 1;

        if( verbose != 0 )
            printf( "  CAMELLIA-CBC-%3d (%s): ", 128 + u * 64,
                    ( v == CAMELLIA_DECRYPT ) ? "dec" : "enc" );

	memcpy( src, camellia_test_cbc_iv, 16);
	memcpy( dst, camellia_test_cbc_iv, 16);
	memcpy( key, camellia_test_cbc_key[u], 16 + 8 * u);

	if (v == CAMELLIA_DECRYPT) {
		camellia_setkey_dec(&ctx, key, 128 + u * 64);
	} else {
		camellia_setkey_enc(&ctx, key, 128 + u * 64);
	}

	for (i = 0; i < CAMELLIA_TESTS_CBC; i++ ) {

		if (v == CAMELLIA_DECRYPT) {
			memcpy( iv , src, 16 );
			memcpy(src, camellia_test_cbc_cipher[u][i], 16);
			memcpy(dst, camellia_test_cbc_plain[i], 16);
		} else { /* CAMELLIA_ENCRYPT */
			memcpy( iv , dst, 16 );
			memcpy(src, camellia_test_cbc_plain[i], 16);
			memcpy(dst, camellia_test_cbc_cipher[u][i], 16);
		}

		camellia_crypt_cbc(&ctx, v, 16, iv, src, buf);

		if( memcmp( buf, dst, 16 ) != 0 )
		{
			if( verbose != 0 )
				printf( "failed\n" );

			return( 1 );
		}
	}

        if( verbose != 0 )
            printf( "passed\n" );
    }

    if( verbose != 0 )
        printf( "\n" );

    return ( 0 );

    /*
     * CFB128 mode
     */
    /*
    for( i = 0; i < 6; i++ )
    {
        u = i >> 1;
        v = i  & 1;

        if( verbose != 0 )
            printf( "  AES-CFB128-%3d (%s): ", 128 + u * 64,
                    ( v == AES_DECRYPT ) ? "dec" : "enc" );

        memcpy( iv,  aes_test_cfb128_iv, 16 );
        memcpy( key, aes_test_cfb128_key[u], 16 + u * 8 );

        offset = 0;
        aes_setkey_enc( &ctx, key, 128 + u * 64 );

        if( v == AES_DECRYPT )
        {
            memcpy( buf, aes_test_cfb128_ct[u], 64 );
            aes_crypt_cfb128( &ctx, v, 64, &offset, iv, buf, buf );

            if( memcmp( buf, aes_test_cfb128_pt, 64 ) != 0 )
            {
                if( verbose != 0 )
                    printf( "failed\n" );

                return( 1 );
            }
        }
        else
        {
            memcpy( buf, aes_test_cfb128_pt, 64 );
            aes_crypt_cfb128( &ctx, v, 64, &offset, iv, buf, buf );

            if( memcmp( buf, aes_test_cfb128_ct[u], 64 ) != 0 )
            {
                if( verbose != 0 )
                    printf( "failed\n" );

                return( 1 );
            }
        }

        if( verbose != 0 )
            printf( "passed\n" );
    }


    if( verbose != 0 )
        printf( "\n" );

    return( 0 ); */
}

#endif

#endif
