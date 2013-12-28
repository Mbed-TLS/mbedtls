/*
 *  AES-NI support functions
 *
 *  Copyright (C) 2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
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
 * [AES-WP] http://software.intel.com/en-us/articles/intel-advanced-encryption-standard-aes-instructions-set
 * [CLMUL-WP] http://software.intel.com/en-us/articles/intel-carry-less-multiplication-instruction-and-its-usage-for-computing-the-gcm-mode/
 */

#include "polarssl/config.h"

#if defined(POLARSSL_AESNI_C)

#include "polarssl/aesni.h"
#include <stdio.h>

#if defined(POLARSSL_HAVE_X86_64)

/*
 * AES-NI support detection routine
 */
int aesni_supports( unsigned int what )
{
    static int done = 0;
    static unsigned int c = 0;

    if( ! done )
    {
        asm( "movl  $1, %%eax   \n"
             "cpuid             \n"
             : "=c" (c)
             :
             : "eax", "ebx", "edx" );
        done = 1;
    }

    return( ( c & what ) != 0 );
}

/*
 * AES-NI AES-ECB block en(de)cryption
 */
int aesni_crypt_ecb( aes_context *ctx,
                     int mode,
                     const unsigned char input[16],
                     unsigned char output[16] )
{
    asm( "movdqu    (%3), %%xmm0    \n" // load input
         "movdqu    (%1), %%xmm1    \n" // load round key 0
         "pxor      %%xmm1, %%xmm0  \n" // round 0
         "addq      $16, %1         \n" // point to next round key
         "subl      $1, %0          \n" // normal rounds = nr - 1
         "test      %2, %2          \n" // mode?
         "jz        2f              \n" // 0 = decrypt

         "1:                        \n" // encryption loop
         "movdqu    (%1), %%xmm1    \n" // load round key
         "aesenc    %%xmm1, %%xmm0  \n" // do round
         "addq      $16, %1         \n" // point to next round key
         "subl      $1, %0          \n" // loop
         "jnz       1b              \n"
         "movdqu    (%1), %%xmm1    \n" // load round key
         "aesenclast %%xmm1, %%xmm0 \n" // last round
         "jmp       3f              \n"

         "2:                        \n" // decryption loop
         "movdqu    (%1), %%xmm1    \n"
         "aesdec    %%xmm1, %%xmm0  \n"
         "addq      $16, %1         \n"
         "subl      $1, %0          \n"
         "jnz       2b              \n"
         "movdqu    (%1), %%xmm1    \n" // load round key
         "aesdeclast %%xmm1, %%xmm0 \n" // last round

         "3:                        \n"
         "movdqu    %%xmm0, (%4)    \n" // export output
         :
         : "r" (ctx->nr), "r" (ctx->rk), "r" (mode), "r" (input), "r" (output)
         : "memory", "cc", "xmm0", "xmm1" );


    return( 0 );
}

/*
 * GCM multiplication: c = a times b in GF(2^128)
 * Based on [CLMUL-WP] algorithms 1 (with equation 27) and 5.
 */
int aesni_gcm_mult( unsigned char c[16],
                    const unsigned char a[16],
                    const unsigned char b[16] )
{
    unsigned char aa[16], bb[16], cc[16];
    size_t i;

    /* The inputs are in big-endian order, so byte-reverse them */
    for( i = 0; i < 16; i++ )
    {
        aa[i] = a[15 - i];
        bb[i] = b[15 - i];
    }

    asm( "movdqu (%0), %%xmm0               \n" // a1:a0
         "movdqu (%1), %%xmm1               \n" // b1:b0

         /*
          * Caryless multiplication xmm2:xmm1 = xmm0 * xmm1
          * using [CLMUL-WP] algorithm 1 (p. 13).
          */
         "movdqa %%xmm1, %%xmm2             \n" // copy of b1:b0
         "movdqa %%xmm1, %%xmm3             \n" // same
         "movdqa %%xmm1, %%xmm4             \n" // same
         "pclmulqdq $0x00, %%xmm0, %%xmm1   \n" // a0*b0 = c1:c0
         "pclmulqdq $0x11, %%xmm0, %%xmm2   \n" // a1*b1 = d1:d0
         "pclmulqdq $0x10, %%xmm0, %%xmm3   \n" // a0*b1 = e1:e0
         "pclmulqdq $0x01, %%xmm0, %%xmm4   \n" // a1*b0 = f1:f0
         "pxor %%xmm3, %%xmm4               \n" // e1+f1:e0+f0
         "movdqa %%xmm4, %%xmm3             \n" // same
         "psrldq $8, %%xmm4                 \n" // 0:e1+f1
         "pslldq $8, %%xmm3                 \n" // e0+f0:0
         "pxor %%xmm4, %%xmm2               \n" // d1:d0+e1+f1
         "pxor %%xmm3, %%xmm1               \n" // c1+e0+f1:c0

         /*
          * Now shift the result one bit to the left,
          * taking advantage of [CLMUL-WP] eq 27 (p. 20)
          */
         "movdqa %%xmm1, %%xmm3             \n" // r1:r0
         "movdqa %%xmm2, %%xmm4             \n" // r3:r2
         "psllq $1, %%xmm1                  \n" // r1<<1:r0<<1
         "psllq $1, %%xmm2                  \n" // r3<<1:r2<<1
         "psrlq $63, %%xmm3                 \n" // r1>>63:r0>>63
         "psrlq $63, %%xmm4                 \n" // r3>>63:r2>>63
         "movdqa %%xmm3, %%xmm5             \n" // r1>>63:r0>>63
         "pslldq $8, %%xmm3                 \n" // r0>>63:0
         "pslldq $8, %%xmm4                 \n" // r2>>63:0
         "psrldq $8, %%xmm5                 \n" // 0:r1>>63
         "por %%xmm3, %%xmm1                \n" // r1<<1|r0>>63:r0<<1
         "por %%xmm4, %%xmm2                \n" // r3<<1|r2>>62:r2<<1
         "por %%xmm5, %%xmm2                \n" // r3<<1|r2>>62:r2<<1|r1>>63

         /*
          * Now reduce modulo the GCM polynomial x^128 + x^7 + x^2 + x + 1
          * using [CLMUL-WP] algorithm 5 (p. 20).
          * Currently xmm2:xmm1 holds x3:x2:x1:x0 (already shifted).
          */
         /* Step 2 (1) */
         "movdqa %%xmm1, %%xmm3             \n" // x1:x0
         "movdqa %%xmm1, %%xmm4             \n" // same
         "movdqa %%xmm1, %%xmm5             \n" // same
         "psllq $63, %%xmm3                 \n" // x1<<63:x0<<63 = stuff:a
         "psllq $62, %%xmm4                 \n" // x1<<62:x0<<62 = stuff:b
         "psllq $57, %%xmm5                 \n" // x1<<57:x0<<57 = stuff:c

         /* Step 2 (2) */
         "pxor %%xmm4, %%xmm3               \n" // stuff:a+b
         "pxor %%xmm5, %%xmm3               \n" // stuff:a+b+c
         "pslldq $8, %%xmm3                 \n" // a+b+c:0
         "pxor %%xmm3, %%xmm1               \n" // x1+a+b+c:x0 = d:x0

         /* Steps 3 and 4 */
         "movdqa %%xmm1,%%xmm0              \n" // d:x0
         "movdqa %%xmm1,%%xmm4              \n" // same
         "movdqa %%xmm1,%%xmm5              \n" // same
         "psrlq $1, %%xmm0                  \n" // e1:x0>>1 = e1:e0'
         "psrlq $2, %%xmm4                  \n" // f1:x0>>2 = f1:f0'
         "psrlq $7, %%xmm5                  \n" // g1:x0>>7 = g1:g0'
         "pxor %%xmm4, %%xmm0               \n" // e1+f1:e0'+f0'
         "pxor %%xmm5, %%xmm0               \n" // e1+f1+g1:e0'+f0'+g0'
         // e0'+f0'+g0' is almost e0+f0+g0, except for some missing
         // bits carried from d. Now get those bits back in.
         "movdqa %%xmm1,%%xmm3              \n" // d:x0
         "movdqa %%xmm1,%%xmm4              \n" // same
         "movdqa %%xmm1,%%xmm5              \n" // same
         "psllq $63, %%xmm3                 \n" // d<<63:stuff
         "psllq $62, %%xmm4                 \n" // d<<62:stuff
         "psllq $57, %%xmm5                 \n" // d<<57:stuff
         "pxor %%xmm4, %%xmm3               \n" // d<<63+d<<62:stuff
         "pxor %%xmm5, %%xmm3               \n" // missing bits of d:stuff
         "psrldq $8, %%xmm3                 \n" // 0:missing bits of d
         "pxor %%xmm3, %%xmm0               \n" // e1+f1+g1:e0+f0+g0
         "pxor %%xmm1, %%xmm0               \n" // h1:h0
         "pxor %%xmm2, %%xmm0               \n" // x3+h1:x2+h0

         "movdqu %%xmm0, (%2)               \n" // done
         :
         : "r" (aa), "r" (bb), "r" (cc)
         : "memory", "cc", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5" );

    /* Now byte-reverse the outputs */
    for( i = 0; i < 16; i++ )
        c[i] = cc[15 - i];

    return( 0 );
}

/*
 * Compute decryption round keys from encryption round keys
 */
void aesni_inverse_key( unsigned char *invkey,
                        const unsigned char *fwdkey, int nr )
{
    unsigned char *ik = invkey;
    const unsigned char *fk = fwdkey + 16 * nr;

    memcpy( ik, fk, 16 );

    for( fk -= 16, ik += 16; fk > fwdkey; fk -= 16, ik += 16 )
        asm( "movdqu (%0), %%xmm0       \n"
             "aesimc %%xmm0, %%xmm0     \n"
             "movdqu %%xmm0, (%1)       \n"
             :
             : "r" (fk), "r" (ik)
             : "memory", "xmm0" );

    memcpy( ik, fk, 16 );
}

#endif /* POLARSSL_HAVE_X86_64 */

#endif /* POLARSSL_AESNI_C */
