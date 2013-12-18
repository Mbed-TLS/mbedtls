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
 */

#include "polarssl/config.h"

#if defined(POLARSSL_AESNI_C)

#include "polarssl/aesni.h"
#include <stdio.h>

#if defined(POLARSSL_HAVE_X86_64)

/*
 * AES-NI support detection routine, [AES-WP] figure 23
 */
int aesni_supported( void )
{
    static int supported = -1;
    unsigned int c;

    if( supported == -1 )
    {
        asm( "movl  $1, %%eax   \n"
             "cpuid             \n"
             : "=c" (c)
             :
             : "eax", "ebx", "edx" );
        supported = ( ( c & 0x02000000 ) != 0 );
    }

    return( supported );
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
#endif /* POLARSSL_HAVE_X86_64 */

#endif /* POLARSSL_AESNI_C */
