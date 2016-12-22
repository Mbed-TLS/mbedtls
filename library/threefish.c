/*
 *  Threefish implementation
 *
 *  Copyright (C) 2016, ARM Limited, All Rights Reserved
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
 *  The Threefish block cipher was designed in 2008 as part of the Skein hash
 *  function. Threefish was created and analyzed by: Niels Ferguson,
 *  Stefan Lucks, Bruce Schneier, Doug Whiting, Mihir Bellare, Tadayoshi Kohno,
 *  Jon Callas, and Jesse Walker.
 *
 *  https://www.schneier.com/academic/paperfiles/skein1.3.pdf
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_THREEFISH_C)

#include "mbedtls/threefish.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if !defined(MBEDTLS_BLOWFISH_ALT)

#define THREEFISH_KEY_SCHED_CONST           0x1BD11BDAA9FC1A22L

#define THREEFISH_LROTATE64(V,R_DIST)                           \
    ( ( (V) << R_DIST ) | ( (V) >> ( 64 - R_DIST ) ) )

#define THREEFISH_RROTATE64(V,R_DIST)                           \
    ( ( (V) >> R_DIST ) | ( (V) << ( 64 - R_DIST ) ) )

#define THREEFISH_MIX_PERM(C,OP1,OP2,R_DIST)                    \
{                                                               \
    (C)[OP1] += (C)[OP2];                                       \
    (C)[OP2]  = THREEFISH_LROTATE64( (C)[OP2], R_DIST );        \
    (C)[OP2] ^= (C)[OP1];                                       \
}

#define THREEFISH_INV_MIX_PERM(C,OP1,OP2,R_DIST)                \
{                                                               \
    (C)[OP2] ^= (C)[OP1];                                       \
    (C)[OP2]  = THREEFISH_RROTATE64( (C)[OP2], R_DIST );        \
    (C)[OP1] -= (C)[OP2];                                       \
}

#define THREEFISH256_ADD_SUBKEY(C,K,T,S)                        \
{                                                               \
    (C)[0] += (K)[( S + 0 ) % 5];                               \
    (C)[1] += (K)[( S + 1 ) % 5] + (T)[( S + 0 ) % 3];          \
    (C)[2] += (K)[( S + 2 ) % 5] + (T)[( S + 1 ) % 3];          \
    (C)[3] += (K)[( S + 3 ) % 5] + S;                           \
}

#define THREEFISH512_ADD_SUBKEY(C,K,T,S)                        \
{                                                               \
    (C)[0] += (K)[( S + 0 ) % 9];                               \
    (C)[1] += (K)[( S + 1 ) % 9];                               \
    (C)[2] += (K)[( S + 2 ) % 9];                               \
    (C)[3] += (K)[( S + 3 ) % 9];                               \
    (C)[4] += (K)[( S + 4 ) % 9];                               \
    (C)[5] += (K)[( S + 5 ) % 9] + (T)[( S + 0 ) % 3];          \
    (C)[6] += (K)[( S + 6 ) % 9] + (T)[( S + 1 ) % 3];          \
    (C)[7] += (K)[( S + 7 ) % 9] + S;                           \
}

#define THREEFISH1024_ADD_SUBKEY(C,K,T,S)                       \
{                                                               \
    (C)[ 0] += (K)[( S +  0 ) % 17];                            \
    (C)[ 1] += (K)[( S +  1 ) % 17];                            \
    (C)[ 2] += (K)[( S +  2 ) % 17];                            \
    (C)[ 3] += (K)[( S +  3 ) % 17];                            \
    (C)[ 4] += (K)[( S +  4 ) % 17];                            \
    (C)[ 5] += (K)[( S +  5 ) % 17];                            \
    (C)[ 6] += (K)[( S +  6 ) % 17];                            \
    (C)[ 7] += (K)[( S +  7 ) % 17];                            \
    (C)[ 8] += (K)[( S +  8 ) % 17];                            \
    (C)[ 9] += (K)[( S +  9 ) % 17];                            \
    (C)[10] += (K)[( S + 10 ) % 17];                            \
    (C)[11] += (K)[( S + 11 ) % 17];                            \
    (C)[12] += (K)[( S + 12 ) % 17];                            \
    (C)[13] += (K)[( S + 13 ) % 17] + (T)[( S + 0 ) % 3];       \
    (C)[14] += (K)[( S + 14 ) % 17] + (T)[( S + 1 ) % 3];       \
    (C)[15] += (K)[( S + 15 ) % 17] + S;                        \
}

#define THREEFISH256_SUB_SUBKEY(C,K,T,S)                        \
{                                                               \
    (C)[0] -= (K)[( S + 0 ) % 5];                               \
    (C)[1] -= (K)[( S + 1 ) % 5] + (T)[( S + 0 ) % 3];          \
    (C)[2] -= (K)[( S + 2 ) % 5] + (T)[( S + 1 ) % 3];          \
    (C)[3] -= (K)[( S + 3 ) % 5] + S;                           \
}

#define THREEFISH512_SUB_SUBKEY(C,K,T,S)                        \
{                                                               \
    (C)[0] -= (K)[( S + 0 ) % 9];                               \
    (C)[1] -= (K)[( S + 1 ) % 9];                               \
    (C)[2] -= (K)[( S + 2 ) % 9];                               \
    (C)[3] -= (K)[( S + 3 ) % 9];                               \
    (C)[4] -= (K)[( S + 4 ) % 9];                               \
    (C)[5] -= (K)[( S + 5 ) % 9] + (T)[( S + 0 ) % 3];          \
    (C)[6] -= (K)[( S + 6 ) % 9] + (T)[( S + 1 ) % 3];          \
    (C)[7] -= (K)[( S + 7 ) % 9] + S;                           \
}

#define THREEFISH1024_SUB_SUBKEY(C,K,T,S)                       \
{                                                               \
    (C)[ 0] -= (K)[( S +  0 ) % 17];                            \
    (C)[ 1] -= (K)[( S +  1 ) % 17];                            \
    (C)[ 2] -= (K)[( S +  2 ) % 17];                            \
    (C)[ 3] -= (K)[( S +  3 ) % 17];                            \
    (C)[ 4] -= (K)[( S +  4 ) % 17];                            \
    (C)[ 5] -= (K)[( S +  5 ) % 17];                            \
    (C)[ 6] -= (K)[( S +  6 ) % 17];                            \
    (C)[ 7] -= (K)[( S +  7 ) % 17];                            \
    (C)[ 8] -= (K)[( S +  8 ) % 17];                            \
    (C)[ 9] -= (K)[( S +  9 ) % 17];                            \
    (C)[10] -= (K)[( S + 10 ) % 17];                            \
    (C)[11] -= (K)[( S + 11 ) % 17];                            \
    (C)[12] -= (K)[( S + 12 ) % 17];                            \
    (C)[13] -= (K)[( S + 13 ) % 17] + (T)[( S + 0 ) % 3];       \
    (C)[14] -= (K)[( S + 14 ) % 17] + (T)[( S + 1 ) % 3];       \
    (C)[15] -= (K)[( S + 15 ) % 17] + S;                        \
}

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = (unsigned char*)v; while( n-- ) *p++ = 0;
}

/*
 * Encrypt one data block
 */
static void threefish_enc( mbedtls_threefish_context *ctx,
                           const unsigned char *input,
                           const unsigned char *output )
{
    const uint64_t *P = (const uint64_t *)input;
    uint64_t *C = (uint64_t *)output;
    uint64_t *K = (uint64_t *)ctx->key;
    uint64_t *T = (uint64_t *)ctx->tweak;

    memcpy( C, P, sizeof( uint64_t ) * ( ctx->keybits >> 6 ) );

    switch( ctx->keybits )
    {
        case 256:
            THREEFISH256_ADD_SUBKEY( C, K, T, 0 );

            THREEFISH_MIX_PERM( C, 0, 1, 14 ); THREEFISH_MIX_PERM( C, 2, 3, 16 );
            THREEFISH_MIX_PERM( C, 0, 3, 52 ); THREEFISH_MIX_PERM( C, 2, 1, 57 );
            THREEFISH_MIX_PERM( C, 0, 1, 23 ); THREEFISH_MIX_PERM( C, 2, 3, 40 );
            THREEFISH_MIX_PERM( C, 0, 3,  5 ); THREEFISH_MIX_PERM( C, 2, 1, 37 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 1 );

            THREEFISH_MIX_PERM( C, 0, 1, 25 ); THREEFISH_MIX_PERM( C, 2, 3, 33 );
            THREEFISH_MIX_PERM( C, 0, 3, 46 ); THREEFISH_MIX_PERM( C, 2, 1, 12 );
            THREEFISH_MIX_PERM( C, 0, 1, 58 ); THREEFISH_MIX_PERM( C, 2, 3, 22 );
            THREEFISH_MIX_PERM( C, 0, 3, 32 ); THREEFISH_MIX_PERM( C, 2, 1, 32 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 2 );

            THREEFISH_MIX_PERM( C, 0, 1, 14 ); THREEFISH_MIX_PERM( C, 2, 3, 16 );
            THREEFISH_MIX_PERM( C, 0, 3, 52 ); THREEFISH_MIX_PERM( C, 2, 1, 57 );
            THREEFISH_MIX_PERM( C, 0, 1, 23 ); THREEFISH_MIX_PERM( C, 2, 3, 40 );
            THREEFISH_MIX_PERM( C, 0, 3,  5 ); THREEFISH_MIX_PERM( C, 2, 1, 37 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 3 );

            THREEFISH_MIX_PERM( C, 0, 1, 25 ); THREEFISH_MIX_PERM( C, 2, 3, 33 );
            THREEFISH_MIX_PERM( C, 0, 3, 46 ); THREEFISH_MIX_PERM( C, 2, 1, 12 );
            THREEFISH_MIX_PERM( C, 0, 1, 58 ); THREEFISH_MIX_PERM( C, 2, 3, 22 );
            THREEFISH_MIX_PERM( C, 0, 3, 32 ); THREEFISH_MIX_PERM( C, 2, 1, 32 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 4 );

            THREEFISH_MIX_PERM( C, 0, 1, 14 ); THREEFISH_MIX_PERM( C, 2, 3, 16 );
            THREEFISH_MIX_PERM( C, 0, 3, 52 ); THREEFISH_MIX_PERM( C, 2, 1, 57 );
            THREEFISH_MIX_PERM( C, 0, 1, 23 ); THREEFISH_MIX_PERM( C, 2, 3, 40 );
            THREEFISH_MIX_PERM( C, 0, 3,  5 ); THREEFISH_MIX_PERM( C, 2, 1, 37 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 5 );

            THREEFISH_MIX_PERM( C, 0, 1, 25 ); THREEFISH_MIX_PERM( C, 2, 3, 33 );
            THREEFISH_MIX_PERM( C, 0, 3, 46 ); THREEFISH_MIX_PERM( C, 2, 1, 12 );
            THREEFISH_MIX_PERM( C, 0, 1, 58 ); THREEFISH_MIX_PERM( C, 2, 3, 22 );
            THREEFISH_MIX_PERM( C, 0, 3, 32 ); THREEFISH_MIX_PERM( C, 2, 1, 32 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 6 );

            THREEFISH_MIX_PERM( C, 0, 1, 14 ); THREEFISH_MIX_PERM( C, 2, 3, 16 );
            THREEFISH_MIX_PERM( C, 0, 3, 52 ); THREEFISH_MIX_PERM( C, 2, 1, 57 );
            THREEFISH_MIX_PERM( C, 0, 1, 23 ); THREEFISH_MIX_PERM( C, 2, 3, 40 );
            THREEFISH_MIX_PERM( C, 0, 3,  5 ); THREEFISH_MIX_PERM( C, 2, 1, 37 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 7 );

            THREEFISH_MIX_PERM( C, 0, 1, 25 ); THREEFISH_MIX_PERM( C, 2, 3, 33 );
            THREEFISH_MIX_PERM( C, 0, 3, 46 ); THREEFISH_MIX_PERM( C, 2, 1, 12 );
            THREEFISH_MIX_PERM( C, 0, 1, 58 ); THREEFISH_MIX_PERM( C, 2, 3, 22 );
            THREEFISH_MIX_PERM( C, 0, 3, 32 ); THREEFISH_MIX_PERM( C, 2, 1, 32 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 8 );

            THREEFISH_MIX_PERM( C, 0, 1, 14 ); THREEFISH_MIX_PERM( C, 2, 3, 16 );
            THREEFISH_MIX_PERM( C, 0, 3, 52 ); THREEFISH_MIX_PERM( C, 2, 1, 57 );
            THREEFISH_MIX_PERM( C, 0, 1, 23 ); THREEFISH_MIX_PERM( C, 2, 3, 40 );
            THREEFISH_MIX_PERM( C, 0, 3,  5 ); THREEFISH_MIX_PERM( C, 2, 1, 37 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 9 );

            THREEFISH_MIX_PERM( C, 0, 1, 25 ); THREEFISH_MIX_PERM( C, 2, 3, 33 );
            THREEFISH_MIX_PERM( C, 0, 3, 46 ); THREEFISH_MIX_PERM( C, 2, 1, 12 );
            THREEFISH_MIX_PERM( C, 0, 1, 58 ); THREEFISH_MIX_PERM( C, 2, 3, 22 );
            THREEFISH_MIX_PERM( C, 0, 3, 32 ); THREEFISH_MIX_PERM( C, 2, 1, 32 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 10 );

            THREEFISH_MIX_PERM( C, 0, 1, 14 ); THREEFISH_MIX_PERM( C, 2, 3, 16 );
            THREEFISH_MIX_PERM( C, 0, 3, 52 ); THREEFISH_MIX_PERM( C, 2, 1, 57 );
            THREEFISH_MIX_PERM( C, 0, 1, 23 ); THREEFISH_MIX_PERM( C, 2, 3, 40 );
            THREEFISH_MIX_PERM( C, 0, 3,  5 ); THREEFISH_MIX_PERM( C, 2, 1, 37 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 11 );

            THREEFISH_MIX_PERM( C, 0, 1, 25 ); THREEFISH_MIX_PERM( C, 2, 3, 33 );
            THREEFISH_MIX_PERM( C, 0, 3, 46 ); THREEFISH_MIX_PERM( C, 2, 1, 12 );
            THREEFISH_MIX_PERM( C, 0, 1, 58 ); THREEFISH_MIX_PERM( C, 2, 3, 22 );
            THREEFISH_MIX_PERM( C, 0, 3, 32 ); THREEFISH_MIX_PERM( C, 2, 1, 32 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 12 );

            THREEFISH_MIX_PERM( C, 0, 1, 14 ); THREEFISH_MIX_PERM( C, 2, 3, 16 );
            THREEFISH_MIX_PERM( C, 0, 3, 52 ); THREEFISH_MIX_PERM( C, 2, 1, 57 );
            THREEFISH_MIX_PERM( C, 0, 1, 23 ); THREEFISH_MIX_PERM( C, 2, 3, 40 );
            THREEFISH_MIX_PERM( C, 0, 3,  5 ); THREEFISH_MIX_PERM( C, 2, 1, 37 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 13 );

            THREEFISH_MIX_PERM( C, 0, 1, 25 ); THREEFISH_MIX_PERM( C, 2, 3, 33 );
            THREEFISH_MIX_PERM( C, 0, 3, 46 ); THREEFISH_MIX_PERM( C, 2, 1, 12 );
            THREEFISH_MIX_PERM( C, 0, 1, 58 ); THREEFISH_MIX_PERM( C, 2, 3, 22 );
            THREEFISH_MIX_PERM( C, 0, 3, 32 ); THREEFISH_MIX_PERM( C, 2, 1, 32 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 14 );

            THREEFISH_MIX_PERM( C, 0, 1, 14 ); THREEFISH_MIX_PERM( C, 2, 3, 16 );
            THREEFISH_MIX_PERM( C, 0, 3, 52 ); THREEFISH_MIX_PERM( C, 2, 1, 57 );
            THREEFISH_MIX_PERM( C, 0, 1, 23 ); THREEFISH_MIX_PERM( C, 2, 3, 40 );
            THREEFISH_MIX_PERM( C, 0, 3,  5 ); THREEFISH_MIX_PERM( C, 2, 1, 37 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 15 );

            THREEFISH_MIX_PERM( C, 0, 1, 25 ); THREEFISH_MIX_PERM( C, 2, 3, 33 );
            THREEFISH_MIX_PERM( C, 0, 3, 46 ); THREEFISH_MIX_PERM( C, 2, 1, 12 );
            THREEFISH_MIX_PERM( C, 0, 1, 58 ); THREEFISH_MIX_PERM( C, 2, 3, 22 );
            THREEFISH_MIX_PERM( C, 0, 3, 32 ); THREEFISH_MIX_PERM( C, 2, 1, 32 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 16 );

            THREEFISH_MIX_PERM( C, 0, 1, 14 ); THREEFISH_MIX_PERM( C, 2, 3, 16 );
            THREEFISH_MIX_PERM( C, 0, 3, 52 ); THREEFISH_MIX_PERM( C, 2, 1, 57 );
            THREEFISH_MIX_PERM( C, 0, 1, 23 ); THREEFISH_MIX_PERM( C, 2, 3, 40 );
            THREEFISH_MIX_PERM( C, 0, 3,  5 ); THREEFISH_MIX_PERM( C, 2, 1, 37 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 17 );

            THREEFISH_MIX_PERM( C, 0, 1, 25 ); THREEFISH_MIX_PERM( C, 2, 3, 33 );
            THREEFISH_MIX_PERM( C, 0, 3, 46 ); THREEFISH_MIX_PERM( C, 2, 1, 12 );
            THREEFISH_MIX_PERM( C, 0, 1, 58 ); THREEFISH_MIX_PERM( C, 2, 3, 22 );
            THREEFISH_MIX_PERM( C, 0, 3, 32 ); THREEFISH_MIX_PERM( C, 2, 1, 32 );

            THREEFISH256_ADD_SUBKEY( C, K, T, 18 );

            break;

        case 512:
            THREEFISH512_ADD_SUBKEY( C, K, T, 0 );

            THREEFISH_MIX_PERM( C, 0, 1, 46 ); THREEFISH_MIX_PERM( C, 2, 3, 36 ); THREEFISH_MIX_PERM( C, 4, 5, 19 ); THREEFISH_MIX_PERM( C, 6, 7, 37 );
            THREEFISH_MIX_PERM( C, 2, 1, 33 ); THREEFISH_MIX_PERM( C, 4, 7, 27 ); THREEFISH_MIX_PERM( C, 6, 5, 14 ); THREEFISH_MIX_PERM( C, 0, 3, 42 );
            THREEFISH_MIX_PERM( C, 4, 1, 17 ); THREEFISH_MIX_PERM( C, 6, 3, 49 ); THREEFISH_MIX_PERM( C, 0, 5, 36 ); THREEFISH_MIX_PERM( C, 2, 7, 39 );
            THREEFISH_MIX_PERM( C, 6, 1, 44 ); THREEFISH_MIX_PERM( C, 0, 7,  9 ); THREEFISH_MIX_PERM( C, 2, 5, 54 ); THREEFISH_MIX_PERM( C, 4, 3, 56 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 1 );

            THREEFISH_MIX_PERM( C, 0, 1, 39 ); THREEFISH_MIX_PERM( C, 2, 3, 30 ); THREEFISH_MIX_PERM( C, 4, 5, 34 ); THREEFISH_MIX_PERM( C, 6, 7, 24 );
            THREEFISH_MIX_PERM( C, 2, 1, 13 ); THREEFISH_MIX_PERM( C, 4, 7, 50 ); THREEFISH_MIX_PERM( C, 6, 5, 10 ); THREEFISH_MIX_PERM( C, 0, 3, 17 );
            THREEFISH_MIX_PERM( C, 4, 1, 25 ); THREEFISH_MIX_PERM( C, 6, 3, 29 ); THREEFISH_MIX_PERM( C, 0, 5, 39 ); THREEFISH_MIX_PERM( C, 2, 7, 43 );
            THREEFISH_MIX_PERM( C, 6, 1,  8 ); THREEFISH_MIX_PERM( C, 0, 7, 35 ); THREEFISH_MIX_PERM( C, 2, 5, 56 ); THREEFISH_MIX_PERM( C, 4, 3, 22 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 2 );

            THREEFISH_MIX_PERM( C, 0, 1, 46 ); THREEFISH_MIX_PERM( C, 2, 3, 36 ); THREEFISH_MIX_PERM( C, 4, 5, 19 ); THREEFISH_MIX_PERM( C, 6, 7, 37 );
            THREEFISH_MIX_PERM( C, 2, 1, 33 ); THREEFISH_MIX_PERM( C, 4, 7, 27 ); THREEFISH_MIX_PERM( C, 6, 5, 14 ); THREEFISH_MIX_PERM( C, 0, 3, 42 );
            THREEFISH_MIX_PERM( C, 4, 1, 17 ); THREEFISH_MIX_PERM( C, 6, 3, 49 ); THREEFISH_MIX_PERM( C, 0, 5, 36 ); THREEFISH_MIX_PERM( C, 2, 7, 39 );
            THREEFISH_MIX_PERM( C, 6, 1, 44 ); THREEFISH_MIX_PERM( C, 0, 7,  9 ); THREEFISH_MIX_PERM( C, 2, 5, 54 ); THREEFISH_MIX_PERM( C, 4, 3, 56 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 3 );

            THREEFISH_MIX_PERM( C, 0, 1, 39 ); THREEFISH_MIX_PERM( C, 2, 3, 30 ); THREEFISH_MIX_PERM( C, 4, 5, 34 ); THREEFISH_MIX_PERM( C, 6, 7, 24 );
            THREEFISH_MIX_PERM( C, 2, 1, 13 ); THREEFISH_MIX_PERM( C, 4, 7, 50 ); THREEFISH_MIX_PERM( C, 6, 5, 10 ); THREEFISH_MIX_PERM( C, 0, 3, 17 );
            THREEFISH_MIX_PERM( C, 4, 1, 25 ); THREEFISH_MIX_PERM( C, 6, 3, 29 ); THREEFISH_MIX_PERM( C, 0, 5, 39 ); THREEFISH_MIX_PERM( C, 2, 7, 43 );
            THREEFISH_MIX_PERM( C, 6, 1,  8 ); THREEFISH_MIX_PERM( C, 0, 7, 35 ); THREEFISH_MIX_PERM( C, 2, 5, 56 ); THREEFISH_MIX_PERM( C, 4, 3, 22 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 4 );

            THREEFISH_MIX_PERM( C, 0, 1, 46 ); THREEFISH_MIX_PERM( C, 2, 3, 36 ); THREEFISH_MIX_PERM( C, 4, 5, 19 ); THREEFISH_MIX_PERM( C, 6, 7, 37 );
            THREEFISH_MIX_PERM( C, 2, 1, 33 ); THREEFISH_MIX_PERM( C, 4, 7, 27 ); THREEFISH_MIX_PERM( C, 6, 5, 14 ); THREEFISH_MIX_PERM( C, 0, 3, 42 );
            THREEFISH_MIX_PERM( C, 4, 1, 17 ); THREEFISH_MIX_PERM( C, 6, 3, 49 ); THREEFISH_MIX_PERM( C, 0, 5, 36 ); THREEFISH_MIX_PERM( C, 2, 7, 39 );
            THREEFISH_MIX_PERM( C, 6, 1, 44 ); THREEFISH_MIX_PERM( C, 0, 7,  9 ); THREEFISH_MIX_PERM( C, 2, 5, 54 ); THREEFISH_MIX_PERM( C, 4, 3, 56 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 5 );

            THREEFISH_MIX_PERM( C, 0, 1, 39 ); THREEFISH_MIX_PERM( C, 2, 3, 30 ); THREEFISH_MIX_PERM( C, 4, 5, 34 ); THREEFISH_MIX_PERM( C, 6, 7, 24 );
            THREEFISH_MIX_PERM( C, 2, 1, 13 ); THREEFISH_MIX_PERM( C, 4, 7, 50 ); THREEFISH_MIX_PERM( C, 6, 5, 10 ); THREEFISH_MIX_PERM( C, 0, 3, 17 );
            THREEFISH_MIX_PERM( C, 4, 1, 25 ); THREEFISH_MIX_PERM( C, 6, 3, 29 ); THREEFISH_MIX_PERM( C, 0, 5, 39 ); THREEFISH_MIX_PERM( C, 2, 7, 43 );
            THREEFISH_MIX_PERM( C, 6, 1,  8 ); THREEFISH_MIX_PERM( C, 0, 7, 35 ); THREEFISH_MIX_PERM( C, 2, 5, 56 ); THREEFISH_MIX_PERM( C, 4, 3, 22 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 6 );

            THREEFISH_MIX_PERM( C, 0, 1, 46 ); THREEFISH_MIX_PERM( C, 2, 3, 36 ); THREEFISH_MIX_PERM( C, 4, 5, 19 ); THREEFISH_MIX_PERM( C, 6, 7, 37 );
            THREEFISH_MIX_PERM( C, 2, 1, 33 ); THREEFISH_MIX_PERM( C, 4, 7, 27 ); THREEFISH_MIX_PERM( C, 6, 5, 14 ); THREEFISH_MIX_PERM( C, 0, 3, 42 );
            THREEFISH_MIX_PERM( C, 4, 1, 17 ); THREEFISH_MIX_PERM( C, 6, 3, 49 ); THREEFISH_MIX_PERM( C, 0, 5, 36 ); THREEFISH_MIX_PERM( C, 2, 7, 39 );
            THREEFISH_MIX_PERM( C, 6, 1, 44 ); THREEFISH_MIX_PERM( C, 0, 7,  9 ); THREEFISH_MIX_PERM( C, 2, 5, 54 ); THREEFISH_MIX_PERM( C, 4, 3, 56 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 7 );

            THREEFISH_MIX_PERM( C, 0, 1, 39 ); THREEFISH_MIX_PERM( C, 2, 3, 30 ); THREEFISH_MIX_PERM( C, 4, 5, 34 ); THREEFISH_MIX_PERM( C, 6, 7, 24 );
            THREEFISH_MIX_PERM( C, 2, 1, 13 ); THREEFISH_MIX_PERM( C, 4, 7, 50 ); THREEFISH_MIX_PERM( C, 6, 5, 10 ); THREEFISH_MIX_PERM( C, 0, 3, 17 );
            THREEFISH_MIX_PERM( C, 4, 1, 25 ); THREEFISH_MIX_PERM( C, 6, 3, 29 ); THREEFISH_MIX_PERM( C, 0, 5, 39 ); THREEFISH_MIX_PERM( C, 2, 7, 43 );
            THREEFISH_MIX_PERM( C, 6, 1,  8 ); THREEFISH_MIX_PERM( C, 0, 7, 35 ); THREEFISH_MIX_PERM( C, 2, 5, 56 ); THREEFISH_MIX_PERM( C, 4, 3, 22 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 8 );

            THREEFISH_MIX_PERM( C, 0, 1, 46 ); THREEFISH_MIX_PERM( C, 2, 3, 36 ); THREEFISH_MIX_PERM( C, 4, 5, 19 ); THREEFISH_MIX_PERM( C, 6, 7, 37 );
            THREEFISH_MIX_PERM( C, 2, 1, 33 ); THREEFISH_MIX_PERM( C, 4, 7, 27 ); THREEFISH_MIX_PERM( C, 6, 5, 14 ); THREEFISH_MIX_PERM( C, 0, 3, 42 );
            THREEFISH_MIX_PERM( C, 4, 1, 17 ); THREEFISH_MIX_PERM( C, 6, 3, 49 ); THREEFISH_MIX_PERM( C, 0, 5, 36 ); THREEFISH_MIX_PERM( C, 2, 7, 39 );
            THREEFISH_MIX_PERM( C, 6, 1, 44 ); THREEFISH_MIX_PERM( C, 0, 7,  9 ); THREEFISH_MIX_PERM( C, 2, 5, 54 ); THREEFISH_MIX_PERM( C, 4, 3, 56 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 9 );

            THREEFISH_MIX_PERM( C, 0, 1, 39 ); THREEFISH_MIX_PERM( C, 2, 3, 30 ); THREEFISH_MIX_PERM( C, 4, 5, 34 ); THREEFISH_MIX_PERM( C, 6, 7, 24 );
            THREEFISH_MIX_PERM( C, 2, 1, 13 ); THREEFISH_MIX_PERM( C, 4, 7, 50 ); THREEFISH_MIX_PERM( C, 6, 5, 10 ); THREEFISH_MIX_PERM( C, 0, 3, 17 );
            THREEFISH_MIX_PERM( C, 4, 1, 25 ); THREEFISH_MIX_PERM( C, 6, 3, 29 ); THREEFISH_MIX_PERM( C, 0, 5, 39 ); THREEFISH_MIX_PERM( C, 2, 7, 43 );
            THREEFISH_MIX_PERM( C, 6, 1,  8 ); THREEFISH_MIX_PERM( C, 0, 7, 35 ); THREEFISH_MIX_PERM( C, 2, 5, 56 ); THREEFISH_MIX_PERM( C, 4, 3, 22 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 10 );

            THREEFISH_MIX_PERM( C, 0, 1, 46 ); THREEFISH_MIX_PERM( C, 2, 3, 36 ); THREEFISH_MIX_PERM( C, 4, 5, 19 ); THREEFISH_MIX_PERM( C, 6, 7, 37 );
            THREEFISH_MIX_PERM( C, 2, 1, 33 ); THREEFISH_MIX_PERM( C, 4, 7, 27 ); THREEFISH_MIX_PERM( C, 6, 5, 14 ); THREEFISH_MIX_PERM( C, 0, 3, 42 );
            THREEFISH_MIX_PERM( C, 4, 1, 17 ); THREEFISH_MIX_PERM( C, 6, 3, 49 ); THREEFISH_MIX_PERM( C, 0, 5, 36 ); THREEFISH_MIX_PERM( C, 2, 7, 39 );
            THREEFISH_MIX_PERM( C, 6, 1, 44 ); THREEFISH_MIX_PERM( C, 0, 7,  9 ); THREEFISH_MIX_PERM( C, 2, 5, 54 ); THREEFISH_MIX_PERM( C, 4, 3, 56 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 11 );

            THREEFISH_MIX_PERM( C, 0, 1, 39 ); THREEFISH_MIX_PERM( C, 2, 3, 30 ); THREEFISH_MIX_PERM( C, 4, 5, 34 ); THREEFISH_MIX_PERM( C, 6, 7, 24 );
            THREEFISH_MIX_PERM( C, 2, 1, 13 ); THREEFISH_MIX_PERM( C, 4, 7, 50 ); THREEFISH_MIX_PERM( C, 6, 5, 10 ); THREEFISH_MIX_PERM( C, 0, 3, 17 );
            THREEFISH_MIX_PERM( C, 4, 1, 25 ); THREEFISH_MIX_PERM( C, 6, 3, 29 ); THREEFISH_MIX_PERM( C, 0, 5, 39 ); THREEFISH_MIX_PERM( C, 2, 7, 43 );
            THREEFISH_MIX_PERM( C, 6, 1,  8 ); THREEFISH_MIX_PERM( C, 0, 7, 35 ); THREEFISH_MIX_PERM( C, 2, 5, 56 ); THREEFISH_MIX_PERM( C, 4, 3, 22 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 12 );

            THREEFISH_MIX_PERM( C, 0, 1, 46 ); THREEFISH_MIX_PERM( C, 2, 3, 36 ); THREEFISH_MIX_PERM( C, 4, 5, 19 ); THREEFISH_MIX_PERM( C, 6, 7, 37 );
            THREEFISH_MIX_PERM( C, 2, 1, 33 ); THREEFISH_MIX_PERM( C, 4, 7, 27 ); THREEFISH_MIX_PERM( C, 6, 5, 14 ); THREEFISH_MIX_PERM( C, 0, 3, 42 );
            THREEFISH_MIX_PERM( C, 4, 1, 17 ); THREEFISH_MIX_PERM( C, 6, 3, 49 ); THREEFISH_MIX_PERM( C, 0, 5, 36 ); THREEFISH_MIX_PERM( C, 2, 7, 39 );
            THREEFISH_MIX_PERM( C, 6, 1, 44 ); THREEFISH_MIX_PERM( C, 0, 7,  9 ); THREEFISH_MIX_PERM( C, 2, 5, 54 ); THREEFISH_MIX_PERM( C, 4, 3, 56 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 13 );

            THREEFISH_MIX_PERM( C, 0, 1, 39 ); THREEFISH_MIX_PERM( C, 2, 3, 30 ); THREEFISH_MIX_PERM( C, 4, 5, 34 ); THREEFISH_MIX_PERM( C, 6, 7, 24 );
            THREEFISH_MIX_PERM( C, 2, 1, 13 ); THREEFISH_MIX_PERM( C, 4, 7, 50 ); THREEFISH_MIX_PERM( C, 6, 5, 10 ); THREEFISH_MIX_PERM( C, 0, 3, 17 );
            THREEFISH_MIX_PERM( C, 4, 1, 25 ); THREEFISH_MIX_PERM( C, 6, 3, 29 ); THREEFISH_MIX_PERM( C, 0, 5, 39 ); THREEFISH_MIX_PERM( C, 2, 7, 43 );
            THREEFISH_MIX_PERM( C, 6, 1,  8 ); THREEFISH_MIX_PERM( C, 0, 7, 35 ); THREEFISH_MIX_PERM( C, 2, 5, 56 ); THREEFISH_MIX_PERM( C, 4, 3, 22 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 14 );

            THREEFISH_MIX_PERM( C, 0, 1, 46 ); THREEFISH_MIX_PERM( C, 2, 3, 36 ); THREEFISH_MIX_PERM( C, 4, 5, 19 ); THREEFISH_MIX_PERM( C, 6, 7, 37 );
            THREEFISH_MIX_PERM( C, 2, 1, 33 ); THREEFISH_MIX_PERM( C, 4, 7, 27 ); THREEFISH_MIX_PERM( C, 6, 5, 14 ); THREEFISH_MIX_PERM( C, 0, 3, 42 );
            THREEFISH_MIX_PERM( C, 4, 1, 17 ); THREEFISH_MIX_PERM( C, 6, 3, 49 ); THREEFISH_MIX_PERM( C, 0, 5, 36 ); THREEFISH_MIX_PERM( C, 2, 7, 39 );
            THREEFISH_MIX_PERM( C, 6, 1, 44 ); THREEFISH_MIX_PERM( C, 0, 7,  9 ); THREEFISH_MIX_PERM( C, 2, 5, 54 ); THREEFISH_MIX_PERM( C, 4, 3, 56 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 15 );

            THREEFISH_MIX_PERM( C, 0, 1, 39 ); THREEFISH_MIX_PERM( C, 2, 3, 30 ); THREEFISH_MIX_PERM( C, 4, 5, 34 ); THREEFISH_MIX_PERM( C, 6, 7, 24 );
            THREEFISH_MIX_PERM( C, 2, 1, 13 ); THREEFISH_MIX_PERM( C, 4, 7, 50 ); THREEFISH_MIX_PERM( C, 6, 5, 10 ); THREEFISH_MIX_PERM( C, 0, 3, 17 );
            THREEFISH_MIX_PERM( C, 4, 1, 25 ); THREEFISH_MIX_PERM( C, 6, 3, 29 ); THREEFISH_MIX_PERM( C, 0, 5, 39 ); THREEFISH_MIX_PERM( C, 2, 7, 43 );
            THREEFISH_MIX_PERM( C, 6, 1,  8 ); THREEFISH_MIX_PERM( C, 0, 7, 35 ); THREEFISH_MIX_PERM( C, 2, 5, 56 ); THREEFISH_MIX_PERM( C, 4, 3, 22 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 16 );

            THREEFISH_MIX_PERM( C, 0, 1, 46 ); THREEFISH_MIX_PERM( C, 2, 3, 36 ); THREEFISH_MIX_PERM( C, 4, 5, 19 ); THREEFISH_MIX_PERM( C, 6, 7, 37 );
            THREEFISH_MIX_PERM( C, 2, 1, 33 ); THREEFISH_MIX_PERM( C, 4, 7, 27 ); THREEFISH_MIX_PERM( C, 6, 5, 14 ); THREEFISH_MIX_PERM( C, 0, 3, 42 );
            THREEFISH_MIX_PERM( C, 4, 1, 17 ); THREEFISH_MIX_PERM( C, 6, 3, 49 ); THREEFISH_MIX_PERM( C, 0, 5, 36 ); THREEFISH_MIX_PERM( C, 2, 7, 39 );
            THREEFISH_MIX_PERM( C, 6, 1, 44 ); THREEFISH_MIX_PERM( C, 0, 7,  9 ); THREEFISH_MIX_PERM( C, 2, 5, 54 ); THREEFISH_MIX_PERM( C, 4, 3, 56 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 17 );

            THREEFISH_MIX_PERM( C, 0, 1, 39 ); THREEFISH_MIX_PERM( C, 2, 3, 30 ); THREEFISH_MIX_PERM( C, 4, 5, 34 ); THREEFISH_MIX_PERM( C, 6, 7, 24 );
            THREEFISH_MIX_PERM( C, 2, 1, 13 ); THREEFISH_MIX_PERM( C, 4, 7, 50 ); THREEFISH_MIX_PERM( C, 6, 5, 10 ); THREEFISH_MIX_PERM( C, 0, 3, 17 );
            THREEFISH_MIX_PERM( C, 4, 1, 25 ); THREEFISH_MIX_PERM( C, 6, 3, 29 ); THREEFISH_MIX_PERM( C, 0, 5, 39 ); THREEFISH_MIX_PERM( C, 2, 7, 43 );
            THREEFISH_MIX_PERM( C, 6, 1,  8 ); THREEFISH_MIX_PERM( C, 0, 7, 35 ); THREEFISH_MIX_PERM( C, 2, 5, 56 ); THREEFISH_MIX_PERM( C, 4, 3, 22 );

            THREEFISH512_ADD_SUBKEY( C, K, T, 18 );

            break;

        case 1024:
            THREEFISH1024_ADD_SUBKEY( C, K, T, 0 );

            THREEFISH_MIX_PERM( C,  0,  1, 24 ); THREEFISH_MIX_PERM( C,  2,  3, 13 ); THREEFISH_MIX_PERM( C,  4,  5,  8 ); THREEFISH_MIX_PERM( C,  6,  7, 47 ); THREEFISH_MIX_PERM( C,  8,  9,  8 ); THREEFISH_MIX_PERM( C, 10, 11, 17 ); THREEFISH_MIX_PERM( C, 12, 13, 22 ); THREEFISH_MIX_PERM( C, 14, 15, 37 );
            THREEFISH_MIX_PERM( C,  0,  9, 38 ); THREEFISH_MIX_PERM( C,  2, 13, 19 ); THREEFISH_MIX_PERM( C,  6, 11, 10 ); THREEFISH_MIX_PERM( C,  4, 15, 55 ); THREEFISH_MIX_PERM( C, 10,  7, 49 ); THREEFISH_MIX_PERM( C, 12,  3, 18 ); THREEFISH_MIX_PERM( C, 14,  5, 23 ); THREEFISH_MIX_PERM( C,  8,  1, 52 );
            THREEFISH_MIX_PERM( C,  0,  7, 33 ); THREEFISH_MIX_PERM( C,  2,  5,  4 ); THREEFISH_MIX_PERM( C,  4,  3, 51 ); THREEFISH_MIX_PERM( C,  6,  1, 13 ); THREEFISH_MIX_PERM( C, 12, 15, 34 ); THREEFISH_MIX_PERM( C, 14, 13, 41 ); THREEFISH_MIX_PERM( C,  8, 11, 59 ); THREEFISH_MIX_PERM( C, 10,  9, 17 );
            THREEFISH_MIX_PERM( C,  0, 15,  5 ); THREEFISH_MIX_PERM( C,  2, 11, 20 ); THREEFISH_MIX_PERM( C,  6, 13, 48 ); THREEFISH_MIX_PERM( C,  4,  9, 41 ); THREEFISH_MIX_PERM( C, 14,  1, 47 ); THREEFISH_MIX_PERM( C,  8,  5, 28 ); THREEFISH_MIX_PERM( C, 10,  3, 16 ); THREEFISH_MIX_PERM( C, 12,  7, 25 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 1 );

            THREEFISH_MIX_PERM( C,  0,  1, 41 ); THREEFISH_MIX_PERM( C,  2,  3,  9 ); THREEFISH_MIX_PERM( C,  4,  5, 37 ); THREEFISH_MIX_PERM( C,  6,  7, 31 ); THREEFISH_MIX_PERM( C,  8,  9, 12 ); THREEFISH_MIX_PERM( C, 10, 11, 47 ); THREEFISH_MIX_PERM( C, 12, 13, 44 ); THREEFISH_MIX_PERM( C, 14, 15, 30 );
            THREEFISH_MIX_PERM( C,  0,  9, 16 ); THREEFISH_MIX_PERM( C,  2, 13, 34 ); THREEFISH_MIX_PERM( C,  6, 11, 56 ); THREEFISH_MIX_PERM( C,  4, 15, 51 ); THREEFISH_MIX_PERM( C, 10,  7,  4 ); THREEFISH_MIX_PERM( C, 12,  3, 53 ); THREEFISH_MIX_PERM( C, 14,  5, 42 ); THREEFISH_MIX_PERM( C,  8,  1, 41 );
            THREEFISH_MIX_PERM( C,  0,  7, 31 ); THREEFISH_MIX_PERM( C,  2,  5, 44 ); THREEFISH_MIX_PERM( C,  4,  3, 47 ); THREEFISH_MIX_PERM( C,  6,  1, 46 ); THREEFISH_MIX_PERM( C, 12, 15, 19 ); THREEFISH_MIX_PERM( C, 14, 13, 42 ); THREEFISH_MIX_PERM( C,  8, 11, 44 ); THREEFISH_MIX_PERM( C, 10,  9, 25 );
            THREEFISH_MIX_PERM( C,  0, 15,  9 ); THREEFISH_MIX_PERM( C,  2, 11, 48 ); THREEFISH_MIX_PERM( C,  6, 13, 35 ); THREEFISH_MIX_PERM( C,  4,  9, 52 ); THREEFISH_MIX_PERM( C, 14,  1, 23 ); THREEFISH_MIX_PERM( C,  8,  5, 31 ); THREEFISH_MIX_PERM( C, 10,  3, 37 ); THREEFISH_MIX_PERM( C, 12,  7, 20 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 2 );

            THREEFISH_MIX_PERM( C,  0,  1, 24 ); THREEFISH_MIX_PERM( C,  2,  3, 13 ); THREEFISH_MIX_PERM( C,  4,  5,  8 ); THREEFISH_MIX_PERM( C,  6,  7, 47 ); THREEFISH_MIX_PERM( C,  8,  9,  8 ); THREEFISH_MIX_PERM( C, 10, 11, 17 ); THREEFISH_MIX_PERM( C, 12, 13, 22 ); THREEFISH_MIX_PERM( C, 14, 15, 37 );
            THREEFISH_MIX_PERM( C,  0,  9, 38 ); THREEFISH_MIX_PERM( C,  2, 13, 19 ); THREEFISH_MIX_PERM( C,  6, 11, 10 ); THREEFISH_MIX_PERM( C,  4, 15, 55 ); THREEFISH_MIX_PERM( C, 10,  7, 49 ); THREEFISH_MIX_PERM( C, 12,  3, 18 ); THREEFISH_MIX_PERM( C, 14,  5, 23 ); THREEFISH_MIX_PERM( C,  8,  1, 52 );
            THREEFISH_MIX_PERM( C,  0,  7, 33 ); THREEFISH_MIX_PERM( C,  2,  5,  4 ); THREEFISH_MIX_PERM( C,  4,  3, 51 ); THREEFISH_MIX_PERM( C,  6,  1, 13 ); THREEFISH_MIX_PERM( C, 12, 15, 34 ); THREEFISH_MIX_PERM( C, 14, 13, 41 ); THREEFISH_MIX_PERM( C,  8, 11, 59 ); THREEFISH_MIX_PERM( C, 10,  9, 17 );
            THREEFISH_MIX_PERM( C,  0, 15,  5 ); THREEFISH_MIX_PERM( C,  2, 11, 20 ); THREEFISH_MIX_PERM( C,  6, 13, 48 ); THREEFISH_MIX_PERM( C,  4,  9, 41 ); THREEFISH_MIX_PERM( C, 14,  1, 47 ); THREEFISH_MIX_PERM( C,  8,  5, 28 ); THREEFISH_MIX_PERM( C, 10,  3, 16 ); THREEFISH_MIX_PERM( C, 12,  7, 25 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 3 );

            THREEFISH_MIX_PERM( C,  0,  1, 41 ); THREEFISH_MIX_PERM( C,  2,  3,  9 ); THREEFISH_MIX_PERM( C,  4,  5, 37 ); THREEFISH_MIX_PERM( C,  6,  7, 31 ); THREEFISH_MIX_PERM( C,  8,  9, 12 ); THREEFISH_MIX_PERM( C, 10, 11, 47 ); THREEFISH_MIX_PERM( C, 12, 13, 44 ); THREEFISH_MIX_PERM( C, 14, 15, 30 );
            THREEFISH_MIX_PERM( C,  0,  9, 16 ); THREEFISH_MIX_PERM( C,  2, 13, 34 ); THREEFISH_MIX_PERM( C,  6, 11, 56 ); THREEFISH_MIX_PERM( C,  4, 15, 51 ); THREEFISH_MIX_PERM( C, 10,  7,  4 ); THREEFISH_MIX_PERM( C, 12,  3, 53 ); THREEFISH_MIX_PERM( C, 14,  5, 42 ); THREEFISH_MIX_PERM( C,  8,  1, 41 );
            THREEFISH_MIX_PERM( C,  0,  7, 31 ); THREEFISH_MIX_PERM( C,  2,  5, 44 ); THREEFISH_MIX_PERM( C,  4,  3, 47 ); THREEFISH_MIX_PERM( C,  6,  1, 46 ); THREEFISH_MIX_PERM( C, 12, 15, 19 ); THREEFISH_MIX_PERM( C, 14, 13, 42 ); THREEFISH_MIX_PERM( C,  8, 11, 44 ); THREEFISH_MIX_PERM( C, 10,  9, 25 );
            THREEFISH_MIX_PERM( C,  0, 15,  9 ); THREEFISH_MIX_PERM( C,  2, 11, 48 ); THREEFISH_MIX_PERM( C,  6, 13, 35 ); THREEFISH_MIX_PERM( C,  4,  9, 52 ); THREEFISH_MIX_PERM( C, 14,  1, 23 ); THREEFISH_MIX_PERM( C,  8,  5, 31 ); THREEFISH_MIX_PERM( C, 10,  3, 37 ); THREEFISH_MIX_PERM( C, 12,  7, 20 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 4 );

            THREEFISH_MIX_PERM( C,  0,  1, 24 ); THREEFISH_MIX_PERM( C,  2,  3, 13 ); THREEFISH_MIX_PERM( C,  4,  5,  8 ); THREEFISH_MIX_PERM( C,  6,  7, 47 ); THREEFISH_MIX_PERM( C,  8,  9,  8 ); THREEFISH_MIX_PERM( C, 10, 11, 17 ); THREEFISH_MIX_PERM( C, 12, 13, 22 ); THREEFISH_MIX_PERM( C, 14, 15, 37 );
            THREEFISH_MIX_PERM( C,  0,  9, 38 ); THREEFISH_MIX_PERM( C,  2, 13, 19 ); THREEFISH_MIX_PERM( C,  6, 11, 10 ); THREEFISH_MIX_PERM( C,  4, 15, 55 ); THREEFISH_MIX_PERM( C, 10,  7, 49 ); THREEFISH_MIX_PERM( C, 12,  3, 18 ); THREEFISH_MIX_PERM( C, 14,  5, 23 ); THREEFISH_MIX_PERM( C,  8,  1, 52 );
            THREEFISH_MIX_PERM( C,  0,  7, 33 ); THREEFISH_MIX_PERM( C,  2,  5,  4 ); THREEFISH_MIX_PERM( C,  4,  3, 51 ); THREEFISH_MIX_PERM( C,  6,  1, 13 ); THREEFISH_MIX_PERM( C, 12, 15, 34 ); THREEFISH_MIX_PERM( C, 14, 13, 41 ); THREEFISH_MIX_PERM( C,  8, 11, 59 ); THREEFISH_MIX_PERM( C, 10,  9, 17 );
            THREEFISH_MIX_PERM( C,  0, 15,  5 ); THREEFISH_MIX_PERM( C,  2, 11, 20 ); THREEFISH_MIX_PERM( C,  6, 13, 48 ); THREEFISH_MIX_PERM( C,  4,  9, 41 ); THREEFISH_MIX_PERM( C, 14,  1, 47 ); THREEFISH_MIX_PERM( C,  8,  5, 28 ); THREEFISH_MIX_PERM( C, 10,  3, 16 ); THREEFISH_MIX_PERM( C, 12,  7, 25 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 5 );

            THREEFISH_MIX_PERM( C,  0,  1, 41 ); THREEFISH_MIX_PERM( C,  2,  3,  9 ); THREEFISH_MIX_PERM( C,  4,  5, 37 ); THREEFISH_MIX_PERM( C,  6,  7, 31 ); THREEFISH_MIX_PERM( C,  8,  9, 12 ); THREEFISH_MIX_PERM( C, 10, 11, 47 ); THREEFISH_MIX_PERM( C, 12, 13, 44 ); THREEFISH_MIX_PERM( C, 14, 15, 30 );
            THREEFISH_MIX_PERM( C,  0,  9, 16 ); THREEFISH_MIX_PERM( C,  2, 13, 34 ); THREEFISH_MIX_PERM( C,  6, 11, 56 ); THREEFISH_MIX_PERM( C,  4, 15, 51 ); THREEFISH_MIX_PERM( C, 10,  7,  4 ); THREEFISH_MIX_PERM( C, 12,  3, 53 ); THREEFISH_MIX_PERM( C, 14,  5, 42 ); THREEFISH_MIX_PERM( C,  8,  1, 41 );
            THREEFISH_MIX_PERM( C,  0,  7, 31 ); THREEFISH_MIX_PERM( C,  2,  5, 44 ); THREEFISH_MIX_PERM( C,  4,  3, 47 ); THREEFISH_MIX_PERM( C,  6,  1, 46 ); THREEFISH_MIX_PERM( C, 12, 15, 19 ); THREEFISH_MIX_PERM( C, 14, 13, 42 ); THREEFISH_MIX_PERM( C,  8, 11, 44 ); THREEFISH_MIX_PERM( C, 10,  9, 25 );
            THREEFISH_MIX_PERM( C,  0, 15,  9 ); THREEFISH_MIX_PERM( C,  2, 11, 48 ); THREEFISH_MIX_PERM( C,  6, 13, 35 ); THREEFISH_MIX_PERM( C,  4,  9, 52 ); THREEFISH_MIX_PERM( C, 14,  1, 23 ); THREEFISH_MIX_PERM( C,  8,  5, 31 ); THREEFISH_MIX_PERM( C, 10,  3, 37 ); THREEFISH_MIX_PERM( C, 12,  7, 20 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 6 );

            THREEFISH_MIX_PERM( C,  0,  1, 24 ); THREEFISH_MIX_PERM( C,  2,  3, 13 ); THREEFISH_MIX_PERM( C,  4,  5,  8 ); THREEFISH_MIX_PERM( C,  6,  7, 47 ); THREEFISH_MIX_PERM( C,  8,  9,  8 ); THREEFISH_MIX_PERM( C, 10, 11, 17 ); THREEFISH_MIX_PERM( C, 12, 13, 22 ); THREEFISH_MIX_PERM( C, 14, 15, 37 );
            THREEFISH_MIX_PERM( C,  0,  9, 38 ); THREEFISH_MIX_PERM( C,  2, 13, 19 ); THREEFISH_MIX_PERM( C,  6, 11, 10 ); THREEFISH_MIX_PERM( C,  4, 15, 55 ); THREEFISH_MIX_PERM( C, 10,  7, 49 ); THREEFISH_MIX_PERM( C, 12,  3, 18 ); THREEFISH_MIX_PERM( C, 14,  5, 23 ); THREEFISH_MIX_PERM( C,  8,  1, 52 );
            THREEFISH_MIX_PERM( C,  0,  7, 33 ); THREEFISH_MIX_PERM( C,  2,  5,  4 ); THREEFISH_MIX_PERM( C,  4,  3, 51 ); THREEFISH_MIX_PERM( C,  6,  1, 13 ); THREEFISH_MIX_PERM( C, 12, 15, 34 ); THREEFISH_MIX_PERM( C, 14, 13, 41 ); THREEFISH_MIX_PERM( C,  8, 11, 59 ); THREEFISH_MIX_PERM( C, 10,  9, 17 );
            THREEFISH_MIX_PERM( C,  0, 15,  5 ); THREEFISH_MIX_PERM( C,  2, 11, 20 ); THREEFISH_MIX_PERM( C,  6, 13, 48 ); THREEFISH_MIX_PERM( C,  4,  9, 41 ); THREEFISH_MIX_PERM( C, 14,  1, 47 ); THREEFISH_MIX_PERM( C,  8,  5, 28 ); THREEFISH_MIX_PERM( C, 10,  3, 16 ); THREEFISH_MIX_PERM( C, 12,  7, 25 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 7 );

            THREEFISH_MIX_PERM( C,  0,  1, 41 ); THREEFISH_MIX_PERM( C,  2,  3,  9 ); THREEFISH_MIX_PERM( C,  4,  5, 37 ); THREEFISH_MIX_PERM( C,  6,  7, 31 ); THREEFISH_MIX_PERM( C,  8,  9, 12 ); THREEFISH_MIX_PERM( C, 10, 11, 47 ); THREEFISH_MIX_PERM( C, 12, 13, 44 ); THREEFISH_MIX_PERM( C, 14, 15, 30 );
            THREEFISH_MIX_PERM( C,  0,  9, 16 ); THREEFISH_MIX_PERM( C,  2, 13, 34 ); THREEFISH_MIX_PERM( C,  6, 11, 56 ); THREEFISH_MIX_PERM( C,  4, 15, 51 ); THREEFISH_MIX_PERM( C, 10,  7,  4 ); THREEFISH_MIX_PERM( C, 12,  3, 53 ); THREEFISH_MIX_PERM( C, 14,  5, 42 ); THREEFISH_MIX_PERM( C,  8,  1, 41 );
            THREEFISH_MIX_PERM( C,  0,  7, 31 ); THREEFISH_MIX_PERM( C,  2,  5, 44 ); THREEFISH_MIX_PERM( C,  4,  3, 47 ); THREEFISH_MIX_PERM( C,  6,  1, 46 ); THREEFISH_MIX_PERM( C, 12, 15, 19 ); THREEFISH_MIX_PERM( C, 14, 13, 42 ); THREEFISH_MIX_PERM( C,  8, 11, 44 ); THREEFISH_MIX_PERM( C, 10,  9, 25 );
            THREEFISH_MIX_PERM( C,  0, 15,  9 ); THREEFISH_MIX_PERM( C,  2, 11, 48 ); THREEFISH_MIX_PERM( C,  6, 13, 35 ); THREEFISH_MIX_PERM( C,  4,  9, 52 ); THREEFISH_MIX_PERM( C, 14,  1, 23 ); THREEFISH_MIX_PERM( C,  8,  5, 31 ); THREEFISH_MIX_PERM( C, 10,  3, 37 ); THREEFISH_MIX_PERM( C, 12,  7, 20 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 8 );

            THREEFISH_MIX_PERM( C,  0,  1, 24 ); THREEFISH_MIX_PERM( C,  2,  3, 13 ); THREEFISH_MIX_PERM( C,  4,  5,  8 ); THREEFISH_MIX_PERM( C,  6,  7, 47 ); THREEFISH_MIX_PERM( C,  8,  9,  8 ); THREEFISH_MIX_PERM( C, 10, 11, 17 ); THREEFISH_MIX_PERM( C, 12, 13, 22 ); THREEFISH_MIX_PERM( C, 14, 15, 37 );
            THREEFISH_MIX_PERM( C,  0,  9, 38 ); THREEFISH_MIX_PERM( C,  2, 13, 19 ); THREEFISH_MIX_PERM( C,  6, 11, 10 ); THREEFISH_MIX_PERM( C,  4, 15, 55 ); THREEFISH_MIX_PERM( C, 10,  7, 49 ); THREEFISH_MIX_PERM( C, 12,  3, 18 ); THREEFISH_MIX_PERM( C, 14,  5, 23 ); THREEFISH_MIX_PERM( C,  8,  1, 52 );
            THREEFISH_MIX_PERM( C,  0,  7, 33 ); THREEFISH_MIX_PERM( C,  2,  5,  4 ); THREEFISH_MIX_PERM( C,  4,  3, 51 ); THREEFISH_MIX_PERM( C,  6,  1, 13 ); THREEFISH_MIX_PERM( C, 12, 15, 34 ); THREEFISH_MIX_PERM( C, 14, 13, 41 ); THREEFISH_MIX_PERM( C,  8, 11, 59 ); THREEFISH_MIX_PERM( C, 10,  9, 17 );
            THREEFISH_MIX_PERM( C,  0, 15,  5 ); THREEFISH_MIX_PERM( C,  2, 11, 20 ); THREEFISH_MIX_PERM( C,  6, 13, 48 ); THREEFISH_MIX_PERM( C,  4,  9, 41 ); THREEFISH_MIX_PERM( C, 14,  1, 47 ); THREEFISH_MIX_PERM( C,  8,  5, 28 ); THREEFISH_MIX_PERM( C, 10,  3, 16 ); THREEFISH_MIX_PERM( C, 12,  7, 25 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 9 );

            THREEFISH_MIX_PERM( C,  0,  1, 41 ); THREEFISH_MIX_PERM( C,  2,  3,  9 ); THREEFISH_MIX_PERM( C,  4,  5, 37 ); THREEFISH_MIX_PERM( C,  6,  7, 31 ); THREEFISH_MIX_PERM( C,  8,  9, 12 ); THREEFISH_MIX_PERM( C, 10, 11, 47 ); THREEFISH_MIX_PERM( C, 12, 13, 44 ); THREEFISH_MIX_PERM( C, 14, 15, 30 );
            THREEFISH_MIX_PERM( C,  0,  9, 16 ); THREEFISH_MIX_PERM( C,  2, 13, 34 ); THREEFISH_MIX_PERM( C,  6, 11, 56 ); THREEFISH_MIX_PERM( C,  4, 15, 51 ); THREEFISH_MIX_PERM( C, 10,  7,  4 ); THREEFISH_MIX_PERM( C, 12,  3, 53 ); THREEFISH_MIX_PERM( C, 14,  5, 42 ); THREEFISH_MIX_PERM( C,  8,  1, 41 );
            THREEFISH_MIX_PERM( C,  0,  7, 31 ); THREEFISH_MIX_PERM( C,  2,  5, 44 ); THREEFISH_MIX_PERM( C,  4,  3, 47 ); THREEFISH_MIX_PERM( C,  6,  1, 46 ); THREEFISH_MIX_PERM( C, 12, 15, 19 ); THREEFISH_MIX_PERM( C, 14, 13, 42 ); THREEFISH_MIX_PERM( C,  8, 11, 44 ); THREEFISH_MIX_PERM( C, 10,  9, 25 );
            THREEFISH_MIX_PERM( C,  0, 15,  9 ); THREEFISH_MIX_PERM( C,  2, 11, 48 ); THREEFISH_MIX_PERM( C,  6, 13, 35 ); THREEFISH_MIX_PERM( C,  4,  9, 52 ); THREEFISH_MIX_PERM( C, 14,  1, 23 ); THREEFISH_MIX_PERM( C,  8,  5, 31 ); THREEFISH_MIX_PERM( C, 10,  3, 37 ); THREEFISH_MIX_PERM( C, 12,  7, 20 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 10 );

            THREEFISH_MIX_PERM( C,  0,  1, 24 ); THREEFISH_MIX_PERM( C,  2,  3, 13 ); THREEFISH_MIX_PERM( C,  4,  5,  8 ); THREEFISH_MIX_PERM( C,  6,  7, 47 ); THREEFISH_MIX_PERM( C,  8,  9,  8 ); THREEFISH_MIX_PERM( C, 10, 11, 17 ); THREEFISH_MIX_PERM( C, 12, 13, 22 ); THREEFISH_MIX_PERM( C, 14, 15, 37 );
            THREEFISH_MIX_PERM( C,  0,  9, 38 ); THREEFISH_MIX_PERM( C,  2, 13, 19 ); THREEFISH_MIX_PERM( C,  6, 11, 10 ); THREEFISH_MIX_PERM( C,  4, 15, 55 ); THREEFISH_MIX_PERM( C, 10,  7, 49 ); THREEFISH_MIX_PERM( C, 12,  3, 18 ); THREEFISH_MIX_PERM( C, 14,  5, 23 ); THREEFISH_MIX_PERM( C,  8,  1, 52 );
            THREEFISH_MIX_PERM( C,  0,  7, 33 ); THREEFISH_MIX_PERM( C,  2,  5,  4 ); THREEFISH_MIX_PERM( C,  4,  3, 51 ); THREEFISH_MIX_PERM( C,  6,  1, 13 ); THREEFISH_MIX_PERM( C, 12, 15, 34 ); THREEFISH_MIX_PERM( C, 14, 13, 41 ); THREEFISH_MIX_PERM( C,  8, 11, 59 ); THREEFISH_MIX_PERM( C, 10,  9, 17 );
            THREEFISH_MIX_PERM( C,  0, 15,  5 ); THREEFISH_MIX_PERM( C,  2, 11, 20 ); THREEFISH_MIX_PERM( C,  6, 13, 48 ); THREEFISH_MIX_PERM( C,  4,  9, 41 ); THREEFISH_MIX_PERM( C, 14,  1, 47 ); THREEFISH_MIX_PERM( C,  8,  5, 28 ); THREEFISH_MIX_PERM( C, 10,  3, 16 ); THREEFISH_MIX_PERM( C, 12,  7, 25 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 11 );

            THREEFISH_MIX_PERM( C,  0,  1, 41 ); THREEFISH_MIX_PERM( C,  2,  3,  9 ); THREEFISH_MIX_PERM( C,  4,  5, 37 ); THREEFISH_MIX_PERM( C,  6,  7, 31 ); THREEFISH_MIX_PERM( C,  8,  9, 12 ); THREEFISH_MIX_PERM( C, 10, 11, 47 ); THREEFISH_MIX_PERM( C, 12, 13, 44 ); THREEFISH_MIX_PERM( C, 14, 15, 30 );
            THREEFISH_MIX_PERM( C,  0,  9, 16 ); THREEFISH_MIX_PERM( C,  2, 13, 34 ); THREEFISH_MIX_PERM( C,  6, 11, 56 ); THREEFISH_MIX_PERM( C,  4, 15, 51 ); THREEFISH_MIX_PERM( C, 10,  7,  4 ); THREEFISH_MIX_PERM( C, 12,  3, 53 ); THREEFISH_MIX_PERM( C, 14,  5, 42 ); THREEFISH_MIX_PERM( C,  8,  1, 41 );
            THREEFISH_MIX_PERM( C,  0,  7, 31 ); THREEFISH_MIX_PERM( C,  2,  5, 44 ); THREEFISH_MIX_PERM( C,  4,  3, 47 ); THREEFISH_MIX_PERM( C,  6,  1, 46 ); THREEFISH_MIX_PERM( C, 12, 15, 19 ); THREEFISH_MIX_PERM( C, 14, 13, 42 ); THREEFISH_MIX_PERM( C,  8, 11, 44 ); THREEFISH_MIX_PERM( C, 10,  9, 25 );
            THREEFISH_MIX_PERM( C,  0, 15,  9 ); THREEFISH_MIX_PERM( C,  2, 11, 48 ); THREEFISH_MIX_PERM( C,  6, 13, 35 ); THREEFISH_MIX_PERM( C,  4,  9, 52 ); THREEFISH_MIX_PERM( C, 14,  1, 23 ); THREEFISH_MIX_PERM( C,  8,  5, 31 ); THREEFISH_MIX_PERM( C, 10,  3, 37 ); THREEFISH_MIX_PERM( C, 12,  7, 20 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 12 );

            THREEFISH_MIX_PERM( C,  0,  1, 24 ); THREEFISH_MIX_PERM( C,  2,  3, 13 ); THREEFISH_MIX_PERM( C,  4,  5,  8 ); THREEFISH_MIX_PERM( C,  6,  7, 47 ); THREEFISH_MIX_PERM( C,  8,  9,  8 ); THREEFISH_MIX_PERM( C, 10, 11, 17 ); THREEFISH_MIX_PERM( C, 12, 13, 22 ); THREEFISH_MIX_PERM( C, 14, 15, 37 );
            THREEFISH_MIX_PERM( C,  0,  9, 38 ); THREEFISH_MIX_PERM( C,  2, 13, 19 ); THREEFISH_MIX_PERM( C,  6, 11, 10 ); THREEFISH_MIX_PERM( C,  4, 15, 55 ); THREEFISH_MIX_PERM( C, 10,  7, 49 ); THREEFISH_MIX_PERM( C, 12,  3, 18 ); THREEFISH_MIX_PERM( C, 14,  5, 23 ); THREEFISH_MIX_PERM( C,  8,  1, 52 );
            THREEFISH_MIX_PERM( C,  0,  7, 33 ); THREEFISH_MIX_PERM( C,  2,  5,  4 ); THREEFISH_MIX_PERM( C,  4,  3, 51 ); THREEFISH_MIX_PERM( C,  6,  1, 13 ); THREEFISH_MIX_PERM( C, 12, 15, 34 ); THREEFISH_MIX_PERM( C, 14, 13, 41 ); THREEFISH_MIX_PERM( C,  8, 11, 59 ); THREEFISH_MIX_PERM( C, 10,  9, 17 );
            THREEFISH_MIX_PERM( C,  0, 15,  5 ); THREEFISH_MIX_PERM( C,  2, 11, 20 ); THREEFISH_MIX_PERM( C,  6, 13, 48 ); THREEFISH_MIX_PERM( C,  4,  9, 41 ); THREEFISH_MIX_PERM( C, 14,  1, 47 ); THREEFISH_MIX_PERM( C,  8,  5, 28 ); THREEFISH_MIX_PERM( C, 10,  3, 16 ); THREEFISH_MIX_PERM( C, 12,  7, 25 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 13 );

            THREEFISH_MIX_PERM( C,  0,  1, 41 ); THREEFISH_MIX_PERM( C,  2,  3,  9 ); THREEFISH_MIX_PERM( C,  4,  5, 37 ); THREEFISH_MIX_PERM( C,  6,  7, 31 ); THREEFISH_MIX_PERM( C,  8,  9, 12 ); THREEFISH_MIX_PERM( C, 10, 11, 47 ); THREEFISH_MIX_PERM( C, 12, 13, 44 ); THREEFISH_MIX_PERM( C, 14, 15, 30 );
            THREEFISH_MIX_PERM( C,  0,  9, 16 ); THREEFISH_MIX_PERM( C,  2, 13, 34 ); THREEFISH_MIX_PERM( C,  6, 11, 56 ); THREEFISH_MIX_PERM( C,  4, 15, 51 ); THREEFISH_MIX_PERM( C, 10,  7,  4 ); THREEFISH_MIX_PERM( C, 12,  3, 53 ); THREEFISH_MIX_PERM( C, 14,  5, 42 ); THREEFISH_MIX_PERM( C,  8,  1, 41 );
            THREEFISH_MIX_PERM( C,  0,  7, 31 ); THREEFISH_MIX_PERM( C,  2,  5, 44 ); THREEFISH_MIX_PERM( C,  4,  3, 47 ); THREEFISH_MIX_PERM( C,  6,  1, 46 ); THREEFISH_MIX_PERM( C, 12, 15, 19 ); THREEFISH_MIX_PERM( C, 14, 13, 42 ); THREEFISH_MIX_PERM( C,  8, 11, 44 ); THREEFISH_MIX_PERM( C, 10,  9, 25 );
            THREEFISH_MIX_PERM( C,  0, 15,  9 ); THREEFISH_MIX_PERM( C,  2, 11, 48 ); THREEFISH_MIX_PERM( C,  6, 13, 35 ); THREEFISH_MIX_PERM( C,  4,  9, 52 ); THREEFISH_MIX_PERM( C, 14,  1, 23 ); THREEFISH_MIX_PERM( C,  8,  5, 31 ); THREEFISH_MIX_PERM( C, 10,  3, 37 ); THREEFISH_MIX_PERM( C, 12,  7, 20 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 14 );

            THREEFISH_MIX_PERM( C,  0,  1, 24 ); THREEFISH_MIX_PERM( C,  2,  3, 13 ); THREEFISH_MIX_PERM( C,  4,  5,  8 ); THREEFISH_MIX_PERM( C,  6,  7, 47 ); THREEFISH_MIX_PERM( C,  8,  9,  8 ); THREEFISH_MIX_PERM( C, 10, 11, 17 ); THREEFISH_MIX_PERM( C, 12, 13, 22 ); THREEFISH_MIX_PERM( C, 14, 15, 37 );
            THREEFISH_MIX_PERM( C,  0,  9, 38 ); THREEFISH_MIX_PERM( C,  2, 13, 19 ); THREEFISH_MIX_PERM( C,  6, 11, 10 ); THREEFISH_MIX_PERM( C,  4, 15, 55 ); THREEFISH_MIX_PERM( C, 10,  7, 49 ); THREEFISH_MIX_PERM( C, 12,  3, 18 ); THREEFISH_MIX_PERM( C, 14,  5, 23 ); THREEFISH_MIX_PERM( C,  8,  1, 52 );
            THREEFISH_MIX_PERM( C,  0,  7, 33 ); THREEFISH_MIX_PERM( C,  2,  5,  4 ); THREEFISH_MIX_PERM( C,  4,  3, 51 ); THREEFISH_MIX_PERM( C,  6,  1, 13 ); THREEFISH_MIX_PERM( C, 12, 15, 34 ); THREEFISH_MIX_PERM( C, 14, 13, 41 ); THREEFISH_MIX_PERM( C,  8, 11, 59 ); THREEFISH_MIX_PERM( C, 10,  9, 17 );
            THREEFISH_MIX_PERM( C,  0, 15,  5 ); THREEFISH_MIX_PERM( C,  2, 11, 20 ); THREEFISH_MIX_PERM( C,  6, 13, 48 ); THREEFISH_MIX_PERM( C,  4,  9, 41 ); THREEFISH_MIX_PERM( C, 14,  1, 47 ); THREEFISH_MIX_PERM( C,  8,  5, 28 ); THREEFISH_MIX_PERM( C, 10,  3, 16 ); THREEFISH_MIX_PERM( C, 12,  7, 25 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 15 );

            THREEFISH_MIX_PERM( C,  0,  1, 41 ); THREEFISH_MIX_PERM( C,  2,  3,  9 ); THREEFISH_MIX_PERM( C,  4,  5, 37 ); THREEFISH_MIX_PERM( C,  6,  7, 31 ); THREEFISH_MIX_PERM( C,  8,  9, 12 ); THREEFISH_MIX_PERM( C, 10, 11, 47 ); THREEFISH_MIX_PERM( C, 12, 13, 44 ); THREEFISH_MIX_PERM( C, 14, 15, 30 );
            THREEFISH_MIX_PERM( C,  0,  9, 16 ); THREEFISH_MIX_PERM( C,  2, 13, 34 ); THREEFISH_MIX_PERM( C,  6, 11, 56 ); THREEFISH_MIX_PERM( C,  4, 15, 51 ); THREEFISH_MIX_PERM( C, 10,  7,  4 ); THREEFISH_MIX_PERM( C, 12,  3, 53 ); THREEFISH_MIX_PERM( C, 14,  5, 42 ); THREEFISH_MIX_PERM( C,  8,  1, 41 );
            THREEFISH_MIX_PERM( C,  0,  7, 31 ); THREEFISH_MIX_PERM( C,  2,  5, 44 ); THREEFISH_MIX_PERM( C,  4,  3, 47 ); THREEFISH_MIX_PERM( C,  6,  1, 46 ); THREEFISH_MIX_PERM( C, 12, 15, 19 ); THREEFISH_MIX_PERM( C, 14, 13, 42 ); THREEFISH_MIX_PERM( C,  8, 11, 44 ); THREEFISH_MIX_PERM( C, 10,  9, 25 );
            THREEFISH_MIX_PERM( C,  0, 15,  9 ); THREEFISH_MIX_PERM( C,  2, 11, 48 ); THREEFISH_MIX_PERM( C,  6, 13, 35 ); THREEFISH_MIX_PERM( C,  4,  9, 52 ); THREEFISH_MIX_PERM( C, 14,  1, 23 ); THREEFISH_MIX_PERM( C,  8,  5, 31 ); THREEFISH_MIX_PERM( C, 10,  3, 37 ); THREEFISH_MIX_PERM( C, 12,  7, 20 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 16 );

            THREEFISH_MIX_PERM( C,  0,  1, 24 ); THREEFISH_MIX_PERM( C,  2,  3, 13 ); THREEFISH_MIX_PERM( C,  4,  5,  8 ); THREEFISH_MIX_PERM( C,  6,  7, 47 ); THREEFISH_MIX_PERM( C,  8,  9,  8 ); THREEFISH_MIX_PERM( C, 10, 11, 17 ); THREEFISH_MIX_PERM( C, 12, 13, 22 ); THREEFISH_MIX_PERM( C, 14, 15, 37 );
            THREEFISH_MIX_PERM( C,  0,  9, 38 ); THREEFISH_MIX_PERM( C,  2, 13, 19 ); THREEFISH_MIX_PERM( C,  6, 11, 10 ); THREEFISH_MIX_PERM( C,  4, 15, 55 ); THREEFISH_MIX_PERM( C, 10,  7, 49 ); THREEFISH_MIX_PERM( C, 12,  3, 18 ); THREEFISH_MIX_PERM( C, 14,  5, 23 ); THREEFISH_MIX_PERM( C,  8,  1, 52 );
            THREEFISH_MIX_PERM( C,  0,  7, 33 ); THREEFISH_MIX_PERM( C,  2,  5,  4 ); THREEFISH_MIX_PERM( C,  4,  3, 51 ); THREEFISH_MIX_PERM( C,  6,  1, 13 ); THREEFISH_MIX_PERM( C, 12, 15, 34 ); THREEFISH_MIX_PERM( C, 14, 13, 41 ); THREEFISH_MIX_PERM( C,  8, 11, 59 ); THREEFISH_MIX_PERM( C, 10,  9, 17 );
            THREEFISH_MIX_PERM( C,  0, 15,  5 ); THREEFISH_MIX_PERM( C,  2, 11, 20 ); THREEFISH_MIX_PERM( C,  6, 13, 48 ); THREEFISH_MIX_PERM( C,  4,  9, 41 ); THREEFISH_MIX_PERM( C, 14,  1, 47 ); THREEFISH_MIX_PERM( C,  8,  5, 28 ); THREEFISH_MIX_PERM( C, 10,  3, 16 ); THREEFISH_MIX_PERM( C, 12,  7, 25 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 17 );

            THREEFISH_MIX_PERM( C,  0,  1, 41 ); THREEFISH_MIX_PERM( C,  2,  3,  9 ); THREEFISH_MIX_PERM( C,  4,  5, 37 ); THREEFISH_MIX_PERM( C,  6,  7, 31 ); THREEFISH_MIX_PERM( C,  8,  9, 12 ); THREEFISH_MIX_PERM( C, 10, 11, 47 ); THREEFISH_MIX_PERM( C, 12, 13, 44 ); THREEFISH_MIX_PERM( C, 14, 15, 30 );
            THREEFISH_MIX_PERM( C,  0,  9, 16 ); THREEFISH_MIX_PERM( C,  2, 13, 34 ); THREEFISH_MIX_PERM( C,  6, 11, 56 ); THREEFISH_MIX_PERM( C,  4, 15, 51 ); THREEFISH_MIX_PERM( C, 10,  7,  4 ); THREEFISH_MIX_PERM( C, 12,  3, 53 ); THREEFISH_MIX_PERM( C, 14,  5, 42 ); THREEFISH_MIX_PERM( C,  8,  1, 41 );
            THREEFISH_MIX_PERM( C,  0,  7, 31 ); THREEFISH_MIX_PERM( C,  2,  5, 44 ); THREEFISH_MIX_PERM( C,  4,  3, 47 ); THREEFISH_MIX_PERM( C,  6,  1, 46 ); THREEFISH_MIX_PERM( C, 12, 15, 19 ); THREEFISH_MIX_PERM( C, 14, 13, 42 ); THREEFISH_MIX_PERM( C,  8, 11, 44 ); THREEFISH_MIX_PERM( C, 10,  9, 25 );
            THREEFISH_MIX_PERM( C,  0, 15,  9 ); THREEFISH_MIX_PERM( C,  2, 11, 48 ); THREEFISH_MIX_PERM( C,  6, 13, 35 ); THREEFISH_MIX_PERM( C,  4,  9, 52 ); THREEFISH_MIX_PERM( C, 14,  1, 23 ); THREEFISH_MIX_PERM( C,  8,  5, 31 ); THREEFISH_MIX_PERM( C, 10,  3, 37 ); THREEFISH_MIX_PERM( C, 12,  7, 20 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 18 );

            THREEFISH_MIX_PERM( C,  0,  1, 24 ); THREEFISH_MIX_PERM( C,  2,  3, 13 ); THREEFISH_MIX_PERM( C,  4,  5,  8 ); THREEFISH_MIX_PERM( C,  6,  7, 47 ); THREEFISH_MIX_PERM( C,  8,  9,  8 ); THREEFISH_MIX_PERM( C, 10, 11, 17 ); THREEFISH_MIX_PERM( C, 12, 13, 22 ); THREEFISH_MIX_PERM( C, 14, 15, 37 );
            THREEFISH_MIX_PERM( C,  0,  9, 38 ); THREEFISH_MIX_PERM( C,  2, 13, 19 ); THREEFISH_MIX_PERM( C,  6, 11, 10 ); THREEFISH_MIX_PERM( C,  4, 15, 55 ); THREEFISH_MIX_PERM( C, 10,  7, 49 ); THREEFISH_MIX_PERM( C, 12,  3, 18 ); THREEFISH_MIX_PERM( C, 14,  5, 23 ); THREEFISH_MIX_PERM( C,  8,  1, 52 );
            THREEFISH_MIX_PERM( C,  0,  7, 33 ); THREEFISH_MIX_PERM( C,  2,  5,  4 ); THREEFISH_MIX_PERM( C,  4,  3, 51 ); THREEFISH_MIX_PERM( C,  6,  1, 13 ); THREEFISH_MIX_PERM( C, 12, 15, 34 ); THREEFISH_MIX_PERM( C, 14, 13, 41 ); THREEFISH_MIX_PERM( C,  8, 11, 59 ); THREEFISH_MIX_PERM( C, 10,  9, 17 );
            THREEFISH_MIX_PERM( C,  0, 15,  5 ); THREEFISH_MIX_PERM( C,  2, 11, 20 ); THREEFISH_MIX_PERM( C,  6, 13, 48 ); THREEFISH_MIX_PERM( C,  4,  9, 41 ); THREEFISH_MIX_PERM( C, 14,  1, 47 ); THREEFISH_MIX_PERM( C,  8,  5, 28 ); THREEFISH_MIX_PERM( C, 10,  3, 16 ); THREEFISH_MIX_PERM( C, 12,  7, 25 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 19 );

            THREEFISH_MIX_PERM( C,  0,  1, 41 ); THREEFISH_MIX_PERM( C,  2,  3,  9 ); THREEFISH_MIX_PERM( C,  4,  5, 37 ); THREEFISH_MIX_PERM( C,  6,  7, 31 ); THREEFISH_MIX_PERM( C,  8,  9, 12 ); THREEFISH_MIX_PERM( C, 10, 11, 47 ); THREEFISH_MIX_PERM( C, 12, 13, 44 ); THREEFISH_MIX_PERM( C, 14, 15, 30 );
            THREEFISH_MIX_PERM( C,  0,  9, 16 ); THREEFISH_MIX_PERM( C,  2, 13, 34 ); THREEFISH_MIX_PERM( C,  6, 11, 56 ); THREEFISH_MIX_PERM( C,  4, 15, 51 ); THREEFISH_MIX_PERM( C, 10,  7,  4 ); THREEFISH_MIX_PERM( C, 12,  3, 53 ); THREEFISH_MIX_PERM( C, 14,  5, 42 ); THREEFISH_MIX_PERM( C,  8,  1, 41 );
            THREEFISH_MIX_PERM( C,  0,  7, 31 ); THREEFISH_MIX_PERM( C,  2,  5, 44 ); THREEFISH_MIX_PERM( C,  4,  3, 47 ); THREEFISH_MIX_PERM( C,  6,  1, 46 ); THREEFISH_MIX_PERM( C, 12, 15, 19 ); THREEFISH_MIX_PERM( C, 14, 13, 42 ); THREEFISH_MIX_PERM( C,  8, 11, 44 ); THREEFISH_MIX_PERM( C, 10,  9, 25 );
            THREEFISH_MIX_PERM( C,  0, 15,  9 ); THREEFISH_MIX_PERM( C,  2, 11, 48 ); THREEFISH_MIX_PERM( C,  6, 13, 35 ); THREEFISH_MIX_PERM( C,  4,  9, 52 ); THREEFISH_MIX_PERM( C, 14,  1, 23 ); THREEFISH_MIX_PERM( C,  8,  5, 31 ); THREEFISH_MIX_PERM( C, 10,  3, 37 ); THREEFISH_MIX_PERM( C, 12,  7, 20 );

            THREEFISH1024_ADD_SUBKEY( C, K, T, 20 );

            break;
    }
}

/*
 * Decrypt one data block
 */
static void threefish_dec( mbedtls_threefish_context *ctx,
                           const unsigned char *input,
                           const unsigned char *output )
{
    uint64_t *P = (uint64_t *)output;
    const uint64_t *C = (const uint64_t *)input;
    uint64_t *K = (uint64_t *)ctx->key;
    uint64_t *T = (uint64_t *)ctx->tweak;

    memcpy( P, C, sizeof( uint64_t ) * ( ctx->keybits >> 6 ) );

    switch( ctx->keybits )
    {
        case 256:
            THREEFISH256_SUB_SUBKEY( P, K, T, 18 );

            THREEFISH_INV_MIX_PERM( P, 0, 3, 32 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 32 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 58 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 12 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 33 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 17 );

            THREEFISH_INV_MIX_PERM( P, 0, 3,  5 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 37 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 23 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 40 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 52 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 57 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 14 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 16 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 16 );

            THREEFISH_INV_MIX_PERM( P, 0, 3, 32 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 32 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 58 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 12 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 33 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 15 );

            THREEFISH_INV_MIX_PERM( P, 0, 3,  5 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 37 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 23 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 40 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 52 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 57 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 14 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 16 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 14 );

            THREEFISH_INV_MIX_PERM( P, 0, 3, 32 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 32 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 58 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 12 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 33 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 13 );

            THREEFISH_INV_MIX_PERM( P, 0, 3,  5 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 37 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 23 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 40 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 52 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 57 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 14 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 16 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 12 );

            THREEFISH_INV_MIX_PERM( P, 0, 3, 32 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 32 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 58 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 12 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 33 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 11 );

            THREEFISH_INV_MIX_PERM( P, 0, 3,  5 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 37 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 23 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 40 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 52 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 57 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 14 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 16 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 10 );

            THREEFISH_INV_MIX_PERM( P, 0, 3, 32 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 32 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 58 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 12 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 33 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 9 );

            THREEFISH_INV_MIX_PERM( P, 0, 3,  5 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 37 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 23 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 40 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 52 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 57 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 14 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 16 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 8 );

            THREEFISH_INV_MIX_PERM( P, 0, 3, 32 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 32 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 58 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 12 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 33 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 7 );

            THREEFISH_INV_MIX_PERM( P, 0, 3,  5 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 37 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 23 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 40 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 52 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 57 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 14 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 16 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 6 );

            THREEFISH_INV_MIX_PERM( P, 0, 3, 32 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 32 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 58 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 12 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 33 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 5 );

            THREEFISH_INV_MIX_PERM( P, 0, 3,  5 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 37 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 23 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 40 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 52 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 57 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 14 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 16 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 4 );

            THREEFISH_INV_MIX_PERM( P, 0, 3, 32 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 32 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 58 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 12 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 33 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 3 );

            THREEFISH_INV_MIX_PERM( P, 0, 3,  5 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 37 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 23 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 40 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 52 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 57 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 14 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 16 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 2 );

            THREEFISH_INV_MIX_PERM( P, 0, 3, 32 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 32 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 58 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 12 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 33 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 1 );

            THREEFISH_INV_MIX_PERM( P, 0, 3,  5 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 37 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 23 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 40 );
            THREEFISH_INV_MIX_PERM( P, 0, 3, 52 ); THREEFISH_INV_MIX_PERM( P, 2, 1, 57 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 14 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 16 );

            THREEFISH256_SUB_SUBKEY( P, K, T, 0 );

            break;

        case 512:
            THREEFISH512_SUB_SUBKEY( P, K, T, 18 );

            THREEFISH_INV_MIX_PERM( P, 6, 1,  8 ); THREEFISH_INV_MIX_PERM( P, 0, 7, 35 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 56 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 29 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 43 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 13 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 50 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 10 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 17 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 30 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 34 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 24 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 17 );

            THREEFISH_INV_MIX_PERM( P, 6, 1, 44 ); THREEFISH_INV_MIX_PERM( P, 0, 7,  9 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 54 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 56 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 17 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 49 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 36 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 39 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 33 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 27 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 14 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 42 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 36 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 19 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 37 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 16 );

            THREEFISH_INV_MIX_PERM( P, 6, 1,  8 ); THREEFISH_INV_MIX_PERM( P, 0, 7, 35 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 56 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 29 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 43 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 13 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 50 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 10 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 17 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 30 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 34 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 24 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 15 );

            THREEFISH_INV_MIX_PERM( P, 6, 1, 44 ); THREEFISH_INV_MIX_PERM( P, 0, 7,  9 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 54 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 56 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 17 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 49 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 36 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 39 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 33 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 27 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 14 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 42 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 36 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 19 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 37 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 14 );

            THREEFISH_INV_MIX_PERM( P, 6, 1,  8 ); THREEFISH_INV_MIX_PERM( P, 0, 7, 35 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 56 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 29 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 43 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 13 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 50 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 10 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 17 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 30 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 34 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 24 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 13 );

            THREEFISH_INV_MIX_PERM( P, 6, 1, 44 ); THREEFISH_INV_MIX_PERM( P, 0, 7,  9 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 54 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 56 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 17 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 49 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 36 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 39 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 33 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 27 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 14 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 42 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 36 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 19 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 37 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 12 );

            THREEFISH_INV_MIX_PERM( P, 6, 1,  8 ); THREEFISH_INV_MIX_PERM( P, 0, 7, 35 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 56 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 29 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 43 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 13 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 50 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 10 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 17 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 30 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 34 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 24 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 11 );

            THREEFISH_INV_MIX_PERM( P, 6, 1, 44 ); THREEFISH_INV_MIX_PERM( P, 0, 7,  9 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 54 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 56 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 17 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 49 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 36 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 39 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 33 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 27 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 14 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 42 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 36 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 19 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 37 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 10 );

            THREEFISH_INV_MIX_PERM( P, 6, 1,  8 ); THREEFISH_INV_MIX_PERM( P, 0, 7, 35 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 56 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 29 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 43 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 13 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 50 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 10 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 17 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 30 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 34 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 24 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 9 );

            THREEFISH_INV_MIX_PERM( P, 6, 1, 44 ); THREEFISH_INV_MIX_PERM( P, 0, 7,  9 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 54 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 56 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 17 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 49 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 36 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 39 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 33 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 27 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 14 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 42 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 36 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 19 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 37 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 8 );

            THREEFISH_INV_MIX_PERM( P, 6, 1,  8 ); THREEFISH_INV_MIX_PERM( P, 0, 7, 35 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 56 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 29 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 43 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 13 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 50 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 10 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 17 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 30 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 34 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 24 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 7 );

            THREEFISH_INV_MIX_PERM( P, 6, 1, 44 ); THREEFISH_INV_MIX_PERM( P, 0, 7,  9 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 54 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 56 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 17 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 49 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 36 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 39 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 33 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 27 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 14 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 42 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 36 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 19 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 37 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 6 );

            THREEFISH_INV_MIX_PERM( P, 6, 1,  8 ); THREEFISH_INV_MIX_PERM( P, 0, 7, 35 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 56 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 29 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 43 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 13 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 50 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 10 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 17 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 30 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 34 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 24 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 5 );

            THREEFISH_INV_MIX_PERM( P, 6, 1, 44 ); THREEFISH_INV_MIX_PERM( P, 0, 7,  9 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 54 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 56 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 17 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 49 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 36 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 39 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 33 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 27 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 14 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 42 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 36 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 19 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 37 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 4 );

            THREEFISH_INV_MIX_PERM( P, 6, 1,  8 ); THREEFISH_INV_MIX_PERM( P, 0, 7, 35 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 56 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 29 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 43 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 13 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 50 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 10 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 17 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 30 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 34 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 24 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 3 );

            THREEFISH_INV_MIX_PERM( P, 6, 1, 44 ); THREEFISH_INV_MIX_PERM( P, 0, 7,  9 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 54 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 56 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 17 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 49 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 36 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 39 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 33 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 27 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 14 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 42 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 36 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 19 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 37 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 2 );

            THREEFISH_INV_MIX_PERM( P, 6, 1,  8 ); THREEFISH_INV_MIX_PERM( P, 0, 7, 35 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 56 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 22 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 25 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 29 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 43 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 13 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 50 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 10 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 17 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 39 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 30 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 34 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 24 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 1 );

            THREEFISH_INV_MIX_PERM( P, 6, 1, 44 ); THREEFISH_INV_MIX_PERM( P, 0, 7,  9 ); THREEFISH_INV_MIX_PERM( P, 2, 5, 54 ); THREEFISH_INV_MIX_PERM( P, 4, 3, 56 );
            THREEFISH_INV_MIX_PERM( P, 4, 1, 17 ); THREEFISH_INV_MIX_PERM( P, 6, 3, 49 ); THREEFISH_INV_MIX_PERM( P, 0, 5, 36 ); THREEFISH_INV_MIX_PERM( P, 2, 7, 39 );
            THREEFISH_INV_MIX_PERM( P, 2, 1, 33 ); THREEFISH_INV_MIX_PERM( P, 4, 7, 27 ); THREEFISH_INV_MIX_PERM( P, 6, 5, 14 ); THREEFISH_INV_MIX_PERM( P, 0, 3, 42 );
            THREEFISH_INV_MIX_PERM( P, 0, 1, 46 ); THREEFISH_INV_MIX_PERM( P, 2, 3, 36 ); THREEFISH_INV_MIX_PERM( P, 4, 5, 19 ); THREEFISH_INV_MIX_PERM( P, 6, 7, 37 );

            THREEFISH512_SUB_SUBKEY( P, K, T, 0 );

            break;

        case 1024:
            THREEFISH1024_SUB_SUBKEY( P, K, T, 20 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  9 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 48 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 35 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 52 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 31 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 37 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 20 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  2,  5, 44 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 47 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 46 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 19 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 42 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 44 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 16 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 34 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 56 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 51 ); THREEFISH_INV_MIX_PERM( P, 10,  7,  4 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 53 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 42 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 41 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 41 ); THREEFISH_INV_MIX_PERM( P,  2,  3,  9 ); THREEFISH_INV_MIX_PERM( P,  4,  5, 37 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  8,  9, 12 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 47 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 44 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 30 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 19 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  5 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 20 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 48 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 41 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 28 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 16 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 33 ); THREEFISH_INV_MIX_PERM( P,  2,  5,  4 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 51 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 13 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 34 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 41 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 59 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 17 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 38 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 19 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 10 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 55 ); THREEFISH_INV_MIX_PERM( P, 10,  7, 49 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 18 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 52 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 24 ); THREEFISH_INV_MIX_PERM( P,  2,  3, 13 ); THREEFISH_INV_MIX_PERM( P,  4,  5,  8 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  9,  8 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 17 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 22 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 37 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 18 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  9 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 48 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 35 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 52 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 31 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 37 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 20 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  2,  5, 44 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 47 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 46 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 19 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 42 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 44 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 16 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 34 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 56 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 51 ); THREEFISH_INV_MIX_PERM( P, 10,  7,  4 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 53 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 42 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 41 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 41 ); THREEFISH_INV_MIX_PERM( P,  2,  3,  9 ); THREEFISH_INV_MIX_PERM( P,  4,  5, 37 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  8,  9, 12 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 47 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 44 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 30 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 17 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  5 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 20 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 48 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 41 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 28 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 16 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 33 ); THREEFISH_INV_MIX_PERM( P,  2,  5,  4 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 51 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 13 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 34 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 41 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 59 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 17 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 38 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 19 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 10 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 55 ); THREEFISH_INV_MIX_PERM( P, 10,  7, 49 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 18 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 52 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 24 ); THREEFISH_INV_MIX_PERM( P,  2,  3, 13 ); THREEFISH_INV_MIX_PERM( P,  4,  5,  8 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  9,  8 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 17 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 22 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 37 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 16 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  9 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 48 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 35 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 52 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 31 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 37 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 20 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  2,  5, 44 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 47 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 46 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 19 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 42 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 44 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 16 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 34 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 56 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 51 ); THREEFISH_INV_MIX_PERM( P, 10,  7,  4 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 53 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 42 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 41 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 41 ); THREEFISH_INV_MIX_PERM( P,  2,  3,  9 ); THREEFISH_INV_MIX_PERM( P,  4,  5, 37 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  8,  9, 12 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 47 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 44 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 30 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 15 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  5 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 20 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 48 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 41 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 28 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 16 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 33 ); THREEFISH_INV_MIX_PERM( P,  2,  5,  4 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 51 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 13 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 34 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 41 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 59 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 17 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 38 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 19 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 10 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 55 ); THREEFISH_INV_MIX_PERM( P, 10,  7, 49 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 18 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 52 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 24 ); THREEFISH_INV_MIX_PERM( P,  2,  3, 13 ); THREEFISH_INV_MIX_PERM( P,  4,  5,  8 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  9,  8 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 17 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 22 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 37 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 14 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  9 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 48 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 35 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 52 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 31 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 37 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 20 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  2,  5, 44 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 47 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 46 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 19 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 42 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 44 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 16 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 34 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 56 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 51 ); THREEFISH_INV_MIX_PERM( P, 10,  7,  4 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 53 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 42 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 41 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 41 ); THREEFISH_INV_MIX_PERM( P,  2,  3,  9 ); THREEFISH_INV_MIX_PERM( P,  4,  5, 37 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  8,  9, 12 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 47 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 44 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 30 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 13 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  5 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 20 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 48 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 41 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 28 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 16 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 33 ); THREEFISH_INV_MIX_PERM( P,  2,  5,  4 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 51 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 13 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 34 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 41 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 59 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 17 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 38 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 19 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 10 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 55 ); THREEFISH_INV_MIX_PERM( P, 10,  7, 49 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 18 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 52 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 24 ); THREEFISH_INV_MIX_PERM( P,  2,  3, 13 ); THREEFISH_INV_MIX_PERM( P,  4,  5,  8 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  9,  8 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 17 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 22 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 37 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 12 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  9 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 48 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 35 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 52 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 31 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 37 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 20 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  2,  5, 44 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 47 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 46 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 19 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 42 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 44 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 16 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 34 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 56 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 51 ); THREEFISH_INV_MIX_PERM( P, 10,  7,  4 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 53 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 42 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 41 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 41 ); THREEFISH_INV_MIX_PERM( P,  2,  3,  9 ); THREEFISH_INV_MIX_PERM( P,  4,  5, 37 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  8,  9, 12 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 47 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 44 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 30 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 11 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  5 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 20 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 48 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 41 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 28 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 16 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 33 ); THREEFISH_INV_MIX_PERM( P,  2,  5,  4 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 51 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 13 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 34 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 41 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 59 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 17 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 38 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 19 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 10 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 55 ); THREEFISH_INV_MIX_PERM( P, 10,  7, 49 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 18 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 52 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 24 ); THREEFISH_INV_MIX_PERM( P,  2,  3, 13 ); THREEFISH_INV_MIX_PERM( P,  4,  5,  8 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  9,  8 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 17 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 22 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 37 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 10 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  9 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 48 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 35 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 52 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 31 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 37 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 20 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  2,  5, 44 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 47 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 46 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 19 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 42 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 44 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 16 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 34 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 56 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 51 ); THREEFISH_INV_MIX_PERM( P, 10,  7,  4 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 53 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 42 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 41 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 41 ); THREEFISH_INV_MIX_PERM( P,  2,  3,  9 ); THREEFISH_INV_MIX_PERM( P,  4,  5, 37 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  8,  9, 12 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 47 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 44 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 30 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 9 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  5 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 20 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 48 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 41 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 28 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 16 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 33 ); THREEFISH_INV_MIX_PERM( P,  2,  5,  4 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 51 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 13 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 34 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 41 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 59 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 17 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 38 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 19 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 10 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 55 ); THREEFISH_INV_MIX_PERM( P, 10,  7, 49 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 18 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 52 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 24 ); THREEFISH_INV_MIX_PERM( P,  2,  3, 13 ); THREEFISH_INV_MIX_PERM( P,  4,  5,  8 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  9,  8 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 17 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 22 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 37 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 8 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  9 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 48 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 35 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 52 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 31 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 37 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 20 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  2,  5, 44 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 47 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 46 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 19 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 42 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 44 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 16 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 34 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 56 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 51 ); THREEFISH_INV_MIX_PERM( P, 10,  7,  4 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 53 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 42 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 41 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 41 ); THREEFISH_INV_MIX_PERM( P,  2,  3,  9 ); THREEFISH_INV_MIX_PERM( P,  4,  5, 37 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  8,  9, 12 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 47 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 44 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 30 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 7 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  5 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 20 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 48 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 41 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 28 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 16 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 33 ); THREEFISH_INV_MIX_PERM( P,  2,  5,  4 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 51 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 13 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 34 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 41 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 59 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 17 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 38 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 19 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 10 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 55 ); THREEFISH_INV_MIX_PERM( P, 10,  7, 49 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 18 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 52 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 24 ); THREEFISH_INV_MIX_PERM( P,  2,  3, 13 ); THREEFISH_INV_MIX_PERM( P,  4,  5,  8 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  9,  8 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 17 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 22 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 37 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 6 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  9 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 48 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 35 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 52 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 31 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 37 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 20 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  2,  5, 44 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 47 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 46 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 19 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 42 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 44 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 16 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 34 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 56 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 51 ); THREEFISH_INV_MIX_PERM( P, 10,  7,  4 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 53 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 42 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 41 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 41 ); THREEFISH_INV_MIX_PERM( P,  2,  3,  9 ); THREEFISH_INV_MIX_PERM( P,  4,  5, 37 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  8,  9, 12 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 47 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 44 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 30 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 5 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  5 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 20 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 48 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 41 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 28 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 16 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 33 ); THREEFISH_INV_MIX_PERM( P,  2,  5,  4 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 51 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 13 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 34 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 41 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 59 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 17 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 38 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 19 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 10 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 55 ); THREEFISH_INV_MIX_PERM( P, 10,  7, 49 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 18 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 52 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 24 ); THREEFISH_INV_MIX_PERM( P,  2,  3, 13 ); THREEFISH_INV_MIX_PERM( P,  4,  5,  8 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  9,  8 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 17 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 22 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 37 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 4 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  9 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 48 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 35 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 52 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 31 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 37 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 20 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  2,  5, 44 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 47 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 46 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 19 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 42 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 44 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 16 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 34 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 56 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 51 ); THREEFISH_INV_MIX_PERM( P, 10,  7,  4 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 53 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 42 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 41 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 41 ); THREEFISH_INV_MIX_PERM( P,  2,  3,  9 ); THREEFISH_INV_MIX_PERM( P,  4,  5, 37 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  8,  9, 12 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 47 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 44 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 30 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 3 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  5 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 20 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 48 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 41 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 28 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 16 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 33 ); THREEFISH_INV_MIX_PERM( P,  2,  5,  4 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 51 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 13 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 34 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 41 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 59 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 17 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 38 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 19 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 10 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 55 ); THREEFISH_INV_MIX_PERM( P, 10,  7, 49 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 18 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 52 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 24 ); THREEFISH_INV_MIX_PERM( P,  2,  3, 13 ); THREEFISH_INV_MIX_PERM( P,  4,  5,  8 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  9,  8 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 17 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 22 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 37 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 2 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  9 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 48 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 35 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 52 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 31 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 37 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 20 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  2,  5, 44 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 47 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 46 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 19 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 42 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 44 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 16 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 34 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 56 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 51 ); THREEFISH_INV_MIX_PERM( P, 10,  7,  4 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 53 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 42 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 41 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 41 ); THREEFISH_INV_MIX_PERM( P,  2,  3,  9 ); THREEFISH_INV_MIX_PERM( P,  4,  5, 37 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 31 ); THREEFISH_INV_MIX_PERM( P,  8,  9, 12 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 47 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 44 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 30 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 1 );

            THREEFISH_INV_MIX_PERM( P,  0, 15,  5 ); THREEFISH_INV_MIX_PERM( P,  2, 11, 20 ); THREEFISH_INV_MIX_PERM( P,  6, 13, 48 ); THREEFISH_INV_MIX_PERM( P,  4,  9, 41 ); THREEFISH_INV_MIX_PERM( P, 14,  1, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  5, 28 ); THREEFISH_INV_MIX_PERM( P, 10,  3, 16 ); THREEFISH_INV_MIX_PERM( P, 12,  7, 25 );
            THREEFISH_INV_MIX_PERM( P,  0,  7, 33 ); THREEFISH_INV_MIX_PERM( P,  2,  5,  4 ); THREEFISH_INV_MIX_PERM( P,  4,  3, 51 ); THREEFISH_INV_MIX_PERM( P,  6,  1, 13 ); THREEFISH_INV_MIX_PERM( P, 12, 15, 34 ); THREEFISH_INV_MIX_PERM( P, 14, 13, 41 ); THREEFISH_INV_MIX_PERM( P,  8, 11, 59 ); THREEFISH_INV_MIX_PERM( P, 10,  9, 17 );
            THREEFISH_INV_MIX_PERM( P,  0,  9, 38 ); THREEFISH_INV_MIX_PERM( P,  2, 13, 19 ); THREEFISH_INV_MIX_PERM( P,  6, 11, 10 ); THREEFISH_INV_MIX_PERM( P,  4, 15, 55 ); THREEFISH_INV_MIX_PERM( P, 10,  7, 49 ); THREEFISH_INV_MIX_PERM( P, 12,  3, 18 ); THREEFISH_INV_MIX_PERM( P, 14,  5, 23 ); THREEFISH_INV_MIX_PERM( P,  8,  1, 52 );
            THREEFISH_INV_MIX_PERM( P,  0,  1, 24 ); THREEFISH_INV_MIX_PERM( P,  2,  3, 13 ); THREEFISH_INV_MIX_PERM( P,  4,  5,  8 ); THREEFISH_INV_MIX_PERM( P,  6,  7, 47 ); THREEFISH_INV_MIX_PERM( P,  8,  9,  8 ); THREEFISH_INV_MIX_PERM( P, 10, 11, 17 ); THREEFISH_INV_MIX_PERM( P, 12, 13, 22 ); THREEFISH_INV_MIX_PERM( P, 14, 15, 37 );

            THREEFISH1024_SUB_SUBKEY( P, K, T, 0 );

            break;
    }
}

void mbedtls_threefish_init( mbedtls_threefish_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_threefish_context ) );
}

void mbedtls_threefish_free( mbedtls_threefish_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_zeroize( ctx, sizeof( mbedtls_threefish_context ) );
}

int mbedtls_threefish_setkey( mbedtls_threefish_context *ctx,
                              const unsigned char *key, unsigned int keybits )
{
    unsigned int i;

    switch( keybits )
    {
        case  256:
        case  512:
        case 1024:
            ctx->keybits = keybits;
            break;

        default:
            return( MBEDTLS_ERR_THREEFISH_INVALID_KEY_LENGTH );
    }

    memcpy( ctx->key, key, keybits >> 3 );

    /* Calculate key parity */
    ctx->key[keybits >> 6] = THREEFISH_KEY_SCHED_CONST;
    for( i = 0; i < ( keybits >> 6 ); i++ )
    {
        ctx->key[keybits >> 6] ^= ctx->key[i];
    }

    return( 0 );
}

int mbedtls_threefish_settweak( mbedtls_threefish_context *ctx,
                                const unsigned char *tweak )
{
    memcpy( ctx->tweak, tweak, 16 );

    /* Calculate tweak parity */
    ctx->tweak[2] = ctx->tweak[0] ^ ctx->tweak[1];

    return( 0 );
}

/*
 * Threefish-ECB block encryption/decryption
 */
int mbedtls_threefish_crypt_ecb( mbedtls_threefish_context *ctx,
                                 int mode, const unsigned char *input,
                                 unsigned char *output )
{
    if( mode == MBEDTLS_THREEFISH_DECRYPT )
    {
        threefish_dec( ctx, input, output );
    }
    else /* MBEDTLS_THREEFISH_ENCRYPT */
    {
        threefish_enc( ctx, input, output );
    }

    return( 0 );
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/*
 * Threefish-CBC block encryption/decryption
 */
int mbedtls_threefish_crypt_cbc( mbedtls_threefish_context *ctx,
                                 int mode, size_t length, unsigned char *iv,
                                 const unsigned char *input,
                                 unsigned char *output )
{
    size_t i;
    size_t block_size = ctx->keybits >> 3;
    unsigned char temp[128];

    if( length % block_size )
        return( MBEDTLS_ERR_THREEFISH_INVALID_INPUT_LENGTH );

    if( mode == MBEDTLS_THREEFISH_DECRYPT )
    {
        while( length > 0 )
        {
            memcpy( temp, input, block_size );
            mbedtls_threefish_crypt_ecb( ctx, mode, input, output );

            for( i = 0; i < block_size; i++ )
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, block_size );

            input  += block_size;
            output += block_size;
            length -= block_size;
        }
    }
    else /* MBEDTLS_THREEFISH_ENCRYPT */
    {
        while( length > 0 )
        {
            for( i = 0; i < block_size; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            mbedtls_threefish_crypt_ecb( ctx, mode, output, output );
            memcpy( iv, output, block_size );

            input  += block_size;
            output += block_size;
            length -= block_size;
        }
    }

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/*
 * Threefish-CFB block encryption/decryption
 */
int mbedtls_threefish_crypt_cfb( mbedtls_threefish_context *ctx,
                                 int mode, size_t length, size_t *iv_off,
                                 unsigned char *iv, const unsigned char *input,
                                 unsigned char *output )
{
    int c;
    size_t n = *iv_off;
    size_t block_size = ctx->keybits >> 3;

    if( mode == MBEDTLS_THREEFISH_DECRYPT )
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_threefish_crypt_ecb( ctx, MBEDTLS_THREEFISH_ENCRYPT,
                                             iv, iv );

            c = *input++;
            *output++ = (unsigned char)( c ^ iv[n] );
            iv[n] = (unsigned char)c;

            n = ( n + 1 ) % block_size;
        }
    }
    else /* MBEDTLS_THREEFISH_ENCRYPT */
    {
        while( length-- )
        {
            if( n == 0 )
                mbedtls_threefish_crypt_ecb( ctx, MBEDTLS_THREEFISH_ENCRYPT,
                                             iv, iv );

            iv[n] = *output++ = (unsigned char)( iv[n] ^ *input++ );

            n = ( n + 1 ) % block_size;
        }
    }

    *iv_off = n;

    return( 0 );
}
#endif /*MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/*
 * Threefish-CTR block encryption/decryption
 */
int mbedtls_threefish_crypt_ctr( mbedtls_threefish_context *ctx,
                                 size_t length, size_t *nc_off,
                                 unsigned char *nonce_counter,
                                 unsigned char *stream_block,
                                 const unsigned char *input,
                                 unsigned char *output )
{
    int c, i;
    size_t n = *nc_off;
    size_t block_size = ctx->keybits >> 3;

    while( length-- )
    {
        if( n == 0 )
        {
            mbedtls_threefish_crypt_ecb( ctx, MBEDTLS_THREEFISH_ENCRYPT,
                                         nonce_counter, stream_block );

            for( i = block_size; i > 0; i-- )
                if( ++nonce_counter[i - 1] != 0 )
                    break;
        }
        c = *input++;
        *output++ = (unsigned char)( c ^ stream_block[n] );

        n = ( n + 1 ) % block_size;
    }

    *nc_off = n;

    return( 0 );
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#endif /* !MBEDTLS_THREEFISH_ALT */

#if defined(MBEDTLS_SELF_TEST)
/*
 * Checkup routine
 */
int mbedtls_threefish_self_test( int verbose )
{
    (void) verbose;
    return( 0 );
}
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_THREEFISH_C */
