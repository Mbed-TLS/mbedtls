/*
 *  SHA256-CE support functions
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ARM_CRYTO_C) && defined(MBEDTLS_SHA256_C)
#include "mbedtls/sha256ce.h"

#include <string.h>

#ifndef asm
#define asm __asm
#endif


#if defined(__BYTE_ORDER__)
# if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define IS_BIG_ENDIAN
# else
#  define IS_LITTLE_ENDIAN
# endif
#else
# error macro __BYTE_ORDER__ is not defined for this compiler
#endif

#include <sys/auxv.h>
#include <asm/hwcap.h>
#include <arm_neon.h>

static const uint32_t K[] =
{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

#define Rx( T0, T1, K, W0, W1, W2, W3) \
	W0 = vsha256su0q_u32( W0, W1 );    \
	d2 = d0;                           \
    T1 = vaddq_u32( W1, K );           \
    d0 = vsha256hq_u32( d0, d1, T0);   \
    d1 = vsha256h2q_u32( d1, d2, T0 ); \
	W0 = vsha256su1q_u32( W0, W2, W3 );

#define Ry( T0, T1, K,    W1         ) \
	d2 = d0;                           \
    T1 = vaddq_u32( W1, K  );          \
    d0 = vsha256hq_u32( d0, d1, T0);   \
    d1 = vsha256h2q_u32( d1, d2, T0 );

#define Rz( T0                       ) \
	d2 = d0;                           \
    d0 = vsha256hq_u32( d0, d1, T0);   \
    d1 = vsha256h2q_u32( d1, d2, T0 );

void mbedtls_sha256ce_process( mbedtls_sha256_context *ctx, const unsigned char data[64] )
{
	/* declare variables */

	uint32x4_t k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, ka, kb, kc, kd, ke, kf;
	uint32x4_t s0, s1;
	uint32x4_t w0, w1, w2, w3;
	uint32x4_t d0, d1, d2;
	uint32x4_t t0, t1;

	/* set K0..Kf constants */

	k0 = vld1q_u32 (&K[0x00]);
	k1 = vld1q_u32 (&K[0x04]);
	k2 = vld1q_u32 (&K[0x08]);
	k3 = vld1q_u32 (&K[0x0c]);
	k4 = vld1q_u32 (&K[0x10]);
	k5 = vld1q_u32 (&K[0x14]);
	k6 = vld1q_u32 (&K[0x18]);
	k7 = vld1q_u32 (&K[0x1c]);
	k8 = vld1q_u32 (&K[0x20]);
	k9 = vld1q_u32 (&K[0x24]);
	ka = vld1q_u32 (&K[0x28]);
	kb = vld1q_u32 (&K[0x2c]);
	kc = vld1q_u32 (&K[0x30]);
	kd = vld1q_u32 (&K[0x34]);
	ke = vld1q_u32 (&K[0x38]);
	kf = vld1q_u32 (&K[0x3c]);

	/* load state */

	s0 = vld1q_u32 (&ctx->state[0]);
	s1 = vld1q_u32 (&ctx->state[4]);

	/* load message */

	w0 = vld1q_u32 ((uint32_t const *)(data));
	w1 = vld1q_u32 ((uint32_t const *)(data + 16));
	w2 = vld1q_u32 ((uint32_t const *)(data + 32));
	w3 = vld1q_u32 ((uint32_t const *)(data + 48));

	#ifdef IS_LITTLE_ENDIAN
	w0 = vreinterpretq_u32_u8 (vrev32q_u8 (vreinterpretq_u8_u32 (w0)));
	w1 = vreinterpretq_u32_u8 (vrev32q_u8 (vreinterpretq_u8_u32 (w1)));
	w2 = vreinterpretq_u32_u8 (vrev32q_u8 (vreinterpretq_u8_u32 (w2)));
	w3 = vreinterpretq_u32_u8 (vrev32q_u8 (vreinterpretq_u8_u32 (w3)));
	#endif

	/* initialize t0, d0, d1 */

	t0 = vaddq_u32 (w0, k0);
	d0 = s0;
	d1 = s1;

	/* perform rounds of four */

    Rx(t0, t1, k1, w0, w1, w2, w3);
    Rx(t1, t0, k2, w1, w2, w3, w0);
    Rx(t0, t1, k3, w2, w3, w0, w1);
    Rx(t1, t0, k4, w3, w0, w1, w2);
    Rx(t0, t1, k5, w0, w1, w2, w3);
    Rx(t1, t0, k6, w1, w2, w3, w0);
    Rx(t0, t1, k7, w2, w3, w0, w1);
    Rx(t1, t0, k8, w3, w0, w1, w2);
    Rx(t0, t1, k9, w0, w1, w2, w3);
    Rx(t1, t0, ka, w1, w2, w3, w0);
    Rx(t0, t1, kb, w2, w3, w0, w1);
    Rx(t1, t0, kc, w3, w0, w1, w2);
    Ry(t0, t1, kd,     w1        );
    Ry(t1, t0, ke,     w2        );
    Ry(t0, t1, kf,     w3        );
    Rz(t1                        );

    /* update state */

	s0 = vaddq_u32(s0, d0);
	s1 = vaddq_u32(s1, d1);

	/* save state */

	vst1q_u32 (&ctx->state[0], s0);
	vst1q_u32 (&ctx->state[4], s1);
}


#endif /* MBEDTLS_SHA256CE_C */
