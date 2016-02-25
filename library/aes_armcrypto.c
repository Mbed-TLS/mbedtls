/*
 *  ARMv8 crytpo extension AES support functions
 *
 *  Copyright (C) 2016, CriticalBlue Limited, All Rights Reserved
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
 * [GCM-WP] http://conradoplg.cryptoland.net/files/2010/12/gcm14.pdf
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/* Check if the module is enabled */
#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_ARM_CRYTO_C)
#include "mbedtls/aes_armcrypto.h"

/* Check if crypto is supported */
#if defined(MBEDTLS_HAVE_ARM_CRYPTO)

#include <arm_neon.h>
#include <stdio.h>

/*
 * AES-NI AES-ECB block en(de)cryption
 */
int mbedtls_aes_armcrypto_crypt_ecb( mbedtls_aes_context *ctx,
                     int mode,
                     const unsigned char input[16],
                     unsigned char output[16] )
{
	int i;
	uint8x16_t state_vec, roundkey_vec;
	uint8_t *RK = (uint8_t*)ctx->rk;

	// Load input and round key into into their vectors
	state_vec = vld1q_u8(input);

	if ( mode == MBEDTLS_AES_ENCRYPT )
	{
		// Initial AddRoundKey is in the loop due to AES instruction always doing AddRoundKey first
		for( i = 0; i < ctx->nr - 1; i++ ) {
			// Load Round Key
			roundkey_vec = vld1q_u8(RK);
			// Forward (AESE) round (AddRoundKey, SubBytes and ShiftRows)
			state_vec = vaeseq_u8(state_vec, roundkey_vec);
			// Mix Columns (AESMC)
			state_vec = vaesmcq_u8(state_vec);
			// Move pointer ready to load next round key
			RK += 16;
		}

		// Final Forward (AESE) round (AddRoundKey, SubBytes and ShiftRows). No Mix columns
		roundkey_vec = vld1q_u8(RK); /* RK already moved in loop */
		state_vec = vaeseq_u8(state_vec, roundkey_vec);
	}
	else
	{
		// Initial AddRoundKey is in the loop due to AES instruction always doing AddRoundKey first
		for( i = 0; i < ctx->nr - 1; i++ ) {
			// Load Round Key
			roundkey_vec = vld1q_u8(RK);
			// Reverse (AESD) round (AddRoundKey, SubBytes and ShiftRows)
			state_vec = vaesdq_u8(state_vec, roundkey_vec);
			// Inverse Mix Columns (AESIMC)
			state_vec = vaesimcq_u8(state_vec);
			// Move pointer ready to load next round key
			RK += 16;
		}

		// Final Reverse (AESD) round (AddRoundKey, SubBytes and ShiftRows). No Mix columns
		roundkey_vec = vld1q_u8(RK); /* RK already moved in loop */
		state_vec = vaesdq_u8(state_vec, roundkey_vec);
	}

	// Manually apply final Add RoundKey step (EOR)
	RK += 16;
	roundkey_vec = vld1q_u8(RK);
	state_vec = veorq_u8(state_vec, roundkey_vec);

	// Write results back to output array
	vst1q_u8 (output, state_vec);

	return 0;
}

/* because the vmull_p64 intrinsic uses the wrong argument types: */
#define vmull_low_p64(A, B) ({                               \
	poly128_t res__;                                         \
	asm("pmull    %0.1q, %1.1d, %2.1d                \n\t"   \
        : "=w" (res__) : "w" (A), "w" (B) );                 \
    res__;                                                   \
})

/*
 * GCM multiplication: c = a times b in GF(2^128)
 * Based on [GCM-WP] algorithms 3 and 5.
 * This method assumes both inputs are in gcm format (little byte + big bit endianness).
 */
void mbedtls_aes_armcrypto_gcm_mult( unsigned char c[16],
                     const unsigned char a[16],
                     const unsigned char b[16] )
{
	/* vector variables */
	uint8x16_t a_p, b_p; /* inputs */
	uint8x16_t z, p; /* constants */
	uint8x16_t r0, r1; /* full width multiply result (before reduction) */
	uint8x16_t t0, t1; /* temps */
	uint8x16_t c_p; /* output */

	/* reverse bits in each byte to convert from gcm format to little-little endian */
	a_p = vrbitq_u8(vld1q_u8(a));
	b_p = vrbitq_u8(vld1q_u8(b));

	/* polynomial multiply (128*128->256bit). See [GCM-WP] algorithms 3. */
	z = vdupq_n_u8(0);
	r0 = (uint8x16_t)vmull_low_p64((poly64x2_t)a_p, (poly64x2_t)b_p);
	r1 = (uint8x16_t)vmull_high_p64((poly64x2_t)a_p, (poly64x2_t)b_p);
	t0 = vextq_u8(b_p, b_p, 8);
	t1 = (uint8x16_t)vmull_low_p64((poly64x2_t)a_p, (poly64x2_t)t0);
	t0 = (uint8x16_t)vmull_high_p64((poly64x2_t)a_p, (poly64x2_t)t0);
	t0 = veorq_u8(t0, t1);
	t1 = vextq_u8(z, t0, 8);
	r0 = veorq_u8(r0, t1);
	t1 = vextq_u8(t0, z, 8);
	r1 = veorq_u8(r1, t1);

	/* polynomial reduction (256->128bit). See [GCM-WP] algorithms 5. */
	p = (uint8x16_t)vdupq_n_u64(0x0000000000000087);
	t0 = (uint8x16_t)vmull_high_p64((poly64x2_t)r1, (poly64x2_t)p);
	t1 = vextq_u8(t0, z, 8);
	r1 = veorq_u8(r1, t1);
	t1 = vextq_u8(z, t0, 8);
	r0 = veorq_u8(r0, t1);
	t0 = (uint8x16_t)vmull_low_p64((poly64x2_t)r1, (poly64x2_t)p);
	c_p = veorq_u8(r0, t0);

	/* reverse bits in each byte to convert from little-little endian to gcm format */
	vst1q_u8(c, vrbitq_u8(c_p));
    return;
}

#endif /* #if defined(MBEDTLS_HAVE_ARM_CRYPTO) */

#endif /* defined(MBEDTLS_ARM_CRYTO_C) && defined(MBEDTLS_AES_C) */

