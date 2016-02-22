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


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif


#if defined(MBEDTLS_ARM_CRYTO_C)
#include "mbedtls/aes_armcrypto.h"

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

/*
 * GCM multiplication: c = a times b in GF(2^128)
 * Based on [CLMUL-WP] algorithms 1 (with equation 27) and 5.
 */
void mbedtls_aes_armcrypto_gcm_mult( unsigned char c[16],
                     const unsigned char a[16],
                     const unsigned char b[16] )
{

    return;
}


#endif /* MBEDTLS_AESNI_C */
