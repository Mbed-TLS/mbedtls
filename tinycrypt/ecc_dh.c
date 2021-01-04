/* ec_dh.c - TinyCrypt implementation of EC-DH */

/*
 *  Copyright (c) 2019, Arm Limited (or its affiliates), All Rights Reserved.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Copyright (c) 2014, Kenneth MacKay
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  * Redistributions of source code must retain the above copyright notice,
 *	this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *	this list of conditions and the following disclaimer in the documentation
 *	and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 *  Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *	- Redistributions of source code must retain the above copyright notice,
 *	 this list of conditions and the following disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 *
 *	- Neither the name of Intel Corporation nor the names of its contributors
 *	may be used to endorse or promote products derived from this software
 *	without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_USE_TINYCRYPT)
#include <tinycrypt/ecc.h>
#include <tinycrypt/ecc_dh.h>
#include <string.h>
#include "mbedtls/platform_util.h"

int uECC_make_key_with_d(uint8_t *public_key, uint8_t *private_key,
			 unsigned int *d)
{
	int ret = UECC_FAULT_DETECTED;
	uECC_word_t _private[NUM_ECC_WORDS];
	uECC_word_t _public[NUM_ECC_WORDS * 2];

	/* This function is designed for test purposes-only (such as validating NIST
	 * test vectors) as it uses a provided value for d instead of generating
	 * it uniformly at random. */
	if( mbedtls_platform_memcpy (_private, d, NUM_ECC_BYTES) != _private )
	{
		goto exit;
	}

	/* Computing public-key from private: */
	ret = EccPoint_compute_public_key(_public, _private);
	if (ret != UECC_SUCCESS) {
		goto exit;
	}

	/* Converting buffers to correct bit order: */
	uECC_vli_nativeToBytes(private_key,
				   BITS_TO_BYTES(NUM_ECC_BITS),
				   _private);
	uECC_vli_nativeToBytes(public_key,
				   NUM_ECC_BYTES,
				   _public);
	uECC_vli_nativeToBytes(public_key + NUM_ECC_BYTES,
				   NUM_ECC_BYTES,
				   _public + NUM_ECC_WORDS);

exit:
	/* erasing temporary buffer used to store secret: */
	mbedtls_platform_memset(_private, 0, NUM_ECC_BYTES);

	return ret;
}

int uECC_make_key(uint8_t *public_key, uint8_t *private_key)
{
	int ret = UECC_FAULT_DETECTED;
	uECC_word_t _random[NUM_ECC_WORDS * 2];
	uECC_word_t _private[NUM_ECC_WORDS];
	uECC_word_t _public[NUM_ECC_WORDS * 2];
	uECC_word_t tries;
	volatile uint8_t *public_key_dup = public_key;
	volatile uint8_t *private_key_dup = private_key;

	for (tries = 0; tries < uECC_RNG_MAX_TRIES; ++tries) {
		/* Generating _private uniformly at random: */
		uECC_RNG_Function rng_function = uECC_get_rng();
		if (!rng_function ||
			rng_function((uint8_t *)_random, 2 * NUM_ECC_WORDS*uECC_WORD_SIZE) != 2 * NUM_ECC_WORDS*uECC_WORD_SIZE) {
				return UECC_FAILURE;
		}

		/* computing modular reduction of _random (see FIPS 186.4 B.4.1): */
		ret = uECC_vli_mmod(_private, _random, curve_n);
		if (ret != UECC_SUCCESS)
			return ret;
		/* Computing public-key from private: */
		ret = EccPoint_compute_public_key(_public, _private);
		/* don't try again if a fault was detected */
		if (ret == UECC_FAULT_DETECTED) {
			return ret;
		}
		if (ret == UECC_SUCCESS) {

			/* Converting buffers to correct bit order: */
			uECC_vli_nativeToBytes(private_key,
						   BITS_TO_BYTES(NUM_ECC_BITS),
						   _private);
			uECC_vli_nativeToBytes(public_key,
						   NUM_ECC_BYTES,
						   _public);
			uECC_vli_nativeToBytes(public_key + NUM_ECC_BYTES,
 						   NUM_ECC_BYTES,
						   _public + NUM_ECC_WORDS);

			/* erasing temporary buffer that stored secret: */
			mbedtls_platform_memset(_private, 0, NUM_ECC_BYTES);

			if (private_key == private_key_dup && public_key == public_key_dup) {
				return UECC_SUCCESS;
			}
			/* Erase key in case of FI */
			mbedtls_platform_memset(public_key, 0, 2*NUM_ECC_BYTES);
			return UECC_FAULT_DETECTED;
		}
  	}
	return UECC_FAILURE;
}

int uECC_shared_secret(const uint8_t *public_key, const uint8_t *private_key,
			   uint8_t *secret)
{

	uECC_word_t _public[NUM_ECC_WORDS * 2];
	uECC_word_t _private[NUM_ECC_WORDS];
	wordcount_t num_words = NUM_ECC_WORDS;
	wordcount_t num_bytes = NUM_ECC_BYTES;
	int r = UECC_FAULT_DETECTED;

	/* Converting buffers to correct bit order: */
	uECC_vli_bytesToNative(_private,
	  				   private_key,
				   BITS_TO_BYTES(NUM_ECC_BITS));
	uECC_vli_bytesToNative(_public,
	  				   public_key,
				   num_bytes);
	uECC_vli_bytesToNative(_public + num_words,
				   public_key + num_bytes,
				   num_bytes);

	r = EccPoint_mult_safer(_public, _public, _private);
	uECC_vli_nativeToBytes(secret, num_bytes, _public);

	/* erasing temporary buffer used to store secret: */
	if (_private == mbedtls_platform_zeroize(_private, sizeof(_private))) {
		return r;
	}

	return UECC_FAULT_DETECTED;
}
#endif /* MBEDTLS_USE_TINYCRYPT */
