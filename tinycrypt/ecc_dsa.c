/* ec_dsa.c - TinyCrypt implementation of EC-DSA */

/*
 *  Copyright (c) 2019, Arm Limited (or its affiliates), All Rights Reserved.
 *  SPDX-License-Identifier: BSD-3-Clause
 */

/* Copyright (c) 2014, Kenneth MacKay
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
 * POSSIBILITY OF SUCH DAMAGE.*/

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
#include <tinycrypt/ecc_dsa.h>
#include "mbedtls/platform_util.h"

static void bits2int(uECC_word_t *native, const uint8_t *bits,
			 unsigned bits_size)
{
	unsigned num_n_bytes = BITS_TO_BYTES(NUM_ECC_BITS);

	if (bits_size > num_n_bytes) {
		bits_size = num_n_bytes;
	}

	uECC_vli_clear(native);
	uECC_vli_bytesToNative(native, bits, bits_size);
}

int uECC_sign_with_k(const uint8_t *private_key, const uint8_t *message_hash,
			 unsigned hash_size, uECC_word_t *k, uint8_t *signature)
{

	uECC_word_t tmp[NUM_ECC_WORDS];
	uECC_word_t s[NUM_ECC_WORDS];
	uECC_word_t p[NUM_ECC_WORDS * 2];
	wordcount_t num_n_words = BITS_TO_WORDS(NUM_ECC_BITS);
	int r = UECC_FAILURE;


	/* Make sure 0 < k < curve_n */
  	if (uECC_vli_isZero(k) ||
		uECC_vli_cmp(curve_n, k) != 1) {
		return UECC_FAILURE;
	}

	r = EccPoint_mult_safer(p, curve_G, k);
		if (r != UECC_SUCCESS) {
		return r;
	}

	/* If an RNG function was specified, get a random number
	to prevent side channel analysis of k. */
	if (!uECC_get_rng()) {
		uECC_vli_clear(tmp);
		tmp[0] = 1;
	}
	else if (uECC_generate_random_int(tmp, curve_n, num_n_words) != UECC_SUCCESS) {
		return UECC_FAILURE;
	}

	/* Prevent side channel analysis of uECC_vli_modInv() to determine
	bits of k / the private key by premultiplying by a random number */
	uECC_vli_modMult(k, k, tmp, curve_n); /* k' = rand * k */
	uECC_vli_modInv(k, k, curve_n);	   /* k = 1 / k' */
	uECC_vli_modMult(k, k, tmp, curve_n); /* k = 1 / k */

	uECC_vli_nativeToBytes(signature, NUM_ECC_BYTES, p); /* store r */

	/* tmp = d: */
	uECC_vli_bytesToNative(tmp, private_key, BITS_TO_BYTES(NUM_ECC_BITS));

	s[num_n_words - 1] = 0;
	uECC_vli_set(s, p);
	uECC_vli_modMult(s, tmp, s, curve_n); /* s = r*d */

	bits2int(tmp, message_hash, hash_size);
	uECC_vli_modAdd(s, tmp, s, curve_n); /* s = e + r*d */
	uECC_vli_modMult(s, s, k, curve_n);  /* s = (e + r*d) / k */
	if (uECC_vli_numBits(s) > (bitcount_t)NUM_ECC_BYTES * 8) {
		return UECC_FAILURE;
	}

	uECC_vli_nativeToBytes(signature + NUM_ECC_BYTES, NUM_ECC_BYTES, s);
	return r;
}

int uECC_sign(const uint8_t *private_key, const uint8_t *message_hash,
		  unsigned hash_size, uint8_t *signature)
{
	int r;
	uECC_word_t _random[2*NUM_ECC_WORDS];
	uECC_word_t k[NUM_ECC_WORDS];
	uECC_word_t tries;
	volatile const uint8_t *private_key_dup = private_key;
	volatile const uint8_t *message_hash_dup = message_hash;
	volatile unsigned hash_size_dup = hash_size;
	volatile uint8_t *signature_dup = signature;

	for (tries = 0; tries < uECC_RNG_MAX_TRIES; ++tries) {
		/* Generating _random uniformly at random: */
		uECC_RNG_Function rng_function = uECC_get_rng();
		if (!rng_function ||
			rng_function((uint8_t *)_random, 2*NUM_ECC_WORDS*uECC_WORD_SIZE) != 2*NUM_ECC_WORDS*uECC_WORD_SIZE) {
			return UECC_FAILURE;
		}

		// computing k as modular reduction of _random (see FIPS 186.4 B.5.1):
		uECC_vli_mmod(k, _random, curve_n);

		r = uECC_sign_with_k(private_key, message_hash, hash_size, k, signature);
		/* don't keep trying if a fault was detected */
		if (r == UECC_FAULT_DETECTED) {
		    mbedtls_platform_memset(signature, 0, 2*NUM_ECC_BYTES);
			return r;
		}
		if (r == UECC_SUCCESS) {
			if (private_key_dup != private_key || message_hash_dup != message_hash ||
				hash_size_dup != hash_size || signature_dup != signature) {
			    mbedtls_platform_memset(signature, 0, 2*NUM_ECC_BYTES);
				return UECC_FAULT_DETECTED;
			}
			return UECC_SUCCESS;
		}
		/* else keep trying */
	}
	return UECC_FAILURE;
}

static bitcount_t smax(bitcount_t a, bitcount_t b)
{
	return (a > b ? a : b);
}

int uECC_verify(const uint8_t *public_key, const uint8_t *message_hash,
		unsigned hash_size, const uint8_t *signature)
{

	uECC_word_t u1[NUM_ECC_WORDS], u2[NUM_ECC_WORDS];
	uECC_word_t z[NUM_ECC_WORDS];
	uECC_word_t sum[NUM_ECC_WORDS * 2];
	uECC_word_t rx[NUM_ECC_WORDS];
	uECC_word_t ry[NUM_ECC_WORDS];
	uECC_word_t tx[NUM_ECC_WORDS];
	uECC_word_t ty[NUM_ECC_WORDS];
	uECC_word_t tz[NUM_ECC_WORDS];
	const uECC_word_t *points[4];
	const uECC_word_t *point;
	bitcount_t num_bits;
	bitcount_t i;
	bitcount_t flow_control;
	volatile uECC_word_t diff;

	uECC_word_t _public[NUM_ECC_WORDS * 2];
	uECC_word_t r[NUM_ECC_WORDS], s[NUM_ECC_WORDS];
	wordcount_t num_words = NUM_ECC_WORDS;
	wordcount_t num_n_words = BITS_TO_WORDS(NUM_ECC_BITS);

	rx[num_n_words - 1] = 0;
	r[num_n_words - 1] = 0;
	s[num_n_words - 1] = 0;
	flow_control = 1;

	uECC_vli_bytesToNative(_public, public_key, NUM_ECC_BYTES);
	uECC_vli_bytesToNative(_public + num_words, public_key + NUM_ECC_BYTES,
				   NUM_ECC_BYTES);
	uECC_vli_bytesToNative(r, signature, NUM_ECC_BYTES);
	uECC_vli_bytesToNative(s, signature + NUM_ECC_BYTES, NUM_ECC_BYTES);

	/* r, s must not be 0. */
	if (uECC_vli_isZero(r) || uECC_vli_isZero(s)) {
		return UECC_FAILURE;
	}

	/* r, s must be < n. */
	if (uECC_vli_cmp_unsafe(curve_n, r) != 1 ||
		uECC_vli_cmp_unsafe(curve_n, s) != 1) {
		return UECC_FAILURE;
	}

	flow_control++;

	/* Calculate u1 and u2. */
	uECC_vli_modInv(z, s, curve_n); /* z = 1/s */
	u1[num_n_words - 1] = 0;
	bits2int(u1, message_hash, hash_size);
	uECC_vli_modMult(u1, u1, z, curve_n); /* u1 = e/s */
	uECC_vli_modMult(u2, r, z, curve_n); /* u2 = r/s */

	/* Calculate sum = G + Q. */
	uECC_vli_set(sum, _public);
	uECC_vli_set(sum + num_words, _public + num_words);
	uECC_vli_set(tx, curve_G);
	uECC_vli_set(ty, curve_G + num_words);
	uECC_vli_modSub(z, sum, tx, curve_p); /* z = x2 - x1 */
	XYcZ_add(tx, ty, sum, sum + num_words);
	uECC_vli_modInv(z, z, curve_p); /* z = 1/z */
	apply_z(sum, sum + num_words, z);

	flow_control++;

	/* Use Shamir's trick to calculate u1*G + u2*Q */
	points[0] = 0;
	points[1] = curve_G;
	points[2] = _public;
	points[3] = sum;
	num_bits = smax(uECC_vli_numBits(u1),
	uECC_vli_numBits(u2));

	point = points[(!!uECC_vli_testBit(u1, num_bits - 1)) |
					   ((!!uECC_vli_testBit(u2, num_bits - 1)) << 1)];
	uECC_vli_set(rx, point);
	uECC_vli_set(ry, point + num_words);
	uECC_vli_clear(z);
	z[0] = 1;
	flow_control++;

	for (i = num_bits - 2; i >= 0; --i) {
		uECC_word_t index;
		double_jacobian_default(rx, ry, z);

		index = (!!uECC_vli_testBit(u1, i)) | ((!!uECC_vli_testBit(u2, i)) << 1);
		point = points[index];
		if (point) {
			uECC_vli_set(tx, point);
			uECC_vli_set(ty, point + num_words);
			apply_z(tx, ty, z);
			uECC_vli_modSub(tz, rx, tx, curve_p); /* Z = x2 - x1 */
			XYcZ_add(tx, ty, rx, ry);
			uECC_vli_modMult_fast(z, z, tz);
		}
		flow_control++;
  	}

	uECC_vli_modInv(z, z, curve_p); /* Z = 1/Z */
	apply_z(rx, ry, z);
	flow_control++;

	/* v = x1 (mod n) */
	if (uECC_vli_cmp_unsafe(curve_n, rx) != 1) {
		uECC_vli_sub(rx, rx, curve_n);
	}

	/* Accept only if v == r. */
	diff = uECC_vli_equal(rx, r);
	if (diff == 0) {
		flow_control++;
		mbedtls_platform_random_delay();

		/* Re-check the condition and test if the control flow is as expected.
		 * 1 (base value) + num_bits - 1 (from the loop) + 5 incrementations.
		 */
		if (diff == 0 && flow_control == (num_bits + 5)) {
			return UECC_SUCCESS;
		}
		else {
			return UECC_FAULT_DETECTED;
		}
	}

	return UECC_FAILURE;
}
#endif /* MBEDTLS_USE_TINYCRYPT */
