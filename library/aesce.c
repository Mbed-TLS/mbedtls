/*
 *  Arm64 crypto extension support functions
 *
 *  Copyright The Mbed TLS Contributors
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
 */

#include <string.h>
#include "common.h"

#if defined(MBEDTLS_AESCE_C)

#include "aesce.h"

#if defined(MBEDTLS_HAVE_ARM64)

#if defined(__clang__)
#   if __clang_major__ < 4
#       error "A more recent Clang is required for MBEDTLS_AESCE_C"
#   endif
#elif defined(__GNUC__)
#   if __GNUC__ < 6
#       error "A more recent GCC is required for MBEDTLS_AESCE_C"
#   endif
#else
#    error "Only GCC and Clang supported for MBEDTLS_AESCE_C"
#endif

#if !defined(__ARM_FEATURE_CRYPTO)
#   error "`crypto` feature moddifier MUST be enabled for MBEDTLS_AESCE_C."
#   error "Typical option for GCC and Clang is `-march=armv8-a+crypto`."
#endif /* !__ARM_FEATURE_CRYPTO */

#include <arm_neon.h>

#if defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

/*
 * AES instruction support detection routine
 */
int mbedtls_aesce_has_support(void)
{
#if defined(__linux__)
    unsigned long auxval = getauxval(AT_HWCAP);
    return (auxval & (HWCAP_ASIMD | HWCAP_AES)) ==
           (HWCAP_ASIMD | HWCAP_AES);
#else
    /* Assume AES instructions are supported. */
    return 1;
#endif
}

static uint8x16_t aesce_encrypt_block(uint8x16_t block,
                                      unsigned char *keys,
                                      int rounds)
{
    for (int i = 0; i < rounds - 1; i++) {
        /* AES AddRoundKey, SubBytes, ShiftRows (in this order).
         * AddRoundKey adds the round key for the previous round. */
        block = vaeseq_u8(block, vld1q_u8(keys + i * 16));
        /* AES mix columns */
        block = vaesmcq_u8(block);
    }

    /* AES AddRoundKey for the previous round.
     * SubBytes, ShiftRows for the final round.  */
    block = vaeseq_u8(block, vld1q_u8(keys + (rounds -1) * 16));

    /* Final round: no MixColumns */

    /* Final AddRoundKey */
    block = veorq_u8(block, vld1q_u8(keys + rounds  * 16));

    return block;
}

static uint8x16_t aesce_decrypt_block(uint8x16_t block,
                                      unsigned char *keys,
                                      int rounds)
{

    for (int i = 0; i < rounds - 1; i++) {
        /* AES AddRoundKey, SubBytes, ShiftRows */
        block = vaesdq_u8(block, vld1q_u8(keys + i * 16));
        /* AES inverse MixColumns for the next round.
         *
         * This means that we switch the order of the inverse AddRoundKey and
         * inverse MixColumns operations. We have to do this as AddRoundKey is
         * done in an atomic instruction together with the inverses of SubBytes
         * and ShiftRows.
         *
         * It works because MixColumns is a linear operation over GF(2^8) and
         * AddRoundKey is an exclusive or, which is equivalent to addition over
         * GF(2^8). (The inverse of MixColumns needs to be applied to the
         * affected round keys separately which has been done when the
         * decryption round keys were calculated.) */
        block = vaesimcq_u8(block);
    }

    /* The inverses of AES AddRoundKey, SubBytes, ShiftRows finishing up the
     * last full round. */
    block = vaesdq_u8(block, vld1q_u8(keys + (rounds - 1) * 16));

    /* Inverse AddRoundKey for inverting the initial round key addition. */
    block = veorq_u8(block, vld1q_u8(keys + rounds * 16));

    return block;
}

/*
 * AES-ECB block en(de)cryption
 */
int mbedtls_aesce_crypt_ecb(mbedtls_aes_context *ctx,
                            int mode,
                            const unsigned char input[16],
                            unsigned char output[16])
{
    uint8x16_t block = vld1q_u8(&input[0]);
    unsigned char *keys = (unsigned char *) (ctx->buf + ctx->rk_offset);

    if (mode == MBEDTLS_AES_ENCRYPT) {
        block = aesce_encrypt_block(block, keys, ctx->nr);
    } else {
        block = aesce_decrypt_block(block, keys, ctx->nr);
    }
    vst1q_u8(&output[0], block);

    return 0;
}

/*
 * Compute decryption round keys from encryption round keys
 */
void mbedtls_aesce_inverse_key(unsigned char *invkey,
                               const unsigned char *fwdkey,
                               int nr)
{
    int i, j;
    j = nr;
    vst1q_u8(invkey, vld1q_u8(fwdkey + j * 16));
    for (i = 1, j--; j > 0; i++, j--) {
        vst1q_u8(invkey + i * 16,
                 vaesimcq_u8(vld1q_u8(fwdkey + j * 16)));
    }
    vst1q_u8(invkey + i * 16, vld1q_u8(fwdkey + j * 16));

}

static inline uint32_t aes_rot_word(uint32_t word)
{
    return (word << (32 - 8)) | (word >> 8);
}

static inline uint32_t aes_sub_word(uint32_t in)
{
    uint8x16_t v = vreinterpretq_u8_u32(vdupq_n_u32(in));
    uint8x16_t zero = vdupq_n_u8(0);

    /* vaeseq_u8 does both SubBytes and ShiftRows. Taking the first row yields
     * the correct result as ShiftRows doesn't change the first row. */
    v = vaeseq_u8(zero, v);
    return vgetq_lane_u32(vreinterpretq_u32_u8(v), 0);
}

/*
 * Key expansion function
 */
static void aesce_setkey_enc(unsigned char *rk,
                             const unsigned char *key,
                             const size_t key_bit_length)
{
    static uint8_t const rcon[] = { 0x01, 0x02, 0x04, 0x08, 0x10,
                                    0x20, 0x40, 0x80, 0x1b, 0x36 };
    /* See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
     *   - Section 5, Nr = Nk + 6
     *   - Section 5.2, the key expansion size is Nb*(Nr+1)
     */
    const uint32_t key_len_in_words = key_bit_length / 32;  /* Nk */
    const size_t round_key_len_in_words = 4;                /* Nb */
    const size_t round_keys_needed = key_len_in_words + 6;  /* Nr */
    const size_t key_expansion_size_in_words =
        round_key_len_in_words * (round_keys_needed + 1);   /* Nb*(Nr+1) */
    const uint32_t *rko_end = (uint32_t *) rk + key_expansion_size_in_words;

    memcpy(rk, key, key_len_in_words * 4);

    for (uint32_t *rki = (uint32_t *) rk;
         rki + key_len_in_words < rko_end;
         rki += key_len_in_words) {

        size_t iteration = (rki - (uint32_t *) rk) / key_len_in_words;
        uint32_t *rko;
        rko = rki + key_len_in_words;
        rko[0] = aes_rot_word(aes_sub_word(rki[key_len_in_words - 1]));
        rko[0] ^= rcon[iteration] ^ rki[0];
        rko[1] = rko[0] ^ rki[1];
        rko[2] = rko[1] ^ rki[2];
        rko[3] = rko[2] ^ rki[3];
        if (rko + key_len_in_words > rko_end) {
            /* Do not write overflow words.*/
            continue;
        }
        switch (key_bit_length) {
            case 128:
                break;
            case 192:
                rko[4] = rko[3] ^ rki[4];
                rko[5] = rko[4] ^ rki[5];
                break;
            case 256:
                rko[4] = aes_sub_word(rko[3]) ^ rki[4];
                rko[5] = rko[4] ^ rki[5];
                rko[6] = rko[5] ^ rki[6];
                rko[7] = rko[6] ^ rki[7];
                break;
        }
    }
}

/*
 * Key expansion, wrapper
 */
int mbedtls_aesce_setkey_enc(unsigned char *rk,
                             const unsigned char *key,
                             size_t bits)
{
    switch (bits) {
        case 128:
        case 192:
        case 256:
            aesce_setkey_enc(rk, key, bits);
            break;
        default:
            return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }

    return 0;
}

#endif /* MBEDTLS_HAVE_ARM64 */

#endif /* MBEDTLS_AESCE_C */
