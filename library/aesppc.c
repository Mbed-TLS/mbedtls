/*
 *  AES PPC (ppc64le)  support functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"
#include <string.h>

#if defined(MBEDTLS_GCM_C)
#include "mbedtls/gcm.h"
#endif

#if defined(MBEDTLS_AES_C)
#include "mbedtls/aes.h"
#endif

#include "ppc_common.h"

/*
 * ppc_support.c - PPC capability supports.
 */
#ifndef PPC_VEC_CRYPTO
# define PPC_VEC_CRYPTO   0x02000000
#endif
#ifndef PPC_ARCH_3_00
# define PPC_ARCH_3_00    0x00800000
#endif
#ifndef PPC_ARCH_3_10
# define PPC_ARCH_3_10    0x00040000
#endif

#if defined(MBEDTIS_USE_PPC) && defined(PPC_LITTLE_ENDIAN)

int ppc_crypto_capable()
{
#if defined(__GLIBC__) && defined(__GNUC__) && __GNUC__ >= 6
    int ppc_hwcap2 = 0;

    if (__builtin_cpu_supports("vcrypto")) {
        ppc_hwcap2 |= PPC_VEC_CRYPTO;
    }

    if (__builtin_cpu_supports("arch_3_00")) {
        ppc_hwcap2 |= PPC_ARCH_3_00;
    }
    if (__builtin_cpu_supports("arch_3_1")) {
        ppc_hwcap2 |= PPC_ARCH_3_10;
    }

    if (ppc_hwcap2 & (PPC_VEC_CRYPTO | PPC_ARCH_3_00)) {
        return PPC_CRYPTO_SUPPORT;
    }
#endif
    return 0;
}

/*
 * AES encrypt
 */
static void aes_encrypt(const unsigned char *in, unsigned char *out,
                        unsigned char *rk, int rounds)
{
    asm volatile (
        "lxvb16x 32+1, 0, %1    \n\t" // load inp
        "vmr    2, 1            \n\t"

        "lvx    2, 0, %2        \n\t" // load key
        "vxor   2, 2, 1         \n\t"

        "addi   7, %3, -1       \n\t" // n round - 1
        "mtctr  7               \n\t"
        "li     8, 16           \n\t" // round key index

        "1:                     \n\t"
        "lvx    0, 8, %2        \n\t" // load key
        "vcipher 2, 2, 0        \n\t"
        "addi   8, 8, 16        \n\t"
        "bdnz   1b              \n\t"

        "lvx    0, 8, %2        \n\t" // load key
        "vcipherlast 2, 2, 0    \n\t"
        "stxvb16x 32+2, 0, %0   \n\t"
        : "+r" (out)
        : "r" (in), "r" (rk), "r" (rounds)
        : "memory");
}

/*
 * AES decrypt
 */
static void aes_decrypt(const unsigned char *in, unsigned char *out,
                        unsigned char *rk, int rounds)
{
    asm volatile (
        "lxvb16x 32+1, 0, %1    \n\t" // load inp
        "vmr    2, 1            \n\t"

        "lvx    2, 0, %2        \n\t" // load key
        "vxor   2, 2, 1         \n\t"

        "addi   7, %3, -1       \n\t" // n round - 1
        "mtctr  7               \n\t"
        "li     8, 16           \n\t" // round key index

        "1:                     \n\t"
        "lvx    0, 8, %2        \n\t" // load key
        "vncipher 2, 2, 0       \n\t"
        "addi   8, 8, 16        \n\t"
        "bdnz   1b              \n\t"

        "lvx    0, 8, %2        \n\t" // load key
        "vncipherlast 2, 2, 0   \n\t"
        "stxvb16x 32+2, 0, %0   \n\t"
        : "+r" (out)
        : "r" (in), "r" (rk), "r" (rounds)
        : "memory");
}

/*
 * AES PPC AES-ECB block en(de)cryption
 */
int mbedtls_aesppc_crypt_ecb(mbedtls_aes_context *ctx,
                             int mode,
                             const unsigned char input[16],
                             unsigned char output[16])
{
    int rounds = ctx->nr;
    unsigned char *rkey = (unsigned char *) (ctx->buf + ctx->rk_offset);

    if (mode == MBEDTLS_AES_ENCRYPT) {
        aes_encrypt(input, output, rkey, rounds);
    } else {
        aes_decrypt(input, output, rkey, rounds);
    }

    return 0;
}

/*
 * Compute decryption round keys from encryption round keys
 */
void mbedtls_aesppc_inverse_key(unsigned char *invkey,
                                const unsigned char *fwdkey,
                                int nr)
{
    unsigned char *ik = invkey;
    const unsigned char *fk = fwdkey + 16 * nr;

    memcpy(ik, fk, 16);

    for (fk -= 16, ik += 16; fk > fwdkey; fk -= 16, ik += 16) {
        memcpy(ik, fk, 16);
    }
    memcpy(ik, fk, 16);
}

/*
 * ppc_gcm_mul(Xi, Htable, input, len)
 *
 * Refer to:
 *   1. Karatsuba multiplication method in Optimzed Galois-Counter-Mode
 *      Implementation On Intel Architecture Processors.
 *   2. Implementing GCM on ARMv8.
 */
static void ppc_gcm_mul(unsigned char *Xi, unsigned char *Htable,
                        const unsigned char *input, int len)
{
    asm volatile (
        "li     8, 0xc2          \n\t"
        "sldi   8, 8, 56         \n\t"
        "mtvsrdd 32+18, 0, 8     \n\t"

        "li      10, 16          \n\t"
        "lxvd2x  10+32, 10, %1   \n\t"    // Hl
        "li      10, 32          \n\t"
        "lxvd2x  2+32, 10, %1    \n\t"    // H
        "li      10, 48          \n\t"
        "lxvd2x  11+32, 10, %1   \n\t"    // Hh

        "vxor    0, 0, 0         \n\t"

        "li    10, 16            \n\t"
        "divdu 10, %3, 10        \n\t"
        "mtctr 10                \n\t"
        "li    9, 0              \n\t"

        "1:                      \n\t"
        "lxvb16x  32+1, 9, %2    \n\t"     // load input
        "addi  9, 9, 16          \n\t"

        "vpmsumd         4, 10, 1 \n\t"              // L
        "vpmsumd         5, 2, 1  \n\t"              // M
        "vpmsumd         6, 11, 1 \n\t"              // H

        "vpmsumd         7, 4, 18 \n\t"              // reduction

        "vsldoi          8, 5, 0, 8 \n\t"          // mL
        "vsldoi          9, 0, 5, 8 \n\t"          // mH
        "vxor            4, 4, 8    \n\t"             // LL + LL
        "vxor            6, 6, 9    \n\t"             // HH + HH

        "vsldoi          4, 4, 4, 8 \n\t"          // swap
        "vxor            4, 4, 7    \n\t"

        "vsldoi          10, 4, 4, 8 \n\t"          // swap
        "vpmsumd         4, 4, 18    \n\t"              // reduction
        "vxor            10, 10, 6   \n\t"
        "vxor            0, 4, 10    \n\t"
        "bdnz    1b                  \n\t"

        "stxvb16x 32+0, 0, %0        \n\t"

        : "+r" (Xi)
        : "r" (Htable), "r" (input), "r" (len)
        : "memory");
}

/*
 * Shift H <<< 1
 * ppc_gcm_shift(H, output)
 */
void ppc_gcm_shift(const unsigned char *H, unsigned char *output)
{
    asm volatile (
        "li     5, 0xc2                 \n\t"
        "sldi   5, 5, 56                \n\t"
        "mtvsrd 32+19, 5                \n\t"
        "vxor    0, 0, 0                \n\t"
        "lxvd2x 32+1, 0, %1             \n\t"  // load H

        "vspltisb 7, 1                  \n\t"
        "vspltisb 10, 7                 \n\t"
        "vsldoi 8, 0, 7, 1              \n\t"   // ...0x1
        "vor    18, 19, 8               \n\t"   // 0xc2...1
        "vspltb 9, 1, 0                 \n\t"   // most sig byte
        "vsl    1, 1, 7                 \n\t"   // Carry = H << 7
        "vsrab  9, 9, 10                \n\t"
        "vand   9, 9, 18                \n\t"   // intersted carry
        "vxor   10, 1, 9                \n\t"   // shift H <<< 1

        "vsldoi 19, 0, 18, 8            \n\t"   // 0...0xc2
        "vsldoi 11, 10, 10, 8           \n\t"   // swap L, H
        "vsldoi 2, 0, 11, 8             \n\t"   // H.L
        "vsldoi 3, 11, 0, 8             \n\t"   // H.H

        "stxvd2x 32+19, 0, %0           \n\t"
        "li     9, 16                   \n\t"
        "stxvd2x 32+2, 9, %0            \n\t"
        "addi   9, 9, 16                \n\t"
        "stxvd2x 32+11, 9, %0           \n\t"
        "addi   9, 9, 16                \n\t"
        "stxvd2x 32+3, 9, %0            \n\t"
        : "+r" (output)
        : "r" (H)
        : "memory");
}

/*
 * GCM multiplication
 */
void mbedtls_aesppc_gcm_mult(unsigned char output[16],
                             const unsigned char x[16],
                             const unsigned char h[16])
{
    unsigned char H[64] = { 0, };

    /* Shift H <<< 1 and arrange hash in (L, M, H) */
    ppc_gcm_shift(h, H);

    ppc_gcm_mul(output, H, x, 16);

    return;
}

/*
 * vr1 is the first key
 * vr5 is a mask to rotate a word in applied for all four words in our key.
 * vr5 = 0x0d0e0f0c 0d0e0f0c 0d0e0f0c 0d0e0f0c
 * vr3 is the key in use destination
 * vr4 is the first rcon loaded: 01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00
 *
 * key: (w0 - w3) -> (w4 - w7)
 * rcon : 1, 2, 3, 4, 5, 6, 7, 8, 0x1b, 0x36
 * Z1(w3): vcipherlast: (RotWord, SubWord) xor rcon(n, 0, 0, 0)
 *
 * Operation for 128 bits:
 *        w0    w1    w2    w3
 *       0    w0    w1    w2
 *  xor ------------------------
 *        w4'   w5'  t-w6'  t-w7'
 *       0    0     w0    w1
 *  xor ------------------------
 *        w4'   w5'   w6'  t-w7'
 *       0    0     0     w0
 *  xor ------------------------
 *        w4'   w5'   w6'    w7'
 *        Z1    Z1    Z1     Z1
 *  xor ------------------------
 *        w4    w5    w6     w7
 *
 * Refer to NIST.FIPS.197 appendix A.
 * -------------------------------------------------------------
 */

static uint8_t const rcon1[16] = { 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1,
                                   0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1};
static uint8_t const rcon1b[16] = { 0x0, 0x0, 0x0, 0x1b, 0x0, 0x0, 0x0, 0x1b,
                                    0x0, 0x0, 0x0, 0x1b, 0x0, 0x0, 0x0, 0x1b};
static uint8_t const mask[16] = { 0xc, 0xf, 0xe, 0xd, 0xc, 0xf, 0xe, 0xd,
                                  0xc, 0xf, 0xe, 0xd, 0xc, 0xf, 0xe, 0xd};

static void _ppc_setkey128(const unsigned char *key, unsigned char *rk)
{
    unsigned char buf[48+16];
    unsigned char *r1, *m;

    r1 = (unsigned char *) PPC_ALIGN(buf, 16);
    m = r1 + 32;
    memcpy(r1, rcon1, 16);
    memcpy(r1+16, rcon1b, 16);
    memcpy(m, mask, 16);

    asm volatile (
        "lvx    4, 0, %2        \n\t"   // 01 00 00 00
        "lvx    5, 0, %3        \n\t"   // mask

        "vxor   0, 0, 0         \n\t"
        "lxvb16x 32+1, 0, %1    \n\t"   // key
        "li     6, 8            \n\t"
        "mtctr  6               \n\t"
        "mr     7, %0           \n\t"   // out
        "stvx   1, 0, 7         \n\t"
        "addi   7, 7, 16        \n\t"

        "1:                     \n\t"
        "vperm  3,1,1,5         \n\t"   // Z1 (v3) = RotWord(w3)
        "vsldoi 6,0,1,12        \n\t"   // v6 = key >> 32
        "vcipherlast 3,3,4      \n\t"   // v3 = (SubBytes, ShiftRows) ^ rcon
        "vxor   1,1,6           \n\t"   // w4' w5' t-w6' t-w7'
        "vsldoi 6,0,6,12        \n\t"   //
        "vxor   1,1,6           \n\t"   // w4' w5' w6' t-w7'
        "vsldoi 6,0,6,12        \n\t"   //
        "vxor   1,1,6           \n\t"   // w4' w5' w6' w7'
        "vadduwm 4,4,4          \n\t"   // next rcon
        "vxor   1,1,3           \n\t"   // w4 w5 w6 w7
        "stvx   1, 0, 7         \n\t"
        "addi   7, 7, 16        \n\t"
        "bdnz   1b              \n\t"

        "li     6, 16           \n\t"
        "lvx    4, 6, %2        \n\t" // 0x1b

        "vperm  3,1,1,5         \n\t"
        "vsldoi 6,0,1,12        \n\t"
        "vcipherlast 3,3,4      \n\t"
        "vxor   1,1,6           \n\t"
        "vsldoi 6,0,6,12        \n\t"
        "vxor   1,1,6           \n\t"
        "vsldoi 6,0,6,12        \n\t"
        "vxor   1,1,6           \n\t"
        "vadduwm 4,4,4          \n\t"
        "vxor   1,1,3           \n\t"
        "stvx   1, 0, 7         \n\t"
        "addi   7, 7, 16        \n\t"

        "vperm  3,1,1,5         \n\t"
        "vsldoi 6,0,1,12        \n\t"
        "vcipherlast 3,3,4      \n\t"
        "vxor   1,1,6           \n\t"
        "vsldoi 6,0,6,12        \n\t"
        "vxor   1,1,6           \n\t"
        "vsldoi 6,0,6,12        \n\t"
        "vxor   1,1,6           \n\t"
        "vxor   1,1,3           \n\t"
        "stvx   1, 0, 7         \n\t"

        "addi   7, 7, 0x50      \n\t"
        "li     11, 10          \n\t"   // round
        "stw    11, 0(7)        \n\t"
        : "+r" (rk)
        : "r" (key), "r" (r1), "r" (m)
        : "memory");
}

static void _ppc_setkey192(const unsigned char *key, unsigned char *rk)
{
    unsigned char buf[48+16];
    unsigned char *r1, *m;
    r1 = (unsigned char *) PPC_ALIGN(buf, 16);
    m = r1 + 16;
    memcpy(r1, rcon1, 16);
    memcpy(m, mask, 16);

    asm volatile (
        "lvx    4, 0, %2        \n\t" // 01 00 00 00
        "lvx    5, 0, %3        \n\t" // mask

        "vxor   0, 0, 0         \n\t"
        "lxvb16x 32+1, 0, %1    \n\t" // load first 16-byte key
        "li     6, 16           \n\t"
        "lxvb16x 32+11, 6, %1   \n\t"   // load second 8-byte key
        "vsldoi 11, 0, 11, 8    \n\t"   // >> 8 bytes (0, 0, w4, w5)
        "li     6, 4            \n\t"
        "mtctr  6               \n\t"
        "mr     7, %0           \n\t"   // out
        "stvx   1, 0, 7         \n\t"
        "addi   7, 7, 16        \n\t"

        "1:                     \n\t"
        // frst 4 words
        "vperm  3,11,11,5       \n\t"   // Z1 (v3) = RotWord(w5)
        "vsldoi 6,0,1,12        \n\t"   // v6 = key >> 32
        "vcipherlast 3,3,4      \n\t"   // v3 = (SubBytes, ShiftRows) ^ rcon
        "vxor   1,1,6           \n\t"   // w4' w5' t-w6' t-w7'
        "vsldoi 6,0,6,12        \n\t"   //
        "vxor   1,1,6           \n\t"   // w4' w5' w6' t-w7'
        "vsldoi 6,0,6,12        \n\t"   //
        "vxor   2,1,6           \n\t"   // w4' w5' w6' w7'
        "vxor   1,2,3           \n\t"   // w4 w5 w6 w7
        "vsldoi 7, 11, 1, 8     \n\t"   // w4" w5" w0 w1
        "stvx   7, 0, 7         \n\t"
        "addi   7, 7, 16        \n\t"

        // handle remaining 2 words
        "vspltw 3, 1, 3         \n\t"
        "vsldoi 6,0,11,12       \n\t"   // v6 = key >> 32
        "vxor   11,11,6         \n\t"   // w4' w5'
        "vxor   11,11,3         \n\t"   // w4 w5
        "vsldoi 11, 11, 0, 8    \n\t"
        "vsldoi 7, 1, 11, 8     \n\t"   // (w6, w7, w4, w5)
        "vadduwm 4,4,4          \n\t"
        "stvx   7, 0, 7         \n\t"
        "addi   7, 7, 16        \n\t"

        // previous 6 words, v2 (w4", w5", w0, w1) and v11 (w4 w5, 0, 0)
        // handle new 4 words
        "vsldoi 11, 0, 11, 8    \n\t"
        "vperm  3,11,11,5       \n\t"   // Z1 (v3) = RotWord(last word)
        "vsldoi 6,0,1,12        \n\t"   // v6 = key >> 32
        "vcipherlast 3,3,4      \n\t"   // v3 = (SubBytes, ShiftRows) ^ rcon
        "vxor   1,1,6           \n\t"   // w4' w5' t-w6' t-w7'
        "vsldoi 6,0,6,12        \n\t"   //
        "vxor   1,1,6           \n\t"   // w4' w5' w6' t-w7'
        "vsldoi 6,0,6,12        \n\t"   //
        "vxor   2,1,6           \n\t"   // w4' w5' w6' w7'
        "vxor   1,2,3           \n\t"   // w4 w5 w6 w7
        "stvx   1, 0, 7         \n\t"
        "addi   7, 7, 16        \n\t"
        "vadduwm 4,4,4          \n\t"

        // handle remaining 2 words
        "vspltw 3, 1, 3         \n\t"
        "vsldoi 6,0,11,12       \n\t"   // v6 = key >> 32
        "vxor   11,11,6         \n\t"   // w4' w5'
        "vxor   11,11,3         \n\t"   // w4 w5
        "vsldoi 11, 11, 11, 8   \n\t"
        "vsldoi 11, 0, 11, 8    \n\t"

        "bdnz   1b              \n\t"

        "addi   7, 7, 0x20      \n\t"
        "li     11, 0x0c        \n\t"   // round
        "stw    11, 0(7)        \n\t"
        : "+r" (rk)
        : "r" (key), "r" (r1), "r" (m)
        : "memory");
}

static void _ppc_setkey256(const unsigned char *key, unsigned char *rk)
{
    unsigned char buf[48+16];
    unsigned char *r1, *m;
    r1 = (unsigned char *) PPC_ALIGN(buf, 16);
    m = r1 + 16;
    memcpy(r1, rcon1, 16);
    memcpy(m, mask, 16);

    asm volatile (
        "lvx    4, 0, %2        \n\t" // 01 00 00 00
        "lvx    5, 0, %3        \n\t" // mask

        "vxor   0, 0, 0         \n\t"
        "lxvb16x 32+1, 0, %1    \n\t"   // load first 16-byte key
        "li     6, 16           \n\t"
        "lxvb16x 32+11, 6, %1   \n\t"   // load second 16-byte key
        "li     6, 6            \n\t"   // 7 - 1
        "mtctr  6               \n\t"
        "mr     7, %0           \n\t"   // out
        "stvx   1, 0, 7         \n\t"
        "addi   7, 7, 16        \n\t"
        "stvx   11, 0, 7        \n\t"
        "addi   7, 7, 16        \n\t"

        "1:                     \n\t"
        "vperm  3,11,11,5       \n\t"   // Z1 (v3) = RotWord(w7)
        "vsldoi 6,0,1,12        \n\t"   // v6 = key >> 32
        "vcipherlast 3,3,4      \n\t"   // v3 = (SubBytes, ShiftRows) ^ rcon
        "vxor   1,1,6           \n\t"   // w4' w5' t-w6' t-w7'
        "vsldoi 6,0,6,12        \n\t"   //
        "vxor   1,1,6           \n\t"   // w4' w5' w6' t-w7'
        "vsldoi 6,0,6,12        \n\t"   //
        "vxor   1,1,6           \n\t"   // w4' w5' w6' w7'
        "vxor   1,1,3           \n\t"   // w4 w5 w6 w7
        "stvx   1, 0, 7         \n\t"
        "addi   7, 7, 16        \n\t"

        "vspltw 3,1,3           \n\t"   // splat last word
        "vsldoi 6,0,11,12       \n\t"
        "vsbox  3,3             \n\t"   // SubWord
        "vxor   11,11,6         \n\t"
        "vsldoi 6,0,6,12        \n\t"
        "vxor   11,11,6         \n\t"
        "vsldoi 6,0,6,12        \n\t"
        "vxor   11,11,6         \n\t"
        "vadduwm 4,4,4          \n\t"
        "vxor   11,11,3         \n\t"
        "stvx   11, 0, 7        \n\t"
        "addi   7, 7, 16        \n\t"
        "bdnz   1b              \n\t"

        // need one more
        "vperm  3,11,11,5       \n\t"   // Splat and rotate last key
        "vsldoi 6,0,1,12        \n\t"   // v6 = key >> 32
        "vcipherlast 3,3,4      \n\t"   // v3 = (SubBytes, ShiftRows) ^ rcon
        "vxor   1,1,6           \n\t"   // w4' w5' t-w6' t-w7'
        "vsldoi 6,0,6,12        \n\t"   //
        "vxor   1,1,6           \n\t"   // w4' w5' w6' t-w7'
        "vsldoi 6,0,6,12        \n\t"   //
        "vxor   1,1,6           \n\t"   // w4' w5' w6' w7'
        "vxor   1,1,3           \n\t"   // w4 w5 w6 w7
        "stvx   1, 0, 7         \n\t"
        "addi   7, 7, 16        \n\t"

        "li     11, 0x0e        \n\t"   // round
        "stw    11, 0(7)        \n\t"
        : "+r" (rk)
        : "r" (key), "r" (r1), "r" (m)
        : "memory");
}

int mbedtls_aesppc_setkey_enc(unsigned char *rk, const unsigned char *key,
                              unsigned int keybits)
{
    unsigned char Rkey[256+16];
    unsigned char *t1;
    uint32_t *t2 = (uint32_t *) rk;
    int i = 0, nr = 10;

    t1 = (unsigned char *) PPC_ALIGN(Rkey, 16);
    switch (keybits) {
        case 128:
            _ppc_setkey128(key, t1);
            nr = 10;
            break;
        case 192:
            _ppc_setkey192(key, t1);
            nr = 12;
            break;
        case 256:
            _ppc_setkey256(key, t1);
            nr = 14;
            break;
    }

    /* Reverse word order */
    for (i = 0; i < (nr+1); i++) {
        t2[0] = MBEDTLS_GET_UINT32_LE(t1, 0);
        t2[1] = MBEDTLS_GET_UINT32_LE(t1, 4);
        t2[2] = MBEDTLS_GET_UINT32_LE(t1, 8);
        t2[3] = MBEDTLS_GET_UINT32_LE(t1, 12);
        t1 += 16;
        t2 += 4;
    }
    return 0;
}

#endif /* MBEDTIS_USE_PPC */
