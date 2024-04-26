/**
 * \file crypto-config-symmetric-only.h
 *
 * \brief \brief Minimal crypto configuration for
 * TLS NSA Suite B Profile (RFC 6460).
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/**
 * Minimal crypto configuration for TLS NSA Suite B Profile (RFC 6460)
 *
 * Distinguishing features:
 * - no RSA or classic DH, fully based on ECC
 * - optimized for low RAM usage
 *
 * Possible improvements:
 * - if 128-bit security is enough, disable secp384r1 and SHA-512
 * - use embedded certs in DER format and disable PEM_PARSE_C and BASE64_C
 *
 * To be used in conjunction with configs/config-suite-b.h. */

#ifndef PSA_CRYPTO_CONFIG_H
#define PSA_CRYPTO_CONFIG_H

#define PSA_WANT_ALG_ECB_NO_PADDING              1
#define PSA_WANT_ALG_ECDH                        1
#define PSA_WANT_ALG_ECDSA                       1
#define PSA_WANT_ALG_GCM                         1
#define PSA_WANT_ALG_HMAC                        1
#define PSA_WANT_ALG_SHA_256                     1
#define PSA_WANT_ALG_SHA_384                     1
#define PSA_WANT_ALG_SHA_512                     1
#define PSA_WANT_ECC_SECP_R1_256                 1
#define PSA_WANT_ALG_TLS12_PRF                   1
#define PSA_WANT_ALG_TLS12_PSK_TO_MS             1
#define PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS        1

#define PSA_WANT_KEY_TYPE_AES                    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC     1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE  1
#define PSA_WANT_KEY_TYPE_HMAC                   1
#endif /* PSA_CRYPTO_CONFIG_H */
