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
 *
 * To be used in conjunction with configs/config-suite-b.h. */

#ifndef PSA_CRYPTO_CONFIG_H
#define PSA_CRYPTO_CONFIG_H

#define PSA_WANT_ALG_ECDH                        1
#define PSA_WANT_ALG_ECDSA                       1
#define PSA_WANT_ALG_GCM                         1
#define PSA_WANT_ALG_SHA_256                     1
#define PSA_WANT_ALG_SHA_384                     1
#define PSA_WANT_ALG_SHA_512                     1
#define PSA_WANT_ECC_SECP_R1_256                 1
#define PSA_WANT_ECC_SECP_R1_384                 1
#define PSA_WANT_ALG_TLS12_PRF                   1

#define PSA_WANT_KEY_TYPE_AES                    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC     1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE  1

#define MBEDTLS_PSA_CRYPTO_C

/* System support */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME

#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C

/* For test certificates */
#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C

/* Save RAM at the expense of ROM */
#define MBEDTLS_AES_ROM_TABLES

/* Save RAM by adjusting to our exact needs */
#define MBEDTLS_MPI_MAX_SIZE    48 // 384-bit EC curve = 48 bytes

/* Save RAM at the expense of speed, see ecp.h */
#define MBEDTLS_ECP_WINDOW_SIZE        2
#define MBEDTLS_ECP_FIXED_POINT_OPTIM  0

/* Significant speed benefit at the expense of some ROM */
#define MBEDTLS_ECP_NIST_OPTIM

/*
 * You should adjust this to the exact number of sources you're using: default
 * is the "mbedtls_platform_entropy_poll" source, but you may want to add other ones.
 * Minimum is 2 for the entropy test suite.
 */
#define MBEDTLS_ENTROPY_MAX_SOURCES 2
#endif /* PSA_CRYPTO_CONFIG_H */
