/**
 * \file config-thread.h
 *
 * \brief Minimal configuration for using TLS as part of Thread
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * Minimal configuration for using TLS a part of Thread
 * http://threadgroup.org/
 *
 * Distinguishing features:
 * - no RSA or classic DH, fully based on ECC
 * - no X.509
 * - support for experimental EC J-PAKE key exchange
 *
 * To be used in conjunction with configs/crypto-config-thread.h.
 * See README.txt for usage instructions.
 */

#define MBEDTLS_PSA_CRYPTO_CONFIG_FILE "../configs/crypto-config-thread.h"

#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_CONFIG
#define MBEDTLS_USE_PSA_CRYPTO

/* System support */
#define MBEDTLS_HAVE_ASM

/* Mbed TLS feature support */
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_PROTO_DTLS
#define MBEDTLS_SSL_DTLS_ANTI_REPLAY
#define MBEDTLS_SSL_DTLS_HELLO_VERIFY

/* Mbed TLS modules */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_SSL_COOKIE_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_TLS_C

/* For tests using ssl-opt.sh */
#define MBEDTLS_NET_C
#define MBEDTLS_TIMING_C

/* Save RAM at the expense of ROM */
#define MBEDTLS_AES_ROM_TABLES

/* Save RAM by adjusting to our exact needs */
#define MBEDTLS_MPI_MAX_SIZE              32 // 256-bit EC curve = 32 bytes

/* Save ROM and a few bytes of RAM by specifying our own ciphersuite list */
#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8
