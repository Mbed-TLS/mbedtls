/**
 * \file config-symmetric-only.h
 *
 * \brief Configuration without any asymmetric cryptography.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#define MBEDTLS_PSA_CRYPTO_CONFIG_FILE "../configs/crypto-config-symmetric-only.h"

#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_USE_PSA_CRYPTO

/* System support */
//#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

/* Mbed TLS feature support */
#define MBEDTLS_ERROR_STRERROR_DUMMY
#define MBEDTLS_FS_IO
#define MBEDTLS_ENTROPY_NV_SEED
#define MBEDTLS_SELF_TEST
#define MBEDTLS_VERSION_FEATURES

/* Mbed TLS modules */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_NIST_KW_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_PEM_WRITE_C
#define MBEDTLS_PKCS5_C
#define MBEDTLS_PKCS12_C
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PSA_CRYPTO_SE_C
#define MBEDTLS_PSA_CRYPTO_STORAGE_C
#define MBEDTLS_PSA_ITS_FILE_C

//#define MBEDTLS_THREADING_C
#define MBEDTLS_TIMING_C
#define MBEDTLS_VERSION_C
