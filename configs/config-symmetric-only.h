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

/* Mbed TLS feature support */
#define MBEDTLS_ERROR_STRERROR_DUMMY
#define MBEDTLS_VERSION_FEATURES

#define MBEDTLS_TIMING_C
#define MBEDTLS_VERSION_C
