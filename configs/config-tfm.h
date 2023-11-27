/**
 * \file config-tfm.h
 *
 * \brief TF-M medium profile, adapted to work on other platforms.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/* TF-M medium profile: mbedtls legacy configuration */
#include "../configs/ext/tfm_mbedcrypto_config_profile_medium.h"

/* TF-M medium profile: PSA crypto configuration */
#define MBEDTLS_PSA_CRYPTO_CONFIG_FILE "../configs/ext/crypto_config_profile_medium.h"

/***********************************************************/
/* Tweak the configuration to remove dependencies on TF-M. */
/***********************************************************/

/* MBEDTLS_PSA_CRYPTO_SPM needs third-party files, so disable it. */
#undef MBEDTLS_PSA_CRYPTO_SPM

/* Use built-in platform entropy functions (TF-M provides its own). */
#undef MBEDTLS_NO_PLATFORM_ENTROPY

/* Disable buffer-based memory allocator. This isn't strictly required,
 * but using the native allocator is faster and works better with
 * memory management analysis frameworks such as ASan. */
#undef MBEDTLS_MEMORY_BUFFER_ALLOC_C
