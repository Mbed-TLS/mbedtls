/**
 * \file config-tfm.h
 *
 * \brief TF-M medium profile, adapted to work on other platforms.
 */
/*
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

/* TF-M medium profile: mbedtls legacy configuration */
#include "../configs/ext/tfm_mbedcrypto_config_profile_medium.h"

/* TF-M medium profile: PSA crypto configuration */
#define MBEDTLS_PSA_CRYPTO_CONFIG_FILE "../configs/ext/crypto_config_profile_medium.h"

/***********************************************************/
/* Tweak the configuration to remove dependencies on TF-M. */
/***********************************************************/

/* MBEDTLS_PSA_CRYPTO_SPM needs third-party files, so disable it. */
#undef MBEDTLS_PSA_CRYPTO_SPM

/* TF-M provides its own dummy implementations to save code size.
 * We don't have any way to disable the tests that need these feature,
 * so we just keep AES decryption enabled. We will resolve this through
 * an official way to disable AES decryption, then this deviation
 * will no longer be needed:
 * https://github.com/Mbed-TLS/mbedtls/issues/7368
 */
#undef MBEDTLS_AES_SETKEY_DEC_ALT
#undef MBEDTLS_AES_DECRYPT_ALT
/* The configuration we have enables MBEDTLS_PK_PARSE_C and MBEDTLS_PK_WRITE_C
 * but not MBEDTLS_OID_C. This is inconsistent, and leads to a link error
 * when using one of the mbedtls_pk_parse_xxx or mbedtls_pk_write_xxx
 * functions that depend on an mbedtls_oid_xxx function.
 * Mbed TLS needs PK parse/write for RSA with PSA, but the medium
 * profile doesn't have RSA. Later versions of TF-M no longer enable
 * PK parse/write: it wasn't a wanted feature. So disable it here
 * (otherwise we'd have to enable MBEDTLS_OID_C).
 */
#undef MBEDTLS_PK_PARSE_C
#undef MBEDTLS_PK_WRITE_C

/* Use built-in platform entropy functions (TF-M provides its own). */
#undef MBEDTLS_NO_PLATFORM_ENTROPY

/* Disable buffer-based memory allocator. This isn't strictly required,
 * but using the native allocator is faster and works better with
 * memory management analysis frameworks such as ASan. */
#undef MBEDTLS_MEMORY_BUFFER_ALLOC_C
