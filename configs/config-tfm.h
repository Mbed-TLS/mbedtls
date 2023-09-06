/**
 * \file config-tfm.h
 *
 * \brief TF-M configuration with tweaks for a successful build and test.
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

/* TF-M Configuration Options */
#include "../configs/ext/tfm_mbedcrypto_config_profile_medium.h"

/* TF-M PSA Crypto Configuration */
#define MBEDTLS_PSA_CRYPTO_CONFIG_FILE "../configs/ext/crypto_config_profile_medium.h"

/*****************************************************************************/
/* Tweak configuration based on TF-M config for a successful build and test. */
/*****************************************************************************/

/* MBEDTLS_PSA_CRYPTO_SPM needs third party files, so disable it. */
#undef MBEDTLS_PSA_CRYPTO_SPM
/* TF-M provides its own (dummy) implemenations which Mbed TLS doesn't need. */
#undef MBEDTLS_AES_SETKEY_DEC_ALT
#undef MBEDTLS_AES_DECRYPT_ALT
/* pkparse.c fails to link without this. */
#define MBEDTLS_OID_C

/* Since MBEDTLS_PSA_CRYPTO_STORAGE_C is disabled, we need to disable this to
   pass test_suite_psa_crypto_slot_management. */
#undef MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
/* Use built-in platform entropy functions. */
#undef MBEDTLS_NO_PLATFORM_ENTROPY
/* Disable buffer-based memory allocator */
#undef MBEDTLS_MEMORY_BUFFER_ALLOC_C
