/* MBEDTLS_USER_CONFIG_FILE for testing.
 * Only used for a few test configurations.
 *
 * Typical usage (note multiple levels of quoting):
 *     make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/user-config-for-test.h\"'"
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

#if defined(PSA_CRYPTO_DRIVER_TEST_ALL)

/* Enable the use of the test driver in the library, and build the generic
 * part of the test driver. */
#define PSA_CRYPTO_DRIVER_TEST

/* Use the accelerator driver for all cryptographic mechanisms for which
 * the test driver implemented. */
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_AES
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_CAMELLIA
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR
#define MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR
#define MBEDTLS_PSA_ACCEL_ALG_CBC_NO_PADDING
#define MBEDTLS_PSA_ACCEL_ALG_CBC_PKCS7
#define MBEDTLS_PSA_ACCEL_ALG_CTR
#define MBEDTLS_PSA_ACCEL_ALG_CFB
#define MBEDTLS_PSA_ACCEL_ALG_ECDSA
#define MBEDTLS_PSA_ACCEL_ALG_DETERMINISTIC_ECDSA
#define MBEDTLS_PSA_ACCEL_ALG_MD5
#define MBEDTLS_PSA_ACCEL_ALG_OFB
#define MBEDTLS_PSA_ACCEL_ALG_RIPEMD160
#define MBEDTLS_PSA_ACCEL_ALG_RSA_PKCS1V15_SIGN
#define MBEDTLS_PSA_ACCEL_ALG_RSA_PSS
#define MBEDTLS_PSA_ACCEL_ALG_SHA_1
#define MBEDTLS_PSA_ACCEL_ALG_SHA_224
#define MBEDTLS_PSA_ACCEL_ALG_SHA_256
#define MBEDTLS_PSA_ACCEL_ALG_SHA_384
#define MBEDTLS_PSA_ACCEL_ALG_SHA_512
#define MBEDTLS_PSA_ACCEL_ALG_XTS
#define MBEDTLS_PSA_ACCEL_ALG_CMAC
#define MBEDTLS_PSA_ACCEL_ALG_HMAC

#endif  /* PSA_CRYPTO_DRIVER_TEST_ALL */



#if defined(MBEDTLS_TEST_PLATFORM_MACROS)
/* A build for testing where the platform macros are defined to be functions
 * in the test framework that log that the function was called, then call the
 * standard function. See tests/configs/user-config-for-test.h.
 *
 * Currently implemented only for calloc/free, to be extended eventually
 * to all such macros.
 */

#include <stddef.h>

#if defined(MBEDTLS_PLATFORM_C)
#define MBEDTLS_PLATFORM_MEMORY
#endif
void *mbedtls_test_platform_calloc_macro( size_t, size_t );
#define MBEDTLS_PLATFORM_CALLOC_MACRO mbedtls_test_platform_calloc_macro
void mbedtls_test_platform_free_macro( void* );
#define MBEDTLS_PLATFORM_FREE_MACRO mbedtls_test_platform_free_macro

#endif
