/*
 *  Example computing a SHA-256 hash using the PSA Crypto API
 *
 *  The example computes the SHA-256 hash of a test string using the
 *  one-shot API call psa_hash_compute() and the using multi-part
 *  operation, which requires psa_hash_setup(), psa_hash_update() and
 *  psa_hash_finish(). The multi-part operation is popular on embedded
 *  devices where a rolling hash needs to be computed.
 *
 *
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


#include "psa/crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "mbedtls/build_info.h"
#include "mbedtls/platform.h"

#define HASH_ALG PSA_ALG_SHA_256

#define TEST_SHA256_HASH {                                                 \
        0x5a, 0x09, 0xe8, 0xfa, 0x9c, 0x77, 0x80, 0x7b, 0x24, 0xe9, 0x9c, 0x9c, \
        0xf9, 0x99, 0xde, 0xbf, 0xad, 0x84, 0x41, 0xe2, 0x69, 0xeb, 0x96, 0x0e, \
        0x20, 0x1f, 0x61, 0xfc, 0x3d, 0xe2, 0x0d, 0x5a                          \
}

const uint8_t test_sha256_hash[] = TEST_SHA256_HASH;

const size_t test_sha256_hash_len =
    sizeof(test_sha256_hash);

#if !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(PSA_WANT_ALG_SHA_256)
int main(void)
{
    mbedtls_printf("MBEDTLS_PSA_CRYPTO_C and PSA_WANT_ALG_SHA_256"
                   "not defined.\r\n");
    return EXIT_SUCCESS;
}
#else

int main(void)
{
    uint8_t buf[] = "Hello World!";
    psa_status_t status;
    uint8_t hash[PSA_HASH_LENGTH(HASH_ALG)];
    size_t hash_length;
    psa_hash_operation_t hash_operation = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t cloned_hash_operation = PSA_HASH_OPERATION_INIT;

    mbedtls_printf("PSA Crypto API: SHA-256 example\n\n");

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_crypto_init failed\n");
        return EXIT_FAILURE;
    }

    /* Compute hash using multi-part operation */

    status = psa_hash_setup(&hash_operation, HASH_ALG);
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_hash_setup failed\n");
        psa_hash_abort(&hash_operation);
        psa_hash_abort(&cloned_hash_operation);
        return EXIT_FAILURE;
    }

    status = psa_hash_update(&hash_operation, buf, sizeof(buf));
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_hash_update failed\n");
        psa_hash_abort(&hash_operation);
        psa_hash_abort(&cloned_hash_operation);
        return EXIT_FAILURE;
    }

    status = psa_hash_clone(&hash_operation, &cloned_hash_operation);
    if (status != PSA_SUCCESS) {
        mbedtls_printf("PSA hash clone failed");
        psa_hash_abort(&hash_operation);
        psa_hash_abort(&cloned_hash_operation);
        return EXIT_FAILURE;
    }

    status = psa_hash_finish(&hash_operation, hash, sizeof(hash), &hash_length);
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_hash_finish failed\n");
        psa_hash_abort(&hash_operation);
        psa_hash_abort(&cloned_hash_operation);
        return EXIT_FAILURE;
    }

    status =
        psa_hash_verify(&cloned_hash_operation, test_sha256_hash,
                        test_sha256_hash_len);
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_hash_verify failed\n");
        psa_hash_abort(&hash_operation);
        psa_hash_abort(&cloned_hash_operation);
        return EXIT_FAILURE;
    } else {
        mbedtls_printf("Multi-part hash operation successful!\n");
    }

    /* Clear local variables prior to one-shot hash demo */
    memset(hash, 0, sizeof(hash));
    hash_length = 0;

    /* Compute hash using one-shot function call */
    status = psa_hash_compute(HASH_ALG,
                              buf, sizeof(buf),
                              hash, sizeof(hash),
                              &hash_length);
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_hash_compute failed\n");
        psa_hash_abort(&hash_operation);
        psa_hash_abort(&cloned_hash_operation);
        return EXIT_FAILURE;
    }

    if (memcmp(hash, test_sha256_hash, test_sha256_hash_len) != 0)
    {
        mbedtls_printf("One-shot hash operation gave the wrong result!\n\n");
        psa_hash_abort(&hash_operation);
        psa_hash_abort(&cloned_hash_operation);
        return EXIT_FAILURE;
    }

    mbedtls_printf("One-shot hash operation successful!\n\n");

    mbedtls_printf("The SHA-256( '%s' ) is: ", buf);

    for (size_t j = 0; j < test_sha256_hash_len; j++) {
        mbedtls_printf("%02x", hash[j]);
    }

    mbedtls_printf("\n");

    mbedtls_psa_crypto_free();
    return EXIT_SUCCESS;
}
#endif /* MBEDTLS_PSA_CRYPTO_C && PSA_WANT_ALG_SHA_256 */