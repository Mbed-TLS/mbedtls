/*
 *  Example illustrating a digital signature operation using the PSA
 *  Crypto API.
 *
 *  psa_sign_hash(), is an API call to sign an already-calculated hash
 *  with a private key. Alternatively, psa_sign_message() offers a way
 *  to to hash and sign a message in a single call. psa_sign_hash() is
 *  used in this example.
 *
 *  psa_verify_hash() allows the recipient of a signature to verify
 *  the message.
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

#if !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(MBEDTLS_ECDSA_C) || \
    defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
int main(void)
{
    mbedtls_printf("MBEDTLS_PSA_CRYPTO_C and MBEDTLS_ECDSA_C"
                   "not defined and/or "
                   "MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER defined.\r\n");
    return 0;
}
#else

#define KEY_BYTES_VALUE {                                                       \
        0x49, 0xc9, 0xa8, 0xc1, 0x8c, 0x4b, 0x88, 0x56, 0x38, 0xc4, 0x31, 0xcf, \
        0x1d, 0xf1, 0xc9, 0x94, 0x13, 0x16, 0x09, 0xb5, 0x80, 0xd4, 0xfd, 0x43, \
        0xa0, 0xca, 0xb1, 0x7d, 0xb2, 0xf1, 0x3e, 0xee                          \
}

#define PLAINTEXT_VALUE "Hello World!"

/* SHA-256(plaintext) */
#define HASH_VALUE {                                                            \
        0x5a, 0x09, 0xe8, 0xfa, 0x9c, 0x77, 0x80, 0x7b, 0x24, 0xe9, 0x9c, 0x9c, \
        0xf9, 0x99, 0xde, 0xbf, 0xad, 0x84, 0x41, 0xe2, 0x69, 0xeb, 0x96, 0x0e, \
        0x20, 0x1f, 0x61, 0xfc, 0x3d, 0xe2, 0x0d, 0x5a                          \
}

int main(void)
{
    psa_status_t status;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t signature[PSA_SIGNATURE_MAX_SIZE] = { 0 };
    size_t signature_length;
    const uint8_t key_bytes[] = KEY_BYTES_VALUE;
    const uint8_t plaintext[] = PLAINTEXT_VALUE;
    const uint8_t hash[] = HASH_VALUE;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_crypto_init failed\n");
        return EXIT_FAILURE;
    }

    psa_set_key_usage_flags(&attributes,
                            PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&attributes, key_bytes, sizeof(key_bytes), &key_id);
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_import_key failed\n");
        return EXIT_FAILURE;
    }

    status = psa_sign_hash(key_id,                          // key handle
                           PSA_ALG_ECDSA(PSA_ALG_SHA_256),  // signature algorithm
                           hash, sizeof(hash),              // hash of the message
                           signature, sizeof(signature),    // signature (as output)
                           &signature_length);              // length of signature output
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_sign_hash failed\n");
        return EXIT_FAILURE;
    }

    mbedtls_printf("ECDSA-SHA256 signature of SHA-256('%s'):\n", plaintext);

    for (size_t j = 0; j < signature_length; j++) {
        if (j % 8 == 0) {
            mbedtls_printf("\n    ");
        }
        mbedtls_printf("%02x ", signature[j]);
    }

    mbedtls_printf("\n");

    status = psa_verify_hash(key_id,                          // key handle
                             PSA_ALG_ECDSA(PSA_ALG_SHA_256),  // signature algorithm
                             hash, sizeof(hash),              // hash of message
                             signature, signature_length);    // signature
    if (status != PSA_SUCCESS) {
        mbedtls_printf("psa_verify_hash failed\n");
        return EXIT_FAILURE;
    } else {
        mbedtls_printf("\nSignature verification successful!\n");
    }

    psa_destroy_key(key_id);
    mbedtls_psa_crypto_free();
    return 0;
}
#endif /* MBEDTLS_PSA_CRYPTO_C && MBEDTLS_ECDSA_C */
