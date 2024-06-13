/**
 * \file crypto-config-no-entropy.h
 *
 * \brief Minimal crypto configuration of features that do not require an entropy source
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 * Minimal configuration of features that do not require an entropy source
 * Distinguishing features:
 * - no entropy module
 * - no TLS protocol implementation available due to absence of an entropy
 *   source
 *
 * See README.txt for usage instructions.
 */

#define PSA_WANT_ALG_CBC_PKCS7                  1
#define PSA_WANT_ALG_CCM                        1
#define PSA_WANT_ALG_DETERMINISTIC_ECDSA        1
#define PSA_WANT_ALG_ECDSA                      1
#define PSA_WANT_ALG_GCM                        1
#define PSA_WANT_ALG_HMAC                       1
#define PSA_WANT_ALG_RSA_OAEP                   1
#define PSA_WANT_ALG_RSA_PKCS1V15_CRYPT         1
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN          1
#define PSA_WANT_ALG_RSA_PSS                    1
#define PSA_WANT_ALG_SHA_224                    1
#define PSA_WANT_ALG_SHA_256                    1
#define PSA_WANT_ALG_SHA_384                    1
#define PSA_WANT_ALG_SHA_512                    1

#define PSA_WANT_ECC_MONTGOMERY_255             1
#define PSA_WANT_ECC_SECP_R1_256                1
#define PSA_WANT_ECC_SECP_R1_384                1

#define PSA_WANT_KEY_TYPE_AES                   1
