/**
 * \file configs/crypto-config-ccm-aes-sha256.h
 *
 * \brief PSA crypto configuration with only symmetric cryptography: CCM-AES,
 *        SHA-256, HMAC and key derivation
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

#ifndef PSA_CRYPTO_CONFIG_H
#define PSA_CRYPTO_CONFIG_H

#define PSA_WANT_ALG_CCM 1
#define PSA_WANT_ALG_HMAC 1
#define PSA_WANT_ALG_SHA_256 1
#define PSA_WANT_ALG_TLS12_PRF 1
#define PSA_WANT_ALG_TLS12_PSK_TO_MS 1
#define PSA_WANT_KEY_TYPE_DERIVE 1
#define PSA_WANT_KEY_TYPE_HMAC 1
#define PSA_WANT_KEY_TYPE_AES 1
#define PSA_WANT_KEY_TYPE_RAW_DATA 1

#endif /* PSA_CRYPTO_CONFIG_H */
