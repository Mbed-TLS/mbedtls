/**
 * \file baremetal.h
 *
 * \brief Test configuration for minimal baremetal Mbed TLS builds
 *        based on the following primitives:
 *        - ECDHE-ECDSA only
 *        - Elliptic curve SECP256R1 only
 *        - SHA-256 only
 *        - AES-CCM-8 only
 *
 *        The library compiles in this configuration, but the example
 *        programs `ssl_client2` and `ssl_server2` require the
 *        modifications from `baremetal_test.h`.
 */
/*
 *  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_BAREMETAL_CONFIG_H
#define MBEDTLS_BAREMETAL_CONFIG_H

/* Symmetric crypto: AES-CCM only */
#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_AES_FEWER_TABLES
#define MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH
#define MBEDTLS_AES_ONLY_ENCRYPT
#define MBEDTLS_AES_SCA_COUNTERMEASURES
#define MBEDTLS_AES_128_BIT_MASKED
#define MBEDTLS_CCM_C

/* Asymmetric crypto: Single-curve ECC only. */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C

#define MBEDTLS_ENTROPY_MAX_SOURCES 1

#define MBEDTLS_SSL_CONF_SINGLE_EC
#define MBEDTLS_SSL_CONF_SINGLE_UECC_GRP_ID MBEDTLS_UECC_DP_SECP256R1
#define MBEDTLS_SSL_CONF_SINGLE_EC_TLS_ID 23
#define MBEDTLS_SSL_CONF_SINGLE_SIG_HASH
#define MBEDTLS_SSL_CONF_SINGLE_SIG_HASH_MD_ID MBEDTLS_MD_SHA256
#define MBEDTLS_SSL_CONF_SINGLE_SIG_HASH_TLS_ID MBEDTLS_SSL_HASH_SHA256

/* Harcoded options in abstraction layers */
#define MBEDTLS_MD_SINGLE_HASH MBEDTLS_MD_INFO_SHA256
#define MBEDTLS_PK_SINGLE_TYPE MBEDTLS_PK_INFO_ECKEY

/* Key exchanges */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
#define MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8

/* Digests - just SHA-256 */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA256_SMALLER
#define MBEDTLS_SHA256_NO_SHA224

/* TLS options */
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#define MBEDTLS_SSL_NO_SESSION_CACHE
#define MBEDTLS_SSL_NO_SESSION_RESUMPTION
#define MBEDTLS_SSL_COOKIE_C
#define MBEDTLS_SSL_PROTO_DTLS
#define MBEDTLS_SSL_PROTO_NO_TLS
#define MBEDTLS_SSL_DTLS_ANTI_REPLAY
#define MBEDTLS_SSL_DTLS_HELLO_VERIFY
#define MBEDTLS_SSL_DTLS_BADMAC_LIMIT
#define MBEDTLS_SSL_DTLS_CONNECTION_ID
#define MBEDTLS_SSL_TRANSFORM_OPTIMIZE_CIPHERS

/* Compile-time fixed parts of the SSL configuration */
#define MBEDTLS_SSL_CONF_TRANSPORT MBEDTLS_SSL_TRANSPORT_DATAGRAM
#define MBEDTLS_SSL_CONF_CERT_REQ_CA_LIST MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED
#define MBEDTLS_SSL_CONF_READ_TIMEOUT 0
#define MBEDTLS_SSL_CONF_HS_TIMEOUT_MIN 1000
#define MBEDTLS_SSL_CONF_HS_TIMEOUT_MAX 16000
#define MBEDTLS_SSL_CONF_CID_LEN 2
#define MBEDTLS_SSL_CONF_IGNORE_UNEXPECTED_CID MBEDTLS_SSL_UNEXPECTED_CID_IGNORE
#define MBEDTLS_SSL_CONF_ALLOW_LEGACY_RENEGOTIATION \
    MBEDTLS_SSL_SECURE_RENEGOTIATION
#define MBEDTLS_SSL_CONF_AUTHMODE MBEDTLS_SSL_VERIFY_REQUIRED
#define MBEDTLS_SSL_CONF_BADMAC_LIMIT 0
#define MBEDTLS_SSL_CONF_ANTI_REPLAY MBEDTLS_SSL_ANTI_REPLAY_ENABLED
#define MBEDTLS_SSL_CONF_GET_TIMER mbedtls_timing_get_delay
#define MBEDTLS_SSL_CONF_SET_TIMER mbedtls_timing_set_delay
#define MBEDTLS_SSL_CONF_RECV mbedtls_net_recv
#define MBEDTLS_SSL_CONF_SEND mbedtls_net_send
#define MBEDTLS_SSL_CONF_RECV_TIMEOUT mbedtls_net_recv_timeout
#define MBEDTLS_SSL_CONF_RNG rng_wrap
#define MBEDTLS_SSL_CONF_MIN_MINOR_VER MBEDTLS_SSL_MINOR_VERSION_3
#define MBEDTLS_SSL_CONF_MAX_MINOR_VER MBEDTLS_SSL_MINOR_VERSION_3
#define MBEDTLS_SSL_CONF_MIN_MAJOR_VER MBEDTLS_SSL_MAJOR_VERSION_3
#define MBEDTLS_SSL_CONF_MAX_MAJOR_VER MBEDTLS_SSL_MAJOR_VERSION_3
#define MBEDTLS_SSL_CONF_EXTENDED_MASTER_SECRET \
    MBEDTLS_SSL_EXTENDED_MS_ENABLED
#define MBEDTLS_SSL_CONF_ENFORCE_EXTENDED_MASTER_SECRET \
    MBEDTLS_SSL_EXTENDED_MS_ENFORCE_ENABLED

#define MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH

#define MBEDTLS_USE_TINYCRYPT
#define MBEDTLS_HAVE_ASM
#if !( defined(__STRICT_ANSI__) && defined(__CC_ARM) )
    #define MBEDTLS_OPTIMIZE_TINYCRYPT_ASM
#endif
/* X.509 CRT parsing */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CHECK_KEY_USAGE
#define MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE
#define MBEDTLS_X509_REMOVE_INFO
#define MBEDTLS_X509_CRT_REMOVE_TIME
#define MBEDTLS_X509_CRT_REMOVE_SUBJECT_ISSUER_ID
#define MBEDTLS_X509_ON_DEMAND_PARSING
#define MBEDTLS_X509_ALWAYS_FLUSH
#define MBEDTLS_X509_REMOVE_VERIFY_CALLBACK
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_X509_REMOVE_HOSTNAME_VERIFICATION

/* RNG and PRNG */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_HMAC_DRBG_C

#define MBEDTLS_OID_C
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_VALIDATE_SSL_KEYS_INTEGRITY
#define MBEDTLS_VALIDATE_AES_KEYS_INTEGRITY

/* I/O buffer configuration */
#define MBEDTLS_SSL_MAX_CONTENT_LEN             2048

/* Server-side only */
#define MBEDTLS_SSL_SRV_C

#define MBEDTLS_DEPRECATED_REMOVED

/* Fault Injection Countermeasures */
#define MBEDTLS_FI_COUNTERMEASURES
#define MBEDTLS_CCM_SHUFFLING_MASKING

#if defined(MBEDTLS_USER_CONFIG_FILE)
#include MBEDTLS_USER_CONFIG_FILE
#endif

#include <mbedtls/check_config.h>

#endif /* MBEDTLS_BAREMETAL_CONFIG_H */
