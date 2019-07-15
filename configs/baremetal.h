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
#define MBEDTLS_CCM_C

/* Asymmetric crypto: Single-curve ECC only. */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECDSA_DETERMINISTIC
#define MBEDTLS_ECP_WINDOW_SIZE        2
#define MBEDTLS_ECP_FIXED_POINT_OPTIM  0
#define MBEDTLS_ECP_MAX_BITS   256
#define MBEDTLS_MPI_MAX_SIZE    32 // 256 bits is 32 bytes

#define MBEDTLS_SSL_CONF_SINGLE_EC
#define MBEDTLS_SSL_CONF_SINGLE_EC_GRP_ID MBEDTLS_ECP_DP_SECP256R1
#define MBEDTLS_SSL_CONF_SINGLE_EC_TLS_ID 23

/* Key exchanges */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_SSL_CIPHERSUITES MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
#define MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8

/* Digests - just SHA-256 */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA256_SMALLER

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

/* Compile-time fixed parts of the SSL configuration */
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
#define MBEDTLS_SSL_CONF_RNG mbedtls_hmac_drbg_random
#define MBEDTLS_SSL_CONF_MIN_MINOR_VER MBEDTLS_SSL_MINOR_VERSION_3
#define MBEDTLS_SSL_CONF_MAX_MINOR_VER MBEDTLS_SSL_MINOR_VERSION_3
#define MBEDTLS_SSL_CONF_MIN_MAJOR_VER MBEDTLS_SSL_MAJOR_VERSION_3
#define MBEDTLS_SSL_CONF_MAX_MAJOR_VER MBEDTLS_SSL_MAJOR_VERSION_3
#define MBEDTLS_SSL_CONF_EXTENDED_MASTER_SECRET \
    MBEDTLS_SSL_EXTENDED_MS_ENABLED
#define MBEDTLS_SSL_CONF_ENFORCE_EXTENDED_MASTER_SECRET \
    MBEDTLS_SSL_EXTENDED_MS_ENFORCE_ENABLED

/* X.509 CRT parsing */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CHECK_KEY_USAGE
#define MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE
#define MBEDTLS_X509_REMOVE_INFO
#define MBEDTLS_X509_ON_DEMAND_PARSING
#define MBEDTLS_X509_ALWAYS_FLUSH
#define MBEDTLS_ASN1_PARSE_C

/* X.509 CSR writing */
#define MBEDTLS_X509_CSR_WRITE_C
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_ASN1_WRITE_C

/* RNG and PRNG */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_HMAC_DRBG_C

#define MBEDTLS_OID_C
#define MBEDTLS_PLATFORM_C

/* I/O buffer configuration */
#define MBEDTLS_SSL_MAX_CONTENT_LEN             2048

/* Server-side only */
#define MBEDTLS_SSL_TICKET_C
#define MBEDTLS_SSL_SRV_C

#if defined(MBEDTLS_USER_CONFIG_FILE)
#include MBEDTLS_USER_CONFIG_FILE
#endif

#include <mbedtls/check_config.h>

#endif /* MBEDTLS_BAREMETAL_CONFIG_H */
