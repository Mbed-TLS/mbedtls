/**
 * \file config-milagro.h
 *
 * \brief Configuration options (set of defines)
 *
 *  This set of compile-time options may be used to enable
 *  or disable features selectively, and reduce the global
 *  memory footprint.
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS
#define MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN
#define MBEDTLS_CIPHER_PADDING_ZEROS
#define MBEDTLS_KEY_EXCHANGE_MILAGRO_CS_ENABLED
#define MBEDTLS_KEY_EXCHANGE_MILAGRO_P2P_ENABLED
#define MBEDTLS_ERROR_STRERROR_DUMMY
#define MBEDTLS_FS_IO
#define MBEDTLS_TLS_MILAGRO_CS
#define MBEDTLS_TLS_MILAGRO_P2P
#define MBEDTLS_TLS_MILAGRO_CS_TIME_PERMITS
//#define MBEDTLS_TLS_MILAGRO_CS_ENABLE_PIN
#define MBEDTLS_SELF_TEST
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_VERSION_FEATURES
#define MBEDTLS_AESNI_C
#define MBEDTLS_AES_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_DEBUG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_GCM_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_MD_C
#define MBEDTLS_NET_C
#define MBEDTLS_PADLOCK_C
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SSL_CACHE_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_TIMING_C
#define MBEDTLS_VERSION_C

#if defined(TARGET_LIKE_MBED)
#include "mbedtls/target_config.h"
#endif

#if defined(YOTTA_CFG_MBEDTLS_USER_CONFIG_FILE)
#include YOTTA_CFG_MBEDTLS_USER_CONFIG_FILE
#elif defined(MBEDTLS_USER_CONFIG_FILE)
#include MBEDTLS_USER_CONFIG_FILE
#endif

#include "check_config.h"

#endif /* MBEDTLS_CONFIG_H */
