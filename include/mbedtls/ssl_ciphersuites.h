/**
 * \file ssl_ciphersuites.h
 *
 * \brief SSL Ciphersuites for mbed TLS
 */
/*
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
#ifndef MBEDTLS_SSL_CIPHERSUITES_H
#define MBEDTLS_SSL_CIPHERSUITES_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "pk.h"
#include "cipher.h"
#include "md.h"
#include "ssl.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Supported ciphersuites (Official IANA names)
 */
#define MBEDTLS_TLS_RSA_WITH_NULL_MD5                    0x01   /**< Weak! */
#define MBEDTLS_TLS_RSA_WITH_NULL_SHA                    0x02   /**< Weak! */

#define MBEDTLS_TLS_RSA_WITH_RC4_128_MD5                 0x04
#define MBEDTLS_TLS_RSA_WITH_RC4_128_SHA                 0x05
#define MBEDTLS_TLS_RSA_WITH_DES_CBC_SHA                 0x09   /**< Weak! Not in TLS 1.2 */

#define MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA            0x0A

#define MBEDTLS_TLS_DHE_RSA_WITH_DES_CBC_SHA             0x15   /**< Weak! Not in TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA        0x16

#define MBEDTLS_TLS_PSK_WITH_NULL_SHA                    0x2C   /**< Weak! */
#define MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA                0x2D   /**< Weak! */
#define MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA                0x2E   /**< Weak! */
#define MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA             0x2F

#define MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA         0x33
#define MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA             0x35
#define MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA         0x39

#define MBEDTLS_TLS_RSA_WITH_NULL_SHA256                 0x3B   /**< Weak! */
#define MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256          0x3C   /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256          0x3D   /**< TLS 1.2 */

#define MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA        0x41
#define MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA    0x45

#define MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256      0x67   /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256      0x6B   /**< TLS 1.2 */

#define MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA        0x84
#define MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA    0x88

#define MBEDTLS_TLS_PSK_WITH_RC4_128_SHA                 0x8A
#define MBEDTLS_TLS_PSK_WITH_3DES_EDE_CBC_SHA            0x8B
#define MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA             0x8C
#define MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA             0x8D

#define MBEDTLS_TLS_DHE_PSK_WITH_RC4_128_SHA             0x8E
#define MBEDTLS_TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA        0x8F
#define MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA         0x90
#define MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA         0x91

#define MBEDTLS_TLS_RSA_PSK_WITH_RC4_128_SHA             0x92
#define MBEDTLS_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA        0x93
#define MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA         0x94
#define MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA         0x95

#define MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256          0x9C   /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384          0x9D   /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256      0x9E   /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384      0x9F   /**< TLS 1.2 */

#define MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256          0xA8   /**< TLS 1.2 */
#define MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384          0xA9   /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256      0xAA   /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384      0xAB   /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256      0xAC   /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384      0xAD   /**< TLS 1.2 */

#define MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256          0xAE
#define MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384          0xAF
#define MBEDTLS_TLS_PSK_WITH_NULL_SHA256                 0xB0   /**< Weak! */
#define MBEDTLS_TLS_PSK_WITH_NULL_SHA384                 0xB1   /**< Weak! */

#define MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256      0xB2
#define MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384      0xB3
#define MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA256             0xB4   /**< Weak! */
#define MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA384             0xB5   /**< Weak! */

#define MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256      0xB6
#define MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384      0xB7
#define MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA256             0xB8   /**< Weak! */
#define MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA384             0xB9   /**< Weak! */

#define MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256     0xBA   /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 0xBE   /**< TLS 1.2 */

#define MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256     0xC0   /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 0xC4   /**< TLS 1.2 */

#define MBEDTLS_TLS_ECDH_ECDSA_WITH_NULL_SHA             0xC001 /**< Weak! */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_RC4_128_SHA          0xC002 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA     0xC003 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA      0xC004 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA      0xC005 /**< Not in SSL3! */

#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_NULL_SHA            0xC006 /**< Weak! */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA         0xC007 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA    0xC008 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA     0xC009 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA     0xC00A /**< Not in SSL3! */

#define MBEDTLS_TLS_ECDH_RSA_WITH_NULL_SHA               0xC00B /**< Weak! */
#define MBEDTLS_TLS_ECDH_RSA_WITH_RC4_128_SHA            0xC00C /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA       0xC00D /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA        0xC00E /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA        0xC00F /**< Not in SSL3! */

#define MBEDTLS_TLS_ECDHE_RSA_WITH_NULL_SHA              0xC010 /**< Weak! */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_RC4_128_SHA           0xC011 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA      0xC012 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA       0xC013 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA       0xC014 /**< Not in SSL3! */

#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256  0xC023 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384  0xC024 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256   0xC025 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384   0xC026 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256    0xC027 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384    0xC028 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256     0xC029 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384     0xC02A /**< TLS 1.2 */

#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  0xC02B /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  0xC02C /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256   0xC02D /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384   0xC02E /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    0xC02F /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384    0xC030 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256     0xC031 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384     0xC032 /**< TLS 1.2 */

#define MBEDTLS_TLS_ECDHE_PSK_WITH_RC4_128_SHA           0xC033 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA      0xC034 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA       0xC035 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA       0xC036 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256    0xC037 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384    0xC038 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA              0xC039 /**< Weak! No SSL3! */
#define MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA256           0xC03A /**< Weak! No SSL3! */
#define MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA384           0xC03B /**< Weak! No SSL3! */

#define MBEDTLS_TLS_RSA_WITH_ARIA_128_CBC_SHA256         0xC03C /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_WITH_ARIA_256_CBC_SHA384         0xC03D /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256     0xC044 /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384     0xC045 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 0xC048 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 0xC049 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256  0xC04A /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384  0xC04B /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256   0xC04C /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384   0xC04D /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256    0xC04E /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384    0xC04F /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_WITH_ARIA_128_GCM_SHA256         0xC050 /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_WITH_ARIA_256_GCM_SHA384         0xC051 /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256     0xC052 /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384     0xC053 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 0xC05C /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 0xC05D /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256  0xC05E /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384  0xC05F /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256   0xC060 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384   0xC061 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256    0xC062 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384    0xC063 /**< TLS 1.2 */
#define MBEDTLS_TLS_PSK_WITH_ARIA_128_CBC_SHA256         0xC064 /**< TLS 1.2 */
#define MBEDTLS_TLS_PSK_WITH_ARIA_256_CBC_SHA384         0xC065 /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256     0xC066 /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384     0xC067 /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256     0xC068 /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384     0xC069 /**< TLS 1.2 */
#define MBEDTLS_TLS_PSK_WITH_ARIA_128_GCM_SHA256         0xC06A /**< TLS 1.2 */
#define MBEDTLS_TLS_PSK_WITH_ARIA_256_GCM_SHA384         0xC06B /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256     0xC06C /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384     0xC06D /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256     0xC06E /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384     0xC06F /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256   0xC070 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384   0xC071 /**< TLS 1.2 */

#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 0xC072 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 0xC073 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  0xC074 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  0xC075 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256   0xC076 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384   0xC077 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256    0xC078 /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384    0xC079 /**< Not in SSL3! */

#define MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256         0xC07A /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384         0xC07B /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256     0xC07C /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384     0xC07D /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 0xC086 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 0xC087 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256  0xC088 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384  0xC089 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256   0xC08A /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384   0xC08B /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256    0xC08C /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384    0xC08D /**< TLS 1.2 */

#define MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256       0xC08E /**< TLS 1.2 */
#define MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384       0xC08F /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256   0xC090 /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384   0xC091 /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256   0xC092 /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384   0xC093 /**< TLS 1.2 */

#define MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256       0xC094
#define MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384       0xC095
#define MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256   0xC096
#define MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384   0xC097
#define MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256   0xC098
#define MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384   0xC099
#define MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 0xC09A /**< Not in SSL3! */
#define MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 0xC09B /**< Not in SSL3! */

#define MBEDTLS_TLS_RSA_WITH_AES_128_CCM                0xC09C  /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_WITH_AES_256_CCM                0xC09D  /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM            0xC09E  /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM            0xC09F  /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_WITH_AES_128_CCM_8              0xC0A0  /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_WITH_AES_256_CCM_8              0xC0A1  /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8          0xC0A2  /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8          0xC0A3  /**< TLS 1.2 */
#define MBEDTLS_TLS_PSK_WITH_AES_128_CCM                0xC0A4  /**< TLS 1.2 */
#define MBEDTLS_TLS_PSK_WITH_AES_256_CCM                0xC0A5  /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM            0xC0A6  /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM            0xC0A7  /**< TLS 1.2 */
#define MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8              0xC0A8  /**< TLS 1.2 */
#define MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8              0xC0A9  /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM_8          0xC0AA  /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM_8          0xC0AB  /**< TLS 1.2 */
/* The last two are named with PSK_DHE in the RFC, which looks like a typo */

#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM        0xC0AC  /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM        0xC0AD  /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8      0xC0AE  /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8      0xC0AF  /**< TLS 1.2 */

#define MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8          0xC0FF  /**< experimental */

/* RFC 7905 */
#define MBEDTLS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   0xCCA8 /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 0xCCA9 /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     0xCCAA /**< TLS 1.2 */
#define MBEDTLS_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         0xCCAB /**< TLS 1.2 */
#define MBEDTLS_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   0xCCAC /**< TLS 1.2 */
#define MBEDTLS_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     0xCCAD /**< TLS 1.2 */
#define MBEDTLS_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256     0xCCAE /**< TLS 1.2 */

/* Reminder: update mbedtls_ssl_premaster_secret when adding a new key exchange.
 * Reminder: update MBEDTLS_KEY_EXCHANGE__xxx below
 */
typedef enum {
    MBEDTLS_KEY_EXCHANGE_NONE = 0,
    MBEDTLS_KEY_EXCHANGE_RSA,
    MBEDTLS_KEY_EXCHANGE_DHE_RSA,
    MBEDTLS_KEY_EXCHANGE_ECDHE_RSA,
    MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA,
    MBEDTLS_KEY_EXCHANGE_PSK,
    MBEDTLS_KEY_EXCHANGE_DHE_PSK,
    MBEDTLS_KEY_EXCHANGE_RSA_PSK,
    MBEDTLS_KEY_EXCHANGE_ECDHE_PSK,
    MBEDTLS_KEY_EXCHANGE_ECDH_RSA,
    MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA,
    MBEDTLS_KEY_EXCHANGE_ECJPAKE,
} mbedtls_key_exchange_type_t;

typedef struct mbedtls_ssl_ciphersuite_t mbedtls_ssl_ciphersuite_t;

#define MBEDTLS_CIPHERSUITE_WEAK       0x01    /**< Weak ciphersuite flag  */
#define MBEDTLS_CIPHERSUITE_SHORT_TAG  0x02    /**< Short authentication tag,
                                                     eg for CCM_8 */
#define MBEDTLS_CIPHERSUITE_NODTLS     0x04    /**< Can't be used with DTLS */

/*
 * Ciphersuite macro definitions
 *
 * This is highly incomplete and only contains those ciphersuites for
 * which we need to be able to build the library with support for that
 * ciphersuite only (currently MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
 * as an example).
 */

#define MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8_ID              MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
#define MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8_NAME            "TLS-ECDHE-ECDSA-WITH-AES-128-CCM-8"
#define MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8_CIPHER          MBEDTLS_CIPHER_AES_128_CCM
#define MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8_MAC             MBEDTLS_MD_SHA256
#define MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8_KEY_EXCHANGE    MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA
#define MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8_MIN_MAJOR_VER   MBEDTLS_SSL_MAJOR_VERSION_3
#define MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8_MIN_MINOR_VER   MBEDTLS_SSL_MINOR_VERSION_3
#define MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8_MAX_MAJOR_VER   MBEDTLS_SSL_MAJOR_VERSION_3
#define MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8_MAX_MINOR_VER   MBEDTLS_SSL_MINOR_VERSION_3
#define MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8_FLAGS           MBEDTLS_CIPHERSUITE_SHORT_TAG

/* This is just to make check-names.sh happy -- don't uncomment. */
//#define MBEDTLS_SUITE_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8

/*
 * Helper macros to extract fields from ciphersuites.
 */

#define MBEDTLS_SSL_SUITE_ID_T(            SUITE ) SUITE ## _ID
#define MBEDTLS_SSL_SUITE_NAME_T(          SUITE ) SUITE ## _NAME
#define MBEDTLS_SSL_SUITE_CIPHER_T(        SUITE ) SUITE ## _CIPHER
#define MBEDTLS_SSL_SUITE_MAC_T(           SUITE ) SUITE ## _MAC
#define MBEDTLS_SSL_SUITE_KEY_EXCHANGE_T(  SUITE ) SUITE ## _KEY_EXCHANGE
#define MBEDTLS_SSL_SUITE_MIN_MAJOR_VER_T( SUITE ) SUITE ## _MIN_MAJOR_VER
#define MBEDTLS_SSL_SUITE_MIN_MINOR_VER_T( SUITE ) SUITE ## _MIN_MINOR_VER
#define MBEDTLS_SSL_SUITE_MAX_MAJOR_VER_T( SUITE ) SUITE ## _MAX_MAJOR_VER
#define MBEDTLS_SSL_SUITE_MAX_MINOR_VER_T( SUITE ) SUITE ## _MAX_MINOR_VER
#define MBEDTLS_SSL_SUITE_FLAGS_T(         SUITE ) SUITE ## _FLAGS

/* Wrapper around MBEDTLS_SSL_SUITE_XXX_T() which makes sure that
 * the argument is macro-expanded before concatenated with the
 * field name. This allows to call these macros as
 *    MBEDTLS_SSL_SUITE_XXX( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE ),
 * where MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE expands to MBEDTLS_SSL_SUITE_XXX. */
#define MBEDTLS_SSL_SUITE_ID(            SUITE ) MBEDTLS_SSL_SUITE_ID_T(            SUITE )
#define MBEDTLS_SSL_SUITE_NAME(          SUITE ) MBEDTLS_SSL_SUITE_NAME_T(          SUITE )
#define MBEDTLS_SSL_SUITE_CIPHER(        SUITE ) MBEDTLS_SSL_SUITE_CIPHER_T(        SUITE )
#define MBEDTLS_SSL_SUITE_MAC(           SUITE ) MBEDTLS_SSL_SUITE_MAC_T(           SUITE )
#define MBEDTLS_SSL_SUITE_KEY_EXCHANGE(  SUITE ) MBEDTLS_SSL_SUITE_KEY_EXCHANGE_T(  SUITE )
#define MBEDTLS_SSL_SUITE_MIN_MAJOR_VER( SUITE ) MBEDTLS_SSL_SUITE_MIN_MAJOR_VER_T( SUITE )
#define MBEDTLS_SSL_SUITE_MIN_MINOR_VER( SUITE ) MBEDTLS_SSL_SUITE_MIN_MINOR_VER_T( SUITE )
#define MBEDTLS_SSL_SUITE_MAX_MAJOR_VER( SUITE ) MBEDTLS_SSL_SUITE_MAX_MAJOR_VER_T( SUITE )
#define MBEDTLS_SSL_SUITE_MAX_MINOR_VER( SUITE ) MBEDTLS_SSL_SUITE_MAX_MINOR_VER_T( SUITE )
#define MBEDTLS_SSL_SUITE_FLAGS(         SUITE ) MBEDTLS_SSL_SUITE_FLAGS_T(         SUITE )

#if !defined(MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE)
/**
 * \brief   This structure is used for storing ciphersuite information
 */
struct mbedtls_ssl_ciphersuite_t
{
    int id;
    const char * name;

    mbedtls_cipher_type_t cipher;
    mbedtls_md_type_t mac;
    mbedtls_key_exchange_type_t key_exchange;

    int min_major_ver;
    int min_minor_ver;
    int max_major_ver;
    int max_minor_ver;

    unsigned char flags;
};

typedef mbedtls_ssl_ciphersuite_t const * mbedtls_ssl_ciphersuite_handle_t;
#define MBEDTLS_SSL_CIPHERSUITE_INVALID_HANDLE ( (mbedtls_ssl_ciphersuite_handle_t) NULL )

/**
 * \brief   This macro builds an instance of ::mbedtls_ssl_ciphersuite_t
 *          from an \c MBEDTLS_SUITE_XXX identifier.
 */
#define MBEDTLS_SSL_SUITE_INFO( SUITE )           \
    { MBEDTLS_SSL_SUITE_ID( SUITE ),              \
      MBEDTLS_SSL_SUITE_NAME( SUITE ),            \
      MBEDTLS_SSL_SUITE_CIPHER( SUITE ),          \
      MBEDTLS_SSL_SUITE_MAC( SUITE ),             \
      MBEDTLS_SSL_SUITE_KEY_EXCHANGE(  SUITE ),   \
      MBEDTLS_SSL_SUITE_MIN_MAJOR_VER( SUITE ),   \
      MBEDTLS_SSL_SUITE_MIN_MINOR_VER( SUITE ),   \
      MBEDTLS_SSL_SUITE_MAX_MAJOR_VER( SUITE ),   \
      MBEDTLS_SSL_SUITE_MAX_MINOR_VER( SUITE ),   \
      MBEDTLS_SSL_SUITE_FLAGS( SUITE ) }

#else /* !MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE */

typedef unsigned char mbedtls_ssl_ciphersuite_handle_t;
#define MBEDTLS_SSL_CIPHERSUITE_INVALID_HANDLE      ( (mbedtls_ssl_ciphersuite_handle_t) 0 )
#define MBEDTLS_SSL_CIPHERSUITE_UNIQUE_VALID_HANDLE ( (mbedtls_ssl_ciphersuite_handle_t) 1 )

#endif /* MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE */

#if !defined(MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE)
static inline int mbedtls_ssl_session_get_ciphersuite(
    mbedtls_ssl_session const * session )
{
    return( session->ciphersuite );
}
#else /* !MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE */
static inline int mbedtls_ssl_session_get_ciphersuite(
    mbedtls_ssl_session const * session )
{
    ((void) session);
    return( MBEDTLS_SSL_SUITE_ID( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE ) );
}
#endif /* MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE */

/*
 * Getter functions for the extraction of ciphersuite attributes
 * from a ciphersuite handle.
 *
 * Warning: These functions have the validity of the handle as a precondition!
 * Their behaviour is undefined when MBEDTLS_SSL_CIPHERSUITE_INVALID_HANDLE
 * is passed.
 */

#if !defined(MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE)
/*
 * Implementation of getter functions when the ciphersuite handle
 * is a pointer to the ciphersuite information structure.
 *
 * The precondition that the handle is valid means that
 * we don't need to check that info != NULL.
 */
static inline int mbedtls_ssl_suite_get_id(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    return( info->id );
}
static inline const char* mbedtls_ssl_suite_get_name(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    return( info->name );
}
static inline mbedtls_cipher_type_t mbedtls_ssl_suite_get_cipher(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    return( info->cipher );
}
static inline mbedtls_md_type_t mbedtls_ssl_suite_get_mac(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    return( info->mac );
}
static inline mbedtls_key_exchange_type_t mbedtls_ssl_suite_get_key_exchange(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    return( info->key_exchange );
}
static inline int mbedtls_ssl_suite_get_min_major_ver(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    return( info->min_major_ver );
}
static inline int mbedtls_ssl_suite_get_min_minor_ver(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    return( info->min_minor_ver );
}
static inline int mbedtls_ssl_suite_get_max_major_ver(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    return( info->max_major_ver );
}
static inline int mbedtls_ssl_suite_get_max_minor_ver(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    return( info->max_minor_ver );
}
static inline unsigned char mbedtls_ssl_suite_get_flags(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    return( info->flags );
}
#else /* !MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE */
/*
 * Implementations of getter functions in the case of only a single possible
 * ciphersuite. In this case, the handle is logically a boolean (either the
 * invalid handle or the unique valid handle representing the single enabled
 * ciphersuite), and the precondition that the handle is valid means that we
 * can statically return the hardcoded attribute of the enabled ciphersuite.
 */
static inline int mbedtls_ssl_suite_get_id(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    ((void) info);
    return( MBEDTLS_SSL_SUITE_ID( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE ) );
}
static inline const char* mbedtls_ssl_suite_get_name(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    ((void) info);
    return( MBEDTLS_SSL_SUITE_NAME( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE ) );
}
static inline mbedtls_cipher_type_t mbedtls_ssl_suite_get_cipher(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    ((void) info);
    return( MBEDTLS_SSL_SUITE_CIPHER( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE ) );
}
static inline mbedtls_md_type_t mbedtls_ssl_suite_get_mac(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    ((void) info);
    return( MBEDTLS_SSL_SUITE_MAC( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE ) );
}
static inline mbedtls_key_exchange_type_t mbedtls_ssl_suite_get_key_exchange(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    ((void) info);
    return( MBEDTLS_SSL_SUITE_KEY_EXCHANGE( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE ) );
}
static inline int mbedtls_ssl_suite_get_min_major_ver(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    ((void) info);
    return( MBEDTLS_SSL_SUITE_MIN_MAJOR_VER( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE ) );
}
static inline int mbedtls_ssl_suite_get_min_minor_ver(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    ((void) info);
    return( MBEDTLS_SSL_SUITE_MIN_MINOR_VER( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE ) );
}
static inline int mbedtls_ssl_suite_get_max_major_ver(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    ((void) info);
    return( MBEDTLS_SSL_SUITE_MAX_MAJOR_VER( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE ) );
}
static inline int mbedtls_ssl_suite_get_max_minor_ver(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    ((void) info);
    return( MBEDTLS_SSL_SUITE_MAX_MINOR_VER( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE ) );
}
static inline unsigned char mbedtls_ssl_suite_get_flags(
    mbedtls_ssl_ciphersuite_handle_t const info )
{
    ((void) info);
    return( MBEDTLS_SSL_SUITE_FLAGS( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE ) );
}
#endif /* MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE */

const int *mbedtls_ssl_list_ciphersuites( void );

/*
 * Various small helper functions for ciphersuites.
 *
 * Like the getter functions, they assume that the provided ciphersuite
 * handle is valid, and hence can be optimized in case there's only one
 * ciphersuite enabled.
 *
 * To avoid code-duplication between inline and non-inline implementations
 * of this, we define internal static inline versions of all functions first,
 * and define wrappers around these either here or in ssl_ciphersuites.c,
 * depending on whether MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE is defined.
 */

#if defined(MBEDTLS_PK_C)
static inline mbedtls_pk_type_t mbedtls_ssl_get_ciphersuite_sig_pk_alg_internal(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    switch( mbedtls_ssl_suite_get_key_exchange( info ) )
    {
        case MBEDTLS_KEY_EXCHANGE_RSA:
        case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
            return( MBEDTLS_PK_RSA );

        case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
            return( MBEDTLS_PK_ECDSA );

        case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
            return( MBEDTLS_PK_ECKEY );

        default:
            return( MBEDTLS_PK_NONE );
    }
}

static inline mbedtls_pk_type_t mbedtls_ssl_get_ciphersuite_sig_alg_internal(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    switch( mbedtls_ssl_suite_get_key_exchange( info ) )
    {
        case MBEDTLS_KEY_EXCHANGE_RSA:
        case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
            return( MBEDTLS_PK_RSA );

        case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
            return( MBEDTLS_PK_ECDSA );

        default:
            return( MBEDTLS_PK_NONE );
    }
}

#endif /* MBEDTLS_PK_C */

#if defined(MBEDTLS_USE_TINYCRYPT) ||                           \
    defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) ||      \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static inline int mbedtls_ssl_ciphersuite_uses_ec_internal(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    switch( mbedtls_ssl_suite_get_key_exchange( info ) )
    {
        case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
        case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
        case MBEDTLS_KEY_EXCHANGE_ECJPAKE:
            return( 1 );

        default:
            return( 0 );
    }
}
#endif /* MBEDTLS_USE_TINYCRYPT ||
          MBEDTLS_ECDH_C        ||
          MBEDTLS_ECDSA_C       ||
          MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
static inline int mbedtls_ssl_ciphersuite_uses_psk_internal(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    switch( mbedtls_ssl_suite_get_key_exchange( info ) )
    {
        case MBEDTLS_KEY_EXCHANGE_PSK:
        case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
        case MBEDTLS_KEY_EXCHANGE_DHE_PSK:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
            return( 1 );

        default:
            return( 0 );
    }
}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

/*
 * Wrappers around internal helper functions to be used by the rest of
 * the library, either defined static inline here or in ssl_ciphersuites.c.
 */

#if !defined(MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE)

mbedtls_ssl_ciphersuite_handle_t mbedtls_ssl_ciphersuite_from_string(
    const char *ciphersuite_name );
mbedtls_ssl_ciphersuite_handle_t mbedtls_ssl_ciphersuite_from_id(
    int ciphersuite_id );

#if defined(MBEDTLS_PK_C)
mbedtls_pk_type_t mbedtls_ssl_get_ciphersuite_sig_pk_alg(
    mbedtls_ssl_ciphersuite_handle_t info );
mbedtls_pk_type_t mbedtls_ssl_get_ciphersuite_sig_alg(
    mbedtls_ssl_ciphersuite_handle_t info );
#endif /* MBEDTLS_PK_C */

#if defined(MBEDTLS_USE_TINYCRYPT) ||                           \
    defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) ||      \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
int mbedtls_ssl_ciphersuite_uses_ec( mbedtls_ssl_ciphersuite_handle_t info );
#endif /* MBEDTLS_USE_TINYCRYPT ||
          MBEDTLS_ECDH_C        ||
          MBEDTLS_ECDSA_C       ||
          MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int mbedtls_ssl_ciphersuite_uses_psk( mbedtls_ssl_ciphersuite_handle_t info );
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#else /* !MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE */

#if defined(MBEDTLS_PK_C)
static inline mbedtls_pk_type_t mbedtls_ssl_get_ciphersuite_sig_pk_alg(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    return( mbedtls_ssl_get_ciphersuite_sig_pk_alg_internal( info ) );
}

static inline mbedtls_pk_type_t mbedtls_ssl_get_ciphersuite_sig_alg(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    return( mbedtls_ssl_get_ciphersuite_sig_alg_internal( info ) );
}
#endif /* MBEDTLS_PK_C */

#if defined(MBEDTLS_USE_TINYCRYPT) ||                           \
    defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) ||      \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static inline int mbedtls_ssl_ciphersuite_uses_ec(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    return( mbedtls_ssl_ciphersuite_uses_ec_internal( info ) );
}
#endif /* MBEDTLS_USE_TINYCRYPT ||
          MBEDTLS_ECDH_C        ||
          MBEDTLS_ECDSA_C       ||
          MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
static inline int mbedtls_ssl_ciphersuite_uses_psk(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    return( mbedtls_ssl_ciphersuite_uses_psk_internal( info ) );
}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

static inline mbedtls_ssl_ciphersuite_handle_t mbedtls_ssl_ciphersuite_from_id(
    int ciphersuite )
{
    static const int single_suite_id =
        MBEDTLS_SSL_SUITE_ID( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE );

    if( ciphersuite == single_suite_id )
        return( MBEDTLS_SSL_CIPHERSUITE_UNIQUE_VALID_HANDLE );

    return( MBEDTLS_SSL_CIPHERSUITE_INVALID_HANDLE );
}

static inline mbedtls_ssl_ciphersuite_handle_t mbedtls_ssl_ciphersuite_from_string(
                                                const char *ciphersuite_name )
{
    static const char * const single_suite_name =
        MBEDTLS_SSL_SUITE_NAME( MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE );

    if( strcmp( ciphersuite_name, single_suite_name ) == 0 )
        return( MBEDTLS_SSL_CIPHERSUITE_UNIQUE_VALID_HANDLE );

    return( MBEDTLS_SSL_CIPHERSUITE_INVALID_HANDLE );
}

#endif /* MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE */

static inline int mbedtls_ssl_ciphersuite_has_pfs(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    switch( mbedtls_ssl_suite_get_key_exchange( info ) )
    {
        case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_DHE_PSK:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
        case MBEDTLS_KEY_EXCHANGE_ECJPAKE:
            return( 1 );

        default:
            return( 0 );
    }
}

static inline int mbedtls_ssl_ciphersuite_no_pfs(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    switch( mbedtls_ssl_suite_get_key_exchange( info ) )
    {
        case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
        case MBEDTLS_KEY_EXCHANGE_RSA:
        case MBEDTLS_KEY_EXCHANGE_PSK:
        case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
            return( 1 );

        default:
            return( 0 );
    }
}


static inline int mbedtls_ssl_ciphersuite_uses_ecdh(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    switch( mbedtls_ssl_suite_get_key_exchange( info ) )
    {
        case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
            return( 1 );

        default:
            return( 0 );
    }
}

static inline int mbedtls_ssl_ciphersuite_cert_req_allowed(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    switch( mbedtls_ssl_suite_get_key_exchange( info ) )
    {
        case MBEDTLS_KEY_EXCHANGE_RSA:
        case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
            return( 1 );

        default:
            return( 0 );
    }
}

static inline int mbedtls_ssl_ciphersuite_uses_srv_cert(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    switch( mbedtls_ssl_suite_get_key_exchange( info ) )
    {
        case MBEDTLS_KEY_EXCHANGE_RSA:
        case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
        case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
            return( 1 );

        default:
            return( 0 );
    }
}

static inline int mbedtls_ssl_ciphersuite_uses_dhe(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    switch( mbedtls_ssl_suite_get_key_exchange( info ) )
    {
        case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_DHE_PSK:
            return( 1 );

        default:
            return( 0 );
    }
}

static inline int mbedtls_ssl_ciphersuite_uses_ecdhe(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    switch( mbedtls_ssl_suite_get_key_exchange( info ) )
    {
        case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
            return( 1 );

        default:
            return( 0 );
    }
}

static inline int mbedtls_ssl_ciphersuite_uses_server_signature(
    mbedtls_ssl_ciphersuite_handle_t info )
{
    switch( mbedtls_ssl_suite_get_key_exchange( info ) )
    {
        case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
        case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
            return( 1 );

        default:
            return( 0 );
    }
}

#ifdef __cplusplus
}
#endif

#endif /* ssl_ciphersuites.h */
