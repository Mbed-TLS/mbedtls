/*
 *  Common code for SSL test programs
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

#ifndef MBEDTLS_PROGRAMS_SSL_SSL_TEST_LIB_H
#define MBEDTLS_PROGRAMS_SSL_SSL_TEST_LIB_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif

#if !defined(MBEDTLS_CTR_DRBG_C) ||                         \
    !defined(MBEDTLS_ENTROPY_C) ||                          \
    !defined(MBEDTLS_NET_C) ||                              \
    !defined(MBEDTLS_SSL_TLS_C) ||                          \
    defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
#define MBEDTLS_SSL_TEST_IMPOSSIBLE                             \
    "MBEDTLS_CTR_DRBG_C and/or "                                \
    "MBEDTLS_ENTROPY_C and/or "                                 \
    "MBEDTLS_NET_C and/or "                                     \
    "MBEDTLS_SSL_TLS_C not defined, "                           \
    "and/or MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER defined.\n"
#else
#undef MBEDTLS_SSL_TEST_IMPOSSIBLE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"
#include "mbedtls/base64.h"

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#include "mbedtls/psa_util.h"
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#include <test/helpers.h>

#endif /* MBEDTLS_SSL_TEST_IMPOSSIBLE conditions: else */

#endif /* MBEDTLS_PROGRAMS_SSL_SSL_TEST_LIB_H */
