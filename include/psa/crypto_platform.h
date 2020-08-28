/**
 * \file psa/crypto_platform.h
 *
 * \brief PSA cryptography module: Mbed TLS platform definitions
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file contains platform-dependent type definitions.
 *
 * In implementations with isolation between the application and the
 * cryptography module, implementers should take care to ensure that
 * the definitions that are exposed to applications match what the
 * module implements.
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

#ifndef PSA_CRYPTO_PLATFORM_H
#define PSA_CRYPTO_PLATFORM_H

/* Include the Mbed TLS configuration file, the way Mbed TLS does it
 * in each of its header files. */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/* PSA requires several types which C99 provides in stdint.h. */
#include <stdint.h>

/* Integral type representing a key handle. */
typedef uint16_t psa_key_handle_t;

#if defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)

#if defined(PSA_CRYPTO_SECURE)
/* Building for the PSA Crypto service on a PSA platform. */
/* A key owner is a PSA partition identifier. */
typedef int32_t mbedtls_key_owner_id_t;
#endif

#endif /* MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER */

#endif /* PSA_CRYPTO_PLATFORM_H */
