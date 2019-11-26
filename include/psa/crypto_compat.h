/**
 * \file psa/crypto_compat.h
 *
 * \brief PSA cryptography module: Backward compatibility aliases
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 */
/*
 *  Copyright (C) 2019, ARM Limited, All Rights Reserved
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

#ifndef PSA_CRYPTO_COMPAT_H
#define PSA_CRYPTO_COMPAT_H

#include "mbedtls/platform_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Deprecated PSA Crypto error code definitions
 */
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#define PSA_ERROR_UNKNOWN_ERROR \
    MBEDTLS_DEPRECATED_NUMERIC_CONSTANT( PSA_ERROR_GENERIC_ERROR )
#define PSA_ERROR_OCCUPIED_SLOT \
    MBEDTLS_DEPRECATED_NUMERIC_CONSTANT( PSA_ERROR_ALREADY_EXISTS )
#define PSA_ERROR_EMPTY_SLOT \
    MBEDTLS_DEPRECATED_NUMERIC_CONSTANT( PSA_ERROR_DOES_NOT_EXIST )
#define PSA_ERROR_INSUFFICIENT_CAPACITY \
    MBEDTLS_DEPRECATED_NUMERIC_CONSTANT( PSA_ERROR_INSUFFICIENT_DATA )
#define PSA_ERROR_TAMPERING_DETECTED \
    MBEDTLS_DEPRECATED_NUMERIC_CONSTANT( PSA_ERROR_CORRUPTION_DETECTED )
#endif

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_COMPAT_H */
