/**
 * \file sha256ce.h
 *
 * \brief SHA256-CE for hardware SHA256 acceleration on some ARM processors
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
#ifndef MBEDTLS_SHA256CE_H
#define MBEDTLS_SHA256CE_H

#include "sha256.h"

#define MBEDTLS_SHA256CE_SHA2      1

#if defined(MBEDTLS_HAVE_ASM) && defined(__GNUC__) &&  \
    defined(__aarch64__)   &&  \
    ! defined(MBEDTLS_HAVE_AARCH64)
#define MBEDTLS_HAVE_AARCH64
#endif

#if defined(MBEDTLS_HAVE_AARCH64)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SHA256-CE features detection routine
 *
 * \param what     The features to detect.
 *
 * \return         1 if CPU has support for all features, 0 otherwise
 */
int mbedtls_sha256ce_has_support( unsigned int what );

/* Internal use */
void mbedtls_sha256ce_process( mbedtls_sha256_context *ctx, const unsigned char data[64] );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_HAVE_AARCH64 */

#endif /* MBEDTLS_SHA256CE_H */
