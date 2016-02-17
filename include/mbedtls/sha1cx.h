/**
 * \file sha1cx.h
 *
 * \brief SHA1-CX for hardware SHA1 acceleration on some ARM processors
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
#ifndef MBEDTLS_SHA1CX_H
#define MBEDTLS_SHA1CX_H

#include "sha1.h"

#define MBEDTLS_SHA1CX_SHA1      0x00000001u

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
 * \brief          SHA1-CX features detection routine
 *
 * \param what     The feature to detect.
 *
 * \return         1 if CPU has support for the feature, 0 otherwise
 */
int mbedtls_sha1cx_has_support( unsigned int what );

/* Internal use */
void mbedtls_sha1cx_process( mbedtls_sha1_context *ctx, const unsigned char data[64] );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_HAVE_AARCH64 */

#endif /* MBEDTLS_SHA1CX_H */
