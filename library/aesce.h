/**
 * \file aesce.h
 *
 * \brief AES-CE for hardware AES acceleration on ARMv8 processors with crypto
 *        engine.
 *
 * \warning These functions are only for internal use by other library
 *          functions; you must not call them directly.
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
#ifndef MBEDTLS_AESCE_H
#define MBEDTLS_AESCE_H

#include "mbedtls/build_info.h"

#include "mbedtls/aes.h"


#if !defined(MBEDTLS_HAVE_ARM64) && \
    (defined(__aarch64__) || defined(_M_ARM64))
#define MBEDTLS_HAVE_ARM64
#endif

#if defined(MBEDTLS_HAVE_ARM64)

#ifdef __cplusplus
extern "C" {
#endif
#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_HAVE_ARM64 */

#endif /* MBEDTLS_AESCE_H */
