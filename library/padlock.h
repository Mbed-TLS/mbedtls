/**
 * \file padlock.h
 *
 * \brief VIA PadLock ACE for HW encryption/decryption supported by some
 *        processors
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
#ifndef MBEDTLS_PADLOCK_H
#define MBEDTLS_PADLOCK_H

#include "mbedtls/build_info.h"

#include "mbedtls/aes.h"

#include "cpuid_internal.h"

#define MBEDTLS_ERR_PADLOCK_DATA_MISALIGNED               -0x0030  /**< Input data should be aligned. */

#if defined(MBEDTLS_VIA_PADLOCK_HAVE_CODE)

#include <stdint.h>

#define MBEDTLS_PADLOCK_RNG 0x000C
#define MBEDTLS_PADLOCK_ACE 0x00C0
#define MBEDTLS_PADLOCK_PHE 0x0C00
#define MBEDTLS_PADLOCK_PMM 0x3000

#define MBEDTLS_PADLOCK_ALIGN16(x) (uint32_t *) (16 + ((int32_t) (x) & ~15))

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_AES_CPUID_HAVE_CODE)

#define MBEDTLS_PADLOCK_HAS_SUPPORT() \
    mbedtls_cpu_has_support(MBEDTLS_HWCAP_PADLOCK_ACE)
#else /* MBEDTLS_AES_CPUID_HAVE_CODE */

#define MBEDTLS_PADLOCK_HAS_SUPPORT() 1

#endif /* !MBEDTLS_AES_CPUID_HAVE_CODE */

/**
 * \brief          Internal PadLock AES-ECB block en(de)cryption
 *
 * \note           This function is only for internal use by other library
 *                 functions; you must not call it directly.
 *
 * \param ctx      AES context
 * \param mode     MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 if success, 1 if operation failed
 */
int mbedtls_padlock_xcryptecb(mbedtls_aes_context *ctx,
                              int mode,
                              const unsigned char input[16],
                              unsigned char output[16]);

/**
 * \brief          Internal PadLock AES-CBC buffer en(de)cryption
 *
 * \note           This function is only for internal use by other library
 *                 functions; you must not call it directly.
 *
 * \param ctx      AES context
 * \param mode     MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if success, 1 if operation failed
 */
int mbedtls_padlock_xcryptcbc(mbedtls_aes_context *ctx,
                              int mode,
                              size_t length,
                              unsigned char iv[16],
                              const unsigned char *input,
                              unsigned char *output);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_VIA_PADLOCK_HAVE_CODE  */

#endif /* padlock.h */
