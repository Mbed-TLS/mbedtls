/**
 * \file armv8a_ce.h
 *
 * \brief Compile and runtime checks for ARM features to accelerate crypto
 *
 *  Copyright (C) 2016, CriticalBlue Limited, All Rights Reserved
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

/*
 * Include this file at the start of the header for any ARMv8-A specific module
 */

#ifndef MBEDTLS_ARMV8A_CE_H
#define MBEDTLS_ARMV8A_CE_H


/*
 * Set compile time flags for capabilities
 * Here we separate out the detection of the
 * optional cryptography extensions.
 *
 * To limit complexity we will only support
 * ARMv8, A profile, AArch64 code on Linux
 *
 * If the platform is suitable, then we define
 * MBEDTLS_HAVE_ARMV8A_CE which should then be
 * used whenever a platform test is required.
 */


#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) && __ARM_ARCH >= 8 && __ARM_ARCH_PROFILE == 'A' && defined(__aarch64__)  &&  defined(__ARM_FEATURE_CRYPTO) && ! defined(MBEDTLS_HAVE_ARMV8A_CE)

/* Platform supports ARMv8 cryptography extensions */
#define MBEDTLS_HAVE_ARMV8A_CE

#endif

#if defined MBEDTLS_HAVE_ARMV8A_CE && defined MBEDTLS_ARMV8A_CE_C

/* Ensure that constants and a detection function for ARMv8 cryptography extensions are defined */
#if !defined(MBEDTLS_PLATFORM_ARMV8A_CE_GET_HWCAP)

#if defined(linux)

/* Linux specific */
#include <sys/auxv.h>
#include <asm/hwcap.h>

#define MBEDTLS_ARMV8A_CE_SHA2	HWCAP_SHA2
#define MBEDTLS_ARMV8A_CE_SHA1	HWCAP_SHA1
#define MBEDTLS_ARMV8A_CE_AES	HWCAP_AES
#define MBEDTLS_ARMV8A_CE_PMULL HWCAP_PMULL

#define MBEDTLS_PLATFORM_ARMV8A_CE_GET_HWCAP mbedtls_platform_linux_armv8a_ce_get_hwcap

unsigned long mbedtls_platform_linux_armv8a_ce_get_hwcap(void);

#else /* linux */

/* Other platforms: Assume no ARMv8 cryptography extensions */
#define MBEDTLS_ARMV8A_CE_SHA2	0
#define MBEDTLS_ARMV8A_CE_SHA1	0
#define MBEDTLS_ARMV8A_CE_AES	0
#define MBEDTLS_ARMV8A_CE_PMULL 0

#define MBEDTLS_PLATFORM_ARMV8A_CE_GET_HWCAP mbedtls_platform_none_armv8a_ce_get_hwcap

unsigned long mbedtls_platform_none_armv8a_ce_get_hwcap(void);

#endif /* linux */

#else /* MBEDTLS_PLATFORM_ARMV8A_CE_GET_HWCAP */

/* Detection function for ARMv8 cryptography extensions is defined externally (e.g. in config.h).
 * Check that the relevant constants are also defined. */
#if !defined MBEDTLS_ARMV8A_CE_SHA2
#error MBEDTLS_PLATFORM_ARMV8A_CE_GET_HWCAP defined but MBEDTLS_ARMV8A_CE_SHA2 undefined
#endif
#if !defined MBEDTLS_ARMV8A_CE_SHA1
#error MBEDTLS_PLATFORM_ARMV8A_CE_GET_HWCAP defined but MBEDTLS_ARMV8A_CE_SHA1 undefined
#endif
#if !defined MBEDTLS_ARMV8A_CE_AES
#error MBEDTLS_PLATFORM_ARMV8A_CE_GET_HWCAP defined but MBEDTLS_ARMV8A_CE_AES undefined
#endif
#if !defined MBEDTLS_ARMV8A_CE_PMULL
#error MBEDTLS_PLATFORM_ARMV8A_CE_GET_HWCAP defined but MBEDTLS_ARMV8A_CE_PMULL undefined
#endif

#endif /* MBEDTLS_PLATFORM_ARMV8A_CE_GET_HWCAP */

/**
 * \brief          ARMv8-A features detection routine
 *
 * \param what     The feature to detect
 *                 (MBEDTLS_ARMV8A_CE_AES, MBEDTLS_ARMV8A_CE_PMULL,
 *                  MBEDTLS_ARMV8A_CE_SHA1 or MBEDTLS_ARMV8A_CE_SHA2)
 *
 * \return         1 if the CPU has support for the feature, 0 otherwise
 */
int mbedtls_armv8a_ce_has_support( unsigned int what );

#endif /* MBEDTLS_HAVE_ARMV8A_CE */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_ARMV8A_CE_H */
