/*
 *  Constants and prototype of alternative runtime detection function for core
 *  CPU feature sets.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 ( the "License" ); you may
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
#if !defined(MBEDTLS_RUNTIME_H)
#define MBEDTLS_RUNTIME_H

#include <stdbool.h>
#include <stdint.h>
#include "mbedtls/build_info.h"

/* Reserverd by internal runtime detection module to check if cpu features have
 * been profiled. */
#define MBEDTLS_HWCAP_PROFILED  (1ULL << 63)

#if defined(MBEDTLS_ARCH_IS_ARM64)

/* The bit mask definitions follow up [`hwcap.h`](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/hwcap.h)
 * to reduce down code size of runtime detection module.
 */
#define MBEDTLS_HWCAP_ASIMD     (1ULL <<  1)
#define MBEDTLS_HWCAP_AES       (1ULL <<  3)
#define MBEDTLS_HWCAP_PMULL     (1ULL <<  4)
#define MBEDTLS_HWCAP_SHA2      (1ULL <<  6)
#define MBEDTLS_HWCAP_SHA512    (1ULL << 21)

#endif /* MBEDTLS_ARCH_IS_ARM64 */

#if defined(MBEDTLS_ARCH_IS_X64) || defined(MBEDTLS_ARCH_IS_X86)
/* The lower 32bits follow up https://en.wikipedia.org/wiki/CPUID to reduce code
 * size. VIA Padlock ACE needs different instructions, it is put in high 32bits.
 */
#define MBEDTLS_HWCAP_AESNI_AES         (1ULL <<  25)
#define MBEDTLS_HWCAP_AESNI_CLMUL       (1ULL <<   1)
#define MBEDTLS_HWCAP_PADLOCK_ACE       (1ULL <<  32)

#endif /* MBEDTLS_ARCH_IS_X64 || MBEDTLS_ARCH_IS_X86 */

typedef uint64_t mbedtls_hwcap_mask_t;
/**
 * \brief Definition of core CPU feature sets detection on x64/i386.
 *
 * \param hwcap  Bit mask of request feature sets. `MBEDTLS_HWCAP_*` are
 *               valid bit masks
 *
 * \return true if the request fetature sets available.
 *
 * \note We only define the features that are used in MbedTLS.
 *
 * \note When only one CPU accelerator or only plain C enabled for target plat-
 *       form and algorithm, this function won't be compiled. It will be
 *       replaced with extenal function when \c MBEDTLS_CPU_HAS_FEATURES_ALT
 *       enabled.
 *
 *       When built-in implementation does not support target platform, please
 *       provide extenal implementation or adjust config options to disable run-
 *       time detection.
 *       Built-in function has supported i386,x86_64, arm64 linux,arm64 freebsd
 *       and arm64 apple os.
 */
bool mbedtls_cpu_has_features(mbedtls_hwcap_mask_t hwcap);

#endif /* MBEDTLS_RUNTIME_H */
