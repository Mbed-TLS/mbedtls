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
#if !defined(MBEDTLS_CPUID_H)
#define MBEDTLS_CPUID_H

#include <stdbool.h>
#include <stdint.h>
#include "mbedtls/build_info.h"


/* CPU features bit mask definitions for aarch64
 *
 * That follows up [`hwcap.h`](https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/hwcap.h)
 * to reduce down code size of runtime detection module.
 */
#define MBEDTLS_HWCAP_ASIMD     (1ULL <<  1)
#define MBEDTLS_HWCAP_AES       (1ULL <<  3)
#define MBEDTLS_HWCAP_PMULL     (1ULL <<  4)
#define MBEDTLS_HWCAP_SHA2      (1ULL <<  6)
#define MBEDTLS_HWCAP_SHA512    (1ULL << 21)

/* CPU features bit mask definitions for i386/x86_64
 *
 * The lower 32bits follow up https://en.wikipedia.org/wiki/CPUID to reduce code
 * size. VIA Padlock ACE needs different instructions, it is put in high 32bits.
 */
#define MBEDTLS_HWCAP_AESNI_AES         (1ULL <<  25)
#define MBEDTLS_HWCAP_AESNI_CLMUL       (1ULL <<   1)
#define MBEDTLS_HWCAP_PADLOCK_ACE       (1ULL <<  32)


typedef uint64_t mbedtls_hwcap_mask_t;
/**
 * \brief Get CPU feature sets.
 *
 * \return Bit mask of CPU feature sets.
 *
 * \note We only define the CPU features that are used in MbedTLS.
 *
 * \note When only one CPU accelerator or only plain C enabled for target plat-
 *       form and algorithm, this function won't be called. It can be
 *       replaced with extenal function when \c MBEDTLS_CPUID_GET_ALT
 *       enabled.
 *
 *       When built-in implementation does not support target platform, please
 *       provide extenal implementation or adjust config options to disable CPU
 *       features detection.
 *       Built-in function has support for i386, x86_64, aarch64 Linux, aarch64
 *       FreeBSD and Darwin on Apple Silicon.
 */
mbedtls_hwcap_mask_t mbedtls_cpuid_get(void);

#endif /* MBEDTLS_CPUID_H */
