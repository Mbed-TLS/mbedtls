/*
 *  Internal runtime detection macros and funtions
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
#if !defined(MBEDTLS_CPUID_INTERNAL_H)
#define MBEDTLS_CPUID_INTERNAL_H

#include <mbedtls/cpuid.h>

#if !defined(MBEDTLS_CPUID_GET_ALT)

#if defined(MBEDTLS_ARCH_IS_ARM64)

#if defined(__linux__) || \
    (defined(__FreeBSD__) && __FreeBSD_version >= 1200000) || \
    defined(_WIN64) || \
    defined(__APPLE__)
#define MBEDTLS_CPUID_C
#endif

#endif

#if defined(MBEDTLS_ARCH_IS_X64) || defined(MBEDTLS_ARCH_IS_X86)
#define MBEDTLS_CPUID_C
#endif

#endif /* !MBEDTLS_CPUID_GET_ALT */

/* Check if AES module needs runtime detection */
#if defined(MBEDTLS_AES_C)
#if !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
#define MBEDTLS_AES_HAVE_PLAIN_C 1
#else
#define MBEDTLS_AES_HAVE_PLAIN_C 0
#endif

#if defined(MBEDTLS_AESNI_C) && \
    (defined(MBEDTLS_ARCH_IS_X64) || defined(MBEDTLS_ARCH_IS_X86))
#define MBEDTLS_AESNI_HAVE_CODE 1
#endif

#if defined(MBEDTLS_PADLOCK_C) && defined(MBEDTLS_ARCH_IS_X86)
#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define MBEDTLS_HAVE_ASAN
#endif
#endif
#if !(defined(MBEDTLS_HAVE_ASAN)) && \
    defined(__GNUC__) && defined(MBEDTLS_HAVE_ASM)
/*
 * - `padlock` is implements with GNUC assembly for x86 target.
 * - Some versions of ASan result in errors about not enough registers.
 */
#define MBEDTLS_VIA_PADLOCK_HAVE_CODE 1
#endif
#endif

#if defined(MBEDTLS_AESCE_C) && defined(MBEDTLS_ARCH_IS_ARM64)
#define MBEDTLS_AESCE_HAVE_CODE 1
#endif

#define MBEDTLS_AES_ACCELERATOR_NUM \
    (MBEDTLS_AES_HAVE_PLAIN_C + MBEDTLS_AESNI_HAVE_CODE + \
     MBEDTLS_VIA_PADLOCK_HAVE_CODE + MBEDTLS_AESCE_HAVE_CODE)

#if MBEDTLS_AES_ACCELERATOR_NUM == 0
#error "AES implementation is not available"
#elif MBEDTLS_AES_ACCELERATOR_NUM > 1
#define MBEDTLS_AES_CPUID_HAVE_CODE
#endif

#undef MBEDTLS_AES_HAVE_PLAIN_C
#undef MBEDTLS_AES_ACCELERATOR_NUM
#endif /* MBEDTLS_AES_C */

#if !(defined(MBEDTLS_CPUID_C) || defined(MBEDTLS_CPUID_GET_ALT)) && \
    defined(MBEDTLS_AES_CPUID_HAVE_CODE)
#error "CPU identify module is needed but not provided."
#endif

#define MBEDTLS_HWCAP_PROFILED  (1ULL << 63)
extern mbedtls_hwcap_mask_t mbedtls_cpu_hwcaps;
static inline bool mbedtls_cpu_has_support(mbedtls_hwcap_mask_t mask)
{
    if (mbedtls_cpu_hwcaps == 0) {
        mbedtls_cpu_hwcaps = mbedtls_cpuid_get() | MBEDTLS_HWCAP_PROFILED;
    }
    return (mbedtls_cpu_hwcaps & mask) == mask;
}

#endif /* MBEDTLS_CPUID_INTERNAL_H */
