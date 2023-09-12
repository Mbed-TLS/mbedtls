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
#if !defined(MBEDTLS_RUNTIME_INTERNAL_H)
#define MBEDTLS_RUNTIME_INTERNAL_H

#include <mbedtls/runtime.h>

#if !defined(MBEDTLS_CPU_HAS_FEATURES_ALT)

#if defined(MBEDTLS_ARCH_IS_ARM64)

#if defined(__linux__) || \
    (defined(__FreeBSD__) && __FreeBSD_version >= 1200000) || \
    defined(_WIN64) || \
    defined(__APPLE__)
#define MBEDTLS_RUNTIME_C
#endif

#endif

#if defined(MBEDTLS_ARCH_IS_X64) || defined(MBEDTLS_ARCH_IS_X86)
#define MBEDTLS_RUNTIME_C
#endif

#endif /* !MBEDTLS_CPU_HAS_FEATURES_ALT */

/* Check if AES module needs runtime detection */
#if defined(MBEDTLS_AES_C)
#if !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
#define MBEDTLS_AES_HAVE_PLAIN_C 1
#else
#define MBEDTLS_AES_HAVE_PLAIN_C 0
#endif

#if defined(MBEDTLS_AESNI_C) && \
    (defined(MBEDTLS_ARCH_IS_X64) || defined(MBEDTLS_ARCH_IS_X86))
#define MBEDTLS_AESNI_HAVE_CODE
#define MBEDTLS_AES_HAVE_AESNI 1
#else
#define MBEDTLS_AES_HAVE_AESNI 0
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
#define MBEDTLS_AES_HAVE_PADLOCK 1
#define MBEDTLS_VIA_PADLOCK_HAVE_CODE
#endif
#else
#define MBEDTLS_AES_HAVE_PADLOCK 0
#endif

#if defined(MBEDTLS_AESCE_C) && defined(MBEDTLS_ARCH_IS_ARM64)
#define MBEDTLS_AES_HAVE_AESCE 1
#define MBEDTLS_AESCE_HAVE_CODE
#else
#define MBEDTLS_AES_HAVE_AESCE 0
#endif

#define MBEDTLS_AES_ACCELERATOR_NUM \
    (MBEDTLS_AES_HAVE_PLAIN_C + MBEDTLS_AES_HAVE_AESNI + \
     MBEDTLS_AES_HAVE_PADLOCK + MBEDTLS_AES_HAVE_AESCE)

#if MBEDTLS_AES_ACCELERATOR_NUM == 0
#error "AES implementation is not available"
#elif MBEDTLS_AES_ACCELERATOR_NUM > 1
#define MBEDTLS_AES_RUNTIME_HAVE_CODE
#endif

#undef MBEDTLS_AES_HAVE_PLAIN_C
#undef MBEDTLS_AES_HAVE_AESNI
#undef MBEDTLS_AES_HAVE_AESCE
#undef MBEDTLS_AES_HAVE_PADLOCK
#undef MBEDTLS_AES_ACCELERATOR_NUM
#endif /* MBEDTLS_AES_C */

#if (defined(MBEDTLS_RUNTIME_C) || defined(MBEDTLS_CPU_HAS_FEATURES_ALT)) && \
    defined(MBEDTLS_AES_RUNTIME_HAVE_CODE)
#define MBEDTLS_RUNTIME_HAVE_CODE
#endif

#endif /* MBEDTLS_RUNTIME_INTERNAL_H */
