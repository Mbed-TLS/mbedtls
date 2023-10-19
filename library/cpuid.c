/*
 *  Runtime detection module for Arm64 CPU feature sets.
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
#include "cpuid_internal.h"

mbedtls_hwcap_mask_t mbedtls_cpu_hwcaps = 0;

#if defined(MBEDTLS_CPUID_C) && defined(MBEDTLS_AES_CPUID_HAVE_CODE)

#if defined(MBEDTLS_ARCH_IS_ARM64)

#define MBEDTLS_RUNTIME_AVAILABLE_MASKS ( \
        MBEDTLS_HWCAP_ASIMD     | \
        MBEDTLS_HWCAP_AES       | \
        MBEDTLS_HWCAP_PMULL     | \
        MBEDTLS_HWCAP_SHA2      | \
        MBEDTLS_HWCAP_SHA512      \
        )
#if defined(__linux__)
#include <sys/auxv.h>
static mbedtls_hwcap_mask_t cpu_feature_get(void)
{
    return (mbedtls_hwcap_mask_t) getauxval(AT_HWCAP) & \
           MBEDTLS_RUNTIME_AVAILABLE_MASKS;
}
#elif defined(__FreeBSD__) && __FreeBSD_version >= 1200000
#include <sys/auxv.h>
/* See:
 * - https://man.freebsd.org/cgi/man.cgi?query=elf_aux_info&sektion=3&format=html
 * - https://docs.freebsd.org/en/books/porters-handbook/versions/#versions-12
 * - https://reviews.freebsd.org/D12743
 *
 * On freebsd, we should use `elf_aux_info` to detect CPU feature sets.
 */
static mbedtls_hwcap_mask_t cpu_feature_get(void)
{
    mbedtls_hwcap_mask_t hwcap = 0;
    if (!elf_aux_info(aux, &hwcap, sizeof(hwcap))) {
        return hwcap & MBEDTLS_RUNTIME_AVAILABLE_MASKS;
    }
    return 0;
}
#elif defined(_WIN64)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <processthreadsapi.h>

static mbedtls_hwcap_mask_t cpu_feature_get(void)
{
    return IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) ?
           MBEDTLS_HWCAP_ASIMD     | \
           MBEDTLS_HWCAP_AES       | \
           MBEDTLS_HWCAP_PMULL     | \
           MBEDTLS_HWCAP_SHA2 : 0;
}

#elif defined(__APPLE__)
/* See: https://developer.apple.com/documentation/kernel/1387446-sysctlbyname/determining_instruction_set_characteristics */
#include <sys/types.h>
#include <sys/sysctl.h>
static bool is_cpu_feature_available(const char *name)
{
    int value = 0;
    size_t value_len = sizeof(value);

    int ret = sysctlbyname(name, &value, &value_len, NULL, 0);
    return ret == 0 && value != 0;
}

static mbedtls_hwcap_mask_t cpu_feature_get(void)
{
#define MBEDTLS_APPLE_GET_FEATURE(name, mask) \
    is_cpu_feature_available(name) ? mask : 0

    mbedtls_hwcap_mask_t hwcap = 0;
    hwcap |= MBEDTLS_APPLE_GET_FEATURE("hw.optional.arm.FEAT_AES",
                                       MBEDTLS_HWCAP_ASIMD | MBEDTLS_HWCAP_AES);
    hwcap |= MBEDTLS_APPLE_GET_FEATURE("hw.optional.arm.FEAT_PMULL",
                                       MBEDTLS_HWCAP_PMULL);
    hwcap |= MBEDTLS_APPLE_GET_FEATURE("hw.optional.arm.FEAT_SHA256",
                                       MBEDTLS_HWCAP_SHA2);
    hwcap |= MBEDTLS_APPLE_GET_FEATURE("hw.optional.arm.FEAT_SHA512",
                                       MBEDTLS_HWCAP_SHA512);
    return hwcap;
}

#endif /* __APPLE__ */

#endif /* MBEDTLS_ARCH_IS_ARM64 */

#if defined(MBEDTLS_ARCH_IS_X64) || defined(MBEDTLS_ARCH_IS_X86)
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
static void get_cpuid(unsigned eax, unsigned info[4])
{
#if defined(_MSC_VER)
    __cpuid(info, eax);
#else
    __cpuid(eax, info[0], info[1], info[2], info[3]);
#endif
}

#define MBEDTLS_GET_HIGHEST_CENTAUR_EXT 0xc0000000
#define MBEDTLS_GET_CENTAUR_INFO        0xc0000001
#define MBEDTLS_PADLOCK_ACE 0x00c0

static mbedtls_hwcap_mask_t cpu_feature_get(void)
{
    unsigned info[4] = { 0, 0, 0, 0 };
    mbedtls_hwcap_mask_t hwcap = 0;

#if defined(MBEDTLS_AESNI_C)
    get_cpuid(1, info);
    hwcap |= info[2] & (MBEDTLS_HWCAP_AESNI_AES | MBEDTLS_HWCAP_AESNI_CLMUL);
#endif

#if defined(MBEDTLS_PADLOCK_C)
    get_cpuid(MBEDTLS_GET_HIGHEST_CENTAUR_EXT, info);
    if (info[0] >= MBEDTLS_GET_CENTAUR_INFO) {
        get_cpuid(MBEDTLS_GET_CENTAUR_INFO, info);
        if ((info[2]&MBEDTLS_PADLOCK_ACE) == MBEDTLS_PADLOCK_ACE) {
            hwcap |= MBEDTLS_HWCAP_PADLOCK_ACE;
        }
    }
#endif

    return hwcap;
}
#endif /* MBEDTLS_ARCH_IS_X64 || MBEDTLS_ARCH_IS_X86 */

mbedtls_hwcap_mask_t mbedtls_cpuid_get(void)
{
    return cpu_feature_get() | MBEDTLS_HWCAP_PROFILED;
}

#endif /* MBEDTLS_CPUID_C && MBEDTLS_AES_CPUID_HAVE_CODE */
