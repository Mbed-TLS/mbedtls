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
#include "runtime_internal.h"

#if defined(MBEDTLS_RUNTIME_C) && defined(MBEDTLS_RUNTIME_HAVE_CODE)

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
#endif /* __linux__ */

#endif /* MBEDTLS_ARCH_IS_ARM64 */

bool mbedtls_cpu_has_features(mbedtls_hwcap_mask_t hwcap)
{
    static mbedtls_hwcap_mask_t mbedtls_cpu_hwcaps = 0;
    if ((mbedtls_cpu_hwcaps & MBEDTLS_HWCAP_PROFILED) == 0) {
        mbedtls_cpu_hwcaps = cpu_feature_get() | MBEDTLS_HWCAP_PROFILED;
    }
    return (hwcap & mbedtls_cpu_hwcaps) == hwcap;
}

#endif /* MBEDTLS_RUNTIME_C && MBEDTLS_RUNTIME_HAVE_CODE */
