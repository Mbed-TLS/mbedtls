/*
 *  Arm64 crypto engine support functions
 *
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

#include <string.h>
#include "common.h"

#if defined(MBEDTLS_AESCE_C)

#include "aesce.h"

#if defined(MBEDTLS_HAVE_ARM64)

#if defined(__clang__)
#   if __clang_major__ < 4
#       error "A more recent Clang is required for MBEDTLS_AES_C"
#   endif
#elif defined(__GNUC__)
#   if __GNUC__ < 6
#       error "A more recent GCC is required for MBEDTLS_AES_C"
#   endif
#else
#    error "Only GCC and Clang supported for MBEDTLS_AES_C"
#endif

#if !defined(__ARM_FEATURE_CRYPTO)
#   error "`crypto` feature moddifier MUST be enabled for MBEDTLS_AESCE_C."
#   error "Typical option for GCC and Clang is `-march=armv8-a+crypto`."
#endif /* !__ARM_FEATURE_CRYPTO */

#include <arm_neon.h>

#if defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

/*
 * AES instruction support detection routine
 */
int mbedtls_aesce_has_support(void)
{
#if defined(__linux__)
    unsigned long auxval = getauxval(AT_HWCAP);
    return (auxval & (HWCAP_ASIMD | HWCAP_AES)) ==
           (HWCAP_ASIMD | HWCAP_AES);
#else
    /* Suppose aes instructions are supported. */
    return 1;
#endif
}

#endif /* MBEDTLS_HAVE_ARM64 */

#endif /* MBEDTLS_AESCE_C */
