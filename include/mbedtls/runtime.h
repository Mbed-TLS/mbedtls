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

/* Reserverd by internal runtime detection module to check if cpu features have
 * been profiled. */
#define MBEDTLS_HWCAP_PROFILED  (1ULL << 63)

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
 */
bool mbedtls_cpu_has_features(mbedtls_hwcap_mask_t hwcap);

#endif /* MBEDTLS_RUNTIME_H */
