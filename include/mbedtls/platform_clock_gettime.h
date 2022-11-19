/**
 * \file platform_clock_gettime.h
 *
 * \brief mbed TLS Platform clock_gettime abstraction
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
#ifndef MBEDTLS_PLATFORM_CLOCK_GETTIME_H
#define MBEDTLS_PLATFORM_CLOCK_GETTIME_H

#include "mbedtls/build_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The time_t datatype
 */
#if defined(MBEDTLS_PLATFORM_CLOCK_GETTIME_TYPE_MACRO)
typedef MBEDTLS_PLATFORM_CLOCK_GETTIME_TYPE_MACRO mbedtls_timespec_t;
#else
/* For time_t */
#include <time.h>
typedef struct timespec mbedtls_timespec_t;
#endif /* MBEDTLS_PLATFORM_CLOCK_GETTIME_TYPE_MACRO */

#if defined(MBEDTLS_PLATFORM_CLOCK_GETTIME_MACRO)
#define mbedtls_clock_gettime   MBEDTLS_PLATFORM_CLOCK_GETTIME_MACRO
#else
#define mbedtls_clock_gettime   clock_gettime
#endif /* MBEDTLS_PLATFORM_CLOCK_GETTIME_MACRO */

#if defined(MBEDTLS_PLATFORM_CLOCK_REALTIME_MACRO)
#define MBEDTLS_CLOCK_REALTIME   MBEDTLS_PLATFORM_CLOCK_REALTIME_MACRO
#else
#define MBEDTLS_CLOCK_REALTIME   CLOCK_REALTIME
#endif /* MBEDTLS_PLATFORM_CLOCK_GETTIME_MACRO */

#ifdef __cplusplus
}
#endif

#endif /* platform_clock_gettime.h */
