/**
 * \file platform_time.h
 *
 * \brief Mbed TLS Platform time abstraction
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
#ifndef MBEDTLS_PLATFORM_TIME_H
#define MBEDTLS_PLATFORM_TIME_H

#include "mbedtls/build_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The time_t datatype
 */
#if defined(MBEDTLS_PLATFORM_TIME_TYPE_MACRO)
typedef MBEDTLS_PLATFORM_TIME_TYPE_MACRO mbedtls_time_t;
#else
/* For time_t */
#include <time.h>
typedef time_t mbedtls_time_t;
#endif /* MBEDTLS_PLATFORM_TIME_TYPE_MACRO */

#if defined(MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO)
typedef MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO mbedtls_ms_time_t;
#else
#include <stdint.h>
#include <inttypes.h>
typedef int64_t mbedtls_ms_time_t;
#endif /* MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO */

/**
 * \brief   Get time in milliseconds.
 *
 * \return Monotonically-increasing current time in milliseconds.
 *
 * \note Define MBEDTLS_PLATFORM_MS_TIME_ALT to be able to provide an
 *       alternative implementation
 *
 * \warning This function returns a monotonically-increasing time value from a
 *          start time that will differ from platform to platform, and possibly
 *          from run to run of the process.
 *
 */
mbedtls_ms_time_t mbedtls_ms_time(void);

/*
 * The function pointers for time
 */
#if defined(MBEDTLS_PLATFORM_TIME_ALT)
extern mbedtls_time_t (*mbedtls_time)(mbedtls_time_t *time);

/**
 * \brief   Set your own time function pointer
 *
 * \param   time_func   the time function implementation
 *
 * \return              0
 */
int mbedtls_platform_set_time(mbedtls_time_t (*time_func)(mbedtls_time_t *time));
#else
#if defined(MBEDTLS_PLATFORM_TIME_MACRO)
#define mbedtls_time    MBEDTLS_PLATFORM_TIME_MACRO
#else
#define mbedtls_time   time
#endif /* MBEDTLS_PLATFORM_TIME_MACRO */
#endif /* MBEDTLS_PLATFORM_TIME_ALT */

#ifdef __cplusplus
}
#endif

#endif /* platform_time.h */
