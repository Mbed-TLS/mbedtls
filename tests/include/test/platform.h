/** Utilities for testing platform functions.
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

#ifndef MBEDTLS_TEST_PLATFORM_H
#define MBEDTLS_TEST_PLATFORM_H

/** Counters keeping track of how many times each platform function was
 * called. It's up to the implementation of the platform function to
 * update an instance of this structure. */
typedef struct
{
    size_t calloc;              /*!< mbedtls_calloc */
    size_t free;                /*!< mbedtls_free */
} mbedtls_test_platform_function_counters_t;

#if defined(MBEDTLS_TEST_PLATFORM_MACROS)
/* This macro should be set via tests/configs/user-config-for-test.h, which
 * sets each mbedtls_test_platform_xxx_macro functions defined here as
 * implementations of the corresponding platform abstraction. */

/** Counters keeping track of how many times the platform functions were
 * called. They are reset at the beginning of each test case. */
extern mbedtls_test_platform_function_counters_t mbedtls_test_platform_macro_counters;

/** Reset ::mbedtls_test_platform_macro_counters to zero. */
void mbedtls_test_reset_platform_macro_counters( void );

/** An implementation of mbedtls_calloc() that updates
 * ::mbedtls_test_platform_macro_counters. */
void *mbedtls_test_platform_calloc_macro( size_t nbmem, size_t size );

/** An implementation of mbedtls_free() that updates
 * ::mbedtls_test_platform_macro_counters. */
void mbedtls_test_platform_free_macro( void* ptr );

#endif /* MBEDTLS_TEST_PLATFORM_MACROS */

#endif /* MBEDTLS_TEST_PLATFORM_H */
