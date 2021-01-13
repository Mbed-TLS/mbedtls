/**
 * \file common.h
 *
 * \brief Utility macros for internal use in the library
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

#ifndef MBEDTLS_LIBRARY_COMMON_H
#define MBEDTLS_LIBRARY_COMMON_H

#if defined(MBEDTLS_CONFIG_FILE)
#include MBEDTLS_CONFIG_FILE
#else
#include "mbedtls/config.h"
#endif

#if defined(MBEDTLS_TEST_HOOKS)
/** Helper to define a function as static except when building invasive tests.
 *
 * If a function is only used inside its own source file and should be
 * declared `static` to allow the compiler to optimize for code size,
 * but that function has unit tests, define it with
 * ```
 * MBEDTLS_STATIC_TESTABLE int mbedtls_foo(...) { ... }
 * ```
 * and declare it in a header in the `library/` directory with
 * ```
 * #if defined(MBEDTLS_TEST_HOOKS)
 * int mbedtls_foo(...);
 * #endif
 * ```
 */
#define MBEDTLS_STATIC_TESTABLE

/** Helper macro and function to combine a high and low level error code.
 *
 * This function uses a hook (`mbedtls_test_err_add_hook`) to allow invasive
 * testing of its inputs. This is used in the test infrastructure to report
 * on errors when combining two error codes of the same level (e.g: two high
 * or two low level errors).
 *
 * To set a hook use
 * ```
 * mbedtls_set_err_add_hook(&mbedtls_check_foo);
 * ```
 */
void mbedtls_set_err_add_hook( void *hook );
int mbedtls_err_add( int high, int low, const char *file, int line );
#define MBEDTLS_ERR_ADD( high, low )  \
    ( mbedtls_err_add( high, low, __FILE__, __LINE__ ) )

#else
#define MBEDTLS_STATIC_TESTABLE static

#define MBEDTLS_ERR_ADD( high, low ) \
    ( high + low )

#endif /* MBEDTLS_TEST_HOOKS */

#endif /* MBEDTLS_LIBRARY_COMMON_H */
