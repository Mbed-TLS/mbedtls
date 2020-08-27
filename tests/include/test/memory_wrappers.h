/**
 * \file memory.h
 *
 * \brief   This file declares wrappers for mbedtls_calloc() and mbedtls_free().
 */

/*
 *  Copyright (C) 2020, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef TEST_MEMORY_WRAPPERS_H
#define TEST_MEMORY_WRAPPERS_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>

/** Wrapper around mbedtls_calloc() meant to be used from library code.
 *
 * This wrapper must be used in conjunctin with mbedtls_test_free_wrapper().
 *
 * To enable the wrappers, compile the library with the following
 * preprocessor symbols defined:
 * - #MBEDTLS_PLATFORM_MEMORY;
 * - #MBEDTLS_PLATFORM_CALLOC_MACRO set to mbedtls_test_calloc_wrapper();
 * - #MBEDTLS_PLATFORM_FREE_MACRO set to mbedtls_test_free_wrapper().
 * Note that you must also arrange for this header to be included in
 * the configuration file, so that the functions are declared.
 *
 * This wrapper is not meant to be enabled when compiling test code.
 * However test code must use this wrapper when allocating memory
 * that will be freed by a call to mbedtls_free() inside the library.
 *
 * The typical way to enable the memory wrappers are:
 * - Compile the library with `MBEDTLS_CONFIG_FILE` set to
 *   `"tests/configs/config-wrapper-test-memory.h"`.
 * - Compile the tests with `-DMBEDTLS_TEST_MEMORY_WRAPPERS`.
 */
void *mbedtls_test_calloc_wrapper( size_t n, size_t size );

/** Wrapper around mbedtls_free() meant to be used from library code.
 *
 * This wrapper must be used in conjunction with mbedtls_test_free_wrapper().
 * See the documentation of this function for details.
 *
 * This wrapper is not meant to be enabled when compiling test code.
 * However test code must use this wrapper when free memory
 * that has been allocated by a call to mbedtls_calloc() inside the library.
 */
void mbedtls_test_free_wrapper( void *ptr );

#endif /* TEST_MEMORY_WRAPPERS_H */
