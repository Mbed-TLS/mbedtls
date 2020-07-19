/* config.h wrapper that declares and enables memory management wrappers
 * used for testing.
 *
 * Use this configuration file only when building the library, not when
 * building tests and sample programs, so that the wrappers are only used
 * for memory allocations made from library code.
 *
 * See the documentation of mbedtls_test_calloc_wrapper() in
 * `tests/include/test/memory_wrappers.h` for more information.
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

#ifndef MBEDTLS_CONFIG_H
/* Don't #define MBEDTLS_CONFIG_H, let config.h do it. */

#include "mbedtls/config.h"

/* This includes MBEDTLS_CONFIG_FILE recursively. But since MBEDTLS_CONFIG_H
 * is now defined, the recursive inclusion is effectively empty. */
#include "../include/test/memory_wrappers.h"

#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO mbedtls_test_calloc_wrapper
#define MBEDTLS_PLATFORM_FREE_MACRO mbedtls_test_free_wrapper

#endif /* MBEDTLS_CONFIG_H */
