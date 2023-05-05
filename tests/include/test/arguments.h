/**
 * \file arguments.h
 *
 * \brief Manipulation of test arguments.
 *
 * Much of the code is in host_test.function, to be migrated here later.
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

#ifndef TEST_ARGUMENTS_H
#define TEST_ARGUMENTS_H

#include "mbedtls/build_info.h"
#include <stdint.h>
#include <stdlib.h>

typedef union {
    size_t len;
    intmax_t sint;
} mbedtls_test_argument_t;

#endif /* TEST_ARGUMENTS_H */
