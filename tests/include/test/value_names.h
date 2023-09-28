/**
 * \file value_names.h
 *
 * \brief Convert enum-like values into their name.
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

#ifndef TEST_VALUE_NAMES_H
#define TEST_VALUE_NAMES_H

#include <mbedtls/build_info.h>
#include <psa/crypto.h>

/* Functions that map values in a given category to their name.
 * These functions return either a string literal or NULL.
 * See tests/scripts/generate_value_names.py.
 */
const char *mbedtls_test_get_name_of_error(int value);
const char *mbedtls_test_get_name_of_psa_status_t(psa_status_t value);

#endif /* TEST_VALUE_NAMES_H */
