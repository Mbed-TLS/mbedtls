/* mbedtls_config.h modifier that defines mbedtls_platform_zeroize() to be
 * memset(), so that the compile can check arguments for us.
 * Used for testing.
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

#include <string.h>

/* Define _ALT so we don't get the built-in implementation. The test code will
 * also need to define MBEDTLS_TEST_DEFINES_ZEROIZE so we don't get the
 * declaration. */
#define MBEDTLS_PLATFORM_ZEROIZE_ALT

#define mbedtls_platform_zeroize(buf, len) memset(buf, 0, len)
