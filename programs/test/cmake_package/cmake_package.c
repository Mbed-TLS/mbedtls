/*
 *  Simple program to test that Mbed TLS builds correctly as a CMake package.
 *
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

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#include "mbedtls/version.h"

/* The main reason to build this is for testing the CMake build, so the program
 * doesn't need to do very much. It calls a single library function to ensure
 * linkage works, but that is all. */
int main()
{
    /* This version string is 18 bytes long, as advised by version.h. */
    char version[18];

    mbedtls_version_get_string_full( version );

    mbedtls_printf( "Built against %s\n", version );

    return( 0 );
}
