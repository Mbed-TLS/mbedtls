/*
 *  Simple program to test that CMake builds with Mbed TLS as a subdirectory
 *  work correctly.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#include "mbedtls/version.h"

/* The main reason to build this is for testing the CMake build, so the program
 * doesn't need to do very much. It calls a single library function to ensure
 * linkage works, but that is all. */
int main()
{
    const char *version = mbedtls_version_get_string_full();

    mbedtls_printf("Built against %s\n", version);

    return 0;
}
