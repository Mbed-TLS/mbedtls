/*
 *  Query the Mbed TLS compile time configuration
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/platform.h"

#define USAGE                                                                \
    "usage: %s [ <MBEDTLS_CONFIG> | -l ]\n\n"                                \
    "This program takes one command line argument which corresponds to\n"    \
    "the string representation of a Mbed TLS compile time configuration.\n"  \
    "The value 0 will be returned if this configuration is defined in the\n" \
    "Mbed TLS build and the macro expansion of that configuration will be\n" \
    "printed (if any). Otherwise, 1 will be returned.\n"                     \
    "-l\tPrint all available configuration.\n"
#include <string.h>
#include "query_config.h"

int main(int argc, char *argv[])
{
    if (argc < 2 || strcmp(argv[1], "-h") == 0) {
        mbedtls_printf(USAGE, argv[0]);
        return MBEDTLS_EXIT_FAILURE;
    }

    if (strcmp(argv[1], "-l") == 0) {
        list_config();
        return 0;
    }

    return query_config(argv[1]);
}
