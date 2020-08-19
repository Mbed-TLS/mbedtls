/*
 *  Translate error code to error string
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 *  This file is provided under the Apache License 2.0, or the
 *  GNU General Public License v2.0 or later.
 *
 *  **********
 *  Apache License 2.0:
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
 *  **********
 *
 *  **********
 *  GNU General Public License v2.0 or later:
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  **********
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf     printf
#define mbedtls_exit       exit
#endif

#if defined(MBEDTLS_ERROR_C) || defined(MBEDTLS_ERROR_STRERROR_DUMMY)
#include "mbedtls/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#define USAGE \
    "\n usage: strerror <errorcode>\n" \
    "\n where <errorcode> can be a decimal or hexadecimal (starts with 0x or -0x)\n"

#if !defined(MBEDTLS_ERROR_C) && !defined(MBEDTLS_ERROR_STRERROR_DUMMY)
int main( void )
{
    mbedtls_printf("MBEDTLS_ERROR_C and/or MBEDTLS_ERROR_STRERROR_DUMMY not defined.\n");
    mbedtls_exit( 0 );
}
#else
int main( int argc, char *argv[] )
{
    long int val;
    char *end = argv[1];

    if( argc != 2 )
    {
        mbedtls_printf( USAGE );
        mbedtls_exit( 0 );
    }

    val = strtol( argv[1], &end, 10 );
    if( *end != '\0' )
    {
        val = strtol( argv[1], &end, 16 );
        if( *end != '\0' )
        {
            mbedtls_printf( USAGE );
            return( 0 );
        }
    }
    if( val > 0 )
        val = -val;

    if( val != 0 )
    {
        char error_buf[200];
        mbedtls_strerror( val, error_buf, 200 );
        mbedtls_printf("Last error was: -0x%04x - %s\n\n", (int) -val, error_buf );
    }

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    mbedtls_exit( val );
}
#endif /* MBEDTLS_ERROR_C */
