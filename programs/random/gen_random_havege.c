/**
 *  \brief Generate random data into a file
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
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if defined(MBEDTLS_HAVEGE_C) && defined(MBEDTLS_FS_IO)
#include "mbedtls/havege.h"

#include <stdio.h>
#include <time.h>
#endif

#if !defined(MBEDTLS_HAVEGE_C) || !defined(MBEDTLS_FS_IO)
int main( void )
{
    mbedtls_printf("MBEDTLS_HAVEGE_C not defined.\n");
    mbedtls_exit( 0 );
}
#else
int main( int argc, char *argv[] )
{
    FILE *f;
    time_t t;
    int i, k, ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_havege_state hs;
    unsigned char buf[1024];

    if( argc < 2 )
    {
        mbedtls_fprintf( stderr, "usage: %s <output filename>\n", argv[0] );
        mbedtls_exit( exit_code );
    }

    if( ( f = fopen( argv[1], "wb+" ) ) == NULL )
    {
        mbedtls_printf( "failed to open '%s' for writing.\n", argv[1] );
        mbedtls_exit( exit_code );
    }

    mbedtls_havege_init( &hs );

    t = time( NULL );

    for( i = 0, k = 768; i < k; i++ )
    {
        if( ( ret = mbedtls_havege_random( &hs, buf, sizeof( buf ) ) ) != 0 )
        {
            mbedtls_printf( " failed\n  !  mbedtls_havege_random returned -0x%04X",
                            -ret );
            goto exit;
        }

        fwrite( buf, sizeof( buf ), 1, f );

        mbedtls_printf( "Generating %ldkb of data in file '%s'... %04.1f" \
                "%% done\r", (long)(sizeof(buf) * k / 1024), argv[1], (100 * (float) (i + 1)) / k );
        fflush( stdout );
    }

    if( t == time( NULL ) )
        t--;

    mbedtls_printf(" \n ");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    mbedtls_havege_free( &hs );
    fclose( f );
    mbedtls_exit( exit_code );
}
#endif /* MBEDTLS_HAVEGE_C */
