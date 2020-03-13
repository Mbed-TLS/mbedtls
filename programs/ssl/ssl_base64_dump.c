/*
 *  MbedTLS SSL context deserializer from base64 code
 *
 *  Copyright (C) 2006-2020, ARM Limited, All Rights Reserved
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

/*
 * This program version
 */
#define PROG_NAME "ssl_base64_dump"
#define VER_MAJOR 0
#define VER_MINOR 1

/*
 * Global values
 */
FILE *b64_file = NULL;      /* file with base64 codes to deserialize */
char debug = 0;             /* flag for debug messages */

/*
 * Basic printing functions
 */
void print_version( )
{
    printf( "%s v%d.%d\n", PROG_NAME, VER_MAJOR, VER_MINOR );
}

void print_usage( )
{
    print_version();
    printf(
        "Usage:\n"
        "\t-f path - Path to the file with base64 code\n"
        "\t-v      - Show version\n"
        "\t-h      - Show this usage\n"
        "\t-d      - Print more information\n"
        "\n"
    );
}

void printf_dbg( const char *str, ... )
{
    if( debug )
    {
        va_list args;
        va_start( args, str );
        printf( "debug: " );
        vprintf( str, args );
        fflush( stdout );
        va_end( args );
    }
}

void printf_err( const char *str, ... )
{
    va_list args;
    va_start( args, str );
    fprintf( stderr, "ERROR: " );
    vfprintf( stderr, str, args );
    fflush( stderr );
    va_end( args );
}

/*
 * Exit from the program in case of error
 */
void error_exit()
{
    if( NULL != b64_file )
    {
        fclose( b64_file );
    }
    exit( -1 );
}

/*
 * This function takes the input arguments of this program
 */
void parse_arguments( int argc, char *argv[] )
{
    int i = 1;

    if( argc < 2 )
    {
        print_usage();
        error_exit();
    }

    while( i < argc )
    {
        if( strcmp( argv[i], "-d" ) == 0 )
        {
            debug = 1;
        }
        else if( strcmp( argv[i], "-h" ) == 0 )
        {
            print_usage();
        }
        else if( strcmp( argv[i], "-v" ) == 0 )
        {
            print_version();
        }
        else if( strcmp( argv[i], "-f" ) == 0 )
        {
            if( ++i >= argc )
            {
                printf_err( "File path is empty\n" );
                error_exit();
            }

            if( ( b64_file = fopen( argv[i], "r" ) ) == NULL )
            {
                printf_err( "Cannot find file \"%s\"\n", argv[i] );
                error_exit();
            }
        }
        else
        {
            print_usage();
            error_exit();
        }

        i++;
    }
}

int main( int argc, char *argv[] )
{
    parse_arguments( argc, argv );

    return 0;
}
