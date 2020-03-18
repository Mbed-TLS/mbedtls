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
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include "mbedtls/error.h"
#include "mbedtls/base64.h"

/*
 * This program version
 */
#define PROG_NAME "ssl_base64_dump"
#define VER_MAJOR 0
#define VER_MINOR 1

/*
 * Flags copied from the mbedTLS library.
 */
#define SESSION_CONFIG_TIME_BIT          ( 1 << 0 )
#define SESSION_CONFIG_CRT_BIT           ( 1 << 1 )
#define SESSION_CONFIG_CLIENT_TICKET_BIT ( 1 << 2 )
#define SESSION_CONFIG_MFL_BIT           ( 1 << 3 )
#define SESSION_CONFIG_TRUNC_HMAC_BIT    ( 1 << 4 )
#define SESSION_CONFIG_ETM_BIT           ( 1 << 5 )
#define SESSION_CONFIG_TICKET_BIT        ( 1 << 6 )

#define CONTEXT_CONFIG_DTLS_CONNECTION_ID_BIT    ( 1 << 0 )
#define CONTEXT_CONFIG_DTLS_BADMAC_LIMIT_BIT     ( 1 << 1 )
#define CONTEXT_CONFIG_DTLS_ANTI_REPLAY_BIT      ( 1 << 2 )
#define CONTEXT_CONFIG_ALPN_BIT                  ( 1 << 3 )

#define TRANSFORM_RANDBYTE_LEN  64

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

/*
 * This function prints base64 code to the stdout
 */
void print_b64( const uint8_t *b, size_t len )
{
    size_t i = 0;
    const uint8_t *end = b + len;
    printf("\t");
    while( b < end )
    {
        if( ++i > 75 )
        {
            printf( "\n\t" );
            i = 0;
        }
        printf( "%c", *b++ );
    }
    printf( "\n" );
    fflush( stdout );
}

/*
 * This function prints hex code from the buffer to the stdout.
 */
void print_hex( const uint8_t *b, size_t len )
{
    size_t i = 0;
    const uint8_t *end = b + len;
    printf("\t");
    while( b < end )
    {
        printf( "%02X ", (uint8_t) *b++ );
            if( ++i > 25 )
        {
            printf("\n\t");
            i = 0;
        }
    }
    printf("\n");
    fflush(stdout);
}

/*
 * Print the input string if the bit is set in the value
 */
void print_if_bit( const char *str, int bit, int val )
{
    if( bit & val )
    {
        printf( "\t%s\n", str );
    }
}

/*
 * Read next base64 code from the 'b64_file'. The 'b64_file' must be opened
 * previously. After each call to this function, the internal file position
 * indicator of the global b64_file is advanced.
 *
 * /p b64       buffer for input data
 * /p max_len   the maximum number of bytes to write
 *
 * \retval      number of bytes written in to the b64 buffer or 0 in case no more
 *              data was found
 */
size_t read_next_b64_code( uint8_t *b64, size_t max_len )
{
    size_t len = 0;
    uint32_t missed = 0;
    char pad = 0;
    char c = 0;

    while( EOF != c )
    {
        char c_valid = 0;

        c = (char) fgetc( b64_file );

        if( pad == 1 )
        {
            if( c == '=' )
            {
                c_valid = 1;
                pad = 2;
            }
        }
        else if( ( c >= 'A' && c <= 'Z' ) ||
                 ( c >= 'a' && c <= 'z' ) ||
                 ( c >= '0' && c <= '9' ) ||
                   c == '+' || c == '/' )
        {
            c_valid = 1;
        }
        else if( c == '=' )
        {
            c_valid = 1;
            pad = 1;
        }
        else if( c == '-' )
        {
            c = '+';
            c_valid = 1;
        }
        else if( c == '_' )
        {
            c = '/';
            c_valid = 1;
        }

        if( c_valid )
        {
            if( len < max_len )
            {
                b64[ len++ ] = c;
            }
            else
            {
                missed++;
            }
        }
        else if( len > 0 )
        {
            if( missed > 0 )
            {
                printf_err( "Buffer for the base64 code is too small. Missed %u characters\n", missed );
            }
            return len;
        }
    }

    printf_dbg( "End of file\n" );
    return 0;
}

/*
 * This function deserializes and prints to the stdout all obtained information
 * about the session from provided data. This function was built based on
 * mbedtls_ssl_session_load(). mbedtls_ssl_session_load() could not be used
 * due to dependencies on the mbedTLS configuration.
 *
 * The data structure in the buffer:
 *  uint64 start_time;
 *  uint8 ciphersuite[2];        // defined by the standard
 *  uint8 compression;           // 0 or 1
 *  uint8 session_id_len;        // at most 32
 *  opaque session_id[32];
 *  opaque master[48];           // fixed length in the standard
 *  uint32 verify_result;
 *  opaque peer_cert<0..2^24-1>; // length 0 means no peer cert
 *  opaque ticket<0..2^24-1>;    // length 0 means no ticket
 *  uint32 ticket_lifetime;
 *  uint8 mfl_code;              // up to 255 according to standard
 *  uint8 trunc_hmac;            // 0 or 1
 *  uint8 encrypt_then_mac;      // 0 or 1
 *
 * /p ssl               pointer to serialized session
 * /p len               number of bytes in the buffer
 * /p session_cfg_flag  session configuration flags
 */
void print_deserialized_ssl_session( const uint8_t *ssl, uint32_t len,
                                     int session_cfg_flag )
{
    const uint8_t *end = ssl + len;
    printf( "TODO\n" );
}

/*
 * This function deserializes and prints to the stdout all obtained information
 * about the context from provided data. This function was built based on
 * mbedtls_ssl_context_load(). mbedtls_ssl_context_load() could not be used
 * due to dependencies on the mbedTLS configuration and the configuration of
 * the context when serialization was created.
 *
 * The data structure in the buffer:
 *  // session sub-structure
 *  opaque session<1..2^32-1>;  // see mbedtls_ssl_session_save()
 *  // transform sub-structure
 *  uint8 random[64];           // ServerHello.random+ClientHello.random
 *  uint8 in_cid<0..2^8-1>      // Connection ID: expected incoming value
 *  uint8 out_cid<0..2^8-1>     // Connection ID: outgoing value to use
 *  // fields from ssl_context
 *  uint32 badmac_seen;         // DTLS: number of records with failing MAC
 *  uint64 in_window_top;       // DTLS: last validated record seq_num
 *  uint64 in_window;           // DTLS: bitmask for replay protection
 *  uint8 disable_datagram_packing; // DTLS: only one record per datagram
 *  uint64 cur_out_ctr;         // Record layer: outgoing sequence number
 *  uint16 mtu;                 // DTLS: path mtu (max outgoing fragment size)
 *  uint8 alpn_chosen<0..2^8-1> // ALPN: negotiated application protocol
 *
 * /p ssl   pointer to serialized session
 * /p len   number of bytes in the buffer
 */
void print_deserialized_ssl_context( const uint8_t *ssl, size_t len )
{
    /* TODO: which versions are compatible */
    /* TODO: add checking len */
    const uint8_t *end = ssl + len;
    int session_cfg_flag;
    int context_cfg_flag;
    uint32_t session_len;
    /* TODO is DTLS compiled? */
    char dtls_used = 1;

    printf( "\nMbed TLS version:\n" );

    printf( "\tmajor:\t%u\n", (uint32_t) *ssl++ );
    printf( "\tminor:\t%u\n", (uint32_t) *ssl++ );
    printf( "\tpath:\t%u\n",  (uint32_t) *ssl++ );

    printf( "\nEnabled session and context configuration:\n" );

    session_cfg_flag = ( (int) ssl[0] << 8 ) | ( (int) ssl[1] );
    ssl += 2;

    context_cfg_flag = ( (int) ssl[0] << 16 ) |
                       ( (int) ssl[1] <<  8 ) |
                       ( (int) ssl[2] ) ;
    ssl += 3;

    printf_dbg( "Session config flags 0x%04X\n", session_cfg_flag );
    printf_dbg( "Context config flags 0x%06X\n", context_cfg_flag );

    print_if_bit( "MBEDTLS_HAVE_TIME", SESSION_CONFIG_TIME_BIT, session_cfg_flag );
    print_if_bit( "MBEDTLS_X509_CRT_PARSE_C", SESSION_CONFIG_CRT_BIT, session_cfg_flag );
    print_if_bit( "MBEDTLS_SSL_MAX_FRAGMENT_LENGTH", SESSION_CONFIG_MFL_BIT, session_cfg_flag );
    print_if_bit( "MBEDTLS_SSL_TRUNCATED_HMAC", SESSION_CONFIG_TRUNC_HMAC_BIT, session_cfg_flag );
    print_if_bit( "MBEDTLS_SSL_ENCRYPT_THEN_MAC", SESSION_CONFIG_ETM_BIT, session_cfg_flag );
    print_if_bit( "MBEDTLS_SSL_SESSION_TICKETS", SESSION_CONFIG_TICKET_BIT, session_cfg_flag );
    print_if_bit( "MBEDTLS_SSL_SESSION_TICKETS and client", SESSION_CONFIG_CLIENT_TICKET_BIT, session_cfg_flag );

    print_if_bit( "MBEDTLS_SSL_DTLS_CONNECTION_ID", CONTEXT_CONFIG_DTLS_CONNECTION_ID_BIT, context_cfg_flag );
    print_if_bit( "MBEDTLS_SSL_DTLS_BADMAC_LIMIT", CONTEXT_CONFIG_DTLS_BADMAC_LIMIT_BIT, context_cfg_flag );
    print_if_bit( "MBEDTLS_SSL_DTLS_ANTI_REPLAY", CONTEXT_CONFIG_DTLS_ANTI_REPLAY_BIT, context_cfg_flag );
    print_if_bit( "MBEDTLS_SSL_ALPN", CONTEXT_CONFIG_ALPN_BIT, context_cfg_flag );

    session_len = ( (uint32_t) ssl[0] << 24 ) |
                  ( (uint32_t) ssl[1] << 16 ) |
                  ( (uint32_t) ssl[2] <<  8 ) |
                  ( (uint32_t) ssl[3] );
    ssl += 4;
    printf_dbg( "session length %u\n", session_len );

    print_deserialized_ssl_session( ssl, session_len, session_cfg_flag );
    ssl += session_len;

    /* TODO ssl_populate_transform */
    printf( "\nRandom bytes: \n");
    print_hex( ssl, TRANSFORM_RANDBYTE_LEN );
    printf( "TODO: ssl_populate_transform\n");
    ssl += TRANSFORM_RANDBYTE_LEN;

    if( CONTEXT_CONFIG_DTLS_CONNECTION_ID_BIT & context_cfg_flag )
    {
        uint8_t cid_len;
        printf( "\nDTLS connection ID:\n" );

        cid_len = *ssl++;
        printf_dbg( "in_cid_len %u\n", (uint32_t) cid_len );

        printf( "\tin_cid:" );
        print_hex( ssl, cid_len );
        ssl += cid_len;

        cid_len = *ssl++;
        printf_dbg( "out_cid_len %u\n", (uint32_t) cid_len );

        printf( "\tout_cid:" );
        print_hex( ssl, cid_len );
        ssl += cid_len;
    }

    if( CONTEXT_CONFIG_DTLS_BADMAC_LIMIT_BIT & context_cfg_flag )
    {
        uint32_t badmac_seen = ( (uint32_t) ssl[0] << 24 ) |
                               ( (uint32_t) ssl[1] << 16 ) |
                               ( (uint32_t) ssl[2] <<  8 ) |
                               ( (uint32_t) ssl[3] );
        ssl += 4;
        printf( "\tibadmac_seen: %d\n", badmac_seen );

        printf( "\tin_window_top: " );
        print_hex( ssl, 8 );
        ssl += 8;

        printf( "\twindow_top: " );
        print_hex( ssl, 8 );
        ssl += 8;
    }

    if( dtls_used )
    {
        printf( "\tDTLS datagram packing: %s\n",
                ( ( *ssl++ ) == 0 ) ?
                "enabled" : "disabled" );
    }

    printf( "\tcur_out_ctr: ");
    print_hex( ssl, 8 );
    ssl += 8;

    if( dtls_used )
    {
        uint16_t mtu = ( ssl[0] << 8 ) | ssl[1];
        ssl += 2;
        printf( "\tMTU: %u\n", mtu );
    }


    if( CONTEXT_CONFIG_ALPN_BIT & context_cfg_flag )
    {
        uint8_t alpn_len = *ssl++;
        if( alpn_len > 0 )
        {
            if( strlen( (const char*) ssl ) == alpn_len )
            {
                printf( "\talpn_chosen: %s\n", ssl );
            }
            else
            {
                printf_err( "\talpn_len is incorrect\n" );
            }
            ssl += alpn_len;
        }
        else
        {
            printf( "\talpn_chosen: not selected\n" );
        }
    }

    /* TODO: check mbedtls_ssl_update_out_pointers( ssl, ssl->transform ); */
    printf( "TODO: check mbedtls_ssl_update_out_pointers( ssl, ssl->transform );\n" );

    if( 0 < ( end - ssl ) )
    {
        printf_dbg( "Left to analyze %u\n", (uint32_t)( end - ssl ) );
    }
    printf( "\n" );
}

int main( int argc, char *argv[] )
{
    enum { B64BUF_LEN = 4 * 1024 };
    enum { SSLBUF_LEN = B64BUF_LEN * 3 / 4 + 1 };

    uint8_t b64[ B64BUF_LEN ];
    uint8_t ssl[ SSLBUF_LEN ];
    uint32_t b64_counter = 0;

    parse_arguments( argc, argv );

    while( NULL != b64_file )
    {
        size_t ssl_len;
        size_t b64_len = read_next_b64_code( b64, B64BUF_LEN );
        if( b64_len > 0)
        {
            int ret;

            printf( "%u. Desierializing:\n", ++b64_counter );

            if( debug )
            {
                printf( "\nBase64 code:\n" );
                print_b64( b64, b64_len );
            }

            ret = mbedtls_base64_decode( ssl, SSLBUF_LEN, &ssl_len, b64, b64_len );
            if( ret != 0)
            {
                mbedtls_strerror( ret, (char*) b64, B64BUF_LEN );
                printf_err( "base64 code cannot be decoded - %s\n", b64 );
                continue;
            }

            if( debug )
            {
                printf( "\nDecoded data in hex:\n");
                print_hex( ssl, ssl_len );
            }

            print_deserialized_ssl_context( ssl, ssl_len );

        }
        else
        {
            fclose( b64_file );
            b64_file = NULL;
        }
    }

    printf_dbg( "Finish. Found %u base64 codes\n", b64_counter );

    return 0;
}
