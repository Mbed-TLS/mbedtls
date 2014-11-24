/*
 *  Minimal SSL client, used for memory measurements.
 *
 *  Copyright (C) 2014, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://polarssl.org)
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
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

/*
 * We're creating and connecting the socket "manually" rather than using the
 * NET module, in order to avoid the overhead of getaddrinfo() which tends to
 * dominate memory usage in small configurations. For the sake of simplicity,
 * only a Unix version is implemented.
 */
#if defined(unix) || defined(__unix__) || defined(__unix)
#define UNIX
#endif

#if !defined(POLARSSL_CTR_DRBG_C) || !defined(POLARSSL_ENTROPY_C) || \
    !defined(POLARSSL_NET_C) || !defined(POLARSSL_SSL_CLI_C) || \
    !defined(UNIX)
#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#include <stdio.h>
#define polarssl_printf printf
#endif
int main( void )
{
    polarssl_printf( "POLARSSL_CTR_DRBG_C and/or POLARSSL_ENTROPY_C and/or "
            "POLARSSL_NET_C and/or POLARSSL_SSL_CLI_C and/or UNIX "
            "not defined.\n");
    return( 0 );
}
#else

#include <string.h>

#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * Hardcoded values for server host and port
 */
#define PORT_BE 0x1151      /* 4433 */
#define PORT_LE 0x5111
#define ADDR_BE 0x7f000001  /* 127.0.0.1 */
#define ADDR_LE 0x0100007f

#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

const unsigned char psk[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
const char psk_id[] = "Client_identity";

const char *pers = "mini_client";

int main( void )
{
    int ret = 0;
    int server_fd = -1;
    struct sockaddr_in addr;

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    ssl_context ssl;

    /*
     * 1. Initialize and setup stuff
     */
    memset( &ssl, 0, sizeof( ssl_context ) );

    entropy_init( &entropy );
    if( ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                       (const unsigned char *) pers, strlen( pers ) ) != 0 )
    {
        ret = 1;
        goto exit;
    }

    if( ssl_init( &ssl ) != 0 )
    {
        ret = 2;
        goto exit;
    }

    ssl_set_endpoint( &ssl, SSL_IS_CLIENT );

    ssl_set_rng( &ssl, ctr_drbg_random, &ctr_drbg );

    ssl_set_psk( &ssl, psk, sizeof( psk ),
                (const unsigned char *) psk_id, sizeof( psk_id ) - 1 );

    /*
     * 1. Start the connection
     */
    memset( &addr, 0, sizeof( addr ) );
    addr.sin_family = AF_INET;

    ret = 1; /* for endianness detection */
    addr.sin_port = *((char *) &ret) == ret ? PORT_LE : PORT_BE;
    addr.sin_addr.s_addr = *((char *) &ret) == ret ? ADDR_LE : ADDR_BE;
    ret = 0;

    if( ( server_fd = socket( AF_INET, SOCK_STREAM, 0 ) ) < 0 )
    {
        ret = 3;
        goto exit;
    }

    if( connect( server_fd,
                (const struct sockaddr *) &addr, sizeof( addr ) ) < 0 )
    {
        ret = 4;
        goto exit;
    }

    ssl_set_bio( &ssl, net_recv, &server_fd, net_send, &server_fd );

    if( ssl_handshake( &ssl ) != 0 )
    {
        ret = 5;
        goto exit;
    }

    /*
     * 2. Write the GET request and close the connection
     */
    if( ssl_write( &ssl, (const unsigned char *) GET_REQUEST,
                         sizeof( GET_REQUEST ) - 1 ) <= 0 )
    {
        ret = 6;
        goto exit;
    }

    ssl_close_notify( &ssl );

exit:
    if( server_fd != -1 )
        net_close( server_fd );

    ssl_free( &ssl );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

    return( ret );
}
#endif
