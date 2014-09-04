/*
 *  UDP proxy: emulate an unreliable UDP connexion for DTLS testing
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
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

#if !defined(POLARSSL_NET_C)
#include <stdio.h>
int main( void )
{
    printf( "POLARSSL_NET_C not defined.\n" );
    return( 0 );
}
#else

#include "polarssl/net.h"
#include "polarssl/error.h"

#include <stdio.h>
#include <stdlib.h>

/* For select() */
#if (defined(_WIN32) || defined(_WIN32_WCE)) && !defined(EFIX64) && \
    !defined(EFI32)
#include <winsock2.h>
#include <windows.h>
#if defined(_MSC_VER)
#if defined(_WIN32_WCE)
#pragma comment( lib, "ws2.lib" )
#else
#pragma comment( lib, "ws2_32.lib" )
#endif
#endif /* _MSC_VER */
#else /* ( _WIN32 || _WIN32_WCE ) && !EFIX64 && !EFI32 */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif /* ( _WIN32 || _WIN32_WCE ) && !EFIX64 && !EFI32 */

#define MAX_MSG_SIZE            18445 /* 2^14 + 2048 + 13 */

#define DFL_SERVER_ADDR         "localhost"
#define DFL_SERVER_PORT         4433
#define DFL_LISTEN_ADDR         "localhost"
#define DFL_LISTEN_PORT         5556

/*
 * global options
 */
struct options
{
    const char *server_addr;    /* address to forward packets to            */
    int server_port;            /* port to forward packets to               */
    const char *listen_addr;    /* address for accepting client connections */
    int listen_port;            /* port for accepting client connections    */
} opt;

#define USAGE                                                               \
    "\n usage: udp_proxy param=<>...\n"                                     \
    "\n acceptable parameters:\n"                                           \
    "    server_addr=%%d      default: localhost\n"                         \
    "    server_port=%%d      default: 4433\n"                              \
    "    listen_addr=%%d      default: localhost\n"                         \
    "    listen_port=%%d      default: 4433\n"                              \
    "\n"

static void exit_usage( void )
{
    printf( USAGE );
    exit( 1 );
}

static void get_options( int argc, char *argv[] )
{
    int i;
    char *p, *q;

    opt.server_addr    = DFL_SERVER_ADDR;
    opt.server_port    = DFL_SERVER_PORT;
    opt.listen_addr    = DFL_LISTEN_ADDR;
    opt.listen_port    = DFL_LISTEN_PORT;

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            exit_usage();
        *q++ = '\0';

        if( strcmp( p, "server_addr" ) == 0 )
            opt.server_addr = q;
        else if( strcmp( p, "server_port" ) == 0 )
        {
            opt.server_port = atoi( q );
            if( opt.server_port < 1 || opt.server_port > 65535 )
                exit_usage();
        }
        else if( strcmp( p, "listen_addr" ) == 0 )
            opt.listen_addr = q;
        else if( strcmp( p, "listen_port" ) == 0 )
        {
            opt.listen_port = atoi( q );
            if( opt.listen_port < 1 || opt.listen_port > 65535 )
                exit_usage();
        }
        else
            exit_usage();
    }
}

int handle_message( const char *way, int dst, int src )
{
    unsigned char buf[MAX_MSG_SIZE] = { 0 };
    int ret;
    size_t len;

    if( ( ret = net_recv( &src, buf, sizeof( buf ) ) ) <= 0 )
    {
        printf( "  ! net_recv returned %d\n", ret );
        return( ret );
    }

    printf( "  .. %s: %d bytes forwarded\n", way, ret );

    len = (size_t) ret;

    if( ( ret = net_send( &dst, buf, len ) ) <= 0 )
    {
        printf( "  ! net_send returned %d\n", ret );
        return( ret );
    }

    fflush( stdout );
    return( 0 );
}

int main( int argc, char *argv[] )
{
    int ret;

    int listen_fd = -1;
    int client_fd = -1;
    int server_fd = -1;

    int nb_fds;
    fd_set read_fds;

    get_options( argc, argv );

    /*
     * 0. Connect to the server
     */
    printf( "  . Connect to server on UDP/%s/%d ...",
            opt.server_addr, opt.server_port );
    fflush( stdout );

    if( ( ret = net_connect( &server_fd, opt.server_addr, opt.server_port,
                             NET_PROTO_UDP ) ) != 0 )
    {
        printf( " failed\n  ! net_connect returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 1. Setup the "listening" UDP socket
     */
    printf( "  . Bind on UDP/%s/%d ...",
            opt.listen_addr, opt.listen_port );
    fflush( stdout );

    if( ( ret = net_bind( &listen_fd, opt.listen_addr, opt.listen_port,
                          NET_PROTO_UDP ) ) != 0 )
    {
        printf( " failed\n  ! net_bind returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 2. Wait until a client connects
     */
    printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );

    if( ( ret = net_accept( listen_fd, &client_fd, NULL ) ) != 0 )
    {
        printf( " failed\n  ! net_accept returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );
    fflush( stdout );

    /*
     * 3. Forward packets forever (kill the process to terminate it)
     */
    nb_fds = ( client_fd > server_fd ? client_fd : server_fd ) + 1;

    while( 1 )
    {
        FD_ZERO( &read_fds );
        FD_SET( server_fd, &read_fds );
        FD_SET( client_fd, &read_fds );

        if( ( ret = select( nb_fds, &read_fds, NULL, NULL, NULL ) ) <= 0 )
        {
            perror( "select" );
            goto exit;
        }

        if( FD_ISSET( client_fd, &read_fds ) )
        {
            if( ( ret = handle_message( "c2s", server_fd, client_fd ) ) != 0 )
                goto exit;
        }

        if( FD_ISSET( server_fd, &read_fds ) )
        {
            if( ( ret = handle_message( "s2c", client_fd, server_fd ) ) != 0 )
                goto exit;
        }
    }

exit:

#ifdef POLARSSL_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        polarssl_strerror( ret, error_buf, 100 );
        printf( "Last error was: -0x%04X - %s\n\n", - ret, error_buf );
        fflush( stdout );
    }
#endif

    if( client_fd != -1 )
        net_close( client_fd );

    if( listen_fd != -1 )
        net_close( listen_fd );

#if defined(_WIN32)
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret != 0 );
}

#endif /* POLARSSL_NET_C */
