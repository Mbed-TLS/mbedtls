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
#include "polarssl/ssl.h"

#include <stdio.h>
#include <stdlib.h>
#if defined(POLARSSL_HAVE_TIME)
#include <time.h>
#endif

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

/* For gettimeofday() */
#if !defined(_WIN32)
#include <sys/time.h>
#endif

#define MAX_MSG_SIZE            4096 /* Reasonable max size for our tests */

#define DFL_SERVER_ADDR         "localhost"
#define DFL_SERVER_PORT         4433
#define DFL_LISTEN_ADDR         "localhost"
#define DFL_LISTEN_PORT         5556

#define USAGE                                                               \
    "\n usage: udp_proxy param=<>...\n"                                     \
    "\n acceptable parameters:\n"                                           \
    "    server_addr=%%d      default: localhost\n"                         \
    "    server_port=%%d      default: 4433\n"                              \
    "    listen_addr=%%d      default: localhost\n"                         \
    "    listen_port=%%d      default: 4433\n"                              \
    "\n"                                                                    \
    "    duplicate=%%d        default: 0 (no duplication)\n"                \
    "                        duplicate 1 packet every N packets\n"          \
    "    delay=%%d            default: 0 (no delayed packets)\n"            \
    "                        delay 1 packet every N packets\n"              \
    "    delay_ccs=%%d        default: 0 (don't delay ChangeCipherSuite)\n" \
    "    drop=%%d             default: 0 (no dropped packets)\n"            \
    "                        drop 1 packet every N packets\n"               \
    "    mtu=%%d              default: 0 (unlimited)\n"                     \
    "                        drop packets larger than N bytes\n"            \
    "    bad_ad=%%d           default: 0 (don't add bad ApplicationData)\n" \
    "\n"

/*
 * global options
 */
static struct options
{
    const char *server_addr;    /* address to forward packets to            */
    int server_port;            /* port to forward packets to               */
    const char *listen_addr;    /* address for accepting client connections */
    int listen_port;            /* port for accepting client connections    */

    int duplicate;              /* duplicate 1 in N packets (none if 0)     */
    int delay;                  /* delay 1 packet in N (none if 0)          */
    int delay_ccs;              /* delay ChangeCipherSpec                   */
    int drop;                   /* drop 1 packet in N (none if 0)           */
    int mtu;                    /* drop packets larger than this            */
    int bad_ad;                 /* inject corrupted ApplicationData record  */
} opt;

/*
 * global counters
 */
static int dupl_cnt;
static int delay_cnt;
static int drop_cnt;

/* Do not always start with the same state */
static void randomize_counters( void )
{
#if defined(POLARSSL_HAVE_TIME)
    srand( time( NULL ) );
#endif

    if( opt.duplicate != 0 )
        dupl_cnt = rand() % opt.duplicate;
    if( opt.delay != 0 )
        delay_cnt = rand() % opt.delay;
    if( opt.drop != 0 )
        drop_cnt = rand() % opt.drop;
}

static void exit_usage( const char *name, const char *value )
{
    if( value == NULL )
        printf( " unknown option or missing value: %s\n", name );
    else
        printf( " option %s: illegal value: %s\n", name, value );

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
    /* Other members default to 0 */

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            exit_usage( p, NULL );
        *q++ = '\0';

        if( strcmp( p, "server_addr" ) == 0 )
            opt.server_addr = q;
        else if( strcmp( p, "server_port" ) == 0 )
        {
            opt.server_port = atoi( q );
            if( opt.server_port < 1 || opt.server_port > 65535 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "listen_addr" ) == 0 )
            opt.listen_addr = q;
        else if( strcmp( p, "listen_port" ) == 0 )
        {
            opt.listen_port = atoi( q );
            if( opt.listen_port < 1 || opt.listen_port > 65535 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "duplicate" ) == 0 )
        {
            opt.duplicate = atoi( q );
            if( opt.duplicate < 0 || opt.duplicate > 10 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "delay" ) == 0 )
        {
            opt.delay = atoi( q );
            if( opt.delay < 0 || opt.delay > 10 || opt.delay == 1 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "delay_ccs" ) == 0 )
        {
            opt.delay_ccs = atoi( q );
            if( opt.delay_ccs < 0 || opt.delay_ccs > 1 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "drop" ) == 0 )
        {
            opt.drop = atoi( q );
            if( opt.drop < 0 || opt.drop > 10 || opt.drop == 1 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "mtu" ) == 0 )
        {
            opt.mtu = atoi( q );
            if( opt.mtu < 0 || opt.mtu > MAX_MSG_SIZE )
                exit_usage( p, q );
        }
        else if( strcmp( p, "bad_ad" ) == 0 )
        {
            opt.bad_ad = atoi( q );
            if( opt.bad_ad < 0 || opt.bad_ad > 1 )
                exit_usage( p, q );
        }
        else
            exit_usage( p, NULL );
    }
}

static const char *msg_type( unsigned char *msg, size_t len )
{
    if( len < 1 )                           return( "Invalid" );
    switch( msg[0] )
    {
        case SSL_MSG_CHANGE_CIPHER_SPEC:    return( "ChangeCipherSpec" );
        case SSL_MSG_ALERT:                 return( "Alert" );
        case SSL_MSG_APPLICATION_DATA:      return( "ApplicationData" );
        case SSL_MSG_HANDSHAKE:             break; /* See below */
        default:                            return( "Unknown" );
    }

    if( len < 13 )                          return( "Invalid handshake" );
    switch( msg[13] )
    {
        case SSL_HS_HELLO_REQUEST:          return( "HelloRequest" );
        case SSL_HS_CLIENT_HELLO:           return( "ClientHello" );
        case SSL_HS_SERVER_HELLO:           return( "ServerHello" );
        case SSL_HS_HELLO_VERIFY_REQUEST:   return( "HelloVerifyRequest" );
        case SSL_HS_NEW_SESSION_TICKET:     return( "NewSessionTicket" );
        case SSL_HS_CERTIFICATE:            return( "Certificate" );
        case SSL_HS_SERVER_KEY_EXCHANGE:    return( "ServerKeyExchange" );
        case SSL_HS_CERTIFICATE_REQUEST:    return( "CertificateRequest" );
        case SSL_HS_SERVER_HELLO_DONE:      return( "ServerHelloDone" );
        case SSL_HS_CERTIFICATE_VERIFY:     return( "CertificateVerify" );
        case SSL_HS_CLIENT_KEY_EXCHANGE:    return( "ClientKeyExchange" );
        case SSL_HS_FINISHED:               return( "Finished" );
        default:                            return( "Unkown handshake" );
    }
}

/* Return elapsed time in milliseconds since the first call */
static unsigned long ellapsed_time( void )
{
#if defined(_WIN32)
    return( 0 );
#else
    static struct timeval ref = { 0, 0 };
    struct timeval now;

    if( ref.tv_sec == 0 && ref.tv_usec == 0 )
    {
        gettimeofday( &ref, NULL );
        return( 0 );
    }

    gettimeofday( &now, NULL );
    return( 1000 * ( now.tv_sec  - ref.tv_sec )
                 + ( now.tv_usec - ref.tv_usec ) / 1000 );
#endif
}

typedef struct
{
    void *dst;
    const char *way;
    const char *type;
    unsigned len;
    unsigned char buf[MAX_MSG_SIZE];
} packet;

/* Print packet. Outgoing packets come with a reason (forward, dupl, etc.) */
void print_packet( const packet *p, const char *why )
{
    if( why == NULL )
        printf( "  %05lu %s %s (%u bytes)\n",
                ellapsed_time(), p->way, p->type, p->len );
    else
        printf( "        %s %s (%u bytes): %s\n",
                p->way, p->type, p->len, why );
    fflush( stdout );
}

int send_packet( const packet *p, const char *why )
{
    int ret;

    /* insert corrupted ApplicationData record? */
    if( opt.bad_ad &&
        strcmp( p->type, "ApplicationData" ) == 0 )
    {
        unsigned char buf[MAX_MSG_SIZE];
        memcpy( buf, p->buf, p->len );
        ++buf[p->len - 1];

        print_packet( p, "corrupted" );
        if( ( ret = net_send( p->dst, buf, p->len ) ) <= 0 )
        {
            printf( "  ! net_send returned %d\n", ret );
            return( ret );
        }
    }

    print_packet( p, why );
    if( ( ret = net_send( p->dst, p->buf, p->len ) ) <= 0 )
    {
        printf( "  ! net_send returned %d\n", ret );
        return( ret );
    }

    /* Don't duplicate Application Data, only handshake covered */
    if( opt.duplicate != 0 &&
        strcmp( p->type, "ApplicationData" ) != 0 &&
        ++dupl_cnt == opt.duplicate )
    {
        dupl_cnt = 0;
        print_packet( p, "duplicated" );

        if( ( ret = net_send( p->dst, p->buf, p->len ) ) <= 0 )
        {
            printf( "  ! net_send returned %d\n", ret );
            return( ret );
        }
    }

    return( 0 );
}

int handle_message( const char *way, int dst, int src )
{
    int ret;
    packet cur;
    static packet prev;

    /* receive packet */
    if( ( ret = net_recv( &src, cur.buf, sizeof( cur.buf ) ) ) <= 0 )
    {
        printf( "  ! net_recv returned %d\n", ret );
        return( ret );
    }

    cur.len  = ret;
    cur.type = msg_type( cur.buf, cur.len );
    cur.way  = way;
    cur.dst  = &dst;
    print_packet( &cur, NULL );

    /* do we want to drop, delay, or forward it? */
    if( ( opt.mtu != 0 &&
          cur.len > (unsigned) opt.mtu ) ||
        ( opt.drop != 0 &&
          strcmp( cur.type, "ApplicationData" ) != 0 &&
          ++drop_cnt == opt.drop ) )
    {
        drop_cnt = 0;
    }
    else if( ( opt.delay_ccs == 1 &&
               strcmp( cur.type, "ChangeCipherSpec" ) == 0 ) ||
             ( opt.delay != 0 &&
               strcmp( cur.type, "ApplicationData" ) != 0 &&
               ++delay_cnt == opt.delay ) )
    {
        delay_cnt = 0;
        memcpy( &prev, &cur, sizeof( packet ) );
    }
    else
    {
        /* forward and possibly duplicate */
        if( ( ret = send_packet( &cur, "forwarded" ) ) != 0 )
            return( ret );

        /* send previously delayed message if any */
        if( prev.dst != NULL )
        {
            ret = send_packet( &prev, "delayed" );
            memset( &prev, 0, sizeof( packet ) );
            if( ret != 0 )
                return( ret );
        }
    }

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
    randomize_counters();

    /*
     * 0. "Connect" to the server
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
            if( ( ret = handle_message( "S <- C",
                                        server_fd, client_fd ) ) != 0 )
                goto exit;
        }

        if( FD_ISSET( server_fd, &read_fds ) )
        {
            if( ( ret = handle_message( "S -> C",
                                        client_fd, server_fd ) ) != 0 )
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
