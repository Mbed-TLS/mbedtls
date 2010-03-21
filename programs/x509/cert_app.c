/*
 *  Certificate reading application
 *
 *  Copyright (C) 2006-2010, Paul Bakker <polarssl_maintainer at polarssl.org>
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

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "polarssl/havege.h"
#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/x509.h"

#define MODE_NONE               0
#define MODE_FILE               1
#define MODE_SSL                2

#define DFL_MODE                MODE_NONE
#define DFL_FILENAME            "cert.crt"
#define DFL_SERVER_NAME         "localhost"
#define DFL_SERVER_PORT         4433
#define DFL_DEBUG_LEVEL         0

/*
 * global options
 */
struct options
{
    int mode;                   /* the mode to run the application in   */
    char *filename;             /* filename of the certificate file     */
    char *server_name;          /* hostname of the server (client only) */
    int server_port;            /* port on which the ssl service runs   */
    int debug_level;            /* level of debugging                   */
} opt;

void my_debug( void *ctx, int level, const char *str )
{
    if( level < opt.debug_level )
    {
        fprintf( (FILE *) ctx, "%s", str );
        fflush(  (FILE *) ctx  );
    }
}

#define USAGE \
    "\n usage: cert_app param=<>...\n"                  \
    "\n acceptable parameters:\n"                       \
    "    mode=file|ssl       default: none\n"          \
    "    filename=%%s         default: cert.crt\n"      \
    "    server_name=%%s      default: localhost\n"     \
    "    server_port=%%d      default: 4433\n"          \
    "    debug_level=%%d      default: 0 (disabled)\n"  \
    "\n"

int main( int argc, char *argv[] )
{
    int ret = 0, server_fd;
    unsigned char buf[1024];
    havege_state hs;
    ssl_context ssl;
    ssl_session ssn;
    x509_cert clicert;
    rsa_context rsa;
    int i, j, n;
    char *p, *q;

    if( argc == 0 )
    {
    usage:
        printf( USAGE );
        goto exit;
    }

    opt.mode                = DFL_MODE;
    opt.filename            = DFL_FILENAME;
    opt.server_name         = DFL_SERVER_NAME;
    opt.server_port         = DFL_SERVER_PORT;
    opt.debug_level         = DFL_DEBUG_LEVEL;

    for( i = 1; i < argc; i++ )
    {
        n = strlen( argv[i] );

        for( j = 0; j < n; j++ )
        {
            if( argv[i][j] >= 'A' && argv[i][j] <= 'Z' )
                argv[i][j] |= 0x20;
        }

        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "mode" ) == 0 )
        {
            if( strcmp( q, "file" ) == 0 )
                opt.mode = MODE_FILE;
            else if( strcmp( q, "ssl" ) == 0 )
                opt.mode = MODE_SSL;
            else
                goto usage;
        }
        else if( strcmp( p, "filename" ) == 0 )
            opt.filename = q;
        else if( strcmp( p, "server_name" ) == 0 )
            opt.server_name = q;
        else if( strcmp( p, "server_port" ) == 0 )
        {
            opt.server_port = atoi( q );
            if( opt.server_port < 1 || opt.server_port > 65535 )
                goto usage;
        }
        else if( strcmp( p, "debug_level" ) == 0 )
        {
            opt.debug_level = atoi( q );
            if( opt.debug_level < 0 || opt.debug_level > 65535 )
                goto usage;
        }
        else
            goto usage;
    }

    if( opt.mode == MODE_FILE )
    {
        x509_cert crt;

        memset( &crt, 0, sizeof( x509_cert ) );

        /*
         * 1.1. Load the certificate
         */
        printf( "\n  . Loading the certificate ..." );
        fflush( stdout );

        ret = x509parse_crtfile( &crt, opt.filename );

        if( ret != 0 )
        {
            printf( " failed\n  !  x509parse_crt returned %d\n\n", ret );
            x509_free( &crt );
            goto exit;
        }

        printf( " ok\n" );

        /*
         * 1.2 Print the certificate
         */
        printf( "  . Peer certificate information    ...\n" );
        ret = x509parse_cert_info( (char *) buf, sizeof( buf ) - 1, "      ", &crt );
        if( ret == -1 )
        {
            printf( " failed\n  !  x509parse_cert_info returned %d\n\n", ret );
            x509_free( &crt );
            goto exit;
        }

        printf( "%s\n", buf );

        x509_free( &crt );
    }
    else if( opt.mode == MODE_SSL )
    {
        /*
         * 1. Initialize the RNG and the session data
         */
        havege_init( &hs );
        memset( &ssn, 0, sizeof( ssl_session ) );

        /*
         * 2. Start the connection
         */
        printf( "  . SSL connection to tcp/%s/%-4d...", opt.server_name,
                                                        opt.server_port );
        fflush( stdout );

        if( ( ret = net_connect( &server_fd, opt.server_name,
                                             opt.server_port ) ) != 0 )
        {
            printf( " failed\n  ! net_connect returned %d\n\n", ret );
            goto exit;
        }

        /*
         * 3. Setup stuff
         */
        if( ( ret = ssl_init( &ssl ) ) != 0 )
        {
            printf( " failed\n  ! ssl_init returned %d\n\n", ret );
            goto exit;
        }

        ssl_set_endpoint( &ssl, SSL_IS_CLIENT );
        ssl_set_authmode( &ssl, SSL_VERIFY_NONE );

        ssl_set_rng( &ssl, havege_rand, &hs );
        ssl_set_dbg( &ssl, my_debug, stdout );
        ssl_set_bio( &ssl, net_recv, &server_fd,
                net_send, &server_fd );

        ssl_set_ciphers( &ssl, ssl_default_ciphers );
        ssl_set_session( &ssl, 1, 600, &ssn );

        ssl_set_own_cert( &ssl, &clicert, &rsa );

        ssl_set_hostname( &ssl, opt.server_name );

        /*
         * 4. Handshake
         */
        while( ( ret = ssl_handshake( &ssl ) ) != 0 )
        {
            if( ret != POLARSSL_ERR_NET_TRY_AGAIN )
            {
                printf( " failed\n  ! ssl_handshake returned %d\n\n", ret );
                goto exit;
            }
        }

        printf( " ok\n" );

        /*
         * 5. Print the certificate
         */
        printf( "  . Peer certificate information    ...\n" );
        ret = x509parse_cert_info( (char *) buf, sizeof( buf ) - 1, "      ", ssl.peer_cert );
        if( ret == -1 )
        {
            printf( " failed\n  !  x509parse_cert_info returned %d\n\n", ret );
            goto exit;
        }

        printf( "%s\n", buf );

        ssl_close_notify( &ssl );
    }
    else
        goto usage;

exit:

    net_close( server_fd );
    x509_free( &clicert );
    rsa_free( &rsa );
    ssl_free( &ssl );

    memset( &ssl, 0, sizeof( ssl ) );

#ifdef WIN32
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
