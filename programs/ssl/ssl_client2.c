/*
 *  SSL client with certificate authentication
 *
 *  Copyright (C) 2006-2007  Christophe Devine
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
#include <stdio.h>

#include "xyssl/net.h"
#include "xyssl/ssl.h"
#include "xyssl/havege.h"
#include "xyssl/certs.h"
#include "xyssl/x509.h"

#define SERVER_PORT 443
/*
#define SERVER_NAME "localhost"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"
*/
#define SERVER_NAME "xyssl.org"
#define GET_REQUEST \
    "GET /hello/ HTTP/1.1\r\n" \
    "Host: xyssl.org\r\n\r\n"

#define DEBUG_LEVEL 0

void my_debug( void *ctx, int level, char *str )
{
    if( level < DEBUG_LEVEL )
    {
        fprintf( (FILE *) ctx, "%s", str );
        fflush(  (FILE *) ctx  );
    }
}

int main( void )
{
    int ret, len, server_fd;
    unsigned char buf[1024];
    havege_state hs;
    ssl_context ssl;
    ssl_session ssn;
    x509_cert cacert;
    x509_cert clicert;
    rsa_context rsa;

    /*
     * 0. Initialize the RNG and the session data
     */
    havege_init( &hs );
    memset( &ssn, 0, sizeof( ssl_session ) );

    /*
     * 1.1. Load the trusted CA
     */
    printf( "\n  . Loading the CA root certificate ..." );
    fflush( stdout );

    memset( &cacert, 0, sizeof( x509_cert ) );

    /*
     * Alternatively, you may load the CA certificates from a .pem or
     * .crt file by calling x509parse_crtfile( &cacert, "myca.crt" ).
     */
    ret = x509parse_crt( &cacert, (unsigned char *) xyssl_ca_crt,
                         strlen( xyssl_ca_crt ) );
    if( ret != 0 )
    {
        printf( " failed\n  !  x509parse_crt returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 1.2. Load own certificate and private key
     *
     * (can be skipped if client authentication is not required)
     */
    printf( "  . Loading the client cert. and key..." );
    fflush( stdout );

    memset( &clicert, 0, sizeof( x509_cert ) );

    ret = x509parse_crt( &clicert, (unsigned char *) test_cli_crt,
                         strlen( test_cli_crt ) );
    if( ret != 0 )
    {
        printf( " failed\n  !  x509parse_crt returned %d\n\n", ret );
        goto exit;
    }

    ret = x509parse_key( &rsa, (unsigned char *) test_cli_key,
                         strlen( test_cli_key ), NULL, 0 );
    if( ret != 0 )
    {
        printf( " failed\n  !  x509parse_key returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 2. Start the connection
     */
    printf( "  . Connecting to tcp/%s/%-4d...", SERVER_NAME,
                                                SERVER_PORT );
    fflush( stdout );

    if( ( ret = net_connect( &server_fd, SERVER_NAME,
                                         SERVER_PORT ) ) != 0 )
    {
        printf( " failed\n  ! net_connect returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 3. Setup stuff
     */
    printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );

    havege_init( &hs );

    if( ( ret = ssl_init( &ssl ) ) != 0 )
    {
        printf( " failed\n  ! ssl_init returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    ssl_set_endpoint( &ssl, SSL_IS_CLIENT );
    ssl_set_authmode( &ssl, SSL_VERIFY_OPTIONAL );

    ssl_set_rng( &ssl, havege_rand, &hs );
    ssl_set_bio( &ssl, net_recv, &server_fd,
                       net_send, &server_fd );

    ssl_set_ciphers( &ssl, ssl_default_ciphers );
    ssl_set_session( &ssl, 1, 600, &ssn );

    ssl_set_ca_chain( &ssl, &cacert, SERVER_NAME );
    ssl_set_own_cert( &ssl, &clicert, &rsa );

    ssl_set_hostname( &ssl, SERVER_NAME );

    /*
     * 4. Handshake
     */
    printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != XYSSL_ERR_NET_TRY_AGAIN )
        {
            printf( " failed\n  ! ssl_handshake returned %d\n\n", ret );
            goto exit;
        }
    }

    printf( " ok\n    [ Cipher is %s ]\n",
            ssl_get_cipher( &ssl ) );

    /*
     * 5. Verify the server certificate
     */
    printf( "  . Verifying peer X.509 certificate..." );

    if( ( ret = ssl_get_verify_result( &ssl ) ) != 0 )
    {
        printf( " failed\n" );

        if( ( ret & BADCERT_EXPIRED ) != 0 )
            printf( "  ! server certificate has expired\n" );

        if( ( ret & BADCERT_REVOKED ) != 0 )
            printf( "  ! server certificate has been revoked\n" );

        if( ( ret & BADCERT_CN_MISMATCH ) != 0 )
            printf( "  ! CN mismatch (expected CN=%s)\n", SERVER_NAME );

        if( ( ret & BADCERT_NOT_TRUSTED ) != 0 )
            printf( "  ! self-signed or not signed by a trusted CA\n" );

        printf( "\n" );
    }
    else
        printf( " ok\n" );

    printf( "  . Peer certificate information    ...\n" );
    printf( x509parse_cert_info( "      ", ssl.peer_cert ) );

    /*
     * 6. Write the GET request
     */
    printf( "  > Write to server:" );
    fflush( stdout );

    len = sprintf( (char *) buf, GET_REQUEST );

    while( ( ret = ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret != XYSSL_ERR_NET_TRY_AGAIN )
        {
            printf( " failed\n  ! ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    printf( " %d bytes written\n\n%s", len, (char *) buf );

    /*
     * 7. Read the HTTP response
     */
    printf( "  < Read from server:" );
    fflush( stdout );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = ssl_read( &ssl, buf, len );

        if( ret == XYSSL_ERR_NET_TRY_AGAIN )
            continue;

        if( ret == XYSSL_ERR_SSL_PEER_CLOSE_NOTIFY )
            break;

        if( ret <= 0 )
        {
            printf( "failed\n  ! ssl_read returned %d\n\n", ret );
            break;
        }

        len = ret;
        printf( " %d bytes read\n\n%s", len, (char *) buf );
    }
    while( 0 );

    ssl_close_notify( &ssl );

exit:

    net_close( server_fd );
    x509_free( &clicert );
    x509_free( &cacert );
    rsa_free( &rsa );
    ssl_free( &ssl );

    memset( &ssl, 0, sizeof( ssl ) );

#ifdef WIN32
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
