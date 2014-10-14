/*
 *  Simple DTLS server demonstration program
 *
 *  Copyright (C) 2014, Brainspark B.V.
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

#if !defined(POLARSSL_SSL_SRV_C) || !defined(POLARSSL_SSL_PROTO_DTLS) ||    \
    !defined(POLARSSL_SSL_COOKIE_C) || !defined(POLARSSL_NET_C) ||          \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_CTR_DRBG_C) ||        \
    !defined(POLARSSL_X509_CRT_PARSE_C) || !defined(POLARSSL_RSA_C) ||      \
    !defined(POLARSSL_CERTS_C)

#include <stdio.h>
int main( void )
{
    printf( "POLARSSL_SSL_SRV_C and/or POLARSSL_SSL_PROTO_DTLS and/or "
            "POLARSSL_SSL_COOKIE_C and/or POLARSSL_NET_C and/or "
            "POLARSSL_ENTROPY_C and/or POLARSSL_CTR_DRBG_C and/or "
            "POLARSSL_X509_CRT_PARSE_C and/or POLARSSL_RSA_C and/or "
            "POLARSSL_CERTS_C not defined.\n" );
    return( 0 );
}
#else

#if defined(_WIN32)
#include <windows.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/ssl.h"
#include "polarssl/ssl_cookie.h"
#include "polarssl/net.h"
#include "polarssl/error.h"
#include "polarssl/debug.h"

#if defined(POLARSSL_SSL_CACHE_C)
#include "polarssl/ssl_cache.h"
#endif

#define READ_TIMEOUT_MS 10000   /* 5 seconds */
#define DEBUG_LEVEL 0

static void my_debug( void *ctx, int level, const char *str )
{
    ((void) level);

    fprintf( (FILE *) ctx, "%s", str );
    fflush(  (FILE *) ctx  );
}

int main( void )
{
    int ret, len;
    int listen_fd;
    int client_fd = -1;
    unsigned char buf[1024];
    const char *pers = "dtls_server";
    unsigned char client_ip[16] = { 0 };
    ssl_cookie_ctx cookie_ctx;

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    ssl_context ssl;
    x509_crt srvcert;
    pk_context pkey;
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_context cache;
#endif

    memset( &ssl, 0, sizeof(ssl_context) );
    ssl_cookie_init( &cookie_ctx );
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_init( &cache );
#endif
    x509_crt_init( &srvcert );
    pk_init( &pkey );
    entropy_init( &entropy );

#if defined(POLARSSL_DEBUG_C)
    debug_set_threshold( DEBUG_LEVEL );
#endif

    /*
     * 1. Load the certificates and private RSA key
     */
    printf( "\n  . Loading the server cert. and key..." );
    fflush( stdout );

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use x509_crt_parse_file() to read the
     * server and CA certificates, as well as pk_parse_keyfile().
     */
    ret = x509_crt_parse( &srvcert, (const unsigned char *) test_srv_crt,
                          strlen( test_srv_crt ) );
    if( ret != 0 )
    {
        printf( " failed\n  !  x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret = x509_crt_parse( &srvcert, (const unsigned char *) test_ca_list,
                          strlen( test_ca_list ) );
    if( ret != 0 )
    {
        printf( " failed\n  !  x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret =  pk_parse_key( &pkey, (const unsigned char *) test_srv_key,
                         strlen( test_srv_key ), NULL, 0 );
    if( ret != 0 )
    {
        printf( " failed\n  !  pk_parse_key returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 2. Setup the "listening" UDP socket
     */
    printf( "  . Bind on udp/*/4433 ..." );
    fflush( stdout );

    if( ( ret = net_bind( &listen_fd, NULL, 4433, NET_PROTO_UDP ) ) != 0 )
    {
        printf( " failed\n  ! net_bind returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 3. Seed the RNG
     */
    printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 4. Setup stuff
     */
    printf( "  . Setting up the DTLS data..." );
    fflush( stdout );

    if( ( ret = ssl_init( &ssl ) ) != 0 )
    {
        printf( " failed\n  ! ssl_init returned %d\n\n", ret );
        goto exit;
    }

    ssl_set_endpoint( &ssl, SSL_IS_SERVER );
    ssl_set_transport( &ssl, SSL_TRANSPORT_DATAGRAM );
    ssl_set_authmode( &ssl, SSL_VERIFY_NONE );

    ssl_set_rng( &ssl, ctr_drbg_random, &ctr_drbg );
    ssl_set_dbg( &ssl, my_debug, stdout );

#if defined(POLARSSL_SSL_CACHE_C)
    ssl_set_session_cache( &ssl, ssl_cache_get, &cache,
                                 ssl_cache_set, &cache );
#endif

    ssl_set_ca_chain( &ssl, srvcert.next, NULL, NULL );
    if( ( ret = ssl_set_own_cert( &ssl, &srvcert, &pkey ) ) != 0 )
    {
        printf( " failed\n  ! ssl_set_own_cert returned %d\n\n", ret );
        goto exit;
    }

    if( ( ret = ssl_cookie_setup( &cookie_ctx,
                                  ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! ssl_cookie_setup returned %d\n\n", ret );
        goto exit;
    }

    ssl_set_dtls_cookies( &ssl, ssl_cookie_write, ssl_cookie_check,
                               &cookie_ctx );

    printf( " ok\n" );

reset:
#ifdef POLARSSL_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        polarssl_strerror( ret, error_buf, 100 );
        printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    if( client_fd != -1 )
        net_close( client_fd );

    ssl_session_reset( &ssl );

    /*
     * 3. Wait until a client connects
     */
    client_fd = -1;

    printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );

    if( ( ret = net_accept( listen_fd, &client_fd, client_ip ) ) != 0 )
    {
        printf( " failed\n  ! net_accept returned %d\n\n", ret );
        goto exit;
    }

    /* With UDP, bind_fd is hijacked by client_fd, so bind a new one */
    if( ( ret = net_bind( &listen_fd, NULL, 4433, NET_PROTO_UDP ) ) != 0 )
    {
        printf( " failed\n  ! net_bind returned -0x%x\n\n", -ret );
        goto exit;
    }

    /* For HelloVerifyRequest cookies */
    if( ( ret = ssl_set_client_transport_id( &ssl, client_ip,
                                           sizeof( client_ip ) ) ) != 0 )
    {
        printf( " failed\n  ! "
                "ssl_set_client_tranport_id() returned -0x%x\n\n", -ret );
        goto exit;
    }

    ssl_set_bio_timeout( &ssl, &client_fd,
                         net_send, net_recv, net_recv_timeout,
                         READ_TIMEOUT_MS );

    printf( " ok\n" );

    /*
     * 5. Handshake
     */
    printf( "  . Performing the DTLS handshake..." );
    fflush( stdout );

    do ret = ssl_handshake( &ssl );
    while( ret == POLARSSL_ERR_NET_WANT_READ ||
           ret == POLARSSL_ERR_NET_WANT_WRITE );

    if( ret == POLARSSL_ERR_SSL_HELLO_VERIFY_REQUIRED )
    {
        printf( " hello verification requested\n" );
        ret = 0;
        goto reset;
    }
    else if( ret != 0 )
    {
        printf( " failed\n  ! ssl_handshake returned -0x%x\n\n", -ret );
        goto reset;
    }

    printf( " ok\n" );

    /*
     * 6. Read the echo Request
     */
    printf( "  < Read from client:" );
    fflush( stdout );

    len = sizeof( buf ) - 1;
    memset( buf, 0, sizeof( buf ) );

    do ret = ssl_read( &ssl, buf, len );
    while( ret == POLARSSL_ERR_NET_WANT_READ ||
           ret == POLARSSL_ERR_NET_WANT_WRITE );

    if( ret <= 0 )
    {
        switch( ret )
        {
            case POLARSSL_ERR_NET_TIMEOUT:
                printf( " timeout\n\n" );
                goto reset;

            case POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY:
                printf( " connection was closed gracefully\n" );
                ret = 0;
                goto close_notify;

            default:
                printf( " ssl_read returned -0x%x\n\n", -ret );
                goto reset;
        }
    }

    len = ret;
    printf( " %d bytes read\n\n%s\n\n", len, buf );

    /*
     * 7. Write the 200 Response
     */
    printf( "  > Write to client:" );
    fflush( stdout );

    do ret = ssl_write( &ssl, buf, len );
    while( ret == POLARSSL_ERR_NET_WANT_READ ||
           ret == POLARSSL_ERR_NET_WANT_WRITE );

    if( ret < 0 )
    {
        printf( " failed\n  ! ssl_write returned %d\n\n", ret );
        goto exit;
    }

    len = ret;
    printf( " %d bytes written\n\n%s\n\n", len, buf );

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    printf( "  . Closing the connection..." );

    /* No error checking, the connection might be closed already */
    do ret = ssl_close_notify( &ssl );
    while( ret == POLARSSL_ERR_NET_WANT_WRITE );
    ret = 0;

    printf( " done\n" );

    goto reset;

    /*
     * Final clean-ups and exit
     */
exit:

#ifdef POLARSSL_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        polarssl_strerror( ret, error_buf, 100 );
        printf( "Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    if( client_fd != -1 )
        net_close( client_fd );

    x509_crt_free( &srvcert );
    pk_free( &pkey );
    ssl_free( &ssl );
    ssl_cookie_free( &cookie_ctx );
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_free( &cache );
#endif
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#if defined(_WIN32)
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    /* Shell can not handle large exit numbers -> 1 for errors */
    if( ret < 0 )
        ret = 1;

    return( ret );
}
#endif /* POLARSSL_SSL_SRV_C && POLARSSL_SSL_PROTO_DTLS &&
          POLARSSL_SSL_COOKIE_C && POLARSSL_NET_C && POLARSSL_ENTROPY_C &&
          POLARSSL_CTR_DRBG_C && POLARSSL_X509_CRT_PARSE_C && POLARSSL_RSA_C
          && POLARSSL_CERTS_C */
