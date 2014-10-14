/*
 *  Simple DTLS client demonstration program
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

#if !defined(POLARSSL_SSL_CLI_C) || !defined(POLARSSL_SSL_PROTO_DTLS) ||    \
    !defined(POLARSSL_NET_C) ||                                             \
    !defined(POLARSSL_ENTROPY_C) || !defined(POLARSSL_CTR_DRBG_C) ||        \
    !defined(POLARSSL_X509_CRT_PARSE_C) || !defined(POLARSSL_RSA_C) ||      \
    !defined(POLARSSL_CERTS_C)

#include <stdio.h>
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    printf( "POLARSSL_SSL_CLI_C and/or POLARSSL_SSL_PROTO_DTLS and/or "
            "POLARSSL_NET_C and/or "
            "POLARSSL_ENTROPY_C and/or POLARSSL_CTR_DRBG_C and/or "
            "POLARSSL_X509_CRT_PARSE_C and/or POLARSSL_RSA_C and/or "
            "POLARSSL_CERTS_C not defined.\n" );
    return( 0 );
}
#else

#include <string.h>
#include <stdio.h>

#include "polarssl/net.h"
#include "polarssl/debug.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/error.h"
#include "polarssl/certs.h"

#define SERVER_PORT 4433
#define SERVER_NAME "localhost"
#define SERVER_ADDR "127.0.0.1" /* forces IPv4 */
#define MESSAGE     "Echo this"

#define READ_TIMEOUT_MS 1000
#define MAX_RETRY       5

#define DEBUG_LEVEL 0

static void my_debug( void *ctx, int level, const char *str )
{
    ((void) level);

    fprintf( (FILE *) ctx, "%s", str );
    fflush(  (FILE *) ctx  );
}

int main( int argc, char *argv[] )
{
    int ret, len, server_fd = -1;
    unsigned char buf[1024];
    const char *pers = "dtls_client";
    int retry_left = MAX_RETRY;

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    ssl_context ssl;
    x509_crt cacert;

    ((void) argc);
    ((void) argv);

#if defined(POLARSSL_DEBUG_C)
    debug_set_threshold( DEBUG_LEVEL );
#endif

    /*
     * 0. Initialize the RNG and the session data
     */
    memset( &ssl, 0, sizeof( ssl_context ) );
    x509_crt_init( &cacert );

    printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 0. Initialize certificates
     */
    printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );

#if defined(POLARSSL_CERTS_C)
    ret = x509_crt_parse( &cacert, (const unsigned char *) test_ca_list,
                          strlen( test_ca_list ) );
#else
    ret = 1;
    printf("POLARSSL_CERTS_C not defined.");
#endif

    if( ret < 0 )
    {
        printf( " failed\n  !  x509_crt_parse returned -0x%x\n\n", -ret );
        goto exit;
    }

    printf( " ok (%d skipped)\n", ret );

    /*
     * 1. Start the connection
     */
    printf( "  . Connecting to udp/%s/%4d...", SERVER_NAME,
                                               SERVER_PORT );
    fflush( stdout );

    if( ( ret = net_connect( &server_fd, SERVER_ADDR,
                                         SERVER_PORT, NET_PROTO_UDP ) ) != 0 )
    {
        printf( " failed\n  ! net_connect returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 2. Setup stuff
     */
    printf( "  . Setting up the DTLS structure..." );
    fflush( stdout );

    if( ( ret = ssl_init( &ssl ) ) != 0 )
    {
        printf( " failed\n  ! ssl_init returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    ssl_set_endpoint( &ssl, SSL_IS_CLIENT );
    ssl_set_transport( &ssl, SSL_TRANSPORT_DATAGRAM );

    /* OPTIONAL is usually a bad choice for security, but makes interop easier
     * in this simplified example, in which the ca chain is hardcoded.
     * Production code should set a proper ca chain and use REQUIRED. */
    ssl_set_authmode( &ssl, SSL_VERIFY_OPTIONAL );
    ssl_set_ca_chain( &ssl, &cacert, NULL, SERVER_NAME );

    ssl_set_rng( &ssl, ctr_drbg_random, &ctr_drbg );
    ssl_set_dbg( &ssl, my_debug, stdout );

    ssl_set_bio_timeout( &ssl, &server_fd,
                         net_send, net_recv, net_recv_timeout,
                         READ_TIMEOUT_MS );

    /*
     * 4. Handshake
     */
    printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    do ret = ssl_handshake( &ssl );
    while( ret == POLARSSL_ERR_NET_WANT_READ ||
           ret == POLARSSL_ERR_NET_WANT_WRITE );

    if( ret != 0 )
    {
        printf( " failed\n  ! ssl_handshake returned -0x%x\n\n", -ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 5. Verify the server certificate
     */
    printf( "  . Verifying peer X.509 certificate..." );

    /* In real life, we would have used SSL_VERIFY_REQUIRED so that the
     * handshake would not succeed if the peer's cert is bad.  Even if we used
     * SSL_VERIFY_OPTIONAL, we would bail out here if ret != 0 */
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

    /*
     * 6. Write the echo request
     */
send_request:
    printf( "  > Write to server:" );
    fflush( stdout );

    len = sizeof( MESSAGE ) - 1;

    do ret = ssl_write( &ssl, (unsigned char *) MESSAGE, len );
    while( ret == POLARSSL_ERR_NET_WANT_READ ||
           ret == POLARSSL_ERR_NET_WANT_WRITE );

    if( ret < 0 )
    {
        printf( " failed\n  ! ssl_write returned %d\n\n", ret );
        goto exit;
    }

    len = ret;
    printf( " %d bytes written\n\n%s\n\n", len, MESSAGE );

    /*
     * 7. Read the echo response
     */
    printf( "  < Read from server:" );
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
                if( retry_left-- > 0 )
                    goto send_request;
                goto exit;

            case POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY:
                printf( " connection was closed gracefully\n" );
                ret = 0;
                goto close_notify;

            default:
                printf( " ssl_read returned -0x%x\n\n", -ret );
                goto exit;
        }
    }

    len = ret;
    printf( " %d bytes read\n\n%s\n\n", len, buf );

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

    /*
     * 9. Final clean-ups and exit
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

    if( server_fd != -1 )
        net_close( server_fd );

    x509_crt_free( &cacert );
    ssl_free( &ssl );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#if defined(_WIN32)
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    /* Shell can not handle large exit numbers -> 1 for errors */
    if( ret < 0 )
        ret = 1;

    return( ret );
}
#endif /* POLARSSL_SSL_CLI_C && POLARSSL_SSL_PROTO_DTLS && POLARSSL_NET_C &&
          POLARSSL_ENTROPY_C && POLARSSL_CTR_DRBG_C &&
          POLARSSL_X509_CRT_PARSE_C && POLARSSL_RSA_C && POLARSSL_CERTS_C */
