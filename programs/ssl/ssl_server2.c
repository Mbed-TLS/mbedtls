/*
 *  SSL client with options
 *
 *  Copyright (C) 2006-2012, Brainspark B.V.
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

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "polarssl/config.h"

#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/error.h"

#define DFL_SERVER_PORT         4433
#define DFL_REQUEST_PAGE        "/"
#define DFL_DEBUG_LEVEL         0
#define DFL_CA_FILE             ""
#define DFL_CA_PATH             ""
#define DFL_CRT_FILE            ""
#define DFL_KEY_FILE            ""
#define DFL_FORCE_CIPHER        0
#define DFL_RENEGOTIATION       SSL_RENEGOTIATION_ENABLED
#define DFL_ALLOW_LEGACY        SSL_LEGACY_NO_RENEGOTIATION

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>PolarSSL Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

/*
 * Computing a "safe" DH-1024 prime can take a very
 * long time, so a precomputed value is provided below.
 * You may run dh_genprime to generate a new value.
 */
char *my_dhm_P =
    "E4004C1F94182000103D883A448B3F80" \
    "2CE4B44A83301270002C20D0321CFD00" \
    "11CCEF784C26A400F43DFB901BCA7538" \
    "F2C6B176001CF5A0FD16D2C48B1D0C1C" \
    "F6AC8E1DA6BCC3B4E1F96B0564965300" \
    "FFA1D0B601EB2800F489AA512C4B248C" \
    "01F76949A60BB7F00A40B1EAB64BDD48" \
    "E8A700D60B7F1200FA8E77B0A979DABF";

char *my_dhm_G = "4";

/*
 * global options
 */
struct options
{
    int server_port;            /* port on which the ssl service runs       */
    int debug_level;            /* level of debugging                       */
    char *ca_file;              /* the file with the CA certificate(s)      */
    char *ca_path;              /* the path with the CA certificate(s) reside */
    char *crt_file;             /* the file with the client certificate     */
    char *key_file;             /* the file with the client key             */
    int force_ciphersuite[2];   /* protocol/ciphersuite to use, or all      */
    int renegotiation;          /* enable / disable renegotiation           */
    int allow_legacy;           /* allow legacy renegotiation               */
} opt;

void my_debug( void *ctx, int level, const char *str )
{
    if( level < opt.debug_level )
    {
        fprintf( (FILE *) ctx, "%s", str );
        fflush(  (FILE *) ctx  );
    }
}

/*
 * These session callbacks use a simple chained list
 * to store and retrieve the session information.
 */
ssl_session *s_list_1st = NULL;
ssl_session *cur, *prv;

static int my_get_session( ssl_context *ssl )
{
    time_t t = time( NULL );

    if( ssl->resume == 0 )
        return( 1 );

    cur = s_list_1st;
    prv = NULL;

    while( cur != NULL )
    {
        prv = cur;
        cur = cur->next;

        if( ssl->timeout != 0 && (int) ( t - prv->start ) > ssl->timeout )
            continue;

        if( ssl->session->ciphersuite != prv->ciphersuite ||
            ssl->session->length != prv->length )
            continue;

        if( memcmp( ssl->session->id, prv->id, prv->length ) != 0 )
            continue;

        memcpy( ssl->session->master, prv->master, 48 );
        return( 0 );
    }

    return( 1 );
}

static int my_set_session( ssl_context *ssl )
{
    time_t t = time( NULL );

    cur = s_list_1st;
    prv = NULL;

    while( cur != NULL )
    {
        if( ssl->timeout != 0 && (int) ( t - cur->start ) > ssl->timeout )
            break; /* expired, reuse this slot */

        if( memcmp( ssl->session->id, cur->id, cur->length ) == 0 )
            break; /* client reconnected */

        prv = cur;
        cur = cur->next;
    }

    if( cur == NULL )
    {
        cur = (ssl_session *) malloc( sizeof( ssl_session ) );
        if( cur == NULL )
            return( 1 );

        if( prv == NULL )
              s_list_1st = cur;
        else  prv->next  = cur;
    }

    memcpy( cur, ssl->session, sizeof( ssl_session ) );

    return( 0 );
}

#if defined(POLARSSL_FS_IO)
#define USAGE_IO \
    "    ca_file=%%s          default: \"\" (pre-loaded)\n" \
    "    ca_path=%%s          default: \"\" (pre-loaded) (overrides ca_file)\n" \
    "    crt_file=%%s         default: \"\" (pre-loaded)\n" \
    "    key_file=%%s         default: \"\" (pre-loaded)\n"
#else
#define USAGE_IO \
    "    No file operations available (POLARSSL_FS_IO not defined)\n"
#endif /* POLARSSL_FS_IO */

#define USAGE \
    "\n usage: ssl_server2 param=<>...\n"                   \
    "\n acceptable parameters:\n"                           \
    "    server_port=%%d      default: 4433\n"              \
    "    debug_level=%%d      default: 0 (disabled)\n"      \
    USAGE_IO                                                \
    "    request_page=%%s     default: \".\"\n"             \
    "    renegotiation=%%d    default: 1 (enabled)\n"       \
    "    allow_legacy=%%d     default: 0 (disabled)\n"      \
    "    force_ciphersuite=<name>    default: all enabled\n"\
    " acceptable ciphersuite names:\n"

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_ENTROPY_C) ||  \
    !defined(POLARSSL_SSL_TLS_C) || !defined(POLARSSL_SSL_SRV_C) || \
    !defined(POLARSSL_NET_C) || !defined(POLARSSL_RSA_C) ||         \
    !defined(POLARSSL_CTR_DRBG_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    printf("POLARSSL_BIGNUM_C and/or POLARSSL_ENTROPY_C and/or "
           "POLARSSL_SSL_TLS_C and/or POLARSSL_SSL_SRV_C and/or "
           "POLARSSL_NET_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    int ret = 0, len;
    int listen_fd;
    int client_fd = -1;
    unsigned char buf[1024];
    char *pers = "ssl_server2";

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    ssl_context ssl;
    ssl_session ssn;
    x509_cert cacert;
    x509_cert srvcert;
    rsa_context rsa;

    int i;
    size_t j, n;
    char *p, *q;
    const int *list;

    /*
     * Make sure memory references are valid.
     */
    listen_fd = 0;
    memset( &ssn, 0, sizeof( ssl_session ) );
    memset( &ssl, 0, sizeof( ssl_context ) );
    memset( &cacert, 0, sizeof( x509_cert ) );
    memset( &srvcert, 0, sizeof( x509_cert ) );
    memset( &rsa, 0, sizeof( rsa_context ) );

    if( argc == 0 )
    {
    usage:
        if( ret == 0 )
            ret = 1;

        printf( USAGE );

        list = ssl_list_ciphersuites();
        while( *list )
        {
            printf("    %s\n", ssl_get_ciphersuite_name( *list ) );
            list++;
        }
        printf("\n");
        goto exit;
    }

    opt.server_port         = DFL_SERVER_PORT;
    opt.debug_level         = DFL_DEBUG_LEVEL;
    opt.ca_file             = DFL_CA_FILE;
    opt.ca_path             = DFL_CA_PATH;
    opt.crt_file            = DFL_CRT_FILE;
    opt.key_file            = DFL_KEY_FILE;
    opt.force_ciphersuite[0]= DFL_FORCE_CIPHER;
    opt.renegotiation       = DFL_RENEGOTIATION;
    opt.allow_legacy        = DFL_ALLOW_LEGACY;

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

        if( strcmp( p, "server_port" ) == 0 )
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
        else if( strcmp( p, "ca_file" ) == 0 )
            opt.ca_file = q;
        else if( strcmp( p, "ca_path" ) == 0 )
            opt.ca_path = q;
        else if( strcmp( p, "crt_file" ) == 0 )
            opt.crt_file = q;
        else if( strcmp( p, "key_file" ) == 0 )
            opt.key_file = q;
        else if( strcmp( p, "force_ciphersuite" ) == 0 )
        {
            opt.force_ciphersuite[0] = -1;

            opt.force_ciphersuite[0] = ssl_get_ciphersuite_id( q );

            if( opt.force_ciphersuite[0] <= 0 )
            {
                ret = 2;
                goto usage;
            }
            opt.force_ciphersuite[1] = 0;
        }
        else if( strcmp( p, "renegotiation" ) == 0 )
        {
            opt.renegotiation = (atoi( q )) ? SSL_RENEGOTIATION_ENABLED :
                                              SSL_RENEGOTIATION_DISABLED;
        }
        else if( strcmp( p, "allow_legacy" ) == 0 )
        {
            opt.allow_legacy = atoi( q );
            if( opt.allow_legacy < 0 || opt.allow_legacy > 1 )
                goto usage;
        }
        else
            goto usage;
    }

    /*
     * 0. Initialize the RNG and the session data
     */
    printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (unsigned char *) pers, strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! ctr_drbg_init returned -0x%x\n", -ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 1.1. Load the trusted CA
     */
    printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );

#if defined(POLARSSL_FS_IO)
    if( strlen( opt.ca_path ) )
        ret = x509parse_crtpath( &cacert, opt.ca_path );
    else if( strlen( opt.ca_file ) )
        ret = x509parse_crtfile( &cacert, opt.ca_file );
    else 
#endif
#if defined(POLARSSL_CERTS_C)
        ret = x509parse_crt( &cacert, (unsigned char *) test_ca_crt,
                strlen( test_ca_crt ) );
#else
    {
        ret = 1;
        printf("POLARSSL_CERTS_C not defined.");
    }
#endif
    if( ret < 0 )
    {
        printf( " failed\n  !  x509parse_crt returned -0x%x\n\n", -ret );
        goto exit;
    }

    printf( " ok (%d skipped)\n", ret );

    /*
     * 1.2. Load own certificate and private key
     */
    printf( "  . Loading the server cert. and key..." );
    fflush( stdout );

#if defined(POLARSSL_FS_IO)
    if( strlen( opt.crt_file ) )
        ret = x509parse_crtfile( &srvcert, opt.crt_file );
    else 
#endif
#if defined(POLARSSL_CERTS_C)
        ret = x509parse_crt( &srvcert, (unsigned char *) test_srv_crt,
                strlen( test_srv_crt ) );
#else
    {
        ret = 1;
        printf("POLARSSL_CERTS_C not defined.");
    }
#endif
    if( ret != 0 )
    {
        printf( " failed\n  !  x509parse_crt returned -0x%x\n\n", -ret );
        goto exit;
    }

#if defined(POLARSSL_FS_IO)
    if( strlen( opt.key_file ) )
        ret = x509parse_keyfile( &rsa, opt.key_file, "" );
    else
#endif
#if defined(POLARSSL_CERTS_C)
        ret = x509parse_key( &rsa, (unsigned char *) test_srv_key,
                strlen( test_srv_key ), NULL, 0 );
#else
    {
        ret = 1;
        printf("POLARSSL_CERTS_C not defined.");
    }
#endif
    if( ret != 0 )
    {
        printf( " failed\n  !  x509parse_key returned -0x%x\n\n", -ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 2. Setup the listening TCP socket
     */
    printf( "  . Bind on tcp://localhost:%-4d/ ...", opt.server_port );
    fflush( stdout );

    if( ( ret = net_bind( &listen_fd, NULL, opt.server_port ) ) != 0 )
    {
        printf( " failed\n  ! net_bind returned -0x%x\n\n", -ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * 3. Setup stuff
     */
    printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );

    if( ( ret = ssl_init( &ssl ) ) != 0 )
    {
        printf( " failed\n  ! ssl_init returned -0x%x\n\n", -ret );
        goto exit;
    }

    ssl_set_endpoint( &ssl, SSL_IS_SERVER );
    ssl_set_authmode( &ssl, SSL_VERIFY_NONE );

    ssl_set_rng( &ssl, ctr_drbg_random, &ctr_drbg );
    ssl_set_dbg( &ssl, my_debug, stdout );

    ssl_set_scb( &ssl, my_get_session,
                       my_set_session );

    if( opt.force_ciphersuite[0] == DFL_FORCE_CIPHER )
        ssl_set_ciphersuites( &ssl, ssl_default_ciphersuites );
    else
        ssl_set_ciphersuites( &ssl, opt.force_ciphersuite );

    ssl_set_renegotiation( &ssl, opt.renegotiation );
    ssl_legacy_renegotiation( &ssl, opt.allow_legacy );

    ssl_set_session( &ssl, 1, 0, &ssn );

    ssl_set_ca_chain( &ssl, &cacert, NULL, NULL );
    ssl_set_own_cert( &ssl, &srvcert, &rsa );

#if defined(POLARSSL_DHM_C)
    ssl_set_dh_param( &ssl, my_dhm_P, my_dhm_G );
#endif

    printf( " ok\n" );

reset:
#ifdef POLARSSL_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        error_strerror( ret, error_buf, 100 );
        printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    if( client_fd != -1 )
        net_close( client_fd );

    ssl_session_reset( &ssl );

    /*
     * 3. Wait until a client connects
     */
#if defined(_WIN32_WCE)
    {
        SHELLEXECUTEINFO sei;

        ZeroMemory( &sei, sizeof( SHELLEXECUTEINFO ) );

        sei.cbSize = sizeof( SHELLEXECUTEINFO );
        sei.fMask = 0;
        sei.hwnd = 0;
        sei.lpVerb = _T( "open" );
        sei.lpFile = _T( "https://localhost:4433/" );
        sei.lpParameters = NULL;
        sei.lpDirectory = NULL;
        sei.nShow = SW_SHOWNORMAL;

        ShellExecuteEx( &sei );
    }
#elif defined(_WIN32)
    ShellExecute( NULL, "open", "https://localhost:4433/",
                  NULL, NULL, SW_SHOWNORMAL );
#endif

    client_fd = -1;

    printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );

    if( ( ret = net_accept( listen_fd, &client_fd, NULL ) ) != 0 )
    {
        printf( " failed\n  ! net_accept returned -0x%x\n\n", -ret );
        goto exit;
    }

    ssl_set_bio( &ssl, net_recv, &client_fd,
                       net_send, &client_fd );

    printf( " ok\n" );

    /*
     * 4. Handshake
     */
    printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            printf( " failed\n  ! ssl_handshake returned -0x%x\n\n", -ret );
            goto exit;
        }
    }

    printf( " ok\n    [ Ciphersuite is %s ]\n",
            ssl_get_ciphersuite( &ssl ) );

    /*
     * 5. Verify the server certificate
     */
    printf( "  . Verifying peer X.509 certificate..." );

    if( ( ret = ssl_get_verify_result( &ssl ) ) != 0 )
    {
        printf( " failed\n" );

        if( !ssl.session->peer_cert )
            printf( "  ! no client certificate sent\n" );

        if( ( ret & BADCERT_EXPIRED ) != 0 )
            printf( "  ! client certificate has expired\n" );

        if( ( ret & BADCERT_REVOKED ) != 0 )
            printf( "  ! client certificate has been revoked\n" );

        if( ( ret & BADCERT_NOT_TRUSTED ) != 0 )
            printf( "  ! self-signed or not signed by a trusted CA\n" );

        printf( "\n" );
    }
    else
        printf( " ok\n" );

    if( ssl.session->peer_cert )
    {
        printf( "  . Peer certificate information    ...\n" );
        x509parse_cert_info( (char *) buf, sizeof( buf ) - 1, "      ",
                             ssl.session->peer_cert );
        printf( "%s\n", buf );
    }

    /*
     * 6. Read the HTTP Request
     */
    printf( "  < Read from client:" );
    fflush( stdout );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = ssl_read( &ssl, buf, len );

        if( ret == POLARSSL_ERR_NET_WANT_READ || ret == POLARSSL_ERR_NET_WANT_WRITE )
            continue;

        if( ret <= 0 )
        {
            switch( ret )
            {
                case POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY:
                    printf( " connection was closed gracefully\n" );
                    break;

                case POLARSSL_ERR_NET_CONN_RESET:
                    printf( " connection was reset by peer\n" );
                    break;

                default:
                    printf( " ssl_read returned -0x%x\n", -ret );
                    break;
            }

            break;
        }

        len = ret;
        printf( " %d bytes read\n\n%s", len, (char *) buf );

        if( ret > 0 )
            break;
    }
    while( 1 );

    /*
     * 7. Write the 200 Response
     */
    printf( "  > Write to client:" );
    fflush( stdout );

    len = sprintf( (char *) buf, HTTP_RESPONSE,
                   ssl_get_ciphersuite( &ssl ) );

    while( ( ret = ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret == POLARSSL_ERR_NET_CONN_RESET )
        {
            printf( " failed\n  ! peer closed the connection\n\n" );
            goto reset;
        }

        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            printf( " failed\n  ! ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    printf( " %d bytes written\n\n%s\n", len, (char *) buf );

    ret = 0;
    goto reset;

exit:

#ifdef POLARSSL_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        error_strerror( ret, error_buf, 100 );
        printf("Last error was: -0x%X - %s\n\n", -ret, error_buf );
    }
#endif

    net_close( client_fd );
    x509_free( &srvcert );
    x509_free( &cacert );
    rsa_free( &rsa );
    ssl_session_free( &ssn );
    ssl_session_free( s_list_1st );
    ssl_free( &ssl );

#if defined(_WIN32)
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_ENTROPY_C && POLARSSL_SSL_TLS_C &&
          POLARSSL_SSL_SRV_C && POLARSSL_NET_C && POLARSSL_RSA_C &&
          POLARSSL_CTR_DRBG_C */
