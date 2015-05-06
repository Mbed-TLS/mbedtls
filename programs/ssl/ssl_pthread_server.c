/*
 *  SSL server demonstration program using pthread for handling multiple
 *  clients.
 *
 *  Copyright (C) 2006-2013, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_CERTS_C) ||            \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_SSL_TLS_C) ||         \
    !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_NET_C) ||             \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_CTR_DRBG_C) ||            \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) ||      \
    !defined(MBEDTLS_THREADING_C) || !defined(MBEDTLS_THREADING_PTHREAD) || \
    !defined(MBEDTLS_PEM_PARSE_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_CERTS_C and/or MBEDTLS_ENTROPY_C "
           "and/or MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
           "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C and/or "
           "MBEDTLS_THREADING_C and/or MBEDTLS_THREADING_PTHREAD "
           "and/or MBEDTLS_PEM_PARSE_C not defined.\n");
    return( 0 );
}
#else

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

#define MAX_NUM_THREADS 5

mbedtls_threading_mutex_t debug_mutex;

static void my_mutexed_debug( void *ctx, int level, const char *str )
{
    mbedtls_mutex_lock( &debug_mutex );
    if( level < DEBUG_LEVEL )
    {
        mbedtls_fprintf( (FILE *) ctx, "%s", str );
        fflush(  (FILE *) ctx  );
    }
    mbedtls_mutex_unlock( &debug_mutex );
}

typedef struct {
    int client_fd;
    int thread_complete;
    mbedtls_entropy_context *entropy;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context *cache;
#endif
    mbedtls_x509_crt *ca_chain;
    mbedtls_x509_crt *server_cert;
    mbedtls_pk_context *server_key;
} thread_info_t;

typedef struct {
    int active;
    thread_info_t   data;
    pthread_t       thread;
} pthread_info_t;

static thread_info_t    base_info;
static pthread_info_t   threads[MAX_NUM_THREADS];

static void *handle_ssl_connection( void *data )
{
    int ret, len;
    thread_info_t *thread_info = (thread_info_t *) data;
    int client_fd = thread_info->client_fd;
    int thread_id = (int) pthread_self();
    unsigned char buf[1024];
    char pers[50];
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;

    /* Make sure memory references are valid */
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_snprintf( pers, sizeof(pers), "SSL Pthread Thread %d", thread_id );
    mbedtls_printf( "  [ #%d ]  Client FD %d\n", thread_id, client_fd );
    mbedtls_printf( "  [ #%d ]  Seeding the random number generator...\n", thread_id );

    /* mbedtls_entropy_func() is thread-safe if MBEDTLS_THREADING_C is set
     */
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, thread_info->entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( "  [ #%d ]  failed: mbedtls_ctr_drbg_seed returned -0x%04x\n",
                thread_id, -ret );
        goto thread_exit;
    }

    mbedtls_printf( "  [ #%d ]  ok\n", thread_id );

    /*
     * 4. Setup stuff
     */
    mbedtls_printf( "  [ #%d ]  Setting up the SSL data....\n", thread_id );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM ) ) != 0 )
    {
        mbedtls_printf( "  [ #%d ]  failed: mbedtls_ssl_config_defaults returned -0x%04x\n",
                thread_id, -ret );
        goto thread_exit;
    }

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( "  [ #%d ]  failed: mbedtls_ssl_setup returned -0x%04x\n",
                thread_id, -ret );
        goto thread_exit;
    }

    mbedtls_ssl_set_rng( &ssl, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_set_dbg( &conf, my_mutexed_debug, stdout );

    /* mbedtls_ssl_cache_get() and mbedtls_ssl_cache_set() are thread-safe if
     * MBEDTLS_THREADING_C is set.
     */
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_set_session_cache( &conf,
                                   mbedtls_ssl_cache_get, thread_info->cache,
                                   mbedtls_ssl_cache_set, thread_info->cache );
#endif

    mbedtls_ssl_set_ca_chain( &conf, thread_info->ca_chain, NULL );
    if( ( ret = mbedtls_ssl_set_own_cert( &ssl, thread_info->server_cert, thread_info->server_key ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_set_own_cert returned %d\n\n", ret );
        goto thread_exit;
    }

    mbedtls_printf( "  [ #%d ]  ok\n", thread_id );

    mbedtls_ssl_set_bio( &ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    mbedtls_printf( "  [ #%d ]  ok\n", thread_id );

    /*
     * 5. Handshake
     */
    mbedtls_printf( "  [ #%d ]  Performing the SSL/TLS handshake\n", thread_id );

    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_NET_WANT_READ && ret != MBEDTLS_ERR_NET_WANT_WRITE )
        {
            mbedtls_printf( "  [ #%d ]  failed: mbedtls_ssl_handshake returned -0x%04x\n",
                    thread_id, -ret );
            goto thread_exit;
        }
    }

    mbedtls_printf( "  [ #%d ]  ok\n", thread_id );

    /*
     * 6. Read the HTTP Request
     */
    mbedtls_printf( "  [ #%d ]  < Read from client\n", thread_id );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &ssl, buf, len );

        if( ret == MBEDTLS_ERR_NET_WANT_READ || ret == MBEDTLS_ERR_NET_WANT_WRITE )
            continue;

        if( ret <= 0 )
        {
            switch( ret )
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf( "  [ #%d ]  connection was closed gracefully\n",
                            thread_id );
                    goto thread_exit;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf( "  [ #%d ]  connection was reset by peer\n",
                            thread_id );
                    goto thread_exit;

                default:
                    mbedtls_printf( "  [ #%d ]  mbedtls_ssl_read returned -0x%04x\n",
                            thread_id, -ret );
                    goto thread_exit;
            }
        }

        len = ret;
        mbedtls_printf( "  [ #%d ]  %d bytes read\n=====\n%s\n=====\n",
                thread_id, len, (char *) buf );

        if( ret > 0 )
            break;
    }
    while( 1 );

    /*
     * 7. Write the 200 Response
     */
    mbedtls_printf( "  [ #%d ]  > Write to client:\n", thread_id );

    len = sprintf( (char *) buf, HTTP_RESPONSE,
                   mbedtls_ssl_get_ciphersuite( &ssl ) );

    while( ( ret = mbedtls_ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret == MBEDTLS_ERR_NET_CONN_RESET )
        {
            mbedtls_printf( "  [ #%d ]  failed: peer closed the connection\n",
                    thread_id );
            goto thread_exit;
        }

        if( ret != MBEDTLS_ERR_NET_WANT_READ && ret != MBEDTLS_ERR_NET_WANT_WRITE )
        {
            mbedtls_printf( "  [ #%d ]  failed: mbedtls_ssl_write returned -0x%04x\n",
                    thread_id, ret );
            goto thread_exit;
        }
    }

    len = ret;
    mbedtls_printf( "  [ #%d ]  %d bytes written\n=====\n%s\n=====\n",
            thread_id, len, (char *) buf );

    mbedtls_printf( "  [ #%d ]  . Closing the connection...", thread_id );

    while( ( ret = mbedtls_ssl_close_notify( &ssl ) ) < 0 )
    {
        if( ret != MBEDTLS_ERR_NET_WANT_READ &&
            ret != MBEDTLS_ERR_NET_WANT_WRITE )
        {
            mbedtls_printf( "  [ #%d ]  failed: mbedtls_ssl_close_notify returned -0x%04x\n",
                    thread_id, ret );
            goto thread_exit;
        }
    }

    mbedtls_printf( " ok\n" );

    ret = 0;

thread_exit:

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("  [ #%d ]  Last error was: -0x%04x - %s\n\n",
               thread_id, -ret, error_buf );
    }
#endif

    mbedtls_net_close( client_fd );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );

    thread_info->thread_complete = 1;

    return( NULL );
}

static int thread_create( int client_fd )
{
    int ret, i;

    /*
     * Find in-active or finished thread slot
     */
    for( i = 0; i < MAX_NUM_THREADS; i++ )
    {
        if( threads[i].active == 0 )
            break;

        if( threads[i].data.thread_complete == 1 )
        {
            mbedtls_printf( "  [ main ]  Cleaning up thread %d\n", i );
            pthread_join(threads[i].thread, NULL );
            memset( &threads[i], 0, sizeof(pthread_info_t) );
            break;
        }
    }

    if( i == MAX_NUM_THREADS )
        return( -1 );

    /*
     * Fill thread-info for thread
     */
    memcpy( &threads[i].data, &base_info, sizeof(base_info) );
    threads[i].active = 1;
    threads[i].data.client_fd = client_fd;

    if( ( ret = pthread_create( &threads[i].thread, NULL, handle_ssl_connection,                                &threads[i].data ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

int main( void )
{
    int ret;
    int listen_fd;
    int client_fd = -1;

    mbedtls_entropy_context entropy;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[100000];
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init( &cache );
    base_info.cache = &cache;
#endif

    memset( threads, 0, sizeof(threads) );

    mbedtls_mutex_init( &debug_mutex );

    /*
     * We use only a single entropy source that is used in all the threads.
     */
    mbedtls_entropy_init( &entropy );
    base_info.entropy = &entropy;

    /*
     * 1. Load the certificates and private RSA key
     */
    mbedtls_printf( "\n  . Loading the server cert. and key..." );
    fflush( stdout );

    mbedtls_x509_crt_init( &srvcert );

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                          mbedtls_test_srv_crt_len );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_pk_init( &pkey );
    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key,
                         mbedtls_test_srv_key_len, NULL, 0 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        goto exit;
    }

    base_info.ca_chain = srvcert.next;
    base_info.server_cert = &srvcert;
    base_info.server_key = &pkey;

    mbedtls_printf( " ok\n" );

    /*
     * 2. Setup the listening TCP socket
     */
    mbedtls_printf( "  . Bind on https://localhost:4433/ ..." );
    fflush( stdout );

    if( ( ret = mbedtls_net_bind( &listen_fd, NULL, 4433, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

reset:
#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf( "  [ main ]  Last error was: -0x%04x - %s\n", -ret, error_buf );
    }
#endif

    /*
     * 3. Wait until a client connects
     */
    client_fd = -1;

    mbedtls_printf( "  [ main ]  Waiting for a remote connection\n" );

    if( ( ret = mbedtls_net_accept( listen_fd, &client_fd, NULL ) ) != 0 )
    {
        mbedtls_printf( "  [ main ] failed: mbedtls_net_accept returned -0x%04x\n", ret );
        goto exit;
    }

    mbedtls_printf( "  [ main ]  ok\n" );
    mbedtls_printf( "  [ main ]  Creating a new thread\n" );

    if( ( ret = thread_create( client_fd ) ) != 0 )
    {
        mbedtls_printf( "  [ main ]  failed: thread_create returned %d\n", ret );
        mbedtls_net_close( client_fd );
        goto reset;
    }

    ret = 0;
    goto reset;

exit:
    mbedtls_x509_crt_free( &srvcert );
    mbedtls_pk_free( &pkey );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free( &cache );
#endif
    mbedtls_entropy_free( &entropy );

    mbedtls_mutex_free( &debug_mutex );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_free();
#endif

#if defined(_WIN32)
    mbedtls_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_CERTS_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C &&
          MBEDTLS_RSA_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_THREADING_C &&
          MBEDTLS_THREADING_PTHREAD && MBEDTLS_PEM_PARSE_C */
