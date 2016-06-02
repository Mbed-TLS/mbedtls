
/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

/*
 *
 * tls_server.c
 *
 *
 */


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_free       free
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define mbedtls_calloc     calloc
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#endif

#include <stdio.h>

#if !defined(MBEDTLS_ENTROPY_C) || \
!defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_SRV_C) || \
!defined(MBEDTLS_NET_C) || !defined(MBEDTLS_CTR_DRBG_C) || \
!defined(MBEDTLS_MILAGRO_CS_C) || !defined(MBEDTLS_MILAGRO_P2P_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_ENTROPY_C and/or "
                   "MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
                   "MBEDTLS_NET_C and/or MBEDTLS_CTR_DRBG_C and/or not defined.\n");
    return( 0 );
}
#else

#include <string.h>

#if !defined(_WIN32)
#include <signal.h>
#endif

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION) && defined(MBEDTLS_FS_IO)
#define SNI_OPTION
#endif

#if defined(_WIN32)
#include <windows.h>
#endif


#define DFL_SERVER_ADDR         NULL
#define DFL_SERVER_PORT         "4444"
#define DFL_DEBUG_LEVEL         1
#define DFL_NBIO                0
#define DFL_FORCE_CIPHER        49329
#define DFL_VERSION_SUITES      NULL
#define DFL_EXCHANGES           1
#define DFL_MIN_VERSION         MBEDTLS_SSL_MAJOR_VERSION_3
#define DFL_MAX_VERSION         MBEDTLS_SSL_MAJOR_VERSION_3
#define DFL_AUTH_MODE           -1
#define DFL_MFL_CODE            MBEDTLS_SSL_MAX_FRAG_LEN_NONE
#define DFL_TRANSPORT           MBEDTLS_SSL_TRANSPORT_STREAM

/*  packets (for fragmentation purposes) */
#define HTTP_RESPONSE \
    "\n   SERVER: Hi Client, yes very well!!!\n\n"

/*
 * Size of the basic I/O buffer. Able to hold our default response.
 *
 * You will need to adapt the mbedtls_ssl_get_bytes_avail() test in ssl-opt.sh
 * if you change this value to something outside the range <= 100 or > 500
 */
#define IO_BUF_LEN      200

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
#define USAGE_MAX_FRAG_LEN                                      \
    "    max_frag_len=%%d     default: 16384 (tls default)\n"   \
    "                        options: 512, 1024, 2048, 4096\n"
#else
#define USAGE_MAX_FRAG_LEN ""
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#define USAGE \
    "\n usage: tls_server param=<>...\n"                   \
    "\n acceptable parameters:\n"                           \
    "    server_addr=%%d      default: (all interfaces)\n"  \
    "    server_port=%%d      default: 4444\n"              \
    "    debug_level=%%d      default: 0 (disabled)\n"      \
    "    nbio=%%d             default: 0 (blocking I/O)\n"  \
    "                        options: 1 (non-blocking), 2 (added delays)\n" \
    "    force_ciphersuite=<name>"                          \
    " acceptable ciphersuite names:\n"                      \
    "            TLS-MILAGRO-CS-WITH-AES-128-GCM-SHA256\n"  \
    "            TLS-MILAGRO-CS-WITH-AES-128-GCM-SHA512\n"  \
    "            TLS-MILAGRO-CS-WITH-CAMELLIA-128-GCM-SHA256\n"  \
    "            TLS-MILAGRO-CS-WITH-CAMELLIA-128-GCM-SHA512\n"  \
    "            TLS-MILAGRO-CS-WITH-3DES-EDE-CBC-SHA256\n"  \
    "            TLS-MILAGRO-CS-WITH-3DES-EDE-CBC-SHA512\n"  \
    "            TLS-MILAGRO-CS-WITH-NULL-SHA256\n"         \
    "            TLS-MILAGRO-P2P-WITH-AES-128-GCM-SHA256\n" \
    "            TLS-MILAGRO-P2P-WITH-AES-128-GCM-SHA512\n" \
    "            TLS-MILAGRO-P2P-WITH-CAMELLIA-128-GCM-SHA256\n"  \
    "            TLS-MILAGRO-P2P-WITH-CAMELLIA-128-GCM-SHA512\n"  \
    "            TLS-MILAGRO-P2P-WITH-3DES-EDE-CBC-SHA256\n"  \
    "            TLS-MILAGRO-P2P-WITH-3DES-EDE-CBC-SHA512\n"  \
    "            TLS-MILAGRO-P2P-WITH-NULL-SHA256\n"         \
    "\n"                                                    \
    "\n"                                                    \
    "    exchanges=%%d        default: 1\n"                 \
    "\n"                                                    \
    USAGE_MAX_FRAG_LEN                                      \
    "\n"                                                    \
    "\n"                                                    \


/*
 * global options
 */
struct options
{
    const char *server_addr;    /* address on which the ssl service runs    */
    const char *server_port;    /* port on which the ssl service runs       */
    int debug_level;            /* level of debugging                       */
    int nbio;                   /* should I/O be blocking?                  */
    int force_ciphersuite[2];   /* protocol/ciphersuite to use, or all      */
    const char *version_suites; /* per-version ciphersuites                 */
    int exchanges;              /* number of data exchanges                 */
    int min_version;            /* minimum protocol version accepted        */
    int max_version;            /* maximum protocol version accepted        */
    int auth_mode;              /* verify mode for connection               */
    unsigned char mfl_code;     /* code for maximum fragment length         */
    int transport;              /* TLS as default (no DTLS)                 */
} opt;


int read_from_file(const char* path, char* secret, int len_secret){
    char hex[len_secret];
    int tmp=0;
    unsigned int i=0;
    FILE* file = fopen(path,"r");
    if(!file)
    {
        printf("Secret file is missing\n");
        exit(-1);
    }

    
    fscanf(file,"%[^\n]",hex);
    fclose(file);

    for (i = 0; i < strlen(hex)/2; i++){
        sscanf(&hex[i * 2], "%02x", &tmp);
        secret[i] = tmp;
    }
    secret[(strlen(hex)/2)+1] = 0;
    
    return 0;
}


static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    const char *p, *basename;

    /* Extract basename from file */
    for( p = basename = file; *p != '\0'; p++ )
        if( *p == '/' || *p == '\\' )
            basename = p + 1;

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: |%d| %s", basename, line, level, str );
    fflush(  (FILE *) ctx  );
}

/*
 * Test recv/send functions that make sure each try returns
 * WANT_READ/WANT_WRITE at least once before sucesseding
 */
static int my_recv( void *ctx, unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( MBEDTLS_ERR_SSL_WANT_READ );
    }

    ret = mbedtls_net_recv( ctx, buf, len );
    if( ret != MBEDTLS_ERR_SSL_WANT_READ )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

static int my_send( void *ctx, const unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( MBEDTLS_ERR_SSL_WANT_WRITE );
    }

    ret = mbedtls_net_send( ctx, buf, len );
    if( ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

/*
 * Return authmode from string, or -1 on error
 */
static int get_auth_mode( const char *s )
{
    if( strcmp( s, "none" ) == 0 )
        return( MBEDTLS_SSL_VERIFY_NONE );
    if( strcmp( s, "optional" ) == 0 )
        return( MBEDTLS_SSL_VERIFY_OPTIONAL );
    if( strcmp( s, "required" ) == 0 )
        return( MBEDTLS_SSL_VERIFY_REQUIRED );

    return( -1 );
}


static mbedtls_net_context listen_fd, client_fd;

/* Interruption handler to ensure clean exit (for valgrind testing) */
#if !defined(_WIN32)
static int received_sigterm = 0;
void term_handler( int sig )
{
    ((void) sig);
    received_sigterm = 1;
    mbedtls_net_free( &listen_fd ); /* causes mbedtls_net_accept() to abort */
    mbedtls_net_free( &client_fd ); /* causes net_read() to abort */
}
#endif

int main( int argc, char *argv[] )
{
    int ret = 0, len, written, frags, exchanges_left;
    unsigned char buf[IO_BUF_LEN];
    const char *pers = "tls_server";
    unsigned char client_ip[16] = { 0 };
    size_t cliip_len;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    char *cs_server_key;
    char *p2p_server_key;
#if defined(MBEDTLS_MILAGRO_CS_C)
    mbedtls_milagro_cs_context milagro_cs;
#endif
#if defined(MBEDTLS_MILAGRO_P2P_C)
    mbedtls_milagro_p2p_context milagro_p2p;
#endif
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[100000];
#endif

    int i;
    char *p, *q;

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif

    /*
     * Make sure memory references are valid in case we exit early.
     */
    mbedtls_net_init( &client_fd );
    mbedtls_net_init( &listen_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );
#if defined(MBEDTLS_MILAGRO_CS_C)
    mbedtls_milagro_cs_init(&milagro_cs );
#endif
#if defined(MBEDTLS_MILAGRO_P2P_C)
    mbedtls_milagro_p2p_init(&milagro_p2p);
#endif
#if !defined(_WIN32)
    /* Abort cleanly on SIGTERM and SIGINT */
    signal( SIGTERM, term_handler );
    signal( SIGINT, term_handler );
#endif

    if( argc == 0 )
    {
    usage:
        if( ret == 0 )
            ret = 1;
        
        mbedtls_printf( USAGE );
        mbedtls_printf("\n");
        goto exit;
    }

    opt.server_addr         = DFL_SERVER_ADDR;
    opt.server_port         = DFL_SERVER_PORT;
    opt.debug_level         = DFL_DEBUG_LEVEL;
    opt.nbio                = DFL_NBIO;
    opt.force_ciphersuite[0]= DFL_FORCE_CIPHER;
    opt.version_suites      = DFL_VERSION_SUITES;
    opt.exchanges           = DFL_EXCHANGES;
    opt.min_version         = DFL_MIN_VERSION;
    opt.max_version         = DFL_MAX_VERSION;
    opt.auth_mode           = DFL_AUTH_MODE;
    opt.mfl_code            = DFL_MFL_CODE;
    opt.transport           = DFL_TRANSPORT;
    
    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        if( strcmp( p, "server_port" ) == 0 )
            opt.server_port = q;
        else if( strcmp( p, "server_addr" ) == 0 )
            opt.server_addr = q;
        else if( strcmp( p, "debug_level" ) == 0 )
        {
            opt.debug_level = atoi( q );
            if( opt.debug_level < 0 || opt.debug_level > 65535 )
                goto usage;
        }
        else if( strcmp( p, "force_ciphersuite" ) == 0 )
        {
            opt.force_ciphersuite[0] = mbedtls_ssl_get_ciphersuite_id( q );
            
            if( opt.force_ciphersuite[0] == 0 )
            {
                ret = 2;
                goto usage;
            }
            opt.force_ciphersuite[1] = 0;
        }
        else if( strcmp( p, "nbio" ) == 0 )
        {
            opt.nbio = atoi( q );
            if( opt.nbio < 0 || opt.nbio > 2 )
                goto usage;
        }
        else if( strcmp( p, "exchanges" ) == 0 )
        {
            opt.exchanges = atoi( q );
            if( opt.exchanges < 0 )
                goto usage;
        }
         else if( strcmp( p, "auth_mode" ) == 0 )
        {
            if( ( opt.auth_mode = get_auth_mode( q ) ) < 0 )
                goto usage;
        }
        else if( strcmp( p, "max_frag_len" ) == 0 )
        {
            if( strcmp( q, "512" ) == 0 )
                opt.mfl_code = MBEDTLS_SSL_MAX_FRAG_LEN_512;
            else if( strcmp( q, "1024" ) == 0 )
                opt.mfl_code = MBEDTLS_SSL_MAX_FRAG_LEN_1024;
            else if( strcmp( q, "2048" ) == 0 )
                opt.mfl_code = MBEDTLS_SSL_MAX_FRAG_LEN_2048;
            else if( strcmp( q, "4096" ) == 0 )
                opt.mfl_code = MBEDTLS_SSL_MAX_FRAG_LEN_4096;
            else
                goto usage;
        }
        else
            goto usage;
    }

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( opt.debug_level );
#endif

    /*
     * 1. Initialize the RNG and the session data
     */
    
    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 2. Setup the listening TCP socket
     */
    mbedtls_printf( "  . Bind on %s://%s:%s/ ...",
            opt.transport == MBEDTLS_SSL_TRANSPORT_STREAM ? "tcp" : "udp",
            opt.server_addr ? opt.server_addr : "*",
            opt.server_port );
    fflush( stdout );

    if( ( ret = mbedtls_net_bind( &listen_fd, opt.server_addr, opt.server_port,
                          opt.transport == MBEDTLS_SSL_TRANSPORT_STREAM ?
                          MBEDTLS_NET_PROTO_TCP : MBEDTLS_NET_PROTO_UDP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_bind returned -0x%x\n\n", -ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 2.1. Setup stuff
     */
    mbedtls_printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    opt.transport,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret );
        goto exit;
    }

    if( opt.auth_mode != DFL_AUTH_MODE )
        mbedtls_ssl_conf_authmode( &conf, opt.auth_mode );

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    if( ( ret = mbedtls_ssl_conf_max_frag_len( &conf, opt.mfl_code ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_max_frag_len returned %d\n\n", ret );
        goto exit;
    };
#endif
    
    
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
    mbedtls_ssl_conf_ciphersuites( &conf, opt.force_ciphersuite );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", -ret );
        goto exit;
    }

    if( opt.nbio == 2 )
        mbedtls_ssl_set_bio( &ssl, &client_fd, my_send, my_recv, NULL );
    else
        mbedtls_ssl_set_bio( &ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv,
                             opt.nbio == 0 ? mbedtls_net_recv_timeout : NULL );

    mbedtls_printf( " ok\n" );

reset:
#if !defined(_WIN32)
    if( received_sigterm )
    {
        mbedtls_printf( " interrupted by SIGTERM\n" );
        ret = 0;
        goto exit;
    }
#endif

    if( ret == MBEDTLS_ERR_SSL_CLIENT_RECONNECT )
    {
        mbedtls_printf( "  ! Client initiated reconnection from same port\n" );
        goto handshake;
    }

#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
    }
#endif

    mbedtls_net_free( &client_fd );
    mbedtls_ssl_session_reset( &ssl );
    
#if defined(MBEDTLS_MILAGRO_CS_C)
        /*
         * 2.5 Setup MILAGRO_CS parameters
         */
    
        printf( "  . Setting up MILAGRO_CS parameters..." );
    
        cs_server_key = calloc(4*PFS,sizeof(char));
    
        read_from_file("CSServerKey", cs_server_key, 2*(4*PFS));
    
        mbedtls_milagro_cs_set_secret(&milagro_cs, cs_server_key, 4*PFS); mbedtls_free(cs_server_key);
    
        if( mbedtls_milagro_cs_setup_RNG(&milagro_cs, &entropy) != 0)
        {
            printf("\n\nFailed while setting the RNG in MILAGRO_CS\n");
            exit(-1);
        }
    
        mbedtls_ssl_set_milagro_cs(ssl.handshake, &milagro_cs);
    
        printf( " ok\n" );

#endif /* MBEDTLS_MILAGRO_CS_C */
    
    
#if defined(MBEDTLS_MILAGRO_P2P_C)

        /*
         * 2.5 Setup MILAGRO_P2P parameters
         */
        mbedtls_printf( "  . Setting up MILAGRO_P2P parameters..." );
    
        p2p_server_key = calloc(2*PFS+1, sizeof(char));
    
        read_from_file("P2PServerKey", p2p_server_key, 2*(2*PFS+1));
    
        mbedtls_milagro_p2p_set_key(MBEDTLS_MILAGRO_IS_SERVER, &milagro_p2p, p2p_server_key, 2*PFS+1); mbedtls_free(p2p_server_key);
    
        if (mbedtls_milagro_p2p_setup_RNG( &milagro_p2p, &entropy) != 0 )
        {
            mbedtls_printf("\n\nFailed while setting the RNG in MILAGRO_P2P\n");
            exit(-1);
        }
    
        mbedtls_milagro_p2p_set_identity(MBEDTLS_MILAGRO_IS_SERVER, &milagro_p2p, (char *)"server@miracl.com");
    
        mbedtls_ssl_set_milagro_p2p(ssl.handshake, &milagro_p2p);
    
        mbedtls_printf( " ok\n" );
#endif /* MBEDTLS_MILAGRO_P2P_C */
    
    
    /*
     * 3. Wait until a client connects
     */
    mbedtls_printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );

    if( ( ret = mbedtls_net_accept( &listen_fd, &client_fd,
                    client_ip, sizeof( client_ip ), &cliip_len ) ) != 0 )
    {
#if !defined(_WIN32)
        if( received_sigterm )
        {
            mbedtls_printf( " interrupted by signal\n" );
            ret = 0;
            goto exit;
        }
#endif

        mbedtls_printf( " failed\n  ! mbedtls_net_accept returned -0x%x\n\n", -ret );
        goto exit;
    }

    if( opt.nbio > 0 )
        ret = mbedtls_net_set_nonblock( &client_fd );
    else
        ret = mbedtls_net_set_block( &client_fd );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! net_set_(non)block() returned -0x%x\n\n", -ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 4. Handshake
     */
handshake:
    mbedtls_printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    do ret = mbedtls_ssl_handshake( &ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_READ ||
           ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    if( ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED )
    {
        mbedtls_printf( " hello verification requested\n" );
        ret = 0;
        goto reset;
    }
    else if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );

        goto reset;
    }
    else /* ret == 0 */
    {
        mbedtls_printf( " ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n",
                mbedtls_ssl_get_version( &ssl ), mbedtls_ssl_get_ciphersuite( &ssl ) );
    }

    if( ( ret = mbedtls_ssl_get_record_expansion( &ssl ) ) >= 0 )
        mbedtls_printf( "    [ Record expansion is %d ]\n", ret );
    else
        mbedtls_printf( "    [ Record expansion is unknown (compression) ]\n" );

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    mbedtls_printf( "    [ Maximum fragment length is %u ]\n",
                    (unsigned int) mbedtls_ssl_get_max_frag_len( &ssl ) );
#endif
    
    
    if( opt.exchanges == 0 )
        goto close_notify;

    exchanges_left = opt.exchanges;
data_exchange:
    /*
     * 6. Read from client
     */
    mbedtls_printf( "  < Read from client:" );
    fflush( stdout );

        do
        {
            int terminated = 0;
            len = sizeof( buf ) - 1;
            memset( buf, 0, sizeof( buf ) );
            ret = mbedtls_ssl_read( &ssl, buf, len );

            if( ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE )
                continue;

            if( ret <= 0 )
            {
                switch( ret )
                {
                    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                        mbedtls_printf( " connection was closed gracefully\n" );
                        goto close_notify;

                    case 0:
                    case MBEDTLS_ERR_NET_CONN_RESET:
                        mbedtls_printf( " connection was reset by peer\n" );
                        ret = MBEDTLS_ERR_NET_CONN_RESET;
                        goto reset;

                    default:
                        mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
                        goto reset;
                }
            }

            if( mbedtls_ssl_get_bytes_avail( &ssl ) == 0 )
            {
                len = ret;
                buf[len] = '\0';
                mbedtls_printf( " %d bytes read\n\n%s\n", len, (char *) buf );

                /* End of message should be detected according to the syntax of the
                 * application protocol (eg HTTP), just use a dummy test here. */
                if( buf[len - 1] == '\n' )
                    terminated = 1;
            }
            else
            {
                int extra_len, ori_len;
                unsigned char *larger_buf;

                ori_len = ret;
                extra_len = (int) mbedtls_ssl_get_bytes_avail( &ssl );

                larger_buf = mbedtls_calloc( 1, ori_len + extra_len + 1 );
                if( larger_buf == NULL )
                {
                    mbedtls_printf( "  ! memory allocation failed\n" );
                    ret = 1;
                    goto reset;
                }

                memset( larger_buf, 0, ori_len + extra_len );
                memcpy( larger_buf, buf, ori_len );

                /* This read should never fail and get the whole cached data */
                ret = mbedtls_ssl_read( &ssl, larger_buf + ori_len, extra_len );
                if( ret != extra_len ||
                    mbedtls_ssl_get_bytes_avail( &ssl ) != 0 )
                {
                    mbedtls_printf( "  ! mbedtls_ssl_read failed on cached data\n" );
                    ret = 1;
                    goto reset;
                }

                larger_buf[ori_len + extra_len] = '\0';
                mbedtls_printf( " %u bytes read (%u + %u)\n\n%s\n",
                        ori_len + extra_len, ori_len, extra_len,
                        (char *) larger_buf );

                /* End of message should be detected according to the syntax of the
                 * application protocol (eg HTTP), just use a dummy test here. */
                if( larger_buf[ori_len + extra_len - 1] == '\n' )
                    terminated = 1;

                mbedtls_free( larger_buf );
            }

            if( terminated )
            {
                break;
            }
        }
        while( 1 );


    /*
     * 7. Write the response
     */
    mbedtls_printf( "  > Write to client:" );
    fflush( stdout );

    len = sprintf( (char *) buf, HTTP_RESPONSE );


    for( written = 0, frags = 0; written < len; written += ret, frags++ )
    {
        while( ( ret = mbedtls_ssl_write( &ssl, buf + written, len - written ) )
                        <= 0 )
        {
            if( ret == MBEDTLS_ERR_NET_CONN_RESET )
            {
                mbedtls_printf( " failed\n  ! peer closed the connection\n\n" );
                goto reset;
            }
            if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
                goto reset;
            }
        }
    }


    buf[written] = '\0';
    mbedtls_printf( " %d bytes written in %d fragments\n\n%s\n", written, frags, (char *) buf );

    /*
     * 7b. Continue doing data exchanges?
     */
    if( --exchanges_left > 0 )
        goto data_exchange;

    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    mbedtls_printf( "  . Closing the connection..." );

    /* No error checking, the connection might be closed already */
    do ret = mbedtls_ssl_close_notify( &ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
    ret = 0;

    mbedtls_printf( " done\n" );

    goto reset;

    /*
     * Cleanup and exit
     */
exit:
#ifdef MBEDTLS_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf("Last error was: -0x%X - %s\n\n", -ret, error_buf );
    }
#endif

    mbedtls_printf( "  . Cleaning up..." );
    fflush( stdout );

    mbedtls_net_free( &client_fd );
    mbedtls_net_free( &listen_fd );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#if defined(MBEDTLS_MEMORY_DEBUG)
    mbedtls_memory_buffer_alloc_status();
#endif
    mbedtls_memory_buffer_alloc_free();
#endif

    mbedtls_printf( " done.\n" );

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    // Shell can not handle large exit numbers -> 1 for errors
    if( ret < 0 )
        ret = 1;

    return( ret );
}
#endif /* MBEDTLS_ENTROPY_C && MBEDTLS_SSL_TLS_C &&
          MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C &&
          MBEDTLS_CTR_DRBG_C */
