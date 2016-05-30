
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
 * tls_client.c
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
#include <stdio.h>
#define mbedtls_free       free
#define mbedtls_time       time
#define mbedtls_time_t     time_t
#define mbedtls_calloc     calloc
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#define mbedtls_snprintf   snprintf
#endif

#if !defined(MBEDTLS_ENTROPY_C) || \
!defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_SRV_C) || \
!defined(MBEDTLS_NET_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_ENTROPY_C and/or "
                   "MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
                   "MBEDTLS_NET_C and/or MBEDTLS_CTR_DRBG_C and/or not defined.\n");
    return( 0 );
}
#else

#include <string.h>

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

#define DFL_CLIENT_IDENTITY     "client@miracl.com"
#define DFL_SERVER_NAME         "localhost"
#define DFL_SERVER_ADDR         NULL
#define DFL_SERVER_PORT         "4444"
#define DFL_REQUEST_PAGE        "/"
#define DFL_REQUEST_SIZE        -1
#define DFL_DEBUG_LEVEL         0
#define DFL_NBIO                0
#define DFL_FORCE_CIPHER        49329
#define DFL_EXCHANGES           1
#define DFL_MIN_VERSION         MBEDTLS_SSL_MAJOR_VERSION_3
#define DFL_MAX_VERSION         MBEDTLS_SSL_MAJOR_VERSION_3
#define DFL_AUTH_MODE           -1
#define DFL_MFL_CODE            MBEDTLS_SSL_MAX_FRAG_LEN_NONE
#define DFL_TRANSPORT           MBEDTLS_SSL_TRANSPORT_STREAM
#define DFL_FALLBACK            -1

#define GET_REQUEST "   CLIENT: Hi, I'm %s can you hear me???"
#define GET_REQUEST_END "\r\n\r\n"

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
#define USAGE_MAX_FRAG_LEN                                      \
"    max_frag_len=%%d     default: 16384 (tls default)\n"   \
"                        options: 512, 1024, 2048, 4096\n"
#else
#define USAGE_MAX_FRAG_LEN ""
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_SSL_FALLBACK_SCSV)
#define USAGE_FALLBACK \
"    fallback=0/1        default: (library default: off)\n"
#else
#define USAGE_FALLBACK ""
#endif

#define USAGE \
"\n usage: tls_client param=<>...\n"                   \
"\n acceptable parameters:\n"                           \
"    server_name=%%s      default: localhost\n"         \
"    server_addr=%%s      default: given by name\n"     \
"    server_port=%%d      default: 4444\n"              \
"    request_page=%%s     default: \".\"\n"             \
"    request_size=%%d     default: about 34 (basic request)\n" \
"                        (minimum: 0, max: 16384)\n" \
"    debug_level=%%d      default: 0 (disabled)\n"      \
"    nbio=%%d             default: 0 (blocking I/O)\n"  \
"                        options: 1 (non-blocking), 2 (added delays)\n" \
"    force_ciphersuite=<name>"                          \
" acceptable ciphersuite names:\n"                      \
"            TLS-MILAGRO-CS-WITH-AES-128-GCM-SHA256\n"  \
"            TLS-MILAGRO-P2P-WITH-AES-128-GCM-SHA256\n" \
"\n"                                                    \
"\n"                                                    \
"    exchanges=%%d        default: 1\n"                 \
USAGE_MAX_FRAG_LEN                                      \
USAGE_FALLBACK                                          \
"\n"                                                    \

/*
 * global options
 */
struct options
{
    const char *server_name;    /* hostname of the server (client only)     */
    const char *server_addr;    /* address of the server (client only)      */
    const char *server_port;    /* port on which the ssl service runs       */
    int debug_level;            /* level of debugging                       */
    int nbio;                   /* should I/O be blocking?                  */
    const char *request_page;   /* page on server to request                */
    int request_size;           /* pad request with header to requested size */
    const char *key_file;       /* the file with the client key             */
    int force_ciphersuite[2];   /* protocol/ciphersuite to use, or all      */
    int exchanges;              /* number of data exchanges                 */
    int min_version;            /* minimum protocol version accepted        */
    int max_version;            /* maximum protocol version accepted        */
    int auth_mode;              /* verify mode for connection               */
    unsigned char mfl_code;     /* code for maximum fragment length         */
    int transport;              /* TLS or DTLS?                             */
    int fallback;               /* is this a fallback connection?           */
} opt;



int read_from_file(const char* path, char* secret, int length_key){
    char hex[length_key];    
    int tmp;
    unsigned int i;
    FILE* file = fopen(path,"r");
    if(!file)
    {
        printf("Secret or time permit file is missing\n");
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

int main( int argc, char *argv[] )
{
    int ret = 0, len, tail_len, i, written, frags;
    mbedtls_net_context server_fd;
    unsigned char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];
    const char *pers = "tls_client";
    
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ssl_session saved_session;
    const int *ciphersuites;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    int got_milagro_cs_ciphersuite;
    int got_milagro_p2p_ciphersuite;
#if defined(MBEDTLS_MILAGRO_CS_C)
    mbedtls_milagro_cs_context milagro_cs;
    char *cs_client_key;
    char *cs_tp;
#endif
#if defined(MBEDTLS_MILAGRO_P2P_C)
    mbedtls_milagro_p2p_context milagro_p2p;
    char *p2p_client_key;
#endif
    
    char *p, *q;
    
    /*
     * Make sure memory references are valid.
     */
    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    memset( &saved_session, 0, sizeof( mbedtls_ssl_session ) );
    mbedtls_ctr_drbg_init( &ctr_drbg );
#if defined(MBEDTLS_MILAGRO_CS_C)
    mbedtls_milagro_cs_init(&milagro_cs );
#endif
#if defined(MBEDTLS_MILAGRO_P2P_C)
    mbedtls_milagro_p2p_init(&milagro_p2p);
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
    
    opt.server_name         = DFL_SERVER_NAME;
    opt.server_addr         = DFL_SERVER_ADDR;
    opt.server_port         = DFL_SERVER_PORT;
    opt.debug_level         = DFL_DEBUG_LEVEL;
    opt.nbio                = DFL_NBIO;
    opt.request_page        = DFL_REQUEST_PAGE;
    opt.request_size        = DFL_REQUEST_SIZE;
    opt.force_ciphersuite[0]= DFL_FORCE_CIPHER;
    opt.exchanges           = DFL_EXCHANGES;
    opt.min_version         = DFL_MIN_VERSION;
    opt.max_version         = DFL_MAX_VERSION;
    opt.auth_mode           = DFL_AUTH_MODE;
    opt.mfl_code            = DFL_MFL_CODE;
    opt.transport           = DFL_TRANSPORT;
    opt.fallback            = DFL_FALLBACK;
    
    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';
        
        if( strcmp( p, "server_name" ) == 0 )
            opt.server_name = q;
        else if( strcmp( p, "server_addr" ) == 0 )
            opt.server_addr = q;
        else if( strcmp( p, "server_port" ) == 0 )
            opt.server_port = q;
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
        else if( strcmp( p, "request_page" ) == 0 )
            opt.request_page = q;
        else if( strcmp( p, "request_size" ) == 0 )
        {
            opt.request_size = atoi( q );
            if( opt.request_size < 0 || opt.request_size > MBEDTLS_SSL_MAX_CONTENT_LEN )
                goto usage;
        }
        else if( strcmp( p, "key_file" ) == 0 )
            opt.key_file = q;
        else if( strcmp( p, "exchanges" ) == 0 )
        {
            opt.exchanges = atoi( q );
            if( opt.exchanges < 1 )
                goto usage;
        }
        else if( strcmp( p, "fallback" ) == 0 )
        {
            switch( atoi( q ) )
            {
                case 0: opt.fallback = MBEDTLS_SSL_IS_NOT_FALLBACK; break;
                case 1: opt.fallback = MBEDTLS_SSL_IS_FALLBACK; break;
                default: goto usage;
            }
        }
        else if( strcmp( p, "auth_mode" ) == 0 )
        {
            if( strcmp( q, "none" ) == 0 )
                opt.auth_mode = MBEDTLS_SSL_VERIFY_NONE;
            else if( strcmp( q, "optional" ) == 0 )
                opt.auth_mode = MBEDTLS_SSL_VERIFY_OPTIONAL;
            else if( strcmp( q, "required" ) == 0 )
                opt.auth_mode = MBEDTLS_SSL_VERIFY_REQUIRED;
            else
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
     * 2. Start the connection
     */
    if( opt.server_addr == NULL)
        opt.server_addr = opt.server_name;
    
    mbedtls_printf( "  . Connecting to %s/%s/%s...",
                   opt.transport == MBEDTLS_SSL_TRANSPORT_STREAM ? "tcp" : "udp",
                   opt.server_addr, opt.server_port );
    fflush( stdout );
    
    if( ( ret = mbedtls_net_connect( &server_fd, opt.server_addr, opt.server_port,
                                    opt.transport == MBEDTLS_SSL_TRANSPORT_STREAM ?
                                    MBEDTLS_NET_PROTO_TCP : MBEDTLS_NET_PROTO_UDP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_connect returned -0x%x\n\n", -ret );
        goto exit;
    }
    
    if( opt.nbio > 0 )
        ret = mbedtls_net_set_nonblock( &server_fd );
    else
        ret = mbedtls_net_set_block( &server_fd );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! net_set_(non)block() returned -0x%x\n\n", -ret );
        goto exit;
    }
    
    mbedtls_printf( " ok\n" );
    
    /*
     * 3. Setup stuff
     */
    mbedtls_printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );
    
    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                                            MBEDTLS_SSL_IS_CLIENT,
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
    }
#endif
    
    
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
    mbedtls_ssl_conf_ciphersuites( &conf, opt.force_ciphersuite );
    
#if defined(MBEDTLS_SSL_FALLBACK_SCSV)
    if( opt.fallback != DFL_FALLBACK )
        mbedtls_ssl_conf_fallback( &conf, opt.fallback );
#endif
    
    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", -ret );
        goto exit;
    }
    
    if( opt.nbio == 2 )
        mbedtls_ssl_set_bio( &ssl, &server_fd, my_send, my_recv, NULL );
    else
        mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv,
                            opt.nbio == 0 ? mbedtls_net_recv_timeout : NULL );
    
    mbedtls_printf( " ok\n" );
    
    
    ciphersuites = ssl.conf->ciphersuite_list[ssl.minor_ver];
    got_milagro_cs_ciphersuite = 0;
    got_milagro_p2p_ciphersuite = 0;
    ciphersuite_info = NULL;
    for(i = 0; ciphersuites[i] != 0; i++ )
    {
        ciphersuite_info = mbedtls_ssl_ciphersuite_from_id(ciphersuites[i]);
        if (ciphersuite_info->id ==
            mbedtls_ssl_get_ciphersuite_id( "TLS-MILAGRO-CS-WITH-AES-128-GCM-SHA256" ) )
        {
            got_milagro_cs_ciphersuite++;
        }
        else if(ciphersuite_info->id ==
                mbedtls_ssl_get_ciphersuite_id( "TLS-MILAGRO-P2P-WITH-AES-128-GCM-SHA256" ) )
        {
            got_milagro_p2p_ciphersuite++;
        }
    }
    

#if defined(MBEDTLS_MILAGRO_CS_C)
    if(got_milagro_cs_ciphersuite>0)
    {
        /*
         * 3.5 Setup MILAGRO_CS parameters
         */
    
        mbedtls_printf( "  . Setting up MILAGRO_CS parameters..." );
        fflush( stdout );

        cs_client_key = calloc(2*PFS+1,sizeof(char));
        read_from_file("CSClientKey", cs_client_key, 2*(2*PFS+1));
        mbedtls_milagro_cs_set_secret(&milagro_cs, cs_client_key, 2*PFS+1); free(cs_client_key);
        mbedtls_milagro_cs_set_client_identity (&milagro_cs, (char *)DFL_CLIENT_IDENTITY);
    
#if defined(MBEDTLS_MILAGRO_CS_TIME_PERMITS)
        cs_tp = calloc(2*PFS+1,sizeof(char));
        read_from_file("CSTimePermit", cs_tp, 2*(2*PFS+1));
        mbedtls_milagro_cs_set_timepermit(&milagro_cs, cs_tp, 2*PFS+1); free(cs_tp);
#endif
    
        if (mbedtls_milagro_cs_setup_RNG(&milagro_cs, &entropy) != 0)
        {
            printf("\n\nFailed while setting the RNG in MILAGRO_CS\n");
            exit(-1);
        }
    
#if defined(MBEDTLS_MILAGRO_CS_ENABLE_PIN)
        printf("\n Enter pin: ");
        scanf("%d",&milagro_cs.pin);
#endif
    
        mbedtls_ssl_set_milagro_cs(ssl.handshake, &milagro_cs);
    
        mbedtls_printf( " ok\n" );
        }
#endif /* MBEDTLS_MILAGRO_CS_C */
    
#if defined(MBEDTLS_MILAGRO_P2P_C)
    if(got_milagro_p2p_ciphersuite>0)
    {
        /*
         * 3.5 Setup MILAGRO_P2P parameters
         */
        mbedtls_printf( "  . Setting up MILAGRO_P2P parameters..." );
    
        p2p_client_key = calloc(4*PFS, sizeof(char));
    
        read_from_file("P2PClientKey", p2p_client_key, 2*(4*PFS));
    
        mbedtls_milagro_p2p_set_key(MBEDTLS_SSL_IS_CLIENT, &milagro_p2p, p2p_client_key, 4*PFS); free(p2p_client_key);
    
        if (mbedtls_milagro_p2p_setup_RNG( &milagro_p2p, &entropy) != 0 )
        {
            printf("\n\nFailed while setting the RNG in MILAGRO_P2P\n");
            exit(-1);
        }
    
        mbedtls_milagro_p2p_set_identity(MBEDTLS_SSL_IS_CLIENT, &milagro_p2p, (char *)DFL_CLIENT_IDENTITY);

        mbedtls_ssl_set_milagro_p2p(ssl.handshake, &milagro_p2p);
    
        mbedtls_printf( " ok\n" );
    }
#endif /* MBEDTLS_MILAGRO_P2P_C */
    
    
    /*
     * 4. Handshake
     */
    mbedtls_printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );
    
    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret );
            goto exit;
        }
    }
    
    mbedtls_printf( " ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n",
                   mbedtls_ssl_get_version( &ssl ), mbedtls_ssl_get_ciphersuite( &ssl ) );
    
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    mbedtls_printf( "    [ Maximum fragment length is %u ]\n",
                   (unsigned int) mbedtls_ssl_get_max_frag_len( &ssl ) );
#endif

    /*
     * 6. Write the GET request
     */
send_request:
    mbedtls_printf( "  > Write to server:" );
    fflush( stdout );
    
    len = mbedtls_snprintf( (char *) buf, sizeof(buf) - 1, GET_REQUEST,DFL_CLIENT_IDENTITY);
    tail_len = (int) strlen( GET_REQUEST_END );
    
    /* Add padding to GET request to reach opt.request_size in length */
    if( opt.request_size != DFL_REQUEST_SIZE &&
       len + tail_len < opt.request_size )
    {
        memset( buf + len, 'A', opt.request_size - len - tail_len );
        len += opt.request_size - len - tail_len;
    }
    
    strncpy( (char *) buf + len, GET_REQUEST_END, sizeof(buf) - len - 1 );
    len += tail_len;
    
    /* Truncate if request size is smaller than the "natural" size */
    if( opt.request_size != DFL_REQUEST_SIZE &&
       len > opt.request_size )
    {
        len = opt.request_size;
        
        /* Still end with \r\n unless that's really not possible */
        if( len >= 2 ) buf[len - 2] = '\r';
        if( len >= 1 ) buf[len - 1] = '\n';
    }
    
    for( written = 0, frags = 0; written < len; written += ret, frags++ )
    {
        while( ( ret = mbedtls_ssl_write( &ssl, buf + written, len - written ) )
              <= 0 )
        {
            if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
               ret != MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned -0x%x\n\n", -ret );
                goto exit;
            }
        }
    }
    
    buf[written] = '\0';
    mbedtls_printf( " %d bytes written in %d fragments\n\n%s\n", written, frags, (char *) buf );
    
    /*
     * 7. Read the HTTP response
     */
    mbedtls_printf( "  < Read from server:" );
    fflush( stdout );
    
    
    /**
     *  Setting for TLS
     */
    do
    {
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
                    
                default:
                    mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
                    goto exit;
            }
        }
        
        len = ret;
        buf[len] = '\0';
        mbedtls_printf( " %d bytes read\n\n%s", len, (char *) buf );
        
        /* End of message should be detected according to the syntax of the
         * application protocol (eg HTTP), just use a dummy test here. */
        if( ret > 0 && buf[len-1] == '\n' )
        {
            break;
        }
    }
    while( 1 );
    
    /*
     * 7v. Continue doing data exchanges?
     */
    if( --opt.exchanges > 0 )
        goto send_request;
    
    /*
     * 8. Done, cleanly close the connection
     */
close_notify:
    mbedtls_printf( "  . Closing the connection..." );
    fflush( stdout );
    
    /* No error checking, the connection might be closed already */
    do ret = mbedtls_ssl_close_notify( &ssl );
    while( ret == MBEDTLS_ERR_SSL_WANT_WRITE );
    ret = 0;
    
    mbedtls_printf( " done\n" );
    
    
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
    
    mbedtls_net_free( &server_fd );
    
    mbedtls_ssl_session_free( &saved_session );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    
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
MBEDTLS_SSL_CLI_C && MBEDTLS_NET_C  &&
MBEDTLS_CTR_DRBG_C MBEDTLS_TIMING_C */
