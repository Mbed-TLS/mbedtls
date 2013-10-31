/*
 *  SSL client with options
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
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

#include "polarssl/config.h"

#if defined(_WIN32)
#include <windows.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/error.h"

#if defined(POLARSSL_SSL_CACHE_C)
#include "polarssl/ssl_cache.h"
#endif

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
#include "polarssl/memory.h"
#endif

#define DFL_SERVER_PORT         4433
#define DFL_DEBUG_LEVEL         0
#define DFL_CA_FILE             ""
#define DFL_CA_PATH             ""
#define DFL_CRT_FILE            ""
#define DFL_KEY_FILE            ""
#define DFL_CRT_FILE2           ""
#define DFL_KEY_FILE2           ""
#define DFL_PSK                 ""
#define DFL_PSK_IDENTITY        "Client_identity"
#define DFL_FORCE_CIPHER        0
#define DFL_RENEGOTIATION       SSL_RENEGOTIATION_ENABLED
#define DFL_ALLOW_LEGACY        SSL_LEGACY_NO_RENEGOTIATION
#define DFL_MIN_VERSION         -1
#define DFL_MAX_VERSION         -1
#define DFL_AUTH_MODE           SSL_VERIFY_OPTIONAL
#define DFL_MFL_CODE            SSL_MAX_FRAG_LEN_NONE
#define DFL_TICKETS             SSL_SESSION_TICKETS_ENABLED

#define LONG_RESPONSE "<p>01-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n" \
    "02-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "03-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "04-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "05-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "06-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah\r\n"  \
    "07-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah-blah</p>\r\n"

/* Uncomment LONG_RESPONSE at the end of HTTP_RESPONSE to test sending longer
 * packets (for fragmentation purposes) */
#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>PolarSSL Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n" // LONG_RESPONSE

/* Uncomment to test server-initiated renegotiation */
// #define TEST_RENEGO

/*
 * global options
 */
struct options
{
    int server_port;            /* port on which the ssl service runs       */
    int debug_level;            /* level of debugging                       */
    const char *ca_file;        /* the file with the CA certificate(s)      */
    const char *ca_path;        /* the path with the CA certificate(s) reside */
    const char *crt_file;       /* the file with the server certificate     */
    const char *key_file;       /* the file with the server key             */
    const char *crt_file2;      /* the file with the 2nd server certificate */
    const char *key_file2;      /* the file with the 2nd server key         */
    const char *psk;            /* the pre-shared key                       */
    const char *psk_identity;   /* the pre-shared key identity              */
    int force_ciphersuite[2];   /* protocol/ciphersuite to use, or all      */
    int renegotiation;          /* enable / disable renegotiation           */
    int allow_legacy;           /* allow legacy renegotiation               */
    int min_version;            /* minimum protocol version accepted        */
    int max_version;            /* maximum protocol version accepted        */
    int auth_mode;              /* verify mode for connection               */
    unsigned char mfl_code;     /* code for maximum fragment length         */
    int tickets;                /* enable / disable session tickets         */
} opt;

static void my_debug( void *ctx, int level, const char *str )
{
    if( level < opt.debug_level )
    {
        fprintf( (FILE *) ctx, "%s", str );
        fflush(  (FILE *) ctx  );
    }
}


#if defined(POLARSSL_X509_CRT_PARSE_C)
#if defined(POLARSSL_FS_IO)
#define USAGE_IO \
    "    ca_file=%%s          The single file containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (pre-loaded)\n" \
    "    ca_path=%%s          The path containing the top-level CA(s) you fully trust\n" \
    "                        default: \"\" (pre-loaded) (overrides ca_file)\n" \
    "    crt_file=%%s         Your own cert and chain (in bottom to top order, top may be omitted)\n" \
    "                        default: see note after key_file2\n" \
    "    key_file=%%s         default: see note after key_file2\n" \
    "    crt_file2=%%s        Your second cert and chain (in bottom to top order, top may be omitted)\n" \
    "                        default: see note after key_file2\n" \
    "    key_file2=%%s        default: see note below\n" \
    "                        note: if neither crt_file/key_file nor crt_file2/key_file2 are used,\n" \
    "                              preloaded certificate(s) and key(s) are used if available\n"
#else
#define USAGE_IO \
    "\n"                                                    \
    "    No file operations available (POLARSSL_FS_IO not defined)\n" \
    "\n"
#endif /* POLARSSL_FS_IO */
#else
#define USAGE_IO ""
#endif /* POLARSSL_X509_CRT_PARSE_C */

#if defined(POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED)
#define USAGE_PSK                                                   \
    "    psk=%%s              default: \"\" (in hex, without 0x)\n" \
    "    psk_identity=%%s     default: \"Client_identity\"\n"
#else
#define USAGE_PSK ""
#endif /* POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(POLARSSL_SSL_SESSION_TICKETS)
#define USAGE_TICKETS                                       \
    "    tickets=%%d          default: 1 (enabled)\n"
#else
#define USAGE_TICKETS ""
#endif /* POLARSSL_SSL_SESSION_TICKETS */

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
#define USAGE_MAX_FRAG_LEN                                      \
    "    max_frag_len=%%d     default: 16384 (tls default)\n"   \
    "                        options: 512, 1024, 2048, 4096\n"
#else
#define USAGE_MAX_FRAG_LEN ""
#endif /* POLARSSL_SSL_MAX_FRAGMENT_LENGTH */

#define USAGE \
    "\n usage: ssl_server2 param=<>...\n"                   \
    "\n acceptable parameters:\n"                           \
    "    server_port=%%d      default: 4433\n"              \
    "    debug_level=%%d      default: 0 (disabled)\n"      \
    USAGE_IO                                                \
    "    request_page=%%s     default: \".\"\n"             \
    "    renegotiation=%%d    default: 1 (enabled)\n"       \
    USAGE_TICKETS                                           \
    "    allow_legacy=%%d     default: 0 (disabled)\n"      \
    "    min_version=%%s      default: \"ssl3\"\n"          \
    "    max_version=%%s      default: \"tls1_2\"\n"        \
    "    force_version=%%s    default: \"\" (none)\n"       \
    "                        options: ssl3, tls1, tls1_1, tls1_2\n" \
    "    auth_mode=%%s        default: \"optional\"\n"      \
    "                        options: none, optional, required\n" \
    USAGE_MAX_FRAG_LEN                                      \
    USAGE_PSK                                               \
    "\n"                                                    \
    "    force_ciphersuite=<name>    default: all enabled\n"\
    " acceptable ciphersuite names:\n"

#if !defined(POLARSSL_ENTROPY_C) ||  \
    !defined(POLARSSL_SSL_TLS_C) || !defined(POLARSSL_SSL_SRV_C) || \
    !defined(POLARSSL_NET_C) || !defined(POLARSSL_CTR_DRBG_C)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    printf("POLARSSL_ENTROPY_C and/or "
           "POLARSSL_SSL_TLS_C and/or POLARSSL_SSL_SRV_C and/or "
           "POLARSSL_NET_C and/or POLARSSL_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    int ret = 0, len, written, frags;
    int listen_fd;
    int client_fd = -1;
    unsigned char buf[1024];
#if defined(POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED)
    unsigned char psk[256];
    size_t psk_len = 0;
#endif
    const char *pers = "ssl_server2";

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    ssl_context ssl;
#if defined(POLARSSL_X509_CRT_PARSE_C)
    x509_crt cacert;
    x509_crt srvcert;
    pk_context pkey;
    x509_crt srvcert2;
    pk_context pkey2;
    int key_cert_init = 0, key_cert_init2 = 0;
#endif
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_context cache;
#endif
#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[100000];
#endif

    int i;
    char *p, *q;
    const int *list;

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
    memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif

    /*
     * Make sure memory references are valid in case we exit early.
     */
    listen_fd = 0;
    memset( &ssl, 0, sizeof( ssl_context ) );
#if defined(POLARSSL_X509_CRT_PARSE_C)
    x509_crt_init( &cacert );
    x509_crt_init( &srvcert );
    pk_init( &pkey );
    x509_crt_init( &srvcert2 );
    pk_init( &pkey2 );
#endif
#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_init( &cache );
#endif

    if( argc == 0 )
    {
    usage:
        if( ret == 0 )
            ret = 1;

        printf( USAGE );

        list = ssl_list_ciphersuites();
        while( *list )
        {
            printf(" %-42s", ssl_get_ciphersuite_name( *list ) );
            list++;
            if( !*list )
                break;
            printf(" %s\n", ssl_get_ciphersuite_name( *list ) );
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
    opt.crt_file2           = DFL_CRT_FILE2;
    opt.key_file2           = DFL_KEY_FILE2;
    opt.psk                 = DFL_PSK;
    opt.psk_identity        = DFL_PSK_IDENTITY;
    opt.force_ciphersuite[0]= DFL_FORCE_CIPHER;
    opt.renegotiation       = DFL_RENEGOTIATION;
    opt.allow_legacy        = DFL_ALLOW_LEGACY;
    opt.min_version         = DFL_MIN_VERSION;
    opt.max_version         = DFL_MAX_VERSION;
    opt.auth_mode           = DFL_AUTH_MODE;
    opt.mfl_code            = DFL_MFL_CODE;
    opt.tickets             = DFL_TICKETS;

    for( i = 1; i < argc; i++ )
    {
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
        else if( strcmp( p, "crt_file2" ) == 0 )
            opt.crt_file2 = q;
        else if( strcmp( p, "key_file2" ) == 0 )
            opt.key_file2 = q;
        else if( strcmp( p, "psk" ) == 0 )
            opt.psk = q;
        else if( strcmp( p, "psk_identity" ) == 0 )
            opt.psk_identity = q;
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
        else if( strcmp( p, "min_version" ) == 0 )
        {
            if( strcmp( q, "ssl3" ) == 0 )
                opt.min_version = SSL_MINOR_VERSION_0;
            else if( strcmp( q, "tls1" ) == 0 )
                opt.min_version = SSL_MINOR_VERSION_1;
            else if( strcmp( q, "tls1_1" ) == 0 )
                opt.min_version = SSL_MINOR_VERSION_2;
            else if( strcmp( q, "tls1_2" ) == 0 )
                opt.min_version = SSL_MINOR_VERSION_3;
            else
                goto usage;
        }
        else if( strcmp( p, "max_version" ) == 0 )
        {
            if( strcmp( q, "ssl3" ) == 0 )
                opt.max_version = SSL_MINOR_VERSION_0;
            else if( strcmp( q, "tls1" ) == 0 )
                opt.max_version = SSL_MINOR_VERSION_1;
            else if( strcmp( q, "tls1_1" ) == 0 )
                opt.max_version = SSL_MINOR_VERSION_2;
            else if( strcmp( q, "tls1_2" ) == 0 )
                opt.max_version = SSL_MINOR_VERSION_3;
            else
                goto usage;
        }
        else if( strcmp( p, "force_version" ) == 0 )
        {
            if( strcmp( q, "ssl3" ) == 0 )
            {
                opt.min_version = SSL_MINOR_VERSION_0;
                opt.max_version = SSL_MINOR_VERSION_0;
            }
            else if( strcmp( q, "tls1" ) == 0 )
            {
                opt.min_version = SSL_MINOR_VERSION_1;
                opt.max_version = SSL_MINOR_VERSION_1;
            }
            else if( strcmp( q, "tls1_1" ) == 0 )
            {
                opt.min_version = SSL_MINOR_VERSION_2;
                opt.max_version = SSL_MINOR_VERSION_2;
            }
            else if( strcmp( q, "tls1_2" ) == 0 )
            {
                opt.min_version = SSL_MINOR_VERSION_3;
                opt.max_version = SSL_MINOR_VERSION_3;
            }
            else
                goto usage;
        }
        else if( strcmp( p, "auth_mode" ) == 0 )
        {
            if( strcmp( q, "none" ) == 0 )
                opt.auth_mode = SSL_VERIFY_NONE;
            else if( strcmp( q, "optional" ) == 0 )
                opt.auth_mode = SSL_VERIFY_OPTIONAL;
            else if( strcmp( q, "required" ) == 0 )
                opt.auth_mode = SSL_VERIFY_REQUIRED;
            else
                goto usage;
        }
        else if( strcmp( p, "max_frag_len" ) == 0 )
        {
            if( strcmp( q, "512" ) == 0 )
                opt.mfl_code = SSL_MAX_FRAG_LEN_512;
            else if( strcmp( q, "1024" ) == 0 )
                opt.mfl_code = SSL_MAX_FRAG_LEN_1024;
            else if( strcmp( q, "2048" ) == 0 )
                opt.mfl_code = SSL_MAX_FRAG_LEN_2048;
            else if( strcmp( q, "4096" ) == 0 )
                opt.mfl_code = SSL_MAX_FRAG_LEN_4096;
            else
                goto usage;
        }
        else if( strcmp( p, "tickets" ) == 0 )
        {
            opt.tickets = atoi( q );
            if( opt.tickets < 0 || opt.tickets > 1 )
                goto usage;
        }
        else
            goto usage;
    }

    if( opt.force_ciphersuite[0] > 0 )
    {
        const ssl_ciphersuite_t *ciphersuite_info;
        ciphersuite_info = ssl_ciphersuite_from_id( opt.force_ciphersuite[0] );

        if( opt.max_version != -1 &&
            ciphersuite_info->min_minor_ver > opt.max_version )
        {
            printf("forced ciphersuite not allowed with this protocol version\n");
            ret = 2;
            goto usage;
        }
        if( opt.min_version != -1 &&
            ciphersuite_info->max_minor_ver < opt.min_version )
        {
            printf("forced ciphersuite not allowed with this protocol version\n");
            ret = 2;
            goto usage;
        }
        if( opt.max_version > ciphersuite_info->max_minor_ver )
            opt.max_version = ciphersuite_info->max_minor_ver;
        if( opt.min_version < ciphersuite_info->min_minor_ver )
            opt.min_version = ciphersuite_info->min_minor_ver;
    }

#if defined(POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED)
    /*
     * Unhexify the pre-shared key if any is given
     */
    if( strlen( opt.psk ) )
    {
        unsigned char c;
        size_t j;

        if( strlen( opt.psk ) % 2 != 0 )
        {
            printf("pre-shared key not valid hex\n");
            goto exit;
        }

        psk_len = strlen( opt.psk ) / 2;

        for( j = 0; j < strlen( opt.psk ); j += 2 )
        {
            c = opt.psk[j];
            if( c >= '0' && c <= '9' )
                c -= '0';
            else if( c >= 'a' && c <= 'f' )
                c -= 'a' - 10;
            else if( c >= 'A' && c <= 'F' )
                c -= 'A' - 10;
            else
            {
                printf("pre-shared key not valid hex\n");
                goto exit;
            }
            psk[ j / 2 ] = c << 4;

            c = opt.psk[j + 1];
            if( c >= '0' && c <= '9' )
                c -= '0';
            else if( c >= 'a' && c <= 'f' )
                c -= 'a' - 10;
            else if( c >= 'A' && c <= 'F' )
                c -= 'A' - 10;
            else
            {
                printf("pre-shared key not valid hex\n");
                goto exit;
            }
            psk[ j / 2 ] |= c;
        }
    }
#endif /* POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED */

    /*
     * 0. Initialize the RNG and the session data
     */
    printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! ctr_drbg_init returned -0x%x\n", -ret );
        goto exit;
    }

    printf( " ok\n" );

#if defined(POLARSSL_X509_CRT_PARSE_C)
    /*
     * 1.1. Load the trusted CA
     */
    printf( "  . Loading the CA root certificate ..." );
    fflush( stdout );

#if defined(POLARSSL_FS_IO)
    if( strlen( opt.ca_path ) )
        ret = x509_crt_parse_path( &cacert, opt.ca_path );
    else if( strlen( opt.ca_file ) )
        ret = x509_crt_parse_file( &cacert, opt.ca_file );
    else
#endif
#if defined(POLARSSL_CERTS_C)
        ret = x509_crt_parse( &cacert, (const unsigned char *) test_ca_list,
                              strlen( test_ca_list ) );
#else
    {
        ret = 1;
        printf("POLARSSL_CERTS_C not defined.");
    }
#endif
    if( ret < 0 )
    {
        printf( " failed\n  !  x509_crt_parse returned -0x%x\n\n", -ret );
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
    {
        key_cert_init++;
        if( ( ret = x509_crt_parse_file( &srvcert, opt.crt_file ) ) != 0 )
        {
            printf( " failed\n  !  x509_crt_parse_file returned -0x%x\n\n",
                    -ret );
            goto exit;
        }
    }
    if( strlen( opt.key_file ) )
    {
        key_cert_init++;
        if( ( ret = pk_parse_keyfile( &pkey, opt.key_file, "" ) ) != 0 )
        {
            printf( " failed\n  !  pk_parse_keyfile returned -0x%x\n\n", -ret );
            goto exit;
        }
    }
    if( key_cert_init == 1 )
    {
        printf( " failed\n  !  crt_file without key_file or vice-versa\n\n" );
        goto exit;
    }

    if( strlen( opt.crt_file2 ) )
    {
        key_cert_init2++;
        if( ( ret = x509_crt_parse_file( &srvcert2, opt.crt_file2 ) ) != 0 )
        {
            printf( " failed\n  !  x509_crt_parse_file(2) returned -0x%x\n\n",
                    -ret );
            goto exit;
        }
    }
    if( strlen( opt.key_file2 ) )
    {
        key_cert_init2++;
        if( ( ret = pk_parse_keyfile( &pkey2, opt.key_file2, "" ) ) != 0 )
        {
            printf( " failed\n  !  pk_parse_keyfile(2) returned -0x%x\n\n",
                    -ret );
            goto exit;
        }
    }
    if( key_cert_init2 == 1 )
    {
        printf( " failed\n  !  crt_file2 without key_file2 or vice-versa\n\n" );
        goto exit;
    }
#endif
    if( key_cert_init == 0 && key_cert_init2 == 0 )
    {
#if !defined(POLARSSL_CERTS_C)
        printf( "Not certificated or key provided, and \n"
                "POLARSSL_CERTS_C not defined!\n" );
        goto exit;
#else
#if defined(POLARSSL_RSA_C)
        if( ( ret = x509_crt_parse( &srvcert,
                                    (const unsigned char *) test_srv_crt_rsa,
                                    strlen( test_srv_crt_rsa ) ) ) != 0 )
        {
            printf( " failed\n  !  x509_crt_parse returned -0x%x\n\n", -ret );
            goto exit;
        }
        if( ( ret = pk_parse_key( &pkey,
                                  (const unsigned char *) test_srv_key_rsa,
                                  strlen( test_srv_key_rsa ), NULL, 0 ) ) != 0 )
        {
            printf( " failed\n  !  pk_parse_key returned -0x%x\n\n", -ret );
            goto exit;
        }
        key_cert_init = 2;
#endif /* POLARSSL_RSA_C */
#if defined(POLARSSL_ECDSA_C)
        if( ( ret = x509_crt_parse( &srvcert2,
                                    (const unsigned char *) test_srv_crt_ec,
                                    strlen( test_srv_crt_ec ) ) ) != 0 )
        {
            printf( " failed\n  !  x509_crt_parse2 returned -0x%x\n\n", -ret );
            goto exit;
        }
        if( ( ret = pk_parse_key( &pkey2,
                                  (const unsigned char *) test_srv_key_ec,
                                  strlen( test_srv_key_ec ), NULL, 0 ) ) != 0 )
        {
            printf( " failed\n  !  pk_parse_key2 returned -0x%x\n\n", -ret );
            goto exit;
        }
        key_cert_init2 = 2;
#endif /* POLARSSL_ECDSA_C */
#endif /* POLARSSL_CERTS_C */
    }

    printf( " ok\n" );
#endif /* POLARSSL_X509_CRT_PARSE_C */

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
    ssl_set_authmode( &ssl, opt.auth_mode );

#if defined(POLARSSL_SSL_MAX_FRAGMENT_LENGTH)
    ssl_set_max_frag_len( &ssl, opt.mfl_code );
#endif

    ssl_set_rng( &ssl, ctr_drbg_random, &ctr_drbg );
    ssl_set_dbg( &ssl, my_debug, stdout );

#if defined(POLARSSL_SSL_CACHE_C)
    ssl_set_session_cache( &ssl, ssl_cache_get, &cache,
                                 ssl_cache_set, &cache );
#endif

#if defined(POLARSSL_SSL_SESSION_TICKETS)
    ssl_set_session_tickets( &ssl, opt.tickets );
#endif

    if( opt.force_ciphersuite[0] != DFL_FORCE_CIPHER )
        ssl_set_ciphersuites( &ssl, opt.force_ciphersuite );

    ssl_set_renegotiation( &ssl, opt.renegotiation );
    ssl_legacy_renegotiation( &ssl, opt.allow_legacy );

#if defined(POLARSSL_X509_CRT_PARSE_C)
    ssl_set_ca_chain( &ssl, &cacert, NULL, NULL );
    if( key_cert_init )
        ssl_set_own_cert( &ssl, &srvcert, &pkey );
    if( key_cert_init2 )
        ssl_set_own_cert( &ssl, &srvcert2, &pkey2 );
#endif

#if defined(POLARSSL_KEY_EXCHANGE__SOME__PSK_ENABLED)
    ssl_set_psk( &ssl, psk, psk_len, (const unsigned char *) opt.psk_identity,
                 strlen( opt.psk_identity ) );
#endif

#if defined(POLARSSL_DHM_C)
    /*
     * Use different group than default DHM group
     */
    ssl_set_dh_param( &ssl, POLARSSL_DHM_RFC5114_MODP_2048_P,
                            POLARSSL_DHM_RFC5114_MODP_2048_G );
#endif

    if( opt.min_version != -1 )
        ssl_set_min_version( &ssl, SSL_MAJOR_VERSION_3, opt.min_version );

    if( opt.max_version != -1 )
        ssl_set_max_version( &ssl, SSL_MAJOR_VERSION_3, opt.max_version );

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
            goto reset;
        }
    }

    printf( " ok\n    [ Ciphersuite is %s ]\n",
            ssl_get_ciphersuite( &ssl ) );

#if defined(POLARSSL_X509_CRT_PARSE_C)
    /*
     * 5. Verify the server certificate
     */
    printf( "  . Verifying peer X.509 certificate..." );

    if( ( ret = ssl_get_verify_result( &ssl ) ) != 0 )
    {
        printf( " failed\n" );

        if( !ssl_get_peer_cert( &ssl ) )
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

    if( ssl_get_peer_cert( &ssl ) )
    {
        printf( "  . Peer certificate information    ...\n" );
        x509_crt_info( (char *) buf, sizeof( buf ) - 1, "      ",
                       ssl_get_peer_cert( &ssl ) );
        printf( "%s\n", buf );
    }
#endif /* POLARSSL_X509_CRT_PARSE_C */

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
        printf( " %d bytes read\n\n%s\n", len, (char *) buf );

        if( memcmp( buf, "SERVERQUIT", 10 ) == 0 )
        {
            ret = 0;
            goto exit;
        }

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

    for( written = 0, frags = 0; written < len; written += ret, frags++ )
    {
        while( ( ret = ssl_write( &ssl, buf + written, len - written ) ) <= 0 )
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
    }

    buf[written] = '\0';
    printf( " %d bytes written in %d fragments\n\n%s\n", written, frags, (char *) buf );

#ifdef TEST_RENEGO
    /*
     * Request renegotiation (this must be done when the client is still
     * waiting for input from our side).
     */
    printf( "  . Requestion renegotiation..." );
    fflush( stdout );
    while( ( ret = ssl_renegotiate( &ssl ) ) != 0 )
    {
        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            printf( " failed\n  ! ssl_renegotiate returned %d\n\n", ret );
            goto exit;
        }
    }

    /*
     * Should be a while loop, not an if, but here we're not actually
     * expecting data from the client, and since we're running tests locally,
     * we can just hope the handshake will finish the during the first call.
     */
    if( ( ret = ssl_read( &ssl, buf, 0 ) ) != 0 )
    {
        if( ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE )
        {
            printf( " failed\n  ! ssl_read returned %d\n\n", ret );

            /* Unexpected message probably means client didn't renegotiate */
            if( ret == POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE )
                goto reset;
            else
                goto exit;
        }
    }

    printf( " ok\n" );
#endif

    ret = 0;
    goto reset;

exit:

#ifdef POLARSSL_ERROR_C
    if( ret != 0 )
    {
        char error_buf[100];
        polarssl_strerror( ret, error_buf, 100 );
        printf("Last error was: -0x%X - %s\n\n", -ret, error_buf );
    }
#endif

    net_close( client_fd );
#if defined(POLARSSL_X509_CRT_PARSE_C)
    x509_crt_free( &cacert );
    x509_crt_free( &srvcert );
    pk_free( &pkey );
    x509_crt_free( &srvcert2 );
    pk_free( &pkey2 );
#endif

    ssl_free( &ssl );
    entropy_free( &entropy );

#if defined(POLARSSL_SSL_CACHE_C)
    ssl_cache_free( &cache );
#endif

#if defined(POLARSSL_MEMORY_BUFFER_ALLOC_C)
#if defined(POLARSSL_MEMORY_DEBUG)
    memory_buffer_alloc_status();
#endif
    memory_buffer_alloc_free();
#endif

#if defined(_WIN32)
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    // Shell can not handle large exit numbers -> 1 for errors
    if( ret < 0 )
        ret = 1;

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_ENTROPY_C && POLARSSL_SSL_TLS_C &&
          POLARSSL_SSL_SRV_C && POLARSSL_NET_C && POLARSSL_RSA_C &&
          POLARSSL_CTR_DRBG_C */
