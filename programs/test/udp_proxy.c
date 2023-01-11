/*
 *  UDP proxy: emulate an unreliable UDP connection for DTLS testing
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * Warning: this is an internal utility program we use for tests.
 * It does break some abstractions from the NET layer, and is thus NOT an
 * example of good general usage.
 */

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#if defined(MBEDTLS_HAVE_TIME)
#include <time.h>
#define mbedtls_time            time
#define mbedtls_time_t          time_t
#endif
#define mbedtls_printf          printf
#define mbedtls_calloc          calloc
#define mbedtls_free            free
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_NET_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_NET_C not defined.\n" );
    mbedtls_exit( 0 );
}
#else

#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/ssl.h"
#include "mbedtls/timing.h"
#if defined(MBEDTLS_SHA256_C)
#include "mbedtls/sha256.h"
#endif

#include <test/helpers.h>

#include <string.h>

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
#if defined(MBEDTLS_HAVE_TIME) || (defined(MBEDTLS_TIMING_C) && !defined(MBEDTLS_TIMING_ALT))
#include <sys/time.h>
#endif
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#endif /* ( _WIN32 || _WIN32_WCE ) && !EFIX64 && !EFI32 */

#define MAX_MSG_SIZE            16384 + 2048 /* max record/datagram size */
#define PACKET_HASHES_STORED 1000
#define SHA256_SIZE 32

#define MODE_PATTERN    0
#define MODE_BITFLIP    1

#define DFL_SERVER_ADDR         "localhost"
#define DFL_SERVER_PORT         "4433"
#define DFL_LISTEN_ADDR         "localhost"
#define DFL_LISTEN_PORT         "5556"
#define DFL_PACK                0
#define DFL_RESEND_PROTECTION   0
#define DFL_MALFORM_HS_SEQ_NUM  -1
#define DFL_MALFORM_TRUNCATE    -1
#define DFL_MALFORM_MESSAGE     "Any"

#if defined(MBEDTLS_TIMING_C)
#define USAGE_PACK                                                          \
    "    pack=%%d             default: 0     (don't pack)\n"                \
    "                        options: t > 0 (pack for t milliseconds)\n"
#else
#define USAGE_PACK
#endif

#if defined(MBEDTLS_SHA256_C)
#define USAGE_RESEND \
    "    resend_protection=0/1 default:0 For messages that pass malformation\n"\
    "                        filters (below), calculate and save their hashes\n"\
    "                        to only increment malform_packet_num for\n"    \
    "                        unique packets. Apply the malformation again\n"\
    "                        in case of a resend. The calculated hash\n"    \
    "                        omits the record sequence_number.\n"
#else
#define USAGE_RESEND
#endif

#define USAGE_MALFORM                                                       \
    " Packet malformation arguments:\n"                                     \
    "    malform_mode=%%s     default: 0, memset packet data with a pattern.\n"\
    "                        1, XOR packet data with a pattern.\n"          \
    "    malform_offset=%%d   default: 0, where to start the malformation\n"\
    "    malform_pattern=%%s  What pattern to use to set/xor packet data,\n"\
    "                        in hex. Its presence indicates that\n"         \
    "                        a malformation should be performed.\n"         \
    "    malform_truncate=%%d default: -1, truncate the packet at this\n"   \
    "                        offset and rewrite the length in the packet\n" \
    "                        header. -1 means no truncation."               \
    USAGE_RESEND                                                            \
    " Possible malformation filters (joined by an AND):\n"                  \
    "    malform_packet_num=%%d default:0, which packet of a given type\n"  \
    "                                    that passes all filters to\n"      \
    "                                    malform. Zero means all.\n"        \
    "    malform_hs_seq_num=%%d  only malform handshake messages with this\n"\
    "                            seq_num. default: -1 - do not apply.\n"    \
    "                            Specifying this option and chosing a\n"    \
    "                            non-handshake message type will probably\n"\
    "                            give no results.\n"                        \
    "    malform_message=%%s  Which message to malform. Default: Any.\n"    \
    "                        Acceptable values:\n"                          \
    "                        Any, HelloRequest, ClientHello, ServerHello,\n"\
    "                        HelloVerifyRequest, NewSessionTicket,\n"       \
    "                        Certificate, ServerKeyExchange,\n"             \
    "                        CertificateRequest, ServerHelloDone,\n"        \
    "                        CertificateVerify, ClientKeyExchange,\n"       \
    "                        Finished, ChangeCipherSpec, Alert,\n"          \
    "                        ApplicationData, CID\n"

#define USAGE_1                                                             \
    "\n usage: udp_proxy param=<>...\n"                                     \
    "\n acceptable parameters:\n"                                           \
    "    server_addr=%%s      default: localhost\n"                         \
    "    server_port=%%d      default: 4433\n"                              \
    "    listen_addr=%%s      default: localhost\n"                         \
    "    listen_port=%%d      default: 4433\n"                              \
    "\n"                                                                    \
    "    duplicate=%%d        default: 0 (no duplication)\n"                \
    "                        duplicate about 1:N packets randomly\n"        \
    "    delay=%%d            default: 0 (no delayed packets)\n"            \
    "                        delay about 1:N packets randomly\n"            \
    "    delay_ccs=0/1       default: 0 (don't delay ChangeCipherSpec)\n"   \
    "    delay_cli=%%s        Handshake message from client that should be\n"\
    "                        delayed. Possible values are 'ClientHello',\n" \
    "                        'Certificate', 'CertificateVerify', and\n"     \
    "                        'ClientKeyExchange'.\n"                        \
    "                        May be used multiple times, even for the same\n"\
    "                        message, in which case the respective message\n"\
    "                        gets delayed multiple times.\n"                 \
    "    delay_srv=%%s        Handshake message from server that should be\n"\
    "                        delayed. Possible values are 'HelloRequest',\n"\
    "                        'ServerHello', 'ServerHelloDone', 'Certificate'\n"\
    "                        'ServerKeyExchange', 'NewSessionTicket',\n"    \
    "                        'HelloVerifyRequest' and ''CertificateRequest'.\n"\
    "                        May be used multiple times, even for the same\n"\
    "                        message, in which case the respective message\n"\
    "                        gets delayed multiple times.\n"                \
    "    drop=%%d             default: 0 (no dropped packets)\n"            \
    "                        drop about 1:N packets randomly\n"             \
    "    mtu=%%d              default: 0 (unlimited)\n"                     \
    "                        drop packets larger than N bytes\n"            \
    "    bad_ad=0/1          default: 0 (don't add bad ApplicationData)\n"  \
    "    bad_cid=%%d          default: 0 (don't corrupt Connection IDs)\n"  \
    "                        duplicate 1:N packets containing a CID,\n"     \
    "                        modifying CID in first instance of the packet.\n" \
    "    protect_hvr=0/1     default: 0 (don't protect HelloVerifyRequest)\n" \
    "    protect_len=%%d      default: (don't protect packets of this size)\n" \
    "    inject_clihlo=0/1   default: 0 (don't inject fake ClientHello)\n"  \
    "\n"                                                                    \
    "    seed=%%d             default: (use current time)\n"

#define USAGE_2                                                             \
    USAGE_PACK                                                              \
    "\n"                                                                    \
    USAGE_MALFORM                                                           \
    "\n"

/*
 * global options
 */

#define MAX_DELAYED_HS 10
size_t malform_counter = 0;
unsigned char *malform_pattern = NULL; /* Converted to binary from hex */
size_t malform_pattern_len = 0;

static struct options
{
    const char *server_addr;    /* address to forward packets to            */
    const char *server_port;    /* port to forward packets to               */
    const char *listen_addr;    /* address for accepting client connections */
    const char *listen_port;    /* port for accepting client connections    */

    int duplicate;              /* duplicate 1 in N packets (none if 0)     */
    int delay;                  /* delay 1 packet in N (none if 0)          */
    int delay_ccs;              /* delay ChangeCipherSpec                   */
    char* delay_cli[MAX_DELAYED_HS];  /* handshake types of messages from
                                       * client that should be delayed.     */
    uint8_t delay_cli_cnt;      /* Number of entries in delay_cli.          */
    char* delay_srv[MAX_DELAYED_HS];  /* handshake types of messages from
                                       * server that should be delayed.     */
    uint8_t delay_srv_cnt;      /* Number of entries in delay_srv.          */
    int drop;                   /* drop 1 packet in N (none if 0)           */
    int mtu;                    /* drop packets larger than this            */
    int bad_ad;                 /* inject corrupted ApplicationData record  */
    unsigned bad_cid;           /* inject corrupted CID record              */
    int protect_hvr;            /* never drop or delay HelloVerifyRequest   */
    int protect_len;            /* never drop/delay packet of the given size*/
    int inject_clihlo;          /* inject fake ClientHello after handshake  */
    unsigned pack;              /* merge packets into single datagram for
                                 * at most \c merge milliseconds if > 0     */
    unsigned int seed;          /* seed for "random" events                 */

    uint8_t malform_mode;       /* how to malform the data of a message:
                                 *     0 - pattern.
                                 *     1 - XOR.                             */
    int malform_truncate;       /* Truncate the packet at this offset,
                                 * rewrite length in the packet header.
                                 * -1 means no truncation.                  */
    size_t malform_offset;      /* byte offset to start packet malformation */
    const char* malform_message;/* which message to malform, a name as      */
                                /* present in msg_type(), or Any            */

    unsigned char* malform_pattern;/* Pattern to memset/XOR at an offset.
                                    * Its presence indicates that
                                    * a malformation should be performed. */

    size_t malform_packet_num;  /* Which packet of a given message to
                                 * malform. 0 - all. Currently only one
                                 * packet or all can be malformed. First packet
                                 * has number 1. */
    uint16_t malform_hs_seq_num; /* Records containing which hs_seq_num
                                 * should the malformation be applied to,
                                 * or should increase the malform_packet_num
                                 * counter. Default: -1 - no filter. */
#if defined(MBEDTLS_SHA256_C)
    int resend_protection;       /* For messages that pass malformation
                                  * filters, calculate and save their hashes
                                  * to only increment malform_packet_num for
                                  * unique packets. Apply the malformation again
                                  * in case of a resend. The calculated hash
                                  * omits the record sequence_number. */
#endif

} opt;

static void exit_usage( const char *name, const char *value )
{
    if( value == NULL )
        mbedtls_printf( " unknown option or missing value: %s\n", name );
    else
        mbedtls_printf( " option %s: illegal value: %s\n", name, value );

    mbedtls_printf( USAGE_1 );
    mbedtls_printf( USAGE_2 );
    mbedtls_exit( 1 );
}

static void get_options( int argc, char *argv[] )
{
    int i;
    char *p, *q;

    opt.server_addr    = DFL_SERVER_ADDR;
    opt.server_port    = DFL_SERVER_PORT;
    opt.listen_addr    = DFL_LISTEN_ADDR;
    opt.listen_port    = DFL_LISTEN_PORT;
    opt.pack           = DFL_PACK;
#if defined(MBEDTLS_SHA256_C)
    opt.resend_protection = DFL_RESEND_PROTECTION;
#endif
    opt.malform_hs_seq_num   = DFL_MALFORM_HS_SEQ_NUM;
    opt.malform_truncate     = DFL_MALFORM_TRUNCATE;
    opt.malform_message      = DFL_MALFORM_MESSAGE;
    /* Other members default to 0 */

    opt.delay_cli_cnt = 0;
    opt.delay_srv_cnt = 0;
    memset( opt.delay_cli, 0, sizeof( opt.delay_cli ) );
    memset( opt.delay_srv, 0, sizeof( opt.delay_srv ) );

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            exit_usage( p, NULL );
        *q++ = '\0';

        if( strcmp( p, "server_addr" ) == 0 )
            opt.server_addr = q;
        else if( strcmp( p, "server_port" ) == 0 )
            opt.server_port = q;
        else if( strcmp( p, "listen_addr" ) == 0 )
            opt.listen_addr = q;
        else if( strcmp( p, "listen_port" ) == 0 )
            opt.listen_port = q;
        else if( strcmp( p, "duplicate" ) == 0 )
        {
            opt.duplicate = atoi( q );
            if( opt.duplicate < 0 || opt.duplicate > 20 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "delay" ) == 0 )
        {
            opt.delay = atoi( q );
            if( opt.delay < 0 || opt.delay > 20 || opt.delay == 1 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "delay_ccs" ) == 0 )
        {
            opt.delay_ccs = atoi( q );
            if( opt.delay_ccs < 0 || opt.delay_ccs > 1 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "delay_cli" ) == 0 ||
                 strcmp( p, "delay_srv" ) == 0 )
        {
            uint8_t *delay_cnt;
            char **delay_list;
            size_t len;
            char *buf;

            if( strcmp( p, "delay_cli" ) == 0 )
            {
                delay_cnt  = &opt.delay_cli_cnt;
                delay_list = opt.delay_cli;
            }
            else
            {
                delay_cnt  = &opt.delay_srv_cnt;
                delay_list = opt.delay_srv;
            }

            if( *delay_cnt == MAX_DELAYED_HS )
            {
                mbedtls_printf( " too many uses of %s: only %d allowed\n",
                                p, MAX_DELAYED_HS );
                exit_usage( p, NULL );
            }

            len = strlen( q );
            buf = mbedtls_calloc( 1, len + 1 );
            if( buf == NULL )
            {
                mbedtls_printf( " Allocation failure\n" );
                exit( 1 );
            }
            memcpy( buf, q, len + 1 );

            delay_list[ (*delay_cnt)++ ] = buf;
        }
        else if( strcmp( p, "drop" ) == 0 )
        {
            opt.drop = atoi( q );
            if( opt.drop < 0 || opt.drop > 20 || opt.drop == 1 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "pack" ) == 0 )
        {
#if defined(MBEDTLS_TIMING_C)
            opt.pack = (unsigned) atoi( q );
#else
            mbedtls_printf( " option pack only defined if MBEDTLS_TIMING_C is enabled\n" );
            exit( 1 );
#endif
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
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
        else if( strcmp( p, "bad_cid" ) == 0 )
        {
            opt.bad_cid = (unsigned) atoi( q );
        }
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
        else if( strcmp( p, "protect_hvr" ) == 0 )
        {
            opt.protect_hvr = atoi( q );
            if( opt.protect_hvr < 0 || opt.protect_hvr > 1 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "protect_len" ) == 0 )
        {
            opt.protect_len = atoi( q );
            if( opt.protect_len < 0 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "inject_clihlo" ) == 0 )
        {
            opt.inject_clihlo = atoi( q );
            if( opt.inject_clihlo < 0 || opt.inject_clihlo > 1 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "seed" ) == 0 )
        {
            opt.seed = atoi( q );
            if( opt.seed == 0 )
                exit_usage( p, q );
        }
        else if( strcmp( p, "malform_offset" ) == 0 )
            opt.malform_offset = atoi( q );
        else if( strcmp( p, "malform_truncate" ) == 0 )
            opt.malform_truncate = atoi( q );
        else if( strcmp( p, "malform_mode" ) == 0 )
            opt.malform_mode = atoi( q );
        else if( strcmp( p, "malform_packet_num" ) == 0 )
            opt.malform_packet_num = atoi( q );
        else if( strcmp( p, "malform_message" ) == 0 )
            opt.malform_message = q;
        else if( strcmp( p, "malform_pattern" ) == 0 )
        {
            opt.malform_pattern = mbedtls_test_unhexify_alloc( q,
                &malform_pattern_len );
            if( opt.malform_pattern == NULL )
            {
                mbedtls_printf( " Allocation failure\n" );
                exit( 1 );
            }
        }
        else if( strcmp( p, "malform_hs_seq_num" ) == 0 )
            opt.malform_hs_seq_num = atoi( q );
#if defined(MBEDTLS_SHA256_C)
        else if( strcmp( p, "resend_protection" ) == 0 )
            opt.resend_protection = atoi( q );
#endif
        else
            exit_usage( p, NULL );
    }
}

static const char *msg_type( unsigned char *msg, size_t len )
{
    if( len < 1 )                           return( "Invalid" );
    switch( msg[0] )
    {
        case MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC:    return( "ChangeCipherSpec" );
        case MBEDTLS_SSL_MSG_ALERT:                 return( "Alert" );
        case MBEDTLS_SSL_MSG_APPLICATION_DATA:      return( "ApplicationData" );
        case MBEDTLS_SSL_MSG_CID:                   return( "CID" );
        case MBEDTLS_SSL_MSG_HANDSHAKE:             break; /* See below */
        default:                            return( "Unknown" );
    }

    if( len < 13 + 12 )                     return( "Invalid handshake" );

    /*
     * Our handshake message are less than 2^16 bytes long, so they should
     * have 0 as the first byte of length, frag_offset and frag_length.
     * Otherwise, assume they are encrypted.
     */
    if( msg[14] || msg[19] || msg[22] )     return( "Encrypted handshake" );

    switch( msg[13] )
    {
        case MBEDTLS_SSL_HS_HELLO_REQUEST:          return( "HelloRequest" );
        case MBEDTLS_SSL_HS_CLIENT_HELLO:           return( "ClientHello" );
        case MBEDTLS_SSL_HS_SERVER_HELLO:           return( "ServerHello" );
        case MBEDTLS_SSL_HS_HELLO_VERIFY_REQUEST:   return( "HelloVerifyRequest" );
        case MBEDTLS_SSL_HS_NEW_SESSION_TICKET:     return( "NewSessionTicket" );
        case MBEDTLS_SSL_HS_CERTIFICATE:            return( "Certificate" );
        case MBEDTLS_SSL_HS_SERVER_KEY_EXCHANGE:    return( "ServerKeyExchange" );
        case MBEDTLS_SSL_HS_CERTIFICATE_REQUEST:    return( "CertificateRequest" );
        case MBEDTLS_SSL_HS_SERVER_HELLO_DONE:      return( "ServerHelloDone" );
        case MBEDTLS_SSL_HS_CERTIFICATE_VERIFY:     return( "CertificateVerify" );
        case MBEDTLS_SSL_HS_CLIENT_KEY_EXCHANGE:    return( "ClientKeyExchange" );
        case MBEDTLS_SSL_HS_FINISHED:               return( "Finished" );
        default:                            return( "Unknown handshake" );
    }
}

#if defined(MBEDTLS_TIMING_C)
/* Return elapsed time in milliseconds since the first call */
static unsigned elapsed_time( void )
{
    static int initialized = 0;
    static struct mbedtls_timing_hr_time hires;

    if( initialized == 0 )
    {
        (void) mbedtls_timing_get_timer( &hires, 1 );
        initialized = 1;
        return( 0 );
    }

    return( mbedtls_timing_get_timer( &hires, 0 ) );
}

typedef struct
{
    mbedtls_net_context *ctx;

    const char *description;

    unsigned packet_lifetime;
    unsigned num_datagrams;

    unsigned char data[MAX_MSG_SIZE];
    size_t len;

} ctx_buffer;

static ctx_buffer outbuf[2];

static int ctx_buffer_flush( ctx_buffer *buf )
{
    int ret;

    mbedtls_printf( "  %05u flush    %s: %u bytes, %u datagrams, last %u ms\n",
                    elapsed_time(), buf->description,
                    (unsigned) buf->len, buf->num_datagrams,
                    elapsed_time() - buf->packet_lifetime );

    ret = mbedtls_net_send( buf->ctx, buf->data, buf->len );

    buf->len           = 0;
    buf->num_datagrams = 0;

    return( ret );
}

static unsigned ctx_buffer_time_remaining( ctx_buffer *buf )
{
    unsigned const cur_time = elapsed_time();

    if( buf->num_datagrams == 0 )
        return( (unsigned) -1 );

    if( cur_time - buf->packet_lifetime >= opt.pack )
        return( 0 );

    return( opt.pack - ( cur_time - buf->packet_lifetime ) );
}

static int ctx_buffer_append( ctx_buffer *buf,
                              const unsigned char * data,
                              size_t len )
{
    int ret;

    if( len > (size_t) INT_MAX )
        return( -1 );

    if( len > sizeof( buf->data ) )
    {
        mbedtls_printf( "  ! buffer size %u too large (max %u)\n",
                        (unsigned) len, (unsigned) sizeof( buf->data ) );
        return( -1 );
    }

    if( sizeof( buf->data ) - buf->len < len )
    {
        if( ( ret = ctx_buffer_flush( buf ) ) <= 0 )
        {
            mbedtls_printf( "ctx_buffer_flush failed with -%#04x", (unsigned int) -ret );
            return( ret );
        }
    }

    memcpy( buf->data + buf->len, data, len );

    buf->len += len;
    if( ++buf->num_datagrams == 1 )
        buf->packet_lifetime = elapsed_time();

    return( (int) len );
}
#endif /* MBEDTLS_TIMING_C */

static int dispatch_data( mbedtls_net_context *ctx,
                          const unsigned char * data,
                          size_t len )
{
    int ret;
#if defined(MBEDTLS_TIMING_C)
    ctx_buffer *buf = NULL;
    if( opt.pack > 0 )
    {
        if( outbuf[0].ctx == ctx )
            buf = &outbuf[0];
        else if( outbuf[1].ctx == ctx )
            buf = &outbuf[1];

        if( buf == NULL )
            return( -1 );

        return( ctx_buffer_append( buf, data, len ) );
    }
#endif /* MBEDTLS_TIMING_C */

    ret = mbedtls_net_send( ctx, data, len );
    if( ret < 0 )
    {
        mbedtls_printf( "net_send returned -%#04x\n", (unsigned int) -ret );
    }
    return( ret );
}

typedef struct
{
    mbedtls_net_context *dst;
    const char *way;
    const char *type;
    unsigned len;
    unsigned char buf[MAX_MSG_SIZE];
#if defined(MBEDTLS_SHA256_C)
    unsigned char hash[SHA256_SIZE];
    unsigned int resend_detected;
#endif
} packet;

/* Print packet. Outgoing packets come with a reason (forward, dupl, etc.) */
void print_packet( const packet *p, const char *why )
{
#if defined(MBEDTLS_TIMING_C)
    if( why == NULL )
        mbedtls_printf( "  %05u dispatch %s %s (%u bytes)\n",
                elapsed_time(), p->way, p->type, p->len );
    else
        mbedtls_printf( "  %05u dispatch %s %s (%u bytes): %s\n",
                elapsed_time(), p->way, p->type, p->len, why );
#else
    if( why == NULL )
        mbedtls_printf( "        dispatch %s %s (%u bytes)\n",
                p->way, p->type, p->len );
    else
        mbedtls_printf( "        dispatch %s %s (%u bytes): %s\n",
                p->way, p->type, p->len, why );
#endif

    fflush( stdout );
}

#define DEBUG_BUF_SIZE      512
static void debug_print_buf( const char *file, int line, const char *text,
                      const unsigned char *buf, size_t len )
{
    char str[DEBUG_BUF_SIZE];
    char txt[17];
    size_t i, idx = 0;

    mbedtls_snprintf( str + idx, sizeof( str ) - idx, "dumping '%s' (%u bytes)\n",
              text, (unsigned int) len );

    mbedtls_printf( "%s:%d:%s", file, line, str );

    idx = 0;
    memset( txt, 0, sizeof( txt ) );
    for( i = 0; i < len; i++ )
    {
        if( i % 16 == 0 )
        {
            if( i > 0 )
            {
                mbedtls_snprintf( str + idx, sizeof( str ) - idx, "  %s\n", txt );
                mbedtls_printf( "%s:%d:%s", file, line, str );

                idx = 0;
                memset( txt, 0, sizeof( txt ) );
            }

            idx += mbedtls_snprintf( str + idx, sizeof( str ) - idx, "%04x: ",
                             (unsigned int) i );

        }

        idx += mbedtls_snprintf( str + idx, sizeof( str ) - idx, " %02x",
                         (unsigned int) buf[i] );
        txt[i % 16] = ( buf[i] > 31 && buf[i] < 127 ) ? buf[i] : '.' ;
    }

    if( len > 0 )
    {
        for( /* i = i */; i % 16 != 0; i++ )
            idx += mbedtls_snprintf( str + idx, sizeof( str ) - idx, "   " );

        mbedtls_snprintf( str + idx, sizeof( str ) - idx, "  %s\n", txt );
        mbedtls_printf( "%s:%d:%s", file, line, str );
    }
}
#define PRINT_DEBUG_BUF( text, buf, len )           \
    debug_print_buf( __FILE__, __LINE__, text, buf, len )

#if defined(MBEDTLS_SHA256_C)

size_t num_unique_packets = 0; // Occupied size of unique_packet_hashes
unsigned char unique_packet_hashes[PACKET_HASHES_STORED][SHA256_SIZE] = { { 0 } };

unsigned char single_malformed_hash[SHA256_SIZE] = {0};
unsigned int single_malformation_done = 0;

#define SEQ_NUM_LEN 6
#define SEQ_NUM_POS 5

static void reset_packet_hashes( )
{
    memset( unique_packet_hashes, 0, sizeof( unique_packet_hashes ) );
    memset( single_malformed_hash, 0, sizeof( single_malformed_hash ) );
    single_malformation_done = 0;
    num_unique_packets = 0;
}

static int calculate_packet_hash( packet *cur )
{
    int ret = -1;
    unsigned char seq_num_buffer[SEQ_NUM_LEN] = {0};

    memcpy( seq_num_buffer, &cur->buf[SEQ_NUM_POS], SEQ_NUM_LEN );

    /* Clear out the sequence number in case of a resend */
    memset( &cur->buf[SEQ_NUM_POS], 0, SEQ_NUM_LEN );
    ret = mbedtls_sha256( cur->buf, cur->len, cur->hash, 0 );
    memcpy( &cur->buf[SEQ_NUM_POS], seq_num_buffer, SEQ_NUM_LEN );

    if( ret != 0 )
    {
        mbedtls_printf( " Failed to calculate sha256\n" );
        return ret;
    }
    /* Check if the packet is unique. We do not expect too many
     * packets to pass filters, so a simple for loop is enough. */
    cur->resend_detected = 0;
    for( uint16_t i = 0; i < num_unique_packets; i++ )
    {
        if( memcmp( unique_packet_hashes[i], cur->hash, SHA256_SIZE ) == 0 )
        {
            mbedtls_printf( " Detected resent packet %u\n", i );
            cur->resend_detected = 1;
            break;
        }
    }

    if( cur->resend_detected == 0 )
    {
        mbedtls_printf( " Added as unique packet no. %u\n",
                        (unsigned) num_unique_packets );
        memcpy( unique_packet_hashes[num_unique_packets], cur->hash, SHA256_SIZE );
        if( num_unique_packets == PACKET_HASHES_STORED )
        {
            mbedtls_printf( " Packet hash buffer full. Exiting. \n" );
            exit( MBEDTLS_EXIT_FAILURE );
        }
        num_unique_packets++;
    }

    return ret;
}
#endif

static int message_passes_filters( packet *cur )
{
    if( strcmp( opt.malform_message, "Any" ) != 0 &&
        strcmp( cur->type, opt.malform_message ) != 0 )
        return 0;
    if( opt.malform_hs_seq_num != (uint16_t) -1  &&
        cur->buf[0] == MBEDTLS_SSL_MSG_HANDSHAKE )
    {
        uint16_t rec_seqnum = ( (uint16_t) cur->buf[17] <<  8 ) |
                              ( (uint16_t) cur->buf[18]      );
        if( rec_seqnum != opt.malform_hs_seq_num )
            return 0;
    }
    return 1;
}

static int handle_message_malformation( packet* cur )
{
    int malformed_before = 0;
    if( !message_passes_filters( cur ) )
        return 0;
#if defined(MBEDTLS_SHA256_C)
    if( opt.resend_protection )
        calculate_packet_hash( cur );

    /* resend_detected means that the protection is on */
    if( cur->resend_detected )
    {
        /* Check if this packet was malformed before */
        if( single_malformation_done
            && ( memcmp( cur->hash, single_malformed_hash, SHA256_SIZE ) == 0 ) )
        {
            malformed_before = 1;
            mbedtls_printf( " Detected a resent packet that should be malformed \n" );
        }
    }
    else
#endif
        malform_counter++;

    if( malform_counter == opt.malform_packet_num ||
            opt.malform_packet_num == 0 ||
            malformed_before )
    {
        if( opt.malform_mode == MODE_BITFLIP )
        {
            for( size_t i = 0; i < malform_pattern_len; i++ )
            {
                cur->buf[opt.malform_offset + i] ^= opt.malform_pattern[i];
            }
        }
        else if( opt.malform_mode == MODE_PATTERN )
        {
                memcpy( &cur->buf[opt.malform_offset],
                            opt.malform_pattern, malform_pattern_len );
        }

        if( opt.malform_truncate != -1 )
            cur->len = (unsigned) opt.malform_truncate;
#if defined(MBEDTLS_SHA256_C)
        /* If just a single packet should be malformed - store the hash.
         * Do not overwrite it with the sama data on a resend */
        if( opt.resend_protection && opt.malform_packet_num != 0 &&
                malformed_before == 0 )
        {
            single_malformation_done = 1;
            memcpy( single_malformed_hash, cur->hash, SHA256_SIZE );
        }
#endif
        PRINT_DEBUG_BUF( "malformed packet", cur->buf, cur->len );
    }

    return 0;
}
/*
 * In order to test the server's behaviour when receiving a ClientHello after
 * the connection is established (this could be a hard reset from the client,
 * but the server must not drop the existing connection before establishing
 * client reachability, see RFC 6347 Section 4.2.8), we memorize the first
 * ClientHello we see (which can't have a cookie), then replay it after the
 * first ApplicationData record - then we're done.
 *
 * This is controlled by the inject_clihlo option.
 *
 * We want an explicit state and a place to store the packet.
 */
typedef enum {
    ICH_INIT,       /* haven't seen the first ClientHello yet */
    ICH_CACHED,     /* cached the initial ClientHello */
    ICH_INJECTED,   /* ClientHello already injected, done */
} inject_clihlo_state_t;

static inject_clihlo_state_t inject_clihlo_state;
static packet initial_clihlo;

int send_packet( const packet *p, const char *why )
{
    int ret;
    mbedtls_net_context *dst = p->dst;

    /* save initial ClientHello? */
    if( opt.inject_clihlo != 0 &&
        inject_clihlo_state == ICH_INIT &&
        strcmp( p->type, "ClientHello" ) == 0 )
    {
        memcpy( &initial_clihlo, p, sizeof( packet ) );
        inject_clihlo_state = ICH_CACHED;
    }

    /* insert corrupted CID record? */
    if( opt.bad_cid != 0 &&
        strcmp( p->type, "CID" ) == 0 &&
        ( rand() % opt.bad_cid ) == 0 )
    {
        unsigned char buf[MAX_MSG_SIZE];
        memcpy( buf, p->buf, p->len );

        /* The CID resides at offset 11 in the DTLS record header. */
        buf[11] ^= 1;
        print_packet( p, "modified CID" );

        if( ( ret = dispatch_data( dst, buf, p->len ) ) <= 0 )
        {
            mbedtls_printf( "  ! dispatch returned %d\n", ret );
            return( ret );
        }
    }

    /* insert corrupted ApplicationData record? */
    if( opt.bad_ad &&
        strcmp( p->type, "ApplicationData" ) == 0 )
    {
        unsigned char buf[MAX_MSG_SIZE];
        memcpy( buf, p->buf, p->len );

        if( p->len <= 13 )
        {
            mbedtls_printf( "  ! can't corrupt empty AD record" );
        }
        else
        {
            ++buf[13];
            print_packet( p, "corrupted" );
        }

        if( ( ret = dispatch_data( dst, buf, p->len ) ) <= 0 )
        {
            mbedtls_printf( "  ! dispatch returned %d\n", ret );
            return( ret );
        }
    }

    print_packet( p, why );
    if( ( ret = dispatch_data( dst, p->buf, p->len ) ) <= 0 )
    {
        mbedtls_printf( "  ! dispatch returned %d\n", ret );
        return( ret );
    }

    /* Don't duplicate Application Data, only handshake covered */
    if( opt.duplicate != 0 &&
        strcmp( p->type, "ApplicationData" ) != 0 &&
        rand() % opt.duplicate == 0 )
    {
        print_packet( p, "duplicated" );

        if( ( ret = dispatch_data( dst, p->buf, p->len ) ) <= 0 )
        {
            mbedtls_printf( "  ! dispatch returned %d\n", ret );
            return( ret );
        }
    }

    /* Inject ClientHello after first ApplicationData */
    if( opt.inject_clihlo != 0 &&
        inject_clihlo_state == ICH_CACHED &&
        strcmp( p->type, "ApplicationData" ) == 0 )
    {
        print_packet( &initial_clihlo, "injected" );

        if( ( ret = dispatch_data( dst, initial_clihlo.buf,
                                        initial_clihlo.len ) ) <= 0 )
        {
            mbedtls_printf( "  ! dispatch returned %d\n", ret );
            return( ret );
        }

        inject_clihlo_state = ICH_INJECTED;
    }

    return( 0 );
}

#define MAX_DELAYED_MSG 5
static size_t prev_len;
static packet prev[MAX_DELAYED_MSG];

void clear_pending( void )
{
    memset( &prev, 0, sizeof( prev ) );
    prev_len = 0;
}

void delay_packet( packet *delay )
{
    if( prev_len == MAX_DELAYED_MSG )
        return;

    memcpy( &prev[prev_len++], delay, sizeof( packet ) );
}

int send_delayed()
{
    uint8_t offset;
    int ret;
    for( offset = 0; offset < prev_len; offset++ )
    {
        ret = send_packet( &prev[offset], "delayed" );
        if( ret != 0 )
            return( ret );
    }

    clear_pending();
    return( 0 );
}

/*
 * Avoid dropping or delaying a packet that was already dropped or delayed
 * ("held") twice: this only results in uninteresting timeouts. We can't rely
 * on type to identify packets, since during renegotiation they're all
 * encrypted. So, rely on size mod 2048 (which is usually just size).
 *
 * We only hold packets at the level of entire datagrams, not at the level
 * of records. In particular, if the peer changes the way it packs multiple
 * records into a single datagram, we don't necessarily count the number of
 * times a record has been held correctly. However, the only known reason
 * why a peer would change datagram packing is disabling the latter on
 * retransmission, in which case we'd hold involved records at most
 * HOLD_MAX + 1 times.
 */
static unsigned char held[2048] = { 0 };
#define HOLD_MAX 2

int handle_message( const char *way,
                    mbedtls_net_context *dst,
                    mbedtls_net_context *src )
{
    int ret;
    packet cur;
    size_t id;

    uint8_t delay_idx;
    char ** delay_list;
    uint8_t delay_list_len;

    /* receive packet */
    if( ( ret = mbedtls_net_recv( src, cur.buf, sizeof( cur.buf ) ) ) <= 0 )
    {
        mbedtls_printf( "  ! mbedtls_net_recv returned %d\n", ret );
        return( ret );
    }

    cur.len  = ret;
    cur.type = msg_type( cur.buf, cur.len );
    cur.way  = way;
    cur.dst  = dst;
    print_packet( &cur, NULL );

    if( malform_pattern_len != 0 || opt.malform_truncate != DFL_MALFORM_TRUNCATE )
    {
        if( handle_message_malformation( &cur ) != 0 )
            return 1;
    }

    id = cur.len % sizeof( held );

    if( strcmp( way, "S <- C" ) == 0 )
    {
        delay_list     = opt.delay_cli;
        delay_list_len = opt.delay_cli_cnt;
    }
    else
    {
        delay_list     = opt.delay_srv;
        delay_list_len = opt.delay_srv_cnt;
    }

    /* Check if message type is in the list of messages
     * that should be delayed */
    for( delay_idx = 0; delay_idx < delay_list_len; delay_idx++ )
    {
        if( delay_list[ delay_idx ] == NULL )
            continue;

        if( strcmp( delay_list[ delay_idx ], cur.type ) == 0 )
        {
            /* Delay message */
            delay_packet( &cur );

            /* Remove entry from list */
            mbedtls_free( delay_list[delay_idx] );
            delay_list[delay_idx] = NULL;

            return( 0 );
        }
    }

    /* do we want to drop, delay, or forward it? */
    if( ( opt.mtu != 0 &&
          cur.len > (unsigned) opt.mtu ) ||
        ( opt.drop != 0 &&
          strcmp( cur.type, "CID" ) != 0             &&
          strcmp( cur.type, "ApplicationData" ) != 0 &&
          ! ( opt.protect_hvr &&
              strcmp( cur.type, "HelloVerifyRequest" ) == 0 ) &&
          cur.len != (size_t) opt.protect_len &&
          held[id] < HOLD_MAX &&
          rand() % opt.drop == 0 ) )
    {
        ++held[id];
    }
    else if( ( opt.delay_ccs == 1 &&
               strcmp( cur.type, "ChangeCipherSpec" ) == 0 ) ||
             ( opt.delay != 0 &&
               strcmp( cur.type, "CID" ) != 0             &&
               strcmp( cur.type, "ApplicationData" ) != 0 &&
               ! ( opt.protect_hvr &&
                   strcmp( cur.type, "HelloVerifyRequest" ) == 0 ) &&
               cur.len != (size_t) opt.protect_len &&
               held[id] < HOLD_MAX &&
               rand() % opt.delay == 0 ) )
    {
        ++held[id];
        delay_packet( &cur );
    }
    else
    {
        /* forward and possibly duplicate */
        if( ( ret = send_packet( &cur, "forwarded" ) ) != 0 )
            return( ret );

        /* send previously delayed messages if any */
        ret = send_delayed();
        if( ret != 0 )
            return( ret );
    }

    return( 0 );
}

int main( int argc, char *argv[] )
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    uint8_t delay_idx;

    mbedtls_net_context listen_fd, client_fd, server_fd;

#if defined( MBEDTLS_TIMING_C )
    struct timeval tm;
#endif

    struct timeval *tm_ptr = NULL;

    int nb_fds;
    fd_set read_fds;

    mbedtls_net_init( &listen_fd );
    mbedtls_net_init( &client_fd );
    mbedtls_net_init( &server_fd );

    get_options( argc, argv );

    /*
     * Decisions to drop/delay/duplicate packets are pseudo-random: dropping
     * exactly 1 in N packets would lead to problems when a flight has exactly
     * N packets: the same packet would be dropped on every resend.
     *
     * In order to be able to reproduce problems reliably, the seed may be
     * specified explicitly.
     */
    if( opt.seed == 0 )
    {
#if defined(MBEDTLS_HAVE_TIME)
        opt.seed = (unsigned int) mbedtls_time( NULL );
#else
        opt.seed = 1;
#endif /* MBEDTLS_HAVE_TIME */
        mbedtls_printf( "  . Pseudo-random seed: %u\n", opt.seed );
    }

    srand( opt.seed );

    /*
     * 0. "Connect" to the server
     */
    mbedtls_printf( "  . Connect to server on UDP/%s/%s ...",
            opt.server_addr, opt.server_port );
    fflush( stdout );

    if( ( ret = mbedtls_net_connect( &server_fd, opt.server_addr, opt.server_port,
                             MBEDTLS_NET_PROTO_UDP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 1. Setup the "listening" UDP socket
     */
    mbedtls_printf( "  . Bind on UDP/%s/%s ...",
            opt.listen_addr, opt.listen_port );
    fflush( stdout );

    if( ( ret = mbedtls_net_bind( &listen_fd, opt.listen_addr, opt.listen_port,
                          MBEDTLS_NET_PROTO_UDP ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 2. Wait until a client connects
     */
accept:
    mbedtls_net_free( &client_fd );

    malform_counter = 0;
#if defined(MBEDTLS_SHA256_C)
    reset_packet_hashes( );
#endif
    mbedtls_printf( "  . Waiting for a remote connection ..." );
    fflush( stdout );

    if( ( ret = mbedtls_net_accept( &listen_fd, &client_fd,
                                    NULL, 0, NULL ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * 3. Forward packets forever (kill the process to terminate it)
     */
    clear_pending();
    memset( held, 0, sizeof( held ) );

    nb_fds = client_fd.fd;
    if( nb_fds < server_fd.fd )
        nb_fds = server_fd.fd;
    if( nb_fds < listen_fd.fd )
        nb_fds = listen_fd.fd;
    ++nb_fds;

#if defined(MBEDTLS_TIMING_C)
    if( opt.pack > 0 )
    {
        outbuf[0].ctx = &server_fd;
        outbuf[0].description = "S <- C";
        outbuf[0].num_datagrams = 0;
        outbuf[0].len = 0;

        outbuf[1].ctx = &client_fd;
        outbuf[1].description = "S -> C";
        outbuf[1].num_datagrams = 0;
        outbuf[1].len = 0;
    }
#endif /* MBEDTLS_TIMING_C */

    while( 1 )
    {
#if defined(MBEDTLS_TIMING_C)
        if( opt.pack > 0 )
        {
            unsigned max_wait_server, max_wait_client, max_wait;
            max_wait_server = ctx_buffer_time_remaining( &outbuf[0] );
            max_wait_client = ctx_buffer_time_remaining( &outbuf[1] );

            max_wait = (unsigned) -1;

            if( max_wait_server == 0 )
                ctx_buffer_flush( &outbuf[0] );
            else
                max_wait = max_wait_server;

            if( max_wait_client == 0 )
                ctx_buffer_flush( &outbuf[1] );
            else
            {
                if( max_wait_client < max_wait )
                    max_wait = max_wait_client;
            }

            if( max_wait != (unsigned) -1 )
            {
                tm.tv_sec  = max_wait / 1000;
                tm.tv_usec = ( max_wait % 1000 ) * 1000;

                tm_ptr = &tm;
            }
            else
            {
                tm_ptr = NULL;
            }
        }
#endif /* MBEDTLS_TIMING_C */

        FD_ZERO( &read_fds );
        FD_SET( server_fd.fd, &read_fds );
        FD_SET( client_fd.fd, &read_fds );
        FD_SET( listen_fd.fd, &read_fds );

        if( ( ret = select( nb_fds, &read_fds, NULL, NULL, tm_ptr ) ) < 0 )
        {
            perror( "select" );
            goto exit;
        }

        if( FD_ISSET( listen_fd.fd, &read_fds ) )
        {
            mbedtls_printf( "  . New connection incomming\n" );
            goto accept;
        }

        if( FD_ISSET( client_fd.fd, &read_fds ) )
        {
            if( ( ret = handle_message( "S <- C",
                                        &server_fd, &client_fd ) ) != 0 )
            {
                mbedtls_printf( "  . Unhandled S <- C message\n" );
                goto accept;
            }
        }

        if( FD_ISSET( server_fd.fd, &read_fds ) )
        {
            if( ( ret = handle_message( "S -> C",
                                        &client_fd, &server_fd ) ) != 0 )
            {
                mbedtls_printf( "  . Unhandled S -> C message\n" );
                goto accept;
            }
        }
    }

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#ifdef MBEDTLS_ERROR_C
    if( exit_code != MBEDTLS_EXIT_SUCCESS )
    {
        char error_buf[100];
        mbedtls_strerror( ret, error_buf, 100 );
        mbedtls_printf( "Last error was: -0x%04X - %s\n\n", (unsigned int) -ret, error_buf );
        fflush( stdout );
    }
#endif

    for( delay_idx = 0; delay_idx < MAX_DELAYED_HS; delay_idx++ )
    {
        mbedtls_free( opt.delay_cli[delay_idx] );
        mbedtls_free( opt.delay_srv[delay_idx] );
    }

    mbedtls_net_free( &client_fd );
    mbedtls_net_free( &server_fd );
    mbedtls_net_free( &listen_fd );

    mbedtls_exit( exit_code );
}

#endif /* MBEDTLS_NET_C */
