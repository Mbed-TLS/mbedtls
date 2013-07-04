/*
 *  SSLv3/TLSv1 client-side functions
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

#if defined(POLARSSL_SSL_CLI_C)

#include "polarssl/debug.h"
#include "polarssl/ssl.h"

#include <stdlib.h>
#include <stdio.h>

#ifdef _MSC_VER
#include <basetsd.h>
typedef UINT32 uint32_t;
#else
#include <inttypes.h>
#endif

#if defined(POLARSSL_HAVE_TIME)
#include <time.h>
#endif

static void ssl_write_hostname_ext( ssl_context *ssl,
                                    unsigned char *buf,
                                    size_t *olen )
{
    unsigned char *p = buf;

    *olen = 0;

    if ( ssl->hostname == NULL )
        return;

    SSL_DEBUG_MSG( 3, ( "client hello, adding server name extension: %s",
                   ssl->hostname ) );

    /*
     * struct {
     *     NameType name_type;
     *     select (name_type) {
     *         case host_name: HostName;
     *     } name;
     * } ServerName;
     *
     * enum {
     *     host_name(0), (255)
     * } NameType;
     *
     * opaque HostName<1..2^16-1>;
     *
     * struct {
     *     ServerName server_name_list<1..2^16-1>
     * } ServerNameList;
     */
    *p++ = (unsigned char)( ( TLS_EXT_SERVERNAME >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( TLS_EXT_SERVERNAME      ) & 0xFF );

    *p++ = (unsigned char)( ( (ssl->hostname_len + 5) >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( (ssl->hostname_len + 5)      ) & 0xFF );

    *p++ = (unsigned char)( ( (ssl->hostname_len + 3) >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( (ssl->hostname_len + 3)      ) & 0xFF );

    *p++ = (unsigned char)( ( TLS_EXT_SERVERNAME_HOSTNAME ) & 0xFF );
    *p++ = (unsigned char)( ( ssl->hostname_len >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ssl->hostname_len      ) & 0xFF );

    memcpy( p, ssl->hostname, ssl->hostname_len );

    *olen = ssl->hostname_len + 9;
}

static void ssl_write_renegotiation_ext( ssl_context *ssl,
                                         unsigned char *buf,
                                         size_t *olen )
{
    unsigned char *p = buf;

    *olen = 0;

    if( ssl->renegotiation != SSL_RENEGOTIATION )
        return;

    SSL_DEBUG_MSG( 3, ( "client hello, adding renegotiation extension" ) );

    /*
     * Secure renegotiation
     */
    *p++ = (unsigned char)( ( TLS_EXT_RENEGOTIATION_INFO >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( TLS_EXT_RENEGOTIATION_INFO      ) & 0xFF );

    *p++ = 0x00;
    *p++ = ( ssl->verify_data_len + 1 ) & 0xFF;
    *p++ = ssl->verify_data_len & 0xFF;

    memcpy( p, ssl->own_verify_data, ssl->verify_data_len );

    *olen = 5 + ssl->verify_data_len;
}

static void ssl_write_signature_algorithms_ext( ssl_context *ssl,
                                                unsigned char *buf,
                                                size_t *olen )
{
    unsigned char *p = buf;
    unsigned char sig_alg_list[20];
    size_t sig_alg_len = 0;

    *olen = 0;

    if( ssl->max_minor_ver != SSL_MINOR_VERSION_3 )
        return;

    SSL_DEBUG_MSG( 3, ( "client hello, adding signature_algorithms extension" ) );

    /*
     * Prepare signature_algorithms extension (TLS 1.2)
     */
#if defined(POLARSSL_SHA512_C)
    sig_alg_list[sig_alg_len++] = SSL_HASH_SHA512;
    sig_alg_list[sig_alg_len++] = SSL_SIG_RSA;
    sig_alg_list[sig_alg_len++] = SSL_HASH_SHA384;
    sig_alg_list[sig_alg_len++] = SSL_SIG_RSA;
#endif
#if defined(POLARSSL_SHA256_C)
    sig_alg_list[sig_alg_len++] = SSL_HASH_SHA256;
    sig_alg_list[sig_alg_len++] = SSL_SIG_RSA;
    sig_alg_list[sig_alg_len++] = SSL_HASH_SHA224;
    sig_alg_list[sig_alg_len++] = SSL_SIG_RSA;
#endif
#if defined(POLARSSL_SHA1_C)
    sig_alg_list[sig_alg_len++] = SSL_HASH_SHA1;
    sig_alg_list[sig_alg_len++] = SSL_SIG_RSA;
#endif
#if defined(POLARSSL_MD5_C)
    sig_alg_list[sig_alg_len++] = SSL_HASH_MD5;
    sig_alg_list[sig_alg_len++] = SSL_SIG_RSA;
#endif

    /*
     * enum {
     *     none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
     *     sha512(6), (255)
     * } HashAlgorithm;
     *
     * enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
     *   SignatureAlgorithm;
     *
     * struct {
     *     HashAlgorithm hash;
     *     SignatureAlgorithm signature;
     * } SignatureAndHashAlgorithm;
     *
     * SignatureAndHashAlgorithm
     *   supported_signature_algorithms<2..2^16-2>;
     */
    *p++ = (unsigned char)( ( TLS_EXT_SIG_ALG >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( TLS_EXT_SIG_ALG      ) & 0xFF );

    *p++ = (unsigned char)( ( ( sig_alg_len + 2 ) >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ( sig_alg_len + 2 )      ) & 0xFF );

    *p++ = (unsigned char)( ( sig_alg_len >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( sig_alg_len      ) & 0xFF );

    memcpy( p, sig_alg_list, sig_alg_len );

    *olen = 6 + sig_alg_len;
}

#if defined(POLARSSL_ECDH_C)
static void ssl_write_supported_elliptic_curves_ext( ssl_context *ssl,
                                                     unsigned char *buf,
                                                     size_t *olen )
{
    unsigned char *p = buf;
    unsigned char elliptic_curve_list[20];
    size_t elliptic_curve_len = 0;
    ((void) ssl);

    *olen = 0;

    SSL_DEBUG_MSG( 3, ( "client hello, adding supported_elliptic_curves extension" ) );

#if defined(POLARSSL_ECP_DP_SECP521R1_ENABLED)
    elliptic_curve_list[elliptic_curve_len++] = 0x00;
    elliptic_curve_list[elliptic_curve_len++] = POLARSSL_ECP_DP_SECP521R1;
#endif
#if defined(POLARSSL_ECP_DP_SECP384R1_ENABLED)
    elliptic_curve_list[elliptic_curve_len++] = 0x00;
    elliptic_curve_list[elliptic_curve_len++] = POLARSSL_ECP_DP_SECP384R1;
#endif
#if defined(POLARSSL_ECP_DP_SECP256R1_ENABLED)
    elliptic_curve_list[elliptic_curve_len++] = 0x00;
    elliptic_curve_list[elliptic_curve_len++] = POLARSSL_ECP_DP_SECP256R1;
#endif
#if defined(POLARSSL_ECP_DP_SECP224R1_ENABLED)
    elliptic_curve_list[elliptic_curve_len++] = 0x00;
    elliptic_curve_list[elliptic_curve_len++] = POLARSSL_ECP_DP_SECP224R1;
#endif
#if defined(POLARSSL_ECP_DP_SECP192R1_ENABLED)
    elliptic_curve_list[elliptic_curve_len++] = 0x00;
    elliptic_curve_list[elliptic_curve_len++] = POLARSSL_ECP_DP_SECP192R1;
#endif

    if( elliptic_curve_len == 0 )
        return;

    *p++ = (unsigned char)( ( TLS_EXT_SUPPORTED_ELLIPTIC_CURVES >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( TLS_EXT_SUPPORTED_ELLIPTIC_CURVES      ) & 0xFF );

    *p++ = (unsigned char)( ( ( elliptic_curve_len + 2 ) >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ( elliptic_curve_len + 2 )      ) & 0xFF );

    *p++ = (unsigned char)( ( ( elliptic_curve_len     ) >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ( elliptic_curve_len     )      ) & 0xFF );

    memcpy( p, elliptic_curve_list, elliptic_curve_len );

    *olen = 6 + elliptic_curve_len;
}

static void ssl_write_supported_point_formats_ext( ssl_context *ssl,
                                                   unsigned char *buf,
                                                   size_t *olen )
{
    unsigned char *p = buf;
    ((void) ssl);

    *olen = 0;

    SSL_DEBUG_MSG( 3, ( "client hello, adding supported_point_formats extension" ) );

    *p++ = (unsigned char)( ( TLS_EXT_SUPPORTED_POINT_FORMATS >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( TLS_EXT_SUPPORTED_POINT_FORMATS      ) & 0xFF );

    *p++ = 0x00;
    *p++ = 3;

    *p++ = 2;
    *p++ = POLARSSL_ECP_PF_COMPRESSED;
    *p++ = POLARSSL_ECP_PF_UNCOMPRESSED;

    *olen = 7;
}
#endif

static int ssl_write_client_hello( ssl_context *ssl )
{
    int ret;
    size_t i, n, olen, ext_len = 0;
    unsigned char *buf;
    unsigned char *p, *q;
#if defined(POLARSSL_HAVE_TIME)
    time_t t;
#endif
    const int *ciphersuites;
    const ssl_ciphersuite_t *ciphersuite_info;

    SSL_DEBUG_MSG( 2, ( "=> write client hello" ) );

    if( ssl->renegotiation == SSL_INITIAL_HANDSHAKE )
    {
        ssl->major_ver = ssl->min_major_ver;
        ssl->minor_ver = ssl->min_minor_ver;
    }

    if( ssl->max_major_ver == 0 && ssl->max_minor_ver == 0 )
    {
        ssl->max_major_ver = SSL_MAJOR_VERSION_3;
        ssl->max_minor_ver = SSL_MINOR_VERSION_3;
    }

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   highest version supported
     *     6  .   9   current UNIX time
     *    10  .  37   random bytes
     */
    buf = ssl->out_msg;
    p = buf + 4;

    *p++ = (unsigned char) ssl->max_major_ver;
    *p++ = (unsigned char) ssl->max_minor_ver;

    SSL_DEBUG_MSG( 3, ( "client hello, max version: [%d:%d]",
                   buf[4], buf[5] ) );

#if defined(POLARSSL_HAVE_TIME)
    t = time( NULL );
    *p++ = (unsigned char)( t >> 24 );
    *p++ = (unsigned char)( t >> 16 );
    *p++ = (unsigned char)( t >>  8 );
    *p++ = (unsigned char)( t       );

    SSL_DEBUG_MSG( 3, ( "client hello, current time: %lu", t ) );
#else
    if( ( ret = ssl->f_rng( ssl->p_rng, p, 4 ) ) != 0 )
        return( ret );

    p += 4;
#endif

    if( ( ret = ssl->f_rng( ssl->p_rng, p, 28 ) ) != 0 )
        return( ret );

    p += 28;

    memcpy( ssl->handshake->randbytes, buf + 6, 32 );

    SSL_DEBUG_BUF( 3, "client hello, random bytes", buf + 6, 32 );

    /*
     *    38  .  38   session id length
     *    39  . 39+n  session id
     *   40+n . 41+n  ciphersuitelist length
     *   42+n . ..    ciphersuitelist
     *   ..   . ..    compression methods length
     *   ..   . ..    compression methods
     *   ..   . ..    extensions length
     *   ..   . ..    extensions
     */
    n = ssl->session_negotiate->length;

    if( ssl->renegotiation != SSL_INITIAL_HANDSHAKE || n < 16 || n > 32 ||
        ssl->handshake->resume == 0 )
        n = 0;

    *p++ = (unsigned char) n;

    for( i = 0; i < n; i++ )
        *p++ = ssl->session_negotiate->id[i];

    SSL_DEBUG_MSG( 3, ( "client hello, session id len.: %d", n ) );
    SSL_DEBUG_BUF( 3,   "client hello, session id", buf + 39, n );

    ciphersuites = ssl->ciphersuite_list[ssl->minor_ver];
    n = 0;
    q = p;

    // Skip writing ciphersuite length for now
    p += 2;

    /*
     * Add TLS_EMPTY_RENEGOTIATION_INFO_SCSV
     */
    if( ssl->renegotiation == SSL_INITIAL_HANDSHAKE )
    {
        *p++ = (unsigned char)( SSL_EMPTY_RENEGOTIATION_INFO >> 8 );
        *p++ = (unsigned char)( SSL_EMPTY_RENEGOTIATION_INFO      );
        n++;
    }

    for( i = 0; ciphersuites[i] != 0; i++ )
    {
        ciphersuite_info = ssl_ciphersuite_from_id( ciphersuites[i] );

        if( ciphersuite_info == NULL )
            continue;

        if( ciphersuite_info->min_minor_ver > ssl->max_minor_ver ||
            ciphersuite_info->max_minor_ver < ssl->min_minor_ver )
            continue;

        SSL_DEBUG_MSG( 3, ( "client hello, add ciphersuite: %2d",
                       ciphersuites[i] ) );

        n++;
        *p++ = (unsigned char)( ciphersuites[i] >> 8 );
        *p++ = (unsigned char)( ciphersuites[i]      );
    }

    *q++ = (unsigned char)( n >> 7 );
    *q++ = (unsigned char)( n << 1 );

    SSL_DEBUG_MSG( 3, ( "client hello, got %d ciphersuites", n ) );


#if defined(POLARSSL_ZLIB_SUPPORT)
    SSL_DEBUG_MSG( 3, ( "client hello, compress len.: %d", 2 ) );
    SSL_DEBUG_MSG( 3, ( "client hello, compress alg.: %d %d",
                        SSL_COMPRESS_DEFLATE, SSL_COMPRESS_NULL ) );

    *p++ = 2;
    *p++ = SSL_COMPRESS_DEFLATE;
    *p++ = SSL_COMPRESS_NULL;
#else
    SSL_DEBUG_MSG( 3, ( "client hello, compress len.: %d", 1 ) );
    SSL_DEBUG_MSG( 3, ( "client hello, compress alg.: %d", SSL_COMPRESS_NULL ) );

    *p++ = 1;
    *p++ = SSL_COMPRESS_NULL;
#endif

    // First write extensions, then the total length
    //
    ssl_write_hostname_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;

    ssl_write_renegotiation_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;

    ssl_write_signature_algorithms_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;

#if defined(POLARSSL_ECDH_C)
    ssl_write_supported_elliptic_curves_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;

    ssl_write_supported_point_formats_ext( ssl, p + 2 + ext_len, &olen );
    ext_len += olen;
#endif

    SSL_DEBUG_MSG( 3, ( "client hello, total extension length: %d",
                   ext_len ) );

    *p++ = (unsigned char)( ( ext_len >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ext_len      ) & 0xFF );
    p += ext_len;

    ssl->out_msglen  = p - buf;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CLIENT_HELLO;

    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_write_record", ret );
        return( ret );
    }

    SSL_DEBUG_MSG( 2, ( "<= write client hello" ) );

    return( 0 );
}

static int ssl_parse_renegotiation_info( ssl_context *ssl,
                                         unsigned char *buf,
                                         size_t len )
{
    int ret;

    if( ssl->renegotiation == SSL_INITIAL_HANDSHAKE )
    {
        if( len != 1 || buf[0] != 0x0 )
        {
            SSL_DEBUG_MSG( 1, ( "non-zero length renegotiated connection field" ) );

            if( ( ret = ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                return( ret );

            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
        }

        ssl->secure_renegotiation = SSL_SECURE_RENEGOTIATION;
    }
    else
    {
        if( len    != 1 + ssl->verify_data_len * 2 ||
            buf[0] !=     ssl->verify_data_len * 2 ||
            memcmp( buf + 1, ssl->own_verify_data,  ssl->verify_data_len ) != 0 ||
            memcmp( buf + 1 + ssl->verify_data_len,
                    ssl->peer_verify_data, ssl->verify_data_len ) != 0 )
        {
            SSL_DEBUG_MSG( 1, ( "non-matching renegotiated connection field" ) );

            if( ( ret = ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
                return( ret );

            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
        }
    }

    return( 0 );
}

static int ssl_parse_server_hello( ssl_context *ssl )
{
    uint32_t t;
    int ret, i, comp;
    size_t n;
    size_t ext_len = 0;
    unsigned char *buf, *ext;
    int renegotiation_info_seen = 0;
    int handshake_failure = 0;

    SSL_DEBUG_MSG( 2, ( "=> parse server hello" ) );

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   protocol version
     *     6  .   9   UNIX time()
     *    10  .  37   random bytes
     */
    buf = ssl->in_msg;

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_read_record", ret );
        return( ret );
    }

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
    {
        SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    SSL_DEBUG_MSG( 3, ( "server hello, chosen version: [%d:%d]",
                   buf[4], buf[5] ) );

    if( ssl->in_hslen < 42 ||
        buf[0] != SSL_HS_SERVER_HELLO ||
        buf[4] != SSL_MAJOR_VERSION_3 )
    {
        SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    if( buf[5] > ssl->max_minor_ver )
    {
        SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    ssl->minor_ver = buf[5];

    if( ssl->minor_ver < ssl->min_minor_ver )
    {
        SSL_DEBUG_MSG( 1, ( "server only supports ssl smaller than minimum"
                            " [%d:%d] < [%d:%d]", ssl->major_ver, ssl->minor_ver,
                            buf[4], buf[5] ) );

        ssl_send_alert_message( ssl, SSL_ALERT_LEVEL_FATAL,
                                     SSL_ALERT_MSG_PROTOCOL_VERSION );

        return( POLARSSL_ERR_SSL_BAD_HS_PROTOCOL_VERSION );
    }

#if defined(POLARSSL_DEBUG_C)
    t = ( (uint32_t) buf[6] << 24 )
      | ( (uint32_t) buf[7] << 16 )
      | ( (uint32_t) buf[8] <<  8 )
      | ( (uint32_t) buf[9]       );
#endif

    memcpy( ssl->handshake->randbytes + 32, buf + 6, 32 );

    n = buf[38];

    SSL_DEBUG_MSG( 3, ( "server hello, current time: %lu", t ) );
    SSL_DEBUG_BUF( 3,   "server hello, random bytes", buf + 6, 32 );

    if( n > 32 )
    {
        SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    /*
     *    38  .  38   session id length
     *    39  . 38+n  session id
     *   39+n . 40+n  chosen ciphersuite
     *   41+n . 41+n  chosen compression alg.
     *   42+n . 43+n  extensions length
     *   44+n . 44+n+m extensions
     */
    if( ssl->in_hslen > 42 + n )
    {
        ext_len = ( ( buf[42 + n] <<  8 )
                  | ( buf[43 + n]       ) );

        if( ( ext_len > 0 && ext_len < 4 ) ||
            ssl->in_hslen != 44 + n + ext_len )
        {
            SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
        }
    }

    i = ( buf[39 + n] << 8 ) | buf[40 + n];
    comp = buf[41 + n];

    /*
     * Initialize update checksum functions
     */
    ssl->transform_negotiate->ciphersuite_info = ssl_ciphersuite_from_id( i );
    ssl_optimize_checksum( ssl, ssl->transform_negotiate->ciphersuite_info );

    if( ssl->transform_negotiate->ciphersuite_info == NULL )
    {
        SSL_DEBUG_MSG( 1, ( "ciphersuite info for %02x not found",
                          ssl->ciphersuite_list[ssl->minor_ver][i] ) );
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
    }

    SSL_DEBUG_MSG( 3, ( "server hello, session id len.: %d", n ) );
    SSL_DEBUG_BUF( 3,   "server hello, session id", buf + 39, n );

    /*
     * Check if the session can be resumed
     */
    if( ssl->renegotiation != SSL_INITIAL_HANDSHAKE ||
        ssl->handshake->resume == 0 || n == 0 ||
        ssl->session_negotiate->ciphersuite != i ||
        ssl->session_negotiate->compression != comp ||
        ssl->session_negotiate->length != n ||
        memcmp( ssl->session_negotiate->id, buf + 39, n ) != 0 )
    {
        ssl->state++;
        ssl->handshake->resume = 0;
#if defined(POLARSSL_HAVE_TIME)
        ssl->session_negotiate->start = time( NULL );
#endif
        ssl->session_negotiate->ciphersuite = i;
        ssl->session_negotiate->compression = comp;
        ssl->session_negotiate->length = n;
        memcpy( ssl->session_negotiate->id, buf + 39, n );
    }
    else
    {
        ssl->state = SSL_SERVER_CHANGE_CIPHER_SPEC;

        if( ( ret = ssl_derive_keys( ssl ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ssl_derive_keys", ret );
            return( ret );
        }
    }

    SSL_DEBUG_MSG( 3, ( "%s session has been resumed",
                   ssl->handshake->resume ? "a" : "no" ) );

    SSL_DEBUG_MSG( 3, ( "server hello, chosen ciphersuite: %d", i ) );
    SSL_DEBUG_MSG( 3, ( "server hello, compress alg.: %d", buf[41 + n] ) );

    i = 0;
    while( 1 )
    {
        if( ssl->ciphersuite_list[ssl->minor_ver][i] == 0 )
        {
            SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
        }

        if( ssl->ciphersuite_list[ssl->minor_ver][i++] ==
            ssl->session_negotiate->ciphersuite )
        {
            break;
        }
    }

    if( comp != SSL_COMPRESS_NULL
#if defined(POLARSSL_ZLIB_SUPPORT)
        && comp != SSL_COMPRESS_DEFLATE
#endif
      )
    {
        SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
    }
    ssl->session_negotiate->compression = comp;

    ext = buf + 44 + n;

    while( ext_len )
    {
        unsigned int ext_id   = ( ( ext[0] <<  8 )
                                | ( ext[1]       ) );
        unsigned int ext_size = ( ( ext[2] <<  8 )
                                | ( ext[3]       ) );

        if( ext_size + 4 > ext_len )
        {
            SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
        }

        switch( ext_id )
        {
        case TLS_EXT_RENEGOTIATION_INFO:
            SSL_DEBUG_MSG( 3, ( "found renegotiation extension" ) );
            renegotiation_info_seen = 1;

            if( ( ret = ssl_parse_renegotiation_info( ssl, ext + 4, ext_size ) ) != 0 )
                return( ret );

            break;

        default:
            SSL_DEBUG_MSG( 3, ( "unknown extension found: %d (ignoring)",
                           ext_id ) );
        }

        ext_len -= 4 + ext_size;
        ext += 4 + ext_size;

        if( ext_len > 0 && ext_len < 4 )
        {
            SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
        }
    }

    /*
     * Renegotiation security checks
     */
    if( ssl->secure_renegotiation == SSL_LEGACY_RENEGOTIATION &&
        ssl->allow_legacy_renegotiation == SSL_LEGACY_BREAK_HANDSHAKE )
    {
        SSL_DEBUG_MSG( 1, ( "legacy renegotiation, breaking off handshake" ) );
        handshake_failure = 1;
    }
    else if( ssl->renegotiation == SSL_RENEGOTIATION &&
             ssl->secure_renegotiation == SSL_SECURE_RENEGOTIATION &&
             renegotiation_info_seen == 0 )
    {
        SSL_DEBUG_MSG( 1, ( "renegotiation_info extension missing (secure)" ) );
        handshake_failure = 1;
    }
    else if( ssl->renegotiation == SSL_RENEGOTIATION &&
             ssl->secure_renegotiation == SSL_LEGACY_RENEGOTIATION &&
             ssl->allow_legacy_renegotiation == SSL_LEGACY_NO_RENEGOTIATION )
    {
        SSL_DEBUG_MSG( 1, ( "legacy renegotiation not allowed" ) );
        handshake_failure = 1;
    }
    else if( ssl->renegotiation == SSL_RENEGOTIATION &&
             ssl->secure_renegotiation == SSL_LEGACY_RENEGOTIATION &&
             renegotiation_info_seen == 1 )
    {
        SSL_DEBUG_MSG( 1, ( "renegotiation_info extension present (legacy)" ) );
        handshake_failure = 1;
    }

    if( handshake_failure == 1 )
    {
        if( ( ret = ssl_send_fatal_handshake_failure( ssl ) ) != 0 )
            return( ret );

        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    SSL_DEBUG_MSG( 2, ( "<= parse server hello" ) );

    return( 0 );
}

#if defined(POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED)
static int ssl_parse_server_dh_params( ssl_context *ssl, unsigned char **p,
                                       unsigned char *end )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;

    /*
     * Ephemeral DH parameters:
     *
     * struct {
     *     opaque dh_p<1..2^16-1>;
     *     opaque dh_g<1..2^16-1>;
     *     opaque dh_Ys<1..2^16-1>;
     * } ServerDHParams;
     */
    if( ( ret = dhm_read_params( &ssl->handshake->dhm_ctx, p, end ) ) != 0 )
    {
        SSL_DEBUG_RET( 2, ( "dhm_read_params" ), ret );
        return( ret );
    }

    if( ssl->handshake->dhm_ctx.len < 64  ||
        ssl->handshake->dhm_ctx.len > 512 )
    {
        SSL_DEBUG_MSG( 1, ( "bad server key exchange message (DHM length)" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
    }

    SSL_DEBUG_MPI( 3, "DHM: P ", &ssl->handshake->dhm_ctx.P  );
    SSL_DEBUG_MPI( 3, "DHM: G ", &ssl->handshake->dhm_ctx.G  );
    SSL_DEBUG_MPI( 3, "DHM: GY", &ssl->handshake->dhm_ctx.GY );

    return( ret );
}
#endif /* POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED */

#if defined(POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED)
static int ssl_parse_server_ecdh_params( ssl_context *ssl,
                                         unsigned char **p,
                                         unsigned char *end )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;

    /*
     * Ephemeral ECDH parameters:
     *
     * struct {
     *     ECParameters curve_params;
     *     ECPoint      public;
     * } ServerECDHParams;
     */
    if( ( ret = ecdh_read_params( &ssl->handshake->ecdh_ctx,
                                  (const unsigned char **) p, end ) ) != 0 )
    {
        SSL_DEBUG_RET( 2, ( "ecdh_read_params" ), ret );
        return( ret );
    }

    if( ssl->handshake->ecdh_ctx.grp.nbits < 163 ||
        ssl->handshake->ecdh_ctx.grp.nbits > 521 )
    {
        SSL_DEBUG_MSG( 1, ( "bad server key exchange message (ECDH length)" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
    }

    SSL_DEBUG_ECP( 3, "ECDH: Qp", &ssl->handshake->ecdh_ctx.Qp );

    return( ret );
}
#endif /* POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED */

#if defined(POLARSSL_KEY_EXCHANGE_PSK_ENABLED) ||                           \
    defined(POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED)
static int ssl_parse_server_psk_hint( ssl_context *ssl,
                                      unsigned char **p,
                                      unsigned char *end )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;
    size_t  len;
    ((void) ssl);

    /*
     * PSK parameters:
     *
     * opaque psk_identity_hint<0..2^16-1>;
     */
    len = (*p)[1] << 8 | (*p)[0];
    *p += 2;

    if( (*p) + len > end )
    {
        SSL_DEBUG_MSG( 1, ( "bad server key exchange message (psk_identity_hint length)" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
    }

    // TODO: Retrieve PSK identity hint and callback to app
    //
    *p += len;
    ret = 0;

    return( ret );
}
#endif /* POLARSSL_KEY_EXCHANGE_PSK_ENABLED ||
          POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED */

#if defined(POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED) ||                       \
    defined(POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED)
static int ssl_parse_signature_algorithm( ssl_context *ssl,
                                          unsigned char **p,
                                          unsigned char *end,
                                          md_type_t *md_alg )
{
    ((void) ssl);
    *md_alg = POLARSSL_MD_NONE;

    if( (*p) + 2 > end )
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );

    if( (*p)[1] != SSL_SIG_RSA )
    {
        SSL_DEBUG_MSG( 2, ( "server used unsupported SignatureAlgorithm %d", (*p)[1] ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
    }

    switch( (*p)[0] )
    {
#if defined(POLARSSL_MD5_C)
        case SSL_HASH_MD5:
            *md_alg = POLARSSL_MD_MD5;
            break;
#endif
#if defined(POLARSSL_SHA1_C)
        case SSL_HASH_SHA1:
            *md_alg = POLARSSL_MD_SHA1;
            break;
#endif
#if defined(POLARSSL_SHA256_C)
        case SSL_HASH_SHA224:
            *md_alg = POLARSSL_MD_SHA224;
            break;
        case SSL_HASH_SHA256:
            *md_alg = POLARSSL_MD_SHA256;
            break;
#endif
#if defined(POLARSSL_SHA512_C)
        case SSL_HASH_SHA384:
            *md_alg = POLARSSL_MD_SHA384;
            break;
        case SSL_HASH_SHA512:
            *md_alg = POLARSSL_MD_SHA512;
            break;
#endif
        default:
            SSL_DEBUG_MSG( 2, ( "Server used unsupported HashAlgorithm %d", *(p)[0] ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
    }

    SSL_DEBUG_MSG( 2, ( "Server used SignatureAlgorithm %d", (*p)[1] ) );
    SSL_DEBUG_MSG( 2, ( "Server used HashAlgorithm %d", (*p)[0] ) );
    *p += 2;

    return( 0 );
}
#endif /* POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED ||
          POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED */

static int ssl_parse_server_key_exchange( ssl_context *ssl )
{
    int ret;
    const ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;
    unsigned char *p, *end;
#if defined(POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED) ||                       \
    defined(POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED)
    size_t n;
    unsigned char hash[64];
    md_type_t md_alg = POLARSSL_MD_NONE;
    unsigned int hashlen = 0;
#endif 

    SSL_DEBUG_MSG( 2, ( "=> parse server key exchange" ) );

    if( ciphersuite_info->key_exchange != POLARSSL_KEY_EXCHANGE_DHE_RSA &&
        ciphersuite_info->key_exchange != POLARSSL_KEY_EXCHANGE_ECDHE_RSA &&
        ciphersuite_info->key_exchange != POLARSSL_KEY_EXCHANGE_PSK &&
        ciphersuite_info->key_exchange != POLARSSL_KEY_EXCHANGE_DHE_PSK )
    {
        SSL_DEBUG_MSG( 2, ( "<= skip parse server key exchange" ) );
        ssl->state++;
        return( 0 );
    }

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_read_record", ret );
        return( ret );
    }

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
    {
        SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
        return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    if( ssl->in_msg[0] != SSL_HS_SERVER_KEY_EXCHANGE )
    {
        if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_PSK )
        {
            ssl->record_read = 1;
            goto exit;
        }

        SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
        return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    SSL_DEBUG_BUF( 3,   "server key exchange", ssl->in_msg + 4, ssl->in_hslen - 4 );

    p   = ssl->in_msg + 4;
    end = ssl->in_msg + ssl->in_hslen;

#if defined(POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED)
    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_RSA )
    {
        if( ssl_parse_server_dh_params( ssl, &p, end ) != 0 )
        {
            SSL_DEBUG_MSG( 1, ( "failed to parsebad server key exchange message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
        }
    }
    else
#endif /* POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED */
#if defined(POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED)
    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_RSA )
    {
        if( ssl_parse_server_ecdh_params( ssl, &p, end ) != 0 )
        {
            SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
        }
    }
    else
#endif /* POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED */
#if defined(POLARSSL_KEY_EXCHANGE_PSK_ENABLED)
    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_PSK )
    {
        if( ssl_parse_server_psk_hint( ssl, &p, end ) != 0 )
        {
            SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
        }
    }
    else
#endif /* POLARSSL_KEY_EXCHANGE_PSK_ENABLED */
#if defined(POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED)
    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_PSK )
    {
        if( ssl_parse_server_psk_hint( ssl, &p, end ) != 0 )
        {
            SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
        }
        if( ssl_parse_server_dh_params( ssl, &p, end ) != 0 )
        {
            SSL_DEBUG_MSG( 1, ( "failed to parsebad server key exchange message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
        }
    }
    else
#endif /* POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED */
    {
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

#if defined(POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED) ||                       \
    defined(POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED)
    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_RSA ||
        ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_RSA )
    {
        /*
         * Handle the digitally-signed structure
         */
        if( ssl->minor_ver == SSL_MINOR_VERSION_3 )
        {
            if( ssl_parse_signature_algorithm( ssl, &p, end, &md_alg ) != 0 )
            {
                SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
                return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
            }
        }

        n = ( p[0] << 8 ) | p[1];
        p += 2;

        if( end != p + n )
        {
            SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
        }

        if( (unsigned int)( end - p ) !=
            ssl->session_negotiate->peer_cert->rsa.len )
        {
            SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
        }

        if( ssl->minor_ver != SSL_MINOR_VERSION_3 )
        {
            md5_context md5;
            sha1_context sha1;

            /*
             * digitally-signed struct {
             *     opaque md5_hash[16];
             *     opaque sha_hash[20];
             * };
             *
             * md5_hash
             *     MD5(ClientHello.random + ServerHello.random
             *                            + ServerParams);
             * sha_hash
             *     SHA(ClientHello.random + ServerHello.random
             *                            + ServerParams);
             */
            n = ssl->in_hslen - ( end - p ) - 6;

            md5_starts( &md5 );
            md5_update( &md5, ssl->handshake->randbytes, 64 );
            md5_update( &md5, ssl->in_msg + 4, n );
            md5_finish( &md5, hash );

            sha1_starts( &sha1 );
            sha1_update( &sha1, ssl->handshake->randbytes, 64 );
            sha1_update( &sha1, ssl->in_msg + 4, n );
            sha1_finish( &sha1, hash + 16 );

            md_alg = POLARSSL_MD_NONE;
            hashlen = 36;
        }
        else
        {
            md_context_t ctx;

            n = ssl->in_hslen - ( end - p ) - 8;

            /*
             * digitally-signed struct {
             *     opaque client_random[32];
             *     opaque server_random[32];
             *     ServerDHParams params;
             * };
             */
            if( ( ret = md_init_ctx( &ctx, md_info_from_type( md_alg ) ) ) != 0 )
            {
                SSL_DEBUG_RET( 1, "md_init_ctx", ret );
                return( ret );
            }

            md_starts( &ctx );
            md_update( &ctx, ssl->handshake->randbytes, 64 );
            md_update( &ctx, ssl->in_msg + 4, n );
            md_finish( &ctx, hash );
        }

        SSL_DEBUG_BUF( 3, "parameters hash", hash, hashlen );

        if( ( ret = rsa_pkcs1_verify( &ssl->session_negotiate->peer_cert->rsa,
                                      RSA_PUBLIC,
                                      md_alg, hashlen, hash, p ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "rsa_pkcs1_verify", ret );
            return( ret );
        }
    }
#endif /* POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED ||
          POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED */

exit:
    ssl->state++;

    SSL_DEBUG_MSG( 2, ( "<= parse server key exchange" ) );

    return( 0 );
}

static int ssl_parse_certificate_request( ssl_context *ssl )
{
    int ret;
    unsigned char *buf, *p;
    size_t n = 0, m = 0;
    size_t cert_type_len = 0, sig_alg_len = 0, dn_len = 0;

    SSL_DEBUG_MSG( 2, ( "=> parse certificate request" ) );

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   4   cert type count
     *     5  .. m-1  cert types
     *     m  .. m+1  sig alg length (TLS 1.2 only)
     *    m+1 .. n-1  SignatureAndHashAlgorithms (TLS 1.2 only)
     *     n  .. n+1  length of all DNs
     *    n+2 .. n+3  length of DN 1
     *    n+4 .. ...  Distinguished Name #1
     *    ... .. ...  length of DN 2, etc.
     */
    if( ssl->record_read == 0 )
    {
        if( ( ret = ssl_read_record( ssl ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ssl_read_record", ret );
            return( ret );
        }

        if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
        {
            SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
            return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
        }

        ssl->record_read = 1;
    }

    ssl->client_auth = 0;
    ssl->state++;

    if( ssl->in_msg[0] == SSL_HS_CERTIFICATE_REQUEST )
        ssl->client_auth++;

    SSL_DEBUG_MSG( 3, ( "got %s certificate request",
                        ssl->client_auth ? "a" : "no" ) );

    if( ssl->client_auth == 0 )
        goto exit;

    ssl->record_read = 0;

    // TODO: handshake_failure alert for an anonymous server to request
    // client authentication

    buf = ssl->in_msg;

    // Retrieve cert types
    //
    cert_type_len = buf[4];
    n = cert_type_len;

    if( ssl->in_hslen < 6 + n )
    {
        SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
    }

    p = buf + 5;
    while( cert_type_len > 0 )
    {
        if( *p == SSL_CERT_TYPE_RSA_SIGN )
        {
            ssl->handshake->cert_type = SSL_CERT_TYPE_RSA_SIGN;
            break;
        }

        cert_type_len--;
        p++;
    }

    if( ssl->handshake->cert_type == 0 )
    {
        SSL_DEBUG_MSG( 1, ( "no known cert_type provided" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
    }

    if( ssl->minor_ver == SSL_MINOR_VERSION_3 )
    {
        sig_alg_len = ( ( buf[5 + n] <<  8 )
                      | ( buf[6 + n]       ) );

        p = buf + 7 + n;
        m += 2;
        n += sig_alg_len;

        if( ssl->in_hslen < 6 + n )
        {
            SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
        }
    }

    dn_len = ( ( buf[5 + m + n] <<  8 )
             | ( buf[6 + m + n]       ) );

    n += dn_len;
    if( ssl->in_hslen != 7 + m + n )
    {
        SSL_DEBUG_MSG( 1, ( "bad certificate request message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST );
    }

exit:
    SSL_DEBUG_MSG( 2, ( "<= parse certificate request" ) );

    return( 0 );
}

static int ssl_parse_server_hello_done( ssl_context *ssl )
{
    int ret;

    SSL_DEBUG_MSG( 2, ( "=> parse server hello done" ) );

    if( ssl->record_read == 0 )
    {
        if( ( ret = ssl_read_record( ssl ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ssl_read_record", ret );
            return( ret );
        }

        if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
        {
            SSL_DEBUG_MSG( 1, ( "bad server hello done message" ) );
            return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
        }
    }
    ssl->record_read = 0;

    if( ssl->in_hslen  != 4 ||
        ssl->in_msg[0] != SSL_HS_SERVER_HELLO_DONE )
    {
        SSL_DEBUG_MSG( 1, ( "bad server hello done message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO_DONE );
    }

    ssl->state++;

    SSL_DEBUG_MSG( 2, ( "<= parse server hello done" ) );

    return( 0 );
}

static int ssl_write_client_key_exchange( ssl_context *ssl )
{
    int ret;
    size_t i, n;
    const ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

    SSL_DEBUG_MSG( 2, ( "=> write client key exchange" ) );

#if defined(POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED)
    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_RSA )
    {
        /*
         * DHM key exchange -- send G^X mod P
         */
        n = ssl->handshake->dhm_ctx.len;

        ssl->out_msg[4] = (unsigned char)( n >> 8 );
        ssl->out_msg[5] = (unsigned char)( n      );
        i = 6;

        ret = dhm_make_public( &ssl->handshake->dhm_ctx,
                                mpi_size( &ssl->handshake->dhm_ctx.P ),
                               &ssl->out_msg[i], n,
                                ssl->f_rng, ssl->p_rng );
        if( ret != 0 )
        {
            SSL_DEBUG_RET( 1, "dhm_make_public", ret );
            return( ret );
        }

        SSL_DEBUG_MPI( 3, "DHM: X ", &ssl->handshake->dhm_ctx.X  );
        SSL_DEBUG_MPI( 3, "DHM: GX", &ssl->handshake->dhm_ctx.GX );

        ssl->handshake->pmslen = ssl->handshake->dhm_ctx.len;

        if( ( ret = dhm_calc_secret( &ssl->handshake->dhm_ctx,
                                      ssl->handshake->premaster,
                                     &ssl->handshake->pmslen ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "dhm_calc_secret", ret );
            return( ret );
        }

        SSL_DEBUG_MPI( 3, "DHM: K ", &ssl->handshake->dhm_ctx.K  );
    }
    else
#endif /* POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED */
#if defined(POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED)
    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_ECDHE_RSA )
    {
        /*
         * ECDH key exchange -- send client public value
         */
        i = 4;

        ret = ecdh_make_public( &ssl->handshake->ecdh_ctx,
                                &n,
                                &ssl->out_msg[i], 1000,
                                ssl->f_rng, ssl->p_rng );
        if( ret != 0 )
        {
            SSL_DEBUG_RET( 1, "ecdh_make_public", ret );
            return( ret );
        }

        SSL_DEBUG_ECP( 3, "ECDH: Q", &ssl->handshake->ecdh_ctx.Q );

        if( ( ret = ecdh_calc_secret( &ssl->handshake->ecdh_ctx,
                                      &ssl->handshake->pmslen,
                                       ssl->handshake->premaster,
                                       POLARSSL_MPI_MAX_SIZE ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ecdh_calc_secret", ret );
            return( ret );
        }

        SSL_DEBUG_MPI( 3, "ECDH: z", &ssl->handshake->ecdh_ctx.z );
    }
    else
#endif /* POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED */
#if defined(POLARSSL_KEY_EXCHANGE_PSK_ENABLED)
    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_PSK )
    {
        unsigned char *p = ssl->handshake->premaster;

        /*
         * PSK key exchange
         *
         * opaque psk_identity<0..2^16-1>;
         */
        if( ssl->psk == NULL )
            return( POLARSSL_ERR_SSL_PRIVATE_KEY_REQUIRED );

        if( sizeof(ssl->handshake->premaster) < 4 + 2 * ssl->psk_len )
            return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );

        n = ssl->psk_identity_len;

        ssl->out_msg[4] = (unsigned char)( n >> 8 );
        ssl->out_msg[5] = (unsigned char)( n      );
        i = 6;

        memcpy( ssl->out_msg + i, ssl->psk_identity, ssl->psk_identity_len );

        *(p++) = (unsigned char)( ssl->psk_len >> 8 );
        *(p++) = (unsigned char)( ssl->psk_len      );
        p += ssl->psk_len;

        *(p++) = (unsigned char)( ssl->psk_len >> 8 );
        *(p++) = (unsigned char)( ssl->psk_len      );
        memcpy( p, ssl->psk, ssl->psk_len );
        p += ssl->psk_len;

        ssl->handshake->pmslen = 4 + 2 * ssl->psk_len;
    }
    else
#endif /* POLARSSL_KEY_EXCHANGE_PSK_ENABLED */
#if defined(POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED)
    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_PSK )
    {
        unsigned char *p = ssl->handshake->premaster;

        /*
         * DHE_PSK key exchange
         *
         * opaque psk_identity<0..2^16-1>;
         * ClientDiffieHellmanPublic public (DHM send G^X mod P)
         */
        if( ssl->psk == NULL )
            return( POLARSSL_ERR_SSL_PRIVATE_KEY_REQUIRED );

        if( sizeof(ssl->handshake->premaster) < 4 + ssl->psk_identity_len +
                                                ssl->handshake->dhm_ctx.len )
            return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );

        i = 4;
        n = ssl->psk_identity_len;
        ssl->out_msg[4] = (unsigned char)( n >> 8 );
        ssl->out_msg[5] = (unsigned char)( n      );

        memcpy( ssl->out_msg + 6, ssl->psk_identity, ssl->psk_identity_len );

        n = ssl->handshake->dhm_ctx.len;
        ssl->out_msg[6 + ssl->psk_identity_len] = (unsigned char)( n >> 8 );
        ssl->out_msg[7 + ssl->psk_identity_len] = (unsigned char)( n      );

        ret = dhm_make_public( &ssl->handshake->dhm_ctx,
                                mpi_size( &ssl->handshake->dhm_ctx.P ),
                               &ssl->out_msg[8 + ssl->psk_identity_len], n,
                                ssl->f_rng, ssl->p_rng );
        if( ret != 0 )
        {
            SSL_DEBUG_RET( 1, "dhm_make_public", ret );
            return( ret );
        }

        SSL_DEBUG_MPI( 3, "DHM: X ", &ssl->handshake->dhm_ctx.X  );
        SSL_DEBUG_MPI( 3, "DHM: GX", &ssl->handshake->dhm_ctx.GX );

        *(p++) = (unsigned char)( ssl->handshake->dhm_ctx.len >> 8 );
        *(p++) = (unsigned char)( ssl->handshake->dhm_ctx.len      );
        if( ( ret = dhm_calc_secret( &ssl->handshake->dhm_ctx,
                                      p, &n ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "dhm_calc_secret", ret );
            return( ret );
        }

        if( n != ssl->handshake->dhm_ctx.len )
        {
            SSL_DEBUG_MSG( 1, ( "dhm_calc_secret result smaller than DHM" ) );
            return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
        }

        SSL_DEBUG_MPI( 3, "DHM: K ", &ssl->handshake->dhm_ctx.K  );

        p += ssl->handshake->dhm_ctx.len;

        *(p++) = (unsigned char)( ssl->psk_len >> 8 );
        *(p++) = (unsigned char)( ssl->psk_len      );
        memcpy( p, ssl->psk, ssl->psk_len );
        p += ssl->psk_len;

        ssl->handshake->pmslen = 4 + ssl->handshake->dhm_ctx.len + ssl->psk_len;
        n = ssl->handshake->pmslen;
    }
    else
#endif /* POLARSSL_KEY_EXCHANGE_DHE_PSK_ENABLED */
#if defined(POLARSSL_KEY_EXCHANGE_RSA_ENABLED)
    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_RSA )
    {
        /*
         * RSA key exchange -- send rsa_public(pkcs1 v1.5(premaster))
         */
        ssl->handshake->premaster[0] = (unsigned char) ssl->max_major_ver;
        ssl->handshake->premaster[1] = (unsigned char) ssl->max_minor_ver;
        ssl->handshake->pmslen = 48;

        ret = ssl->f_rng( ssl->p_rng, ssl->handshake->premaster + 2,
                          ssl->handshake->pmslen - 2 );
        if( ret != 0 )
            return( ret );

        i = 4;
        n = ssl->session_negotiate->peer_cert->rsa.len;

        if( ssl->minor_ver != SSL_MINOR_VERSION_0 )
        {
            i += 2;
            ssl->out_msg[4] = (unsigned char)( n >> 8 );
            ssl->out_msg[5] = (unsigned char)( n      );
        }

        ret = rsa_pkcs1_encrypt( &ssl->session_negotiate->peer_cert->rsa,
                                  ssl->f_rng, ssl->p_rng,
                                  RSA_PUBLIC,
                                  ssl->handshake->pmslen,
                                  ssl->handshake->premaster,
                                  ssl->out_msg + i );
        if( ret != 0 )
        {
            SSL_DEBUG_RET( 1, "rsa_pkcs1_encrypt", ret );
            return( ret );
        }
    }
    else
#endif /* POLARSSL_KEY_EXCHANGE_RSA_ENABLED */
    {
        ((void) ciphersuite_info);
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    if( ( ret = ssl_derive_keys( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_derive_keys", ret );
        return( ret );
    }

    ssl->out_msglen  = i + n;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CLIENT_KEY_EXCHANGE;

    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_write_record", ret );
        return( ret );
    }

    SSL_DEBUG_MSG( 2, ( "<= write client key exchange" ) );

    return( 0 );
}

#if !defined(POLARSSL_KEY_EXCHANGE_RSA_ENABLED)       && \
    !defined(POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED)   && \
    !defined(POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED)
static int ssl_write_certificate_verify( ssl_context *ssl )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;
    const ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;

    SSL_DEBUG_MSG( 2, ( "=> write certificate verify" ) );

    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_PSK ||
        ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_PSK )
    {
        SSL_DEBUG_MSG( 2, ( "<= skip write certificate verify" ) );
        ssl->state++;
        return( 0 );
    }

    return( ret );
}
#else
static int ssl_write_certificate_verify( ssl_context *ssl )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;
    const ssl_ciphersuite_t *ciphersuite_info = ssl->transform_negotiate->ciphersuite_info;
    size_t n = 0, offset = 0;
    unsigned char hash[48];
    md_type_t md_alg = POLARSSL_MD_NONE;
    unsigned int hashlen = 0;

    SSL_DEBUG_MSG( 2, ( "=> write certificate verify" ) );

    if( ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_PSK ||
        ciphersuite_info->key_exchange == POLARSSL_KEY_EXCHANGE_DHE_PSK )
    {
        SSL_DEBUG_MSG( 2, ( "<= skip write certificate verify" ) );
        ssl->state++;
        return( 0 );
    }

    if( ssl->client_auth == 0 || ssl->own_cert == NULL )
    {
        SSL_DEBUG_MSG( 2, ( "<= skip write certificate verify" ) );
        ssl->state++;
        return( 0 );
    }

    if( ssl->rsa_key == NULL )
    {
        SSL_DEBUG_MSG( 1, ( "got no private key" ) );
        return( POLARSSL_ERR_SSL_PRIVATE_KEY_REQUIRED );
    }

    /*
     * Make an RSA signature of the handshake digests
     */
    ssl->handshake->calc_verify( ssl, hash );

    if( ssl->minor_ver != SSL_MINOR_VERSION_3 )
    {
        /*
         * digitally-signed struct {
         *     opaque md5_hash[16];
         *     opaque sha_hash[20];
         * };
         *
         * md5_hash
         *     MD5(handshake_messages);
         *
         * sha_hash
         *     SHA(handshake_messages);
         */
        hashlen = 36;
        md_alg = POLARSSL_MD_NONE;
    }
    else
    {
        /*
         * digitally-signed struct {
         *     opaque handshake_messages[handshake_messages_length];
         * };
         *
         * Taking shortcut here. We assume that the server always allows the
         * PRF Hash function and has sent it in the allowed signature
         * algorithms list received in the Certificate Request message.
         *
         * Until we encounter a server that does not, we will take this
         * shortcut.
         *
         * Reason: Otherwise we should have running hashes for SHA512 and SHA224
         *         in order to satisfy 'weird' needs from the server side.
         */
        if( ssl->transform_negotiate->ciphersuite_info->mac ==
            POLARSSL_MD_SHA384 )
        {
            md_alg = POLARSSL_MD_SHA384;
            ssl->out_msg[4] = SSL_HASH_SHA384;
            ssl->out_msg[5] = SSL_SIG_RSA;
        }
        else
        {
            md_alg = POLARSSL_MD_SHA256;
            ssl->out_msg[4] = SSL_HASH_SHA256;
            ssl->out_msg[5] = SSL_SIG_RSA;
        }

        offset = 2;
    }

    if ( ssl->rsa_key )
        n = ssl->rsa_key_len ( ssl->rsa_key );

    ssl->out_msg[4 + offset] = (unsigned char)( n >> 8 );
    ssl->out_msg[5 + offset] = (unsigned char)( n      );

    if( ssl->rsa_key )
    {
        ret = ssl->rsa_sign( ssl->rsa_key, ssl->f_rng, ssl->p_rng,
                             RSA_PRIVATE, md_alg,
                             hashlen, hash, ssl->out_msg + 6 + offset );
    }

    if (ret != 0)
    {
        SSL_DEBUG_RET( 1, "pkcs1_sign", ret );
        return( ret );
    }

    ssl->out_msglen  = 6 + n + offset;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CERTIFICATE_VERIFY;

    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_write_record", ret );
        return( ret );
    }

    SSL_DEBUG_MSG( 2, ( "<= write certificate verify" ) );

    return( ret );
}
#endif /* !POLARSSL_KEY_EXCHANGE_RSA_ENABLED &&
          !POLARSSL_KEY_EXCHANGE_DHE_RSA_ENABLED &&
          !POLARSSL_KEY_EXCHANGE_ECDHE_RSA_ENABLED */

/*
 * SSL handshake -- client side -- single step
 */
int ssl_handshake_client_step( ssl_context *ssl )
{
    int ret = 0;

    if( ssl->state == SSL_HANDSHAKE_OVER )
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );

    SSL_DEBUG_MSG( 2, ( "client state: %d", ssl->state ) );

    if( ( ret = ssl_flush_output( ssl ) ) != 0 )
        return( ret );

    switch( ssl->state )
    {
        case SSL_HELLO_REQUEST:
            ssl->state = SSL_CLIENT_HELLO;
            break;

       /*
        *  ==>   ClientHello
        */
       case SSL_CLIENT_HELLO:
           ret = ssl_write_client_hello( ssl );
           break;

       /*
        *  <==   ServerHello
        *        Certificate
        *      ( ServerKeyExchange  )
        *      ( CertificateRequest )
        *        ServerHelloDone
        */
       case SSL_SERVER_HELLO:
           ret = ssl_parse_server_hello( ssl );
           break;

       case SSL_SERVER_CERTIFICATE:
           ret = ssl_parse_certificate( ssl );
           break;

       case SSL_SERVER_KEY_EXCHANGE:
           ret = ssl_parse_server_key_exchange( ssl );
           break;

       case SSL_CERTIFICATE_REQUEST:
           ret = ssl_parse_certificate_request( ssl );
           break;

       case SSL_SERVER_HELLO_DONE:
           ret = ssl_parse_server_hello_done( ssl );
           break;

       /*
        *  ==> ( Certificate/Alert  )
        *        ClientKeyExchange
        *      ( CertificateVerify  )
        *        ChangeCipherSpec
        *        Finished
        */
       case SSL_CLIENT_CERTIFICATE:
           ret = ssl_write_certificate( ssl );
           break;

       case SSL_CLIENT_KEY_EXCHANGE:
           ret = ssl_write_client_key_exchange( ssl );
           break;

       case SSL_CERTIFICATE_VERIFY:
           ret = ssl_write_certificate_verify( ssl );
           break;

       case SSL_CLIENT_CHANGE_CIPHER_SPEC:
           ret = ssl_write_change_cipher_spec( ssl );
           break;

       case SSL_CLIENT_FINISHED:
           ret = ssl_write_finished( ssl );
           break;

       /*
        *  <==   ChangeCipherSpec
        *        Finished
        */
       case SSL_SERVER_CHANGE_CIPHER_SPEC:
           ret = ssl_parse_change_cipher_spec( ssl );
           break;

       case SSL_SERVER_FINISHED:
           ret = ssl_parse_finished( ssl );
           break;

       case SSL_FLUSH_BUFFERS:
           SSL_DEBUG_MSG( 2, ( "handshake: done" ) );
           ssl->state = SSL_HANDSHAKE_WRAPUP;
           break;

       case SSL_HANDSHAKE_WRAPUP:
           ssl_handshake_wrapup( ssl );
           break;

       default:
           SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
           return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
   }

    return( ret );
}
#endif
