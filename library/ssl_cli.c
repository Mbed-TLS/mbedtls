/*
 *  SSLv3/TLSv1 client-side functions
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

#include "polarssl/config.h"

#if defined(POLARSSL_SSL_CLI_C)

#include "polarssl/debug.h"
#include "polarssl/ssl.h"

#if defined(POLARSSL_PKCS11_C)
#include "polarssl/pkcs11.h"
#endif /* defined(POLARSSL_PKCS11_C) */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#if defined(POLARSSL_SHA4_C)
#include "polarssl/sha4.h"
#endif

static int ssl_write_client_hello( ssl_context *ssl )
{
    int ret;
    size_t i, n, ext_len = 0;
    unsigned char *buf;
    unsigned char *p;
    time_t t;
    unsigned char sig_alg_list[20];
    size_t sig_alg_len = 0;

    SSL_DEBUG_MSG( 2, ( "=> write client hello" ) );

    ssl->major_ver = SSL_MAJOR_VERSION_3;
    ssl->minor_ver = SSL_MINOR_VERSION_0;

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

    t = time( NULL );
    *p++ = (unsigned char)( t >> 24 );
    *p++ = (unsigned char)( t >> 16 );
    *p++ = (unsigned char)( t >>  8 );
    *p++ = (unsigned char)( t       );

    SSL_DEBUG_MSG( 3, ( "client hello, current time: %lu", t ) );

    if( ( ret = ssl->f_rng( ssl->p_rng, p, 28 ) ) != 0 )
        return( ret );

    p += 28;

    memcpy( ssl->randbytes, buf + 6, 32 );

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
    n = ssl->session->length;

    if( n < 16 || n > 32 || ssl->resume == 0 ||
        ( ssl->timeout != 0 && t - ssl->session->start > ssl->timeout ) )
        n = 0;

    *p++ = (unsigned char) n;

    for( i = 0; i < n; i++ )
        *p++ = ssl->session->id[i];

    SSL_DEBUG_MSG( 3, ( "client hello, session id len.: %d", n ) );
    SSL_DEBUG_BUF( 3,   "client hello, session id", buf + 39, n );

    for( n = 0; ssl->ciphersuites[n] != 0; n++ );
    *p++ = (unsigned char)( n >> 7 );
    *p++ = (unsigned char)( n << 1 );

    SSL_DEBUG_MSG( 3, ( "client hello, got %d ciphersuites", n ) );

    for( i = 0; i < n; i++ )
    {
        SSL_DEBUG_MSG( 3, ( "client hello, add ciphersuite: %2d",
                       ssl->ciphersuites[i] ) );

        *p++ = (unsigned char)( ssl->ciphersuites[i] >> 8 );
        *p++ = (unsigned char)( ssl->ciphersuites[i]      );
    }

#if defined(POLARSSL_ZLIB_SUPPORT)
    SSL_DEBUG_MSG( 3, ( "client hello, compress len.: %d", 2 ) );
    SSL_DEBUG_MSG( 3, ( "client hello, compress alg.: %d %d",
                        SSL_COMPRESS_NULL, SSL_COMPRESS_DEFLATE ) );

    *p++ = 2;
    *p++ = SSL_COMPRESS_NULL;
    *p++ = SSL_COMPRESS_DEFLATE;
#else
    SSL_DEBUG_MSG( 3, ( "client hello, compress len.: %d", 1 ) );
    SSL_DEBUG_MSG( 3, ( "client hello, compress alg.: %d", SSL_COMPRESS_NULL ) );

    *p++ = 1;
    *p++ = SSL_COMPRESS_NULL;
#endif

    if ( ssl->hostname != NULL )
    {
        SSL_DEBUG_MSG( 3, ( "client hello, prepping for server name extension: %s",
                       ssl->hostname ) );

        ext_len += ssl->hostname_len + 9;
    }

    /*
     * Prepare signature_algorithms extension (TLS 1.2)
     */
    if( ssl->max_minor_ver == SSL_MINOR_VERSION_3 )
    {
#if defined(POLARSSL_SHA4_C)
        sig_alg_list[sig_alg_len++] = SSL_HASH_SHA512;
        sig_alg_list[sig_alg_len++] = SSL_SIG_RSA;
        sig_alg_list[sig_alg_len++] = SSL_HASH_SHA384;
        sig_alg_list[sig_alg_len++] = SSL_SIG_RSA;
#endif
#if defined(POLARSSL_SHA2_C)
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
        ext_len = 6 + sig_alg_len;
    }

    SSL_DEBUG_MSG( 3, ( "client hello, total extension length: %d",
                   ext_len ) );

    *p++ = (unsigned char)( ( ext_len >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( ext_len      ) & 0xFF );

    if ( ssl->hostname != NULL )
    {
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
        SSL_DEBUG_MSG( 3, ( "client hello, adding server name extension: %s",
                       ssl->hostname ) );

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

        p += ssl->hostname_len;
    }

    if( ssl->max_minor_ver == SSL_MINOR_VERSION_3 )
    {
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
        SSL_DEBUG_MSG( 3, ( "client hello, adding signature_algorithms extension" ) );

        *p++ = (unsigned char)( ( TLS_EXT_SIG_ALG >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( TLS_EXT_SIG_ALG      ) & 0xFF );

        *p++ = (unsigned char)( ( ( sig_alg_len + 2 ) >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( ( sig_alg_len + 2 )      ) & 0xFF );

        *p++ = (unsigned char)( ( sig_alg_len >> 8 ) & 0xFF );
        *p++ = (unsigned char)( ( sig_alg_len      ) & 0xFF );

        memcpy( p, sig_alg_list, sig_alg_len );

        p += sig_alg_len;
    }

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

static int ssl_parse_server_hello( ssl_context *ssl )
{
#if defined(POLARSSL_DEBUG_C)
    time_t t;
#endif
    int ret, i, comp;
    size_t n;
    int ext_len;
    unsigned char *buf;

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

#if defined(POLARSSL_DEBUG_C)
    t = ( (time_t) buf[6] << 24 )
      | ( (time_t) buf[7] << 16 )
      | ( (time_t) buf[8] <<  8 )
      | ( (time_t) buf[9]       );
#endif

    memcpy( ssl->randbytes + 32, buf + 6, 32 );

    n = buf[38];

    SSL_DEBUG_MSG( 3, ( "server hello, current time: %lu", t ) );
    SSL_DEBUG_BUF( 3,   "server hello, random bytes", buf + 6, 32 );

    /*
     *    38  .  38   session id length
     *    39  . 38+n  session id
     *   39+n . 40+n  chosen ciphersuite
     *   41+n . 41+n  chosen compression alg.
     *   42+n . 43+n  extensions length
     *   44+n . 44+n+m extensions
     */
    if( n > 32 || ssl->in_hslen > 42 + n )
    {
        ext_len = ( ( buf[42 + n] <<  8 )
                  | ( buf[43 + n]       ) ) + 2;
    }
    else
    {
        ext_len = 0;
    }

    if( n > 32 || ssl->in_hslen != 42 + n + ext_len )
    {
        SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
    }

    i = ( buf[39 + n] << 8 ) | buf[40 + n];
    comp = buf[41 + n];

    /*
     * Initialize update checksum functions
     */
    ssl_kickstart_checksum( ssl, i, buf, ssl->in_hslen );

    SSL_DEBUG_MSG( 3, ( "server hello, session id len.: %d", n ) );
    SSL_DEBUG_BUF( 3,   "server hello, session id", buf + 39, n );

    /*
     * Check if the session can be resumed
     */
    if( ssl->resume == 0 || n == 0 ||
        ssl->session->ciphersuite != i ||
        ssl->session->compression != comp ||
        ssl->session->length != n ||
        memcmp( ssl->session->id, buf + 39, n ) != 0 )
    {
        ssl->state++;
        ssl->resume = 0;
        ssl->session->start = time( NULL );
        ssl->session->ciphersuite = i;
        ssl->session->compression = comp;
        ssl->session->length = n;
        memcpy( ssl->session->id, buf + 39, n );
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
                   ssl->resume ? "a" : "no" ) );

    SSL_DEBUG_MSG( 3, ( "server hello, chosen ciphersuite: %d", i ) );
    SSL_DEBUG_MSG( 3, ( "server hello, compress alg.: %d", buf[41 + n] ) );

    i = 0;
    while( 1 )
    {
        if( ssl->ciphersuites[i] == 0 )
        {
            SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO );
        }

        if( ssl->ciphersuites[i++] == ssl->session->ciphersuite )
            break;
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
    ssl->session->compression = comp;

    /* TODO: Process extensions */

    SSL_DEBUG_MSG( 2, ( "<= parse server hello" ) );

    return( 0 );
}

static int ssl_parse_server_key_exchange( ssl_context *ssl )
{
#if defined(POLARSSL_DHM_C)
    int ret;
    size_t n;
    unsigned char *p, *end;
    unsigned char hash[64];
    md5_context md5;
    sha1_context sha1;
    int hash_id = SIG_RSA_RAW;
    unsigned int hashlen = 0;
#endif

    SSL_DEBUG_MSG( 2, ( "=> parse server key exchange" ) );

    if( ssl->session->ciphersuite != SSL_EDH_RSA_DES_SHA &&
        ssl->session->ciphersuite != SSL_EDH_RSA_DES_168_SHA &&
        ssl->session->ciphersuite != SSL_EDH_RSA_AES_128_SHA &&
        ssl->session->ciphersuite != SSL_EDH_RSA_AES_256_SHA &&
        ssl->session->ciphersuite != SSL_EDH_RSA_AES_128_SHA256 &&
        ssl->session->ciphersuite != SSL_EDH_RSA_AES_256_SHA256 &&
        ssl->session->ciphersuite != SSL_EDH_RSA_CAMELLIA_128_SHA &&
        ssl->session->ciphersuite != SSL_EDH_RSA_CAMELLIA_256_SHA &&
        ssl->session->ciphersuite != SSL_EDH_RSA_CAMELLIA_128_SHA256 &&
        ssl->session->ciphersuite != SSL_EDH_RSA_CAMELLIA_256_SHA256 &&
        ssl->session->ciphersuite != SSL_EDH_RSA_AES_128_GCM_SHA256 &&
        ssl->session->ciphersuite != SSL_EDH_RSA_AES_256_GCM_SHA384 )
    {
        SSL_DEBUG_MSG( 2, ( "<= skip parse server key exchange" ) );
        ssl->state++;
        return( 0 );
    }

#if !defined(POLARSSL_DHM_C)
    SSL_DEBUG_MSG( 1, ( "support for dhm in not available" ) );
    return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
#else
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
        SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
    }

    SSL_DEBUG_BUF( 3,   "server key exchange", ssl->in_msg + 4, ssl->in_hslen - 4 );

    /*
     * Ephemeral DH parameters:
     *
     * struct {
     *     opaque dh_p<1..2^16-1>;
     *     opaque dh_g<1..2^16-1>;
     *     opaque dh_Ys<1..2^16-1>;
     * } ServerDHParams;
     */
    p   = ssl->in_msg + 4;
    end = ssl->in_msg + ssl->in_hslen;

    if( ( ret = dhm_read_params( &ssl->dhm_ctx, &p, end ) ) != 0 )
    {
        SSL_DEBUG_MSG( 2, ( "DHM Read Params returned -0x%x", -ret ) );
        SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE ); 
    }

    if( ssl->minor_ver == SSL_MINOR_VERSION_3 )
    {
        if( p[1] != SSL_SIG_RSA )
        {
            SSL_DEBUG_MSG( 2, ( "Server used unsupported SignatureAlgorithm %d", p[1] ) );
            SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE ); 
        }

        switch( p[0] )
        {
#if defined(POLARSSL_MD5_C)
            case SSL_HASH_MD5:
                hash_id = SIG_RSA_MD5;
                break;
#endif
#if defined(POLARSSL_SHA1_C)
            case SSL_HASH_SHA1:
                hash_id = SIG_RSA_SHA1;
                break;
#endif
#if defined(POLARSSL_SHA2_C)
            case SSL_HASH_SHA224:
                hash_id = SIG_RSA_SHA224;
                break;
            case SSL_HASH_SHA256:
                hash_id = SIG_RSA_SHA256;
                break;
#endif
#if defined(POLARSSL_SHA4_C)
            case SSL_HASH_SHA384:
                hash_id = SIG_RSA_SHA384;
                break;
            case SSL_HASH_SHA512:
                hash_id = SIG_RSA_SHA512;
                break;
#endif
            default:
                SSL_DEBUG_MSG( 2, ( "Server used unsupported HashAlgorithm %d", p[0] ) );
                SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
                return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE ); 
        }      

        SSL_DEBUG_MSG( 2, ( "Server used SignatureAlgorithm %d", p[1] ) );
        SSL_DEBUG_MSG( 2, ( "Server used HashAlgorithm %d", p[0] ) );
        p += 2;
    }

    n = ( p[0] << 8 ) | p[1];
    p += 2;

    if( end != p + n )
    {
        SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
    }

    if( (unsigned int)( end - p ) != ssl->peer_cert->rsa.len )
    {
        SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
    }

    if( ssl->dhm_ctx.len < 64 || ssl->dhm_ctx.len > 512 )
    {
        SSL_DEBUG_MSG( 1, ( "bad server key exchange message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE );
    }

    SSL_DEBUG_MPI( 3, "DHM: P ", &ssl->dhm_ctx.P  );
    SSL_DEBUG_MPI( 3, "DHM: G ", &ssl->dhm_ctx.G  );
    SSL_DEBUG_MPI( 3, "DHM: GY", &ssl->dhm_ctx.GY );

    if( ssl->minor_ver != SSL_MINOR_VERSION_3 )
    {
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
        md5_update( &md5, ssl->randbytes, 64 );
        md5_update( &md5, ssl->in_msg + 4, n );
        md5_finish( &md5, hash );

        sha1_starts( &sha1 );
        sha1_update( &sha1, ssl->randbytes, 64 );
        sha1_update( &sha1, ssl->in_msg + 4, n );
        sha1_finish( &sha1, hash + 16 );

        hash_id = SIG_RSA_RAW;
        hashlen = 36;
    }
    else
    {
        sha2_context sha2;
        sha4_context sha4;

        n = ssl->in_hslen - ( end - p ) - 8;

        /*
         * digitally-signed struct {
         *     opaque client_random[32];
         *     opaque server_random[32];
         *     ServerDHParams params;
         * };
         */
        switch( hash_id )
        {
#if defined(POLARSSL_MD5_C)
            case SIG_RSA_MD5:
                md5_starts( &md5 );
                md5_update( &md5, ssl->randbytes, 64 );
                md5_update( &md5, ssl->in_msg + 4, n );
                md5_finish( &md5, hash );
                hashlen = 16;
                break;
#endif
#if defined(POLARSSL_SHA1_C)
            case SIG_RSA_SHA1:
                sha1_starts( &sha1 );
                sha1_update( &sha1, ssl->randbytes, 64 );
                sha1_update( &sha1, ssl->in_msg + 4, n );
                sha1_finish( &sha1, hash );
                hashlen = 20;
                break;
#endif
#if defined(POLARSSL_SHA2_C)
            case SIG_RSA_SHA224:
                sha2_starts( &sha2, 1 );
                sha2_update( &sha2, ssl->randbytes, 64 );
                sha2_update( &sha2, ssl->in_msg + 4, n );
                sha2_finish( &sha2, hash );
                hashlen = 28;
                break;
            case SIG_RSA_SHA256:
                sha2_starts( &sha2, 0 );
                sha2_update( &sha2, ssl->randbytes, 64 );
                sha2_update( &sha2, ssl->in_msg + 4, n );
                sha2_finish( &sha2, hash );
                hashlen = 32;
                break;
#endif
#if defined(POLARSSL_SHA4_C)
            case SIG_RSA_SHA384:
                sha4_starts( &sha4, 1 );
                sha4_update( &sha4, ssl->randbytes, 64 );
                sha4_update( &sha4, ssl->in_msg + 4, n );
                sha4_finish( &sha4, hash );
                hashlen = 48;
                break;
            case SIG_RSA_SHA512:
                sha4_starts( &sha4, 0 );
                sha4_update( &sha4, ssl->randbytes, 64 );
                sha4_update( &sha4, ssl->in_msg + 4, n );
                sha4_finish( &sha4, hash );
                hashlen = 64;
                break;
#endif
        }
    }
    
    SSL_DEBUG_BUF( 3, "parameters hash", hash, hashlen );

    if( ( ret = rsa_pkcs1_verify( &ssl->peer_cert->rsa, RSA_PUBLIC,
                                  hash_id, hashlen, hash, p ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "rsa_pkcs1_verify", ret );
        return( ret );
    }

    ssl->state++;

    SSL_DEBUG_MSG( 2, ( "<= parse server key exchange" ) );

    return( 0 );
#endif
}

static int ssl_parse_certificate_request( ssl_context *ssl )
{
    int ret;

    SSL_DEBUG_MSG( 2, ( "=> parse certificate request" ) );

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   SSL version
     *     6  .   6   cert type count
     *     7  .. n-1  cert types
     *     n  .. n+1  length of all DNs
     *    n+2 .. n+3  length of DN 1
     *    n+4 .. ...  Distinguished Name #1
     *    ... .. ...  length of DN 2, etc.
     */
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

    ssl->client_auth = 0;
    ssl->state++;

    if( ssl->in_msg[0] == SSL_HS_CERTIFICATE_REQUEST )
        ssl->client_auth++;

    SSL_DEBUG_MSG( 3, ( "got %s certificate request",
                        ssl->client_auth ? "a" : "no" ) );

    SSL_DEBUG_MSG( 2, ( "<= parse certificate request" ) );

    return( 0 );
}

static int ssl_parse_server_hello_done( ssl_context *ssl )
{
    int ret;

    SSL_DEBUG_MSG( 2, ( "=> parse server hello done" ) );

    if( ssl->client_auth != 0 )
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

    SSL_DEBUG_MSG( 2, ( "=> write client key exchange" ) );

    if( ssl->session->ciphersuite == SSL_EDH_RSA_DES_SHA ||
        ssl->session->ciphersuite == SSL_EDH_RSA_DES_168_SHA ||
        ssl->session->ciphersuite == SSL_EDH_RSA_AES_128_SHA ||
        ssl->session->ciphersuite == SSL_EDH_RSA_AES_256_SHA ||
        ssl->session->ciphersuite == SSL_EDH_RSA_AES_128_SHA256 ||
        ssl->session->ciphersuite == SSL_EDH_RSA_AES_256_SHA256 ||
        ssl->session->ciphersuite == SSL_EDH_RSA_CAMELLIA_128_SHA ||
        ssl->session->ciphersuite == SSL_EDH_RSA_CAMELLIA_256_SHA ||
        ssl->session->ciphersuite == SSL_EDH_RSA_CAMELLIA_128_SHA256 ||
        ssl->session->ciphersuite == SSL_EDH_RSA_CAMELLIA_256_SHA256 ||
        ssl->session->ciphersuite == SSL_EDH_RSA_AES_128_GCM_SHA256 ||
        ssl->session->ciphersuite == SSL_EDH_RSA_AES_256_GCM_SHA384 )
    {
#if !defined(POLARSSL_DHM_C)
        SSL_DEBUG_MSG( 1, ( "support for dhm in not available" ) );
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
#else
        /*
         * DHM key exchange -- send G^X mod P
         */
        n = ssl->dhm_ctx.len;

        ssl->out_msg[4] = (unsigned char)( n >> 8 );
        ssl->out_msg[5] = (unsigned char)( n      );
        i = 6;

        ret = dhm_make_public( &ssl->dhm_ctx, 256,
                               &ssl->out_msg[i], n,
                                ssl->f_rng, ssl->p_rng );
        if( ret != 0 )
        {
            SSL_DEBUG_RET( 1, "dhm_make_public", ret );
            return( ret );
        }

        SSL_DEBUG_MPI( 3, "DHM: X ", &ssl->dhm_ctx.X  );
        SSL_DEBUG_MPI( 3, "DHM: GX", &ssl->dhm_ctx.GX );

        ssl->pmslen = ssl->dhm_ctx.len;

        if( ( ret = dhm_calc_secret( &ssl->dhm_ctx,
                                      ssl->premaster,
                                     &ssl->pmslen ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "dhm_calc_secret", ret );
            return( ret );
        }

        SSL_DEBUG_MPI( 3, "DHM: K ", &ssl->dhm_ctx.K  );
#endif
    }
    else
    {
        /*
         * RSA key exchange -- send rsa_public(pkcs1 v1.5(premaster))
         */
        ssl->premaster[0] = (unsigned char) ssl->max_major_ver;
        ssl->premaster[1] = (unsigned char) ssl->max_minor_ver;
        ssl->pmslen = 48;

        ret = ssl->f_rng( ssl->p_rng, ssl->premaster + 2, ssl->pmslen - 2 );
        if( ret != 0 )
            return( ret );

        i = 4;
        n = ssl->peer_cert->rsa.len;

        if( ssl->minor_ver != SSL_MINOR_VERSION_0 )
        {
            i += 2;
            ssl->out_msg[4] = (unsigned char)( n >> 8 );
            ssl->out_msg[5] = (unsigned char)( n      );
        }

        ret = rsa_pkcs1_encrypt( &ssl->peer_cert->rsa,
                                  ssl->f_rng, ssl->p_rng,
                                  RSA_PUBLIC,
                                  ssl->pmslen, ssl->premaster,
                                  ssl->out_msg + i );
        if( ret != 0 )
        {
            SSL_DEBUG_RET( 1, "rsa_pkcs1_encrypt", ret );
            return( ret );
        }
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

static int ssl_write_certificate_verify( ssl_context *ssl )
{
    int ret = 0;
    size_t n = 0, offset = 0;
    unsigned char hash[48];
    int hash_id = SIG_RSA_RAW;
    unsigned int hashlen = 36;

    SSL_DEBUG_MSG( 2, ( "=> write certificate verify" ) );

    if( ssl->client_auth == 0 || ssl->own_cert == NULL )
    {
        SSL_DEBUG_MSG( 2, ( "<= skip write certificate verify" ) );
        ssl->state++;
        return( 0 );
    }

    if( ssl->minor_ver == SSL_MINOR_VERSION_3 )
    {
        // TODO TLS1.2 Should be based on allowed signature algorithm received in
        // Certificate Request according to RFC 5246. But OpenSSL only allows
        // SHA256 and SHA384. Find out why OpenSSL does this.
        //
        if( ssl->session->ciphersuite == SSL_RSA_AES_256_GCM_SHA384 ||
            ssl->session->ciphersuite == SSL_EDH_RSA_AES_256_GCM_SHA384 )
        {
            hash_id = SIG_RSA_SHA384;
            hashlen = 48;
        }
        else
        {
            hash_id = SIG_RSA_SHA256;
            hashlen = 32;
        }
    }

    if( ssl->rsa_key == NULL )
    {
#if defined(POLARSSL_PKCS11_C)
        if( ssl->pkcs11_key == NULL )
        {
#endif /* defined(POLARSSL_PKCS11_C) */
            SSL_DEBUG_MSG( 1, ( "got no private key" ) );
            return( POLARSSL_ERR_SSL_PRIVATE_KEY_REQUIRED );
#if defined(POLARSSL_PKCS11_C)
        }
#endif /* defined(POLARSSL_PKCS11_C) */
    }

    /*
     * Make an RSA signature of the handshake digests
     */
    ssl->calc_verify( ssl, hash );

    if ( ssl->rsa_key )
        n = ssl->rsa_key->len;
#if defined(POLARSSL_PKCS11_C)
    else
        n = ssl->pkcs11_key->len;
#endif  /* defined(POLARSSL_PKCS11_C) */

    if( ssl->minor_ver == SSL_MINOR_VERSION_3 )
    {
        // TODO TLS1.2 Should be based on allowed signature algorithm received in
        // Certificate Request according to RFC 5246. But OpenSSL only allows
        // SHA256 and SHA384. Find out why OpenSSL does this.
        //
        if( ssl->session->ciphersuite == SSL_RSA_AES_256_GCM_SHA384 ||
            ssl->session->ciphersuite == SSL_EDH_RSA_AES_256_GCM_SHA384 )
        {
            ssl->out_msg[4] = SSL_HASH_SHA384;
            ssl->out_msg[5] = SSL_SIG_RSA;
        }
        else
        {
            ssl->out_msg[4] = SSL_HASH_SHA256;
            ssl->out_msg[5] = SSL_SIG_RSA;
        }

        offset = 2;
    }

    ssl->out_msg[4 + offset] = (unsigned char)( n >> 8 );
    ssl->out_msg[5 + offset] = (unsigned char)( n      );

    if( ssl->rsa_key )
    {
        ret = rsa_pkcs1_sign( ssl->rsa_key, ssl->f_rng, ssl->p_rng,
                                   RSA_PRIVATE, hash_id,
                                   hashlen, hash, ssl->out_msg + 6 + offset );
    } else {
#if defined(POLARSSL_PKCS11_C)
        ret = pkcs11_sign( ssl->pkcs11_key, RSA_PRIVATE, hash_id,
                                    hashlen, hash, ssl->out_msg + 6 + offset );
#endif  /* defined(POLARSSL_PKCS11_C) */
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

    return( 0 );
}

/*
 * SSL handshake -- client side
 */
int ssl_handshake_client( ssl_context *ssl )
{
    int ret = 0;

    SSL_DEBUG_MSG( 2, ( "=> handshake client" ) );

    while( ssl->state != SSL_HANDSHAKE_OVER )
    {
        SSL_DEBUG_MSG( 2, ( "client state: %d", ssl->state ) );

        if( ( ret = ssl_flush_output( ssl ) ) != 0 )
            break;

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
                ssl->state = SSL_HANDSHAKE_OVER;
                break;

            default:
                SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
                return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );
        }

        if( ret != 0 )
            break;
    }

    SSL_DEBUG_MSG( 2, ( "<= handshake client" ) );

    return( ret );
}

#endif
