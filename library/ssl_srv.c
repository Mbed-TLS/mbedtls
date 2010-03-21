/*
 *  SSLv3/TLSv1 server-side functions
 *
 *  Copyright (C) 2006-2010, Paul Bakker <polarssl_maintainer at polarssl.org>
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

#if defined(POLARSSL_SSL_SRV_C)

#include "polarssl/debug.h"
#include "polarssl/ssl.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static int ssl_parse_client_hello( ssl_context *ssl )
{
    int ret, i, j, n;
    int ciph_len, sess_len;
    int chal_len, comp_len;
    unsigned char *buf, *p;

    SSL_DEBUG_MSG( 2, ( "=> parse client hello" ) );

    if( ( ret = ssl_fetch_input( ssl, 5 ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_fetch_input", ret );
        return( ret );
    }

    buf = ssl->in_hdr;

    if( ( buf[0] & 0x80 ) != 0 )
    {
        SSL_DEBUG_BUF( 4, "record header", buf, 5 );

        SSL_DEBUG_MSG( 3, ( "client hello v2, message type: %d",
                       buf[2] ) );
        SSL_DEBUG_MSG( 3, ( "client hello v2, message len.: %d",
                       ( ( buf[0] & 0x7F ) << 8 ) | buf[1] ) );
        SSL_DEBUG_MSG( 3, ( "client hello v2, max. version: [%d:%d]",
                       buf[3], buf[4] ) );

        /*
         * SSLv2 Client Hello
         *
         * Record layer:
         *     0  .   1   message length
         *
         * SSL layer:
         *     2  .   2   message type
         *     3  .   4   protocol version
         */
        if( buf[2] != SSL_HS_CLIENT_HELLO ||
            buf[3] != SSL_MAJOR_VERSION_3 )
        {
            SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        n = ( ( buf[0] << 8 ) | buf[1] ) & 0x7FFF;

        if( n < 17 || n > 512 )
        {
            SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        ssl->max_major_ver = buf[3];
        ssl->max_minor_ver = buf[4];

        ssl->major_ver = SSL_MAJOR_VERSION_3;
        ssl->minor_ver = ( buf[4] <= SSL_MINOR_VERSION_1 )
                         ? buf[4]  : SSL_MINOR_VERSION_1;

        if( ( ret = ssl_fetch_input( ssl, 2 + n ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ssl_fetch_input", ret );
            return( ret );
        }

         md5_update( &ssl->fin_md5 , buf + 2, n );
        sha1_update( &ssl->fin_sha1, buf + 2, n );

        buf = ssl->in_msg;
        n = ssl->in_left - 5;

        /*
         *    0  .   1   cipherlist length
         *    2  .   3   session id length
         *    4  .   5   challenge length
         *    6  .  ..   cipherlist
         *   ..  .  ..   session id
         *   ..  .  ..   challenge
         */
        SSL_DEBUG_BUF( 4, "record contents", buf, n );

        ciph_len = ( buf[0] << 8 ) | buf[1];
        sess_len = ( buf[2] << 8 ) | buf[3];
        chal_len = ( buf[4] << 8 ) | buf[5];

        SSL_DEBUG_MSG( 3, ( "ciph_len: %d, sess_len: %d, chal_len: %d",
                       ciph_len, sess_len, chal_len ) );

        /*
         * Make sure each parameter length is valid
         */
        if( ciph_len < 3 || ( ciph_len % 3 ) != 0 )
        {
            SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        if( sess_len < 0 || sess_len > 32 )
        {
            SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        if( chal_len < 8 || chal_len > 32 )
        {
            SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        if( n != 6 + ciph_len + sess_len + chal_len )
        {
            SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        SSL_DEBUG_BUF( 3, "client hello, cipherlist",
                       buf + 6,  ciph_len );
        SSL_DEBUG_BUF( 3, "client hello, session id",
                       buf + 6 + ciph_len,  sess_len );
        SSL_DEBUG_BUF( 3, "client hello, challenge",
                       buf + 6 + ciph_len + sess_len,  chal_len );

        p = buf + 6 + ciph_len;
        ssl->session->length = sess_len;
        memset( ssl->session->id, 0, sizeof( ssl->session->id ) );
        memcpy( ssl->session->id, p, ssl->session->length );

        p += sess_len;
        memset( ssl->randbytes, 0, 64 );
        memcpy( ssl->randbytes + 32 - chal_len, p, chal_len );

        for( i = 0; ssl->ciphers[i] != 0; i++ )
        {
            for( j = 0, p = buf + 6; j < ciph_len; j += 3, p += 3 )
            {
                if( p[0] == 0 &&
                    p[1] == 0 &&
                    p[2] == ssl->ciphers[i] )
                    goto have_cipher;
            }
        }
    }
    else
    {
        SSL_DEBUG_BUF( 4, "record header", buf, 5 );

        SSL_DEBUG_MSG( 3, ( "client hello v3, message type: %d",
                       buf[0] ) );
        SSL_DEBUG_MSG( 3, ( "client hello v3, message len.: %d",
                       ( buf[3] << 8 ) | buf[4] ) );
        SSL_DEBUG_MSG( 3, ( "client hello v3, protocol ver: [%d:%d]",
                       buf[1], buf[2] ) );

        /*
         * SSLv3 Client Hello
         *
         * Record layer:
         *     0  .   0   message type
         *     1  .   2   protocol version
         *     3  .   4   message length
         */
        if( buf[0] != SSL_MSG_HANDSHAKE ||
            buf[1] != SSL_MAJOR_VERSION_3 )
        {
            SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        n = ( buf[3] << 8 ) | buf[4];

        if( n < 45 || n > 512 )
        {
            SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        if( ( ret = ssl_fetch_input( ssl, 5 + n ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ssl_fetch_input", ret );
            return( ret );
        }

        buf = ssl->in_msg;
        n = ssl->in_left - 5;

         md5_update( &ssl->fin_md5 , buf, n );
        sha1_update( &ssl->fin_sha1, buf, n );

        /*
         * SSL layer:
         *     0  .   0   handshake type
         *     1  .   3   handshake length
         *     4  .   5   protocol version
         *     6  .   9   UNIX time()
         *    10  .  37   random bytes
         *    38  .  38   session id length
         *    39  . 38+x  session id
         *   39+x . 40+x  cipherlist length
         *   41+x .  ..   cipherlist
         *    ..  .  ..   compression alg.
         *    ..  .  ..   extensions
         */
        SSL_DEBUG_BUF( 4, "record contents", buf, n );

        SSL_DEBUG_MSG( 3, ( "client hello v3, handshake type: %d",
                       buf[0] ) );
        SSL_DEBUG_MSG( 3, ( "client hello v3, handshake len.: %d",
                       ( buf[1] << 16 ) | ( buf[2] << 8 ) | buf[3] ) );
        SSL_DEBUG_MSG( 3, ( "client hello v3, max. version: [%d:%d]",
                       buf[4], buf[5] ) );

        /*
         * Check the handshake type and protocol version
         */
        if( buf[0] != SSL_HS_CLIENT_HELLO ||
            buf[4] != SSL_MAJOR_VERSION_3 )
        {
            SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        ssl->major_ver = SSL_MAJOR_VERSION_3;
        ssl->minor_ver = ( buf[5] <= SSL_MINOR_VERSION_1 )
                         ? buf[5]  : SSL_MINOR_VERSION_1;

        ssl->max_major_ver = buf[4];
        ssl->max_minor_ver = buf[5];

        memcpy( ssl->randbytes, buf + 6, 32 );

        /*
         * Check the handshake message length
         */
        if( buf[1] != 0 || n != 4 + ( ( buf[2] << 8 ) | buf[3] ) )
        {
            SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        /*
         * Check the session length
         */
        sess_len = buf[38];

        if( sess_len < 0 || sess_len > 32 )
        {
            SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        ssl->session->length = sess_len;
        memset( ssl->session->id, 0, sizeof( ssl->session->id ) );
        memcpy( ssl->session->id, buf + 39 , ssl->session->length );

        /*
         * Check the cipherlist length
         */
        ciph_len = ( buf[39 + sess_len] << 8 )
                 | ( buf[40 + sess_len]      );

        if( ciph_len < 2 || ciph_len > 256 || ( ciph_len % 2 ) != 0 )
        {
            SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        /*
         * Check the compression algorithms length
         */
        comp_len = buf[41 + sess_len + ciph_len];

        if( comp_len < 1 || comp_len > 16 )
        {
            SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO );
        }

        SSL_DEBUG_BUF( 3, "client hello, random bytes",
                       buf +  6,  32 );
        SSL_DEBUG_BUF( 3, "client hello, session id",
                       buf + 38,  sess_len );
        SSL_DEBUG_BUF( 3, "client hello, cipherlist",
                       buf + 41 + sess_len,  ciph_len );
        SSL_DEBUG_BUF( 3, "client hello, compression",
                       buf + 42 + sess_len + ciph_len, comp_len );

        /*
         * Search for a matching cipher
         */
        for( i = 0; ssl->ciphers[i] != 0; i++ )
        {
            for( j = 0, p = buf + 41 + sess_len; j < ciph_len;
                j += 2, p += 2 )
            {
                if( p[0] == 0 && p[1] == ssl->ciphers[i] )
                    goto have_cipher;
            }
        }
    }

    SSL_DEBUG_MSG( 1, ( "got no ciphers in common" ) );

    return( POLARSSL_ERR_SSL_NO_CIPHER_CHOSEN );

have_cipher:

    ssl->session->cipher = ssl->ciphers[i];
    ssl->in_left = 0;
    ssl->state++;

    SSL_DEBUG_MSG( 2, ( "<= parse client hello" ) );

    return( 0 );
}

static int ssl_write_server_hello( ssl_context *ssl )
{
    time_t t;
    int ret, i, n;
    unsigned char *buf, *p;

    SSL_DEBUG_MSG( 2, ( "=> write server hello" ) );

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   5   protocol version
     *     6  .   9   UNIX time()
     *    10  .  37   random bytes
     */
    buf = ssl->out_msg;
    p = buf + 4;

    *p++ = (unsigned char) ssl->major_ver;
    *p++ = (unsigned char) ssl->minor_ver;

    SSL_DEBUG_MSG( 3, ( "server hello, chosen version: [%d:%d]",
                   buf[4], buf[5] ) );

    t = time( NULL );
    *p++ = (unsigned char)( t >> 24 );
    *p++ = (unsigned char)( t >> 16 );
    *p++ = (unsigned char)( t >>  8 );
    *p++ = (unsigned char)( t       );

    SSL_DEBUG_MSG( 3, ( "server hello, current time: %lu", t ) );

    for( i = 28; i > 0; i-- )
        *p++ = (unsigned char) ssl->f_rng( ssl->p_rng );

    memcpy( ssl->randbytes + 32, buf + 6, 32 );

    SSL_DEBUG_BUF( 3, "server hello, random bytes", buf + 6, 32 );

    /*
     *    38  .  38   session id length
     *    39  . 38+n  session id
     *   39+n . 40+n  chosen cipher
     *   41+n . 41+n  chosen compression alg.
     */
    ssl->session->length = n = 32;
    *p++ = (unsigned char) ssl->session->length;

    if( ssl->s_get == NULL ||
        ssl->s_get( ssl ) != 0 )
    {
        /*
         * Not found, create a new session id
         */
        ssl->resume = 0;
        ssl->state++;

        for( i = 0; i < n; i++ )
            ssl->session->id[i] =
                (unsigned char) ssl->f_rng( ssl->p_rng );
    }
    else
    {
        /*
         * Found a matching session, resume it
         */
        ssl->resume = 1;
        ssl->state = SSL_SERVER_CHANGE_CIPHER_SPEC;

        if( ( ret = ssl_derive_keys( ssl ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ssl_derive_keys", ret );
            return( ret );
        }
    }

    memcpy( p, ssl->session->id, ssl->session->length );
    p += ssl->session->length;

    SSL_DEBUG_MSG( 3, ( "server hello, session id len.: %d", n ) );
    SSL_DEBUG_BUF( 3,   "server hello, session id", buf + 39, n );
    SSL_DEBUG_MSG( 3, ( "%s session has been resumed",
                   ssl->resume ? "a" : "no" ) );

    *p++ = (unsigned char)( ssl->session->cipher >> 8 );
    *p++ = (unsigned char)( ssl->session->cipher      );
    *p++ = SSL_COMPRESS_NULL;

    SSL_DEBUG_MSG( 3, ( "server hello, chosen cipher: %d",
                   ssl->session->cipher ) );
    SSL_DEBUG_MSG( 3, ( "server hello, compress alg.: %d", 0 ) );

    ssl->out_msglen  = p - buf;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_SERVER_HELLO;

    ret = ssl_write_record( ssl );

    SSL_DEBUG_MSG( 2, ( "<= write server hello" ) );

    return( ret );
}

static int ssl_write_certificate_request( ssl_context *ssl )
{
    int ret, n;
    unsigned char *buf, *p;
    const x509_cert *crt;

    SSL_DEBUG_MSG( 2, ( "=> write certificate request" ) );

    ssl->state++;

    if( ssl->authmode == SSL_VERIFY_NONE )
    {
        SSL_DEBUG_MSG( 2, ( "<= skip write certificate request" ) );
        return( 0 );
    }

    /*
     *     0  .   0   handshake type
     *     1  .   3   handshake length
     *     4  .   4   cert type count
     *     5  .. n-1  cert types
     *     n  .. n+1  length of all DNs
     *    n+2 .. n+3  length of DN 1
     *    n+4 .. ...  Distinguished Name #1
     *    ... .. ...  length of DN 2, etc.
     */
    buf = ssl->out_msg;
    p = buf + 4;

    /*
     * At the moment, only RSA certificates are supported
     */
    *p++ = 1;
    *p++ = 1;

    p += 2;
    crt = ssl->ca_chain;

    while( crt != NULL )
    {
        if( p - buf > 4096 )
            break;

        n = crt->subject_raw.len;
        *p++ = (unsigned char)( n >> 8 );
        *p++ = (unsigned char)( n      );
        memcpy( p, crt->subject_raw.p, n );

        SSL_DEBUG_BUF( 3, "requested DN", p, n );
        p += n; crt = crt->next;
    }

    ssl->out_msglen  = n = p - buf;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CERTIFICATE_REQUEST;
    ssl->out_msg[6]  = (unsigned char)( ( n - 8 ) >> 8 );
    ssl->out_msg[7]  = (unsigned char)( ( n - 8 )      );

    ret = ssl_write_record( ssl );

    SSL_DEBUG_MSG( 2, ( "<= write certificate request" ) );

    return( ret );
}

static int ssl_write_server_key_exchange( ssl_context *ssl )
{
    int ret, n;
    unsigned char hash[36];
    md5_context md5;
    sha1_context sha1;

    SSL_DEBUG_MSG( 2, ( "=> write server key exchange" ) );

    if( ssl->session->cipher != SSL_EDH_RSA_DES_168_SHA &&
        ssl->session->cipher != SSL_EDH_RSA_AES_256_SHA &&
	ssl->session->cipher != SSL_EDH_RSA_CAMELLIA_256_SHA)
    {
        SSL_DEBUG_MSG( 2, ( "<= skip write server key exchange" ) );
        ssl->state++;
        return( 0 );
    }

#if !defined(POLARSSL_DHM_C)
    SSL_DEBUG_MSG( 1, ( "support for dhm is not available" ) );
    return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
#else
    /*
     * Ephemeral DH parameters:
     *
     * struct {
     *     opaque dh_p<1..2^16-1>;
     *     opaque dh_g<1..2^16-1>;
     *     opaque dh_Ys<1..2^16-1>;
     * } ServerDHParams;
     */
    if( ( ret = dhm_make_params( &ssl->dhm_ctx, 256, ssl->out_msg + 4,
                                 &n, ssl->f_rng, ssl->p_rng ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "dhm_make_params", ret );
        return( ret );
    }

    SSL_DEBUG_MPI( 3, "DHM: X ", &ssl->dhm_ctx.X  );
    SSL_DEBUG_MPI( 3, "DHM: P ", &ssl->dhm_ctx.P  );
    SSL_DEBUG_MPI( 3, "DHM: G ", &ssl->dhm_ctx.G  );
    SSL_DEBUG_MPI( 3, "DHM: GX", &ssl->dhm_ctx.GX );

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
    md5_starts( &md5 );
    md5_update( &md5, ssl->randbytes,  64 );
    md5_update( &md5, ssl->out_msg + 4, n );
    md5_finish( &md5, hash );

    sha1_starts( &sha1 );
    sha1_update( &sha1, ssl->randbytes,  64 );
    sha1_update( &sha1, ssl->out_msg + 4, n );
    sha1_finish( &sha1, hash + 16 );

    SSL_DEBUG_BUF( 3, "parameters hash", hash, 36 );

    ssl->out_msg[4 + n] = (unsigned char)( ssl->rsa_key->len >> 8 );
    ssl->out_msg[5 + n] = (unsigned char)( ssl->rsa_key->len      );

    ret = rsa_pkcs1_sign( ssl->rsa_key, RSA_PRIVATE,
                          SIG_RSA_RAW, 36, hash, ssl->out_msg + 6 + n );
    if( ret != 0 )
    {
        SSL_DEBUG_RET( 1, "rsa_pkcs1_sign", ret );
        return( ret );
    }

    SSL_DEBUG_BUF( 3, "my RSA sig", ssl->out_msg + 6 + n,
                                    ssl->rsa_key->len );

    ssl->out_msglen  = 6 + n + ssl->rsa_key->len;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_SERVER_KEY_EXCHANGE;

    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_write_record", ret );
        return( ret );
    }

    SSL_DEBUG_MSG( 2, ( "<= write server key exchange" ) );

    return( 0 );
#endif
}

static int ssl_write_server_hello_done( ssl_context *ssl )
{
    int ret;

    SSL_DEBUG_MSG( 2, ( "=> write server hello done" ) );

    ssl->out_msglen  = 4;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_SERVER_HELLO_DONE;

    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_write_record", ret );
        return( ret );
    }

    SSL_DEBUG_MSG( 2, ( "<= write server hello done" ) );

    return( 0 );
}

static int ssl_parse_client_key_exchange( ssl_context *ssl )
{
    int ret, i, n;

    SSL_DEBUG_MSG( 2, ( "=> parse client key exchange" ) );

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_read_record", ret );
        return( ret );
    }

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
    {
        SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
    }

    if( ssl->in_msg[0] != SSL_HS_CLIENT_KEY_EXCHANGE )
    {
        SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
    }

    if( ssl->session->cipher == SSL_EDH_RSA_DES_168_SHA ||
        ssl->session->cipher == SSL_EDH_RSA_AES_256_SHA ||
	ssl->session->cipher == SSL_EDH_RSA_CAMELLIA_256_SHA)
    {
#if !defined(POLARSSL_DHM_C)
        SSL_DEBUG_MSG( 1, ( "support for dhm is not available" ) );
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
#else
        /*
         * Receive G^Y mod P, premaster = (G^Y)^X mod P
         */
        n = ( ssl->in_msg[4] << 8 ) | ssl->in_msg[5];

        if( n < 1 || n > ssl->dhm_ctx.len ||
            n + 6 != ssl->in_hslen )
        {
            SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
        }

        if( ( ret = dhm_read_public( &ssl->dhm_ctx,
                                      ssl->in_msg + 6, n ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "dhm_read_public", ret );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE | ret );
        }

        SSL_DEBUG_MPI( 3, "DHM: GY", &ssl->dhm_ctx.GY );

        ssl->pmslen = ssl->dhm_ctx.len;

        if( ( ret = dhm_calc_secret( &ssl->dhm_ctx,
                     ssl->premaster, &ssl->pmslen ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "dhm_calc_secret", ret );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE | ret );
        }

        SSL_DEBUG_MPI( 3, "DHM: K ", &ssl->dhm_ctx.K  );
#endif
    }
    else
    {
        /*
         * Decrypt the premaster using own private RSA key
         */
        i = 4;
        n = ssl->rsa_key->len;
        ssl->pmslen = 48;

        if( ssl->minor_ver != SSL_MINOR_VERSION_0 )
        {
            i += 2;
            if( ssl->in_msg[4] != ( ( n >> 8 ) & 0xFF ) ||
                ssl->in_msg[5] != ( ( n      ) & 0xFF ) )
            {
                SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );
                return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
            }
        }

        if( ssl->in_hslen != i + n )
        {
            SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE );
        }

        ret = rsa_pkcs1_decrypt( ssl->rsa_key, RSA_PRIVATE, &ssl->pmslen,
                                 ssl->in_msg + i, ssl->premaster,
				 sizeof(ssl->premaster) );

        if( ret != 0 || ssl->pmslen != 48 ||
            ssl->premaster[0] != ssl->max_major_ver ||
            ssl->premaster[1] != ssl->max_minor_ver )
        {
            SSL_DEBUG_MSG( 1, ( "bad client key exchange message" ) );

            /*
             * Protection against Bleichenbacher's attack:
             * invalid PKCS#1 v1.5 padding must not cause
             * the connection to end immediately; instead,
             * send a bad_record_mac later in the handshake.
             */
            ssl->pmslen = 48;

            for( i = 0; i < ssl->pmslen; i++ )
                ssl->premaster[i] = (unsigned char) ssl->f_rng( ssl->p_rng );
        }
    }

    if( ( ret = ssl_derive_keys( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_derive_keys", ret );
        return( ret );
    }

    if( ssl->s_set != NULL )
        ssl->s_set( ssl );

    ssl->state++;

    SSL_DEBUG_MSG( 2, ( "<= parse client key exchange" ) );

    return( 0 );
}

static int ssl_parse_certificate_verify( ssl_context *ssl )
{
    int n1, n2, ret;
    unsigned char hash[36];

    SSL_DEBUG_MSG( 2, ( "=> parse certificate verify" ) );

    if( ssl->peer_cert == NULL )
    {
        SSL_DEBUG_MSG( 2, ( "<= skip parse certificate verify" ) );
        ssl->state++;
        return( 0 );
    }

    ssl_calc_verify( ssl, hash );

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_read_record", ret );
        return( ret );
    }

    ssl->state++;

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
    {
        SSL_DEBUG_MSG( 1, ( "bad certificate verify message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
    }

    if( ssl->in_msg[0] != SSL_HS_CERTIFICATE_VERIFY )
    {
        SSL_DEBUG_MSG( 1, ( "bad certificate verify message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
    }

    n1 = ssl->peer_cert->rsa.len;
    n2 = ( ssl->in_msg[4] << 8 ) | ssl->in_msg[5];

    if( n1 + 6 != ssl->in_hslen || n1 != n2 )
    {
        SSL_DEBUG_MSG( 1, ( "bad certificate verify message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY );
    }

    ret = rsa_pkcs1_verify( &ssl->peer_cert->rsa, RSA_PUBLIC,
                            SIG_RSA_RAW, 36, hash, ssl->in_msg + 6 );
    if( ret != 0 )
    {
        SSL_DEBUG_RET( 1, "rsa_pkcs1_verify", ret );
        return( ret );
    }

    SSL_DEBUG_MSG( 2, ( "<= parse certificate verify" ) );

    return( 0 );
}

/*
 * SSL handshake -- server side
 */
int ssl_handshake_server( ssl_context *ssl )
{
    int ret = 0;

    SSL_DEBUG_MSG( 2, ( "=> handshake server" ) );

    while( ssl->state != SSL_HANDSHAKE_OVER )
    {
        SSL_DEBUG_MSG( 2, ( "server state: %d", ssl->state ) );

        if( ( ret = ssl_flush_output( ssl ) ) != 0 )
            break;

        switch( ssl->state )
        {
            case SSL_HELLO_REQUEST:
                ssl->state = SSL_CLIENT_HELLO;
                break;

            /*
             *  <==   ClientHello
             */
            case SSL_CLIENT_HELLO:
                ret = ssl_parse_client_hello( ssl );
                break;

            /*
             *  ==>   ServerHello
             *        Certificate
             *      ( ServerKeyExchange  )
             *      ( CertificateRequest )
             *        ServerHelloDone
             */
            case SSL_SERVER_HELLO:
                ret = ssl_write_server_hello( ssl );
                break;

            case SSL_SERVER_CERTIFICATE:
                ret = ssl_write_certificate( ssl );
                break;

            case SSL_SERVER_KEY_EXCHANGE:
                ret = ssl_write_server_key_exchange( ssl );
                break;

            case SSL_CERTIFICATE_REQUEST:
                ret = ssl_write_certificate_request( ssl );
                break;

            case SSL_SERVER_HELLO_DONE:
                ret = ssl_write_server_hello_done( ssl );
                break;

            /*
             *  <== ( Certificate/Alert  )
             *        ClientKeyExchange
             *      ( CertificateVerify  )
             *        ChangeCipherSpec
             *        Finished
             */
            case SSL_CLIENT_CERTIFICATE:
                ret = ssl_parse_certificate( ssl );
                break;

            case SSL_CLIENT_KEY_EXCHANGE:
                ret = ssl_parse_client_key_exchange( ssl );
                break;

            case SSL_CERTIFICATE_VERIFY:
                ret = ssl_parse_certificate_verify( ssl );
                break;

            case SSL_CLIENT_CHANGE_CIPHER_SPEC:
                ret = ssl_parse_change_cipher_spec( ssl );
                break;

            case SSL_CLIENT_FINISHED:
                ret = ssl_parse_finished( ssl );
                break;

            /*
             *  ==>   ChangeCipherSpec
             *        Finished
             */
            case SSL_SERVER_CHANGE_CIPHER_SPEC:
                ret = ssl_write_change_cipher_spec( ssl );
                break;

            case SSL_SERVER_FINISHED:
                ret = ssl_write_finished( ssl );
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

    SSL_DEBUG_MSG( 2, ( "<= handshake server" ) );

    return( ret );
}

#endif
