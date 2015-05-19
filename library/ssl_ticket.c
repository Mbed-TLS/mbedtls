/*
 *  TLS server tickets callbacks implementation
 *
 *  Copyright (C) 2015, ARM Limited, All Rights Reserved
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

#if defined(MBEDTLS_SSL_TICKET_C)

#include "mbedtls/ssl_ticket.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_malloc     malloc
#define mbedtls_free       free
#endif

#include <string.h>

/*
 * Serialize a session in the following format:
 *  0   .   n-1     session structure, n = sizeof(mbedtls_ssl_session)
 *  n   .   n+2     peer_cert length = m (0 if no certificate)
 *  n+3 .   n+2+m   peer cert ASN.1
 *
 *  Assumes ticket is NULL (always true on server side).
 */
static int ssl_save_session( const mbedtls_ssl_session *session,
                             unsigned char *buf, size_t buf_len,
                             size_t *olen )
{
    unsigned char *p = buf;
    size_t left = buf_len;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    size_t cert_len;
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    if( left < sizeof( mbedtls_ssl_session ) )
        return( -1 );

    memcpy( p, session, sizeof( mbedtls_ssl_session ) );
    p += sizeof( mbedtls_ssl_session );
    left -= sizeof( mbedtls_ssl_session );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( session->peer_cert == NULL )
        cert_len = 0;
    else
        cert_len = session->peer_cert->raw.len;

    if( left < 3 + cert_len )
        return( -1 );

    *p++ = (unsigned char)( cert_len >> 16 & 0xFF );
    *p++ = (unsigned char)( cert_len >>  8 & 0xFF );
    *p++ = (unsigned char)( cert_len       & 0xFF );

    if( session->peer_cert != NULL )
        memcpy( p, session->peer_cert->raw.p, cert_len );

    p += cert_len;
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    *olen = p - buf;

    return( 0 );
}

/*
 * Unserialise session, see ssl_save_session()
 */
static int ssl_load_session( mbedtls_ssl_session *session,
                             const unsigned char *buf, size_t len )
{
    const unsigned char *p = buf;
    const unsigned char * const end = buf + len;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    size_t cert_len;
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    if( p + sizeof( mbedtls_ssl_session ) > end )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    memcpy( session, p, sizeof( mbedtls_ssl_session ) );
    p += sizeof( mbedtls_ssl_session );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( p + 3 > end )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    cert_len = ( p[0] << 16 ) | ( p[1] << 8 ) | p[2];
    p += 3;

    if( cert_len == 0 )
    {
        session->peer_cert = NULL;
    }
    else
    {
        int ret;

        if( p + cert_len > end )
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

        session->peer_cert = mbedtls_malloc( sizeof( mbedtls_x509_crt ) );

        if( session->peer_cert == NULL )
            return( MBEDTLS_ERR_SSL_MALLOC_FAILED );

        mbedtls_x509_crt_init( session->peer_cert );

        if( ( ret = mbedtls_x509_crt_parse_der( session->peer_cert,
                                        p, cert_len ) ) != 0 )
        {
            mbedtls_x509_crt_free( session->peer_cert );
            mbedtls_free( session->peer_cert );
            session->peer_cert = NULL;
            return( ret );
        }

        p += cert_len;
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    if( p != end )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    return( 0 );
}

/*
 * Create session ticket, secured as recommended in RFC 5077 section 4:
 *
 *    struct {
 *        opaque key_name[16];
 *        opaque iv[16];
 *        opaque encrypted_state<0..2^16-1>;
 *        opaque mac[32];
 *    } ticket;
 *
 * (the internal state structure differs, however).
 */
int mbedtls_ssl_ticket_write( void *p_ticket,
                              const mbedtls_ssl_session *session,
                              unsigned char *start,
                              const unsigned char *end,
                              size_t *tlen,
                              uint32_t *ticket_lifetime )
{
    int ret;
    mbedtls_ssl_ticket_keys *ctx = p_ticket;
    unsigned char *p = start;
    unsigned char *state;
    unsigned char iv[16];
    size_t clear_len, enc_len, pad_len, i;

    *tlen = 0;

    if( ctx == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    *ticket_lifetime = ctx->ticket_lifetime;

    /* We need at least 16 bytes for key_name, 16 for IV, 2 for len
     * 16 for padding, 32 for MAC, in addition to session itself,
     * that will be checked when writing it. */
    if( end - start < 16 + 16 + 2 + 16 + 32 )
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );

    /* Write key name */
    memcpy( p, ctx->key_name, 16 );
    p += 16;

    /* Generate and write IV (with a copy for aes_crypt) */
    memset( p, 0x2a, 16 ); /* Temporary WIP */
    memcpy( iv, p, 16 );
    p += 16;

    /* Dump session state */
    state = p + 2;
    if( ssl_save_session( session, state, end - state, &clear_len ) != 0 )
        return( MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL );

    /* Apply PKCS padding */
    pad_len = 16 - clear_len % 16;
    enc_len = clear_len + pad_len;
    for( i = clear_len; i < enc_len; i++ )
        state[i] = (unsigned char) pad_len;

    /* Encrypt */
    if( ( ret = mbedtls_aes_crypt_cbc( &ctx->enc, MBEDTLS_AES_ENCRYPT,
                               enc_len, iv, state, state ) ) != 0 )
    {
        return( ret );
    }

    /* Write length */
    *p++ = (unsigned char)( ( enc_len >> 8 ) & 0xFF );
    *p++ = (unsigned char)( ( enc_len      ) & 0xFF );
    p = state + enc_len;

    /* Compute and write MAC( key_name + iv + enc_state_len + enc_state ) */
    if( ( ret = mbedtls_md_hmac( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                         ctx->mac_key, 16,
                         start, p - start, p ) ) != 0 )
    {
        return( ret );
    }
    p += 32;

    *tlen = p - start;

    return( 0 );
}

/*
 * Load session ticket (see mbedtls_ssl_ticket_write for structure)
 */
int mbedtls_ssl_ticket_parse( void *p_ticket,
                              mbedtls_ssl_session *session,
                              unsigned char *buf,
                              size_t len )
{
    int ret;
    mbedtls_ssl_ticket_keys *ctx = p_ticket;
    unsigned char *key_name = buf;
    unsigned char *iv = buf + 16;
    unsigned char *enc_len_p = iv + 16;
    unsigned char *ticket = enc_len_p + 2;
    unsigned char *mac;
    unsigned char computed_mac[32];
    size_t enc_len, clear_len, i;
    unsigned char pad_len, diff;

    if( len < 34 || ctx == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    enc_len = ( enc_len_p[0] << 8 ) | enc_len_p[1];
    mac = ticket + enc_len;

    if( len != enc_len + 66 )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    /* Check name, in constant time though it's not a big secret */
    diff = 0;
    for( i = 0; i < 16; i++ )
        diff |= key_name[i] ^ ctx->key_name[i];
    /* don't return yet, check the MAC anyway */

    /* Check mac, with constant-time buffer comparison */
    if( ( ret = mbedtls_md_hmac( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ),
                         ctx->mac_key, 16,
                         buf, len - 32, computed_mac ) ) != 0 )
    {
        return( ret );
    }

    for( i = 0; i < 32; i++ )
        diff |= mac[i] ^ computed_mac[i];

    /* Now return if ticket is not authentic, since we want to avoid
     * decrypting arbitrary attacker-chosen data */
    if( diff != 0 )
        return( MBEDTLS_ERR_SSL_INVALID_MAC );

    /* Decrypt */
    if( ( ret = mbedtls_aes_crypt_cbc( &ctx->dec, MBEDTLS_AES_DECRYPT,
                               enc_len, iv, ticket, ticket ) ) != 0 )
    {
        return( ret );
    }

    /* Check PKCS padding */
    pad_len = ticket[enc_len - 1];

    ret = 0;
    for( i = 2; i < pad_len; i++ )
        if( ticket[enc_len - i] != pad_len )
            ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    if( ret != 0 )
        return( ret );

    clear_len = enc_len - pad_len;

    /* Actually load session */
    if( ( ret = ssl_load_session( session, ticket, clear_len ) ) != 0 )
        return( ret );

#if defined(MBEDTLS_HAVE_TIME)
    /* Check if still valid */
    if( ( time( NULL) - session->start ) > ctx->ticket_lifetime )
        return( MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED );
#endif

    return( 0 );
}

#endif /* MBEDTLS_SSL_TICKET_C */
