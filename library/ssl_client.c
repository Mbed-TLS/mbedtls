/*
 *  TLS 1.2 and 1.3 client-side functions
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
 *
 *  This file is part of mbed TLS ( https://tls.mbed.org )
 */

#include "common.h"

#if defined(MBEDTLS_SSL_CLI_C)
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) || defined(MBEDTLS_SSL_PROTO_TLS1_2)

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#endif

#include <string.h>

#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#if defined(MBEDTLS_HAVE_TIME)
#include "mbedtls/platform_time.h"
#endif

#include "ssl_client.h"
#include "ssl_misc.h"
#include "ecdh_misc.h"
#include "ssl_tls13_keys.h"
#include "ssl_debug_helpers.h"

#if defined(MBEDTLS_SSL_ALPN)
/*
 * ssl_write_alpn_ext()
 *
 * Structure of the application_layer_protocol_negotiation extension in
 * ClientHello:
 *
 * opaque ProtocolName<1..2^8-1>;
 *
 * struct {
 *     ProtocolName protocol_name_list<2..2^16-1>
 * } ProtocolNameList;
 *
 */
static int ssl_write_alpn_ext( mbedtls_ssl_context *ssl,
                               unsigned char *buf,
                               const unsigned char *end,
                               size_t *out_len )
{
    unsigned char *p = buf;

    *out_len = 0;

    if( ssl->conf->alpn_list == NULL )
        return( 0 );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding alpn extension" ) );


    /* Check we have enough space for the extension type (2 bytes), the
     * extension length (2 bytes) and the protocol_name_list length (2 bytes).
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_ALPN, p, 0 );
    /* Skip writing extension and list length for now */
    p += 6;

    /*
     * opaque ProtocolName<1..2^8-1>;
     *
     * struct {
     *     ProtocolName protocol_name_list<2..2^16-1>
     * } ProtocolNameList;
     */
    for( const char **cur = ssl->conf->alpn_list; *cur != NULL; cur++ )
    {
        /*
         * mbedtls_ssl_conf_set_alpn_protocols() checked that the length of
         * protocol names is less than 255.
         */
        size_t protocol_name_len = strlen( *cur );

        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 1 + protocol_name_len );
        *p++ = (unsigned char)protocol_name_len;
        memcpy( p, *cur, protocol_name_len );
        p += protocol_name_len;
    }

    *out_len = p - buf;

    /* List length = *out_len - 2 (ext_type) - 2 (ext_len) - 2 (list_len) */
    MBEDTLS_PUT_UINT16_BE( *out_len - 6, buf, 4 );

    /* Extension length = *out_len - 2 (ext_type) - 2 (ext_len) */
    MBEDTLS_PUT_UINT16_BE( *out_len - 4, buf, 2 );

    return( 0 );
}
#endif /* MBEDTLS_SSL_ALPN */

/* Write cipher_suites
 * CipherSuite cipher_suites<2..2^16-2>;
 */
/**
 * \brief Validate cipher suite against config in SSL context.
 *
 * \param ssl         SSL context
 * \param suite_info  Cipher suite to validate
 *
 * \return 0 if valid, else 1
 */
static int ssl_validate_ciphersuite(
    const mbedtls_ssl_context *ssl,
    const mbedtls_ssl_ciphersuite_t *suite_info )
{
    if( suite_info == NULL )
        return( 1 );

    if( ( suite_info->min_minor_ver > ssl->conf->max_minor_ver ) ||
        ( suite_info->max_minor_ver < ssl->conf->min_minor_ver ) )
        return( 1 );

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
            ( suite_info->flags & MBEDTLS_CIPHERSUITE_NODTLS ) )
        return( 1 );
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    if( suite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECJPAKE &&
            mbedtls_ecjpake_check( &ssl->handshake->ecjpake_ctx ) != 0 )
        return( 1 );
#endif

    /* Don't suggest PSK-based ciphersuite if no PSK is available. */
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if( mbedtls_ssl_ciphersuite_uses_psk( suite_info ) &&
        mbedtls_ssl_conf_has_static_psk( ssl->conf ) == 0 )
    {
        return( 1 );
    }
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

    return( 0 );
}

static int ssl_write_client_hello_cipher_suites(
            mbedtls_ssl_context *ssl,
            unsigned char *buf,
            unsigned char *end,
            int *tls12_uses_ec,
            size_t *out_len )
{
    unsigned char *p = buf;
    const int *ciphersuite_list;
    unsigned char *cipher_suites; /* Start of the cipher_suites list */
    size_t cipher_suites_len;

    *tls12_uses_ec = 0;
    *out_len = 0;

    /*
     * Ciphersuite list
     *
     * This is a list of the symmetric cipher options supported by
     * the client, specifically the record protection algorithm
     * ( including secret key length ) and a hash to be used with
     * HKDF, in descending order of client preference.
     */
    ciphersuite_list = ssl->conf->ciphersuite_list;

    /* Check there is space for the cipher suite list length (2 bytes). */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    p += 2;

    /* Write cipher_suites */
    cipher_suites = p;
    for ( size_t i = 0; ciphersuite_list[i] != 0; i++ )
    {
        int cipher_suite = ciphersuite_list[i];
        const mbedtls_ssl_ciphersuite_t *ciphersuite_info;

        ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( cipher_suite );

        if( ssl_validate_ciphersuite( ssl, ciphersuite_info ) )
            continue;

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    ( defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) || \
      defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED) )
        *tls12_uses_ec |= mbedtls_ssl_ciphersuite_uses_ec( ciphersuite_info );
#endif

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, add ciphersuite: %04x, %s",
                                    (unsigned int) cipher_suite,
                                    ciphersuite_info->name ) );

        /* Check there is space for the cipher suite identifier (2 bytes). */
        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
        MBEDTLS_PUT_UINT16_BE( cipher_suite, p, 0 );
        p += 2;
    }

    /*
     * Add TLS_EMPTY_RENEGOTIATION_INFO_SCSV
     */
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if( ssl->renego_status == MBEDTLS_SSL_INITIAL_HANDSHAKE )
#endif
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "adding EMPTY_RENEGOTIATION_INFO_SCSV" ) );
        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
        MBEDTLS_PUT_UINT16_BE( MBEDTLS_SSL_EMPTY_RENEGOTIATION_INFO, p, 0 );
        p += 2;
    }

    /* Write the cipher_suites length in number of bytes */
    cipher_suites_len = p - cipher_suites;
    MBEDTLS_PUT_UINT16_BE( cipher_suites_len, buf, 0 );
    MBEDTLS_SSL_DEBUG_MSG( 3,
                           ( "client hello, got %" MBEDTLS_PRINTF_SIZET " cipher suites",
                             cipher_suites_len/2 ) );

    /* Output the total length of cipher_suites field. */
    *out_len = p - buf;

    return( 0 );
}

/*
 * Structure of the TLS 1.3 ClientHello message:
 *
 *    struct {
 *        ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *        Random random;
 *        opaque legacy_session_id<0..32>;
 *        CipherSuite cipher_suites<2..2^16-2>;
 *        opaque legacy_compression_methods<1..2^8-1>;
 *        Extension extensions<8..2^16-1>;
 *    } ClientHello;
 *
 * Structure of the (D)TLS 1.2 ClientHello message:
 *
 * struct {
 *     ProtocolVersion client_version;
 *     Random random;
 *     SessionID session_id;
 *     opaque cookie<0..2^8-1>; // DTLS 1.2 ONLY
 *     CipherSuite cipher_suites<2..2^16-2>;
 *     CompressionMethod compression_methods<1..2^8-1>;
 *     select (extensions_present) {
 *         case false:
 *             struct {};
 *         case true:
 *             Extension extensions<0..2^16-1>;
 *     };
 * } ClientHello;
 */
static int ssl_write_client_hello_body( mbedtls_ssl_context *ssl,
                                        unsigned char *buf,
                                        unsigned char *end,
                                        size_t *out_len )
{
    int ret;
    unsigned char *p = buf;
    int tls12_uses_ec = 0;

    unsigned char *p_extensions_len; /* Pointer to extensions length */
    size_t output_len;               /* Length of buffer used by function */
    size_t extensions_len;           /* Length of the list of extensions*/

    *out_len = 0;

    /*
     * Write client_version (TLS 1.2) or legacy_version (TLS 1.3)
     *
     * In all cases this is the TLS 1.2 version.
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    mbedtls_ssl_write_version( MBEDTLS_SSL_MAJOR_VERSION_3,
                               MBEDTLS_SSL_MINOR_VERSION_3,
                               ssl->conf->transport, p );
    p += 2;

    /* ...
     * Random random;
     * ...
     *
     * with for TLS 1.2
     * struct {
     *     uint32 gmt_unix_time;
     *     opaque random_bytes[28];
     * } Random;
     *
     * and for TLS 1.3
     * opaque Random[32];
     *
     * The random bytes have been prepared by ssl_prepare_client_hello() into
     * the ssl->handshake->randbytes buffer and are copied here into the
     * output buffer.
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    memcpy( p, ssl->handshake->randbytes, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes",
                           p, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    p += MBEDTLS_CLIENT_HELLO_RANDOM_LEN;

    /* TLS 1.2:
     * ...
     * SessionID session_id;
     * ...
     * with
     * opaque SessionID<0..32>;
     *
     * TLS 1.3:
     * ...
     * opaque legacy_session_id<0..32>;
     * ...
     *
     * The (legacy) session identifier bytes have been by
     * ssl_prepare_client_hello() into the ssl->session_negotiate->id buffer
     * and are copied here into the output buffer.
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, ssl->session_negotiate->id_len + 1 );
    *p++ = (unsigned char)ssl->session_negotiate->id_len;
    memcpy( p, ssl->session_negotiate->id, ssl->session_negotiate->id_len );
    p += ssl->session_negotiate->id_len;

    MBEDTLS_SSL_DEBUG_BUF( 3, "session id", ssl->session_negotiate->id,
                              ssl->session_negotiate->id_len );

    /* DTLS 1.2 ONLY
     * ...
     * opaque cookie<0..2^8-1>;
     * ...
     */
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        unsigned char cookie_len = 0;

        if( ssl->handshake->cookie != NULL )
        {
            MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, cookie",
                                   ssl->handshake->cookie,
                                   ssl->handshake->verify_cookie_len );
            cookie_len = ssl->handshake->verify_cookie_len;
        }

        MBEDTLS_SSL_CHK_BUF_PTR( p, end, cookie_len + 1 );
        *p++ = cookie_len;
        if( cookie_len > 0 )
        {
            memcpy( p, ssl->handshake->cookie, cookie_len );
            p += cookie_len;
        }
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 && MBEDTLS_SSL_PROTO_DTLS */

    /* Write cipher_suites */
    ret = ssl_write_client_hello_cipher_suites( ssl, p, end,
                                                &tls12_uses_ec,
                                                &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;

    /* Write legacy_compression_methods (TLS 1.3) or
     * compression_methods (TLS 1.2)
     *
     * For every TLS 1.3 ClientHello, this vector MUST contain exactly
     * one byte set to zero, which corresponds to the 'null' compression
     * method in prior versions of TLS.
     *
     * For TLS 1.2 ClientHello, for security reasons we do not support
     * compression anymore, thus also just the 'null' compression method.
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    *p++ = 1;
    *p++ = MBEDTLS_SSL_COMPRESS_NULL;

    /* Write extensions */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    /* Keeping track of the included extensions */
    ssl->handshake->extensions_present = MBEDTLS_SSL_EXT_NONE;
#endif

    /* First write extensions, then the total length */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    p_extensions_len = p;
    p += 2;

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    ret = mbedtls_ssl_tls13_write_client_hello_exts( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif

#if defined(MBEDTLS_SSL_ALPN)
    ret = ssl_write_alpn_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif /* MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    if( mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
    {
        ret = mbedtls_ssl_write_supported_groups_ext( ssl, p, end, &output_len );
        if( ret != 0 )
            return( ret );
        p += output_len;
    }

    if( mbedtls_ssl_conf_tls13_ephemeral_enabled( ssl ) )
    {
        ret = mbedtls_ssl_write_sig_alg_ext( ssl, p, end, &output_len );
        if( ret != 0 )
            return( ret );
        p += output_len;
    }
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    /* Write server name extension */
    ret = mbedtls_ssl_write_hostname_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

    /* Add more extensions here */

    /* Write the length of the list of extensions. */
    extensions_len = p - p_extensions_len - 2;
    MBEDTLS_PUT_UINT16_BE( extensions_len, p_extensions_len, 0 );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, total extension length: %" MBEDTLS_PRINTF_SIZET ,
                                extensions_len ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello extensions", p_extensions_len, extensions_len );

    *out_len = p - buf;
    return( 0 );
}

static int ssl_generate_random( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *randbytes = ssl->handshake->randbytes;
    size_t gmt_unix_time_len = 0;

    /*
     * Generate the random bytes
     *
     * TLS 1.2 case:
     * struct {
     *     uint32 gmt_unix_time;
     *     opaque random_bytes[28];
     * } Random;
     *
     * TLS 1.3 case:
     * opaque Random[32];
     */
    if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3 )
    {
#if defined(MBEDTLS_HAVE_TIME)
        mbedtls_time_t gmt_unix_time = mbedtls_time( NULL );
        MBEDTLS_PUT_UINT32_BE( gmt_unix_time, randbytes, 0 );
        gmt_unix_time_len = 4;

        MBEDTLS_SSL_DEBUG_MSG( 3,
            ( "client hello, current time: %" MBEDTLS_PRINTF_LONGLONG,
               (long long) gmt_unix_time ) );
#endif /* MBEDTLS_HAVE_TIME */
    }

    ret = ssl->conf->f_rng( ssl->conf->p_rng,
                            randbytes + gmt_unix_time_len,
                            MBEDTLS_CLIENT_HELLO_RANDOM_LEN - gmt_unix_time_len );
    return( ret );
}

static int ssl_prepare_client_hello( mbedtls_ssl_context *ssl )
{
    int ret;
    size_t session_id_len;

    if( ssl->conf->f_rng == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no RNG provided" ) );
        return( MBEDTLS_ERR_SSL_NO_RNG );
    }

    /* Bet on the highest configured version if we are not in a TLS 1.2
     * renegotiation or session resumption.
     */
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if( ssl->renego_status != MBEDTLS_SSL_INITIAL_HANDSHAKE )
        ssl->handshake->min_minor_ver = ssl->minor_ver;
    else
#endif
    {
        ssl->major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;

        if( ssl->handshake->resume )
        {
             ssl->minor_ver = ssl->session_negotiate->minor_ver;
             ssl->handshake->min_minor_ver = ssl->minor_ver;
        }
        else
        {
             ssl->minor_ver = ssl->conf->max_minor_ver;
             ssl->handshake->min_minor_ver = ssl->conf->min_minor_ver;
        }
    }

    /*
     * But when responding to a verify request where we MUST reuse the
     * previoulsy generated random bytes (RFC 6347 4.2.1), generate the
     * random bytes.
     */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ( ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM ) ||
        ( ssl->handshake->cookie == NULL ) )
#endif
    {
        ret = ssl_generate_random( ssl );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "Random bytes generation failed", ret );
            return( ret );
        }
    }

    /*
     * Prepare session identifier. But in the case of a TLS 1.2 session
     * renegotiation or session resumption, the initial value of the session
     * identifier length below is equal to zero.
     */
    session_id_len = ssl->session_negotiate->id_len;

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_3 )
    {
        if( session_id_len < 16 || session_id_len > 32 ||
#if defined(MBEDTLS_SSL_RENEGOTIATION)
            ssl->renego_status != MBEDTLS_SSL_INITIAL_HANDSHAKE ||
#endif
            ssl->handshake->resume == 0 )
        {
            session_id_len = 0;
        }

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    /*
     * RFC 5077 section 3.4: "When presenting a ticket, the client MAY
     * generate and include a Session ID in the TLS ClientHello."
     */
#if defined(MBEDTLS_SSL_RENEGOTIATION)
        if( ssl->renego_status == MBEDTLS_SSL_INITIAL_HANDSHAKE )
#endif
        {
            if( ( ssl->session_negotiate->ticket != NULL ) &&
                ( ssl->session_negotiate->ticket_len != 0 ) )
            {
                session_id_len = 32;
            }
        }
#endif /* MBEDTLS_SSL_SESSION_TICKETS */
    }
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_4 )
    {
        /*
         * Create a legacy session identifier for the purpose of middlebox
         * compatibility only if one has not been created already, which is
         * the case if we are here for the TLS 1.3 second ClientHello.
         *
         * Versions of TLS before TLS 1.3 supported a "session resumption"
         * feature which has been merged with pre-shared keys in TLS 1.3
         * version. A client which has a cached session ID set by a pre-TLS 1.3
         * server SHOULD set this field to that value. In compatibility mode,
         * this field MUST be non-empty, so a client not offering a pre-TLS 1.3
         * session MUST generate a new 32-byte value. This value need not be
         * random but SHOULD be unpredictable to avoid implementations fixating
         * on a specific value (also known as ossification). Otherwise, it MUST
         * be set as a zero-length vector ( i.e., a zero-valued single byte
         * length field ).
         */
        session_id_len = 32;
    }
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

    if( session_id_len != ssl->session_negotiate->id_len )
    {
        ssl->session_negotiate->id_len = session_id_len;
        if( session_id_len > 0 )
        {
            ret = ssl->conf->f_rng( ssl->conf->p_rng,
                                    ssl->session_negotiate->id,
                                    session_id_len );
            if( ret != 0 )
            {
                MBEDTLS_SSL_DEBUG_RET( 1, "creating session id failed", ret );
                return( ret );
            }
        }
    }

    return( 0 );
}

/*
 * Write ClientHello handshake message.
 * Handler for MBEDTLS_SSL_CLIENT_HELLO
 */
int mbedtls_ssl_write_client_hello( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write client hello" ) );

    MBEDTLS_SSL_PROC_CHK( ssl_prepare_client_hello( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg(
                                ssl, MBEDTLS_SSL_HS_CLIENT_HELLO,
                                &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_write_client_hello_body( ssl, buf,
                                                       buf + buf_len,
                                                       &msg_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_CLIENT_HELLO,
                                        buf, msg_len );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg( ssl,
                                                            buf_len,
                                                            msg_len ) );

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_HELLO );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write client hello" ) );
    return ret;
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 || MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_SSL_CLI_C */
