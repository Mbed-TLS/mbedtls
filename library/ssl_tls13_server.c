/*
 *  TLS 1.3 server-side functions
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

#include "common.h"

#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)

#include "mbedtls/debug.h"
#include "mbedtls/platform.h"

#include "ssl_misc.h"
#include "ssl_tls13_keys.h"
#include "ssl_debug_helpers.h"
#include <string.h>
#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#include "ecp_internal.h"
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

/* From RFC 8446:
 *   struct {
 *       select (Handshake.msg_type) {
 *           case client_hello:
 *                ProtocolVersion versions<2..254>;
 *           case server_hello: // and HelloRetryRequest
 *                ProtocolVersion selected_version;
 *       };
 *   } SupportedVersions;
 */
static int ssl_tls13_parse_supported_versions_ext( mbedtls_ssl_context *ssl,
                                                   const unsigned char *buf,
                                                   const unsigned char *end )
{
    size_t list_len;
    int tls13_supported = 0;
    int major_ver, minor_ver;
    const unsigned char *p = buf;
    const unsigned char *version_end;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 1 );

    list_len = p[0];
    p += 1;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, list_len );
    if( list_len % 2 != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Invalid supported version list length %" MBEDTLS_PRINTF_SIZET,
                                    list_len ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    version_end = p + list_len;
    while( p < version_end )
    {
        mbedtls_ssl_read_version( &major_ver, &minor_ver, ssl->conf->transport, p );

        /* In this implementation we only support TLS 1.3 and DTLS 1.3. */
        if( major_ver == MBEDTLS_SSL_MAJOR_VERSION_3 &&
            minor_ver == MBEDTLS_SSL_MINOR_VERSION_4 )
        {
            tls13_supported = 1;
            break;
        }

        p += 2;
    }

    if( tls13_supported == 0 )
    {
        /* When we support runtime negotiation of TLS 1.2 and TLS 1.3, we need
         * a graceful fallback to TLS 1.2 in this case. */

        MBEDTLS_SSL_DEBUG_MSG( 1, ( "TLS 1.3 is not supported by the client" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                      MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
        return( MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
    }

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Negotiated version. Supported is [%d:%d]",
                              major_ver, minor_ver ) );

    ssl->major_ver = major_ver;
    ssl->minor_ver = minor_ver;
    ssl->handshake->max_major_ver = ssl->major_ver;
    ssl->handshake->max_minor_ver = ssl->minor_ver;
    return( 0 );
}

#if ( defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) )
/* This function parses the TLS 1.3 supported_groups extension and
 * stores the received groups in ssl->handshake->curves.
 *
 * From RFC 8446:
 *   enum {
 *       ... (0xFFFF)
 *   } NamedGroup;
 *   struct {
 *       NamedGroup named_group_list<2..2^16-1>;
 *   } NamedGroupList;
 */
static int mbedtls_ssl_tls13_parse_supported_groups_ext(
                mbedtls_ssl_context *ssl,
                const unsigned char *buf, const unsigned char *end )
{

    size_t list_size, our_size;
    const unsigned char *p = buf;
    const mbedtls_ecp_curve_info *curve_info, **curves;
    const unsigned char *extentions_end;

    MBEDTLS_SSL_DEBUG_BUF( 3, "supported_groups extension", p, end - buf );
    list_size = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, list_size );
    if( list_size % 2 != 0 )
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );

    /* TODO: At the moment, this can happen when receiving a second
     *       ClientHello after an HRR. We should properly reset the
     *       state upon receiving an HRR, in which case we should
     *       not observe handshake->curves already being allocated. */
    if( ssl->handshake->curves != NULL )
    {
        mbedtls_free( ssl->handshake->curves );
        ssl->handshake->curves = NULL;
    }

    /* Don't allow our peer to make us allocate too much memory,
     * and leave room for a final 0 */
    our_size = list_size / 2 + 1;
    if( our_size > MBEDTLS_ECP_DP_MAX )
        our_size = MBEDTLS_ECP_DP_MAX;

    if( ( curves = mbedtls_calloc( our_size, sizeof( *curves ) ) ) == NULL )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

    extentions_end = p + list_size;
    ssl->handshake->curves = curves;

    while ( p < extentions_end && our_size > 1 )
    {
        uint16_t tls_grp_id = MBEDTLS_GET_UINT16_BE( p, 0 );
        curve_info = mbedtls_ecp_curve_info_from_tls_id( tls_grp_id );

        /* mbedtls_ecp_curve_info_from_tls_id() uses the mbedtls_ecp_curve_info
         * data structure (defined in ecp.c), which only includes the list of
         * curves implemented. Hence, we only add curves that are also supported
         * and implemented by the server. */
        if( curve_info != NULL )
        {
            *curves++ = curve_info;
            MBEDTLS_SSL_DEBUG_MSG( 4, ( "supported curve: %s", curve_info->name ) );
            our_size--;
        }

        p += 2;
    }

    return( 0 );

}
#endif /* MBEDTLS_ECDH_C || ( MBEDTLS_ECDSA_C */

/* TODO: Code for MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED missing */
/*
 *  ssl_tls13_parse_key_shares_ext() verifies whether the information in the
 *  extension is correct and stores the provided key shares. Whether this is an
 *  acceptable key share depends on the selected ciphersuite.
 *
 *  Possible return values are:
 *  - 0: Successful processing of the client provided key share extension.
 *  - MBEDTLS_ERR_SSL_HRR_REQUIRED: The key share provided by the client
 *    does not match a group supported by the server. A HelloRetryRequest will
 *    be needed.
 *  - Another negative return value for fatal errors.
*/

static int ssl_tls13_parse_key_shares_ext( mbedtls_ssl_context *ssl,
                                           const unsigned char *buf,
                                           const unsigned char *end )
{
    int ret = 0;
    unsigned char const *p = buf;
    unsigned char const *extentions_end;

    size_t total_ext_len, cur_share_len;
    int match_found = 0;

    /* From RFC 8446:
     *
     * struct {
     *     KeyShareEntry client_shares<0..2^16-1>;
     * } KeyShareClientHello;
     *
     */

    /* Read total legnth of KeyShareClientHello */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );

    total_ext_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, total_ext_len );

    ssl->handshake->offered_group_id = 0;
    extentions_end = p + total_ext_len;

    /* We try to find a suitable key share entry and copy it to the
     * handshake context. Later, we have to find out whether we can do
     * something with the provided key share or whether we have to
     * dismiss it and send a HelloRetryRequest message. */

    for( ; p < extentions_end; p += cur_share_len )
    {
        uint16_t their_group;
        mbedtls_ecp_group_id their_curve;
        mbedtls_ecp_curve_info const *their_curve_info;
        unsigned char const *end_of_share;

        /*
         * struct {
         *    NamedGroup group;
         *    opaque key_exchange<1..2^16-1>;
         * } KeyShareEntry;
         */
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extentions_end, 4 );

        their_group = MBEDTLS_GET_UINT16_BE( p, 0 );
        p   += 2;

        cur_share_len = MBEDTLS_GET_UINT16_BE( p, 0 );
        p   += 2;

        end_of_share = p + cur_share_len;

        /* Continue parsing even if we have already found a match,
         * for input validation purposes. */
        if( match_found == 1 )
            continue;

        /*
         * NamedGroup matching
         *
         * For now, we only support ECDHE groups, but e.g.
         * PQC KEMs will need to be added at a later stage.
         */

        /* Type 1: ECDHE shares
         *
         * - Check if we recognize the group
         * - Check if it's supported
         */

        const mbedtls_ecp_curve_info *curve_info;
        curve_info = mbedtls_ecp_curve_info_from_tls_id( their_group );
        if( curve_info == NULL )
            return( MBEDTLS_ECP_DP_NONE );
        their_curve =  curve_info->grp_id;
        if( mbedtls_ssl_check_curve( ssl, their_curve ) != 0 )
            continue;

        /* Type 2..X: Other kinds of shares */
        /* TO BE ADDED */

        /* Skip if we no match succeeded. */
        if( their_curve == MBEDTLS_ECP_DP_NONE )
        {
            MBEDTLS_SSL_DEBUG_MSG( 4, ( "Unrecognized NamedGroup %u",
                                        (unsigned) their_group ) );
            continue;
        }

        match_found = 1;

        /* KeyShare parsing
         *
         * Once we add more key share types, this needs to be a switch
         * over the (type of) the named curve */

        /* Type 1: ECDHE shares
         *
         * - Setup ECDHE context
         * - Import client's public key
         * - Apply further curve checks
         */

        their_curve_info = mbedtls_ecp_curve_info_from_grp_id( their_curve );
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "ECDH curve: %s", their_curve_info->name ) );

        ret = mbedtls_ecdh_setup( &ssl->handshake->ecdh_ctx, their_curve );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_setup()", ret );
            return( ret );
        }

        ret = mbedtls_ecdh_import_public_raw( &ssl->handshake->ecdh_ctx,
                                              p, end_of_share );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_import_public_raw()", ret );
            return( ret );
        }

        ssl->handshake->offered_group_id = their_group;
    }

    if( match_found == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no matching key share" ) );
        return( MBEDTLS_ERR_SSL_HRR_REQUIRED );
    }
    return( 0 );
}
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_SSL_COOKIE_C)
static int ssl_tls13_parse_cookie_ext( mbedtls_ssl_context *ssl,
                                       const unsigned char *buf,
                                       const unsigned char *end )
{
    int ret = 0;
    size_t cookie_len;
    unsigned char const *p = buf;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "parse cookie extension" ) );

    if( ssl->conf->f_cookie_check != NULL )
    {
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
        cookie_len = MBEDTLS_GET_UINT16_BE( p, 0 );
        p += 2;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, cookie_len );

        MBEDTLS_SSL_DEBUG_BUF( 3, "Received cookie", p, cookie_len );

        if( ssl->conf->f_cookie_check( ssl->conf->p_cookie,
                                       p, cookie_len, ssl->cli_id,
                                       ssl->cli_id_len ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "cookie verification failed" ) );
            handshake->verify_cookie_len = 1;
            ret = MBEDTLS_ERR_SSL_HRR_REQUIRED;
        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "cookie verification passed" ) );
            handshake->verify_cookie_len = 0;
        }
    }
    else {
        /* TBD: Check under what cases this is appropriate */
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "cookie verification skipped" ) );
    }

    return( ret );
}
#endif /* MBEDTLS_SSL_COOKIE_C */

/*
 *
 * STATE HANDLING: ClientHello
 *
 * There are three possible classes of outcomes when parsing the CH:
 *
 * 1) The CH was well-formed and matched the server's configuration.
 *
 *    In this case, the server progresses to sending its ServerHello.
 *
 * 2) The CH was well-formed but didn't match the server's configuration.
 *
 *    For example, the client might not have offered a key share which
 *    the server supports, or the server might require a cookie.
 *
 *    In this case, the server sends a HelloRetryRequest.
 *
 * 3) The CH was ill-formed
 *
 *    In this case, we abort the handshake.
 *
 */

/*
 * Overview
 */

/* Main entry point from the state machine; orchestrates the otherfunctions. */
static int ssl_client_hello_process( mbedtls_ssl_context *ssl );

static int ssl_client_hello_parse( mbedtls_ssl_context *ssl,
                                   const unsigned char *buf,
                                   const unsigned char *end );

/* Update the handshake state machine */
/* TODO: At the moment, this doesn't update the state machine - why? */
static int ssl_client_hello_postprocess( mbedtls_ssl_context *ssl,
                                         int hrr_required );

/*
 * Implementation
 */

#define SSL_CLIENT_HELLO_OK           0
#define SSL_CLIENT_HELLO_HRR_REQUIRED 1

static int ssl_client_hello_process( mbedtls_ssl_context *ssl )
{

    int ret = 0;
    int hrr_required = SSL_CLIENT_HELLO_OK;
    unsigned char* buf = NULL;
    size_t buflen = 0;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse client hello" ) );

    ssl->major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_fetch_handshake_msg(
                          ssl, MBEDTLS_SSL_HS_CLIENT_HELLO,
                          &buf, &buflen ) );

    mbedtls_ssl_tls13_add_hs_hdr_to_checksum( ssl,
                                              MBEDTLS_SSL_HS_CLIENT_HELLO,
                                              buflen );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_client_hello_parse( ssl, buf, buf + buflen ) );
    hrr_required = ret;

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "postprocess" ) );
    MBEDTLS_SSL_PROC_CHK( ssl_client_hello_postprocess( ssl, hrr_required ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse client hello" ) );
    return( ret );
}

static void ssl_debug_print_client_hello_exts( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Supported Extensions:" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- KEY_SHARE_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_KEY_SHARE ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- PSK_KEY_EXCHANGE_MODES_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_PSK_KEY_EXCHANGE_MODES ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- PRE_SHARED_KEY_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_PRE_SHARED_KEY ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- SIGNATURE_ALGORITHM_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SIG_ALG ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- SUPPORTED_GROUPS_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SUPPORTED_GROUPS ) >0 ) ?
                                "TRUE" : "FALSE" ) );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- SUPPORTED_VERSION_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SUPPORTED_VERSIONS ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
#if defined ( MBEDTLS_SSL_SERVER_NAME_INDICATION )
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- SERVERNAME_EXTENSION    ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_SERVERNAME ) > 0 ) ?
                                "TRUE" : "FALSE" ) );
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
#if defined ( MBEDTLS_SSL_COOKIE_C )
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "- COOKIE_EXTENSION ( %s )",
                                ( ( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_COOKIE ) >0 ) ?
                                "TRUE" : "FALSE" ) );
#endif /* MBEDTLS_SSL_COOKIE_C */
}

static int ssl_client_hello_has_exts( mbedtls_ssl_context *ssl,
                                      int ext_id_mask )
{
    int masked = ssl->handshake->extensions_present & ext_id_mask;
    return( masked == ext_id_mask );
}

static int ssl_client_hello_has_cert_extensions( mbedtls_ssl_context *ssl )
{
    return( ssl_client_hello_has_exts( ssl,
                          MBEDTLS_SSL_EXT_SUPPORTED_GROUPS |
                          MBEDTLS_SSL_EXT_KEY_SHARE        |
                          MBEDTLS_SSL_EXT_SIG_ALG ) );
}

static int ssl_check_certificate_key_exchange( mbedtls_ssl_context *ssl )
{
    if( !mbedtls_ssl_conf_tls13_ephemeral_enabled( ssl ) )
        return( 0 );

    if( !ssl_client_hello_has_cert_extensions( ssl ) )
        return( 0 );

    ssl->handshake->tls13_kex_modes = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL;
    return( 1 );
}

static int ssl_client_hello_parse( mbedtls_ssl_context *ssl,
                                   const unsigned char *buf,
                                   const unsigned char *end )
{
    int ret;
    size_t i, j;
    size_t comp_len, sess_len;
    size_t cipher_suites_len;
    size_t ext_len;
    const unsigned char *ciph_offset;
    const unsigned char *p = buf;
    const unsigned char *extensions_end;

    const int* ciphersuites;
    const mbedtls_ssl_ciphersuite_t* ciphersuite_info;

    int hrr_required = 0;

    ssl->handshake->extensions_present = MBEDTLS_SSL_EXT_NONE;

    /*
     * ClientHello layer:
     *     0  .   1   protocol version
     *     2  .  33   random bytes ( starting with 4 bytes of Unix time )
     *    34  .  35   session id length ( 1 byte )
     *    35  . 34+x  session id
     *   35+x . 35+x  DTLS only: cookie length ( 1 byte )
     *   36+x .  ..   DTLS only: cookie
     *    ..  .  ..   ciphersuite list length ( 2 bytes )
     *    ..  .  ..   ciphersuite list
     *    ..  .  ..   compression alg. list length ( 1 byte )
     *    ..  .  ..   compression alg. list
     *    ..  .  ..   extensions length ( 2 bytes, optional )
     *    ..  .  ..   extensions ( optional )
     */

    /* TBD: Needs to be updated due to mandatory extensions
     * Minimal length ( with everything empty and extensions ommitted ) is
     * 2 + 32 + 1 + 2 + 1 = 38 bytes. Check that first, so that we can
     * read at least up to session id length without worrying.
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 38 );

    /* ...
     * ProtocolVersion legacy_version = 0x0303; // TLS 1.2
     * ...
     * with ProtocolVersion defined as:
     * uint16 ProtocolVersion;
     */
    if( !( p[0] == MBEDTLS_SSL_MAJOR_VERSION_3 &&
           p[1] == MBEDTLS_SSL_MINOR_VERSION_3 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported version of TLS." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                      MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
        ret = MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION;
        return ret;
    }
    p += 2;

    /*
     * Save client random
     */
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes", p, 32 );

    memcpy( &ssl->handshake->randbytes[0], p, 32 );
    p += 32; /* skip random bytes */

    /*
     * Parse session ID
     */
    sess_len = p[0];
    p++; /* skip session id length */

    if( sess_len > 32 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    ssl->session_negotiate->id_len = sess_len;

    /* Note that this field is echoed even if
     * the client's value corresponded to a cached pre-TLS 1.3 session
     * which the server has chosen not to resume. A client which
     * receives a legacy_session_id_echo field that does not match what
     * it sent in the ClientHello MUST abort the handshake with an
     * "illegal_parameter" alert.
     */
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, session id length ( %" MBEDTLS_PRINTF_SIZET " )", sess_len ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, session id", buf, sess_len );

    memcpy( &ssl->session_negotiate->id[0], p, sess_len ); /* write session id */
    p += sess_len;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    cipher_suites_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, cipher_suites_len );

    /* store pointer to ciphersuite list */
    ciph_offset = p;

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, ciphersuitelist",
                          p, cipher_suites_len );

    /* skip ciphersuites for now */
    p += cipher_suites_len;

    /*
     * For TLS 1.3 we are not using compression.
     */
    comp_len = buf[0];
    p++;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, comp_len );

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, compression",
                           p, comp_len );

    /* Determine whether we are indeed using null compression */
    if( ( comp_len != 1 ) && ( p[1] == 0 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    /* skip compression */
    p++;

    /*
     * Check the extension length
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );

    ext_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    extensions_end = p + ext_len;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, ext_len );

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello extensions", p, ext_len );

    while( p < extensions_end )
    {
        unsigned int extension_type;
        size_t extension_data_len;
        const unsigned char *extension_data_end;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 4 );
        extension_type = MBEDTLS_GET_UINT16_BE( p, 0 );
        extension_data_len = MBEDTLS_GET_UINT16_BE( p, 2 );
        p += 4;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, extension_data_len );
        extension_data_end = p + extension_data_len;

        switch( extension_type )
        {
#if defined(MBEDTLS_SSL_COOKIE_C)
            case MBEDTLS_TLS_EXT_COOKIE:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found cookie extension" ) );

                ret = ssl_tls13_parse_cookie_ext( ssl, p,
                                                  extension_data_end );

                /* if cookie verification failed then we return a hello retry
                 * message, or return success and set cookie extension present
                 */
                if( ret == MBEDTLS_ERR_SSL_HRR_REQUIRED )
                {
                    hrr_required = 1;
                }
                else if( ret == 0 )
                {
                    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_COOKIE;
                }
                break;
#endif /* MBEDTLS_SSL_COOKIE_C  */

#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C)
            case MBEDTLS_TLS_EXT_SUPPORTED_GROUPS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found supported group extension" ) );

                /* Supported Groups Extension
                 *
                 * When sent by the client, the "supported_groups" extension
                 * indicates the named groups which the client supports,
                 * ordered from most preferred to least preferred.
                 */
                ret = mbedtls_ssl_tls13_parse_supported_groups_ext( ssl, p,
                            extension_data_end );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1,
                                "mbedtls_ssl_parse_supported_groups_ext", ret );
                    return( ret );
                }

                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SUPPORTED_GROUPS;
                break;
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

#if ( defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C) )
            case MBEDTLS_TLS_EXT_KEY_SHARE:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found key share extension" ) );

                /*
                 * Key Share Extension
                 *
                 * When sent by the client, the "key_share" extension
                 * contains the endpoint's cryptographic parameters for
                 * ECDHE/DHE key establishment methods.
                 */
                ret = ssl_tls13_parse_key_shares_ext( ssl, p, extension_data_end );
                if( ret == MBEDTLS_ERR_SSL_HRR_REQUIRED )
                {
                    hrr_required = 1;
                    ret = 0;
                }

                if( ret != 0 )
                    return( ret );

                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_KEY_SHARE;
                break;
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

            case MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found supported versions extension" ) );

                ret = ssl_tls13_parse_supported_versions_ext(
                      ssl, p, extension_data_end );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1,
                                ( "ssl_tls13_parse_supported_versions_ext" ), ret );
                    return( ret );
                }
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SUPPORTED_VERSIONS;
                break;

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
            case MBEDTLS_TLS_EXT_SIG_ALG:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found signature_algorithms extension" ) );

                ret = mbedtls_ssl_tls13_parse_sig_alg_ext( ssl, p,
                                                           extension_data_end );
                if( ret != 0 )
                {
                    MBEDTLS_SSL_DEBUG_MSG( 1,
                    ( "ssl_parse_supported_signature_algorithms_server_ext ( %d )",
                      ret ) );
                    return( ret );
                }
                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SIG_ALG;
                break;
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

            default:
                MBEDTLS_SSL_DEBUG_MSG( 3,
                        ( "unknown extension found: %ud ( ignoring )",
                          extension_type ) );
        }

        p += extension_data_len;
    }

    /* Update checksum with either
     * - The entire content of the CH message, if no PSK extension is present
     * - The content up to but excluding the PSK extension, if present.
     */
    ssl->handshake->update_checksum( ssl, buf, p - buf );
    /*
     * Search for a matching ciphersuite
     */
    ciphersuites = ssl->conf->ciphersuite_list;
    ciphersuite_info = NULL;
    for ( j = 0, p = ciph_offset; j < cipher_suites_len; j += 2, p += 2 )
    {
        for ( i = 0; ciphersuites[i] != 0; i++ )
        {
            if( p[0] != ( ( ciphersuites[i] >> 8 ) & 0xFF ) ||
                p[1] != ( ( ciphersuites[i] ) & 0xFF ) )
                continue;

            ciphersuite_info = mbedtls_ssl_ciphersuite_from_id(
                               ciphersuites[i] );

            if( ciphersuite_info == NULL )
            {
                MBEDTLS_SSL_DEBUG_MSG(
                1,
                ( "mbedtls_ssl_ciphersuite_from_id: should never happen" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            goto have_ciphersuite;

        }
    }

    return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );

have_ciphersuite:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "selected ciphersuite: %s",
                                ciphersuite_info->name ) );

    ssl->session_negotiate->ciphersuite = ciphersuites[i];
    ssl->handshake->ciphersuite_info = ciphersuite_info;

    /* List all the extensions we have received */
    ssl_debug_print_client_hello_exts( ssl );

    /*
     * Determine the key exchange algorithm to use.
     * There are three types of key exchanges supported in TLS 1.3:
     * - (EC)DH with ECDSA,
     * - (EC)DH with PSK,
     * - plain PSK.
     *
     * The PSK-based key exchanges may additionally be used with 0-RTT.
     *
     * Our built-in order of preference is
     *  1 ) Plain PSK Mode
     *  2 ) (EC)DHE-PSK Mode
     *  3 ) Certificate Mode
     */

    if( !ssl_check_certificate_key_exchange( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG(
                1,
                ( "ClientHello message misses mandatory extensions." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_MISSING_EXTENSION ,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

#if defined(MBEDTLS_SSL_COOKIE_C)
    /* If we failed to see a cookie extension, and we required it through the
     * configuration settings ( rr_config ), then we need to send a HRR msg.
     * Conceptually, this is similiar to having received a cookie that failed
     * the verification check.
     */
    if( ( ssl->conf->rr_config == MBEDTLS_SSL_FORCE_RR_CHECK_ON ) &&
        !( ssl->handshake->extensions_present & MBEDTLS_SSL_EXT_COOKIE ) )
    {
        MBEDTLS_SSL_DEBUG_MSG(
                2,
                ( "Cookie extension missing. Need to send a HRR." ) );
        hrr_required = 1;
    }
#endif /* MBEDTLS_SSL_COOKIE_C */

    if( hrr_required == 1 )
        return( SSL_CLIENT_HELLO_HRR_REQUIRED );

    return( 0 );
}

static int ssl_client_hello_postprocess( mbedtls_ssl_context* ssl,
                                         int hrr_required )
{
    int ret = 0;

    if( ssl->handshake->hello_retry_request_count == 0 &&
        ssl->conf->rr_config == MBEDTLS_SSL_FORCE_RR_CHECK_ON )
    {
        hrr_required = SSL_CLIENT_HELLO_HRR_REQUIRED;
    }

    if( hrr_required == SSL_CLIENT_HELLO_HRR_REQUIRED )
    {
        /*
         * Create stateless transcript hash for HRR
         */
        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Reset transcript for HRR" ) );
        ret = mbedtls_ssl_reset_transcript_for_hrr( ssl );
        if( ret != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_reset_transcript_for_hrr",
                                   ret );
            return( ret );
        }
        mbedtls_ssl_session_reset_msg_layer( ssl, 0 );

        /* Transmit Hello Retry Request */
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HELLO_RETRY_REQUEST );
        return( 0 );
    }

    ret = mbedtls_ssl_tls13_key_schedule_stage_early( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
             "mbedtls_ssl_tls1_3_key_schedule_stage_early", ret );
        return( ret );
    }

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_HELLO );
    return( 0 );

}

/*
 * TLS and DTLS 1.3 State Maschine -- server side
 */
int mbedtls_ssl_tls13_handshake_server_step( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    if( ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER || ssl->handshake == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "tls13 server state: %s(%d)",
                                mbedtls_ssl_states_str( ssl->state ),
                                ssl->state ) );

    if( ( ret = mbedtls_ssl_flush_output( ssl ) ) != 0 )
        return( ret );

    switch( ssl->state )
    {
        /* start state */
        case MBEDTLS_SSL_HELLO_REQUEST:
            ssl->handshake->hello_retry_request_count = 0;
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );

            break;

            /* ----- READ CLIENT HELLO ----*/

        case MBEDTLS_SSL_CLIENT_HELLO:

            ret = ssl_client_hello_process( ssl );
            if( ret != 0 )
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_client_hello_process", ret );

            break;

        case MBEDTLS_SSL_HANDSHAKE_WRAPUP:
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "handshake: done" ) );

            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to application keys for all traffic" ) );

            mbedtls_ssl_set_inbound_transform ( ssl, ssl->transform_application );
            mbedtls_ssl_set_outbound_transform( ssl, ssl->transform_application );

            mbedtls_ssl_tls13_handshake_wrapup( ssl );
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET );

            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ret );
}

#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_PROTO_TLS1_3 */
