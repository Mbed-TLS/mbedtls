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

#include "ssl_misc.h"
#include "ssl_tls13_keys.h"
#include "ssl_debug_helpers.h"
#include <string.h>
#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif /* MBEDTLS_PLATFORM_C */

/* From RFC 8446:
 *   struct {
 *          ProtocolVersion versions<2..254>;
 *   } SupportedVersions;
 */
static int ssl_tls13_parse_supported_versions_ext( mbedtls_ssl_context *ssl,
                                                   const unsigned char *buf,
                                                   const unsigned char *end )
{
    size_t versions_len;
    int tls13_supported = 0;
    int major_ver, minor_ver;
    const unsigned char *p = buf;
    const unsigned char *versions_end;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 1 );
    versions_len = p[0];
    p += 1;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, versions_len );

    versions_end = p + versions_len;
    while( p < versions_end )
    {
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, versions_end, 2 );
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
        /* Here we only support TLS 1.3, we need report "bad protocol" if it
         * doesn't support TLS 1.2.
         */

        MBEDTLS_SSL_DEBUG_MSG( 1, ( "TLS 1.3 is not supported by the client" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                      MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
        return( MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
    }

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Negotiated version. Supported is [%d:%d]",
                              major_ver, minor_ver ) );

    ssl->major_ver = major_ver;
    ssl->minor_ver = minor_ver;
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
static int ssl_tls13_parse_supported_groups_ext(
                mbedtls_ssl_context *ssl,
                const unsigned char *buf, const unsigned char *end )
{

    size_t named_group_list_len, curve_list_len;
    const unsigned char *p = buf;
    const mbedtls_ecp_curve_info *curve_info, **curves;
    const unsigned char *extentions_end;

    MBEDTLS_SSL_DEBUG_BUF( 3, "supported_groups extension", p, end - buf );
    named_group_list_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, named_group_list_len );
    if( named_group_list_len % 2 != 0 )
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );

    /*       At the moment, this can happen when receiving a second
     *       ClientHello after an HRR. We should properly reset the
     *       state upon receiving an HRR, in which case we should
     *       not observe handshake->curves already being allocated. */
    if( ssl->handshake->curves != NULL )
    {
        mbedtls_free( ssl->handshake->curves );
        ssl->handshake->curves = NULL;
    }

    /* Don't allow our peer to make us allocate too much memory,
     * and leave room for a final 0
     */
    curve_list_len = named_group_list_len / 2 + 1;
    if( curve_list_len > MBEDTLS_ECP_DP_MAX )
        curve_list_len = MBEDTLS_ECP_DP_MAX;

    if( ( curves = mbedtls_calloc( curve_list_len, sizeof( *curves ) ) ) == NULL )
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );

    extentions_end = p + named_group_list_len;
    ssl->handshake->curves = curves;

    while ( p < extentions_end && curve_list_len > 1 )
    {
        uint16_t tls_grp_id = MBEDTLS_GET_UINT16_BE( p, 0 );
        curve_info = mbedtls_ecp_curve_info_from_tls_id( tls_grp_id );

        /* mbedtls_ecp_curve_info_from_tls_id() uses the mbedtls_ecp_curve_info
         * data structure (defined in ecp.c), which only includes the list of
         * curves implemented. Hence, we only add curves that are also supported
         * and implemented by the server.
         */
        if( curve_info != NULL )
        {
            *curves++ = curve_info;
            MBEDTLS_SSL_DEBUG_MSG( 4, ( "supported curve: %s", curve_info->name ) );
            curve_list_len--;
        }

        p += 2;
    }

    return( 0 );

}
#endif /* MBEDTLS_ECDH_C || ( MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_ECDH_C)
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

    size_t total_extensions_len, key_share_len;
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

    total_extensions_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, total_extensions_len );

    ssl->handshake->offered_group_id = 0;
    extentions_end = p + total_extensions_len;

    /* We try to find a suitable key share entry and copy it to the
     * handshake context. Later, we have to find out whether we can do
     * something with the provided key share or whether we have to
     * dismiss it and send a HelloRetryRequest message.
     */

    for( ; p < extentions_end; p += key_share_len )
    {
        uint16_t group;

        /*
         * struct {
         *    NamedGroup group;
         *    opaque key_exchange<1..2^16-1>;
         * } KeyShareEntry;
         */
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extentions_end, 4 );

        group = MBEDTLS_GET_UINT16_BE( p, 0 );
        p += 2;

        key_share_len = MBEDTLS_GET_UINT16_BE( p, 0 );
        p += 2;

        /* Continue parsing even if we have already found a match,
         * for input validation purposes.
         */
        if( match_found == 1 )
            continue;

        /*
         * NamedGroup matching
         *
         * For now, we only support ECDHE groups, but e.g.

         * Type 1: ECDHE shares
         *
         * - Check if we recognize the group
         * - Check if it's supported
         */

        if( mbedtls_ssl_tls13_named_group_is_ecdhe( group ) )
        {
            const mbedtls_ecp_curve_info *curve_info =
                mbedtls_ecp_curve_info_from_tls_id( group );
            if( curve_info == NULL )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "Invalid TLS curve group id" ) );
                return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
            }

            match_found = 1;

            MBEDTLS_SSL_DEBUG_MSG( 2, ( "ECDH curve: %s", curve_info->name ) );

            ret = mbedtls_ssl_tls13_read_public_ecdhe_share( ssl, p, end - p );
            if( ret != 0 )
                return( ret );
        }
        else
        {
            MBEDTLS_SSL_DEBUG_MSG( 4, ( "Unrecognized NamedGroup %u",
                                        (unsigned) group ) );
            continue;
        }

        ssl->handshake->offered_group_id = group;
    }

    if( match_found == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no matching key share" ) );
        return( MBEDTLS_ERR_SSL_HRR_REQUIRED );
    }
    return( 0 );
}
#endif /* MBEDTLS_ECDH_C */

#if defined(MBEDTLS_SSL_DEBUG_C)
static void ssl_tls13_debug_print_client_hello_exts( mbedtls_ssl_context *ssl )
{
    ((void) ssl);

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
}
#endif /* MBEDTLS_SSL_DEBUG_C */

static int ssl_tls13_client_hello_has_exts( mbedtls_ssl_context *ssl,
                                      int ext_id_mask )
{
    int masked = ssl->handshake->extensions_present & ext_id_mask;
    return( masked == ext_id_mask );
}

static int ssl_tls13_client_hello_has_cert_extensions( mbedtls_ssl_context *ssl )
{
    return( ssl_tls13_client_hello_has_exts( ssl,
                          MBEDTLS_SSL_EXT_SUPPORTED_GROUPS |
                          MBEDTLS_SSL_EXT_KEY_SHARE        |
                          MBEDTLS_SSL_EXT_SIG_ALG ) );
}

static int ssl_tls13_check_certificate_key_exchange( mbedtls_ssl_context *ssl )
{
    if( !mbedtls_ssl_conf_tls13_ephemeral_enabled( ssl ) )
        return( 0 );

    if( !ssl_tls13_client_hello_has_cert_extensions( ssl ) )
        return( 0 );

    ssl->handshake->tls13_kex_modes = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL;
    return( 1 );
}

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
 * Structure of this message:
 *
 *       uint16 ProtocolVersion;
 *       opaque Random[32];
 *
 *       uint8 CipherSuite[2];    // Cryptographic suite selector
 *
 *       struct {
 *           ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *           Random random;
 *           opaque legacy_session_id<0..32>;
 *           CipherSuite cipher_suites<2..2^16-2>;
 *           opaque legacy_compression_methods<1..2^8-1>;
 *           Extension extensions<8..2^16-1>;
 *       } ClientHello;
 */

#define SSL_CLIENT_HELLO_OK           0
#define SSL_CLIENT_HELLO_HRR_REQUIRED 1

static int ssl_tls13_parse_client_hello( mbedtls_ssl_context *ssl,
                                         const unsigned char *buf,
                                         const unsigned char *end )
{
    int ret;
    size_t i, j;
    size_t legacy_session_id_len;
    size_t cipher_suites_len;
    size_t extensions_len;
    const unsigned char *cipher_suites_start;
    const unsigned char *p = buf;
    const unsigned char *extensions_end;

    const int* cipher_suites;
    const mbedtls_ssl_ciphersuite_t* ciphersuite_info;

    int hrr_required = 0;

    ssl->handshake->extensions_present = MBEDTLS_SSL_EXT_NONE;

    /*
     * ClientHello layer:
     *     0  .   1   protocol version
     *     2  .  33   random bytes ( starting with 4 bytes of Unix time )
     *    34  .  34   session id length ( 1 byte )
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

    /* Needs to be updated due to mandatory extensions
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
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes",
                           p, MBEDTLS_SERVER_HELLO_RANDOM_LEN );

    memcpy( &ssl->handshake->randbytes[0], p, MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    p += MBEDTLS_SERVER_HELLO_RANDOM_LEN;

    /*
     * Parse session ID
     */
    legacy_session_id_len = p[0];
    p++;

    if( legacy_session_id_len > 32 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad client hello message" ) );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    ssl->session_negotiate->id_len = legacy_session_id_len;

    /* Note that this field is echoed even if
     * the client's value corresponded to a cached pre-TLS 1.3 session
     * which the server has chosen not to resume. A client which
     * receives a legacy_session_id_echo field that does not match what
     * it sent in the ClientHello MUST abort the handshake with an
     * "illegal_parameter" alert.
     */
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, session id",
                           buf, legacy_session_id_len );

    memcpy( &ssl->session_negotiate->id[0], p, legacy_session_id_len );
    p += legacy_session_id_len;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    cipher_suites_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, cipher_suites_len );

    /* store pointer to ciphersuite list */
    cipher_suites_start = p;

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, ciphersuitelist",
                          p, cipher_suites_len );

    /* skip cipher_suites for now */
    p += cipher_suites_len;

    /* ...
     * uint8 legacy_compression_method = 0;
     * ...
     */
    p += 1;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 1 );
    if( p[0] != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad legacy compression method" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return ( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }
    p++;

    /*
     * Check the extensions length
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    extensions_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    extensions_end = p + extensions_len;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, extensions_len );

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello extensions", p, extensions_len );

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
#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C)
            case MBEDTLS_TLS_EXT_SUPPORTED_GROUPS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found supported group extension" ) );

                /* Supported Groups Extension
                 *
                 * When sent by the client, the "supported_groups" extension
                 * indicates the named groups which the client supports,
                 * ordered from most preferred to least preferred.
                 */
                ret = ssl_tls13_parse_supported_groups_ext( ssl, p,
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

#if defined(MBEDTLS_ECDH_C)
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
                    MBEDTLS_SSL_DEBUG_MSG( 2, ( "HRR needed " ) );
                    ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
                }

                if( ret != 0 )
                    return( ret );

                ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_KEY_SHARE;
                break;
#endif /* MBEDTLS_ECDH_C */

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
    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_SERVER_HELLO,
                                        buf, p - buf );
    /*
     * Search for a matching ciphersuite
     */
    cipher_suites = ssl->conf->ciphersuite_list;
    ciphersuite_info = NULL;
    for ( j = 0, p = cipher_suites_start; j < cipher_suites_len; j += 2, p += 2 )
    {
        for ( i = 0; cipher_suites[i] != 0; i++ )
        {
            if( MBEDTLS_GET_UINT16_BE(p, 0) != cipher_suites[i] )
                continue;

            ciphersuite_info = mbedtls_ssl_ciphersuite_from_id(
                               cipher_suites[i] );

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

    ssl->session_negotiate->ciphersuite = cipher_suites[i];
    ssl->handshake->ciphersuite_info = ciphersuite_info;

    /* List all the extensions we have received */
#if defined(MBEDTLS_SSL_DEBUG_C)
    ssl_tls13_debug_print_client_hello_exts( ssl );
#endif /* MBEDTLS_SSL_DEBUG_C */

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

    if( !ssl_tls13_check_certificate_key_exchange( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG(
                1,
                ( "ClientHello message misses mandatory extensions." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_MISSING_EXTENSION ,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    if( hrr_required == 1 )
        return( SSL_CLIENT_HELLO_HRR_REQUIRED );

    return( 0 );
}

/* Update the handshake state machine */

static int ssl_tls13_postprocess_client_hello( mbedtls_ssl_context* ssl )
{
    int ret = 0;

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
 * Main entry point from the state machine; orchestrates the otherfunctions.
 */

static int ssl_tls13_process_client_hello( mbedtls_ssl_context *ssl )
{

    int ret = 0;
    unsigned char* buf = NULL;
    size_t buflen = 0;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse client hello" ) );

    ssl->major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_fetch_handshake_msg(
                          ssl, MBEDTLS_SSL_HS_CLIENT_HELLO,
                          &buf, &buflen ) );

    MBEDTLS_SSL_PROC_CHK_NEG( ssl_tls13_parse_client_hello( ssl, buf,
                                                            buf + buflen ) );
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "postprocess" ) );
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_postprocess_client_hello( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse client hello" ) );
    return( ret );
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

    switch( ssl->state )
    {
        /* start state */
        case MBEDTLS_SSL_HELLO_REQUEST:
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_HELLO );

            break;

            /* ----- READ CLIENT HELLO ----*/

        case MBEDTLS_SSL_CLIENT_HELLO:

            ret = ssl_tls13_process_client_hello( ssl );
            if( ret != 0 )
                MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_process_client_hello", ret );

            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ret );
}

#endif /* MBEDTLS_SSL_SRV_C && MBEDTLS_SSL_PROTO_TLS1_3 */
