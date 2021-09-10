/*
 *  TLS 1.3 client-side functions
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

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#if defined(MBEDTLS_SSL_CLI_C)

#include <string.h>

#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"

#include "ssl_misc.h"
#include "ecdh_misc.h"
#include "ssl_tls13_keys.h"

#define CLIENT_HELLO_RANDOM_LEN 32
#define SERVER_HELLO_RANDOM_LEN 32

/* Write extensions */

/*
 * ssl_tls13_write_supported_versions_ext():
 *
 * struct {
 *      ProtocolVersion versions<2..254>;
 * } SupportedVersions;
 */
static int ssl_tls13_write_supported_versions_ext( mbedtls_ssl_context *ssl,
                                                   unsigned char *buf,
                                                   unsigned char *end,
                                                   size_t *olen )
{
    unsigned char *p = buf;

    *olen = 0;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding supported versions extension" ) );

    /* Check if we have space to write the extension:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - versions_length        (1 byte )
     * - versions               (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 7 );

    /* Write extension_type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS, p, 0 );

    /* Write extension_data_length */
    MBEDTLS_PUT_UINT16_BE( 3, p, 2 );
    p += 4;

    /* Length of versions */
    *p++ = 0x2;

    /* Write values of supported versions.
     *
     * They are defined by the configuration.
     *
     * Currently, only one version is advertised.
     */
    mbedtls_ssl_write_version( ssl->conf->max_major_ver,
                               ssl->conf->max_minor_ver,
                               ssl->conf->transport, p );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "supported version: [%d:%d]",
                                ssl->conf->max_major_ver,
                                ssl->conf->max_minor_ver ) );

    *olen = 7;

    return( 0 );
}

static int ssl_tls1_3_parse_supported_versions_ext( mbedtls_ssl_context *ssl,
                                                    const unsigned char *buf,
                                                    size_t len )
{
    /* TODO: Implement full version and remove force version set in
     *       ssl_tls_parse_server_hello.
     *
     * From page 40,RFC 8446
     *  If supported_versions extension is present, clients MUST ignore the
     *  ServerHello.legacy_version value and MUST use only the
     *  "supported_versions" extension to determine the selected version.  If
     *  the "supported_versions" extension in the ServerHello contains a
     *  version not offered by the client or contains a version prior to
     *  TLS 1.3, the client MUST abort the handshake with an
     *  "illegal_parameter" alert.
     */

    ((void) ssl);

    if( len != 2 ||
        buf[0] != MBEDTLS_SSL_MAJOR_VERSION_3 ||
        buf[1] != MBEDTLS_SSL_MINOR_VERSION_4 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "unexpected version" ) );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    return( 0 );
}

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)

/*
 * Functions for writing supported_groups extension.
 *
 * Stucture of supported_groups:
 *      enum {
 *          secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
 *          x25519(0x001D), x448(0x001E),
 *          ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
 *          ffdhe6144(0x0103), ffdhe8192(0x0104),
 *          ffdhe_private_use(0x01FC..0x01FF),
 *          ecdhe_private_use(0xFE00..0xFEFF),
 *          (0xFFFF)
 *      } NamedGroup;
 *      struct {
 *          NamedGroup named_group_list<2..2^16-1>;
 *      } NamedGroupList;
 */
#if defined(MBEDTLS_ECDH_C)
/*
 * In versions of TLS prior to TLS 1.3, this extension was named
 * 'elliptic_curves' and only contained elliptic curve groups.
 */
static int ssl_tls13_write_named_group_list_ecdhe( mbedtls_ssl_context *ssl,
                                            unsigned char *buf,
                                            unsigned char *end,
                                            size_t *olen )
{
    unsigned char *p = buf;

    *olen = 0;

    if( ssl->conf->curve_list == NULL )
        return( MBEDTLS_ERR_SSL_BAD_CONFIG );

    for ( const mbedtls_ecp_group_id *grp_id = ssl->conf->curve_list;
          *grp_id != MBEDTLS_ECP_DP_NONE;
          grp_id++ )
    {
        const mbedtls_ecp_curve_info *info;
        info = mbedtls_ecp_curve_info_from_grp_id( *grp_id );
        if( info == NULL )
            continue;

        if( !mbedtls_ssl_tls13_named_group_is_ecdhe( info->tls_id ) )
            continue;

        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2);
        MBEDTLS_PUT_UINT16_BE( info->tls_id, p, 0 );
        p += 2;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "NamedGroup: %s ( %x )",
                  mbedtls_ecp_curve_info_from_tls_id( info->tls_id )->name,
                  info->tls_id ) );
    }

    *olen = p - buf;

    return( 0 );
}
#else
static int ssl_tls13_write_named_group_list_ecdhe( mbedtls_ssl_context *ssl,
                                            unsigned char *buf,
                                            unsigned char *end,
                                            size_t *olen )
{
    ((void) ssl);
    ((void) buf);
    ((void) end);
    *olen = 0;
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}
#endif /* MBEDTLS_ECDH_C */

static int ssl_tls13_write_named_group_list_dhe( mbedtls_ssl_context *ssl,
                                        unsigned char *buf,
                                        unsigned char *end,
                                        size_t *olen )
{
    ((void) ssl);
    ((void) buf);
    ((void) end);
    *olen = 0;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "write_named_group_dhe is not implemented" ) );
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}

static int ssl_tls13_write_supported_groups_ext( mbedtls_ssl_context *ssl,
                                                 unsigned char *buf,
                                                 unsigned char *end,
                                                 size_t *olen )
{
    unsigned char *p = buf ;
    unsigned char *named_group_list_ptr; /* Start of named_group_list */
    size_t named_group_list_len;         /* Length of named_group_list */
    size_t output_len = 0;
    int ret_ecdhe, ret_dhe;

    *olen = 0;

    if( !mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
        return( 0 );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding supported_groups extension" ) );

    /* Check if we have space for header and length fields:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - named_group_list_length   (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );
    p += 6;

    named_group_list_ptr = p;
    ret_ecdhe = ssl_tls13_write_named_group_list_ecdhe( ssl, p, end, &output_len );
    if( ret_ecdhe != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_named_group_list_ecdhe", ret_ecdhe );
    }
    p += output_len;

    ret_dhe = ssl_tls13_write_named_group_list_dhe( ssl, p, end, &output_len );
    if( ret_dhe != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_named_group_list_dhe", ret_dhe );
    }
    p += output_len;

    /* Both ECDHE and DHE failed. */
    if( ret_ecdhe != 0 && ret_dhe != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Both ECDHE and DHE groups are fail. " ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Length of named_group_list*/
    named_group_list_len = p - named_group_list_ptr;
    if( named_group_list_len == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "No group available." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Write extension_type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SUPPORTED_GROUPS, buf, 0 );
    /* Write extension_data_length */
    MBEDTLS_PUT_UINT16_BE( named_group_list_len + 2, buf, 2 );
    /* Write length of named_group_list */
    MBEDTLS_PUT_UINT16_BE( named_group_list_len, buf, 4 );

    MBEDTLS_SSL_DEBUG_BUF( 3, "Supported groups extension", buf + 4, named_group_list_len + 2 );

    *olen = p - buf;

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SUPPORTED_GROUPS;

    return( 0 );
}

/*
 * Functions for writing key_share extension.
 */
#if defined(MBEDTLS_ECDH_C)
static int ssl_tls13_generate_and_write_ecdh_key_exchange(
                mbedtls_ssl_context *ssl,
                uint16_t named_group,
                unsigned char *buf,
                unsigned char *end,
                size_t *olen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_ecp_curve_info *curve_info =
        mbedtls_ecp_curve_info_from_tls_id( named_group );

    if( curve_info == NULL )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "offer curve %s", curve_info->name ) );

    if( ( ret = mbedtls_ecdh_setup_no_everest( &ssl->handshake->ecdh_ctx,
                                               curve_info->grp_id ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_setup_no_everest", ret );
        return( ret );
    }

    ret = mbedtls_ecdh_tls13_make_params( &ssl->handshake->ecdh_ctx, olen,
                                           buf, end - buf,
                                           ssl->conf->f_rng, ssl->conf->p_rng );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecdh_tls13_make_params", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_ECDH( 3, &ssl->handshake->ecdh_ctx,
                            MBEDTLS_DEBUG_ECDH_Q );
    return( 0 );
}
#endif /* MBEDTLS_ECDH_C */

static int ssl_tls13_get_default_group_id( mbedtls_ssl_context *ssl,
                                           uint16_t *group_id )
{
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;


#if defined(MBEDTLS_ECDH_C)
    /* Pick first available ECDHE group compatible with TLS 1.3 */
    if( ssl->conf->curve_list == NULL )
        return( MBEDTLS_ERR_SSL_BAD_CONFIG );

    for ( const mbedtls_ecp_group_id *grp_id = ssl->conf->curve_list;
          *grp_id != MBEDTLS_ECP_DP_NONE;
          grp_id++ )
    {
        const mbedtls_ecp_curve_info *info;
        info = mbedtls_ecp_curve_info_from_grp_id( *grp_id );
        if( info != NULL &&
            mbedtls_ssl_tls13_named_group_is_ecdhe( info->tls_id ) )
        {
            *group_id = info->tls_id;
            return( 0 );
        }
    }
#else
    ((void) ssl);
    ((void) group_id);
#endif /* MBEDTLS_ECDH_C */

    /*
     * Add DHE named groups here.
     * Pick first available DHE group compatible with TLS 1.3
     */

    return( ret );
}

/*
 * ssl_tls13_write_key_share_ext
 *
 * Structure of key_share extension in ClientHello:
 *
 *  struct {
 *          NamedGroup group;
 *          opaque key_exchange<1..2^16-1>;
 *      } KeyShareEntry;
 *  struct {
 *          KeyShareEntry client_shares<0..2^16-1>;
 *      } KeyShareClientHello;
 */
static int ssl_tls13_write_key_share_ext( mbedtls_ssl_context *ssl,
                                          unsigned char *buf,
                                          unsigned char *end,
                                          size_t *olen )
{
    unsigned char *p = buf;
    unsigned char *client_shares_ptr; /* Start of client_shares */
    size_t client_shares_len;         /* Length of client_shares */
    uint16_t group_id;
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;

    *olen = 0;

    if( !mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
        return( 0 );

    /* Check if we have space for header and length fields:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - client_shares_length   (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );
    p += 6;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello: adding key share extension" ) );

    /* HRR could already have requested something else. */
    group_id = ssl->handshake->offered_group_id;
    if( !mbedtls_ssl_tls13_named_group_is_ecdhe( group_id ) &&
        !mbedtls_ssl_tls13_named_group_is_dhe( group_id ) )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_get_default_group_id( ssl,
                                                              &group_id ) );
    }

    /*
     * Dispatch to type-specific key generation function.
     *
     * So far, we're only supporting ECDHE. With the introduction
     * of PQC KEMs, we'll want to have multiple branches, one per
     * type of KEM, and dispatch to the corresponding crypto. And
     * only one key share entry is allowed.
     */
    client_shares_ptr = p;
#if defined(MBEDTLS_ECDH_C)
    if( mbedtls_ssl_tls13_named_group_is_ecdhe( group_id ) )
    {
        /* Pointer to group */
        unsigned char *group_ptr = p;
        /* Length of key_exchange */
        size_t key_exchange_len;

        /* Check there is space for header of KeyShareEntry
         * - group                  (2 bytes)
         * - key_exchange_length    (2 bytes)
         */
        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 4 );
        p += 4;
        ret = ssl_tls13_generate_and_write_ecdh_key_exchange( ssl, group_id,
                                                              p, end,
                                                              &key_exchange_len );
        p += key_exchange_len;
        if( ret != 0 )
            return( ret );

        /* Write group */
        MBEDTLS_PUT_UINT16_BE( group_id, group_ptr, 0 );
        /* Write key_exchange_length */
        MBEDTLS_PUT_UINT16_BE( key_exchange_len, group_ptr, 2 );
    }
    else
#endif /* MBEDTLS_ECDH_C */
    if( 0 /* other KEMs? */ )
    {
        /* Do something */
    }
    else
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /* Length of client_shares */
    client_shares_len = p - client_shares_ptr;
    if( client_shares_len == 0)
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "No key share defined." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }
    /* Write extension_type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_KEY_SHARE, buf, 0 );
    /* Write extension_data_length */
    MBEDTLS_PUT_UINT16_BE( client_shares_len + 2, buf, 2 );
    /* Write client_shares_length */
    MBEDTLS_PUT_UINT16_BE( client_shares_len, buf, 4 );

    /* Update offered_group_id field */
    ssl->handshake->offered_group_id = group_id;

    /* Output the total length of key_share extension. */
    *olen = p - buf;

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, key_share extension", buf, *olen );

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_KEY_SHARE;

cleanup:

    return( ret );
}

#if defined(MBEDTLS_ECDH_C)

/* TODO: Code for MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED missing */
static int ssl_tls1_3_check_ecdh_params( const mbedtls_ssl_context *ssl )
{
    const mbedtls_ecp_curve_info *curve_info;
    mbedtls_ecp_group_id grp_id;
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    grp_id = ssl->handshake->ecdh_ctx.grp.id;
#else
    grp_id = ssl->handshake->ecdh_ctx.grp_id;
#endif

    curve_info = mbedtls_ecp_curve_info_from_grp_id( grp_id );
    if( curve_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "ECDH curve: %s", curve_info->name ) );

#if defined(MBEDTLS_ECP_C)
    if( mbedtls_ssl_check_curve( ssl, grp_id ) != 0 )
#else
    if( ssl->handshake->ecdh_ctx.grp.nbits < 163 ||
            ssl->handshake->ecdh_ctx.grp.nbits > 521 )
#endif
            return( -1 );

    MBEDTLS_SSL_DEBUG_ECDH( 3, &ssl->handshake->ecdh_ctx,
                            MBEDTLS_DEBUG_ECDH_QP );

    return( 0 );
}

/* The ssl_tls1_3_parse_key_share_ext() function is used
 *  by the client to parse a KeyShare extension in
 *  a ServerHello message.
 *
 *  The server only provides a single KeyShareEntry.
 */
static int ssl_tls1_3_read_public_ecdhe_share( mbedtls_ssl_context *ssl,
                                               const unsigned char *buf,
                                               size_t len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_ecdh_tls1_3_read_public( &ssl->handshake->ecdh_ctx,
                                          buf, len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "mbedtls_ecdh_tls13_read_public" ), ret );
        return( ret );
    }

    if( ssl_tls1_3_check_ecdh_params( ssl ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ssl_tls1_3_check_ecdh_params() failed!" ) );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    return( 0 );
}
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

/*
 * Parse key_share extension in Server Hello
 * struct {
 *        KeyShareEntry server_share;
 * } KeyShareServerHello;
 * struct {
 *        NamedGroup group;
 *        opaque key_exchange<1..2^16-1>;
 * } KeyShareEntry;
 */
static int ssl_tls1_3_parse_key_share_ext( mbedtls_ssl_context *ssl,
                                          const unsigned char *buf,
                                          const unsigned char *end )
{
    int ret = 0;
    const unsigned char *p = buf;
    uint16_t server_share_group, offered_group;

    /* server_share_group (2 bytes) */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2);
    server_share_group = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    /* Check that chosen group matches the one we offered. */
    offered_group = ssl->handshake->offered_group_id;
    if( offered_group != server_share_group )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
            ( "Invalid server key share, our group %u, their group %u",
              (unsigned) offered_group, (unsigned) server_share_group ) );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

#if defined(MBEDTLS_ECDH_C)
    if( mbedtls_ssl_tls13_named_group_is_ecdhe( server_share_group ) )
    {
        /* Complete ECDHE key agreement */
        ret = ssl_tls1_3_read_public_ecdhe_share( ssl, p, end - p );
        if( ret != 0 )
            return( ret );
    }
#endif /* MBEDTLS_ECDH_C */
    else if( 0 /* other KEMs? */ )
    {
        /* Do something */
    }
    else
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_KEY_SHARE;
    return( ret );
}

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/* Write cipher_suites
 * CipherSuite cipher_suites<2..2^16-2>;
 */
static int ssl_tls13_write_client_hello_cipher_suites(
            mbedtls_ssl_context *ssl,
            unsigned char *buf,
            unsigned char *end,
            size_t *olen )
{
    unsigned char *p = buf;
    const int *ciphersuite_list;
    unsigned char *cipher_suites_ptr; /* Start of the cipher_suites list */
    size_t cipher_suites_len;

    *olen = 0 ;

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
    cipher_suites_ptr = p;
    for ( size_t i = 0; ciphersuite_list[i] != 0; i++ )
    {
        int cipher_suite = ciphersuite_list[i];
        const mbedtls_ssl_ciphersuite_t *ciphersuite_info;

        ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( cipher_suite );
        if( ciphersuite_info == NULL )
            continue;
        if( !( MBEDTLS_SSL_MINOR_VERSION_4 >= ciphersuite_info->min_minor_ver &&
               MBEDTLS_SSL_MINOR_VERSION_4 <= ciphersuite_info->max_minor_ver ) )
            continue;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, add ciphersuite: %04x, %s",
                                    (unsigned int) cipher_suite,
                                    ciphersuite_info->name ) );

        /* Check there is space for the cipher suite identifier (2 bytes). */
        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
        MBEDTLS_PUT_UINT16_BE( cipher_suite, p, 0 );
        p += 2;
    }

    /* Write the cipher_suites length in number of bytes */
    cipher_suites_len = p - cipher_suites_ptr;
    MBEDTLS_PUT_UINT16_BE( cipher_suites_len, buf, 0 );
    MBEDTLS_SSL_DEBUG_MSG( 3,
                           ( "client hello, got %" MBEDTLS_PRINTF_SIZET " cipher suites",
                             cipher_suites_len/2 ) );

    /* Output the total length of cipher_suites field. */
    *olen = p - buf;

    return( 0 );
}

/*
 * Structure of ClientHello message:
 *
 *    struct {
 *        ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
 *        Random random;
 *        opaque legacy_session_id<0..32>;
 *        CipherSuite cipher_suites<2..2^16-2>;
 *        opaque legacy_compression_methods<1..2^8-1>;
 *        Extension extensions<8..2^16-1>;
 *    } ClientHello;
 */
static int ssl_tls13_write_client_hello_body( mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              unsigned char *end,
                                              size_t *olen )
{

    int ret;
    unsigned char *extensions_len_ptr; /* Pointer to extensions length */
    size_t output_len;                 /* Length of buffer used by function */
    size_t extensions_len;             /* Length of the list of extensions*/

    /* Buffer management */
    unsigned char *p = buf;

    *olen = 0;

    /* No validation needed here. It has been done by ssl_conf_check() */
    ssl->major_ver = ssl->conf->min_major_ver;
    ssl->minor_ver = ssl->conf->min_minor_ver;

    /*
     * Write legacy_version
     *    ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
     *
     *  For TLS 1.3 we use the legacy version number {0x03, 0x03}
     *  instead of the true version number.
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    MBEDTLS_PUT_UINT16_BE( 0x0303, p, 0 );
    p += 2;

    /* Write the random bytes ( random ).*/
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, CLIENT_HELLO_RANDOM_LEN );
    memcpy( p, ssl->handshake->randbytes, CLIENT_HELLO_RANDOM_LEN );
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes",
                           p, CLIENT_HELLO_RANDOM_LEN );
    p += CLIENT_HELLO_RANDOM_LEN;

    /*
     * Write legacy_session_id
     *
     * Versions of TLS before TLS 1.3 supported a "session resumption" feature
     * which has been merged with pre-shared keys in this version. A client
     * which has a cached session ID set by a pre-TLS 1.3 server SHOULD set
     * this field to that value. In compatibility mode, this field MUST be
     * non-empty, so a client not offering a pre-TLS 1.3 session MUST generate
     * a new 32-byte value. This value need not be random but SHOULD be
     * unpredictable to avoid implementations fixating on a specific value
     * ( also known as ossification ). Otherwise, it MUST be set as a zero-length
     * vector ( i.e., a zero-valued single byte length field ).
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 1 );
    *p++ = 0; /* session id length set to zero */

    /* Write cipher_suites */
    ret = ssl_tls13_write_client_hello_cipher_suites( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;

    /* Write legacy_compression_methods
     *
     * For every TLS 1.3 ClientHello, this vector MUST contain exactly
     * one byte set to zero, which corresponds to the 'null' compression
     * method in prior versions of TLS.
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    *p++ = 1;
    *p++ = MBEDTLS_SSL_COMPRESS_NULL;

    /* Write extensions */

    /* Keeping track of the included extensions */
    ssl->handshake->extensions_present = MBEDTLS_SSL_EXT_NONE;

    /* First write extensions, then the total length */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    extensions_len_ptr = p;
    p += 2;

    /* Write supported_versions extension
     *
     * Supported Versions Extension is mandatory with TLS 1.3.
     */
    ret = ssl_tls13_write_supported_versions_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    /* Write supported_groups extension
     *
     * It is REQUIRED for ECDHE cipher_suites.
     */
    ret = ssl_tls13_write_supported_groups_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;

    /* Write key_share extension
     *
     * We need to send the key shares under three conditions:
     * 1) A certificate-based ciphersuite is being offered. In this case
     *    supported_groups and supported_signature extensions have been
     *    successfully added.
     * 2) A PSK-based ciphersuite with ECDHE is offered. In this case the
     *    psk_key_exchange_modes has been added as the last extension.
     * 3) Or, in case all ciphers are supported ( which includes #1 and #2
     *    from above )
     */
    ret = ssl_tls13_write_key_share_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;

    /* Write signature_algorithms extension
     *
     * It is REQUIRED for certificate authenticated cipher_suites.
     */
    ret = mbedtls_ssl_tls13_write_sig_alg_ext( ssl, p, end, &output_len );
    if( ret != 0 )
        return( ret );
    p += output_len;

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

    /* Add more extensions here */

    /* Write the length of the list of extensions. */
    extensions_len = p - extensions_len_ptr - 2;
    MBEDTLS_PUT_UINT16_BE( extensions_len, extensions_len_ptr, 0 );
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, total extension length: %" MBEDTLS_PRINTF_SIZET ,
                                extensions_len ) );
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello extensions", extensions_len_ptr, extensions_len );

    *olen = p - buf;
    return( 0 );
}

static int ssl_tls13_finalize_client_hello( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_HELLO );
    return( 0 );
}

static int ssl_tls13_prepare_client_hello( mbedtls_ssl_context *ssl )
{
    int ret;

    if( ssl->conf->f_rng == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "no RNG provided" ) );
        return( MBEDTLS_ERR_SSL_NO_RNG );
    }

    if( ( ret = ssl->conf->f_rng( ssl->conf->p_rng,
                                  ssl->handshake->randbytes,
                                  CLIENT_HELLO_RANDOM_LEN ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "f_rng", ret );
        return( ret );
    }

    return( 0 );
}

/*
 * Write ClientHello handshake message.
 * Handler for MBEDTLS_SSL_CLIENT_HELLO
 */
static int ssl_tls13_write_client_hello( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write client hello" ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_prepare_client_hello( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_start_handshake_msg(
                                ssl, MBEDTLS_SSL_HS_CLIENT_HELLO,
                                &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_client_hello_body( ssl, buf,
                                                             buf + buf_len,
                                                             &msg_len ) );

    mbedtls_ssl_tls13_add_hs_hdr_to_checksum( ssl,
                                              MBEDTLS_SSL_HS_CLIENT_HELLO,
                                              msg_len );
    ssl->handshake->update_checksum( ssl, buf, msg_len );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_finalize_client_hello( ssl ) );
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_finish_handshake_msg( ssl,
                                                                  buf_len,
                                                                  msg_len ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write client hello" ) );
    return ret;
}

/*
 * Functions for parsing and processing ServerHello
 */
static int ssl_server_hello_is_hrr( unsigned const char *buf )
{
    const unsigned char magic_hrr_string[32] =
        { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
          0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
          0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
          0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33 ,0x9C };

    /* Check whether this message is a HelloRetryRequest ( HRR ) message.
     *
     * ServerHello and HRR are only distinguished by Random set to the
     * special value of the SHA-256 of "HelloRetryRequest".
     *
     * struct {
     *    ProtocolVersion legacy_version = 0x0303;
     *    Random random;
     *    opaque legacy_session_id_echo<0..32>;
     *    CipherSuite cipher_suite;
     *    uint8 legacy_compression_method = 0;
     *    Extension extensions<6..2 ^ 16 - 1>;
     * } ServerHello;
     *
     */
    if( memcmp( buf + 2, magic_hrr_string,
                sizeof( magic_hrr_string ) ) == 0 )
    {
        return( 1 );
    }

    return( 0 );
}

/* Fetch and preprocess
 * Returns a negative value on failure, and otherwise
 * - SSL_SERVER_HELLO_COORDINATE_HELLO or
 * - SSL_SERVER_HELLO_COORDINATE_HRR
 * to indicate which message is expected and to be parsed next. */
#define SSL_SERVER_HELLO_COORDINATE_HELLO  0
#define SSL_SERVER_HELLO_COORDINATE_HRR 1
static int ssl_server_hello_coordinate( mbedtls_ssl_context *ssl,
                                        unsigned char **buf,
                                        size_t *buf_len )
{
    int ret;

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_read_record( ssl, 0 ) );

    /* TBD: If we do an HRR, keep track of the number
     * of ClientHello's we sent, and fail if it
     * exceeds the configured threshold. */

    if( ( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE ) ||
        ( ssl->in_msg[0] != MBEDTLS_SSL_HS_SERVER_HELLO ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "unexpected message" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                      MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    *buf = ssl->in_msg + 4;
    *buf_len = ssl->in_hslen - 4;

    if( ssl_server_hello_is_hrr( ssl->in_msg + 4 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "received HelloRetryRequest message" ) );
        ret = SSL_SERVER_HELLO_COORDINATE_HRR;
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "received ServerHello message" ) );
        ret = SSL_SERVER_HELLO_COORDINATE_HELLO;
    }

cleanup:

    return( ret );
}

static int ssl_tls1_3_check_server_hello_session_id( mbedtls_ssl_context *ssl,
                                                    const unsigned char **buf,
                                                    const unsigned char *end )
{
    const unsigned char *p = *buf;
    size_t recv_id_len;

    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 1 );
    recv_id_len = *p++ ;

    MBEDTLS_SSL_CHK_BUF_PTR( p, end, recv_id_len );

    /* legacy_session_id_echo */
    if( ssl->session_negotiate->id_len != recv_id_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Mismatch of session id length:"
            " id_len = %" MBEDTLS_PRINTF_SIZET
            " , recv_id_len = %" MBEDTLS_PRINTF_SIZET,
            ssl->session_negotiate->id_len, recv_id_len ) );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    if( memcmp( ssl->session_negotiate->id, p , recv_id_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unexpected legacy_session_id_echo" ) );
        MBEDTLS_SSL_DEBUG_BUF( 3, "Expected Session ID",
                               ssl->session_negotiate->id,
                               ssl->session_negotiate->id_len );
        MBEDTLS_SSL_DEBUG_BUF( 3, "Received Session ID", p,
                               ssl->session_negotiate->id_len );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    p += recv_id_len;
    *buf = p;

    MBEDTLS_SSL_DEBUG_BUF( 3, "Session ID", ssl->session_negotiate->id,
                            recv_id_len );
    return( 0 );
}

static int ssl_tls1_3_cipher_suite_is_offered( mbedtls_ssl_context *ssl,
                                              uint16_t cipher_suite )
{
    /* Check whether we have offered this ciphersuite */
    for ( int i = 0; ssl->conf->ciphersuite_list[i] != 0; i++ )
    {
        if( ssl->conf->ciphersuite_list[i] == cipher_suite )
        {
            return( 1 );
        }
    }
    return( 0 );
}

/* Parse ServerHello message and configure context
 *
 * struct {
 *    ProtocolVersion legacy_version = 0x0303; // TLS 1.2
 *    Random random;
 *    opaque legacy_session_id_echo<0..32>;
 *    CipherSuite cipher_suite;
 *    uint8 legacy_compression_method = 0;
 *    Extension extensions<6..2 ^ 16 - 1>;
 * } ServerHello;
 */
static int ssl_tls1_3_parse_server_hello( mbedtls_ssl_context *ssl,
                                          const unsigned char *buf,
                                          const unsigned char *end )
{

    int ret;
    const unsigned char *p = buf;
    size_t field_len; /* Length of field */
    const unsigned char *ext_end; /* Pointer to end of individual extension */
    uint16_t cipher_suite;
    const mbedtls_ssl_ciphersuite_t* ciphersuite_info;

    /*
     * Check there is space for minimal fields
     *
     * - legacy_version             ( 2 bytes)
     * - random                     (32 bytes)
     * - legacy_session_id_echo     ( 1 byte ), minimum size
     * - cipher_suite               ( 2 bytes)
     * - legacy_compression_method  ( 1 byte )
     */
    if( mbedtls_ssl_chk_buf_ptr( p, end, 38 ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
            ( "bad server hello message - min size not reached" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "server hello", p, end - p );

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, version", p, 2 );

    /* legacy_version must be 0x0303 (TLS 1.2) */
    if( !( p[0] == MBEDTLS_SSL_MAJOR_VERSION_3 &&
           p[1] == MBEDTLS_SSL_MINOR_VERSION_3 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported version of TLS." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                      MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
        return( MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
    }
    p += 2;
    /* Internally we use the correct 1.3 version
     * TODO: Remove below lines after supported_versions extension
     *       finished.
     */
    ssl->major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;
    ssl->minor_ver = MBEDTLS_SSL_MINOR_VERSION_4;

    /* Store server-provided random values */
    memcpy( ssl->handshake->randbytes + CLIENT_HELLO_RANDOM_LEN, p,
            SERVER_HELLO_RANDOM_LEN );
    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, random bytes",
                           p, SERVER_HELLO_RANDOM_LEN );
    p += SERVER_HELLO_RANDOM_LEN;

    /* Read and store session id (legacy_session_id_echo) */
    if( ssl_tls1_3_check_server_hello_session_id( ssl, &p, end ) != 0 )
    {
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    /* Read server-selected ciphersuite,
       Check if there is space for cipher_suite. */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2);
    cipher_suite = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    /* Configure ciphersuites */
    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( cipher_suite );
    ssl->handshake->ciphersuite_info = ciphersuite_info;
    if( ciphersuite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ciphersuite info for %04x not found",
                                    cipher_suite ) );
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    mbedtls_ssl_optimize_checksum( ssl, ssl->handshake->ciphersuite_info );

    ssl->session_negotiate->ciphersuite = cipher_suite;

    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( cipher_suite );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, chosen ciphersuite: ( %04x ) - %s",
                                 cipher_suite, ciphersuite_info->name ) );

#if defined(MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->start = time( NULL );
#endif /* MBEDTLS_HAVE_TIME */

    /* Check whether we have offered this ciphersuite */
    /* Via the force_ciphersuite version we may have instructed the client */
    /* to use a difference ciphersuite. */
    if( ssl_tls1_3_cipher_suite_is_offered( ssl, cipher_suite ) == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ciphersuite(%04x) is not in offered list",
                                    cipher_suite ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    /* Ensure that compression method is set to zero
     *
     * legacy_compression_method == 0 ( 1 byte)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 1 );
    if( p[0] != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }
    p++;

    /* Check there is space fore extensions_length */
    if( mbedtls_ssl_chk_buf_ptr( p, end, 2 ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /* Get length of extensions field (2 bytes)*/
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
    field_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    /* Check there is space for extensions_data */
    if( mbedtls_ssl_chk_buf_ptr( p, end, field_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }
    /* Set end of extensions */
    ext_end = p + field_len;

    MBEDTLS_SSL_DEBUG_MSG( 3,
        ( "server hello, total extension length: %" MBEDTLS_PRINTF_SIZET ,
          field_len ) );

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello extensions", p, field_len );

    while ( p < ext_end )
    {
        unsigned int extension_type;
        size_t extension_data_len;

        /*
         *    ....
         *    Extension extensions<6..2 ^ 16 - 1>;
         *    ....
         * struct {
         *      ExtensionType extension_type;
         *      opaque extension_data<0..2^16-1>;
         * } Extension;
         * extension_type           (2 bytes)
         * extension_data_length    (2 bytes)
         */
        MBEDTLS_SSL_CHK_BUF_PTR( p, ext_end, 4 );
        extension_type = MBEDTLS_GET_UINT16_BE( p, 0 );
        extension_data_len = MBEDTLS_GET_UINT16_BE( p, 2 );
        p += 4;

        if( mbedtls_ssl_chk_buf_ptr( p, ext_end, extension_data_len ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                          MBEDTLS_ERR_SSL_DECODE_ERROR );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

        switch( extension_type )
        {
            case MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS:
                MBEDTLS_SSL_DEBUG_MSG( 3,
                            ( "found supported_versions extension" ) );

                ret = ssl_tls1_3_parse_supported_versions_ext( ssl,
                                                        p, extension_data_len );
                if( ret != 0 )
                    return( ret );
                break;

            case MBEDTLS_TLS_EXT_PRE_SHARED_KEY:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found pre_shared_key extension." ) );
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "pre_shared_key:Not supported yet" ) );
                break;

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
            case MBEDTLS_TLS_EXT_KEY_SHARE:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found key_shares extension" ) );
                if( ( ret = ssl_tls1_3_parse_key_share_ext( ssl,
                                            p, p + extension_data_len ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1,
                                           "ssl_tls1_3_parse_key_share_ext",
                                           ret );
                    return( ret );
                }
                break;
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

            default:
                MBEDTLS_SSL_DEBUG_MSG( 3,
                                       ( "unknown extension found: %u ( ignoring )",
                                         extension_type ) );
        }

        p += extension_data_len;
    }

    return( 0 );
}

static int ssl_tls13_finalize_server_hello( mbedtls_ssl_context *ssl )
{
    ((void) ssl);
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "postprocess hasn't been implemented" ) );
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}

/*
 * Wait and Parse ServerHello handshake message.
 * Handler for MBEDTLS_SSL_SERVER_HELLO
 */
static int ssl_tls1_3_process_server_hello( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> %s", __func__ ) );

    /* Coordination step
     * - Fetch record
     * - Make sure it's either a ServerHello or a HRR.
     * - Switch processing routine in case of HRR
     */

    ssl->major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;
    ssl->handshake->extensions_present = MBEDTLS_SSL_EXT_NONE;


    ret = ssl_server_hello_coordinate( ssl, &buf, &buf_len );
    /* Parsing step
     * We know what message to expect by now and call
     * the respective parsing function.
     */
    if( ret == SSL_SERVER_HELLO_COORDINATE_HELLO )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_tls1_3_parse_server_hello( ssl, buf,
                                                             buf + buf_len ) );

        mbedtls_ssl_tls1_3_add_hs_msg_to_checksum( ssl,
                                                   MBEDTLS_SSL_HS_SERVER_HELLO,
                                                   buf, buf_len );

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_finalize_server_hello( ssl ) );
    }
    else if( ret == SSL_SERVER_HELLO_COORDINATE_HRR )
    {
        /* TODO: Implement HRR in future #4915 */
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "HRR hasn't been implemented" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                      MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

cleanup:
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= %s", __func__ ) );
    return( ret );
}

/*
 * Handler for MBEDTLS_SSL_ENCRYPTED_EXTENSIONS
 */
static int ssl_tls1_3_process_encrypted_extensions( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "%s hasn't been implemented", __func__ ) );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_REQUEST );
    return( 0 );
}

/*
 * Handler for  MBEDTLS_SSL_CERTIFICATE_REQUEST
 */
static int ssl_tls1_3_process_certificate_request( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "%s hasn't been implemented", __func__ ) );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_CERTIFICATE );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_SERVER_CERTIFICATE
 */
static int ssl_tls1_3_process_server_certificate( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "%s hasn't been implemented", __func__ ) );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_VERIFY );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_CERTIFICATE_VERIFY
 */
static int ssl_tls1_3_process_certificate_verify( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "%s hasn't been implemented", __func__ ) );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_FINISHED );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_SERVER_FINISHED
 */
static int ssl_tls1_3_process_server_finished( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "%s hasn't been implemented", __func__ ) );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CERTIFICATE );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_CLIENT_CERTIFICATE
 */
static int ssl_tls1_3_write_client_certificate( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "%s hasn't been implemented", __func__ ) );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY
 */
static int ssl_tls1_3_write_client_certificate_verify( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "%s hasn't been implemented", __func__ ) );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_FINISHED );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_CLIENT_FINISHED
 */
static int ssl_tls1_3_write_client_finished( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "%s hasn't been implemented", __func__ ) );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_FLUSH_BUFFERS );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_FLUSH_BUFFERS
 */
static int ssl_tls1_3_flush_buffers( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "%s hasn't been implemented", __func__ ) );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_WRAPUP );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_HANDSHAKE_WRAPUP
 */
static int ssl_tls1_3_handshake_wrapup( mbedtls_ssl_context *ssl )
{
    ((void) ssl);
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "%s hasn't been implemented", __func__ ) );
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}

int mbedtls_ssl_tls13_handshake_client_step( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "tls1_3 client state: %d", ssl->state ) );

    switch( ssl->state )
    {
        /*
         * ssl->state is initialized as HELLO_REQUEST. It is the same
         * as CLIENT_HELLO state.
         */
        case MBEDTLS_SSL_HELLO_REQUEST:
        case MBEDTLS_SSL_CLIENT_HELLO:
            ret = ssl_tls13_write_client_hello( ssl );
            break;

        case MBEDTLS_SSL_SERVER_HELLO:
            ret = ssl_tls1_3_process_server_hello( ssl );
            break;

        case MBEDTLS_SSL_ENCRYPTED_EXTENSIONS:
            ret = ssl_tls1_3_process_encrypted_extensions( ssl );
            break;

        case MBEDTLS_SSL_CERTIFICATE_REQUEST:
            ret = ssl_tls1_3_process_certificate_request( ssl );
            break;

        case MBEDTLS_SSL_SERVER_CERTIFICATE:
            ret = ssl_tls1_3_process_server_certificate( ssl );
            break;

        case MBEDTLS_SSL_CERTIFICATE_VERIFY:
            ret = ssl_tls1_3_process_certificate_verify( ssl );
            break;

        case MBEDTLS_SSL_SERVER_FINISHED:
            ret = ssl_tls1_3_process_server_finished( ssl );
            break;

        case MBEDTLS_SSL_CLIENT_CERTIFICATE:
            ret = ssl_tls1_3_write_client_certificate( ssl );
            break;

        case MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY:
            ret = ssl_tls1_3_write_client_certificate_verify( ssl );
            break;

        case MBEDTLS_SSL_CLIENT_FINISHED:
            ret = ssl_tls1_3_write_client_finished( ssl );
            break;

        case MBEDTLS_SSL_FLUSH_BUFFERS:
            ret = ssl_tls1_3_flush_buffers( ssl );
            break;

        case MBEDTLS_SSL_HANDSHAKE_WRAPUP:
            ret = ssl_tls1_3_handshake_wrapup( ssl );
            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ret );
}

#endif /* MBEDTLS_SSL_CLI_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
