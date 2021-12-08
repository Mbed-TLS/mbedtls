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

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

#if defined(MBEDTLS_SSL_CLI_C)

#include <string.h>

#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"

#include "ssl_misc.h"
#include "ecdh_misc.h"
#include "ssl_tls13_keys.h"
#include "ssl_debug_helpers_generated.h"

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
                                                   size_t *out_len )
{
    unsigned char *p = buf;

    *out_len = 0;

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

    *out_len = 7;

    return( 0 );
}

static int ssl_tls13_parse_supported_versions_ext( mbedtls_ssl_context *ssl,
                                                   const unsigned char *buf,
                                                   const unsigned char *end )
{
    ((void) ssl);

    MBEDTLS_SSL_CHK_BUF_READ_PTR( buf, end, 2);
    if( buf[0] != MBEDTLS_SSL_MAJOR_VERSION_3 ||
        buf[1] != MBEDTLS_SSL_MINOR_VERSION_4 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "unexpected version" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
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
                                                   size_t *out_len )
{
    unsigned char *p = buf;

    *out_len = 0;

    const uint16_t *group_list = mbedtls_ssl_get_groups( ssl );

    if( group_list == NULL )
        return( MBEDTLS_ERR_SSL_BAD_CONFIG );

    for ( ; *group_list != 0; group_list++ )
    {
        const mbedtls_ecp_curve_info *curve_info;
        curve_info = mbedtls_ecp_curve_info_from_tls_id( *group_list );
        if( curve_info == NULL )
            continue;

        if( !mbedtls_ssl_tls13_named_group_is_ecdhe( *group_list ) )
            continue;

        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2);
        MBEDTLS_PUT_UINT16_BE( *group_list, p, 0 );
        p += 2;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "NamedGroup: %s ( %x )",
                                    curve_info->name, *group_list ) );
    }

    *out_len = p - buf;

    return( 0 );
}
#else
static int ssl_tls13_write_named_group_list_ecdhe( mbedtls_ssl_context *ssl,
                                            unsigned char *buf,
                                            unsigned char *end,
                                            size_t *out_len )
{
    ((void) ssl);
    ((void) buf);
    ((void) end);
    *out_len = 0;
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}
#endif /* MBEDTLS_ECDH_C */

static int ssl_tls13_write_named_group_list_dhe( mbedtls_ssl_context *ssl,
                                        unsigned char *buf,
                                        unsigned char *end,
                                        size_t *out_len )
{
    ((void) ssl);
    ((void) buf);
    ((void) end);
    *out_len = 0;
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "write_named_group_dhe is not implemented" ) );
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}

static int ssl_tls13_write_supported_groups_ext( mbedtls_ssl_context *ssl,
                                                 unsigned char *buf,
                                                 unsigned char *end,
                                                 size_t *out_len )
{
    unsigned char *p = buf ;
    unsigned char *named_group_list; /* Start of named_group_list */
    size_t named_group_list_len;     /* Length of named_group_list */
    size_t output_len = 0;
    int ret_ecdhe, ret_dhe;

    *out_len = 0;

    if( !mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
        return( 0 );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding supported_groups extension" ) );

    /* Check if we have space for header and length fields:
     * - extension_type            (2 bytes)
     * - extension_data_length     (2 bytes)
     * - named_group_list_length   (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );
    p += 6;

    named_group_list = p;
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
    named_group_list_len = p - named_group_list;
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

    *out_len = p - buf;

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
                size_t *out_len )
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

    ret = mbedtls_ecdh_tls13_make_params( &ssl->handshake->ecdh_ctx, out_len,
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
    const uint16_t *group_list = mbedtls_ssl_get_groups( ssl );
    /* Pick first available ECDHE group compatible with TLS 1.3 */
    if( group_list == NULL )
        return( MBEDTLS_ERR_SSL_BAD_CONFIG );

    for ( ; *group_list != 0; group_list++ )
    {
        const mbedtls_ecp_curve_info *curve_info;
        curve_info = mbedtls_ecp_curve_info_from_tls_id( *group_list );
        if( curve_info != NULL &&
            mbedtls_ssl_tls13_named_group_is_ecdhe( *group_list ) )
        {
            *group_id = *group_list;
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
                                          size_t *out_len )
{
    unsigned char *p = buf;
    unsigned char *client_shares; /* Start of client_shares */
    size_t client_shares_len;     /* Length of client_shares */
    uint16_t group_id;
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;

    *out_len = 0;

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
    client_shares = p;
#if defined(MBEDTLS_ECDH_C)
    if( mbedtls_ssl_tls13_named_group_is_ecdhe( group_id ) )
    {
        /* Pointer to group */
        unsigned char *group = p;
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
        MBEDTLS_PUT_UINT16_BE( group_id, group, 0 );
        /* Write key_exchange_length */
        MBEDTLS_PUT_UINT16_BE( key_exchange_len, group, 2 );
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
    client_shares_len = p - client_shares;
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
    *out_len = p - buf;

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, key_share extension", buf, *out_len );

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_KEY_SHARE;

cleanup:

    return( ret );
}

#if defined(MBEDTLS_ECDH_C)

static int ssl_tls13_check_ecdh_params( const mbedtls_ssl_context *ssl )
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

    if( mbedtls_ssl_check_curve( ssl, grp_id ) != 0 )
        return( -1 );

    MBEDTLS_SSL_DEBUG_ECDH( 3, &ssl->handshake->ecdh_ctx,
                            MBEDTLS_DEBUG_ECDH_QP );

    return( 0 );
}

static int ssl_tls13_read_public_ecdhe_share( mbedtls_ssl_context *ssl,
                                              const unsigned char *buf,
                                              size_t buf_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_ecdh_tls13_read_public( &ssl->handshake->ecdh_ctx,
                                          buf, buf_len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "mbedtls_ecdh_tls13_read_public" ), ret );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    if( ssl_tls13_check_ecdh_params( ssl ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ssl_tls13_check_ecdh_params() failed!" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    return( 0 );
}
#endif /* MBEDTLS_ECDH_C */

/*
 * ssl_tls13_parse_key_share_ext()
 *      Parse key_share extension in Server Hello
 *
 * struct {
 *        KeyShareEntry server_share;
 * } KeyShareServerHello;
 * struct {
 *        NamedGroup group;
 *        opaque key_exchange<1..2^16-1>;
 * } KeyShareEntry;
 */
static int ssl_tls13_parse_key_share_ext( mbedtls_ssl_context *ssl,
                                          const unsigned char *buf,
                                          const unsigned char *end )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    uint16_t group, offered_group;

    /* ...
     * NamedGroup group; (2 bytes)
     * ...
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    group = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    /* Check that the chosen group matches the one we offered. */
    offered_group = ssl->handshake->offered_group_id;
    if( offered_group != group )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
            ( "Invalid server key share, our group %u, their group %u",
              (unsigned) offered_group, (unsigned) group ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

#if defined(MBEDTLS_ECDH_C)
    if( mbedtls_ssl_tls13_named_group_is_ecdhe( group ) )
    {
        /* Complete ECDHE key agreement */
        ret = ssl_tls13_read_public_ecdhe_share( ssl, p, end - p );
        if( ret != 0 )
            return( ret );
    }
    else
#endif /* MBEDTLS_ECDH_C */
    if( 0 /* other KEMs? */ )
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
            size_t *out_len )
{
    unsigned char *p = buf;
    const int *ciphersuite_list;
    unsigned char *cipher_suites; /* Start of the cipher_suites list */
    size_t cipher_suites_len;

    *out_len = 0 ;

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
                                              size_t *out_len )
{

    int ret;
    unsigned char *p_extensions_len; /* Pointer to extensions length */
    size_t output_len;               /* Length of buffer used by function */
    size_t extensions_len;           /* Length of the list of extensions*/

    /* Buffer management */
    unsigned char *p = buf;

    *out_len = 0;

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
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    memcpy( p, ssl->handshake->randbytes, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, random bytes",
                           p, MBEDTLS_CLIENT_HELLO_RANDOM_LEN );
    p += MBEDTLS_CLIENT_HELLO_RANDOM_LEN;

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
#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, ssl->session_negotiate->id_len + 1 );
    *p++ = (unsigned char)ssl->session_negotiate->id_len;
    memcpy( p, ssl->session_negotiate->id, ssl->session_negotiate->id_len );
    p += ssl->session_negotiate->id_len;

    MBEDTLS_SSL_DEBUG_BUF( 3, "session id", ssl->session_negotiate->id,
                              ssl->session_negotiate->id_len );
#else
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 1 );
    *p++ = 0; /* session id length set to zero */
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

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
    p_extensions_len = p;
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
                                  MBEDTLS_CLIENT_HELLO_RANDOM_LEN ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "f_rng", ret );
        return( ret );
    }

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    /*
     * Create a session identifier for the purpose of middlebox compatibility
     * only if one has not been created already.
     */
    if( ssl->session_negotiate->id_len == 0 )
    {
        /* Creating a session id with 32 byte length */
        if( ( ret = ssl->conf->f_rng( ssl->conf->p_rng,
                                      ssl->session_negotiate->id, 32 ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "creating session id failed", ret );
            return( ret );
        }
        ssl->session_negotiate->id_len = 32;
    }
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

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
 * Functions for parsing and processing Server Hello
 */
/* Returns a negative value on failure, and otherwise
 * - SSL_SERVER_HELLO_COORDINATE_HELLO or
 * - SSL_SERVER_HELLO_COORDINATE_HRR
 * to indicate which message is expected and to be parsed next. */
#define SSL_SERVER_HELLO_COORDINATE_HELLO 0
#define SSL_SERVER_HELLO_COORDINATE_HRR 1
static int ssl_server_hello_is_hrr( mbedtls_ssl_context *ssl,
                                    const unsigned char *buf,
                                    const unsigned char *end )
{
    static const unsigned char magic_hrr_string[MBEDTLS_SERVER_HELLO_RANDOM_LEN] =
        { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
          0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
          0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
          0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33 ,0x9C };

    /* Check whether this message is a HelloRetryRequest ( HRR ) message.
     *
     * Server Hello and HRR are only distinguished by Random set to the
     * special value of the SHA-256 of "HelloRetryRequest".
     *
     * struct {
     *    ProtocolVersion legacy_version = 0x0303;
     *    Random random;
     *    opaque legacy_session_id_echo<0..32>;
     *    CipherSuite cipher_suite;
     *    uint8 legacy_compression_method = 0;
     *    Extension extensions<6..2^16-1>;
     * } ServerHello;
     *
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( buf, end, 2 + sizeof( magic_hrr_string ) );

    if( memcmp( buf + 2, magic_hrr_string, sizeof( magic_hrr_string ) ) == 0 )
    {
        return( SSL_SERVER_HELLO_COORDINATE_HRR );
    }

    return( SSL_SERVER_HELLO_COORDINATE_HELLO );
}

/* Fetch and preprocess
 * Returns a negative value on failure, and otherwise
 * - SSL_SERVER_HELLO_COORDINATE_HELLO or
 * - SSL_SERVER_HELLO_COORDINATE_HRR
 */
static int ssl_tls13_server_hello_coordinate( mbedtls_ssl_context *ssl,
                                              unsigned char **buf,
                                              size_t *buf_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_read_record( ssl, 0 ) );

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

    ret = ssl_server_hello_is_hrr( ssl, *buf, *buf + *buf_len );
    switch( ret )
    {
        case SSL_SERVER_HELLO_COORDINATE_HELLO:
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "received ServerHello message" ) );
            break;
        case SSL_SERVER_HELLO_COORDINATE_HRR:
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "received HelloRetryRequest message" ) );
            break;
    }

cleanup:

    return( ret );
}

static int ssl_tls13_check_server_hello_session_id_echo( mbedtls_ssl_context *ssl,
                                                         const unsigned char **buf,
                                                         const unsigned char *end )
{
    const unsigned char *p = *buf;
    size_t legacy_session_id_echo_len;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 1 );
    legacy_session_id_echo_len = *p++ ;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, legacy_session_id_echo_len );

    /* legacy_session_id_echo */
    if( ssl->session_negotiate->id_len != legacy_session_id_echo_len ||
        memcmp( ssl->session_negotiate->id, p , legacy_session_id_echo_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_BUF( 3, "Expected Session ID",
                               ssl->session_negotiate->id,
                               ssl->session_negotiate->id_len );
        MBEDTLS_SSL_DEBUG_BUF( 3, "Received Session ID", p,
                               legacy_session_id_echo_len );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);

        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    p += legacy_session_id_echo_len;
    *buf = p;

    MBEDTLS_SSL_DEBUG_BUF( 3, "Session ID", ssl->session_negotiate->id,
                            ssl->session_negotiate->id_len );
    return( 0 );
}

static int ssl_tls13_cipher_suite_is_offered( mbedtls_ssl_context *ssl,
                                              int cipher_suite )
{
    const int *ciphersuite_list = ssl->conf->ciphersuite_list;

    /* Check whether we have offered this ciphersuite */
    for ( size_t i = 0; ciphersuite_list[i] != 0; i++ )
    {
        if( ciphersuite_list[i] == cipher_suite )
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
 *    Extension extensions<6..2^16-1>;
 * } ServerHello;
 */
static int ssl_tls13_parse_server_hello( mbedtls_ssl_context *ssl,
                                         const unsigned char *buf,
                                         const unsigned char *end )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    size_t extensions_len;
    const unsigned char *extensions_end;
    uint16_t cipher_suite;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;

    /*
     * Check there is space for minimal fields
     *
     * - legacy_version             ( 2 bytes)
     * - random                     (MBEDTLS_SERVER_HELLO_RANDOM_LEN bytes)
     * - legacy_session_id_echo     ( 1 byte ), minimum size
     * - cipher_suite               ( 2 bytes)
     * - legacy_compression_method  ( 1 byte )
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, MBEDTLS_SERVER_HELLO_RANDOM_LEN + 6 );

    MBEDTLS_SSL_DEBUG_BUF( 4, "server hello", p, end - p );
    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, version", p, 2 );

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
        return( MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
    }
    p += 2;

    /* ...
     * Random random;
     * ...
     * with Random defined as:
     * opaque Random[MBEDTLS_SERVER_HELLO_RANDOM_LEN];
     */
    memcpy( &ssl->handshake->randbytes[MBEDTLS_CLIENT_HELLO_RANDOM_LEN], p,
            MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, random bytes",
                           p, MBEDTLS_SERVER_HELLO_RANDOM_LEN );
    p += MBEDTLS_SERVER_HELLO_RANDOM_LEN;

    /* ...
     * opaque legacy_session_id_echo<0..32>;
     * ...
     */
    if( ssl_tls13_check_server_hello_session_id_echo( ssl, &p, end ) != 0 )
    {
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    /* ...
     * CipherSuite cipher_suite;
     * ...
     * with CipherSuite defined as:
     * uint8 CipherSuite[2];
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    cipher_suite = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;


    /*
     * Check whether this ciphersuite is supported and offered.
     * Via the force_ciphersuite version we may have instructed the client
     * to use a different ciphersuite.
     */
    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( cipher_suite );
    if( ciphersuite_info == NULL ||
        ssl_tls13_cipher_suite_is_offered( ssl, cipher_suite ) == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ciphersuite(%04x) not found or not offered",
                                    cipher_suite ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }


    /* Configure ciphersuites */
    mbedtls_ssl_optimize_checksum( ssl, ciphersuite_info );

    ssl->handshake->ciphersuite_info = ciphersuite_info;
    ssl->session_negotiate->ciphersuite = cipher_suite;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, chosen ciphersuite: ( %04x ) - %s",
                                 cipher_suite, ciphersuite_info->name ) );

#if defined(MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->start = time( NULL );
#endif /* MBEDTLS_HAVE_TIME */

    /* ...
     * uint8 legacy_compression_method = 0;
     * ...
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 1 );
    if( p[0] != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad legacy compression method" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }
    p++;

    /* ...
     * Extension extensions<6..2^16-1>;
     * ...
     * struct {
     *      ExtensionType extension_type; (2 bytes)
     *      opaque extension_data<0..2^16-1>;
     * } Extension;
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    extensions_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    /* Check extensions do not go beyond the buffer of data. */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, extensions_len );
    extensions_end = p + extensions_len;

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello extensions", p, extensions_len );

    while( p < extensions_end )
    {
        unsigned int extension_type;
        size_t extension_data_len;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, 4 );
        extension_type = MBEDTLS_GET_UINT16_BE( p, 0 );
        extension_data_len = MBEDTLS_GET_UINT16_BE( p, 2 );
        p += 4;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, extension_data_len );

        switch( extension_type )
        {
            case MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS:
                MBEDTLS_SSL_DEBUG_MSG( 3,
                            ( "found supported_versions extension" ) );

                ret = ssl_tls13_parse_supported_versions_ext( ssl,
                                                              p,
                                                              p + extension_data_len );
                if( ret != 0 )
                    return( ret );
                break;

            case MBEDTLS_TLS_EXT_PRE_SHARED_KEY:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found pre_shared_key extension." ) );
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "pre_shared_key:Not supported yet" ) );

                MBEDTLS_SSL_PEND_FATAL_ALERT(
                    MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT,
                    MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION );
                return( MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION );

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
            case MBEDTLS_TLS_EXT_KEY_SHARE:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found key_shares extension" ) );
                if( ( ret = ssl_tls13_parse_key_share_ext( ssl,
                                            p, p + extension_data_len ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1,
                                           "ssl_tls13_parse_key_share_ext",
                                           ret );
                    return( ret );
                }
                break;
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

            default:
                MBEDTLS_SSL_DEBUG_MSG(
                    3,
                    ( "unknown extension found: %u ( ignoring )",
                      extension_type ) );

                MBEDTLS_SSL_PEND_FATAL_ALERT(
                    MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT,
                    MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION );
                return( MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION );
        }

        p += extension_data_len;
    }

    return( 0 );
}

static int ssl_tls13_finalize_server_hello( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ssl_key_set traffic_keys;
    mbedtls_ssl_transform *transform_handshake = NULL;
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;

    /* Determine the key exchange mode:
     * 1) If both the pre_shared_key and key_share extensions were received
     *    then the key exchange mode is PSK with EPHEMERAL.
     * 2) If only the pre_shared_key extension was received then the key
     *    exchange mode is PSK-only.
     * 3) If only the key_share extension was received then the key
     *    exchange mode is EPHEMERAL-only.
     */
    switch( handshake->extensions_present &
            ( MBEDTLS_SSL_EXT_PRE_SHARED_KEY | MBEDTLS_SSL_EXT_KEY_SHARE ) )
    {
        /* Only the pre_shared_key extension was received */
        case MBEDTLS_SSL_EXT_PRE_SHARED_KEY:
            handshake->tls13_kex_modes = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK;
            break;

        /* Only the key_share extension was received */
        case MBEDTLS_SSL_EXT_KEY_SHARE:
            handshake->tls13_kex_modes = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL;
            break;

        /* Both the pre_shared_key and key_share extensions were received */
        case ( MBEDTLS_SSL_EXT_PRE_SHARED_KEY | MBEDTLS_SSL_EXT_KEY_SHARE ):
            handshake->tls13_kex_modes = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL;
            break;

        /* Neither pre_shared_key nor key_share extension was received */
        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unknown key exchange." ) );
            ret = MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
            goto cleanup;
    }

    /* Start the TLS 1.3 key schedule: Set the PSK and derive early secret.
     *
     * TODO: We don't have to do this in case we offered 0-RTT and the
     *       server accepted it. In this case, we could skip generating
     *       the early secret. */
    ret = mbedtls_ssl_tls13_key_schedule_stage_early( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_key_schedule_stage_early_data",
                               ret );
        goto cleanup;
    }

    /* Compute handshake secret */
    ret = mbedtls_ssl_tls13_key_schedule_stage_handshake( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_derive_master_secret", ret );
        goto cleanup;
    }

    /* Next evolution in key schedule: Establish handshake secret and
     * key material. */
    ret = mbedtls_ssl_tls13_generate_handshake_keys( ssl, &traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_generate_handshake_keys",
                               ret );
        goto cleanup;
    }

    transform_handshake = mbedtls_calloc( 1, sizeof( mbedtls_ssl_transform ) );
    if( transform_handshake == NULL )
    {
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto cleanup;
    }

    ret = mbedtls_ssl_tls13_populate_transform( transform_handshake,
                              ssl->conf->endpoint,
                              ssl->session_negotiate->ciphersuite,
                              &traffic_keys,
                              ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_populate_transform", ret );
        goto cleanup;
    }

    handshake->transform_handshake = transform_handshake;
    mbedtls_ssl_set_inbound_transform( ssl, transform_handshake );

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to handshake keys for inbound traffic" ) );
    ssl->session_in = ssl->session_negotiate;

    /*
     * State machine update
     */
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );

cleanup:

    mbedtls_platform_zeroize( &traffic_keys, sizeof( traffic_keys ) );
    if( ret != 0 )
    {
        mbedtls_free( transform_handshake );

        MBEDTLS_SSL_PEND_FATAL_ALERT(
            MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
            MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }
    return( ret );
}

/*
 * Wait and parse ServerHello handshake message.
 * Handler for MBEDTLS_SSL_SERVER_HELLO
 */
static int ssl_tls13_process_server_hello( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
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

    ret = ssl_tls13_server_hello_coordinate( ssl, &buf, &buf_len );
    /* Parsing step
     * We know what message to expect by now and call
     * the respective parsing function.
     */
    if( ret == SSL_SERVER_HELLO_COORDINATE_HELLO )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_tls13_parse_server_hello( ssl, buf,
                                                            buf + buf_len ) );

        mbedtls_ssl_tls13_add_hs_msg_to_checksum( ssl,
                                                  MBEDTLS_SSL_HS_SERVER_HELLO,
                                                  buf, buf_len );

        MBEDTLS_SSL_PROC_CHK( ssl_tls13_finalize_server_hello( ssl ) );
    }
    else if( ret == SSL_SERVER_HELLO_COORDINATE_HRR )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "HRR not supported" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE ,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        ret = MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }

cleanup:
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= %s", __func__ ) );
    return( ret );
}

/*
 *
 * EncryptedExtensions message
 *
 * The EncryptedExtensions message contains any extensions which
 * should be protected, i.e., any which are not needed to establish
 * the cryptographic context.
 */

/*
 * Overview
 */

/* Main entry point; orchestrates the other functions */
static int ssl_tls13_process_encrypted_extensions( mbedtls_ssl_context *ssl );

static int ssl_tls13_parse_encrypted_extensions( mbedtls_ssl_context *ssl,
                                                 const unsigned char *buf,
                                                 const unsigned char *end );
static int ssl_tls13_postprocess_encrypted_extensions( mbedtls_ssl_context *ssl );

/*
 * Handler for  MBEDTLS_SSL_ENCRYPTED_EXTENSIONS
 */
static int ssl_tls13_process_encrypted_extensions( mbedtls_ssl_context *ssl )
{
    int ret;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse encrypted extensions" ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_fetch_handshake_msg( ssl,
                                             MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS,
                                             &buf, &buf_len ) );

    /* Process the message contents */
    MBEDTLS_SSL_PROC_CHK(
        ssl_tls13_parse_encrypted_extensions( ssl, buf, buf + buf_len ) );

    mbedtls_ssl_tls13_add_hs_msg_to_checksum(
        ssl, MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS, buf, buf_len );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_postprocess_encrypted_extensions( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse encrypted extensions" ) );
    return( ret );

}

/* Parse EncryptedExtensions message
 * struct {
 *     Extension extensions<0..2^16-1>;
 * } EncryptedExtensions;
 */
static int ssl_tls13_parse_encrypted_extensions( mbedtls_ssl_context *ssl,
                                                 const unsigned char *buf,
                                                 const unsigned char *end )
{
    int ret = 0;
    size_t extensions_len;
    const unsigned char *p = buf;
    const unsigned char *extensions_end;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    extensions_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    MBEDTLS_SSL_DEBUG_BUF( 3, "encrypted extensions", p, extensions_len );
    extensions_end = p + extensions_len;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, extensions_len );

    while( p < extensions_end )
    {
        unsigned int extension_type;
        size_t extension_data_len;

        /*
         * struct {
         *     ExtensionType extension_type; (2 bytes)
         *     opaque extension_data<0..2^16-1>;
         * } Extension;
         */
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, 4 );
        extension_type = MBEDTLS_GET_UINT16_BE( p, 0 );
        extension_data_len = MBEDTLS_GET_UINT16_BE( p, 2 );
        p += 4;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, extensions_end, extension_data_len );

        /* The client MUST check EncryptedExtensions for the
         * presence of any forbidden extensions and if any are found MUST abort
         * the handshake with an "unsupported_extension" alert.
         */
        switch( extension_type )
        {

            case MBEDTLS_TLS_EXT_SUPPORTED_GROUPS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found extensions supported groups" ) );
                break;

            default:
                MBEDTLS_SSL_DEBUG_MSG(
                    3, ( "unsupported extension found: %u ", extension_type) );
                MBEDTLS_SSL_PEND_FATAL_ALERT(
                    MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT,
                    MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION );
                return ( MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION );
        }

        p += extension_data_len;
    }

    /* Check that we consumed all the message. */
    if( p != end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "EncryptedExtension lengths misaligned" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    return( ret );
}

static int ssl_tls13_postprocess_encrypted_extensions( mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    if( mbedtls_ssl_tls13_some_psk_enabled( ssl ) )
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_FINISHED );
    else
        mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_REQUEST );
#else
    ((void) ssl);
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_FINISHED );
#endif
    return( 0 );
}

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
/*
 * Handler for  MBEDTLS_SSL_CERTIFICATE_REQUEST
 */
static int ssl_tls13_process_certificate_request( mbedtls_ssl_context *ssl )
{
    int ret = mbedtls_ssl_read_record( ssl, 0 );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        return( ret );
    }

    if( ( ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE ) &&
        ( ssl->in_msg[0] == MBEDTLS_SSL_HS_CERTIFICATE_REQUEST ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "CertificateRequest not supported" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    ssl->keep_current_message = 1;
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_CERTIFICATE );

    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_SERVER_CERTIFICATE
 */
static int ssl_tls13_process_server_certificate( mbedtls_ssl_context *ssl )
{
    int ret;

    ret = mbedtls_ssl_tls13_process_certificate( ssl );
    if( ret != 0 )
        return( ret );

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CERTIFICATE_VERIFY );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_CERTIFICATE_VERIFY
 */
static int ssl_tls13_process_certificate_verify( mbedtls_ssl_context *ssl )
{
    int ret;

    ret = mbedtls_ssl_tls13_process_certificate_verify( ssl );
    if( ret != 0 )
        return( ret );

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_SERVER_FINISHED );
    return( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/*
 * Handler for MBEDTLS_SSL_SERVER_FINISHED
 */
static int ssl_tls13_process_server_finished( mbedtls_ssl_context *ssl )
{
    int ret;

    ret = mbedtls_ssl_tls13_process_finished_message( ssl );
    if( ret != 0 )
        return( ret );

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    mbedtls_ssl_handshake_set_state(
        ssl,
        MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED );
#else
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_FINISHED );
#endif

    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED
 */
#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
static int ssl_tls13_write_change_cipher_spec( mbedtls_ssl_context *ssl )
{
    int ret;

    ret = mbedtls_ssl_tls13_write_change_cipher_spec( ssl );
    if( ret != 0 )
        return( ret );

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_CLIENT_FINISHED );

    return( 0 );
}
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

/*
 * Handler for MBEDTLS_SSL_CLIENT_FINISHED
 */
static int ssl_tls13_write_client_finished( mbedtls_ssl_context *ssl )
{
    int ret;

    mbedtls_ssl_set_outbound_transform( ssl, ssl->handshake->transform_handshake );

    ret = mbedtls_ssl_tls13_write_finished_message( ssl );
    if( ret != 0 )
        return( ret );

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_FLUSH_BUFFERS );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_FLUSH_BUFFERS
 */
static int ssl_tls13_flush_buffers( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "handshake: done" ) );
    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_WRAPUP );
    return( 0 );
}

/*
 * Handler for MBEDTLS_SSL_HANDSHAKE_WRAPUP
 */
static int ssl_tls13_handshake_wrapup( mbedtls_ssl_context *ssl )
{
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to application keys for inbound traffic" ) );
    mbedtls_ssl_set_inbound_transform ( ssl, ssl->transform_application );

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "Switch to application keys for outbound traffic" ) );
    mbedtls_ssl_set_outbound_transform( ssl, ssl->transform_application );

    mbedtls_ssl_tls13_handshake_wrapup( ssl );

    mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_HANDSHAKE_OVER );
    return( 0 );
}

int mbedtls_ssl_tls13_handshake_client_step( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "tls13 client state: %s(%d)",
                                mbedtls_ssl_states_str( ssl->state ),
                                ssl->state ) );

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
            ret = ssl_tls13_process_server_hello( ssl );
            break;

        case MBEDTLS_SSL_ENCRYPTED_EXTENSIONS:
            ret = ssl_tls13_process_encrypted_extensions( ssl );
            break;

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
        case MBEDTLS_SSL_CERTIFICATE_REQUEST:
            ret = ssl_tls13_process_certificate_request( ssl );
            break;

        case MBEDTLS_SSL_SERVER_CERTIFICATE:
            ret = ssl_tls13_process_server_certificate( ssl );
            break;

        case MBEDTLS_SSL_CERTIFICATE_VERIFY:
            ret = ssl_tls13_process_certificate_verify( ssl );
            break;
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

        case MBEDTLS_SSL_SERVER_FINISHED:
            ret = ssl_tls13_process_server_finished( ssl );
            break;

        case MBEDTLS_SSL_CLIENT_FINISHED:
            ret = ssl_tls13_write_client_finished( ssl );
            break;

        case MBEDTLS_SSL_FLUSH_BUFFERS:
            ret = ssl_tls13_flush_buffers( ssl );
            break;

        case MBEDTLS_SSL_HANDSHAKE_WRAPUP:
            ret = ssl_tls13_handshake_wrapup( ssl );
            break;

        /*
         * Injection of dummy-CCS's for middlebox compatibility
         */
#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
        case MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED:
            ret = ssl_tls13_write_change_cipher_spec( ssl );
            break;
#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ret );
}

#endif /* MBEDTLS_SSL_CLI_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */
