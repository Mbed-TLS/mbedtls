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

#include "ssl_misc.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"

#define CLIENT_HELLO_RANDOM_LEN 32
#define CLIENT_HELLO_LEGACY_VERSION_LEN 2

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

    /*
     * Check space for extension header.
     *
     * extension_type           2
     * extension_data_length    2
     * version_length           1
     * versions                 2
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

static int ssl_parse_supported_versions_ext( mbedtls_ssl_context* ssl,
                                            const unsigned char* buf,
                                            size_t len )
{
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
/* Find out available ecdhe named groups in current configuration */
#if defined(MBEDTLS_ECDH_C)
/*
 * In versions of TLS prior to TLS 1.3, this extension was named
 * 'elliptic_curves' and only contained elliptic curve groups.
 */
static int ssl_tls13_write_named_group_ecdhe( mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              unsigned char *end,
                                              size_t *olen )
{
    unsigned char *p = buf; /* Iteration over named_group_list */
#if !defined(MBEDTLS_ECP_C)
    ((void) ssl);
#endif

    *olen = 0;

#if defined(MBEDTLS_ECP_C)
    for ( const mbedtls_ecp_group_id *grp_id = ssl->conf->curve_list;
          *grp_id != MBEDTLS_ECP_DP_NONE;
          grp_id++ )
    {
        const mbedtls_ecp_curve_info *info;
        info = mbedtls_ecp_curve_info_from_grp_id( *grp_id );
        if( info == NULL )
            continue;
#else
    for ( const mbedtls_ecp_curve_info *info = mbedtls_ecp_curve_list();
          info->grp_id != MBEDTLS_ECP_DP_NONE;
          info++ )
    {
#endif
        if( !mbedtls_ssl_named_group_is_ecdhe( info->tls_id ) )
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
static int ssl_tls13_write_named_group_ecdhe( mbedtls_ssl_context *ssl,
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

/* Find out available dhe named groups in current configuration */
static int ssl_tls13_write_named_group_dhe( mbedtls_ssl_context *ssl,
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

/*
 * Supported Groups Extension (supported_groups)
 */
static int ssl_tls13_write_supported_groups_ext( mbedtls_ssl_context *ssl,
                                                 unsigned char *buf,
                                                 unsigned char *end,
                                                 size_t *olen )
{
    unsigned char *p = buf ;
    unsigned char *named_group_ptr; /* Start of named_group_list */
    
    size_t named_group_len = 0;
    int ret = 0, ret_ecdhe, ret_dhe;

    *olen = 0;

    if( !mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
        return( 0 );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello, adding supported_groups extension" ) );

    /* Check there is space for extension header */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );
    p += 6;

    named_group_ptr = p;
    ret_ecdhe = ssl_tls13_write_named_group_ecdhe( ssl, p, end, &named_group_len );
    if( ret_ecdhe != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_named_group_ecdhe", ret );
    }
    p += named_group_len;

    ret_dhe = ssl_tls13_write_named_group_dhe( ssl, p, end, &named_group_len );
    if( ret_dhe != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "ssl_tls13_write_named_group_dhe", ret );
    }
    p += named_group_len;

    /* Both ECDHE and DHE Fail. */
    if( ret_ecdhe != 0 && ret_dhe != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Both ECDHE and DHE groups are fail. " ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Length of named_group_list*/
    named_group_len = p - named_group_ptr;
    if( named_group_len == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "No Named Group Available." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Write extension_type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SUPPORTED_GROUPS, buf, 0 );
    /* Write extension_data_length */
    MBEDTLS_PUT_UINT16_BE( named_group_len + 2, buf, 2 );
    /* Write length of named_group_list */
    MBEDTLS_PUT_UINT16_BE( named_group_len, buf, 4 );

    MBEDTLS_SSL_DEBUG_BUF( 3, "Supported groups extension", buf + 4, named_group_len + 2 );

    *olen = p - buf;

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SUPPORTED_GROUPS;

    return( ret );
}

/*
 * Functions for writing key_share extension.
 */
#if defined(MBEDTLS_ECDH_C)
static int ssl_key_share_gen_and_write_ecdhe( mbedtls_ssl_context *ssl,
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

    if( ( ret = mbedtls_ecdh_setup( &ssl->handshake->ecdh_ctx,
                                    curve_info->grp_id ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ecp_group_load", ret );
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

static int ssl_named_group_get_default_id( mbedtls_ssl_context *ssl,
                                           uint16_t *named_group_id )
{
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;

    /* Pick first entry of curve list.
     *
     * TODO: When we introduce PQC KEMs, we'll have a NamedGroup
     *       list instead, and can just return its first element.
     */

#if defined(MBEDTLS_ECDH_C)

#if !defined(MBEDTLS_ECP_C)
    ((void) ssl);
#endif

#if defined(MBEDTLS_ECP_C)
    for ( const mbedtls_ecp_group_id * grp_id = ssl->conf->curve_list;
          *grp_id != MBEDTLS_ECP_DP_NONE;
          grp_id++ )
    {
        const mbedtls_ecp_curve_info *info;
        info = mbedtls_ecp_curve_info_from_grp_id( *grp_id );
#else
    for ( const mbedtls_ecp_curve_info *info = mbedtls_ecp_curve_list();
          info->grp_id != MBEDTLS_ECP_DP_NONE;
          info++ )
    {
#endif
        if( info != NULL && mbedtls_ssl_named_group_is_ecdhe( info->tls_id ) )
        {
            *named_group_id = info->tls_id;
            return( 0 );
        }
    }
#else
    ((void) ssl);
    ((void) named_group_id);
#endif /* MBEDTLS_ECDH_C */

    /* Add DHE group picking up code here */

    return( ret );
}
/*
 * ssl_tls13_write_key_share_ext
 *
 * Structure of key_share extension in ClientHelo:
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
    uint16_t group_id;
    unsigned char *client_shares_start = buf + 6; /* Start of client_shares */
    unsigned char *client_shares_iter = buf + 6;  /* Iteration over client_shares */

    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;

    *olen = 0;

    if( !mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
        return( 0 );

    /* Check if we have space for headers and length fields:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - client_shares_length   (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( buf, end, 6 );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "client hello: adding key share extension" ) );


    /* HRR could already have requested something else. */
    group_id = ssl->handshake->offered_group_id;
    if( !mbedtls_ssl_named_group_is_ecdhe( group_id ) &&
        !mbedtls_ssl_named_group_is_dhe( group_id ) )
    {
        MBEDTLS_SSL_PROC_CHK( ssl_named_group_get_default_id( ssl,
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
#if defined(MBEDTLS_ECDH_C)
    if( mbedtls_ssl_named_group_is_ecdhe( group_id ) )
    {
        /* Start of key_exchange */
        unsigned char * key_exchange_start = client_shares_iter + 4;
        /* Length of key_exchange */
        size_t key_exchange_len;

        /* Check there is space for header of KeyShareEntry
         * - group                  (2 bytes)
         * - key_exchange_length    (2 bytes)
         */
        MBEDTLS_SSL_CHK_BUF_PTR( client_shares_iter, end, 4 );
        ret = ssl_key_share_gen_and_write_ecdhe( ssl, group_id,
                                                 key_exchange_start, end,
                                                 &key_exchange_len );
        if( ret != 0 )
            return( ret );

        /* Write group */
        MBEDTLS_PUT_UINT16_BE( group_id, client_shares_iter, 0 );
        /* Write key_exchange_length */
        MBEDTLS_PUT_UINT16_BE( key_exchange_len, client_shares_iter, 2 );

        client_shares_iter = key_exchange_start + key_exchange_len;
    }
    else
#endif /* MBEDTLS_ECDH_C */
    if( 0 /* other KEMs? */ )
    {
        /* Do something */
    }
    else
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );


    /* Write extension_type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_KEY_SHARE, buf, 0 );
    /* Write extension_data_length */
    MBEDTLS_PUT_UINT16_BE( client_shares_iter - client_shares_start + 2, buf, 2 );
    /* Write client_shares_length */
    MBEDTLS_PUT_UINT16_BE( client_shares_iter - client_shares_start, buf, 4 );

    /* Update offered_group_id field */
    ssl->handshake->offered_group_id = group_id;

    /* Output the total length of key_share extension. */
    *olen = client_shares_iter - buf;

    MBEDTLS_SSL_DEBUG_BUF( 3, "client hello, key_share extension", buf, *olen );

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_KEY_SHARE;

cleanup:

    return( ret );
}

#if (defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C))

/* TODO: Code for MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED missing */
static int check_ecdh_params( const mbedtls_ssl_context *ssl )
{
    const mbedtls_ecp_curve_info *curve_info;

    curve_info = mbedtls_ecp_curve_info_from_grp_id( ssl->handshake->ecdh_ctx.grp_id );
    if( curve_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "ECDH curve: %s", curve_info->name ) );

#if defined(MBEDTLS_ECP_C)
    if( mbedtls_ssl_check_curve( ssl, ssl->handshake->ecdh_ctx.grp_id ) != 0 )
#else
    if( ssl->handshake->ecdh_ctx.grp.nbits < 163 ||
            ssl->handshake->ecdh_ctx.grp.nbits > 521 )
#endif
            return( -1 );

    MBEDTLS_SSL_DEBUG_ECDH( 3, &ssl->handshake->ecdh_ctx,
                            MBEDTLS_DEBUG_ECDH_QP );

    return( 0 );
}
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

/* The ssl_parse_key_shares_ext() function is used
 *  by the client to parse a KeyShare extension in
 *  a ServerHello message.
 *
 *  The server only provides a single KeyShareEntry.
 */
static int ssl_read_public_ecdhe_share( mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        size_t len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = mbedtls_ecdh_tls13_read_public( &ssl->handshake->ecdh_ctx,
                                          buf, len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, ( "mbedtls_ecdh_tls13_read_public" ), ret );
        return( ret );
    }

    if( check_ecdh_params( ssl ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "check_ecdh_params() failed!" ) );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    return( 0 );
}

static int ssl_parse_key_shares_ext( mbedtls_ssl_context *ssl,
                                     const unsigned char *buf,
                                     size_t len )
{
    int ret = 0;
    uint16_t their_group;

    if( len < 2 )
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );

    their_group = ((uint16_t) buf[0] << 8 ) | ((uint16_t) buf[1] );
    buf += 2;
    len -= 2;

    /* Check that chosen group matches the one we offered. */
    if( ssl->handshake->offered_group_id != their_group )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
            ( "Invalid server key share, our group %u, their group %u",
              (unsigned) ssl->handshake->offered_group_id, (unsigned) their_group ) );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    if( mbedtls_ssl_named_group_is_ecdhe( their_group ) )
    {
        /* Complete ECDHE key agreement */
        ret = ssl_read_public_ecdhe_share( ssl, buf, len );
        if( ret != 0 )
            return( ret );
    }
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
    unsigned char *p = buf;  /* Iteration over the cipher_suites list */
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
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, CLIENT_HELLO_LEGACY_VERSION_LEN );
    MBEDTLS_PUT_UINT16_BE( 0x0303, p, 0 );
    p += CLIENT_HELLO_LEGACY_VERSION_LEN;

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

static int ssl_tls13_finalize_client_hello( mbedtls_ssl_context* ssl )
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
    const char magic_hrr_string[32] =
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
static int ssl_server_hello_coordinate( mbedtls_ssl_context* ssl,
                                        unsigned char **buf,
                                        size_t *buflen )
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

        MBEDTLS_SSL_SEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                      MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    *buf = ssl->in_msg + 4;
    *buflen = ssl->in_hslen - 4;

    if( ssl_server_hello_is_hrr( ssl->in_msg + 4 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "received HelloRetryRequest message" ) );
        ret = SSL_SERVER_HELLO_COORDINATE_HRR;
    }
    else
    {
        ret = SSL_SERVER_HELLO_COORDINATE_HELLO;
    }

cleanup:

    return( ret );
}

static int ssl_server_hello_session_id_check( mbedtls_ssl_context* ssl,
                                              const unsigned char** buf,
                                              const unsigned char* end )
{
    size_t buflen = (size_t)( end - *buf );
    size_t recv_id_len;

    if( buflen == 0 )
        return( 1 );

    recv_id_len = **buf;
    *buf   += 1; /* skip session id length */
    buflen -= 1;

    /* legacy_session_id_echo */
    if( ssl->session_negotiate->id_len != recv_id_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Mismatch of session id length" ) );
        return( 1 );
    }

    if( buflen < recv_id_len )
        return( 1 );

    if( memcmp( ssl->session_negotiate->id, *buf,
                ssl->session_negotiate->id_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unexpected legacy_session_id_echo" ) );
        MBEDTLS_SSL_DEBUG_BUF( 3, "Expected Session ID",
                               ssl->session_negotiate->id,
                               ssl->session_negotiate->id_len );
        MBEDTLS_SSL_DEBUG_BUF( 3, "Received Session ID", *buf,
                               ssl->session_negotiate->id_len );
        return( 1 );
    }

    *buf   += recv_id_len;
    buflen -= recv_id_len;

    MBEDTLS_SSL_DEBUG_BUF( 3, "Session ID",
                           ssl->session_negotiate->id,
                           ssl->session_negotiate->id_len );
    return( 0 );
}

static int ssl_server_hello_parse( mbedtls_ssl_context* ssl,
                                   const unsigned char* buf,
                                   size_t buflen )
{

    int ret; /* return value */
    int i; /* scratch value */
    const unsigned char* msg_end = buf + buflen; /* pointer to the end of the buffer for length checks */

    size_t ext_len; /* stores length of all extensions */
    unsigned int ext_id; /* id of an extension */
    const unsigned char* ext; /* pointer to an individual extension */
    unsigned int ext_size; /* size of an individual extension */

    const mbedtls_ssl_ciphersuite_t* suite_info; /* pointer to ciphersuite */

    /* Check for minimal length */
    /* struct {
     *    ProtocolVersion legacy_version = 0x0303;
     *    Random random;
     *    opaque legacy_session_id_echo<0..32>;
     *    CipherSuite cipher_suite;
     *    uint8 legacy_compression_method = 0;
     *    Extension extensions<6..2 ^ 16 - 1>;
     * } ServerHello;
     *
     *
     * 38 = 32 ( random bytes ) + 2 ( ciphersuite ) + 2 ( version ) +
     *       1 ( legacy_compression_method ) + 1 ( minimum for legacy_session_id_echo )
     */
    if( buflen < 38 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message - min size not reached" ) );
        MBEDTLS_SSL_SEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "server hello", buf, buflen );

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, version", buf + 0, 2 );
    mbedtls_ssl_read_version( &ssl->major_ver, &ssl->minor_ver,
                              ssl->conf->transport, buf + 0 );

    /* The version field in the ServerHello must contain 0x303 */
    if( buf[0] != 0x03 || buf[1] != 0x03 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Unsupported version of TLS." ) );
        MBEDTLS_SSL_SEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION,
                                      MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
        return( MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION );
    }

    /* skip version */
    buf += 2;

    /* Internally we use the correct 1.3 version */
    ssl->major_ver = 0x03;
    ssl->minor_ver = 0x04;

    /* store server-provided random values */
    memcpy( ssl->handshake->randbytes + 32, buf, 32 );
    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello, random bytes", buf + 2, 32 );

    /* skip random bytes */
    buf += 32;

    if( ssl_server_hello_session_id_check( ssl, &buf, msg_end ) != 0 )
    {
        MBEDTLS_SSL_SEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    /* read server-selected ciphersuite, which follows random bytes */
    i = ( buf[0] << 8 ) | buf[1];

    /* skip ciphersuite */
    buf += 2;

    /* TBD: Check whether we have offered this ciphersuite */
    /* Via the force_ciphersuite version we may have instructed the client */
    /* to use a difference ciphersuite. */

    /* Configure ciphersuites */
    ssl->handshake->ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( i );

    if( ssl->handshake->ciphersuite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "ciphersuite info for %04x not found", i ) );
        MBEDTLS_SSL_SEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                                      MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    mbedtls_ssl_optimize_checksum( ssl, ssl->handshake->ciphersuite_info );

    ssl->session_negotiate->ciphersuite = i;

    suite_info = mbedtls_ssl_ciphersuite_from_id( ssl->session_negotiate->ciphersuite );
    if( suite_info == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        MBEDTLS_SSL_SEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, chosen ciphersuite: ( %04x ) - %s", i, suite_info->name ) );

#if defined(MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->start = time( NULL );
#endif /* MBEDTLS_HAVE_TIME */

    i = 0;
    while ( 1 )
    {
        if( ssl->conf->ciphersuite_list[i] == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
            MBEDTLS_SSL_SEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                          MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
            return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        }

        if( ssl->conf->ciphersuite_list[i++] ==
            ssl->session_negotiate->ciphersuite )
        {
            break;
        }
    }

    /* Ensure that compression method is set to zero */
    if( buf[0] != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        MBEDTLS_SSL_SEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                                      MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
        return( MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER );
    }

    /* skip compression */
    buf++;

    /* Are we reading beyond the message buffer? */
    if( ( buf + 2 ) > msg_end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        MBEDTLS_SSL_SEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    ext_len = ( ( buf[0] << 8 ) | ( buf[1] ) );
    buf += 2; /* skip extension length */

    /* Are we reading beyond the message buffer? */
    if( ( buf + ext_len ) > msg_end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
        MBEDTLS_SSL_SEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    ext = buf;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "server hello, total extension length: %" MBEDTLS_PRINTF_SIZET , ext_len ) );

    MBEDTLS_SSL_DEBUG_BUF( 3, "server hello extensions", ext, ext_len );

    while ( ext_len )
    {
        ext_id = ( ( ext[0] << 8 ) | ( ext[1] ) );
        ext_size = ( ( ext[2] << 8 ) | ( ext[3] ) );

        if( ext_size + 4 > ext_len )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
            MBEDTLS_SSL_SEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                          MBEDTLS_ERR_SSL_DECODE_ERROR );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

        switch( ext_id )
        {
            case MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found supported_versions extension" ) );

                ret = ssl_parse_supported_versions_ext( ssl, ext + 4, ext_size );
                if( ret != 0 )
                    return( ret );
                break;

            case MBEDTLS_TLS_EXT_PRE_SHARED_KEY:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found pre_shared_key extension." ) );
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "pre_shared_key:Not supported yet:SKIP" ) );
                break;

#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C)
            case MBEDTLS_TLS_EXT_KEY_SHARE:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "found key_shares extension" ) );

                if( ( ret = ssl_parse_key_shares_ext( ssl, ext + 4, (size_t)ext_size ) ) != 0 )
                {
                    MBEDTLS_SSL_DEBUG_RET( 1, "ssl_parse_key_shares_ext", ret );
                    return( ret );
                }
                break;
#endif /* MBEDTLS_ECDH_C || MBEDTLS_ECDSA_C */

            default:
                MBEDTLS_SSL_DEBUG_MSG( 3, ( "unknown extension found: %d ( ignoring )", ext_id ) );
        }

        ext_len -= 4 + ext_size;
        ext += 4 + ext_size;

        if( ext_len > 0 && ext_len < 4 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad server hello message" ) );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }
    }

    return( 0 );
}

static int ssl_server_hello_postprocess( mbedtls_ssl_context* ssl )
{
    ((void) ssl);
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}

/*
 * Wait and Parse ServerHello handshake message.
 */
static int ssl_tls13_process_server_hello( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse server hello" ) );

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
        MBEDTLS_SSL_PROC_CHK( ssl_server_hello_parse( ssl, buf, buf_len ) );

        mbedtls_ssl_tls13_add_hs_msg_to_checksum( ssl,
                                                  MBEDTLS_SSL_HS_SERVER_HELLO,
                                                  buf, buf_len );

        MBEDTLS_SSL_PROC_CHK( ssl_server_hello_postprocess( ssl ) );
    }
    else if( ret == SSL_SERVER_HELLO_COORDINATE_HRR )
    {
        /* TODO: Implement HRR in future #4915 */
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "HRR hasn't been implemented" ) );

        MBEDTLS_SSL_SEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                      MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }

cleanup:
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse server hello" ) );
    return( ret );
}

int mbedtls_ssl_tls13_handshake_client_step( mbedtls_ssl_context *ssl )
{
    int ret = 0;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "client state: %d", ssl->state ) );

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
            // Stop here : we haven't finished whole flow
            ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ret );
}

#endif /* MBEDTLS_SSL_CLI_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
