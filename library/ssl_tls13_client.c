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
#include <mbedtls/debug.h>

#define CLIENT_HELLO_RANDOM_LEN 32

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

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)

static int ssl_tls13_write_supported_groups_ext( mbedtls_ssl_context *ssl,
                                                 unsigned char *buf,
                                                 unsigned char *end,
                                                 size_t *olen )
{
    ((void) ssl);
    ((void) buf);
    ((void) end);
    ((void) olen);
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}

static int ssl_tls13_write_key_shares_ext( mbedtls_ssl_context *ssl,
                                           unsigned char *buf,
                                           unsigned char *end,
                                           size_t *olen )
{
    ((void) ssl);
    ((void) buf);
    ((void) end);
    ((void) olen);
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/*
 * Functions for writing ClientHello message.
 */
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
    ret = ssl_tls13_write_key_shares_ext( ssl, p, end, &output_len );
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
            // Stop here : we haven't finished whole flow
            ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
            mbedtls_ssl_handshake_set_state( ssl, MBEDTLS_SSL_ENCRYPTED_EXTENSIONS );
            break;

        default:
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "invalid state %d", ssl->state ) );
            return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );
    }

    return( ret );
}

#endif /* MBEDTLS_SSL_CLI_C */

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
