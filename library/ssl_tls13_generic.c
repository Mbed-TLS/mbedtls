/*
 *  TLS 1.3 functionality shared between client and server
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

#if defined(MBEDTLS_SSL_TLS_C)

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#include "ssl_misc.h"
#include <mbedtls/debug.h>
#include <mbedtls/oid.h>
#include <mbedtls/platform.h>


int mbedtls_ssl_tls1_3_fetch_handshake_msg( mbedtls_ssl_context *ssl,
                                            unsigned hs_type,
                                            unsigned char **buf,
                                            size_t *buflen )
{
    int ret;

    if( ( ret = mbedtls_ssl_read_record( ssl, 0 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        goto cleanup;
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE ||
        ssl->in_msg[0]  != hs_type )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Receive unexpected handshake message." ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE,
                                      MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto cleanup;
    }

    /*
     * Jump handshake header (4 bytes, see Section 4 of RFC 8446).
     *    ...
     *    HandshakeType msg_type;
     *    uint24 length;
     *    ...
     */
    *buf    = ssl->in_msg   + 4;
    *buflen = ssl->in_hslen - 4;

cleanup:

    return( ret );
}

int mbedtls_ssl_tls13_start_handshake_msg( mbedtls_ssl_context *ssl,
                                           unsigned hs_type,
                                           unsigned char **buf,
                                           size_t *buf_len )
{
    /*
     * Reserve 4 bytes for hanshake header. ( Section 4,RFC 8446 )
     *    ...
     *    HandshakeType msg_type;
     *    uint24 length;
     *    ...
     */
    *buf = ssl->out_msg + 4;
    *buf_len = MBEDTLS_SSL_OUT_CONTENT_LEN - 4;

    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = hs_type;

    return( 0 );
}

int mbedtls_ssl_tls13_finish_handshake_msg( mbedtls_ssl_context *ssl,
                                            size_t buf_len,
                                            size_t msg_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t msg_len_with_header;
    ((void) buf_len);

    /* Add reserved 4 bytes for handshake header */
    msg_len_with_header = msg_len + 4;
    ssl->out_msglen = msg_len_with_header;
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_handshake_msg_ext( ssl, 0 ) );

cleanup:
    return( ret );
}

void mbedtls_ssl_tls1_3_add_hs_msg_to_checksum( mbedtls_ssl_context *ssl,
                                                unsigned hs_type,
                                                unsigned char const *msg,
                                                size_t msg_len )
{
    mbedtls_ssl_tls13_add_hs_hdr_to_checksum( ssl, hs_type, msg_len );
    ssl->handshake->update_checksum( ssl, msg, msg_len );
}

void mbedtls_ssl_tls13_add_hs_hdr_to_checksum( mbedtls_ssl_context *ssl,
                                               unsigned hs_type,
                                               size_t total_hs_len )
{
    unsigned char hs_hdr[4];

    /* Build HS header for checksum update. */
    hs_hdr[0] = MBEDTLS_BYTE_0( hs_type );
    hs_hdr[1] = MBEDTLS_BYTE_2( total_hs_len );
    hs_hdr[2] = MBEDTLS_BYTE_1( total_hs_len );
    hs_hdr[3] = MBEDTLS_BYTE_0( total_hs_len );

    ssl->handshake->update_checksum( ssl, hs_hdr, sizeof( hs_hdr ) );
}

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)

/*
 * mbedtls_ssl_tls13_write_sig_alg_ext( )
 *
 * enum {
 *    ....
 *   ecdsa_secp256r1_sha256( 0x0403 ),
 *   ecdsa_secp384r1_sha384( 0x0503 ),
 *   ecdsa_secp521r1_sha512( 0x0603 ),
 *    ....
 * } SignatureScheme;
 *
 * struct {
 *    SignatureScheme supported_signature_algorithms<2..2^16-2>;
 * } SignatureSchemeList;
 *
 * Only if we handle at least one key exchange that needs signatures.
 */
int mbedtls_ssl_tls13_write_sig_alg_ext( mbedtls_ssl_context *ssl,
                                         unsigned char *buf,
                                         unsigned char *end,
                                         size_t *olen )
{
    unsigned char *p = buf;
    unsigned char *supported_sig_alg_ptr; /* Start of supported_signature_algorithms */
    size_t supported_sig_alg_len = 0;     /* Length of supported_signature_algorithms */

    *olen = 0;

    /* Skip the extension on the client if all allowed key exchanges
     * are PSK-based. */
#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
        !mbedtls_ssl_conf_tls13_some_ephemeral_enabled( ssl ) )
    {
        return( 0 );
    }
#endif /* MBEDTLS_SSL_CLI_C */

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "adding signature_algorithms extension" ) );

    /* Check if we have space for header and length field:
     * - extension_type         (2 bytes)
     * - extension_data_length  (2 bytes)
     * - supported_signature_algorithms_length   (2 bytes)
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 6 );
    p += 6;

    /*
     * Write supported_signature_algorithms
     */
    supported_sig_alg_ptr = p;
    for( const uint16_t *sig_alg = ssl->conf->tls13_sig_algs;
         *sig_alg != MBEDTLS_TLS13_SIG_NONE; sig_alg++ )
    {
        MBEDTLS_SSL_CHK_BUF_PTR( p, end, 2 );
        MBEDTLS_PUT_UINT16_BE( *sig_alg, p, 0 );
        p += 2;
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "signature scheme [%x]", *sig_alg ) );
    }

    /* Length of supported_signature_algorithms */
    supported_sig_alg_len = p - supported_sig_alg_ptr;
    if( supported_sig_alg_len == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "No signature algorithms defined." ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    /* Write extension_type */
    MBEDTLS_PUT_UINT16_BE( MBEDTLS_TLS_EXT_SIG_ALG, buf, 0 );
    /* Write extension_data_length */
    MBEDTLS_PUT_UINT16_BE( supported_sig_alg_len + 2, buf, 2 );
    /* Write length of supported_signature_algorithms */
    MBEDTLS_PUT_UINT16_BE( supported_sig_alg_len, buf, 4 );

    /* Output the total length of signature algorithms extension. */
    *olen = p - buf;

    ssl->handshake->extensions_present |= MBEDTLS_SSL_EXT_SIG_ALG;
    return( 0 );
}

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/*
 *
 * STATE HANDLING: Incoming Certificate, client-side only currently.
 *
 */

/*
 * Implementation
 */

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
/*
 * Structure of Certificate message:
 *
 * enum {
 *     X509(0),
 *     RawPublicKey(2),
 *     (255)
 * } CertificateType;
 *
 * struct {
 *     select (certificate_type) {
 *         case RawPublicKey:
 *           * From RFC 7250 ASN.1_subjectPublicKeyInfo *
 *           opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
 *         case X509:
 *           opaque cert_data<1..2^24-1>;
 *     };
 *     Extension extensions<0..2^16-1>;
 * } CertificateEntry;
 *
 * struct {
 *     opaque certificate_request_context<0..2^8-1>;
 *     CertificateEntry certificate_list<0..2^24-1>;
 * } Certificate;
 *
 */

/* Parse certificate chain send by the server. */
static int ssl_tls13_parse_certificate( mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        const unsigned char *end )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t certificate_request_context_len = 0;
    size_t certificate_list_len = 0;
    const unsigned char *p = buf;
    const unsigned char *certificate_list_end;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 4 );
    certificate_request_context_len = p[0];
    certificate_list_len = MBEDTLS_GET_UINT24_BE( p, 1 );
    p += 4;

    /* In theory, the certificate list can be up to 2^24 Bytes, but we don't
     * support anything beyond 2^16 = 64K.
     */
    if( ( certificate_request_context_len != 0 ) ||
        ( certificate_list_len >= 0x10000 ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    /* In case we tried to reuse a session but it failed */
    if( ssl->session_negotiate->peer_cert != NULL )
    {
        mbedtls_x509_crt_free( ssl->session_negotiate->peer_cert );
        mbedtls_free( ssl->session_negotiate->peer_cert );
    }

    if( ( ssl->session_negotiate->peer_cert =
          mbedtls_calloc( 1, sizeof( mbedtls_x509_crt ) ) ) == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc( %" MBEDTLS_PRINTF_SIZET " bytes ) failed",
                                    sizeof( mbedtls_x509_crt ) ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                                      MBEDTLS_ERR_SSL_ALLOC_FAILED );
        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    mbedtls_x509_crt_init( ssl->session_negotiate->peer_cert );

    certificate_list_end = p + certificate_list_len;
    while( p < certificate_list_end )
    {
        size_t cert_data_len, extensions_len;

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, certificate_list_end, 3 );
        cert_data_len = MBEDTLS_GET_UINT24_BE( p, 0 );
        p += 3;

        /* In theory, the CRT can be up to 2^24 Bytes, but we don't support
         * anything beyond 2^16 = 64K. Otherwise as in the TLS 1.2 code,
         * check that we have a minimum of 128 bytes of data, this is not
         * clear why we need that though.
         */
        if( ( cert_data_len < 128 ) || ( cert_data_len >= 0x10000 ) )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad Certificate message" ) );
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                          MBEDTLS_ERR_SSL_DECODE_ERROR );
            return( MBEDTLS_ERR_SSL_DECODE_ERROR );
        }

        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, certificate_list_end, cert_data_len );
        ret = mbedtls_x509_crt_parse_der( ssl->session_negotiate->peer_cert,
                                          p, cert_data_len );

        switch( ret )
        {
            case 0: /*ok*/
                break;
            case MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + MBEDTLS_ERR_OID_NOT_FOUND:
                /* Ignore certificate with an unknown algorithm: maybe a
                   prior certificate was already trusted. */
                break;

            case MBEDTLS_ERR_X509_ALLOC_FAILED:
                MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
                                              MBEDTLS_ERR_X509_ALLOC_FAILED );
                MBEDTLS_SSL_DEBUG_RET( 1, " mbedtls_x509_crt_parse_der", ret );
                return( ret );

            case MBEDTLS_ERR_X509_UNKNOWN_VERSION:
                MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT,
                                              MBEDTLS_ERR_X509_UNKNOWN_VERSION );
                MBEDTLS_SSL_DEBUG_RET( 1, " mbedtls_x509_crt_parse_der", ret );
                return( ret );

            default:
                MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_BAD_CERT,
                                              ret );
                MBEDTLS_SSL_DEBUG_RET( 1, " mbedtls_x509_crt_parse_der", ret );
                return( ret );
        }

        p += cert_data_len;

        /* Certificate extensions length */
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, certificate_list_end, 2 );
        extensions_len = MBEDTLS_GET_UINT16_BE( p, 0 );
        p += 2;
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, certificate_list_end, extensions_len );
        p += extensions_len;
    }

    /* Check that all the message is consumed. */
    if( p != end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad Certificate message" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR, \
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    MBEDTLS_SSL_DEBUG_CRT( 3, "peer certificate", ssl->session_negotiate->peer_cert );

    return( ret );
}
#else
static int ssl_tls13_parse_certificate( mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        const unsigned char *end )
{
    ((void) ssl);
    ((void) buf);
    ((void) end);
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
/* Validate certificate chain sent by the server. */
static int ssl_tls13_validate_certificate( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    mbedtls_x509_crt *ca_chain;
    mbedtls_x509_crl *ca_crl;
    uint32_t verify_result = 0;

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if( ssl->handshake->sni_ca_chain != NULL )
    {
        ca_chain = ssl->handshake->sni_ca_chain;
        ca_crl = ssl->handshake->sni_ca_crl;
    }
    else
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
    {
        ca_chain = ssl->conf->ca_chain;
        ca_crl = ssl->conf->ca_crl;
    }

    /*
     * Main check: verify certificate
     */
    ret = mbedtls_x509_crt_verify_with_profile(
        ssl->session_negotiate->peer_cert,
        ca_chain, ca_crl,
        ssl->conf->cert_profile,
        ssl->hostname,
        &verify_result,
        ssl->conf->f_vrfy, ssl->conf->p_vrfy );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "x509_verify_cert", ret );
    }

    /*
     * Secondary checks: always done, but change 'ret' only if it was 0
     */

#if defined(MBEDTLS_ECP_C)
    {
        const mbedtls_pk_context *pk = &ssl->session_negotiate->peer_cert->pk;

        /* If certificate uses an EC key, make sure the curve is OK */
        if( mbedtls_pk_can_do( pk, MBEDTLS_PK_ECKEY ) &&
            mbedtls_ssl_check_curve( ssl, mbedtls_pk_ec( *pk )->grp.id ) != 0 )
        {
            verify_result |= MBEDTLS_X509_BADCERT_BAD_KEY;

            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate ( EC key curve )" ) );
            if( ret == 0 )
                ret = MBEDTLS_ERR_SSL_BAD_CERTIFICATE;
        }
    }
#endif /* MBEDTLS_ECP_C */

    if( mbedtls_ssl_check_cert_usage( ssl->session_negotiate->peer_cert,
                                      ssl->handshake->ciphersuite_info,
                                      !ssl->conf->endpoint,
                                      &verify_result ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate ( usage extensions )" ) );
        if( ret == 0 )
            ret = MBEDTLS_ERR_SSL_BAD_CERTIFICATE;
    }


    if( ca_chain == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no CA chain" ) );
        ret = MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED;
    }

    if( ret != 0 )
    {
        /* The certificate may have been rejected for several reasons.
           Pick one and send the corresponding alert. Which alert to send
           may be a subject of debate in some cases. */
        if( verify_result & MBEDTLS_X509_BADCERT_OTHER )
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED, ret );
        else if( verify_result & MBEDTLS_X509_BADCERT_CN_MISMATCH )
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_BAD_CERT, ret );
        else if( verify_result & ( MBEDTLS_X509_BADCERT_KEY_USAGE |
                                   MBEDTLS_X509_BADCERT_EXT_KEY_USAGE |
                                   MBEDTLS_X509_BADCERT_NS_CERT_TYPE |
                                   MBEDTLS_X509_BADCERT_BAD_PK |
                                   MBEDTLS_X509_BADCERT_BAD_KEY ) )
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT, ret );
        else if( verify_result & MBEDTLS_X509_BADCERT_EXPIRED )
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_CERT_EXPIRED, ret );
        else if( verify_result & MBEDTLS_X509_BADCERT_REVOKED )
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_CERT_REVOKED, ret );
        else if( verify_result & MBEDTLS_X509_BADCERT_NOT_TRUSTED )
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA, ret );
        else
            MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN, ret );
    }

#if defined(MBEDTLS_DEBUG_C)
    if( verify_result != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "! Certificate verification flags %08x",
                                    (unsigned int) verify_result ) );
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Certificate verification flags clear" ) );
    }
#endif /* MBEDTLS_DEBUG_C */

    ssl->session_negotiate->verify_result = verify_result;
    return( ret );
}
#else /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
static int ssl_tls13_validate_certificate( mbedtls_ssl_context *ssl )
{
    ((void) ssl);
    return( MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE );
}
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */

int mbedtls_ssl_tls13_process_certificate( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate" ) );

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls1_3_fetch_handshake_msg(
                          ssl, MBEDTLS_SSL_HS_CERTIFICATE,
                          &buf, &buf_len ) );

    /* Parse the certificate chain sent by the peer. */
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_parse_certificate( ssl, buf, buf + buf_len ) );
    /* Validate the certificate chain and set the verification results. */
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_validate_certificate( ssl ) );

    mbedtls_ssl_tls1_3_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_CERTIFICATE,
                                               buf, buf_len );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse certificate" ) );
#else
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
    return( ret );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#endif /* MBEDTLS_SSL_TLS_C */
