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

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)

#include <string.h>

#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform.h"
#include "mbedtls/constant_time.h"
#include <string.h>

#include "ssl_misc.h"
#include "ssl_tls13_keys.h"
#include "ssl_debug_helpers.h"

int mbedtls_ssl_tls13_fetch_handshake_msg( mbedtls_ssl_context *ssl,
                                           unsigned hs_type,
                                           unsigned char **buf,
                                           size_t *buf_len )
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
    *buf = ssl->in_msg   + 4;
    *buf_len = ssl->in_hslen - 4;

cleanup:

    return( ret );
}

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
/* mbedtls_ssl_tls13_parse_sig_alg_ext()
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
 */
int mbedtls_ssl_tls13_parse_sig_alg_ext( mbedtls_ssl_context *ssl,
                                         const unsigned char *buf,
                                         const unsigned char *end )
{
    const unsigned char *p = buf;
    size_t supported_sig_algs_len = 0;
    const unsigned char *supported_sig_algs_end;
    uint16_t sig_alg;
    uint32_t common_idx = 0;

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    supported_sig_algs_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    memset( ssl->handshake->received_sig_algs, 0,
            sizeof(ssl->handshake->received_sig_algs) );

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, supported_sig_algs_len );
    supported_sig_algs_end = p + supported_sig_algs_len;
    while( p < supported_sig_algs_end )
    {
        MBEDTLS_SSL_CHK_BUF_READ_PTR( p, supported_sig_algs_end, 2 );
        sig_alg = MBEDTLS_GET_UINT16_BE( p, 0 );
        p += 2;

        MBEDTLS_SSL_DEBUG_MSG( 4, ( "received signature algorithm: 0x%x",
                                    sig_alg ) );

        if( ! mbedtls_ssl_sig_alg_is_offered( ssl, sig_alg ) ||
            ! mbedtls_ssl_sig_alg_is_supported( ssl, sig_alg ) )
            continue;

        if( common_idx + 1 < MBEDTLS_RECEIVED_SIG_ALGS_SIZE )
        {
            ssl->handshake->received_sig_algs[common_idx] = sig_alg;
            common_idx += 1;
        }
    }
    /* Check that we consumed all the message. */
    if( p != end )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
            ( "Signature algorithms extension length misaligned" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    if( common_idx == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "no signature algorithm in common" ) );
        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    ssl->handshake->received_sig_algs[common_idx] = MBEDTLS_TLS1_3_SIG_NONE;
    return( 0 );
}

/*
 * STATE HANDLING: Read CertificateVerify
 */
/* Macro to express the maximum length of the verify structure.
 *
 * The structure is computed per TLS 1.3 specification as:
 *   - 64 bytes of octet 32,
 *   - 33 bytes for the context string
 *        (which is either "TLS 1.3, client CertificateVerify"
 *         or "TLS 1.3, server CertificateVerify"),
 *   - 1 byte for the octet 0x0, which serves as a separator,
 *   - 32 or 48 bytes for the Transcript-Hash(Handshake Context, Certificate)
 *     (depending on the size of the transcript_hash)
 *
 * This results in a total size of
 * - 130 bytes for a SHA256-based transcript hash, or
 *   (64 + 33 + 1 + 32 bytes)
 * - 146 bytes for a SHA384-based transcript hash.
 *   (64 + 33 + 1 + 48 bytes)
 *
 */
#define SSL_VERIFY_STRUCT_MAX_SIZE  ( 64 +                          \
                                      33 +                          \
                                       1 +                          \
                                      MBEDTLS_TLS1_3_MD_MAX_SIZE    \
                                    )

/*
 * The ssl_tls13_create_verify_structure() creates the verify structure.
 * As input, it requires the transcript hash.
 *
 * The caller has to ensure that the buffer has size at least
 * SSL_VERIFY_STRUCT_MAX_SIZE bytes.
 */
static void ssl_tls13_create_verify_structure( const unsigned char *transcript_hash,
                                               size_t transcript_hash_len,
                                               unsigned char *verify_buffer,
                                               size_t *verify_buffer_len,
                                               int from )
{
    size_t idx;

    /* RFC 8446, Section 4.4.3:
     *
     * The digital signature [in the CertificateVerify message] is then
     * computed over the concatenation of:
     * -  A string that consists of octet 32 (0x20) repeated 64 times
     * -  The context string
     * -  A single 0 byte which serves as the separator
     * -  The content to be signed
     */
    memset( verify_buffer, 0x20, 64 );
    idx = 64;

    if( from == MBEDTLS_SSL_IS_CLIENT )
    {
        memcpy( verify_buffer + idx, MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( client_cv ) );
        idx += MBEDTLS_SSL_TLS1_3_LBL_LEN( client_cv );
    }
    else
    { /* from == MBEDTLS_SSL_IS_SERVER */
        memcpy( verify_buffer + idx, MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( server_cv ) );
        idx += MBEDTLS_SSL_TLS1_3_LBL_LEN( server_cv );
    }

    verify_buffer[idx++] = 0x0;

    memcpy( verify_buffer + idx, transcript_hash, transcript_hash_len );
    idx += transcript_hash_len;

    *verify_buffer_len = idx;
}

static int ssl_tls13_parse_certificate_verify( mbedtls_ssl_context *ssl,
                                               const unsigned char *buf,
                                               const unsigned char *end,
                                               const unsigned char *verify_buffer,
                                               size_t verify_buffer_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    uint16_t algorithm;
    size_t signature_len;
    mbedtls_pk_type_t sig_alg;
    mbedtls_md_type_t md_alg;
    unsigned char verify_hash[MBEDTLS_MD_MAX_SIZE];
    size_t verify_hash_len;

    void const *options = NULL;
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    mbedtls_pk_rsassa_pss_options rsassa_pss_options;
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */

    /*
     * struct {
     *     SignatureScheme algorithm;
     *     opaque signature<0..2^16-1>;
     * } CertificateVerify;
     */
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    algorithm = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;

    /* RFC 8446 section 4.4.3
     *
     * If the CertificateVerify message is sent by a server, the signature algorithm
     * MUST be one offered in the client's "signature_algorithms" extension unless
     * no valid certificate chain can be produced without unsupported algorithms
     *
     * RFC 8446 section 4.4.2.2
     *
     * If the client cannot construct an acceptable chain using the provided
     * certificates and decides to abort the handshake, then it MUST abort the handshake
     * with an appropriate certificate-related alert (by default, "unsupported_certificate").
     *
     * Check if algorithm is an offered signature algorithm.
     */
    if( ! mbedtls_ssl_sig_alg_is_offered( ssl, algorithm ) )
    {
        /* algorithm not in offered signature algorithms list */
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Received signature algorithm(%04x) is not "
                                    "offered.",
                                    ( unsigned int ) algorithm ) );
        goto error;
    }

    if( mbedtls_ssl_tls13_get_pk_type_and_md_alg_from_sig_alg(
                                        algorithm, &sig_alg, &md_alg ) != 0 )
    {
        goto error;
    }

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Certificate Verify: Signature algorithm ( %04x )",
                                ( unsigned int ) algorithm ) );

    /*
     * Check the certificate's key type matches the signature alg
     */
    if( !mbedtls_pk_can_do( &ssl->session_negotiate->peer_cert->pk, sig_alg ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "signature algorithm doesn't match cert key" ) );
        goto error;
    }

    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, 2 );
    signature_len = MBEDTLS_GET_UINT16_BE( p, 0 );
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR( p, end, signature_len );

    /* Hash verify buffer with indicated hash function */
    switch( md_alg )
    {
#if defined(MBEDTLS_SHA256_C)
        case MBEDTLS_MD_SHA256:
            verify_hash_len = 32;
            ret = mbedtls_sha256( verify_buffer, verify_buffer_len, verify_hash, 0 );
            break;
#endif /* MBEDTLS_SHA256_C */

#if defined(MBEDTLS_SHA384_C)
        case MBEDTLS_MD_SHA384:
            verify_hash_len = 48;
            ret = mbedtls_sha512( verify_buffer, verify_buffer_len, verify_hash, 1 );
            break;
#endif /* MBEDTLS_SHA384_C */

#if defined(MBEDTLS_SHA512_C)
        case MBEDTLS_MD_SHA512:
            verify_hash_len = 64;
            ret = mbedtls_sha512( verify_buffer, verify_buffer_len, verify_hash, 0 );
            break;
#endif /* MBEDTLS_SHA512_C */

        default:
            ret = MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
            break;
    }

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "hash computation error", ret );
        goto error;
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "verify hash", verify_hash, verify_hash_len );
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    if( sig_alg == MBEDTLS_PK_RSASSA_PSS )
    {
        const mbedtls_md_info_t* md_info;
        rsassa_pss_options.mgf1_hash_id = md_alg;
        if( ( md_info = mbedtls_md_info_from_type( md_alg ) ) == NULL )
        {
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }
        rsassa_pss_options.expected_salt_len = mbedtls_md_get_size( md_info );
        options = (const void*) &rsassa_pss_options;
    }
#endif /* MBEDTLS_X509_RSASSA_PSS_SUPPORT */

    if( ( ret = mbedtls_pk_verify_ext( sig_alg, options,
                                       &ssl->session_negotiate->peer_cert->pk,
                                       md_alg, verify_hash, verify_hash_len,
                                       p, signature_len ) ) == 0 )
    {
        return( 0 );
    }
    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_pk_verify_ext", ret );

error:
    /* RFC 8446 section 4.4.3
     *
     * If the verification fails, the receiver MUST terminate the handshake
     * with a "decrypt_error" alert.
    */
    MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR,
                                  MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );

}
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

int mbedtls_ssl_tls13_process_certificate_verify( mbedtls_ssl_context *ssl )
{

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char verify_buffer[SSL_VERIFY_STRUCT_MAX_SIZE];
    size_t verify_buffer_len;
    unsigned char transcript[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    size_t transcript_len;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate verify" ) );

    MBEDTLS_SSL_PROC_CHK(
        mbedtls_ssl_tls13_fetch_handshake_msg( ssl,
                MBEDTLS_SSL_HS_CERTIFICATE_VERIFY, &buf, &buf_len ) );

    /* Need to calculate the hash of the transcript first
     * before reading the message since otherwise it gets
     * included in the transcript
     */
    ret = mbedtls_ssl_get_handshake_transcript( ssl,
                            ssl->handshake->ciphersuite_info->mac,
                            transcript, sizeof( transcript ),
                            &transcript_len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_PEND_FATAL_ALERT(
            MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR,
            MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_BUF( 3, "handshake hash", transcript, transcript_len );

    /* Create verify structure */
    ssl_tls13_create_verify_structure( transcript,
                                       transcript_len,
                                       verify_buffer,
                                       &verify_buffer_len,
                                       ( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT ) ?
                                         MBEDTLS_SSL_IS_SERVER :
                                         MBEDTLS_SSL_IS_CLIENT );

    /* Process the message contents */
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_parse_certificate_verify( ssl, buf,
                            buf + buf_len, verify_buffer, verify_buffer_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY,
                                        buf, buf_len );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse certificate verify" ) );
    MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_process_certificate_verify", ret );
    return( ret );
#else
    ((void) ssl);
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */
}

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

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_fetch_handshake_msg(
                          ssl, MBEDTLS_SSL_HS_CERTIFICATE,
                          &buf, &buf_len ) );

    /* Parse the certificate chain sent by the peer. */
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_parse_certificate( ssl, buf, buf + buf_len ) );
    /* Validate the certificate chain and set the verification results. */
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_validate_certificate( ssl ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_CERTIFICATE,
                                        buf, buf_len );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse certificate" ) );
#else
    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
#endif /* MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED */
    return( ret );
}
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
/*
 *  enum {
 *        X509(0),
 *        RawPublicKey(2),
 *        (255)
 *    } CertificateType;
 *
 *    struct {
 *        select (certificate_type) {
 *            case RawPublicKey:
 *              // From RFC 7250 ASN.1_subjectPublicKeyInfo
 *              opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
 *
 *            case X509:
 *              opaque cert_data<1..2^24-1>;
 *        };
 *        Extension extensions<0..2^16-1>;
 *    } CertificateEntry;
 *
 *    struct {
 *        opaque certificate_request_context<0..2^8-1>;
 *        CertificateEntry certificate_list<0..2^24-1>;
 *    } Certificate;
 */
static int ssl_tls13_write_certificate_body( mbedtls_ssl_context *ssl,
                                             unsigned char *buf,
                                             unsigned char *end,
                                             size_t *out_len )
{
    const mbedtls_x509_crt *crt = mbedtls_ssl_own_cert( ssl );
    unsigned char *p = buf;
    unsigned char *certificate_request_context =
                                    ssl->handshake->certificate_request_context;
    unsigned char certificate_request_context_len =
                                ssl->handshake->certificate_request_context_len;
    unsigned char *p_certificate_list_len;


    /* ...
     * opaque certificate_request_context<0..2^8-1>;
     * ...
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, certificate_request_context_len + 1 );
    *p++ = certificate_request_context_len;
    if( certificate_request_context_len > 0 )
    {
        memcpy( p, certificate_request_context, certificate_request_context_len );
        p += certificate_request_context_len;
    }

    /* ...
     * CertificateEntry certificate_list<0..2^24-1>;
     * ...
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 3 );
    p_certificate_list_len = p;
    p += 3;

    MBEDTLS_SSL_DEBUG_CRT( 3, "own certificate", crt );

    while( crt != NULL )
    {
        size_t cert_data_len = crt->raw.len;

        MBEDTLS_SSL_CHK_BUF_PTR( p, end, cert_data_len + 3 + 2 );
        MBEDTLS_PUT_UINT24_BE( cert_data_len, p, 0 );
        p += 3;

        memcpy( p, crt->raw.p, cert_data_len );
        p += cert_data_len;
        crt = crt->next;

        /* Currently, we don't have any certificate extensions defined.
         * Hence, we are sending an empty extension with length zero.
         */
        MBEDTLS_PUT_UINT24_BE( 0, p, 0 );
        p += 2;
    }

    MBEDTLS_PUT_UINT24_BE( p - p_certificate_list_len - 3,
                           p_certificate_list_len, 0 );

    *out_len = p - buf;

    return( 0 );
}

int mbedtls_ssl_tls13_write_certificate( mbedtls_ssl_context *ssl )
{
    int ret;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write certificate" ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg( ssl,
                          MBEDTLS_SSL_HS_CERTIFICATE, &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_certificate_body( ssl,
                                                            buf,
                                                            buf + buf_len,
                                                            &msg_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_CERTIFICATE,
                                        buf, msg_len );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg(
                              ssl, buf_len, msg_len ) );
cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write certificate" ) );
    return( ret );
}

/*
 * STATE HANDLING: Output Certificate Verify
 */
static int ssl_tls13_get_sig_alg_from_pk( mbedtls_ssl_context *ssl,
                                          mbedtls_pk_context *own_key,
                                          uint16_t *algorithm )
{
    mbedtls_pk_type_t sig = mbedtls_ssl_sig_from_pk( own_key );
    /* Determine the size of the key */
    size_t own_key_size = mbedtls_pk_get_bitlen( own_key );
    *algorithm = MBEDTLS_TLS1_3_SIG_NONE;
    ((void) own_key_size);

    switch( sig )
    {
#if defined(MBEDTLS_ECDSA_C)
        case MBEDTLS_SSL_SIG_ECDSA:
            switch( own_key_size )
            {
                case 256:
                    *algorithm = MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256;
                    return( 0 );
                case 384:
                    *algorithm = MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384;
                    return( 0 );
                case 521:
                    *algorithm = MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512;
                    return( 0 );
                default:
                    MBEDTLS_SSL_DEBUG_MSG( 3,
                                           ( "unknown key size: %"
                                             MBEDTLS_PRINTF_SIZET " bits",
                                             own_key_size ) );
                    break;
            }
            break;
#endif /* MBEDTLS_ECDSA_C */

#if defined(MBEDTLS_RSA_C)
        case MBEDTLS_SSL_SIG_RSA:
#if defined(MBEDTLS_PKCS1_V21)
#if defined(MBEDTLS_SHA256_C)
            if( own_key_size <= 2048 &&
                mbedtls_ssl_sig_alg_is_received( ssl,
                                    MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256 ) )
            {
                *algorithm = MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256;
                return( 0 );
            }
            else
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA384_C)
            if( own_key_size <= 3072 &&
                mbedtls_ssl_sig_alg_is_received( ssl,
                                    MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384 ) )
            {
                *algorithm = MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384;
                return( 0 );
            }
            else
#endif /* MBEDTLS_SHA384_C */
#if defined(MBEDTLS_SHA512_C)
            if( own_key_size <= 4096 &&
                mbedtls_ssl_sig_alg_is_received( ssl,
                                    MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512 ) )
            {
                *algorithm = MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512;
                return( 0 );
            }
            else
#endif /* MBEDTLS_SHA512_C */
#endif /* MBEDTLS_PKCS1_V21 */
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_SHA256_C)
            if( own_key_size <= 2048 &&
                mbedtls_ssl_sig_alg_is_received( ssl,
                                    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256 ) )
            {
                *algorithm = MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256;
                return( 0 );
            }
            else
#endif /* MBEDTLS_SHA256_C */
#if defined(MBEDTLS_SHA384_C)
            if( own_key_size <= 3072 &&
                mbedtls_ssl_sig_alg_is_received( ssl,
                                    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384 ) )
            {
                *algorithm = MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384;
                return( 0 );
            }
            else
#endif /* MBEDTLS_SHA384_C */
#if defined(MBEDTLS_SHA512_C)
            if( own_key_size <= 4096 &&
                mbedtls_ssl_sig_alg_is_received( ssl,
                                    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512 ) )
            {
                *algorithm = MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512;
                return( 0 );
            }
            else
#endif /* MBEDTLS_SHA512_C */
#endif /* MBEDTLS_PKCS1_V15 */
            {
                MBEDTLS_SSL_DEBUG_MSG( 3,
                                       ( "unknown key size: %"
                                         MBEDTLS_PRINTF_SIZET " bits",
                                         own_key_size ) );
            }
            break;
#endif /* MBEDTLS_RSA_C */
        default:
            MBEDTLS_SSL_DEBUG_MSG( 1,
                                   ( "unkown signature type : %u", sig ) );
            break;
    }
    return( -1 );
}

static int ssl_tls13_write_certificate_verify_body( mbedtls_ssl_context *ssl,
                                                    unsigned char *buf,
                                                    unsigned char *end,
                                                    size_t *out_len )
{
    int ret;
    unsigned char *p = buf;
    mbedtls_pk_context *own_key;

    unsigned char handshake_hash[ MBEDTLS_TLS1_3_MD_MAX_SIZE ];
    size_t handshake_hash_len;
    unsigned char verify_buffer[ SSL_VERIFY_STRUCT_MAX_SIZE ];
    size_t verify_buffer_len;
    mbedtls_pk_type_t pk_type = MBEDTLS_PK_NONE;
    mbedtls_md_type_t md_alg = MBEDTLS_MD_NONE;
    uint16_t algorithm = MBEDTLS_TLS1_3_SIG_NONE;
    size_t signature_len = 0;
    const mbedtls_md_info_t *md_info;
    unsigned char verify_hash[ MBEDTLS_MD_MAX_SIZE ];
    size_t verify_hash_len;

    *out_len = 0;

    own_key = mbedtls_ssl_own_key( ssl );
    if( own_key == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    ret = mbedtls_ssl_get_handshake_transcript( ssl,
                                        ssl->handshake->ciphersuite_info->mac,
                                        handshake_hash,
                                        sizeof( handshake_hash ),
                                        &handshake_hash_len );
    if( ret != 0 )
        return( ret );

    MBEDTLS_SSL_DEBUG_BUF( 3, "handshake hash",
        handshake_hash,
        handshake_hash_len);

    ssl_tls13_create_verify_structure( handshake_hash, handshake_hash_len,
                                       verify_buffer, &verify_buffer_len,
                                       ssl->conf->endpoint );

    /*
     *  struct {
     *    SignatureScheme algorithm;
     *    opaque signature<0..2^16-1>;
     *  } CertificateVerify;
     */
    ret = ssl_tls13_get_sig_alg_from_pk( ssl, own_key, &algorithm );
    if( ret != 0 || ! mbedtls_ssl_sig_alg_is_received( ssl, algorithm ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1,
                    ( "signature algorithm not in received or offered list." ) );

        MBEDTLS_SSL_DEBUG_MSG( 1, ( "Signature algorithm is %s",
                                    mbedtls_ssl_sig_alg_to_str( algorithm ) ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }

    if( mbedtls_ssl_tls13_get_pk_type_and_md_alg_from_sig_alg(
                                        algorithm, &pk_type, &md_alg ) != 0 )
    {
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR  );
    }

    /* Check there is space for the algorithm identifier (2 bytes) and the
     * signature length (2 bytes).
     */
    MBEDTLS_SSL_CHK_BUF_PTR( p, end, 4 );
    MBEDTLS_PUT_UINT16_BE( algorithm, p, 0 );
    p += 2;

    /* Hash verify buffer with indicated hash function */
    md_info = mbedtls_md_info_from_type( md_alg );
    if( md_info == NULL )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    ret = mbedtls_md( md_info, verify_buffer, verify_buffer_len, verify_hash );
    if( ret != 0 )
        return( ret );

    verify_hash_len = mbedtls_md_get_size( md_info );
    MBEDTLS_SSL_DEBUG_BUF( 3, "verify hash", verify_hash, verify_hash_len );

    if( ( ret = mbedtls_pk_sign_ext( pk_type, own_key,
                        md_alg, verify_hash, verify_hash_len,
                        p + 2, (size_t)( end - ( p + 2 ) ), &signature_len,
                        ssl->conf->f_rng, ssl->conf->p_rng ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_pk_sign", ret );
        return( ret );
    }

    MBEDTLS_PUT_UINT16_BE( signature_len, p, 0 );
    p += 2 + signature_len;

    *out_len = (size_t)( p - buf );

    return( ret );
}

int mbedtls_ssl_tls13_write_certificate_verify( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write certificate verify" ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg( ssl,
                MBEDTLS_SSL_HS_CERTIFICATE_VERIFY, &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_certificate_verify_body(
                                ssl, buf, buf + buf_len, &msg_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_CERTIFICATE_VERIFY,
                                        buf, msg_len );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg(
                                ssl, buf_len, msg_len ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write certificate verify" ) );
    return( ret );
}

#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED */

/*
 *
 * STATE HANDLING: Incoming Finished message.
 */
/*
 * Implementation
 */

static int ssl_tls13_preprocess_finished_message( mbedtls_ssl_context *ssl )
{
    int ret;

    ret = mbedtls_ssl_tls13_calculate_verify_data( ssl,
                    ssl->handshake->state_local.finished_in.digest,
                    sizeof( ssl->handshake->state_local.finished_in.digest ),
                    &ssl->handshake->state_local.finished_in.digest_len,
                    ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT ?
                        MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_calculate_verify_data", ret );
        return( ret );
    }

    return( 0 );
}

static int ssl_tls13_parse_finished_message( mbedtls_ssl_context *ssl,
                                             const unsigned char *buf,
                                             const unsigned char *end )
{
    /*
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     */
    const unsigned char *expected_verify_data =
        ssl->handshake->state_local.finished_in.digest;
    size_t expected_verify_data_len =
        ssl->handshake->state_local.finished_in.digest_len;
    /* Structural validation */
    if( (size_t)( end - buf ) != expected_verify_data_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                      MBEDTLS_ERR_SSL_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_DECODE_ERROR );
    }

    MBEDTLS_SSL_DEBUG_BUF( 4, "verify_data (self-computed):",
                           expected_verify_data,
                           expected_verify_data_len );
    MBEDTLS_SSL_DEBUG_BUF( 4, "verify_data (received message):", buf,
                           expected_verify_data_len );

    /* Semantic validation */
    if( mbedtls_ct_memcmp( buf,
                           expected_verify_data,
                           expected_verify_data_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );

        MBEDTLS_SSL_PEND_FATAL_ALERT( MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR,
                                      MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
        return( MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }
    return( 0 );
}

#if defined(MBEDTLS_SSL_CLI_C)
static int ssl_tls13_postprocess_server_finished_message( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ssl_key_set traffic_keys;
    mbedtls_ssl_transform *transform_application = NULL;

    ret = mbedtls_ssl_tls13_key_schedule_stage_application( ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
           "mbedtls_ssl_tls13_key_schedule_stage_application", ret );
        goto cleanup;
    }

    ret = mbedtls_ssl_tls13_generate_application_keys( ssl, &traffic_keys );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1,
            "mbedtls_ssl_tls13_generate_application_keys", ret );
        goto cleanup;
    }

    transform_application =
        mbedtls_calloc( 1, sizeof( mbedtls_ssl_transform ) );
    if( transform_application == NULL )
    {
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto cleanup;
    }

    ret = mbedtls_ssl_tls13_populate_transform(
                                    transform_application,
                                    ssl->conf->endpoint,
                                    ssl->session_negotiate->ciphersuite,
                                    &traffic_keys,
                                    ssl );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls13_populate_transform", ret );
        goto cleanup;
    }

    ssl->transform_application = transform_application;

cleanup:

    mbedtls_platform_zeroize( &traffic_keys, sizeof( traffic_keys ) );
    if( ret != 0 )
    {
        mbedtls_free( transform_application );
        MBEDTLS_SSL_PEND_FATAL_ALERT(
                MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE );
    }
    return( ret );
}
#endif /* MBEDTLS_SSL_CLI_C */

static int ssl_tls13_postprocess_finished_message( mbedtls_ssl_context *ssl )
{

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        return( ssl_tls13_postprocess_server_finished_message( ssl ) );
    }
#else
    ((void) ssl);
#endif /* MBEDTLS_SSL_CLI_C */

    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
}

int mbedtls_ssl_tls13_process_finished_message( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse finished message" ) );

    /* Preprocessing step: Compute handshake digest */
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_preprocess_finished_message( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_tls13_fetch_handshake_msg( ssl,
                                              MBEDTLS_SSL_HS_FINISHED,
                                              &buf, &buf_len ) );
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_parse_finished_message( ssl, buf, buf + buf_len ) );
    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_FINISHED,
                                        buf, buf_len );
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_postprocess_finished_message( ssl ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse finished message" ) );
    return( ret );
}

/*
 *
 * STATE HANDLING: Write and send Finished message.
 *
 */
/*
 * Implement
 */

static int ssl_tls13_prepare_finished_message( mbedtls_ssl_context *ssl )
{
    int ret;

    /* Compute transcript of handshake up to now. */
    ret = mbedtls_ssl_tls13_calculate_verify_data( ssl,
                    ssl->handshake->state_local.finished_out.digest,
                    sizeof( ssl->handshake->state_local.finished_out.digest ),
                    &ssl->handshake->state_local.finished_out.digest_len,
                    ssl->conf->endpoint );

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "calculate_verify_data failed", ret );
        return( ret );
    }

    return( 0 );
}

static int ssl_tls13_finalize_finished_message( mbedtls_ssl_context *ssl )
{
    // TODO: Add back resumption keys calculation after MVP.
    ((void) ssl);

    return( 0 );
}

static int ssl_tls13_write_finished_message_body( mbedtls_ssl_context *ssl,
                                                  unsigned char *buf,
                                                  unsigned char *end,
                                                  size_t *out_len )
{
    size_t verify_data_len = ssl->handshake->state_local.finished_out.digest_len;
    /*
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     */
    MBEDTLS_SSL_CHK_BUF_PTR( buf, end, verify_data_len );

    memcpy( buf, ssl->handshake->state_local.finished_out.digest,
            verify_data_len );

    *out_len = verify_data_len;
    return( 0 );
}

/* Main entry point: orchestrates the other functions */
int mbedtls_ssl_tls13_write_finished_message( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *buf;
    size_t buf_len, msg_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write finished message" ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_prepare_finished_message( ssl ) );

    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_start_handshake_msg( ssl,
                              MBEDTLS_SSL_HS_FINISHED, &buf, &buf_len ) );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_finished_message_body(
                              ssl, buf, buf + buf_len, &msg_len ) );

    mbedtls_ssl_add_hs_msg_to_checksum( ssl, MBEDTLS_SSL_HS_FINISHED,
                                        buf, msg_len );

    MBEDTLS_SSL_PROC_CHK( ssl_tls13_finalize_finished_message( ssl ) );
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_finish_handshake_msg(
                              ssl, buf_len, msg_len ) );
cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write finished message" ) );
    return( ret );
}

void mbedtls_ssl_tls13_handshake_wrapup( mbedtls_ssl_context *ssl )
{

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "=> handshake wrapup" ) );

    /*
     * Free the previous session and switch to the current one.
     */
    if( ssl->session )
    {
        mbedtls_ssl_session_free( ssl->session );
        mbedtls_free( ssl->session );
    }
    ssl->session = ssl->session_negotiate;
    ssl->session_negotiate = NULL;

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "<= handshake wrapup" ) );
}

/*
 *
 * STATE HANDLING: Write ChangeCipherSpec
 *
 */
#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
static int ssl_tls13_write_change_cipher_spec_body( mbedtls_ssl_context *ssl,
                                                    unsigned char *buf,
                                                    unsigned char *end,
                                                    size_t *olen )
{
    ((void) ssl);

    MBEDTLS_SSL_CHK_BUF_PTR( buf, end, 1 );
    buf[0] = 1;
    *olen = 1;

    return( 0 );
}

int mbedtls_ssl_tls13_write_change_cipher_spec( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write change cipher spec" ) );

    /* Write CCS message */
    MBEDTLS_SSL_PROC_CHK( ssl_tls13_write_change_cipher_spec_body(
                              ssl, ssl->out_msg,
                              ssl->out_msg + MBEDTLS_SSL_OUT_CONTENT_LEN,
                              &ssl->out_msglen ) );

    ssl->out_msgtype = MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC;

    /* Dispatch message */
    MBEDTLS_SSL_PROC_CHK( mbedtls_ssl_write_record( ssl, 0 ) );

cleanup:

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write change cipher spec" ) );
    return( ret );
}

#endif /* MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE */

/* Reset SSL context and update hash for handling HRR.
 *
 * Replace Transcript-Hash(X) by
 * Transcript-Hash( message_hash     ||
 *                 00 00 Hash.length ||
 *                 X )
 * A few states of the handshake are preserved, including:
 *   - session ID
 *   - session ticket
 *   - negotiated ciphersuite
 */
int mbedtls_ssl_reset_transcript_for_hrr( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char hash_transcript[ MBEDTLS_MD_MAX_SIZE + 4 ];
    size_t hash_len;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    uint16_t cipher_suite = ssl->session_negotiate->ciphersuite;
    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( cipher_suite );

    MBEDTLS_SSL_DEBUG_MSG( 3, ( "Reset SSL session for HRR" ) );

    ret = mbedtls_ssl_get_handshake_transcript( ssl, ciphersuite_info->mac,
                                                hash_transcript + 4,
                                                MBEDTLS_MD_MAX_SIZE,
                                                &hash_len );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 4, "mbedtls_ssl_get_handshake_transcript", ret );
        return( ret );
    }

    hash_transcript[0] = MBEDTLS_SSL_HS_MESSAGE_HASH;
    hash_transcript[1] = 0;
    hash_transcript[2] = 0;
    hash_transcript[3] = (unsigned char) hash_len;

    hash_len += 4;

    if( ciphersuite_info->mac == MBEDTLS_MD_SHA256 )
    {
#if defined(MBEDTLS_SHA256_C)
        MBEDTLS_SSL_DEBUG_BUF( 4, "Truncated SHA-256 handshake transcript",
                               hash_transcript, hash_len );

#if defined(MBEDTLS_USE_PSA_CRYPTO)
        psa_hash_abort( &ssl->handshake->fin_sha256_psa );
        psa_hash_setup( &ssl->handshake->fin_sha256_psa, PSA_ALG_SHA_256 );
#else
        mbedtls_sha256_starts( &ssl->handshake->fin_sha256, 0 );
#endif
#endif /* MBEDTLS_SHA256_C */
    }
    else if( ciphersuite_info->mac == MBEDTLS_MD_SHA384 )
    {
#if defined(MBEDTLS_SHA384_C)
        MBEDTLS_SSL_DEBUG_BUF( 4, "Truncated SHA-384 handshake transcript",
                               hash_transcript, hash_len );

#if defined(MBEDTLS_USE_PSA_CRYPTO)
        psa_hash_abort( &ssl->handshake->fin_sha384_psa );
        psa_hash_setup( &ssl->handshake->fin_sha384_psa, PSA_ALG_SHA_384 );
#else
        mbedtls_sha512_starts( &ssl->handshake->fin_sha512, 1 );
#endif
#endif /* MBEDTLS_SHA384_C */
    }

#if defined(MBEDTLS_SHA256_C) || defined(MBEDTLS_SHA384_C)
    ssl->handshake->update_checksum( ssl, hash_transcript, hash_len );
#endif /* MBEDTLS_SHA256_C || MBEDTLS_SHA384_C */

    return( ret );
}

#endif /* MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_PROTO_TLS1_3 */
