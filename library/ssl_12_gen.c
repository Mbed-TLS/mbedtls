/*
 *  Shared handshake reading/writing functions
 *  for TLS versions <= 1.2.
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#endif

#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/version.h"

#include <string.h>

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "mbedtls/psa_util.h"
#include "psa/crypto.h"
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#include "mbedtls/oid.h"
#endif

#if defined(MBEDTLS_SSL_TLS_C)

/*
 * HANDSHAKE STATE: Outgoing `Certificate`
 */

#if !defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)

int mbedtls_ssl_write_certificate( mbedtls_ssl_context *ssl )
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write certificate" ) );

    if( !mbedtls_ssl_ciphersuite_uses_srv_cert( ciphersuite_info ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
        ssl->state++;
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
}

#else /* MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

int mbedtls_ssl_write_certificate( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    size_t i, n;
    const mbedtls_x509_crt *crt;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write certificate" ) );

    if( !mbedtls_ssl_ciphersuite_uses_srv_cert( ciphersuite_info ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
        ssl->state++;
        return( 0 );
    }

#if defined(MBEDTLS_SSL_CLI_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
    {
        if( ssl->client_auth == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
            ssl->state++;
            return( 0 );
        }

#if defined(MBEDTLS_SSL_PROTO_SSL3)
        /*
         * If using SSLv3 and got no cert, send an Alert message
         * (otherwise an empty Certificate message will be sent).
         */
        if( mbedtls_ssl_own_cert( ssl )  == NULL &&
            ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 )
        {
            ssl->out_msglen  = 2;
            ssl->out_msgtype = MBEDTLS_SSL_MSG_ALERT;
            ssl->out_msg[0]  = MBEDTLS_SSL_ALERT_LEVEL_WARNING;
            ssl->out_msg[1]  = MBEDTLS_SSL_ALERT_MSG_NO_CERT;

            MBEDTLS_SSL_DEBUG_MSG( 2, ( "got no certificate to send" ) );
            goto write_msg;
        }
#endif /* MBEDTLS_SSL_PROTO_SSL3 */
    }
#endif /* MBEDTLS_SSL_CLI_C */
#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        if( mbedtls_ssl_own_cert( ssl ) == NULL )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no certificate to send" ) );
            return( MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED );
        }
    }
#endif

    MBEDTLS_SSL_DEBUG_CRT( 3, "own certificate", mbedtls_ssl_own_cert( ssl ) );

    /*
     *     0  .  0    handshake type
     *     1  .  3    handshake length
     *     4  .  6    length of all certs
     *     7  .  9    length of cert. 1
     *    10  . n-1   peer certificate
     *     n  . n+2   length of cert. 2
     *    n+3 . ...   upper level cert, etc.
     */
    i = 7;
    crt = mbedtls_ssl_own_cert( ssl );

    while( crt != NULL )
    {
        n = crt->raw.len;
        if( n > MBEDTLS_SSL_OUT_CONTENT_LEN - 3 - i )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "certificate too large, %d > %d",
                           i + 3 + n, MBEDTLS_SSL_OUT_CONTENT_LEN ) );
            return( MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE );
        }

        ssl->out_msg[i    ] = (unsigned char)( n >> 16 );
        ssl->out_msg[i + 1] = (unsigned char)( n >>  8 );
        ssl->out_msg[i + 2] = (unsigned char)( n       );

        i += 3; memcpy( ssl->out_msg + i, crt->raw.p, n );
        i += n; crt = crt->next;
    }

    ssl->out_msg[4]  = (unsigned char)( ( i - 7 ) >> 16 );
    ssl->out_msg[5]  = (unsigned char)( ( i - 7 ) >>  8 );
    ssl->out_msg[6]  = (unsigned char)( ( i - 7 )       );

    ssl->out_msglen  = i;
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = MBEDTLS_SSL_HS_CERTIFICATE;

#if defined(MBEDTLS_SSL_PROTO_SSL3) && defined(MBEDTLS_SSL_CLI_C)
write_msg:
#endif

    ssl->state++;

    if( ( ret = mbedtls_ssl_write_handshake_msg( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_handshake_msg", ret );
        return( ret );
    }

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write certificate" ) );

    return( ret );
}
#endif /* MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

/*
 * HANDSHAKE STATE: Incoming `Certificate`
 */

#if !defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)

int mbedtls_ssl_parse_certificate( mbedtls_ssl_context *ssl )
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate" ) );

    if( !mbedtls_ssl_ciphersuite_uses_srv_cert( ciphersuite_info ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate" ) );
        ssl->state++;
        return( 0 );
    }

    MBEDTLS_SSL_DEBUG_MSG( 1, ( "should never happen" ) );
    return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
}

#else /* MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

/* Check if a certificate message is expected.
 * Return either
 * - SSL_CERTIFICATE_EXPECTED, or
 * - SSL_CERTIFICATE_SKIP
 * indicating whether a Certificate message is expected or not.
 */
#define SSL_CERTIFICATE_EXPECTED 0
#define SSL_CERTIFICATE_SKIP     1
static int ssl_parse_certificate_coordinate( mbedtls_ssl_context *ssl,
                                             int authmode );
static int ssl_parse_certificate_chain( mbedtls_ssl_context *ssl,
                                        mbedtls_x509_crt *chain );
static int ssl_parse_certificate_verify( mbedtls_ssl_context *ssl,
                                         int authmode,
                                         mbedtls_x509_crt *chain,
                                         void *rs_ctx );

#if defined(MBEDTLS_SSL_SRV_C)
static int ssl_srv_check_client_no_crt_notification( mbedtls_ssl_context *ssl );
#endif /* MBEDTLS_SSL_SRV_C */

#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
static int ssl_remember_peer_crt_digest( mbedtls_ssl_context *ssl,
                                         unsigned char *start, size_t len );
static int ssl_remember_peer_pubkey( mbedtls_ssl_context *ssl,
                                     unsigned char *start, size_t len );
#endif /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

int mbedtls_ssl_parse_certificate( mbedtls_ssl_context *ssl )
{
    int ret = 0;
    int crt_expected;
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    const int authmode = ssl->handshake->sni_authmode != MBEDTLS_SSL_VERIFY_UNSET
                       ? ssl->handshake->sni_authmode
                       : ssl->conf->authmode;
#else
    const int authmode = ssl->conf->authmode;
#endif
    void *rs_ctx = NULL;
    mbedtls_x509_crt *chain = NULL;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse certificate" ) );

    crt_expected = ssl_parse_certificate_coordinate( ssl, authmode );
    if( crt_expected == SSL_CERTIFICATE_SKIP )
    {
        MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= skip parse certificate" ) );
        goto exit;
    }

#if defined(MBEDTLS_SSL__ECP_RESTARTABLE)
    if( ssl->handshake->ecrs_enabled &&
        ssl->handshake->ecrs_state == ssl_ecrs_crt_verify )
    {
        chain = ssl->handshake->ecrs_peer_cert;
        ssl->handshake->ecrs_peer_cert = NULL;
        goto crt_verify;
    }
#endif

    if( ( ret = mbedtls_ssl_read_record( ssl, 1 ) ) != 0 )
    {
        /* mbedtls_ssl_read_record may have sent an alert already. We
           let it decide whether to alert. */
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        goto exit;
    }

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl_srv_check_client_no_crt_notification( ssl ) == 0 )
    {
        ssl->session_negotiate->verify_result = MBEDTLS_X509_BADCERT_MISSING;

        if( authmode == MBEDTLS_SSL_VERIFY_OPTIONAL )
            ret = 0;
        else
            ret = MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE;

        goto exit;
    }
#endif /* MBEDTLS_SSL_SRV_C */

    /* Clear existing peer CRT structure in case we tried to
     * reuse a session but it failed, and allocate a new one. */
    mbedtls_ssl_clear_peer_cert( ssl->session_negotiate );

    chain = mbedtls_calloc( 1, sizeof( mbedtls_x509_crt ) );
    if( chain == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc(%d bytes) failed",
                                    sizeof( mbedtls_x509_crt ) ) );
        mbedtls_ssl_send_alert_message( ssl,
                                        MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                        MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR );

        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto exit;
    }
    mbedtls_x509_crt_init( chain );

    ret = ssl_parse_certificate_chain( ssl, chain );
    if( ret != 0 )
        goto exit;

#if defined(MBEDTLS_SSL__ECP_RESTARTABLE)
    if( ssl->handshake->ecrs_enabled)
        ssl->handshake->ecrs_state = ssl_ecrs_crt_verify;

crt_verify:
    if( ssl->handshake->ecrs_enabled)
        rs_ctx = &ssl->handshake->ecrs_ctx;
#endif

    ret = ssl_parse_certificate_verify( ssl, authmode,
                                        chain, rs_ctx );
    if( ret != 0 )
        goto exit;

#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    {
        unsigned char *crt_start, *pk_start;
        size_t crt_len, pk_len;

        /* We parse the CRT chain without copying, so
         * these pointers point into the input buffer,
         * and are hence still valid after freeing the
         * CRT chain. */

        crt_start = chain->raw.p;
        crt_len   = chain->raw.len;

        pk_start = chain->pk_raw.p;
        pk_len   = chain->pk_raw.len;

        /* Free the CRT structures before computing
         * digest and copying the peer's public key. */
        mbedtls_x509_crt_free( chain );
        mbedtls_free( chain );
        chain = NULL;

        ret = ssl_remember_peer_crt_digest( ssl, crt_start, crt_len );
        if( ret != 0 )
            goto exit;

        ret = ssl_remember_peer_pubkey( ssl, pk_start, pk_len );
        if( ret != 0 )
            goto exit;
    }
#else /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
    /* Pass ownership to session structure. */
    ssl->session_negotiate->peer_cert = chain;
    chain = NULL;
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse certificate" ) );

exit:

    if( ret == 0 )
        ssl->state++;

#if defined(MBEDTLS_SSL__ECP_RESTARTABLE)
    if( ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS )
    {
        ssl->handshake->ecrs_peer_cert = chain;
        chain = NULL;
    }
#endif

    if( chain != NULL )
    {
        mbedtls_x509_crt_free( chain );
        mbedtls_free( chain );
    }

    return( ret );
}

#if defined(MBEDTLS_SSL_RENEGOTIATION) && defined(MBEDTLS_SSL_CLI_C)

#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
static int ssl_check_peer_crt_unchanged( mbedtls_ssl_context *ssl,
                                         unsigned char *crt_buf,
                                         size_t crt_buf_len )
{
    mbedtls_x509_crt const * const peer_crt = ssl->session->peer_cert;

    if( peer_crt == NULL )
        return( -1 );

    if( peer_crt->raw.len != crt_buf_len )
        return( -1 );

    return( memcmp( peer_crt->raw.p, crt_buf, peer_crt->raw.len ) );
}
#else /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
static int ssl_check_peer_crt_unchanged( mbedtls_ssl_context *ssl,
                                         unsigned char *crt_buf,
                                         size_t crt_buf_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char const * const peer_cert_digest =
        ssl->session->peer_cert_digest;
    mbedtls_md_type_t const peer_cert_digest_type =
        ssl->session->peer_cert_digest_type;
    mbedtls_md_info_t const * const digest_info =
        mbedtls_md_info_from_type( peer_cert_digest_type );
    unsigned char tmp_digest[MBEDTLS_SSL_PEER_CERT_DIGEST_MAX_LEN];
    size_t digest_len;

    if( peer_cert_digest == NULL || digest_info == NULL )
        return( -1 );

    digest_len = mbedtls_md_get_size( digest_info );
    if( digest_len > MBEDTLS_SSL_PEER_CERT_DIGEST_MAX_LEN )
        return( -1 );

    ret = mbedtls_md( digest_info, crt_buf, crt_buf_len, tmp_digest );
    if( ret != 0 )
        return( -1 );

    return( memcmp( tmp_digest, peer_cert_digest, digest_len ) );
}
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
#endif /* MBEDTLS_SSL_RENEGOTIATION && MBEDTLS_SSL_CLI_C */

/*
 * Once the certificate message is read, parse it into a cert chain and
 * perform basic checks, but leave actual verification to the caller
 */
static int ssl_parse_certificate_chain( mbedtls_ssl_context *ssl,
                                        mbedtls_x509_crt *chain )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_SSL_RENEGOTIATION) && defined(MBEDTLS_SSL_CLI_C)
    int crt_cnt=0;
#endif
    size_t i, n;
    uint8_t alert;

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                        MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    if( ssl->in_msg[0] != MBEDTLS_SSL_HS_CERTIFICATE ||
        ssl->in_hslen < mbedtls_ssl_hs_hdr_len( ssl ) + 3 + 3 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                        MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
    }

    i = mbedtls_ssl_hs_hdr_len( ssl );

    /*
     * Same message structure as in mbedtls_ssl_write_certificate()
     */
    n = ( ssl->in_msg[i+1] << 8 ) | ssl->in_msg[i+2];

    if( ssl->in_msg[i] != 0 ||
        ssl->in_hslen != n + 3 + mbedtls_ssl_hs_hdr_len( ssl ) )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                        MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
    }

    /* Make &ssl->in_msg[i] point to the beginning of the CRT chain. */
    i += 3;

    /* Iterate through and parse the CRTs in the provided chain. */
    while( i < ssl->in_hslen )
    {
        /* Check that there's room for the next CRT's length fields. */
        if ( i + 3 > ssl->in_hslen ) {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            mbedtls_ssl_send_alert_message( ssl,
                              MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                              MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }
        /* In theory, the CRT can be up to 2**24 Bytes, but we don't support
         * anything beyond 2**16 ~ 64K. */
        if( ssl->in_msg[i] != 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            mbedtls_ssl_send_alert_message( ssl,
                            MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                            MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        /* Read length of the next CRT in the chain. */
        n = ( (unsigned int) ssl->in_msg[i + 1] << 8 )
            | (unsigned int) ssl->in_msg[i + 2];
        i += 3;

        if( n < 128 || i + n > ssl->in_hslen )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            mbedtls_ssl_send_alert_message( ssl,
                                 MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                 MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR );
            return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        /* Check if we're handling the first CRT in the chain. */
#if defined(MBEDTLS_SSL_RENEGOTIATION) && defined(MBEDTLS_SSL_CLI_C)
        if( crt_cnt++ == 0 &&
            ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
            ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS )
        {
            /* During client-side renegotiation, check that the server's
             * end-CRTs hasn't changed compared to the initial handshake,
             * mitigating the triple handshake attack. On success, reuse
             * the original end-CRT instead of parsing it again. */
            MBEDTLS_SSL_DEBUG_MSG( 3, ( "Check that peer CRT hasn't changed during renegotiation" ) );
            if( ssl_check_peer_crt_unchanged( ssl,
                                              &ssl->in_msg[i],
                                              n ) != 0 )
            {
                MBEDTLS_SSL_DEBUG_MSG( 1, ( "new server cert during renegotiation" ) );
                mbedtls_ssl_send_alert_message( ssl,
                                                MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                                MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED );
                return( MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE );
            }

            /* Now we can safely free the original chain. */
            mbedtls_ssl_clear_peer_cert( ssl->session );
        }
#endif /* MBEDTLS_SSL_RENEGOTIATION && MBEDTLS_SSL_CLI_C */

        /* Parse the next certificate in the chain. */
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
        ret = mbedtls_x509_crt_parse_der( chain, ssl->in_msg + i, n );
#else
        /* If we don't need to store the CRT chain permanently, parse
         * it in-place from the input buffer instead of making a copy. */
        ret = mbedtls_x509_crt_parse_der_nocopy( chain, ssl->in_msg + i, n );
#endif /* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
        switch( ret )
        {
            case 0: /*ok*/
            case MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + MBEDTLS_ERR_OID_NOT_FOUND:
                /* Ignore certificate with an unknown algorithm: maybe a
                   prior certificate was already trusted. */
                break;

            case MBEDTLS_ERR_X509_ALLOC_FAILED:
                alert = MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR;
                goto crt_parse_der_failed;

            case MBEDTLS_ERR_X509_UNKNOWN_VERSION:
                alert = MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
                goto crt_parse_der_failed;

            default:
                alert = MBEDTLS_SSL_ALERT_MSG_BAD_CERT;
            crt_parse_der_failed:
                mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, alert );
                MBEDTLS_SSL_DEBUG_RET( 1, " mbedtls_x509_crt_parse_der", ret );
                return( ret );
        }

        i += n;
    }

    MBEDTLS_SSL_DEBUG_CRT( 3, "peer certificate", chain );
    return( 0 );
}

#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
static int ssl_remember_peer_crt_digest( mbedtls_ssl_context *ssl,
                                         unsigned char *start, size_t len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    /* Remember digest of the peer's end-CRT. */
    ssl->session_negotiate->peer_cert_digest =
        mbedtls_calloc( 1, MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN );
    if( ssl->session_negotiate->peer_cert_digest == NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "alloc(%d bytes) failed",
                                    MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN ) );
        mbedtls_ssl_send_alert_message( ssl,
                                        MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                        MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR );

        return( MBEDTLS_ERR_SSL_ALLOC_FAILED );
    }

    ret = mbedtls_md( mbedtls_md_info_from_type(
                          MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_TYPE ),
                      start, len,
                      ssl->session_negotiate->peer_cert_digest );

    ssl->session_negotiate->peer_cert_digest_type =
        MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_TYPE;
    ssl->session_negotiate->peer_cert_digest_len =
        MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN;

    return( ret );
}

static int ssl_remember_peer_pubkey( mbedtls_ssl_context *ssl,
                                     unsigned char *start, size_t len )
{
    unsigned char *end = start + len;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Make a copy of the peer's raw public key. */
    mbedtls_pk_init( &ssl->handshake->peer_pubkey );
    ret = mbedtls_pk_parse_subpubkey( &start, end,
                                      &ssl->handshake->peer_pubkey );
    if( ret != 0 )
    {
        /* We should have parsed the public key before. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    return( 0 );
}
#endif /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

#if defined(MBEDTLS_SSL_SRV_C)
static int ssl_srv_check_client_no_crt_notification( mbedtls_ssl_context *ssl )
{
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
        return( -1 );

#if defined(MBEDTLS_SSL_PROTO_SSL3)
    /*
     * Check if the client sent an empty certificate
     */
    if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 )
    {
        if( ssl->in_msglen  == 2                        &&
            ssl->in_msgtype == MBEDTLS_SSL_MSG_ALERT            &&
            ssl->in_msg[0]  == MBEDTLS_SSL_ALERT_LEVEL_WARNING  &&
            ssl->in_msg[1]  == MBEDTLS_SSL_ALERT_MSG_NO_CERT )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "SSLv3 client has no certificate" ) );
            return( 0 );
        }

        return( -1 );
    }
#endif /* MBEDTLS_SSL_PROTO_SSL3 */

#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if( ssl->in_hslen   == 3 + mbedtls_ssl_hs_hdr_len( ssl ) &&
        ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE    &&
        ssl->in_msg[0]  == MBEDTLS_SSL_HS_CERTIFICATE   &&
        memcmp( ssl->in_msg + mbedtls_ssl_hs_hdr_len( ssl ), "\0\0\0", 3 ) == 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "TLSv1 client has no certificate" ) );
        return( 0 );
    }

    return( -1 );
#endif /* MBEDTLS_SSL_PROTO_TLS1 || MBEDTLS_SSL_PROTO_TLS1_1 || \
          MBEDTLS_SSL_PROTO_TLS1_2 */
}
#endif /* MBEDTLS_SSL_SRV_C */

static int ssl_parse_certificate_coordinate( mbedtls_ssl_context *ssl,
                                             int authmode )
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;

    if( !mbedtls_ssl_ciphersuite_uses_srv_cert( ciphersuite_info ) )
        return( SSL_CERTIFICATE_SKIP );

#if defined(MBEDTLS_SSL_SRV_C)
    if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
    {
        if( ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_RSA_PSK )
            return( SSL_CERTIFICATE_SKIP );

        if( authmode == MBEDTLS_SSL_VERIFY_NONE )
        {
            ssl->session_negotiate->verify_result =
                MBEDTLS_X509_BADCERT_SKIP_VERIFY;
            return( SSL_CERTIFICATE_SKIP );
        }
    }
#else
    ((void) authmode);
#endif /* MBEDTLS_SSL_SRV_C */

    return( SSL_CERTIFICATE_EXPECTED );
}

static int ssl_parse_certificate_verify( mbedtls_ssl_context *ssl,
                                         int authmode,
                                         mbedtls_x509_crt *chain,
                                         void *rs_ctx )
{
    int ret = 0;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;
    int have_ca_chain = 0;

    int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *);
    void *p_vrfy;

    if( authmode == MBEDTLS_SSL_VERIFY_NONE )
        return( 0 );

    if( ssl->f_vrfy != NULL )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Use context-specific verification callback" ) );
        f_vrfy = ssl->f_vrfy;
        p_vrfy = ssl->p_vrfy;
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Use configuration-specific verification callback" ) );
        f_vrfy = ssl->conf->f_vrfy;
        p_vrfy = ssl->conf->p_vrfy;
    }

    /*
     * Main check: verify certificate
     */
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    if( ssl->conf->f_ca_cb != NULL )
    {
        ((void) rs_ctx);
        have_ca_chain = 1;

        MBEDTLS_SSL_DEBUG_MSG( 3, ( "use CA callback for X.509 CRT verification" ) );
        ret = mbedtls_x509_crt_verify_with_ca_cb(
            chain,
            ssl->conf->f_ca_cb,
            ssl->conf->p_ca_cb,
            ssl->conf->cert_profile,
            ssl->hostname,
            &ssl->session_negotiate->verify_result,
            f_vrfy, p_vrfy );
    }
    else
#endif /* MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK */
    {
        mbedtls_x509_crt *ca_chain;
        mbedtls_x509_crl *ca_crl;

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
        if( ssl->handshake->sni_ca_chain != NULL )
        {
            ca_chain = ssl->handshake->sni_ca_chain;
            ca_crl   = ssl->handshake->sni_ca_crl;
        }
        else
#endif
        {
            ca_chain = ssl->conf->ca_chain;
            ca_crl   = ssl->conf->ca_crl;
        }

        if( ca_chain != NULL )
            have_ca_chain = 1;

        ret = mbedtls_x509_crt_verify_restartable(
            chain,
            ca_chain, ca_crl,
            ssl->conf->cert_profile,
            ssl->hostname,
            &ssl->session_negotiate->verify_result,
            f_vrfy, p_vrfy, rs_ctx );
    }

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "x509_verify_cert", ret );
    }

#if defined(MBEDTLS_SSL__ECP_RESTARTABLE)
    if( ret == MBEDTLS_ERR_ECP_IN_PROGRESS )
        return( MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS );
#endif

    /*
     * Secondary checks: always done, but change 'ret' only if it was 0
     */

#if defined(MBEDTLS_ECP_C)
    {
        const mbedtls_pk_context *pk = &chain->pk;

        /* If certificate uses an EC key, make sure the curve is OK */
        if( mbedtls_pk_can_do( pk, MBEDTLS_PK_ECKEY ) &&
            mbedtls_ssl_check_curve( ssl, mbedtls_pk_ec( *pk )->grp.id ) != 0 )
        {
            ssl->session_negotiate->verify_result |= MBEDTLS_X509_BADCERT_BAD_KEY;

            MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate (EC key curve)" ) );
            if( ret == 0 )
                ret = MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE;
        }
    }
#endif /* MBEDTLS_ECP_C */

    if( mbedtls_ssl_check_cert_usage( chain,
                                      ciphersuite_info,
                                      ! ssl->conf->endpoint,
                                      &ssl->session_negotiate->verify_result ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad certificate (usage extensions)" ) );
        if( ret == 0 )
            ret = MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE;
    }

    /* mbedtls_x509_crt_verify_with_profile is supposed to report a
     * verification failure through MBEDTLS_ERR_X509_CERT_VERIFY_FAILED,
     * with details encoded in the verification flags. All other kinds
     * of error codes, including those from the user provided f_vrfy
     * functions, are treated as fatal and lead to a failure of
     * ssl_parse_certificate even if verification was optional. */
    if( authmode == MBEDTLS_SSL_VERIFY_OPTIONAL &&
        ( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ||
          ret == MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE ) )
    {
        ret = 0;
    }

    if( have_ca_chain == 0 && authmode == MBEDTLS_SSL_VERIFY_REQUIRED )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "got no CA chain" ) );
        ret = MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED;
    }

    if( ret != 0 )
    {
        uint8_t alert;

        /* The certificate may have been rejected for several reasons.
           Pick one and send the corresponding alert. Which alert to send
           may be a subject of debate in some cases. */
        if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_OTHER )
            alert = MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED;
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_CN_MISMATCH )
            alert = MBEDTLS_SSL_ALERT_MSG_BAD_CERT;
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_KEY_USAGE )
            alert = MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_EXT_KEY_USAGE )
            alert = MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_NS_CERT_TYPE )
            alert = MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_BAD_PK )
            alert = MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_BAD_KEY )
            alert = MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_EXPIRED )
            alert = MBEDTLS_SSL_ALERT_MSG_CERT_EXPIRED;
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_REVOKED )
            alert = MBEDTLS_SSL_ALERT_MSG_CERT_REVOKED;
        else if( ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_NOT_TRUSTED )
            alert = MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA;
        else
            alert = MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN;
        mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                        alert );
    }

#if defined(MBEDTLS_DEBUG_C)
    if( ssl->session_negotiate->verify_result != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "! Certificate verification flags %x",
                                    ssl->session_negotiate->verify_result ) );
    }
    else
    {
        MBEDTLS_SSL_DEBUG_MSG( 3, ( "Certificate verification flags clear" ) );
    }
#endif /* MBEDTLS_DEBUG_C */

    return( ret );
}

#endif /* MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

/*
 * HANDSHAKE STATE: Outgoing `Finished`
 */

int mbedtls_ssl_write_finished( mbedtls_ssl_context *ssl )
{
    int ret, hash_len;

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> write finished" ) );

    mbedtls_ssl_update_out_pointers( ssl, ssl->transform_negotiate );

    ssl->handshake->calc_finished( ssl, ssl->out_msg + 4, ssl->conf->endpoint );

    /*
     * RFC 5246 7.4.9 (Page 63) says 12 is the default length and ciphersuites
     * may define some other value. Currently (early 2016), no defined
     * ciphersuite does this (and this is unlikely to change as activity has
     * moved to TLS 1.3 now) so we can keep the hardcoded 12 here.
     */
    hash_len = ( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 ) ? 36 : 12;

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    ssl->verify_data_len = hash_len;
    memcpy( ssl->own_verify_data, ssl->out_msg + 4, hash_len );
#endif

    ssl->out_msglen  = 4 + hash_len;
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = MBEDTLS_SSL_HS_FINISHED;

    /*
     * In case of session resuming, invert the client and server
     * ChangeCipherSpec messages order.
     */
    if( ssl->handshake->resume != 0 )
    {
#if defined(MBEDTLS_SSL_CLI_C)
        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
            ssl->state = MBEDTLS_SSL_HANDSHAKE_WRAPUP;
#endif
#if defined(MBEDTLS_SSL_SRV_C)
        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
            ssl->state = MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC;
#endif
    }
    else
        ssl->state++;

    /*
     * Switch to our negotiated transform and session parameters for outbound
     * data.
     */
    MBEDTLS_SSL_DEBUG_MSG( 3, ( "switching to new transform spec for outbound data" ) );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        unsigned char i;

        /* Remember current epoch settings for resending */
        ssl->handshake->alt_transform_out = ssl->transform_out;
        memcpy( ssl->handshake->alt_out_ctr, ssl->cur_out_ctr, 8 );

        /* Set sequence_number to zero */
        memset( ssl->cur_out_ctr + 2, 0, 6 );

        /* Increment epoch */
        for( i = 2; i > 0; i-- )
            if( ++ssl->cur_out_ctr[i - 1] != 0 )
                break;

        /* The loop goes to its end iff the counter is wrapping */
        if( i == 0 )
        {
            MBEDTLS_SSL_DEBUG_MSG( 1, ( "DTLS epoch would wrap" ) );
            return( MBEDTLS_ERR_SSL_COUNTER_WRAPPING );
        }
    }
    else
#endif /* MBEDTLS_SSL_PROTO_DTLS */
    memset( ssl->cur_out_ctr, 0, 8 );

    ssl->transform_out = ssl->transform_negotiate;
    ssl->session_out = ssl->session_negotiate;

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)
    if( mbedtls_ssl_hw_record_activate != NULL )
    {
        if( ( ret = mbedtls_ssl_hw_record_activate( ssl, MBEDTLS_SSL_CHANNEL_OUTBOUND ) ) != 0 )
        {
            MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_hw_record_activate", ret );
            return( MBEDTLS_ERR_SSL_HW_ACCEL_FAILED );
        }
    }
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        mbedtls_ssl_send_flight_completed( ssl );
#endif

    if( ( ret = mbedtls_ssl_write_handshake_msg( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_write_handshake_msg", ret );
        return( ret );
    }

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ( ret = mbedtls_ssl_flight_transmit( ssl ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_flight_transmit", ret );
        return( ret );
    }
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= write finished" ) );

    return( 0 );
}

#if defined(MBEDTLS_SSL_PROTO_SSL3)
#define SSL_MAX_HASH_LEN 36
#else
#define SSL_MAX_HASH_LEN 12
#endif

/*
 * HANDSHAKE STATE: Incoming `Finished`
 */

int mbedtls_ssl_parse_finished( mbedtls_ssl_context *ssl )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned int hash_len;
    unsigned char buf[SSL_MAX_HASH_LEN];

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "=> parse finished" ) );

    ssl->handshake->calc_finished( ssl, buf, ssl->conf->endpoint ^ 1 );

    if( ( ret = mbedtls_ssl_read_record( ssl, 1 ) ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_read_record", ret );
        return( ret );
    }

    if( ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );
        mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                        MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE );
        return( MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    /* There is currently no ciphersuite using another length with TLS 1.2 */
#if defined(MBEDTLS_SSL_PROTO_SSL3)
    if( ssl->minor_ver == MBEDTLS_SSL_MINOR_VERSION_0 )
        hash_len = 36;
    else
#endif
        hash_len = 12;

    if( ssl->in_msg[0] != MBEDTLS_SSL_HS_FINISHED ||
        ssl->in_hslen  != mbedtls_ssl_hs_hdr_len( ssl ) + hash_len )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );
        mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                        MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_BAD_HS_FINISHED );
    }

    if( mbedtls_ssl_safer_memcmp( ssl->in_msg + mbedtls_ssl_hs_hdr_len( ssl ),
                      buf, hash_len ) != 0 )
    {
        MBEDTLS_SSL_DEBUG_MSG( 1, ( "bad finished message" ) );
        mbedtls_ssl_send_alert_message( ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                        MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR );
        return( MBEDTLS_ERR_SSL_BAD_HS_FINISHED );
    }

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    ssl->verify_data_len = hash_len;
    memcpy( ssl->peer_verify_data, buf, hash_len );
#endif

    if( ssl->handshake->resume != 0 )
    {
#if defined(MBEDTLS_SSL_CLI_C)
        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT )
            ssl->state = MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC;
#endif
#if defined(MBEDTLS_SSL_SRV_C)
        if( ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER )
            ssl->state = MBEDTLS_SSL_HANDSHAKE_WRAPUP;
#endif
    }
    else
        ssl->state++;

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        mbedtls_ssl_recv_flight_completed( ssl );
#endif

    MBEDTLS_SSL_DEBUG_MSG( 2, ( "<= parse finished" ) );

    return( 0 );
}

#endif /* MBEDTLS_SSL_TLS_C */
