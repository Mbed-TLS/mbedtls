/*
 *  OCSP response parsing and verification
 *
 *  Copyright (C) 2017, ARM Limited, All Rights Reserved
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

#if defined(MBEDTLS_X509_OCSP_PARSE_C)

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_free        free
#define mbedtls_calloc      calloc
#define mbedtls_snprintf    snprintf
#endif

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/x509_ocsp.h"
#include "mbedtls/asn1.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/oid.h"

#include <stdint.h>
#include <string.h>

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

void mbedtls_x509_ocsp_response_init( mbedtls_x509_ocsp_response *resp )
{
    memset( &resp->raw, 0, sizeof( mbedtls_x509_buf ) );
    memset( &resp->resp_type, 0, sizeof( mbedtls_x509_buf ) );
    memset( &resp->sig, 0, sizeof( mbedtls_x509_buf ) );
    memset( &resp->response_data, 0, sizeof( mbedtls_x509_buf ) );
    memset( &resp->sig_oid, 0, sizeof( mbedtls_x509_buf ) );

    memset( &resp->produced_at, 0, sizeof( mbedtls_x509_time ) );

    memset( &resp->responder_id, 0, sizeof( mbedtls_x509_ocsp_responder_id ) );
    memset( &resp->single_resp, 0,
            sizeof( mbedtls_x509_ocsp_single_response ) );

    resp->resp_status = 0;
    resp->version = MBEDTLS_X509_OCSP_VERSION_1;
    resp->sig_md = MBEDTLS_MD_NONE;
    resp->sig_pk = MBEDTLS_PK_NONE;
    resp->sig_opts = NULL;

    mbedtls_x509_crt_init( &resp->certs );
}

/*
 * This code is exactly the same as x509_crt_free_name(), we should consider
 * removing code duplication
 */
static void x509_ocsp_free_name( mbedtls_x509_name *name )
{
    mbedtls_x509_name *cur = name->next;
    mbedtls_x509_name *prv;

    while( cur != NULL )
    {
        prv = cur;
        cur = cur->next;
        mbedtls_zeroize( prv, sizeof( mbedtls_x509_name ) );
        mbedtls_free( prv );
    }
}

void mbedtls_x509_ocsp_response_free( mbedtls_x509_ocsp_response *resp )
{
    mbedtls_x509_ocsp_single_response *cur, *next;

    if( resp == NULL )
        return;
    else if( resp->raw.p == NULL )
        goto exit;

    /* Free list of certificates */
    mbedtls_x509_crt_free( &resp->certs );

    /* Free Name from ResponderID if set */
    if( resp->responder_id.type == MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_NAME )
        x509_ocsp_free_name( &resp->responder_id.id.name );

    /* Free list of SingleResponses */
    for( cur = &resp-> single_resp; cur != NULL; cur = next )
    {
        next = cur->next;

        mbedtls_zeroize( cur, sizeof( mbedtls_x509_ocsp_single_response ) );

        if( cur != &resp->single_resp )
            mbedtls_free( cur );
    }

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    /* Free signature options */
    mbedtls_free( resp->sig_opts );
#endif

    /* Free internal buffer holding the raw OCSP response */
    mbedtls_free( resp->raw.p );

exit:
    /* Clear memory to avoid leaking confidential data */
    mbedtls_zeroize( resp, sizeof( mbedtls_x509_ocsp_response ) );
}

static int x509_ocsp_get_response_status( unsigned char **p,
                                          const unsigned char *end,
                                          uint8_t *resp_status )
{
    int ret;
    size_t len;

    /*
     * OCSPResponseStatus ::= ENUMERATED {
     *      successful          (0),    -- Response has valid confirmations
     *      malformedRequest    (1),    -- Illegal confirmation request
     *      internalError       (2),    -- Internal error in issuer
     *      tryLater            (3),    -- Try again later
     *                                  -- (4) is not used
     *      sigRequired         (5),    -- Must sign the request
     *      unauthorized        (6)     -- Request unauthorized }
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                                      MBEDTLS_ASN1_ENUMERATED ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( len != 1 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    *resp_status = *( *p )++;

    /* Ensure the parsed response status is valid */
    switch( *resp_status )
    {
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_SUCCESSFUL:
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_MALFORMED_REQ:
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_INTERNAL_ERR:
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_TRY_LATER:
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_SIG_REQUIRED:
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_UNAUTHORIZED:
            break;
        default:
            return( MBEDTLS_ERR_X509_INVALID_RESPONSE_STATUS );
    }

    return( 0 );
}

static int x509_ocsp_get_response_type( unsigned char **p,
                                        const unsigned char *end,
                                        mbedtls_x509_buf *resp_type )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_OID ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );

    resp_type->tag = MBEDTLS_ASN1_OID;
    resp_type->len = len;
    resp_type->p = *p;

    /*
     * At this stage we only support id-pkix-ocsp-basic. This defines the
     * ASN.1 syntax of the remaining OCSP response so return a failure if the
     * response type is not OCSP Basic.
     */
    if( MBEDTLS_OID_CMP( MBEDTLS_OID_OCSP_BASIC, resp_type ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_RESPONSE_TYPE );

    *p = *p + len;

    return( 0 );
}

static int x509_ocsp_get_extensions( unsigned char **p,
                                     const unsigned char *end )
{
    int ret;
    size_t len;

    /* TODO: Complete the parsing properly */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    *p = *p + len;

    return( 0 );
}

static int x509_ocsp_get_response_version( unsigned char **p,
                                           const unsigned char *end,
                                           int *version )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_int( p, end, version ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_VERSION + ret );
    else if( *version != MBEDTLS_X509_OCSP_VERSION_1 )
        return( MBEDTLS_ERR_X509_UNKNOWN_VERSION );

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_VERSION +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

static int x509_ocsp_get_md( unsigned char **p, const unsigned char *end,
                             mbedtls_md_type_t md_alg, mbedtls_x509_buf *buf )
{
    int ret;
    size_t len;
    const mbedtls_md_info_t *md_info;
    size_t md_len;

    if( ( md_info = mbedtls_md_info_from_type( md_alg ) ) == NULL )
        return( MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE );

    md_len = mbedtls_md_get_size( md_info );

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                                      MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    buf->len = len;
    buf->tag = MBEDTLS_ASN1_OCTET_STRING;
    buf->p = *p;

    /* Check that the length matches the expected length of the md algorithm */
    if( len != md_len )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );

    *p = *p + len;

    return( 0 );
}

static int x509_ocsp_get_responder_id( unsigned char **p,
                                       const unsigned char *end,
                                mbedtls_x509_ocsp_responder_id *responder_id )
{
    int ret;
    size_t len;
    unsigned char tag;
    unsigned char base_tag = MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                             MBEDTLS_ASN1_CONSTRUCTED;

    /*
     * RespoderID ::= CHOICE {
     *  byName          [1] Name,
     *  byKey           [2] KeyHash }
     */
    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    tag = **p;
    ( *p )++;
    if( ( ret = mbedtls_asn1_get_len( p, end, &len ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    end = *p + len;

    if( tag == ( base_tag | MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_NAME ) )
    {
        responder_id->type = MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_NAME;

        /*
         * mbedtls_x509_get_name() cannot handle the following ASN1
         * constructs at the beginning of the Name, so we must remove it
         * manually
         *
         * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
         */
        if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        {
            return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
        }

        if( ( ret = mbedtls_x509_get_name( p, *p + len,
                                           &responder_id->id.name ) ) != 0 )
        {
            return( ret );
        }
    }
    else if( tag == ( base_tag |
                      MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_KEY_HASH ) )
    {
        responder_id->type = MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_KEY_HASH;

        /*
         * KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
         * (excluding the tag and length fields)
         */
        if( ( ret = x509_ocsp_get_md( p, end, MBEDTLS_MD_SHA1,
                                            &responder_id->id.key ) ) != 0 )
        {
            return( ret );
        }
    }
    else
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

static int x509_ocsp_get_generalized_time( unsigned char **p,
                                           const unsigned char *end,
                                           mbedtls_x509_time *t )
{
    int ret;
    unsigned char tag;

    /*
     * mbedtls_x509_get_time() can parse both UTCTime and GeneralizedTime
     * and there is no way to tell from the output which version it parsed.
     * However, OCSP responses require GeneralizedTime only, so we must check
     * the tag manually.
     */

    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_X509_INVALID_DATE +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    tag = **p;

    if( tag != MBEDTLS_ASN1_GENERALIZED_TIME )
        return( MBEDTLS_ERR_X509_INVALID_DATE +
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );

    if( ( ret = mbedtls_x509_get_time( p, end, t ) ) != 0 )
        return( ret );

    return( 0 );
}

static int x509_ocsp_get_cert_id( unsigned char **p,
                                  const unsigned char *end,
                            mbedtls_x509_ocsp_single_response *single_resp )
{
    int ret;
    size_t len;

    /*
     * CertID ::= SEQUENCE {
     *  hashAlgorithm       AlgorithmIdentifier,
     *  issuesNameHash      OCTET STRING,
     *  issuerKeyHash       OCTET STRING,
     *  serialNumber        CertificateSerialNumber }
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = *p + len;

    /* Parse hashAlgorithm */
    if( ( ret = mbedtls_x509_get_alg_null( p, end,
                                           &single_resp->md_oid ) ) != 0 )
    {
        return( ret );
    }
    else if( ( ret = mbedtls_oid_get_md_alg( &single_resp->md_oid,
                                             &single_resp->md_alg ) ) != 0 )
    {
        return( ret );
    }

    /* Parse issuerNameHash */
    if( ( ret = x509_ocsp_get_md( p, end, single_resp->md_alg,
                                    &single_resp->issuer_name_hash ) ) != 0 )
    {
        return( ret );
    }

    /* Parse issuerKeyHash */
    if( ( ret = x509_ocsp_get_md( p, end, single_resp->md_alg,
                                    &single_resp->issuer_key_hash ) ) != 0 )
    {
        return( ret );
    }

    /* Parse serialNumber */
    if( ( ret = mbedtls_x509_get_serial( p, end,
                                         &single_resp->serial ) ) != 0 )
    {
        return( ret );
    }

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * This code is essentially parsing a CRLReason which is a CRL extension. We
 * should consider moving it to x509_crl
 */
static int x509_ocsp_get_crl_reason( unsigned char **p,
                                     const unsigned char *end,
                                     uint8_t *reason )
{
    int ret;
    size_t len;

    /*
     * CRLReason ::= ENUMERATED {
     *  unspecified             (0),
     *  keyCompromise           (1),
     *  cACompromise            (2),
     *  affiliationChanged      (3),
     *  superseded              (4),
     *  cessationOfOperation    (5),
     *  certificateHold         (6),
     *  removeFromCRL           (8),
     *  privilegeWithdrawn      (9),
     *  aACompromise            (10) }
     */

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                                      MBEDTLS_ASN1_ENUMERATED ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( len != 1 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    *reason = *( *p )++;

    /* Ensure the parsed response status is valid */
    switch( *reason )
    {
        case MBEDTLS_X509_CRL_REASON_UNSPECIFIED:
        case MBEDTLS_X509_CRL_REASON_KEY_COMPROMISE:
        case MBEDTLS_X509_CRL_REASON_CA_COMPROMISE:
        case MBEDTLS_X509_CRL_REASON_AFFILIATION_CHANGED:
        case MBEDTLS_X509_CRL_REASON_SUPERSEDED:
        case MBEDTLS_X509_CRL_REASON_CESSATION_OF_OPERATION:
        case MBEDTLS_X509_CRL_REASON_CERTIFICATE_HOLD:
        case MBEDTLS_X509_CRL_REASON_REMOVE_FROM_CRL:
        case MBEDTLS_X509_CRL_REASON_PRIVILEGE_WITHDRAWN:
        case MBEDTLS_X509_CRL_REASON_AA_COMPROMISE:
            break;
        default:
            return( MBEDTLS_ERR_X509_INVALID_CRL_REASON );
    }

    return( 0 );
}

static int x509_ocsp_get_revoked_info( unsigned char **p,
                                       const unsigned char *end,
                            mbedtls_x509_ocsp_single_response *single_resp )
{
    int ret;
    size_t len;

    /*
     * RevokedInfo :: SEQUENCE {
     *  revocationTime          GeneralizedTime,
     *  revocationReason        [0] EXPLICIT CRLReason OPTIONAL }
     *
     * Note: The SEQUENCE tag is parsed as part of the CertStatus CHOICE
     */

    /* Parse revocationTime */
    if( ( ret = x509_ocsp_get_generalized_time( p, end,
                                    &single_resp->revocation_time ) ) != 0 )
    {
        return( ret );
    }

    /* The revocationReason is optional, so return if there is no data */
    if( *p == end )
        return( 0 );

    /* Parse revocationReason */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0 ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    single_resp->has_revocation_reason = 1;

    if( ( ret = x509_ocsp_get_crl_reason( p, *p + len,
                                    &single_resp->revocation_reason ) ) != 0 )
    {
        return( ret );
    }

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

static int x509_ocsp_get_cert_status( unsigned char **p,
                                      const unsigned char *end,
                            mbedtls_x509_ocsp_single_response *single_resp )
{
    int ret;
    size_t len;
    unsigned char tag;
    const unsigned char status_good = MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                      MBEDTLS_ASN1_PRIMITIVE |
                                      MBEDTLS_X509_OCSP_CERT_STATUS_GOOD;
    const unsigned char status_unknown = MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                         MBEDTLS_ASN1_PRIMITIVE |
                                         MBEDTLS_X509_OCSP_CERT_STATUS_UNKNOWN;
    const unsigned char status_revoked = MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                         MBEDTLS_ASN1_CONSTRUCTED |
                                         MBEDTLS_X509_OCSP_CERT_STATUS_REVOKED;

    /*
     * CertStatus ::= CHOICE {
     *  good            [0] IMPLICIT NULL,
     *  revoked         [1] IMPLICIT RevokedInfo,
     *  unknown         [2] IMPLICIT UnknownInfo }
     */
    if( ( end - *p ) < 1 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    tag = **p;
    ( *p )++;

    if( ( ret = mbedtls_asn1_get_len( p, end, &len ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

    end = *p + len;

    if( tag == status_good )
        single_resp->cert_status = MBEDTLS_X509_OCSP_CERT_STATUS_GOOD;
    else if( tag == status_unknown )
        single_resp->cert_status = MBEDTLS_X509_OCSP_CERT_STATUS_UNKNOWN;
    else if( tag == status_revoked )
    {
        single_resp->cert_status = MBEDTLS_X509_OCSP_CERT_STATUS_REVOKED;

        if( ( ret = x509_ocsp_get_revoked_info( p, end, single_resp ) ) != 0 )
            return( ret );
    }
    else
        return( MBEDTLS_ERR_X509_INVALID_CERT_STATUS );

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

static int x509_ocsp_get_single_response( unsigned char **p,
                                          const unsigned char *end,
                                    mbedtls_x509_ocsp_single_response *cur )
{
    int ret;
    size_t len;
    unsigned char tag;

    /*
     * SingleResponse ::= SEQUENCE {
     *  certID              CertID,
     *  certStatus          CertStatus,
     *  thisUpdate          GeneralizedTime,
     *  nextUpdate          [0] GeneralizedTime OPTIONAL,
     *  singleExtensions    [1] Extensions OPTIONAL }
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = *p + len;

    /* Parse certID, skip for now */
    if( ( ret = x509_ocsp_get_cert_id( p, end, cur ) ) != 0 )
    {
        return( ret );
    }

    /*  Parse certStatus */
    if( ( ret = x509_ocsp_get_cert_status( p, end, cur ) ) != 0 )
    {
        return( ret );
    }

    /* Parse thisUpdate */
    if( ( ret = x509_ocsp_get_generalized_time( p, end,
                                            &cur->this_update ) ) != 0 )
    {
        return( ret );
    }

    /*
     * nextUpdate and singleExtensions are optional, so find out which ones
     * are available and parse them
     */
    if( *p == end )
        return( 0 );

    /*
     * Get the EXPLICIT tag and find out what type of data its left to parse.
     * At this point the tag can only be [0] or [1]
     */
    tag = *( *p )++;

    if( ( ret = mbedtls_asn1_get_len( p, end, &len ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );

    switch( tag )
    {
        case MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0:
            /* Parse nextUpdate */
            if( ( ret = x509_ocsp_get_generalized_time( p, *p + len,
                                                &cur->next_update ) ) != 0 )
                return( ret );

            cur->has_next_update = 1;

            if( *p == end )
                return( 0 );

            /* Get the EXPLICIT tag. At this point the tag can only be [1] */
            if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                                MBEDTLS_ASN1_CONSTRUCTED |
                                MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1 ) ) != 0 )
            {
                return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
            }

            /*
             * Note that the missing break statement here is omitted on purpose
             * as we can have nextUpdate followed by extensions
             */

        case MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1:
            /* Parse singleExtensions */
            if( ( ret = x509_ocsp_get_extensions( p, *p + len ) ) != 0 )
                return( ret );

            break;

        default:
            return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                    MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
    }

    /*
     * Sanity check to ensure that we really are at the end of the
     * SingleResponse being parsed
     */
    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

static int x509_ocsp_get_responses( unsigned char **p,
                                    const unsigned char *end,
                            mbedtls_x509_ocsp_single_response *single_resp )
{
    int ret;
    size_t len;
    mbedtls_x509_ocsp_single_response *cur = single_resp;

    /* responses               SEQUENCE OF SingleResponse */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = *p + len;

    /*
     * Strictly speaking the SEQUENCE OF tag can contain 0 or more
     * SingleResponse objects, but RFC 6960 Section 4.1.1 states that the
     * requestList contains one or more single certificate status requests and
     * Section 4.2.2.3 states that the response MUST include a SingleResponse
     * for each certificate in the request. Therefore, an empty responses field
     * is failure
     */
    if( *p == end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    while( *p < end )
    {
        /* Allocate space for the next SingleResponse if necessary */
        if( cur->md_oid.p != NULL )
        {
            /*
             * This check prevents errors when populating an already used
             * mbedtls_x509_ocsp_single_response
             */
            if( cur->next != NULL )
                return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

            cur->next = mbedtls_calloc( 1,
                                sizeof( mbedtls_x509_ocsp_single_response ) );
            if( cur->next == NULL )
                return( MBEDTLS_ERR_X509_ALLOC_FAILED );

            cur = cur->next;
        }

        /* Parse SingleResponse and populate cur */
        if( ( ret = x509_ocsp_get_single_response( p, end, cur ) ) != 0 )
            return( ret );
    }

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

static int x509_ocsp_get_response_data( mbedtls_x509_ocsp_response *resp,
                                unsigned char **p, const unsigned char *end )
{
    int ret;
    size_t len;

    /*
     * Keep track of the ResponseData as we need to ensure its signature is
     * valid
     */
    resp->response_data.p = *p;

    /*
     * ResponseData ::= SEQUENCE {
     *  version                 [0] EXPLICIT Version DEFAULT v1,
     *  responderID             ResponderID,
     *  producedAt              GeneralizedTime,
     *  responses               SEQUENCE OF SingleResponse,
     *  responseExtensions      [1] EXPLICIT Extensions OPTIONAL }
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = *p + len;
    resp->response_data.len = end - resp->response_data.p;

    /* Get the subcomponent [0] EXPLICIT ... DEFAULT v1 */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
        MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) ) != 0 )
    {
        /*
         * Note that DEFAULT means that the version might not be present, in
         * which case the value defaults to v1
         */
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
            resp->version = MBEDTLS_X509_OCSP_VERSION_1;
        else
            return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }
    /* Parse version */
    else if( ( ret = x509_ocsp_get_response_version( p, *p + len,
                                                     &resp->version ) ) != 0 )
    {
        return( ret );
    }

    /* Parse responderID */
    if( ( ret = x509_ocsp_get_responder_id( p, end,
                                            &resp->responder_id ) ) != 0 )
    {
        return( ret );
    }

    /* Parse producedAt */
    if( ( ret = x509_ocsp_get_generalized_time( p, end,
                                                &resp->produced_at ) ) != 0 )
    {
        return( ret );
    }

    /* Parse responses */
    if( ( ret = x509_ocsp_get_responses( p, end, &resp->single_resp ) ) != 0 )
        return( ret );

    /* responseExtensions is optional, so find out if there is more data */
    if( *p == end )
        return( 0 );

    /* Get the [1] EXPLICIT tag */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                                MBEDTLS_ASN1_CONSTRUCTED |
                                MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1 ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    /* Parse responseExtensions */
    if( ( ret = x509_ocsp_get_extensions( p, *p + len ) ) != 0 )
        return( ret );

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

static int x509_ocsp_get_sig_alg( mbedtls_x509_ocsp_response *resp,
                                  unsigned char **p,
                                  const unsigned char *end )
{
    int ret;
    mbedtls_x509_buf sig_params;

    if( ( ret = mbedtls_x509_get_alg( p, end, &resp->sig_oid,
                                      &sig_params ) ) != 0 )
    {
        return( ret );
    }

    if( ( ret = mbedtls_x509_get_sig_alg( &resp->sig_oid, &sig_params,
                                          &resp->sig_md, &resp->sig_pk,
                                          &resp->sig_opts ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

static int x509_ocsp_get_certs( unsigned char **p, const unsigned char *end,
                                mbedtls_x509_crt *certs )
{
    int ret;
    size_t len;
    unsigned char *cert_p;

    /*
     * certs            SEQUENCE OF Certificate
     *
     * Note: the standard allows an OCSPResponse that has no certs
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = *p + len;

    while( *p < end )
    {
        /*
         * mbedtls_x509_crt_parse_der() takes a buffer and length instead of
         * begining and end (such as the asn1 functions). To make this work
         * we need to parse the SEQUENCE of each Certificate and manually
         * compute the length
         */
        cert_p = *p;

        if( ( ret = mbedtls_asn1_get_tag( &cert_p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        {
            return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
        }

        /*
         * Add the size of the tag and the length octets to the total buffer
         * length
         */
        len += cert_p - *p;

        /*
         * Parse Certificate and populate cur
         *
         * TODO: This is massively innefficient in terms of space because
         * internally mbedtls_x509_crt_parse_der will allocate a buffer for
         * the raw certificates, but mbedtls_x509_ocsp_response already has
         * another buffer.
         */
        if( ( ret = mbedtls_x509_crt_parse_der( certs, *p, len ) ) != 0 )
            return( ret );

        *p = *p + len;
    }

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( ret );
}

static int x509_ocsp_get_response( mbedtls_x509_ocsp_response *resp,
                                   unsigned char **p,
                                   const unsigned char *end )
{
    int ret;
    size_t len;

    /*
     * BasicOCSPResponse ::= SEQUENCE {
     *  tbsResponseData     ResponseData,
     *  signatureAlgorithm  AlgorithmIdentifier,
     *  signature           BIT STRING,
     *  certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );

    end = *p + len;

    /* Parse tbsResponseData */
    if( ( ret = x509_ocsp_get_response_data( resp, p, end ) ) != 0 )
        return( ret );

    /* Parse signatureAlgorithm */
    if( ( ret = x509_ocsp_get_sig_alg( resp, p, end ) ) != 0 )
        return( ret );

    /* Parse signature */
    if( ( ret = mbedtls_x509_get_sig( p, end, &resp->sig ) ) != 0 )
        return( ret );

    /* certs is optional */
    if( *p == end )
        return( 0 );

    /* Get the [0] EXPLICIT tag */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                                MBEDTLS_ASN1_CONSTRUCTED |
                                MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0 ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    /* Parse certs */
    if( ( ret = x509_ocsp_get_certs( p, *p + len, &resp->certs ) ) != 0 )
        return( ret );

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

static int x509_ocsp_get_response_bytes( mbedtls_x509_ocsp_response *resp,
                                         unsigned char **p,
                                         const unsigned char *end )
{
    int ret;
    size_t len;

    /*
     * ResponseBytes ::= SEQUENCE {
     *      responseType    OBJECT IDENTIFIER,
     *      response        OCTET STRING }
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = *p + len;

    /* Parse responseType */
    if( ( ret = x509_ocsp_get_response_type( p, end, &resp->resp_type ) ) != 0 )
        return( ret );

    /*
     * Parse response octet string
     *
     * Note that here the OCTET STRING really is a top-level component for
     * response, so it makes sense to parse it here and let
     * x509_ocsp_get_response() deal with the actual BasicOCSPResponse
     * structure
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                                      MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    /* Parse response */
    if( ( ret = x509_ocsp_get_response( resp, p, *p + len ) ) != 0 )
        return( ret );

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * In general, the idea for each parsing function is to parse the current
 * top-level component and delegate parsing of its members to helper functions.
 * The process can be summarised as follows:
 *     1. Parse the top level component(s) for the current ASN.1 object
 *          - Note that sometimes the top level component contains tagged
 *            subcomponents
 *     2. Calls helper parsing functions for individual subcomponents. Note
 *        that some of the helpers functions are static others are from
 *        asn1parse.c or x509.c
 *     3. Perform any required bounds checking
 *
 * The code is kept consistent throughout for checking bounds. Each parsing
 * function must perform the following check:
 *     1. At the begining, there is enough space in the buffer to parse
 *        whatever is being processed.
 *     2. Prior to returning, the length specified in the ASN1 encoding
 *        matches the number of bytes consumed from the buffer p.
 *     3. The lengths of any intermediate sub-components (such as EXPLICIT
 *        tags) parsed matches the number of bytes consumed by its helper
 *        functions
 */
int mbedtls_x509_ocsp_response_parse( mbedtls_x509_ocsp_response *resp,
                                      const unsigned char *buf, size_t buflen )
{
    int ret;
    size_t len;
    unsigned char *p, *end;

    if( resp == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    p = (unsigned char *)buf;
    len = buflen;
    end = p + len;

    /*
     * OCSPResponse ::= SEQUENCE {
     *      responseStatus      OCSPResponseStatus,
     *      responseBytes       [0] EXPLICIT ResponseBytes OPTIONAL }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    /* This check is a small optimisation to ensure the buffer length matches
     * before we attempt to parse the OCSPResponse. In reality, this check is
     * not needed
     */
    if( p + len != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    /*
     * We do not need to check that len > end - p as this is done by
     * mbedtls_asn1_get_tag().
     */

    /* Populate a new buffer for the raw field */
    resp->raw.tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
    resp->raw.len = len;
    resp->raw.p = mbedtls_calloc( 1, resp->raw.len );
    if( resp->raw.p == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );

    memcpy( resp->raw.p, p, resp->raw.len );

    p = resp->raw.p;
    end = p + resp->raw.len;

    /* Parse responseStatus */
    if( ( ret = x509_ocsp_get_response_status( &p, end,
                                               &resp->resp_status ) ) != 0 )
    {
        return( ret );
    }

    /*
     * Check if responseBytes should be present in the response
     *
     * TODO: It is unclear whether the responseBytes will be included when the
     * response status is a failure. Test missing...
     */
    if( resp->resp_status != MBEDTLS_X509_OCSP_RESPONSE_STATUS_SUCCESSFUL )
    {
        if( p == end )
            return( 0 );
        else
            return( MBEDTLS_ERR_X509_INVALID_FORMAT );
    }
    else if( p == end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );

    /* Get the [0] EXPLICIT tag for the optional ResponseBytes */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
        MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( p + len != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    /* Parse responseBytes */
    if( ( ret = x509_ocsp_get_response_bytes( resp, &p, end ) ) != 0 )
        return( ret );

    /* This might seems slightly redundant, but the idea is that each parsing
     * function checks the begin and end bounds for the section of the
     * OCSPResponse that it parses. This implies that some checks will be
     * duplicated, but it makes it easier to reason about.
     */
    if( p != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

static int x509_ocsp_verify_response_status( mbedtls_x509_ocsp_response *resp,
                                             uint32_t *flags )
{
    switch( resp->resp_status )
    {
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_SUCCESSFUL:
            return( 0 );
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_MALFORMED_REQ:
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_INTERNAL_ERR:
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_TRY_LATER:
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_SIG_REQUIRED:
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_UNAUTHORIZED:
            *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_BAD_RESPONSE_STATUS;
            return( MBEDTLS_ERR_X509_OCSP_RESPONSE_VERIFY_FAILED );
        default:
            return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );
    }
}

static int x509_ocsp_mdcmp( mbedtls_md_type_t md_alg, unsigned char *input,
                            size_t len, unsigned char *output )
{
    int ret;
    const mbedtls_md_info_t *md_info;
    unsigned char *buf;
    size_t md_len;

    if( ( md_info = mbedtls_md_info_from_type( md_alg ) ) == NULL )
        return( MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE );

    md_len = mbedtls_md_get_size( md_info );

    if( ( buf = mbedtls_calloc( md_len, sizeof( unsigned char ) ) ) == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );

    if( ( ret = mbedtls_md( md_info, input, len, buf ) ) != 0 )
        goto exit;

    /* Check whether the hash matches the expected value */
    ret = ( memcmp( buf, output, md_len ) != 0 ) ? 1 : 0;

exit:
    mbedtls_free( buf );

    return( ret );
}

static int x509_ocsp_is_issuer( mbedtls_x509_ocsp_responder_id *responder_id,
                                mbedtls_x509_crt *crt,
                                mbedtls_x509_crt **issuer )
{
    int ret;

    *issuer = NULL;

    switch( responder_id->type )
    {
        case MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_NAME:
            /* Compare the responderID with the candidate issuer's subject */
            if( mbedtls_x509_name_cmp( &responder_id->id.name,
                                                        &crt->subject ) == 0 )
            {
                *issuer = crt;
            }

            return( 0 );

        case MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_KEY_HASH:
            /* Check hash of the certificate issuer's public key matches */
            ret = x509_ocsp_mdcmp( MBEDTLS_MD_SHA1, crt->pk_raw.p,
                                   crt->pk_raw.len, responder_id->id.key.p );
            if( ret < 0 )
                return( ret );
            else if( ret == 0 )
                *issuer = crt;

            return( 0 );

        default:
            return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );
    }
}

/*
 * At this stage the goal is only to find the certificate matching the
 * responderID, but not to verify that it is authorized to issue the OCSP
 * response
 */
static int x509_ocsp_find_response_issuer_crt(
                                            mbedtls_x509_ocsp_response *resp,
                                            mbedtls_x509_crt *chain,
                                            mbedtls_x509_crt **issuer,
                                            uint32_t *flags )
{
    int ret;
    mbedtls_x509_crt *cur;

    *issuer = NULL;

    /* Loop through the certs within the OCSP response */
    for( cur = &resp->certs; cur != NULL; cur = cur->next )
    {
        if( ( ret = x509_ocsp_is_issuer( &resp->responder_id, cur,
                                                            issuer ) ) != 0 )
        {
            return( ret );
        }
        else if( *issuer != NULL )
            return( 0 );
    }

    /* Loop through the chain */
    for( cur = chain; cur != NULL; cur = cur->next )
    {
        if( ( ret = x509_ocsp_is_issuer( &resp->responder_id, cur,
                                                            issuer ) ) != 0 )
        {
            return( ret );
        }
        else if( *issuer != NULL )
            return( 0 );
    }

    /* Could not find an issuer that matches the responderID */
    *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_ISSUER_NOT_TRUSTED;

    return( 0 );
}

static int x509_ocsp_verify_sig( mbedtls_x509_ocsp_response *resp,
                                 mbedtls_x509_crt *issuer, uint32_t *flags )
{
    int ret;
    unsigned char *md;
    const mbedtls_md_info_t *md_info;
    size_t md_size;

    if( issuer == NULL )
    {
        *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_NOT_TRUSTED;
        return( 0 );
    }

    if( ( md_info = mbedtls_md_info_from_type( resp->sig_md ) ) == NULL )
        return( MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE );

    md_size = mbedtls_md_get_size( md_info );

    /* Allocate memory to hold the hash of the ResponseData */
    if( ( md = mbedtls_calloc( md_size, sizeof( unsigned char ) ) ) == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );

    /* Calculate hash of the DER encoded ResponseData */
    if( ( ret = mbedtls_md( md_info, resp->response_data.p,
                                        resp->response_data.len, md ) ) != 0 )
    {
        goto exit;
    }

    /* Verify the signature */
    ret = mbedtls_pk_verify_ext( resp->sig_pk, resp->sig_opts, &issuer->pk,
                                 resp->sig_md, md, md_size, resp->sig.p,
                                 resp->sig.len );
    /*
     * Do not abort the verification process if the signature checks fail,
     * only flag it
     */
    if( ret != 0 )
        *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_NOT_TRUSTED;

    ret = 0;

exit:
    mbedtls_free( md );

    return( ret );
}

/*
 * Check if 'parent' is a suitable parent (signing CA) for 'child'.
 * Return 0 if yes, -1 if not.
 *
 * is_trusted_ca means parent is a locally-trusted certificate
 */
static int x509_ocsp_crt_check_parent( mbedtls_x509_crt *child,
                                       mbedtls_x509_crt *parent,
                                       int is_trust_ca )
{
    int need_ca_bit;

    /* Parent must be the issuer */
    if( mbedtls_x509_name_cmp( &child->issuer, &parent->subject ) != 0 )
        return( -1 );

    /* Parent must have the basicConstraints CA bit set as a general rule */
    need_ca_bit = 1;

    /* Exception: v1/v2 certificates that are locally trusted. */
    if( is_trust_ca && parent->version < 3 )
        need_ca_bit = 0;

    if( need_ca_bit && ! parent->ca_istrue )
        return( -1 );

#if defined(MBEDTLS_X509_CHECK_KEY_USAGE)
    if( need_ca_bit && mbedtls_x509_crt_check_key_usage( parent,
                                        MBEDTLS_X509_KU_KEY_CERT_SIGN ) != 0 )
    {
        return( -1 );
    }
#endif

    return( 0 );

}

static int x509_ocsp_crt_check_signature( mbedtls_x509_crt *child,
                                          mbedtls_x509_crt *parent )
{
    int ret;
    const mbedtls_md_info_t *md_info;
    unsigned char *buf;
    size_t md_len;

    if( ( md_info = mbedtls_md_info_from_type( child->sig_md ) ) == NULL )
        return( MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE );

    md_len = mbedtls_md_get_size( md_info );

    if( ( buf = mbedtls_calloc( md_len, sizeof( unsigned char ) ) ) == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );

    if( ( ret = mbedtls_md( md_info, child->tbs.p, child->tbs.len,
                                                                buf ) ) != 0 )
    {
        goto exit;
    }

    ret = mbedtls_pk_verify_ext( child->sig_pk, child->sig_opts, &parent->pk,
                                 child->sig_md, buf, md_len, child->sig.p,
                                 child->sig.len );

exit:
    mbedtls_free( buf );

    return( ret );
}

static int x509_ocsp_is_parent_crt(
                                mbedtls_x509_ocsp_single_response *single_resp,
                                mbedtls_x509_crt *child,
                                mbedtls_x509_crt *parent,
                                int is_trust_ca,
                                int *is_parent )
{
    int ret;

    *is_parent = 0;

    /*
     * Check parental relationship using information in the OCSP response
     */

    /*
     * Note that we cannot check the hash of the parent's DN because it is
     * possible for the DN in the certificate's issuer to be syntactically
     * different from parent certificate's subject, yet still be the parent
     */

    /* Check hash of parent's public key */
    ret = x509_ocsp_mdcmp( single_resp->md_alg, parent->pk_raw.p,
                           parent->pk_raw.len,
                           single_resp->issuer_key_hash.p );
    if( ret < 0 )
        return( ret );
    else if( ret != 0 )
        return( 0 );

    /*
     * Confirm parental relationship using the child certificate
     */

    /* Basic parenting skills (name, CA bit, key usage) */
    if( x509_ocsp_crt_check_parent( child, parent, is_trust_ca ) != 0 )
        return( 0 );

    /* Signature */
    if( x509_ocsp_crt_check_signature( child, parent ) != 0 )
        return( 0 );

    /*
     * Optional time check.
     *
     * TODO: Not sure whether we should accept time-invalid certificates
     */
    if( mbedtls_x509_time_is_past( &parent->valid_to ) ||
        mbedtls_x509_time_is_future( &parent->valid_from ) )
        return( 0 );

    /* Found parent of the requested certificate's status */
    *is_parent = 1;

    return( 0 );
}

static int x509_ocsp_find_parent_crt(
                                mbedtls_x509_ocsp_single_response *single_resp,
                                mbedtls_x509_crt *child,
                                mbedtls_x509_crt *chain,
                                int is_trust_ca,
                                mbedtls_x509_crt **parent )
{
    int ret;
    int is_parent = 0;
    mbedtls_x509_crt *cur;

    *parent = NULL;

    for( cur = chain; cur != NULL; cur = cur->next )
    {
        if( ( ret = x509_ocsp_is_parent_crt( single_resp, child, cur,
                                        is_trust_ca, &is_parent ) ) != 0 )
        {
            return( ret );
        }
        else if( is_parent == 0 )
            continue;

        /* Found parent of the requested certificate's status */
        *parent = cur;

        return( 0 );
    }

    return( 0 );
}

/*
 * According to RFC 6960 Section 4.2.2.2 the OCSP response issuer can be:
 *  1. A locally configured signing authority (TODO: Not implemented)
 *  2. The certificate of the CA that issued the certificate in question
 *  3. A certificate that includes the value of id-kp-OCSPSigning in an
 *     extended key usage extension and is issued by the CA that issued
 *     the certificate in question
 */
static int x509_ocsp_verify_response_issuer(
                                mbedtls_x509_ocsp_single_response *single_resp,
                                mbedtls_x509_crt *req_crt,
                                mbedtls_x509_crt *chain,
                                mbedtls_x509_crt *trust_ca,
                                mbedtls_x509_crt *issuer,
                                uint32_t *flags )
{
    int ret;
    int is_parent = 0;
    int is_trust_ca = 0;
    mbedtls_x509_crt *parent = NULL;

    /* Check whether the issuer is the parent of the requested certificate */
    if( ( ret = x509_ocsp_is_parent_crt( single_resp, req_crt, issuer, 0,
                                                        &is_parent ) ) != 0 )
    {
        return( ret );
    }
    else if( is_parent != 0 )
    {
        /*
         * Condition 2 was satisfied: The issuer is the parent of the requested
         * certificate
         */
        return( 0 );
    }

#if defined(MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE)
    /* Check that the issuer includes the value of id-kp-OCSPSigning */
    if( ( ret = mbedtls_x509_crt_check_extended_key_usage( issuer,
                        MBEDTLS_OID_OCSP_SIGNING,
                        MBEDTLS_OID_SIZE( MBEDTLS_OID_OCSP_SIGNING ) ) ) != 0 )
    {
        *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_ISSUER_NOT_TRUSTED;
        return( ret );
    }

    /*
     * Check that issuer and requested certificate have the same parent.
     *
     * TODO: Currently we try to locate the parent in the untrusted chain,
     * and the trust_ca chain. Should we also look in the OCSP response's
     * certs list? RFC 6960 Section 4.2.1 states that "the responder MAY
     * include certificates in the certs field of BasicOCSPResponse that
     * help the OCSP client verify the responder's signature". Strictly
     * speaking we do notuse the parent to directly verify the response's,
     * so we do not search the parent
     */
    if( ( ret = x509_ocsp_find_parent_crt( single_resp, issuer, trust_ca, 1,
                                                            &parent ) ) != 0 )
    {
        return( ret );
    }
    else if( parent == NULL )
    {
        if( ( ret = x509_ocsp_find_parent_crt( single_resp, issuer, chain,
                                                        0, &parent ) ) != 0 )
        {
            return( ret );
        }
        else if( parent == NULL )
        {
            *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_ISSUER_NOT_TRUSTED;
            return( 0 );
        }
    }
    else
        is_trust_ca = 1;

    if( ( ret = x509_ocsp_is_parent_crt( single_resp, req_crt, parent,
                                            is_trust_ca, &is_parent ) ) != 0 )
    {
        return( ret );
    }
    else if( is_parent != 0 )
    {
        /*
         * Condition 3 was satisfied: The issuer and requested certificate
         * have the same parent
         */
        return( 0 );
    }
#endif /* MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE */

    *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_ISSUER_NOT_TRUSTED;
    return( 0 );
}

static int x509_ocsp_verify_cert_status(
                                mbedtls_x509_ocsp_single_response *single_resp,
                                uint32_t *flags )
{
    switch( single_resp->cert_status )
    {
        case MBEDTLS_X509_OCSP_CERT_STATUS_GOOD:
            break;
        case MBEDTLS_X509_OCSP_CERT_STATUS_REVOKED:
            *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_REVOKED_CERT;

            /* Check that the revocationTime is earlier than now */
            if( mbedtls_x509_time_is_future(
                                    &single_resp->revocation_time ) != 0 )
            {
                *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_FUTURE;
            }

            break;
        case MBEDTLS_X509_OCSP_CERT_STATUS_UNKNOWN:
            *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_UNKNOWN_CERT;
            break;
        default:
            return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );
    }

    return( 0 );
}

static int x509_ocsp_find_single_response( mbedtls_x509_crt *crt,
                            mbedtls_x509_ocsp_single_response *chain,
                            mbedtls_x509_ocsp_single_response **single_resp )
{
    int ret;
    mbedtls_x509_ocsp_single_response *cur;

    *single_resp = NULL;

    /*
     *
     * TODO: This code will find the first SingleResponse element whose
     * certificate ID matches the current certificate being processed. If
     * the verification code below fails, then we do not look if there is
     * another SingleResponse for the same certificate that actually
     * checks out. However, this seems a bit strange and I am not sure if
     * it would happen in practice.
     */
    for( cur = chain; cur != NULL; cur = cur->next )
    {
        /* Compare certificate and SingleResponse serial numbers */
        if( mbedtls_x509_serial_cmp( &crt->serial, &cur->serial ) != 0 )
            continue;

        /*
         * Ensure the certificate's issuer matches the SingleResponse
         * issuerNameHash in the certID
         */
        ret = x509_ocsp_mdcmp( cur->md_alg, crt->issuer_raw.p,
                               crt->issuer_raw.len, cur->issuer_name_hash.p );
        if( ret < 0 )
            return( ret );
        else if( ret != 0 )
            continue;

        /* All checks passed, found SingleResponse that matches certificate */
        *single_resp = cur;

        return( 0 );
    }

    return( 0 );
}

static int x509_ocsp_verify_responses( mbedtls_x509_ocsp_response *resp,
                                       mbedtls_x509_crt *req_chain,
                                       mbedtls_x509_crt *chain,
                                       mbedtls_x509_crt *trust_ca,
                                       mbedtls_x509_crt *issuer,
                                       uint32_t *flags )
{
    int ret;
    mbedtls_x509_crt *cur;
    mbedtls_x509_ocsp_single_response *single_resp;

    /*
     * RFC 6960 Section 4.2.2.3: The response MUST include SingleResponse for
     * each certificate in the request. The response SHOULD NOT include any
     * additional SingleResponse elements...
     */
    for( cur = req_chain; cur != NULL; cur = cur->next )
    {
        /* Identify the SingleResponse for this certificate */
        if( ( ret = x509_ocsp_find_single_response( cur, &resp->single_resp,
                                            &single_resp ) ) != 0 )
        {
            return( ret );
        }
        else if( single_resp == NULL )
        {
            /* Flag if the SingleResponse for this certificate is not found */
            *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_INCOMPLETE;
            continue;
        }

        /*
         * Check that nextUpdate is an later than now (if available).
         *
         * RFC 6960 Section 4.2.2.1: Responses whose nextUpdate value is
         * earlier than the local system time SHOULD be considered unreliable
         */
        if( single_resp->has_next_update == 1 &&
            mbedtls_x509_time_is_past( &single_resp->next_update ) != 0 )
        {
            *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_EXPIRED;
        }

        /*
         * Check that thisUpdate is earlier than now.
         *
         * RFC 6960 Section 4.2.2.1: Responses whose thisUpdate time is later
         * than the local system time SHOULD be considered unreliable
         */
        if( mbedtls_x509_time_is_future( &single_resp->this_update ) != 0 )
            *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_FUTURE;

        /* Check the revocation status of the certificate */
        if( ( ret = x509_ocsp_verify_cert_status( single_resp, flags ) ) != 0 )
            return( ret );

        /*
         * Nothing to verify because we do not know who signed the response. If
         * the issuer is not found the appropriate flags would have been set in
         * x509_ocsp_find_issuer_crt()
         */
        if( issuer == NULL )
            continue;

        /*
         * Check that the issuer is authorised to sign a response for this
         * certificate
         */
        if( ( ret = x509_ocsp_verify_response_issuer( single_resp, cur, chain,
                                            trust_ca, issuer, flags ) ) != 0 )
        {
            return( ret );
        }
    }

    return( 0 );
}

/*
 * TODO:
 *  - We cannot accept locally configured signing authority for each CA
 *  - We cannot accept a tolerance value for timestamps
 *  - We cannot configure parameters such as allowed signature algorithms, etc
 *  - Do not have an auth_mode=optional flag
 *  - Need to check the revocation status of the OCSP response issuer
 */
int mbedtls_x509_ocsp_response_verify( mbedtls_x509_ocsp_response *resp,
                                       mbedtls_x509_crt *req_chain,
                                       mbedtls_x509_crt *chain,
                                       mbedtls_x509_crt *trust_ca,
                                       uint32_t *flags )
{
    int ret;
    mbedtls_x509_crt *issuer;

    *flags = 0;

    if( resp == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    /*
     * Check if the response has a definite status. If there is a failure here
     * it means that either we did not get a definitive response or the input
     * data was invalid. In both cases we cannot continue verifying the
     * response
     */
    if( ( ret = x509_ocsp_verify_response_status( resp, flags ) ) != 0 )
        return( ret );

    /*
     * Check if producedAt is in the past
     *
     * TODO: We might want to check this against some threshold
     */
    if( mbedtls_x509_time_is_future( &resp->produced_at ) != 0 )
        *flags |= MBEDTLS_X509_BADOCSP_RESPONSE_FUTURE;

    /*
     * Find the OCSP response issuer. If there is a failure here it means that
     * the input data was invalid, in which case we return.
     *
     * TODO: Maybe look for the issuer in the trust_ca chain
     * TODO: Maybe look for the issuer in the req_chain
     */
    if( ( ret = x509_ocsp_find_response_issuer_crt( resp, chain, &issuer,
                                                            flags ) ) != 0 )
    {
        return( ret );
    }

    /* Verify the OCSP response signature */
    if( ( ret = x509_ocsp_verify_sig( resp, issuer, flags ) ) != 0 )
        return( ret );

    /* Verify each of the responses */
    if( ( ret = x509_ocsp_verify_responses( resp, req_chain, chain, trust_ca,
                                                    issuer, flags ) ) != 0 )
    {
        return( ret );
    }

    /* Fail if something does not check out */
    if( *flags != 0 )
        return( MBEDTLS_ERR_X509_OCSP_RESPONSE_VERIFY_FAILED );

    return( 0 );
}

static int x509_ocsp_response_status_info( char *buf, size_t size,
                                           uint8_t resp_status )
{
    int ret;
    const char *desc;
    size_t n = size;
    char *p = buf;

    switch( resp_status )
    {
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_SUCCESSFUL:
            desc = "successful";
            break;
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_MALFORMED_REQ:
            desc = "malformedRequest";
            break;
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_INTERNAL_ERR:
            desc = "internalError";
            break;
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_TRY_LATER:
            desc = "tryLater";
            break;
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_SIG_REQUIRED:
            desc = "sigRequired";
            break;
        case MBEDTLS_X509_OCSP_RESPONSE_STATUS_UNAUTHORIZED:
            desc = "unauthorized";
            break;
        default:
            desc = "???";
    }

    ret = mbedtls_snprintf( p, n, "%s", desc );
    MBEDTLS_X509_SAFE_SNPRINTF;

    return( (int)( size - n ) );
}

static int x509_ocsp_response_type_info( char *buf, size_t size,
                                         const mbedtls_x509_buf *resp_type )
{
    int ret;
    const char *desc;
    size_t n = size;
    char *p = buf;

    if( mbedtls_oid_get_ocsp_response_type( resp_type, &desc ) != 0 )
        desc = "???";

    ret = mbedtls_snprintf( p, n, "%s", desc );
    MBEDTLS_X509_SAFE_SNPRINTF;

    return( (int)( size - n ) );
}

static int x509_ocsp_responder_id_info( char *buf, size_t size,
                        const mbedtls_x509_ocsp_responder_id *responder_id )
{
    int ret;
    size_t n = size;
    size_t i;
    char *p = buf;

    switch( responder_id->type )
    {
        case MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_NAME:
            ret = mbedtls_snprintf( p, n, "[%s] ", "Name" );
            MBEDTLS_X509_SAFE_SNPRINTF;
            ret = mbedtls_x509_dn_gets( p, n, &responder_id->id.name );
            MBEDTLS_X509_SAFE_SNPRINTF;
            break;
        case MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_KEY_HASH:
            ret = mbedtls_snprintf( p, n, "[%s] ", "KeyHash" );
            MBEDTLS_X509_SAFE_SNPRINTF;
            for( i = 0; i < responder_id->id.key.len; i++ )
            {
                ret = mbedtls_snprintf( p, n, "%02X",
                                        responder_id->id.key.p[i] );
                MBEDTLS_X509_SAFE_SNPRINTF;
            }
            break;
        default:
            ret = mbedtls_snprintf( p, n, "[???] " );
            MBEDTLS_X509_SAFE_SNPRINTF;
    }

    return( (int)( size - n ) );
}

#define BC      "18"
static int x509_ocsp_responses_info( char *buf, size_t size,
                        const char *prefix,
                        const mbedtls_x509_ocsp_single_response *responses )
{
    int ret;
    size_t n = size;
    char *p = buf;
    const mbedtls_x509_ocsp_single_response *cur = responses;
    const char *desc;

    /* Nothing to display */
    if( cur->md_oid.p == NULL )
    {
        ret = mbedtls_snprintf( p, n, "\n%s%sThere are no responses",
                                prefix, prefix );
        MBEDTLS_X509_SAFE_SNPRINTF;
        return( (int)( size - n ) );
    }

    for( ; cur != NULL; cur = cur->next )
    {
        /* Print hashAlgorithm */
        if( ( ret = mbedtls_oid_get_md_alg_desc( &cur->md_oid, &desc ) ) != 0 )
            desc = "???";
        ret = mbedtls_snprintf( p, n, "\n%s%s%-" BC "s: %s", prefix, prefix,
                                "hash alg.", desc );
        MBEDTLS_X509_SAFE_SNPRINTF;

        /* Print serialNumber */
        ret = mbedtls_snprintf( p, n, "\n%s%s%-" BC "s: ", prefix, prefix,
                                "serial number" );
        MBEDTLS_X509_SAFE_SNPRINTF;

        ret = mbedtls_x509_serial_gets( p, n, &cur->serial );
        MBEDTLS_X509_SAFE_SNPRINTF;

        /* Print certificate status */
        switch( cur->cert_status )
        {
            case MBEDTLS_X509_OCSP_CERT_STATUS_GOOD:
                desc = "good";
                break;
            case MBEDTLS_X509_OCSP_CERT_STATUS_REVOKED:
                desc = "revoked";
                break;
            case MBEDTLS_X509_OCSP_CERT_STATUS_UNKNOWN:
                desc = "unknown";
                break;
            default:
                desc = "???";
        }

        ret = mbedtls_snprintf( p, n, "\n%s%s%-" BC "s: %s", prefix, prefix,
                                "cert. status", desc );
        MBEDTLS_X509_SAFE_SNPRINTF;

        /* Print revocation information (if available) */
        if( cur->cert_status == MBEDTLS_X509_OCSP_CERT_STATUS_REVOKED )
        {
            ret = mbedtls_snprintf( p, n, "\n%s%s%-" BC "s: "
                        "%04d-%02d-%02d %02d:%02d:%02d",
                        prefix, prefix, "revocation time",
                        cur->revocation_time.year, cur->revocation_time.mon,
                        cur->revocation_time.day,  cur->revocation_time.hour,
                        cur->revocation_time.min,  cur->revocation_time.sec );
            MBEDTLS_X509_SAFE_SNPRINTF;
        }

        if( cur->has_revocation_reason )
        {
            switch( cur->revocation_reason )
            {
                case MBEDTLS_X509_CRL_REASON_UNSPECIFIED:
                    desc = "unspecified";
                    break;
                case MBEDTLS_X509_CRL_REASON_KEY_COMPROMISE:
                    desc = "keyCompromise";
                    break;
                case MBEDTLS_X509_CRL_REASON_CA_COMPROMISE:
                    desc = "cACompromise";
                    break;
                case MBEDTLS_X509_CRL_REASON_AFFILIATION_CHANGED:
                    desc = "affiliationChanged";
                    break;
                case MBEDTLS_X509_CRL_REASON_SUPERSEDED:
                    desc = "siperseded";
                    break;
                case MBEDTLS_X509_CRL_REASON_CESSATION_OF_OPERATION:
                    desc = "cessationOfOperation";
                    break;
                case MBEDTLS_X509_CRL_REASON_CERTIFICATE_HOLD:
                    desc = "certificateHold";
                    break;
                case MBEDTLS_X509_CRL_REASON_REMOVE_FROM_CRL:
                    desc = "removeFromCRL";
                    break;
                case MBEDTLS_X509_CRL_REASON_PRIVILEGE_WITHDRAWN:
                    desc = "priviledeWithdrawn";
                    break;
                case MBEDTLS_X509_CRL_REASON_AA_COMPROMISE:
                    desc = "aACompromise";
                    break;
                default:
                    desc = "???";
            }

            ret = mbedtls_snprintf( p, n, "\n%s%s%-" BC "s: %s", prefix,
                                    prefix, "revocation reason", desc );
            MBEDTLS_X509_SAFE_SNPRINTF;
        }

        /* Print thisUpdate */
        ret = mbedtls_snprintf( p, n, "\n%s%s%-" BC "s: "
                                "%04d-%02d-%02d %02d:%02d:%02d",
                                prefix, prefix,"this update",
                                cur->this_update.year, cur->this_update.mon,
                                cur->this_update.day,  cur->this_update.hour,
                                cur->this_update.min,  cur->this_update.sec );
        MBEDTLS_X509_SAFE_SNPRINTF;

        /* Print nextUpdate (if available) */
        if( cur->has_next_update != 0 )
        {
            ret = mbedtls_snprintf( p, n, "\n%s%s%-" BC "s: "
                                "%04d-%02d-%02d %02d:%02d:%02d\n",
                                prefix, prefix, "next update",
                                cur->next_update.year, cur->next_update.mon,
                                cur->next_update.day,  cur->next_update.hour,
                                cur->next_update.min,  cur->next_update.sec );
            MBEDTLS_X509_SAFE_SNPRINTF;
        }
    }

    return( (int)( size - n ) );
}

#define X509_OCSP_SAFE_SNPRINTF                             \
    do {                                                    \
        if( ret < 0 || (size_t) ret >= n )                  \
        {                                                   \
            ret = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;        \
            goto exit;                                      \
        }                                                   \
                                                            \
        n -= (size_t) ret;                                  \
        p += (size_t) ret;                                  \
    } while( 0 )
static int x509_ocsp_certs_info( char *buf, size_t size, const char *prefix,
                                 const mbedtls_x509_crt *certs )
{
    int ret;
    size_t n = size;
    char *p = buf;
    size_t prefix_len = strlen( prefix );
    char *double_prefix;
    const mbedtls_x509_crt *cur;

    if( certs->raw.p == NULL )
    {
        ret = mbedtls_snprintf( p, n, "\n%s%sThere are no certs",
                                prefix, prefix );
        MBEDTLS_X509_SAFE_SNPRINTF;

        return( (int)( size - n ) );
    }
    else if( prefix_len == 0 )
    {
        prefix = " ";
        prefix_len = strlen( prefix );
    }
    else if( prefix_len > SIZE_MAX / 2 )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );

    /* Allocate a new buffer that will contain the prefix string twice */
    double_prefix = mbedtls_calloc( 1, prefix_len * 2 + 1 );
    if( double_prefix == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );

    strcpy( double_prefix, prefix );
    strcat( double_prefix, prefix );

    ret = mbedtls_snprintf( p, n, "\n" );
    X509_OCSP_SAFE_SNPRINTF;

    for( cur = certs; cur != NULL; cur = cur->next )
    {
        ret = mbedtls_x509_crt_info( p, n, double_prefix, cur );
        X509_OCSP_SAFE_SNPRINTF;
    }

    ret = 0;

exit:
    mbedtls_free( double_prefix );

    return( ret );
}


int mbedtls_x509_ocsp_response_info( char *buf, size_t size,
                                     const char *prefix,
                                     const mbedtls_x509_ocsp_response *resp )
{
    int ret;
    size_t n;
    char *p;

    p = buf;
    n = size;

    /*
     * NOTE: Just like mbedtls_x509_crt_info() this function will print rubbish
     * if resp has been initialised but nothing has been parsed.
     */
    if( resp == NULL )
    {
        ret = mbedtls_snprintf( p, n, "\nOCSP Response is uninitialised!\n" );
        MBEDTLS_X509_SAFE_SNPRINTF;

        return( (int)( size - n ) );
    }

    /* Print responseStatus */
    ret = mbedtls_snprintf( p, n, "%s%-" BC "s: ", prefix, "response status" );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = x509_ocsp_response_status_info( p, n, resp->resp_status );
    MBEDTLS_X509_SAFE_SNPRINTF;

    /*
     * The remaining data from the OCSPResponse is optional. We can find
     * whether the information is present by checking that the responseType is
     * set
     */
    if( resp->resp_type.p == NULL )
        return( (int)( size - n ) );

    /* Print responseType */
    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s: ", prefix, "response type" );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = x509_ocsp_response_type_info( p, n, &resp->resp_type );
    MBEDTLS_X509_SAFE_SNPRINTF;

    /* Print version */
    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s: %d", prefix,
                            "response version", resp->version );
    MBEDTLS_X509_SAFE_SNPRINTF;

    /* Print responderID */
    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s: ", prefix, "responder ID" );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = x509_ocsp_responder_id_info( p, n, &resp->responder_id );
    MBEDTLS_X509_SAFE_SNPRINTF;

    /* Print producedAt date */
    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s: "
                        "%04d-%02d-%02d %02d:%02d:%02d", prefix, "produced at",
                        resp->produced_at.year, resp->produced_at.mon,
                        resp->produced_at.day,  resp->produced_at.hour,
                        resp->produced_at.min,  resp->produced_at.sec );
    MBEDTLS_X509_SAFE_SNPRINTF;

    /* Print signatureAlgorithm */
    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s: ", prefix, "signed using" );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_x509_sig_alg_gets( p, n, &resp->sig_oid, resp->sig_pk,
                                     resp->sig_md, resp->sig_opts );
    MBEDTLS_X509_SAFE_SNPRINTF;

    /* Print list of responses */
    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s:", prefix, "responses" );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = x509_ocsp_responses_info( p, n, prefix, &resp->single_resp );
    MBEDTLS_X509_SAFE_SNPRINTF;

    /* Print list of certificates */
    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s:", prefix, "certs" );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = x509_ocsp_certs_info( p, n, prefix, &resp->certs );
    MBEDTLS_X509_SAFE_SNPRINTF;

    return( (int)( size - n ) );
}

static const mbedtls_x509_verify_string x509_ocsp_response_verify_strings[] = {
    { MBEDTLS_X509_BADOCSP_RESPONSE_FUTURE,                 "The response validity starts in the future" },
    { MBEDTLS_X509_BADOCSP_RESPONSE_BAD_RESPONSE_STATUS,    "The response status is an exception value (i.e it is not 'success')" },
    { MBEDTLS_X509_BADOCSP_RESPONSE_ISSUER_NOT_TRUSTED,     "The response issuer certificate was not found or failed the acceptance requirements" },
    { MBEDTLS_X509_BADOCSP_RESPONSE_NOT_TRUSTED,            "The response is not correctly signed by an authorized responder" },
    { MBEDTLS_X509_BADOCSP_RESPONSE_INCOMPLETE,             "The response does not contain the status of all queried certificates" },
    { MBEDTLS_X509_BADOCSP_RESPONSE_EXPIRED,                "The response validity has expired" },
    { MBEDTLS_X509_BADOCSP_RESPONSE_REVOKED_CERT,           "The revocation status of at least one queried certificate is 'revoked'" },
    { MBEDTLS_X509_BADOCSP_RESPONSE_UNKNOWN_CERT,           "The revocation status of at least one queried certificate is 'unknown'" },
    { 0, NULL },
};

int mbedtls_x509_ocsp_response_verify_info( char *buf, size_t size,
                                            const char *prefix,
                                            uint32_t flags )
{
    return( mbedtls_x509_verify_info( buf, size, prefix, flags,
                                      x509_ocsp_response_verify_strings ) );
}

int mbedtls_x509_ocsp_response_parse_file( mbedtls_x509_ocsp_response *resp,
                                           const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = mbedtls_x509_ocsp_response_parse( resp, buf, n );

    mbedtls_zeroize( buf, n );
    mbedtls_free( buf );

    return( ret );
}
#endif /* MBEDTLS_X509_OCSP_PARSE_C */
