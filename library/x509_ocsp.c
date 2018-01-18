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
