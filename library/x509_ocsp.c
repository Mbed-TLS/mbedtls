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
}

void mbedtls_x509_ocsp_response_free( mbedtls_x509_ocsp_response *resp )
{
}

static int x509_ocsp_get_response_status( unsigned char **p,
                                          const unsigned char *end,
                                          uint8_t *resp_status )
{
    int ret;
    size_t len;

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
            return( MBEDTLS_ERR_X509_OCSP_INVALID_RESPONSE_STATUS );
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

    if( MBEDTLS_OID_CMP( MBEDTLS_OID_OCSP, resp_type ) != 0 &&
        MBEDTLS_OID_CMP( MBEDTLS_OID_OCSP_BASIC, resp_type ) != 0 )
    {
        return( MBEDTLS_ERR_X509_OCSP_INVALID_RESPONSE_TYPE );
    }

    *p = *p + len;

    return( 0 );
}

static int x509_ocsp_get_extensions( unsigned char **p,
                                     const unsigned char *end )
{
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

        if( *p + len != end )
            return( MBEDTLS_ERR_X509_INVALID_VERSION +
                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

        if( ( ret = mbedtls_x509_get_name( p, end,
                                           &responder_id->id.name ) ) != 0 )
        {
            return( ret );
        }

        responder_id->type = MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_NAME;
    }
    else if( tag == ( base_tag |
                      MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_KEY_HASH ) )
    {
        /* KeyHash ::= OCTET STRING */
        if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                                          MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        {
           return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
        }

        responder_id->type = MBEDTLS_X509_OCSP_RESPONDER_ID_TYPE_KEY_HASH;
        responder_id->id.key.len = len;
        responder_id->id.key.p = *p;
        responder_id->id.key.tag = MBEDTLS_ASN1_OCTET_STRING;

        *p = *p + len;
    }
    else
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_VERSION +
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
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );

    if( ( ret = mbedtls_x509_get_time( p, end, t ) ) != 0 )
        return( ret );

    return( 0 );
}

static int x509_ocsp_get_single_response( unsigned char **p,
                                          const unsigned char *end,
                                    mbedtls_x509_ocsp_single_response *cur )
{
    return( 0 );
}

static int x509_ocsp_get_responses( unsigned char **p,
                                    const unsigned char *end,
                            mbedtls_x509_ocsp_single_response *single_resp )
{
    int ret;
    size_t len;
    mbedtls_x509_ocsp_single_response *cur = single_resp;

    /*
     * responses               SEQUENCE OF SingleResponse
     *
     * Note: the standard allows an OCSPResponse that has no responses
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = *p + len;

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
                return( MBEDTLS_ERR_X509_INVALID_FORMAT );

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
    return( 0 );
}

static int x509_ocsp_get_certs( unsigned char **p, const unsigned char *end,
                                mbedtls_x509_crt *certs )
{
    return( 0 );
}

static int x509_ocsp_get_response( mbedtls_x509_ocsp_response *resp,
                                   unsigned char **p,
                                   const unsigned char *end )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                                      MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( *p + len != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    /*
     * BasicOCSPResponse ::= SEQUENCE {
     *  tbsResponseData     ResponseData,
     *  signatureAlgorithm  AlgorithmIdentifier,
     *  signature           BIT STRING,
     *  certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )

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

    if( *p + len != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

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

    /* Parse the responseType */
    if( ( ret = x509_ocsp_get_response_type( p, end, &resp->resp_type ) ) != 0 )
        return( ret );

    /* Parse the response octet string */
    if( ( ret = x509_ocsp_get_response( resp, p, end ) ) != 0 )
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
int mbedtls_x509_ocsp_parse_response( mbedtls_x509_ocsp_response *resp,
                                      unsigned char *buf, size_t buflen )
{
    int ret;
    size_t len;
    unsigned char *p, *end;

    if( resp == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    p = buf;
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
    if( ( ret = x509_ocsp_get_response_status( &p, end,
                                               &resp->resp_status ) ) != 0 )
    {
        return( ret );
    }

    /* ResponseBytes is optional, skip if not found */
    if( p == end )
        return( 0 );

    /* Get the [0] EXPLICIT tag for the optional ResponseBytes */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
        MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0 ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( p + len != end )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

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

static int x509_ocsp_info_response_status( char **buf, size_t *size,
                                           uint8_t resp_status )
{
    int ret;
    const char *desc;
    size_t n = *size;
    char *p = *buf;

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

    *size = n;
    *buf = p;

    return( 0 );
}

static int x509_ocsp_info_response_type( char **buf, size_t *size,
                                         const mbedtls_x509_buf *resp_type )
{
    int ret;
    const char *desc;
    size_t n = *size;
    char *p = *buf;

    if( mbedtls_oid_get_ocsp_response_type( resp_type, &desc ) != 0 )
        desc = "???";

    ret = mbedtls_snprintf( p, n, "%s", desc );
    MBEDTLS_X509_SAFE_SNPRINTF;

    *size = n;
    *buf = p;

    return( 0 );
}

static int x509_ocsp_info_responder_id( char **buf, size_t *size,
                        const mbedtls_x509_ocsp_responder_id *responder_id )
{
    int ret;
    size_t n = *size;
    size_t i;
    char *p = *buf;

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

    *size = n;
    *buf = p;

    return( 0 );
}

#define BC      "18"
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
    if( ( ret = x509_ocsp_info_response_status( &p, &n,
                                                resp->resp_status ) ) != 0 )
    {
        return( ret );
    }

    /*
     * The remaining data from the OCSPResponse is optional. We can find
     * whether the information is present by checking that the responseType is
     * set
     */
    if( resp->resp_type.p == NULL )
        return( 0 );

    /* Print responseType */
    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s: ", prefix, "response type" );
    MBEDTLS_X509_SAFE_SNPRINTF;
    if( ( ret = x509_ocsp_info_response_type( &p, &n,
                                              &resp->resp_type ) ) != 0 )
    {
        return( ret );
    }

    /* Print version */
    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s: %d", prefix,
                            "response version", resp->version );
    MBEDTLS_X509_SAFE_SNPRINTF;

    /* Print responderID */
    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s: ", prefix, "responder ID" );
    MBEDTLS_X509_SAFE_SNPRINTF;
    if( ( ret = x509_ocsp_info_responder_id( &p, &n,
                                             &resp->responder_id ) ) != 0 )
    {
        return( ret );
    }

    /* Print producedAt date */
    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s: "
                        "%04d-%02d-%02d %02d:%02d:%02d", prefix, "produced at",
                        resp->produced_at.year, resp->produced_at.mon,
                        resp->produced_at.day,  resp->produced_at.hour,
                        resp->produced_at.min,  resp->produced_at.sec );
    MBEDTLS_X509_SAFE_SNPRINTF;

    return( 0 );
}

int mbedtls_x509_ocsp_parse_response_file( mbedtls_x509_ocsp_response *resp,
                                           const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = mbedtls_x509_ocsp_parse_response( resp, buf, n );

    mbedtls_zeroize( buf, n );
    mbedtls_free( buf );

    return( ret );
}
