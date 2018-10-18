/*
 *  X.509 Certificate Signing Request (CSR) parsing
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
/*
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 *  http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X509_CSR_PARSE_C)

#include "mbedtls/x509_csr.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_free       free
#define mbedtls_calloc    calloc
#define mbedtls_snprintf   snprintf
#endif

#if defined(MBEDTLS_FS_IO) || defined(EFIX64) || defined(EFI32)
#include <stdio.h>
#endif

/*
 *  Version  ::=  INTEGER  {  v1(0)  }
 */
static int x509_csr_get_version( unsigned char **p,
                             const unsigned char *end,
                             int *ver )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_int( p, end, ver ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            *ver = 0;
            return( 0 );
        }

        return( MBEDTLS_ERR_X509_INVALID_VERSION + ret );
    }

    return( 0 );
}

/*
 * Extension Request
 *
 */
static int x509_get_csr_ext_req( unsigned char **p,
                                 const unsigned char *end,
                                 mbedtls_x509_csr *csr )
{
    int ret;
    size_t len;
    unsigned char *end_ext_data, *end_ext_octet;

    if( *p == end )
        return( 0 );

    csr->ext_req.tag = **p;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &csr->ext_req.len,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    csr->ext_req.p = *p;

    if( end != *p + csr->ext_req.len )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    /*
     * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */
    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

    if( end != *p + len )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    while( *p < end )
    {
        /*
         * Extension  ::=  SEQUENCE  {
         *      extnID      OBJECT IDENTIFIER,
         *      critical    BOOLEAN DEFAULT FALSE,
         *      extnValue   OCTET STRING  }
         */
        mbedtls_x509_buf extn_oid = {0, 0, NULL};
        int is_critical = 0; /* DEFAULT FALSE */
        int ext_type = 0;

        if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        end_ext_data = *p + len;

        /* Get extension ID */
        extn_oid.tag = **p;

        if( ( ret = mbedtls_asn1_get_tag( p, end, &extn_oid.len, MBEDTLS_ASN1_OID ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        extn_oid.p = *p;
        *p += extn_oid.len;

        if( ( end - *p ) < 1 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                    MBEDTLS_ERR_ASN1_OUT_OF_DATA );

        /* Get optional critical */
        if( ( ret = mbedtls_asn1_get_bool( p, end_ext_data, &is_critical ) ) != 0 &&
            ( ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG ) )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        /* Data should be octet string type */
        if( ( ret = mbedtls_asn1_get_tag( p, end_ext_data, &len,
                MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS + ret );

        end_ext_octet = *p + len;

        if( end_ext_octet != end_ext_data )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

        /*
         * Detect supported extensions
         */
        ret = mbedtls_oid_get_x509_ext_type( &extn_oid, &ext_type );

        if( ret != 0 )
        {
            /* No parser found, skip extension */
            *p = end_ext_octet;

#if !defined(MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION)
            if( is_critical )
            {
                /* Data is marked as critical: fail */
                return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                        MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );
            }
#endif
            continue;
        }

        /* Forbid repeated extensions */
        if( ( csr->ext_types & ext_type ) != 0 )
            return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS );

        csr->ext_types |= ext_type;

        if( ext_type == MBEDTLS_X509_EXT_SUBJECT_ALT_NAME )
        {
            if( ( ret = mbedtls_x509_get_subject_alt_name( p, end_ext_octet,
                    &csr->subject_alt_names ) ) != 0 )
                return( ret );
        }
        else {
            /* Skip other ext types (x509_csr only supports a subset of x509_crt's extensions) */
            *p = end_ext_octet;
        }
    }

    if( *p != end )
        return( MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * Challenge Password
 *
 */
static int x509_get_csr_challenge( unsigned char **p,
                                 const unsigned char *end,
                                 mbedtls_x509_csr *csr )
{
    int ret;
    size_t len;

    if( *p >= end )
        return( 0 );

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET ) ) != 0 )
    {
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( end != *p + len )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    if( **p != MBEDTLS_ASN1_BMP_STRING && **p != MBEDTLS_ASN1_UTF8_STRING      &&
        **p != MBEDTLS_ASN1_T61_STRING && **p != MBEDTLS_ASN1_PRINTABLE_STRING &&
        **p != MBEDTLS_ASN1_IA5_STRING && **p != MBEDTLS_ASN1_UNIVERSAL_STRING &&
        **p != MBEDTLS_ASN1_BIT_STRING )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_UNEXPECTED_TAG );

    csr->challenge.tag = *(*p)++;

    if( ( ret = mbedtls_asn1_get_len( p, end, &csr->challenge.len ) ) != 0 )
        return( MBEDTLS_ERR_X509_INVALID_NAME + ret );

    if( end != *p + csr->challenge.len )
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    csr->challenge.p = *p;

    *p += csr->challenge.len;

    return( 0 );
}

/*
 * Parse a CSR in DER format
 */
int mbedtls_x509_csr_parse_der( mbedtls_x509_csr *csr,
                        const unsigned char *buf, size_t buflen )
{
    int ret;
    size_t len;
    unsigned char *p, *end;
    mbedtls_x509_buf sig_params;

    memset( &sig_params, 0, sizeof( mbedtls_x509_buf ) );

    /*
     * Check for valid input
     */
    if( csr == NULL || buf == NULL || buflen == 0 )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    mbedtls_x509_csr_init( csr );

    /*
     * first copy the raw DER data
     */
    p = mbedtls_calloc( 1, len = buflen );

    if( p == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );

    memcpy( p, buf, buflen );

    csr->raw.p = p;
    csr->raw.len = len;
    end = p + len;

    /*
     *  CertificationRequest ::= SEQUENCE {
     *       certificationRequestInfo CertificationRequestInfo,
     *       signatureAlgorithm AlgorithmIdentifier,
     *       signature          BIT STRING
     *  }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );
    }

    if( len != (size_t) ( end - p ) )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    /*
     *  CertificationRequestInfo ::= SEQUENCE {
     */
    csr->cri.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = p + len;
    csr->cri.len = end - csr->cri.p;

    /*
     *  Version  ::=  INTEGER {  v1(0) }
     */
    if( ( ret = x509_csr_get_version( &p, end, &csr->version ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    if( csr->version != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_UNKNOWN_VERSION );
    }

    csr->version++;

    /*
     *  subject               Name
     */
    csr->subject_raw.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( ( ret = mbedtls_x509_get_name( &p, p + len, &csr->subject ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    csr->subject_raw.len = p - csr->subject_raw.p;

    /*
     *  subjectPKInfo SubjectPublicKeyInfo
     */
    if( ( ret = mbedtls_pk_parse_subpubkey( &p, end, &csr->pk ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    /*
     *  attributes    [0] Attributes
     *
     *  The list of possible attributes is open-ended, though RFC 2985
     *  (PKCS#9) defines a few in section 5.4. We currently only support
     *  extensions and ignore the rest. This is a safe thing to do as the worst
     *  thing that could happen is that we issue a certificate that does not
     *  match the requester's expectations - this cannot cause a violation of
     *  our signature policies.
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( len != (size_t) ( end - p ) )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    end = p + len;

    while( p < end )
    {
        unsigned char *end_attr_data;
        mbedtls_x509_buf attr_oid = {0, 0, NULL};

        if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        {
            mbedtls_x509_csr_free( csr );
            return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
        }

        end_attr_data = p + len;

        if( end_attr_data > end )
        {
            mbedtls_x509_csr_free( csr );
            return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        }

        attr_oid.tag = *p;

        if( ( ret = mbedtls_asn1_get_tag( &p, end_attr_data, &attr_oid.len, MBEDTLS_ASN1_OID ) ) != 0 )
        {
            mbedtls_x509_csr_free( csr );
            return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
        }

        attr_oid.p = p;
        p += attr_oid.len;

        if( p > end_attr_data )
        {
            mbedtls_x509_csr_free( csr );
            return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                    MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
        }

        if( MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS9_CSR_EXT_REQ, &attr_oid ) == 0 )
        {
            if( ( ret = x509_get_csr_ext_req( &p, end_attr_data, csr ) ) != 0 )
            {
                mbedtls_x509_csr_free( csr );
                return( ret );
            }
        }
        else if( MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS9_CHALLENGE_PASSWORD, &attr_oid ) == 0 )
        {
            if( ( ret = x509_get_csr_challenge( &p, end_attr_data, csr ) ) != 0 )
            {
                mbedtls_x509_csr_free( csr );
                return( ret );
            }
        }

        p = end_attr_data;
    }

    end = csr->raw.p + csr->raw.len;

    /*
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signature            BIT STRING
     */
    if( ( ret = mbedtls_x509_get_alg( &p, end, &csr->sig_oid, &sig_params ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    if( ( ret = mbedtls_x509_get_sig_alg( &csr->sig_oid, &sig_params,
                                  &csr->sig_md, &csr->sig_pk,
                                  &csr->sig_opts ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG );
    }

    if( ( ret = mbedtls_x509_get_sig( &p, end, &csr->sig ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    if( p != end )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    return( 0 );
}

/*
 * Parse a CSR, allowing for PEM or raw DER encoding
 */
int mbedtls_x509_csr_parse( mbedtls_x509_csr *csr, const unsigned char *buf, size_t buflen )
{
#if defined(MBEDTLS_PEM_PARSE_C)
    int ret;
    size_t use_len;
    mbedtls_pem_context pem;
#endif

    /*
     * Check for valid input
     */
    if( csr == NULL || buf == NULL || buflen == 0 )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

#if defined(MBEDTLS_PEM_PARSE_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( buf[buflen - 1] == '\0' )
    {
        mbedtls_pem_init( &pem );
        ret = mbedtls_pem_read_buffer( &pem,
                               "-----BEGIN CERTIFICATE REQUEST-----",
                               "-----END CERTIFICATE REQUEST-----",
                               buf, NULL, 0, &use_len );

        if( ret == 0 )
            /*
             * Was PEM encoded, parse the result
             */
            ret = mbedtls_x509_csr_parse_der( csr, pem.buf, pem.buflen );

        mbedtls_pem_free( &pem );
        if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
            return( ret );
    }
#endif /* MBEDTLS_PEM_PARSE_C */
    return( mbedtls_x509_csr_parse_der( csr, buf, buflen ) );
}

#if defined(MBEDTLS_FS_IO)
/*
 * Load a CSR into the structure
 */
int mbedtls_x509_csr_parse_file( mbedtls_x509_csr *csr, const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = mbedtls_x509_csr_parse( csr, buf, n );

    mbedtls_platform_zeroize( buf, n );
    mbedtls_free( buf );

    return( ret );
}
#endif /* MBEDTLS_FS_IO */

#define BEFORE_COLON    14
#define BC              "14"
/*
 * Return an informational string about the CSR.
 */
int mbedtls_x509_csr_info( char *buf, size_t size, const char *prefix,
                   const mbedtls_x509_csr *csr )
{
    int ret;
    size_t n;
    char *p;
    char key_size_str[BEFORE_COLON];

    p = buf;
    n = size;

    ret = mbedtls_snprintf( p, n, "%sCSR version   : %d",
                               prefix, csr->version );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%ssubject name  : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_x509_dn_gets( p, n, &csr->subject );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%ssigned using  : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_x509_sig_alg_gets( p, n, &csr->sig_oid, csr->sig_pk, csr->sig_md,
                             csr->sig_opts );
    MBEDTLS_X509_SAFE_SNPRINTF;

    if( ( ret = mbedtls_x509_key_size_helper( key_size_str, BEFORE_COLON,
                                      mbedtls_pk_get_name( &csr->pk ) ) ) != 0 )
    {
        return( ret );
    }

    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s: %d bits\n", prefix, key_size_str,
                          (int) mbedtls_pk_get_bitlen( &csr->pk ) );
    MBEDTLS_X509_SAFE_SNPRINTF;

    return( (int) ( size - n ) );
}

/*
 * Initialize a CSR
 */
void mbedtls_x509_csr_init( mbedtls_x509_csr *csr )
{
    memset( csr, 0, sizeof(mbedtls_x509_csr) );
}

/*
 * Unallocate all CSR data
 */
void mbedtls_x509_csr_free( mbedtls_x509_csr *csr )
{
    mbedtls_x509_name *name_cur;
    mbedtls_x509_name *name_prv;
    mbedtls_x509_sequence *seq_cur;
    mbedtls_x509_sequence *seq_prv;

    if( csr == NULL )
        return;

    mbedtls_pk_free( &csr->pk );

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    mbedtls_free( csr->sig_opts );
#endif

    name_cur = csr->subject.next;
    while( name_cur != NULL )
    {
        name_prv = name_cur;
        name_cur = name_cur->next;
        mbedtls_platform_zeroize( name_prv, sizeof( mbedtls_x509_name ) );
        mbedtls_free( name_prv );
    }

    seq_cur = csr->subject_alt_names.next;
    while( seq_cur != NULL )
    {
        seq_prv = seq_cur;
        seq_cur = seq_cur->next;
        mbedtls_platform_zeroize( seq_prv, sizeof( mbedtls_x509_sequence ) );
        mbedtls_free( seq_prv );
    }

    if( csr->raw.p != NULL )
    {
        mbedtls_platform_zeroize( csr->raw.p, csr->raw.len );
        mbedtls_free( csr->raw.p );
    }

    mbedtls_platform_zeroize( csr, sizeof( mbedtls_x509_csr ) );
}

#endif /* MBEDTLS_X509_CSR_PARSE_C */
