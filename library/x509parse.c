/*
 *  X.509 certificate and private key decoding
 *
 *  Copyright (C) 2006-2010, Paul Bakker <polarssl_maintainer at polarssl.org>
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
/*
 *  The ITU-T X.509 standard defines a certificat format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc2459.txt
 *  http://www.ietf.org/rfc/rfc3279.txt
 *
 *  ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-1v2.asc
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 */

#include "polarssl/config.h"

#if defined(POLARSSL_X509_PARSE_C)

#include "polarssl/x509.h"
#include "polarssl/base64.h"
#include "polarssl/des.h"
#include "polarssl/md2.h"
#include "polarssl/md4.h"
#include "polarssl/md5.h"
#include "polarssl/sha1.h"
#include "polarssl/sha2.h"
#include "polarssl/sha4.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/*
 * ASN.1 DER decoding routines
 */
static int asn1_get_len( unsigned char **p,
                         const unsigned char *end,
                         int *len )
{
    if( ( end - *p ) < 1 )
        return( POLARSSL_ERR_ASN1_OUT_OF_DATA );

    if( ( **p & 0x80 ) == 0 )
        *len = *(*p)++;
    else
    {
        switch( **p & 0x7F )
        {
        case 1:
            if( ( end - *p ) < 2 )
                return( POLARSSL_ERR_ASN1_OUT_OF_DATA );

            *len = (*p)[1];
            (*p) += 2;
            break;

        case 2:
            if( ( end - *p ) < 3 )
                return( POLARSSL_ERR_ASN1_OUT_OF_DATA );

            *len = ( (*p)[1] << 8 ) | (*p)[2];
            (*p) += 3;
            break;

        default:
            return( POLARSSL_ERR_ASN1_INVALID_LENGTH );
            break;
        }
    }

    if( *len > (int) ( end - *p ) )
        return( POLARSSL_ERR_ASN1_OUT_OF_DATA );

    return( 0 );
}

static int asn1_get_tag( unsigned char **p,
                         const unsigned char *end,
                         int *len, int tag )
{
    if( ( end - *p ) < 1 )
        return( POLARSSL_ERR_ASN1_OUT_OF_DATA );

    if( **p != tag )
        return( POLARSSL_ERR_ASN1_UNEXPECTED_TAG );

    (*p)++;

    return( asn1_get_len( p, end, len ) );
}

static int asn1_get_bool( unsigned char **p,
                          const unsigned char *end,
                          int *val )
{
    int ret, len;

    if( ( ret = asn1_get_tag( p, end, &len, ASN1_BOOLEAN ) ) != 0 )
        return( ret );

    if( len != 1 )
        return( POLARSSL_ERR_ASN1_INVALID_LENGTH );

    *val = ( **p != 0 ) ? 1 : 0;
    (*p)++;

    return( 0 );
}

static int asn1_get_int( unsigned char **p,
                         const unsigned char *end,
                         int *val )
{
    int ret, len;

    if( ( ret = asn1_get_tag( p, end, &len, ASN1_INTEGER ) ) != 0 )
        return( ret );

    if( len > (int) sizeof( int ) || ( **p & 0x80 ) != 0 )
        return( POLARSSL_ERR_ASN1_INVALID_LENGTH );

    *val = 0;

    while( len-- > 0 )
    {
        *val = ( *val << 8 ) | **p;
        (*p)++;
    }

    return( 0 );
}

static int asn1_get_mpi( unsigned char **p,
                         const unsigned char *end,
                         mpi *X )
{
    int ret, len;

    if( ( ret = asn1_get_tag( p, end, &len, ASN1_INTEGER ) ) != 0 )
        return( ret );

    ret = mpi_read_binary( X, *p, len );

    *p += len;

    return( ret );
}

/*
 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 */
static int x509_get_version( unsigned char **p,
                             const unsigned char *end,
                             int *ver )
{
    int ret, len;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED | 0 ) ) != 0 )
    {
        if( ret == POLARSSL_ERR_ASN1_UNEXPECTED_TAG )
            return( *ver = 0 );

        return( ret );
    }

    end = *p + len;

    if( ( ret = asn1_get_int( p, end, ver ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_VERSION | ret );

    if( *p != end )
        return( POLARSSL_ERR_X509_CERT_INVALID_VERSION |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 *  CertificateSerialNumber  ::=  INTEGER
 */
static int x509_get_serial( unsigned char **p,
                            const unsigned char *end,
                            x509_buf *serial )
{
    int ret;

    if( ( end - *p ) < 1 )
        return( POLARSSL_ERR_X509_CERT_INVALID_SERIAL |
                POLARSSL_ERR_ASN1_OUT_OF_DATA );

    if( **p != ( ASN1_CONTEXT_SPECIFIC | ASN1_PRIMITIVE | 2 ) &&
        **p !=   ASN1_INTEGER )
        return( POLARSSL_ERR_X509_CERT_INVALID_SERIAL |
                POLARSSL_ERR_ASN1_UNEXPECTED_TAG );

    serial->tag = *(*p)++;

    if( ( ret = asn1_get_len( p, end, &serial->len ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_SERIAL | ret );

    serial->p = *p;
    *p += serial->len;

    return( 0 );
}

/*
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
static int x509_get_alg( unsigned char **p,
                         const unsigned char *end,
                         x509_buf *alg )
{
    int ret, len;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_ALG | ret );

    end = *p + len;
    alg->tag = **p;

    if( ( ret = asn1_get_tag( p, end, &alg->len, ASN1_OID ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_ALG | ret );

    alg->p = *p;
    *p += alg->len;

    if( *p == end )
        return( 0 );

    /*
     * assume the algorithm parameters must be NULL
     */
    if( ( ret = asn1_get_tag( p, end, &len, ASN1_NULL ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_ALG | ret );

    if( *p != end )
        return( POLARSSL_ERR_X509_CERT_INVALID_ALG |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 *  RelativeDistinguishedName ::=
 *    SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 */
static int x509_get_name( unsigned char **p,
                          const unsigned char *end,
                          x509_name *cur )
{
    int ret, len;
    const unsigned char *end2;
    x509_buf *oid;
    x509_buf *val;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SET ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_NAME | ret );

    end2 = end;
    end  = *p + len;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_NAME | ret );

    if( *p + len != end )
        return( POLARSSL_ERR_X509_CERT_INVALID_NAME |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    oid = &cur->oid;
    oid->tag = **p;

    if( ( ret = asn1_get_tag( p, end, &oid->len, ASN1_OID ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_NAME | ret );

    oid->p = *p;
    *p += oid->len;

    if( ( end - *p ) < 1 )
        return( POLARSSL_ERR_X509_CERT_INVALID_NAME |
                POLARSSL_ERR_ASN1_OUT_OF_DATA );

    if( **p != ASN1_BMP_STRING && **p != ASN1_UTF8_STRING      &&
        **p != ASN1_T61_STRING && **p != ASN1_PRINTABLE_STRING &&
        **p != ASN1_IA5_STRING && **p != ASN1_UNIVERSAL_STRING )
        return( POLARSSL_ERR_X509_CERT_INVALID_NAME |
                POLARSSL_ERR_ASN1_UNEXPECTED_TAG );

    val = &cur->val;
    val->tag = *(*p)++;

    if( ( ret = asn1_get_len( p, end, &val->len ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_NAME | ret );

    val->p = *p;
    *p += val->len;

    cur->next = NULL;

    if( *p != end )
        return( POLARSSL_ERR_X509_CERT_INVALID_NAME |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    /*
     * recurse until end of SEQUENCE is reached
     */
    if( *p == end2 )
        return( 0 );

    cur->next = (x509_name *) malloc(
         sizeof( x509_name ) );

    if( cur->next == NULL )
        return( 1 );

    return( x509_get_name( p, end2, cur->next ) );
}

/*
 *  Time ::= CHOICE {
 *       utcTime        UTCTime,
 *       generalTime    GeneralizedTime }
 */
static int x509_get_time( unsigned char **p,
                          const unsigned char *end,
                          x509_time *time )
{
    int ret, len;
    char date[64];
    unsigned char tag;

    if( ( end - *p ) < 1 )
        return( POLARSSL_ERR_X509_CERT_INVALID_DATE | POLARSSL_ERR_ASN1_OUT_OF_DATA );

    tag = **p;

    if ( tag == ASN1_UTC_TIME )
    {
        (*p)++;
        ret = asn1_get_len( p, end, &len );
        
        if( ret != 0 )
            return( POLARSSL_ERR_X509_CERT_INVALID_DATE | ret );

        memset( date,  0, sizeof( date ) );
        memcpy( date, *p, ( len < (int) sizeof( date ) - 1 ) ?
                len : (int) sizeof( date ) - 1 );

        if( sscanf( date, "%2d%2d%2d%2d%2d%2d",
                    &time->year, &time->mon, &time->day,
                    &time->hour, &time->min, &time->sec ) < 5 )
            return( POLARSSL_ERR_X509_CERT_INVALID_DATE );

        time->year +=  100 * ( time->year < 90 );
        time->year += 1900;

        *p += len;

        return( 0 );
    }
    else if ( tag == ASN1_GENERALIZED_TIME )
    {
        (*p)++;
        ret = asn1_get_len( p, end, &len );
        
        if( ret != 0 )
            return( POLARSSL_ERR_X509_CERT_INVALID_DATE | ret );

        memset( date,  0, sizeof( date ) );
        memcpy( date, *p, ( len < (int) sizeof( date ) - 1 ) ?
                len : (int) sizeof( date ) - 1 );

        if( sscanf( date, "%4d%2d%2d%2d%2d%2d",
                    &time->year, &time->mon, &time->day,
                    &time->hour, &time->min, &time->sec ) < 5 )
            return( POLARSSL_ERR_X509_CERT_INVALID_DATE );

        *p += len;

        return( 0 );
    }
    else
        return( POLARSSL_ERR_X509_CERT_INVALID_DATE | POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
}


/*
 *  Validity ::= SEQUENCE {
 *       notBefore      Time,
 *       notAfter       Time }
 */
static int x509_get_dates( unsigned char **p,
                           const unsigned char *end,
                           x509_time *from,
                           x509_time *to )
{
    int ret, len;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_DATE | ret );

    end = *p + len;

    if( ( ret = x509_get_time( p, end, from ) ) != 0 )
        return( ret );

    if( ( ret = x509_get_time( p, end, to ) ) != 0 )
        return( ret );

    if( *p != end )
        return( POLARSSL_ERR_X509_CERT_INVALID_DATE |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING }
 */
static int x509_get_pubkey( unsigned char **p,
                            const unsigned char *end,
                            x509_buf *pk_alg_oid,
                            mpi *N, mpi *E )
{
    int ret, len;
    unsigned char *end2;

    if( ( ret = x509_get_alg( p, end, pk_alg_oid ) ) != 0 )
        return( ret );

    /*
     * only RSA public keys handled at this time
     */
    if( pk_alg_oid->len != 9 ||
        memcmp( pk_alg_oid->p, OID_PKCS1_RSA, 9 ) != 0 )
        return( POLARSSL_ERR_X509_CERT_UNKNOWN_PK_ALG );

    if( ( ret = asn1_get_tag( p, end, &len, ASN1_BIT_STRING ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY | ret );

    if( ( end - *p ) < 1 )
        return( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY |
                POLARSSL_ERR_ASN1_OUT_OF_DATA );

    end2 = *p + len;

    if( *(*p)++ != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY );

    /*
     *  RSAPublicKey ::= SEQUENCE {
     *      modulus           INTEGER,  -- n
     *      publicExponent    INTEGER   -- e
     *  }
     */
    if( ( ret = asn1_get_tag( p, end2, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY | ret );

    if( *p + len != end2 )
        return( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    if( ( ret = asn1_get_mpi( p, end2, N ) ) != 0 ||
        ( ret = asn1_get_mpi( p, end2, E ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY | ret );

    if( *p != end )
        return( POLARSSL_ERR_X509_CERT_INVALID_PUBKEY |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

static int x509_get_sig( unsigned char **p,
                         const unsigned char *end,
                         x509_buf *sig )
{
    int ret, len;

    sig->tag = **p;

    if( ( ret = asn1_get_tag( p, end, &len, ASN1_BIT_STRING ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_SIGNATURE | ret );

    if( --len < 1 || *(*p)++ != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_SIGNATURE );

    sig->len = len;
    sig->p = *p;

    *p += len;

    return( 0 );
}

/*
 * X.509 v2/v3 unique identifier (not parsed)
 */
static int x509_get_uid( unsigned char **p,
                         const unsigned char *end,
                         x509_buf *uid, int n )
{
    int ret;

    if( *p == end )
        return( 0 );

    uid->tag = **p;

    if( ( ret = asn1_get_tag( p, end, &uid->len,
            ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED | n ) ) != 0 )
    {
        if( ret == POLARSSL_ERR_ASN1_UNEXPECTED_TAG )
            return( 0 );

        return( ret );
    }

    uid->p = *p;
    *p += uid->len;

    return( 0 );
}

/*
 * X.509 Extensions (No parsing of extensions, pointer should
 * be either manually updated or extensions should be parsed!
 */
static int x509_get_ext( unsigned char **p,
                         const unsigned char *end,
                         x509_buf *ext )
{
    int ret, len;

    if( *p == end )
        return( 0 );

    ext->tag = **p;

    if( ( ret = asn1_get_tag( p, end, &ext->len,
            ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED | 3 ) ) != 0 )
        return( ret );

    ext->p = *p;
    end = *p + ext->len;

    /*
     * Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     *
     * Extension  ::=  SEQUENCE  {
     *      extnID      OBJECT IDENTIFIER,
     *      critical    BOOLEAN DEFAULT FALSE,
     *      extnValue   OCTET STRING  }
     */
    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS | ret );

    if( end != *p + len )
        return( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * X.509 CRL v2 extensions (no extensions parsed yet.)
 */
static int x509_get_crl_ext( unsigned char **p,
                             const unsigned char *end,
                             x509_buf *ext )
{
    int ret, len;

    if( ( ret = x509_get_ext( p, end, ext ) ) != 0 )
    {
        if( ret == POLARSSL_ERR_ASN1_UNEXPECTED_TAG )
            return( 0 );

        return( ret );
    }

    while( *p < end )
    {
        if( ( ret = asn1_get_tag( p, end, &len,
                ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
            return( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS | ret );

        *p += len;
    }

    if( *p != end )
        return( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * X.509 v3 extensions (only BasicConstraints are parsed)
 */
static int x509_get_crt_ext( unsigned char **p,
                             const unsigned char *end,
                             x509_buf *ext,
                             int *ca_istrue,
                             int *max_pathlen )
{
    int ret, len;
    int is_critical = 1;
    int is_cacert   = 0;
    unsigned char *end_ext_data, *end_ext_octet;

    if( ( ret = x509_get_ext( p, end, ext ) ) != 0 )
    {
        if( ret == POLARSSL_ERR_ASN1_UNEXPECTED_TAG )
            return( 0 );

        return( ret );
    }

    while( *p < end )
    {
        if( ( ret = asn1_get_tag( p, end, &len,
                ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
            return( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS | ret );

        end_ext_data = *p + len;

        if( memcmp( *p, "\x06\x03\x55\x1D\x13", 5 ) != 0 )
        {
            *p += len;
            continue;
        }

        *p += 5;

        if( ( ret = asn1_get_bool( p, end_ext_data, &is_critical ) ) != 0 &&
            ( ret != POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) )
            return( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS | ret );

        if( ( ret = asn1_get_tag( p, end_ext_data, &len,
                ASN1_OCTET_STRING ) ) != 0 )
            return( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS | ret );

        /*
         * BasicConstraints ::= SEQUENCE {
         *      cA                      BOOLEAN DEFAULT FALSE,
         *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
         */
        end_ext_octet = *p + len;

        if( end_ext_octet != end_ext_data )
            return( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS |
                    POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

        if( ( ret = asn1_get_tag( p, end_ext_octet, &len,
                ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
            return( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS | ret );

        if( *p == end_ext_octet )
            continue;

        if( ( ret = asn1_get_bool( p, end_ext_octet, &is_cacert ) ) != 0 )
        {
            if( ret == POLARSSL_ERR_ASN1_UNEXPECTED_TAG )
                ret = asn1_get_int( p, end_ext_octet, &is_cacert );

            if( ret != 0 )
                return( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS | ret );

            if( is_cacert != 0 )
                is_cacert  = 1;
        }

        if( *p == end_ext_octet )
            continue;

        if( ( ret = asn1_get_int( p, end_ext_octet, max_pathlen ) ) != 0 )
            return( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS | ret );

        if( *p != end_ext_octet )
            return( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS |
                    POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

        max_pathlen++;
    }

    if( *p != end )
        return( POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    *ca_istrue = is_critical & is_cacert;

    return( 0 );
}

/*
 * X.509 CRL Entries
 */
static int x509_get_entries( unsigned char **p,
                             const unsigned char *end,
                             x509_crl_entry *entry )
{
    int ret, entry_len;
    x509_crl_entry *cur_entry = entry;

    if( *p == end )
        return( 0 );

    if( ( ret = asn1_get_tag( p, end, &entry_len,
            ASN1_SEQUENCE | ASN1_CONSTRUCTED ) ) != 0 )
    {
        if( ret == POLARSSL_ERR_ASN1_UNEXPECTED_TAG )
            return( 0 );

        return( ret );
    }

    end = *p + entry_len;

    while( *p < end )
    {
        int len2;

        if( ( ret = asn1_get_tag( p, end, &len2,
                ASN1_SEQUENCE | ASN1_CONSTRUCTED ) ) != 0 )
        {
            return( ret );
        }

        cur_entry->raw.tag = **p;
        cur_entry->raw.p = *p;
        cur_entry->raw.len = len2;

        if( ( ret = x509_get_serial( p, end, &cur_entry->serial ) ) != 0 )
            return( ret );

        if( ( ret = x509_get_time( p, end, &cur_entry->revocation_date ) ) != 0 )
            return( ret );

        if( ( ret = x509_get_crl_ext( p, end, &cur_entry->entry_ext ) ) != 0 )
            return( ret );

        if ( *p < end ) {
            cur_entry->next = malloc( sizeof( x509_crl_entry ) );
            cur_entry = cur_entry->next;
            memset( cur_entry, 0, sizeof( x509_crl_entry ) );
        }
    }

    return( 0 );
}

static int x509_get_sig_alg( const x509_buf *sig_oid, int *sig_alg )
{
    if( sig_oid->len == 9 &&
        memcmp( sig_oid->p, OID_PKCS1, 8 ) == 0 )
    {
        if( sig_oid->p[8] >= 2 && sig_oid->p[8] <= 5 )
        {
            *sig_alg = sig_oid->p[8];
            return( 0 );
        }

        if ( sig_oid->p[8] >= 11 && sig_oid->p[8] <= 14 )
        {
            *sig_alg = sig_oid->p[8];
            return( 0 );
        }

        return( POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG );
    }

    return( POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG );
}

/*
 * Parse one or more certificates and add them to the chained list
 */
int x509parse_crt( x509_cert *chain, const unsigned char *buf, int buflen )
{
    int ret, len;
    const unsigned char *s1, *s2;
    unsigned char *p, *end;
    x509_cert *crt;

    crt = chain;

    /*
     * Check for valid input
     */
    if( crt == NULL || buf == NULL )
        return( 1 );

    while( crt->version != 0 && crt->next != NULL )
        crt = crt->next;

    /*
     * Add new certificate on the end of the chain if needed.
     */
    if ( crt->version != 0 && crt->next == NULL)
    {
        crt->next = (x509_cert *) malloc( sizeof( x509_cert ) );

        if( crt->next == NULL )
        {
            x509_free( crt );
            return( 1 );
        }

        crt = crt->next;
        memset( crt, 0, sizeof( x509_cert ) );
    }

    /*
     * check if the certificate is encoded in base64
     */
    s1 = (unsigned char *) strstr( (char *) buf,
        "-----BEGIN CERTIFICATE-----" );

    if( s1 != NULL )
    {
        s2 = (unsigned char *) strstr( (char *) buf,
            "-----END CERTIFICATE-----" );

        if( s2 == NULL || s2 <= s1 )
            return( POLARSSL_ERR_X509_CERT_INVALID_PEM );

        s1 += 27;
        if( *s1 == '\r' ) s1++;
        if( *s1 == '\n' ) s1++;
            else return( POLARSSL_ERR_X509_CERT_INVALID_PEM );

        /*
         * get the DER data length and decode the buffer
         */
        len = 0;
        ret = base64_decode( NULL, &len, s1, s2 - s1 );

        if( ret == POLARSSL_ERR_BASE64_INVALID_CHARACTER )
            return( POLARSSL_ERR_X509_CERT_INVALID_PEM | ret );

        if( ( p = (unsigned char *) malloc( len ) ) == NULL )
            return( 1 );
            
        if( ( ret = base64_decode( p, &len, s1, s2 - s1 ) ) != 0 )
        {
            free( p );
            return( POLARSSL_ERR_X509_CERT_INVALID_PEM | ret );
        }

        /*
         * update the buffer size and offset
         */
        s2 += 25;
        if( *s2 == '\r' ) s2++;
        if( *s2 == '\n' ) s2++;
        else
        {
            free( p );
            return( POLARSSL_ERR_X509_CERT_INVALID_PEM );
        }

        buflen -= s2 - buf;
        buf = s2;
    }
    else
    {
        /*
         * nope, copy the raw DER data
         */
        p = (unsigned char *) malloc( len = buflen );

        if( p == NULL )
            return( 1 );

        memcpy( p, buf, buflen );

        buflen = 0;
    }

    crt->raw.p = p;
    crt->raw.len = len;
    end = p + len;

    /*
     * Certificate  ::=  SEQUENCE  {
     *      tbsCertificate       TBSCertificate,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING  }
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_free( crt );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT );
    }

    if( len != (int) ( end - p ) )
    {
        x509_free( crt );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    /*
     * TBSCertificate  ::=  SEQUENCE  {
     */
    crt->tbs.p = p;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_free( crt );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT | ret );
    }

    end = p + len;
    crt->tbs.len = end - crt->tbs.p;

    /*
     * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     *
     * CertificateSerialNumber  ::=  INTEGER
     *
     * signature            AlgorithmIdentifier
     */
    if( ( ret = x509_get_version( &p, end, &crt->version ) ) != 0 ||
        ( ret = x509_get_serial(  &p, end, &crt->serial  ) ) != 0 ||
        ( ret = x509_get_alg(  &p, end, &crt->sig_oid1   ) ) != 0 )
    {
        x509_free( crt );
        return( ret );
    }

    crt->version++;

    if( crt->version > 3 )
    {
        x509_free( crt );
        return( POLARSSL_ERR_X509_CERT_UNKNOWN_VERSION );
    }

    if( ( ret = x509_get_sig_alg( &crt->sig_oid1, &crt->sig_alg ) ) != 0 )
    {
        x509_free( crt );
        return( ret );
    }

    /*
     * issuer               Name
     */
    crt->issuer_raw.p = p;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_free( crt );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT | ret );
    }

    if( ( ret = x509_get_name( &p, p + len, &crt->issuer ) ) != 0 )
    {
        x509_free( crt );
        return( ret );
    }

    crt->issuer_raw.len = p - crt->issuer_raw.p;

    /*
     * Validity ::= SEQUENCE {
     *      notBefore      Time,
     *      notAfter       Time }
     *
     */
    if( ( ret = x509_get_dates( &p, end, &crt->valid_from,
                                         &crt->valid_to ) ) != 0 )
    {
        x509_free( crt );
        return( ret );
    }

    /*
     * subject              Name
     */
    crt->subject_raw.p = p;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_free( crt );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT | ret );
    }

    if( ( ret = x509_get_name( &p, p + len, &crt->subject ) ) != 0 )
    {
        x509_free( crt );
        return( ret );
    }

    crt->subject_raw.len = p - crt->subject_raw.p;

    /*
     * SubjectPublicKeyInfo  ::=  SEQUENCE
     *      algorithm            AlgorithmIdentifier,
     *      subjectPublicKey     BIT STRING  }
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_free( crt );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT | ret );
    }

    if( ( ret = x509_get_pubkey( &p, p + len, &crt->pk_oid,
                                 &crt->rsa.N, &crt->rsa.E ) ) != 0 )
    {
        x509_free( crt );
        return( ret );
    }

    if( ( ret = rsa_check_pubkey( &crt->rsa ) ) != 0 )
    {
        x509_free( crt );
        return( ret );
    }

    crt->rsa.len = mpi_size( &crt->rsa.N );

    /*
     *  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                       -- If present, version shall be v3
     */
    if( crt->version == 2 || crt->version == 3 )
    {
        ret = x509_get_uid( &p, end, &crt->issuer_id,  1 );
        if( ret != 0 )
        {
            x509_free( crt );
            return( ret );
        }
    }

    if( crt->version == 2 || crt->version == 3 )
    {
        ret = x509_get_uid( &p, end, &crt->subject_id,  2 );
        if( ret != 0 )
        {
            x509_free( crt );
            return( ret );
        }
    }

    if( crt->version == 3 )
    {
        ret = x509_get_crt_ext( &p, end, &crt->v3_ext,
                            &crt->ca_istrue, &crt->max_pathlen );
        if( ret != 0 )
        {
            x509_free( crt );
            return( ret );
        }
    }

    if( p != end )
    {
        x509_free( crt );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    end = crt->raw.p + crt->raw.len;

    /*
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signatureValue       BIT STRING
     */
    if( ( ret = x509_get_alg( &p, end, &crt->sig_oid2 ) ) != 0 )
    {
        x509_free( crt );
        return( ret );
    }

    if( memcmp( crt->sig_oid1.p, crt->sig_oid2.p, crt->sig_oid1.len ) != 0 )
    {
        x509_free( crt );
        return( POLARSSL_ERR_X509_CERT_SIG_MISMATCH );
    }

    if( ( ret = x509_get_sig( &p, end, &crt->sig ) ) != 0 )
    {
        x509_free( crt );
        return( ret );
    }

    if( p != end )
    {
        x509_free( crt );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    if( buflen > 0 )
    {
        crt->next = (x509_cert *) malloc( sizeof( x509_cert ) );

        if( crt->next == NULL )
        {
            x509_free( crt );
            return( 1 );
        }

        crt = crt->next;
        memset( crt, 0, sizeof( x509_cert ) );

        return( x509parse_crt( crt, buf, buflen ) );
    }

    return( 0 );
}

/*
 * Parse one or more CRLs and add them to the chained list
 */
int x509parse_crl( x509_crl *chain, const unsigned char *buf, int buflen )
{
    int ret, len;
    unsigned char *s1, *s2;
    unsigned char *p, *end;
    x509_crl *crl;

    crl = chain;

    /*
     * Check for valid input
     */
    if( crl == NULL || buf == NULL )
        return( 1 );

    while( crl->version != 0 && crl->next != NULL )
        crl = crl->next;

    /*
     * Add new CRL on the end of the chain if needed.
     */
    if ( crl->version != 0 && crl->next == NULL)
    {
        crl->next = (x509_crl *) malloc( sizeof( x509_crl ) );

        if( crl->next == NULL )
        {
            x509_crl_free( crl );
            return( 1 );
        }

        crl = crl->next;
        memset( crl, 0, sizeof( x509_crl ) );
    }

    /*
     * check if the CRL is encoded in base64
     */
    s1 = (unsigned char *) strstr( (char *) buf,
        "-----BEGIN X509 CRL-----" );

    if( s1 != NULL )
    {
        s2 = (unsigned char *) strstr( (char *) buf,
            "-----END X509 CRL-----" );

        if( s2 == NULL || s2 <= s1 )
            return( POLARSSL_ERR_X509_CERT_INVALID_PEM );

        s1 += 24;
        if( *s1 == '\r' ) s1++;
        if( *s1 == '\n' ) s1++;
            else return( POLARSSL_ERR_X509_CERT_INVALID_PEM );

        /*
         * get the DER data length and decode the buffer
         */
        len = 0;
        ret = base64_decode( NULL, &len, s1, s2 - s1 );

        if( ret == POLARSSL_ERR_BASE64_INVALID_CHARACTER )
            return( POLARSSL_ERR_X509_CERT_INVALID_PEM | ret );

        if( ( p = (unsigned char *) malloc( len ) ) == NULL )
            return( 1 );
            
        if( ( ret = base64_decode( p, &len, s1, s2 - s1 ) ) != 0 )
        {
            free( p );
            return( POLARSSL_ERR_X509_CERT_INVALID_PEM | ret );
        }

        /*
         * update the buffer size and offset
         */
        s2 += 22;
        if( *s2 == '\r' ) s2++;
        if( *s2 == '\n' ) s2++;
        else
        {
            free( p );
            return( POLARSSL_ERR_X509_CERT_INVALID_PEM );
        }

        buflen -= s2 - buf;
        buf = s2;
    }
    else
    {
        /*
         * nope, copy the raw DER data
         */
        p = (unsigned char *) malloc( len = buflen );

        if( p == NULL )
            return( 1 );

        memcpy( p, buf, buflen );

        buflen = 0;
    }

    crl->raw.p = p;
    crl->raw.len = len;
    end = p + len;

    /*
     * CertificateList  ::=  SEQUENCE  {
     *      tbsCertList          TBSCertList,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING  }
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_crl_free( crl );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT );
    }

    if( len != (int) ( end - p ) )
    {
        x509_crl_free( crl );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    /*
     * TBSCertList  ::=  SEQUENCE  {
     */
    crl->tbs.p = p;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_crl_free( crl );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT | ret );
    }

    end = p + len;
    crl->tbs.len = end - crl->tbs.p;

    /*
     * Version  ::=  INTEGER  OPTIONAL {  v1(0), v2(1)  }
     *               -- if present, MUST be v2
     *
     * signature            AlgorithmIdentifier
     */
    if( ( ret = x509_get_version( &p, end, &crl->version ) ) != 0 ||
        ( ret = x509_get_alg(  &p, end, &crl->sig_oid1   ) ) != 0 )
    {
        x509_crl_free( crl );
        return( ret );
    }

    crl->version++;

    if( crl->version > 2 )
    {
        x509_crl_free( crl );
        return( POLARSSL_ERR_X509_CERT_UNKNOWN_VERSION );
    }

    if( ( ret = x509_get_sig_alg( &crl->sig_oid1, &crl->sig_alg ) ) != 0 )
    {
        x509_crl_free( crl );
        return( POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG );
    }

    /*
     * issuer               Name
     */
    crl->issuer_raw.p = p;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_crl_free( crl );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT | ret );
    }

    if( ( ret = x509_get_name( &p, p + len, &crl->issuer ) ) != 0 )
    {
        x509_crl_free( crl );
        return( ret );
    }

    crl->issuer_raw.len = p - crl->issuer_raw.p;

    /*
     * thisUpdate          Time
     * nextUpdate          Time OPTIONAL
     */
    if( ( ret = x509_get_time( &p, end, &crl->this_update ) ) != 0 )
    {
        x509_crl_free( crl );
        return( ret );
    }

    if( ( ret = x509_get_time( &p, end, &crl->next_update ) ) != 0 )
    {
        if ( ret != ( POLARSSL_ERR_X509_CERT_INVALID_DATE |
                        POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) &&
             ret != ( POLARSSL_ERR_X509_CERT_INVALID_DATE |
                        POLARSSL_ERR_ASN1_OUT_OF_DATA ) )
        {
            x509_crl_free( crl );
            return( ret );
        }
    }

    /*
     * revokedCertificates    SEQUENCE OF SEQUENCE   {
     *      userCertificate        CertificateSerialNumber,
     *      revocationDate         Time,
     *      crlEntryExtensions     Extensions OPTIONAL
     *                                   -- if present, MUST be v2
     *                        } OPTIONAL
     */
    if( ( ret = x509_get_entries( &p, end, &crl->entry ) ) != 0 )
    {
        x509_crl_free( crl );
        return( ret );
    }

    /*
     * crlExtensions          EXPLICIT Extensions OPTIONAL
     *                              -- if present, MUST be v2
     */
    if( crl->version == 2 )
    {
        ret = x509_get_crl_ext( &p, end, &crl->crl_ext );
                            
        if( ret != 0 )
        {
            x509_crl_free( crl );
            return( ret );
        }
    }

    if( p != end )
    {
        x509_crl_free( crl );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    end = crl->raw.p + crl->raw.len;

    /*
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signatureValue       BIT STRING
     */
    if( ( ret = x509_get_alg( &p, end, &crl->sig_oid2 ) ) != 0 )
    {
        x509_crl_free( crl );
        return( ret );
    }

    if( memcmp( crl->sig_oid1.p, crl->sig_oid2.p, crl->sig_oid1.len ) != 0 )
    {
        x509_crl_free( crl );
        return( POLARSSL_ERR_X509_CERT_SIG_MISMATCH );
    }

    if( ( ret = x509_get_sig( &p, end, &crl->sig ) ) != 0 )
    {
        x509_crl_free( crl );
        return( ret );
    }

    if( p != end )
    {
        x509_crl_free( crl );
        return( POLARSSL_ERR_X509_CERT_INVALID_FORMAT |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    if( buflen > 0 )
    {
        crl->next = (x509_crl *) malloc( sizeof( x509_crl ) );

        if( crl->next == NULL )
        {
            x509_crl_free( crl );
            return( 1 );
        }

        crl = crl->next;
        memset( crl, 0, sizeof( x509_crl ) );

        return( x509parse_crl( crl, buf, buflen ) );
    }

    return( 0 );
}

/*
 * Load all data from a file into a given buffer.
 */
int load_file( const char *path, unsigned char **buf, size_t *n )
{
    FILE *f;

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( 1 );

    fseek( f, 0, SEEK_END );
    *n = (size_t) ftell( f );
    fseek( f, 0, SEEK_SET );

    if( ( *buf = (unsigned char *) malloc( *n + 1 ) ) == NULL )
        return( 1 );

    if( fread( *buf, 1, *n, f ) != *n )
    {
        fclose( f );
        free( *buf );
        return( 1 );
    }

    fclose( f );

    (*buf)[*n] = '\0';

    return( 0 );
}

/*
 * Load one or more certificates and add them to the chained list
 */
int x509parse_crtfile( x509_cert *chain, const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if ( load_file( path, &buf, &n ) )
        return( 1 );

    ret = x509parse_crt( chain, buf, (int) n );

    memset( buf, 0, n + 1 );
    free( buf );

    return( ret );
}

/*
 * Load one or more CRLs and add them to the chained list
 */
int x509parse_crlfile( x509_crl *chain, const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if ( load_file( path, &buf, &n ) )
        return( 1 );

    ret = x509parse_crl( chain, buf, (int) n );

    memset( buf, 0, n + 1 );
    free( buf );

    return( ret );
}

#if defined(POLARSSL_DES_C) && defined(POLARSSL_MD5_C)
/*
 * Read a 16-byte hex string and convert it to binary
 */
static int x509_get_iv( const unsigned char *s, unsigned char iv[8] )
{
    int i, j, k;

    memset( iv, 0, 8 );

    for( i = 0; i < 16; i++, s++ )
    {
        if( *s >= '0' && *s <= '9' ) j = *s - '0'; else
        if( *s >= 'A' && *s <= 'F' ) j = *s - '7'; else
        if( *s >= 'a' && *s <= 'f' ) j = *s - 'W'; else
            return( POLARSSL_ERR_X509_KEY_INVALID_ENC_IV );

        k = ( ( i & 1 ) != 0 ) ? j : j << 4;

        iv[i >> 1] = (unsigned char)( iv[i >> 1] | k );
    }

    return( 0 );
}

/*
 * Decrypt with 3DES-CBC, using PBKDF1 for key derivation
 */
static void x509_des3_decrypt( unsigned char des3_iv[8],
                               unsigned char *buf, int buflen,
                               const unsigned char *pwd, int pwdlen )
{
    md5_context md5_ctx;
    des3_context des3_ctx;
    unsigned char md5sum[16];
    unsigned char des3_key[24];

    /*
     * 3DES key[ 0..15] = MD5(pwd || IV)
     *      key[16..23] = MD5(pwd || IV || 3DES key[ 0..15])
     */
    md5_starts( &md5_ctx );
    md5_update( &md5_ctx, pwd, pwdlen );
    md5_update( &md5_ctx, des3_iv,  8 );
    md5_finish( &md5_ctx, md5sum );
    memcpy( des3_key, md5sum, 16 );

    md5_starts( &md5_ctx );
    md5_update( &md5_ctx, md5sum,  16 );
    md5_update( &md5_ctx, pwd, pwdlen );
    md5_update( &md5_ctx, des3_iv,  8 );
    md5_finish( &md5_ctx, md5sum );
    memcpy( des3_key + 16, md5sum, 8 );

    des3_set3key_dec( &des3_ctx, des3_key );
    des3_crypt_cbc( &des3_ctx, DES_DECRYPT, buflen,
                     des3_iv, buf, buf );

    memset(  &md5_ctx, 0, sizeof(  md5_ctx ) );
    memset( &des3_ctx, 0, sizeof( des3_ctx ) );
    memset( md5sum, 0, 16 );
    memset( des3_key, 0, 24 );
}
#endif

/*
 * Parse a private RSA key
 */
int x509parse_key( rsa_context *rsa, const unsigned char *key, int keylen,
                                     const unsigned char *pwd, int pwdlen )
{
    int ret, len, enc;
    unsigned char *buf, *s1, *s2;
    unsigned char *p, *end;
#if defined(POLARSSL_DES_C) && defined(POLARSSL_MD5_C)
    unsigned char des3_iv[8];
#else
    ((void) pwd);
    ((void) pwdlen);
#endif

    s1 = (unsigned char *) strstr( (char *) key,
        "-----BEGIN RSA PRIVATE KEY-----" );

    if( s1 != NULL )
    {
        s2 = (unsigned char *) strstr( (char *) key,
            "-----END RSA PRIVATE KEY-----" );

        if( s2 == NULL || s2 <= s1 )
            return( POLARSSL_ERR_X509_KEY_INVALID_PEM );

        s1 += 31;
        if( *s1 == '\r' ) s1++;
        if( *s1 == '\n' ) s1++;
            else return( POLARSSL_ERR_X509_KEY_INVALID_PEM );

        enc = 0;

        if( memcmp( s1, "Proc-Type: 4,ENCRYPTED", 22 ) == 0 )
        {
#if defined(POLARSSL_DES_C) && defined(POLARSSL_MD5_C)
            enc++;

            s1 += 22;
            if( *s1 == '\r' ) s1++;
            if( *s1 == '\n' ) s1++;
                else return( POLARSSL_ERR_X509_KEY_INVALID_PEM );

            if( memcmp( s1, "DEK-Info: DES-EDE3-CBC,", 23 ) != 0 )
                return( POLARSSL_ERR_X509_KEY_UNKNOWN_ENC_ALG );

            s1 += 23;
            if( x509_get_iv( s1, des3_iv ) != 0 )
                return( POLARSSL_ERR_X509_KEY_INVALID_ENC_IV );

            s1 += 16;
            if( *s1 == '\r' ) s1++;
            if( *s1 == '\n' ) s1++;
                else return( POLARSSL_ERR_X509_KEY_INVALID_PEM );
#else
            return( POLARSSL_ERR_X509_FEATURE_UNAVAILABLE );
#endif
        }

        len = 0;
        ret = base64_decode( NULL, &len, s1, s2 - s1 );

        if( ret == POLARSSL_ERR_BASE64_INVALID_CHARACTER )
            return( ret | POLARSSL_ERR_X509_KEY_INVALID_PEM );

        if( ( buf = (unsigned char *) malloc( len ) ) == NULL )
            return( 1 );

        if( ( ret = base64_decode( buf, &len, s1, s2 - s1 ) ) != 0 )
        {
            free( buf );
            return( ret | POLARSSL_ERR_X509_KEY_INVALID_PEM );
        }

        keylen = len;

        if( enc != 0 )
        {
#if defined(POLARSSL_DES_C) && defined(POLARSSL_MD5_C)
            if( pwd == NULL )
            {
                free( buf );
                return( POLARSSL_ERR_X509_KEY_PASSWORD_REQUIRED );
            }

            x509_des3_decrypt( des3_iv, buf, keylen, pwd, pwdlen );

            if( buf[0] != 0x30 || buf[1] != 0x82 ||
                buf[4] != 0x02 || buf[5] != 0x01 )
            {
                free( buf );
                return( POLARSSL_ERR_X509_KEY_PASSWORD_MISMATCH );
            }
#else
            return( POLARSSL_ERR_X509_FEATURE_UNAVAILABLE );
#endif
        }
    }
    else
    {
        buf = NULL;
    }

    memset( rsa, 0, sizeof( rsa_context ) );

    p = ( s1 != NULL ) ? buf : (unsigned char *) key;
    end = p + keylen;

    /*
     *  RSAPrivateKey ::= SEQUENCE {
     *      version           Version,
     *      modulus           INTEGER,  -- n
     *      publicExponent    INTEGER,  -- e
     *      privateExponent   INTEGER,  -- d
     *      prime1            INTEGER,  -- p
     *      prime2            INTEGER,  -- q
     *      exponent1         INTEGER,  -- d mod (p-1)
     *      exponent2         INTEGER,  -- d mod (q-1)
     *      coefficient       INTEGER,  -- (inverse of q) mod p
     *      otherPrimeInfos   OtherPrimeInfos OPTIONAL
     *  }
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( POLARSSL_ERR_X509_KEY_INVALID_FORMAT | ret );
    }

    end = p + len;

    if( ( ret = asn1_get_int( &p, end, &rsa->ver ) ) != 0 )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( POLARSSL_ERR_X509_KEY_INVALID_FORMAT | ret );
    }

    if( rsa->ver != 0 )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( ret | POLARSSL_ERR_X509_KEY_INVALID_VERSION );
    }

    if( ( ret = asn1_get_mpi( &p, end, &rsa->N  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->E  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->D  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->P  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->Q  ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->DP ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->DQ ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &rsa->QP ) ) != 0 )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( ret | POLARSSL_ERR_X509_KEY_INVALID_FORMAT );
    }

    rsa->len = mpi_size( &rsa->N );

    if( p != end )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( POLARSSL_ERR_X509_KEY_INVALID_FORMAT |
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    if( ( ret = rsa_check_privkey( rsa ) ) != 0 )
    {
        if( s1 != NULL )
            free( buf );

        rsa_free( rsa );
        return( ret );
    }

    if( s1 != NULL )
        free( buf );

    return( 0 );
}

/*
 * Load and parse a private RSA key
 */
int x509parse_keyfile( rsa_context *rsa, const char *path, const char *pwd )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if ( load_file( path, &buf, &n ) )
        return( 1 );

    if( pwd == NULL )
        ret = x509parse_key( rsa, buf, (int) n, NULL, 0 );
    else
        ret = x509parse_key( rsa, buf, (int) n,
                (unsigned char *) pwd, strlen( pwd ) );

    memset( buf, 0, n + 1 );
    free( buf );

    return( ret );
}

#if defined _MSC_VER && !defined snprintf
#include <stdarg.h>

#if !defined vsnprintf
#define vsnprintf _vsnprintf
#endif // vsnprintf

/*
 * Windows _snprintf and _vsnprintf are not compatible to linux versions.
 * Result value is not size of buffer needed, but -1 if no fit is possible.
 *
 * This fuction tries to 'fix' this by at least suggesting enlarging the
 * size by 20.
 */
int compat_snprintf(char *str, size_t size, const char *format, ...)
{
    va_list ap;
    int res = -1;

    va_start( ap, format );

    res = vsnprintf( str, size, format, ap );

    va_end( ap );

    // No quick fix possible
    if ( res < 0 )
        return( size + 20 );
    
    return res;
}

#define snprintf compat_snprintf
#endif

#define POLARSSL_ERR_DEBUG_BUF_TOO_SMALL    -2

#define SAFE_SNPRINTF()                         \
{                                               \
    if( ret == -1 )                             \
        return( -1 );                           \
                                                \
    if ( ret > n ) {                            \
        p[n - 1] = '\0';                        \
        return POLARSSL_ERR_DEBUG_BUF_TOO_SMALL;\
    }                                           \
                                                \
    n -= ret;                                   \
    p += ret;                                   \
}

/*
 * Store the name in printable form into buf; no more
 * than size characters will be written
 */
int x509parse_dn_gets( char *buf, size_t size, const x509_name *dn )
{
    int i, ret, n;
    unsigned char c;
    const x509_name *name;
    char s[128], *p;

    memset( s, 0, sizeof( s ) );

    name = dn;
    p = buf;
    n = size;

    while( name != NULL )
    {
        if( name != dn ) {
            ret = snprintf( p, n, ", " );
            SAFE_SNPRINTF();
        }

        if( memcmp( name->oid.p, OID_X520, 2 ) == 0 )
        {
            switch( name->oid.p[2] )
            {
            case X520_COMMON_NAME:
                ret = snprintf( p, n, "CN=" ); break;

            case X520_COUNTRY:
                ret = snprintf( p, n, "C="  ); break;

            case X520_LOCALITY:
                ret = snprintf( p, n, "L="  ); break;

            case X520_STATE:
                ret = snprintf( p, n, "ST=" ); break;

            case X520_ORGANIZATION:
                ret = snprintf( p, n, "O="  ); break;

            case X520_ORG_UNIT:
                ret = snprintf( p, n, "OU=" ); break;

            default:
                ret = snprintf( p, n, "0x%02X=",
                               name->oid.p[2] );
                break;
            }
        SAFE_SNPRINTF();
        }
        else if( memcmp( name->oid.p, OID_PKCS9, 8 ) == 0 )
        {
            switch( name->oid.p[8] )
            {
            case PKCS9_EMAIL:
                ret = snprintf( p, n, "emailAddress=" ); break;

            default:
                ret = snprintf( p, n, "0x%02X=",
                               name->oid.p[8] );
                break;
            }
        SAFE_SNPRINTF();
        }
        else
    {
            ret = snprintf( p, n, "\?\?=" );
        SAFE_SNPRINTF();
        }

        for( i = 0; i < name->val.len; i++ )
        {
            if( i >= (int) sizeof( s ) - 1 )
                break;

            c = name->val.p[i];
            if( c < 32 || c == 127 || ( c > 128 && c < 160 ) )
                 s[i] = '?';
            else s[i] = c;
        }
        s[i] = '\0';
        ret = snprintf( p, n, "%s", s );
    SAFE_SNPRINTF();
        name = name->next;
    }

    return( size - n );
}

/*
 * Return an informational string about the certificate.
 */
int x509parse_cert_info( char *buf, size_t size, const char *prefix,
                         const x509_cert *crt )
{
    int i, n, nr, ret;
    char *p;

    p = buf;
    n = size;

    ret = snprintf( p, n, "%scert. version : %d\n",
                               prefix, crt->version );
    SAFE_SNPRINTF();
    ret = snprintf( p, n, "%sserial number : ",
                               prefix );
    SAFE_SNPRINTF();

    nr = ( crt->serial.len <= 32 )
        ? crt->serial.len  : 32;

    for( i = 0; i < nr; i++ )
    {
        ret = snprintf( p, n, "%02X%s",
                crt->serial.p[i], ( i < nr - 1 ) ? ":" : "" );
        SAFE_SNPRINTF();
    }

    ret = snprintf( p, n, "\n%sissuer name   : ", prefix );
    SAFE_SNPRINTF();
    ret = x509parse_dn_gets( p, n, &crt->issuer  );
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n%ssubject name  : ", prefix );
    SAFE_SNPRINTF();
    ret = x509parse_dn_gets( p, n, &crt->subject );
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n%sissued  on    : " \
                   "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                   crt->valid_from.year, crt->valid_from.mon,
                   crt->valid_from.day,  crt->valid_from.hour,
                   crt->valid_from.min,  crt->valid_from.sec );
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n%sexpires on    : " \
                   "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                   crt->valid_to.year, crt->valid_to.mon,
                   crt->valid_to.day,  crt->valid_to.hour,
                   crt->valid_to.min,  crt->valid_to.sec );
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n%ssigned using  : RSA+", prefix );
    SAFE_SNPRINTF();

    switch( crt->sig_alg )
    {
        case SIG_RSA_MD2    : ret = snprintf( p, n, "MD2"    ); break;
        case SIG_RSA_MD4    : ret = snprintf( p, n, "MD4"    ); break;
        case SIG_RSA_MD5    : ret = snprintf( p, n, "MD5"    ); break;
        case SIG_RSA_SHA1   : ret = snprintf( p, n, "SHA1"   ); break;
        case SIG_RSA_SHA224 : ret = snprintf( p, n, "SHA224" ); break;
        case SIG_RSA_SHA256 : ret = snprintf( p, n, "SHA256" ); break;
        case SIG_RSA_SHA384 : ret = snprintf( p, n, "SHA384" ); break;
        case SIG_RSA_SHA512 : ret = snprintf( p, n, "SHA512" ); break;
        default: ret = snprintf( p, n, "???"  ); break;
    }
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n%sRSA key size  : %d bits\n", prefix,
                   crt->rsa.N.n * (int) sizeof( unsigned long ) * 8 );
    SAFE_SNPRINTF();

    return( size - n );
}

/*
 * Return an informational string about the CRL.
 */
int x509parse_crl_info( char *buf, size_t size, const char *prefix,
                        const x509_crl *crl )
{
    int i, n, nr, ret;
    char *p;
    const x509_crl_entry *entry;

    p = buf;
    n = size;

    ret = snprintf( p, n, "%sCRL version   : %d",
                               prefix, crl->version );
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n%sissuer name   : ", prefix );
    SAFE_SNPRINTF();
    ret = x509parse_dn_gets( p, n, &crl->issuer );
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n%sthis update   : " \
                   "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                   crl->this_update.year, crl->this_update.mon,
                   crl->this_update.day,  crl->this_update.hour,
                   crl->this_update.min,  crl->this_update.sec );
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n%snext update   : " \
                   "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                   crl->next_update.year, crl->next_update.mon,
                   crl->next_update.day,  crl->next_update.hour,
                   crl->next_update.min,  crl->next_update.sec );
    SAFE_SNPRINTF();

    entry = &crl->entry;

    ret = snprintf( p, n, "\n%sRevoked certificates:",
                               prefix );
    SAFE_SNPRINTF();

    while( entry != NULL && entry->raw.len != 0 )
    {
        ret = snprintf( p, n, "\n%sserial number: ",
                               prefix );
        SAFE_SNPRINTF();

        nr = ( entry->serial.len <= 32 )
            ? entry->serial.len  : 32;

        for( i = 0; i < nr; i++ ) {
            ret = snprintf( p, n, "%02X%s",
                    entry->serial.p[i], ( i < nr - 1 ) ? ":" : "" );
            SAFE_SNPRINTF();
        }
        
        ret = snprintf( p, n, " revocation date: " \
                   "%04d-%02d-%02d %02d:%02d:%02d",
                   entry->revocation_date.year, entry->revocation_date.mon,
                   entry->revocation_date.day,  entry->revocation_date.hour,
                   entry->revocation_date.min,  entry->revocation_date.sec );
    SAFE_SNPRINTF();

        entry = entry->next;
    }

    ret = snprintf( p, n, "\n%ssigned using  : RSA+", prefix );
    SAFE_SNPRINTF();

    switch( crl->sig_alg )
    {
        case SIG_RSA_MD2    : ret = snprintf( p, n, "MD2"    ); break;
        case SIG_RSA_MD4    : ret = snprintf( p, n, "MD4"    ); break;
        case SIG_RSA_MD5    : ret = snprintf( p, n, "MD5"    ); break;
        case SIG_RSA_SHA1   : ret = snprintf( p, n, "SHA1"   ); break;
        case SIG_RSA_SHA224 : ret = snprintf( p, n, "SHA224" ); break;
        case SIG_RSA_SHA256 : ret = snprintf( p, n, "SHA256" ); break;
        case SIG_RSA_SHA384 : ret = snprintf( p, n, "SHA384" ); break;
        case SIG_RSA_SHA512 : ret = snprintf( p, n, "SHA512" ); break;
        default: ret = snprintf( p, n, "???"  ); break;
    }
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n" );
    SAFE_SNPRINTF();

    return( size - n );
}

/*
 * Return 0 if the x509_time is still valid, or 1 otherwise.
 */
int x509parse_time_expired( const x509_time *to )
{
    struct tm *lt;
    time_t tt;

    tt = time( NULL );
    lt = localtime( &tt );

    if( lt->tm_year  > to->year - 1900 )
        return( 1 );

    if( lt->tm_year == to->year - 1900 &&
        lt->tm_mon   > to->mon  - 1 )
        return( 1 );

    if( lt->tm_year == to->year - 1900 &&
        lt->tm_mon  == to->mon  - 1    &&
        lt->tm_mday  > to->day )
        return( 1 );

    return( 0 );
}

/*
 * Return 1 if the certificate is revoked, or 0 otherwise.
 */
int x509parse_revoked( const x509_cert *crt, const x509_crl *crl )
{
    const x509_crl_entry *cur = &crl->entry;

    while( cur != NULL && cur->serial.len != 0 )
    {
        if( memcmp( crt->serial.p, cur->serial.p, crt->serial.len ) == 0 )
        {
            if( x509parse_time_expired( &cur->revocation_date ) )
                return( 1 );
        }

        cur = cur->next;
    }

    return( 0 );
}

/*
 * Wrapper for x509 hashes.
 *
 * @param out   Buffer to receive the hash (Should be at least 64 bytes)
 */
static void x509_hash( const unsigned char *in, int len, int alg,
                       unsigned char *out )
{
    switch( alg )
    {
#if defined(POLARSSL_MD2_C)
        case SIG_RSA_MD2    :  md2( in, len, out ); break;
#endif
#if defined(POLARSSL_MD4_C)
        case SIG_RSA_MD4    :  md4( in, len, out ); break;
#endif
#if defined(POLARSSL_MD5_C)
        case SIG_RSA_MD5    :  md5( in, len, out ); break;
#endif
#if defined(POLARSSL_SHA1_C)
        case SIG_RSA_SHA1   : sha1( in, len, out ); break;
#endif
#if defined(POLARSSL_SHA2_C)
        case SIG_RSA_SHA224 : sha2( in, len, out, 1 ); break;
        case SIG_RSA_SHA256 : sha2( in, len, out, 0 ); break;
#endif
#if defined(POLARSSL_SHA4_C)
        case SIG_RSA_SHA384 : sha4( in, len, out, 1 ); break;
        case SIG_RSA_SHA512 : sha4( in, len, out, 0 ); break;
#endif
        default:
            memset( out, '\xFF', 64 );
            break;
    }
}

/*
 * Verify the certificate validity
 */
int x509parse_verify( x509_cert *crt,
                      x509_cert *trust_ca,
                      x509_crl *ca_crl,
                      const char *cn, int *flags )
{
    int cn_len;
    int hash_id;
    int pathlen;
    x509_cert *cur;
    x509_name *name;
    unsigned char hash[64];

    *flags = 0;

    if( x509parse_time_expired( &crt->valid_to ) )
        *flags = BADCERT_EXPIRED;

    if( cn != NULL )
    {
        name = &crt->subject;
        cn_len = strlen( cn );

        while( name != NULL )
        {
            if( memcmp( name->oid.p, OID_CN,  3 ) == 0 &&
                memcmp( name->val.p, cn, cn_len ) == 0 &&
                name->val.len == cn_len )
                break;

            name = name->next;
        }

        if( name == NULL )
            *flags |= BADCERT_CN_MISMATCH;
    }

    *flags |= BADCERT_NOT_TRUSTED;

    /*
     * Iterate upwards in the given cert chain,
     * ignoring any upper cert with CA != TRUE.
     */
    cur = crt->next;

    pathlen = 1;

    while( cur != NULL && cur->version != 0 )
    {
        if( cur->ca_istrue == 0 ||
            crt->issuer_raw.len != cur->subject_raw.len ||
            memcmp( crt->issuer_raw.p, cur->subject_raw.p,
                    crt->issuer_raw.len ) != 0 )
        {
            cur = cur->next;
            continue;
        }

        hash_id = crt->sig_alg;

        x509_hash( crt->tbs.p, crt->tbs.len, hash_id, hash );

        if( rsa_pkcs1_verify( &cur->rsa, RSA_PUBLIC, hash_id,
                              0, hash, crt->sig.p ) != 0 )
            return( POLARSSL_ERR_X509_CERT_VERIFY_FAILED );

        pathlen++;

        crt = cur;
        cur = crt->next;
    }

    /*
     * Atempt to validate topmost cert with our CA chain.
     */
    while( trust_ca != NULL && trust_ca->version != 0 )
    {
        if( crt->issuer_raw.len != trust_ca->subject_raw.len ||
            memcmp( crt->issuer_raw.p, trust_ca->subject_raw.p,
                    crt->issuer_raw.len ) != 0 )
        {
            trust_ca = trust_ca->next;
            continue;
        }

        if( trust_ca->max_pathlen > 0 &&
            trust_ca->max_pathlen < pathlen )
            break;

        hash_id = crt->sig_alg;

        x509_hash( crt->tbs.p, crt->tbs.len, hash_id, hash );

        if( rsa_pkcs1_verify( &trust_ca->rsa, RSA_PUBLIC, hash_id,
                              0, hash, crt->sig.p ) == 0 )
        {
            /*
             * cert. is signed by a trusted CA
             */
            *flags &= ~BADCERT_NOT_TRUSTED;
            break;
        }

        trust_ca = trust_ca->next;
    }

    /*
     * TODO: What happens if no CRL is present?
     * Suggestion: Revocation state should be unknown if no CRL is present.
     * For backwards compatibility this is not yet implemented.
     */

    /*
     * Check if the topmost certificate is revoked if the trusted CA is
     * determined.
     */
    while( trust_ca != NULL && ca_crl != NULL && ca_crl->version != 0 )
    {
        if( ca_crl->issuer_raw.len != trust_ca->subject_raw.len ||
            memcmp( ca_crl->issuer_raw.p, trust_ca->subject_raw.p,
                    ca_crl->issuer_raw.len ) != 0 )
        {
            ca_crl = ca_crl->next;
            continue;
        }

        /*
         * Check if CRL is correctry signed by the trusted CA
         */
        hash_id = ca_crl->sig_alg;

        x509_hash( ca_crl->tbs.p, ca_crl->tbs.len, hash_id, hash );

        if( !rsa_pkcs1_verify( &trust_ca->rsa, RSA_PUBLIC, hash_id,
                              0, hash, ca_crl->sig.p ) == 0 )
        {
            /*
             * CRL is not trusted
             */
            *flags |= BADCRL_NOT_TRUSTED;
            break;
        }

        /*
         * Check for validity of CRL (Do not drop out)
         */
        if( x509parse_time_expired( &ca_crl->next_update ) )
            *flags |= BADCRL_EXPIRED;
        
        /*
         * Check if certificate is revoked
         */
        if( x509parse_revoked(crt, ca_crl) )
        {
            *flags |= BADCERT_REVOKED;
            break;
        }

        ca_crl = ca_crl->next;
    }

    if( *flags != 0 )
        return( POLARSSL_ERR_X509_CERT_VERIFY_FAILED );

    return( 0 );
}

/*
 * Unallocate all certificate data
 */
void x509_free( x509_cert *crt )
{
    x509_cert *cert_cur = crt;
    x509_cert *cert_prv;
    x509_name *name_cur;
    x509_name *name_prv;

    if( crt == NULL )
        return;

    do
    {
        rsa_free( &cert_cur->rsa );

        name_cur = cert_cur->issuer.next;
        while( name_cur != NULL )
        {
            name_prv = name_cur;
            name_cur = name_cur->next;
            memset( name_prv, 0, sizeof( x509_name ) );
            free( name_prv );
        }

        name_cur = cert_cur->subject.next;
        while( name_cur != NULL )
        {
            name_prv = name_cur;
            name_cur = name_cur->next;
            memset( name_prv, 0, sizeof( x509_name ) );
            free( name_prv );
        }

        if( cert_cur->raw.p != NULL )
        {
            memset( cert_cur->raw.p, 0, cert_cur->raw.len );
            free( cert_cur->raw.p );
        }

        cert_cur = cert_cur->next;
    }
    while( cert_cur != NULL );

    cert_cur = crt;
    do
    {
        cert_prv = cert_cur;
        cert_cur = cert_cur->next;

        memset( cert_prv, 0, sizeof( x509_cert ) );
        if( cert_prv != crt )
            free( cert_prv );
    }
    while( cert_cur != NULL );
}

/*
 * Unallocate all CRL data
 */
void x509_crl_free( x509_crl *crl )
{
    x509_crl *crl_cur = crl;
    x509_crl *crl_prv;
    x509_name *name_cur;
    x509_name *name_prv;
    x509_crl_entry *entry_cur;
    x509_crl_entry *entry_prv;

    if( crl == NULL )
        return;

    do
    {
        name_cur = crl_cur->issuer.next;
        while( name_cur != NULL )
        {
            name_prv = name_cur;
            name_cur = name_cur->next;
            memset( name_prv, 0, sizeof( x509_name ) );
            free( name_prv );
        }

        entry_cur = crl_cur->entry.next;
        while( entry_cur != NULL )
        {
            entry_prv = entry_cur;
            entry_cur = entry_cur->next;
            memset( entry_prv, 0, sizeof( x509_crl_entry ) );
            free( entry_prv );
        }

        if( crl_cur->raw.p != NULL )
        {
            memset( crl_cur->raw.p, 0, crl_cur->raw.len );
            free( crl_cur->raw.p );
        }

        crl_cur = crl_cur->next;
    }
    while( crl_cur != NULL );

    crl_cur = crl;
    do
    {
        crl_prv = crl_cur;
        crl_cur = crl_cur->next;

        memset( crl_prv, 0, sizeof( x509_crl ) );
        if( crl_prv != crl )
            free( crl_prv );
    }
    while( crl_cur != NULL );
}

#if defined(POLARSSL_SELF_TEST)

#include "polarssl/certs.h"

/*
 * Checkup routine
 */
int x509_self_test( int verbose )
{
#if defined(POLARSSL_MD5_C)
    int ret, i, j;
    x509_cert cacert;
    x509_cert clicert;
    rsa_context rsa;

    if( verbose != 0 )
        printf( "  X.509 certificate load: " );

    memset( &clicert, 0, sizeof( x509_cert ) );

    ret = x509parse_crt( &clicert, (unsigned char *) test_cli_crt,
                         strlen( test_cli_crt ) );
    if( ret != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( ret );
    }

    memset( &cacert, 0, sizeof( x509_cert ) );

    ret = x509parse_crt( &cacert, (unsigned char *) test_ca_crt,
                         strlen( test_ca_crt ) );
    if( ret != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( ret );
    }

    if( verbose != 0 )
        printf( "passed\n  X.509 private key load: " );

    i = strlen( test_ca_key );
    j = strlen( test_ca_pwd );

    if( ( ret = x509parse_key( &rsa,
                    (unsigned char *) test_ca_key, i,
                    (unsigned char *) test_ca_pwd, j ) ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( ret );
    }

    if( verbose != 0 )
        printf( "passed\n  X.509 signature verify: ");

    ret = x509parse_verify( &clicert, &cacert, NULL, "PolarSSL Client 2", &i );
    if( ret != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( ret );
    }

    if( verbose != 0 )
        printf( "passed\n\n" );

    x509_free( &cacert  );
    x509_free( &clicert );
    rsa_free( &rsa );

    return( 0 );
#else
    ((void) verbose);
    return( POLARSSL_ERR_X509_FEATURE_UNAVAILABLE );
#endif
}

#endif

#endif
