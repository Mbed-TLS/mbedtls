/*
 * X509 buffer writing functionality
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
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

#include "polarssl/config.h"

#if defined(POLARSSL_X509_WRITE_C)

#include "polarssl/asn1write.h"
#include "polarssl/x509write.h"
#include "polarssl/x509.h"
#include "polarssl/md.h"
#include "polarssl/oid.h"

#if defined(POLARSSL_MEMORY_C)
#include "polarssl/memory.h"
#else
#include <stdlib.h>
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

void x509write_csr_init( x509_csr *ctx )
{
    memset( ctx, 0, sizeof(x509_csr) );
}

void x509write_csr_free( x509_csr *ctx )
{
    x509_req_name *cur;
    asn1_named_data *cur_ext;

    while( ( cur = ctx->subject ) != NULL )
    {
        ctx->subject = cur->next;
        polarssl_free( cur );
    }

    while( ( cur_ext = ctx->extensions ) != NULL )
    {
        ctx->extensions = cur_ext->next;
        asn1_free_named_data( cur_ext );
        polarssl_free( cur_ext );
    }

    memset( ctx, 0, sizeof(x509_csr) );
}

void x509write_csr_set_md_alg( x509_csr *ctx, md_type_t md_alg )
{
    ctx->md_alg = md_alg;
}

void x509write_csr_set_rsa_key( x509_csr *ctx, rsa_context *rsa )
{
    ctx->rsa = rsa;
}

int x509write_csr_set_subject_name( x509_csr *ctx, char *subject_name )
{
    int ret = 0;
    char *s = subject_name, *c = s;
    char *end = s + strlen( s );
    char *oid = NULL;
    int in_tag = 1;
    x509_req_name *cur;

    while( ctx->subject )
    {
        cur = ctx->subject;
        ctx->subject = ctx->subject->next;
        polarssl_free( cur );
    }

    while( c <= end )
    {
        if( in_tag && *c == '=' )
        {
            if( memcmp( s, "CN", 2 ) == 0 && c - s == 2 )
                oid = OID_AT_CN;
            else if( memcmp( s, "C", 1 ) == 0 && c - s == 1 )
                oid = OID_AT_COUNTRY;
            else if( memcmp( s, "O", 1 ) == 0 && c - s == 1 )
                oid = OID_AT_ORGANIZATION;
            else if( memcmp( s, "L", 1 ) == 0 && c - s == 1 )
                oid = OID_AT_LOCALITY;
            else if( memcmp( s, "R", 1 ) == 0 && c - s == 1 )
                oid = OID_PKCS9_EMAIL;
            else if( memcmp( s, "OU", 2 ) == 0 && c - s == 2 )
                oid = OID_AT_ORG_UNIT;
            else if( memcmp( s, "ST", 2 ) == 0 && c - s == 2 )
                oid = OID_AT_STATE;
            else
            {
                ret = POLARSSL_ERR_X509WRITE_UNKNOWN_OID;
                goto exit;
            }

            s = c + 1;
            in_tag = 0;
        }

        if( !in_tag && ( *c == ',' || c == end ) )
        {
            if( c - s > 127 )
            {
                ret = POLARSSL_ERR_X509WRITE_BAD_INPUT_DATA;
                goto exit;
            }

            cur = polarssl_malloc( sizeof(x509_req_name) );

            if( cur == NULL )
            {
                ret = POLARSSL_ERR_X509WRITE_MALLOC_FAILED;
                goto exit;
            }

            memset( cur, 0, sizeof(x509_req_name) );

            cur->next = ctx->subject;
            ctx->subject = cur;

            strncpy( cur->oid, oid, strlen( oid ) );
            strncpy( cur->name, s, c - s );

            s = c + 1;
            in_tag = 1;
        }
        c++;
    }

exit:

    return( ret );
}

int x509write_csr_set_key_usage( x509_csr *ctx, unsigned char key_usage )
{
    asn1_named_data *cur;
    unsigned char *c;
    int len;

    if( ( cur = asn1_find_named_data( ctx->extensions, OID_KEY_USAGE,
                                      OID_SIZE( OID_KEY_USAGE ) ) ) == NULL )
    {
        cur = polarssl_malloc( sizeof(asn1_named_data) );
        if( cur == NULL )
            return( POLARSSL_ERR_X509WRITE_MALLOC_FAILED );

        memset( cur, 0, sizeof(asn1_named_data) );

        cur->oid.len = OID_SIZE( OID_KEY_USAGE );
        cur->oid.p = polarssl_malloc( cur->oid.len );
        if( cur->oid.p == NULL )
        {
            free( cur );
            return( POLARSSL_ERR_X509WRITE_MALLOC_FAILED );
        }

        cur->val.len = 4;
        cur->val.p = polarssl_malloc( cur->val.len );
        if( cur->val.p == NULL )
        {
            free( cur->oid.p );
            free( cur );
            return( POLARSSL_ERR_X509WRITE_MALLOC_FAILED );
        }

        memcpy( cur->oid.p, OID_KEY_USAGE, OID_SIZE( OID_KEY_USAGE ) );

        cur->next = ctx->extensions;
        ctx->extensions = cur;
    }

    c = cur->val.p + cur->val.len;
    if( ( len = asn1_write_bitstring( &c, cur->val.p, &key_usage, 6 ) ) < 0 )
exit(1);

    return( 0 );
}

int x509write_pubkey_der( rsa_context *rsa, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char *c;
    size_t len = 0;

    c = buf + size - 1;

    /*
    *  RSAPublicKey ::= SEQUENCE {
    *      modulus           INTEGER,  -- n
    *      publicExponent    INTEGER   -- e
    *  }
    */
    ASN1_CHK_ADD( len, asn1_write_mpi( &c, buf, &rsa->E ) );
    ASN1_CHK_ADD( len, asn1_write_mpi( &c, buf, &rsa->N ) );

    ASN1_CHK_ADD( len, asn1_write_len( &c, buf, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( &c, buf, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    if( c - buf < 1 )
        return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--c = 0;
    len += 1;

    ASN1_CHK_ADD( len, asn1_write_len( &c, buf, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( &c, buf, ASN1_BIT_STRING ) );

    ASN1_CHK_ADD( len, asn1_write_algorithm_identifier( &c, buf, OID_PKCS1_RSA ) );

    ASN1_CHK_ADD( len, asn1_write_len( &c, buf, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( &c, buf, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    return( len );
}

int x509write_key_der( rsa_context *rsa, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char *c;
    size_t len = 0;

    c = buf + size - 1;

    ASN1_CHK_ADD( len, asn1_write_mpi( &c, buf, &rsa->QP ) );
    ASN1_CHK_ADD( len, asn1_write_mpi( &c, buf, &rsa->DQ ) );
    ASN1_CHK_ADD( len, asn1_write_mpi( &c, buf, &rsa->DP ) );
    ASN1_CHK_ADD( len, asn1_write_mpi( &c, buf, &rsa->Q ) );
    ASN1_CHK_ADD( len, asn1_write_mpi( &c, buf, &rsa->P ) );
    ASN1_CHK_ADD( len, asn1_write_mpi( &c, buf, &rsa->D ) );
    ASN1_CHK_ADD( len, asn1_write_mpi( &c, buf, &rsa->E ) );
    ASN1_CHK_ADD( len, asn1_write_mpi( &c, buf, &rsa->N ) );
    ASN1_CHK_ADD( len, asn1_write_int( &c, buf, 0 ) );

    ASN1_CHK_ADD( len, asn1_write_len( &c, buf, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( &c, buf, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    // TODO: Make NON RSA Specific variant later on
/*    *--c = 0;
    len += 1;

    len += asn1_write_len( &c, len);
    len += asn1_write_tag( &c, ASN1_BIT_STRING );

    len += asn1_write_oid( &c, OID_PKCS1_RSA );

    len += asn1_write_int( &c, 0 );

    len += asn1_write_len( &c, len);
    len += asn1_write_tag( &c, ASN1_CONSTRUCTED | ASN1_SEQUENCE );*/

/*    for(i = 0; i < len; ++i)
    {
        if (i % 16 == 0 ) printf("\n");
        printf("%02x ", c[i]);
    }
    printf("\n");*/

    return( len );
}

static int x509_write_name( unsigned char **p, unsigned char *start, char *oid,
                            char *name )
{
    int ret;
    size_t string_len = 0;
    size_t oid_len = 0;
    size_t len = 0;

    // Write PrintableString for all except OID_PKCS9_EMAIL
    //
    if( OID_SIZE( OID_PKCS9_EMAIL ) == strlen( oid ) &&
        memcmp( oid, OID_PKCS9_EMAIL, strlen( oid ) ) == 0 )
    {
        ASN1_CHK_ADD( string_len, asn1_write_ia5_string( p, start, name ) );
    }
    else
        ASN1_CHK_ADD( string_len, asn1_write_printable_string( p, start, name ) );

    // Write OID
    //
    ASN1_CHK_ADD( oid_len, asn1_write_oid( p, start, oid ) );

    len = oid_len + string_len;
    ASN1_CHK_ADD( len, asn1_write_len( p, start, oid_len + string_len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_CONSTRUCTED | ASN1_SET ) );

    return( len );
}

static int x509_write_sig( unsigned char **p, unsigned char *start,
                           const char *oid, unsigned char *sig, size_t size )
{
    int ret;
    size_t len = 0;

    if( *p - start < (int) size + 1 )
        return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

    len = size;
    (*p) -= len;
    memcpy( *p, sig, len );

    *--(*p) = 0;
    len += 1;

    ASN1_CHK_ADD( len, asn1_write_len( p, start, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( p, start, ASN1_BIT_STRING ) );

    // Write OID
    //
    ASN1_CHK_ADD( len, asn1_write_algorithm_identifier( p, start, oid ) );

    return( len );
}

int x509write_csr_der( x509_csr *ctx, unsigned char *buf, size_t size )
{
    int ret;
    const char *sig_oid;
    unsigned char *c, *c2;
    unsigned char hash[64];
    unsigned char sig[POLARSSL_MPI_MAX_SIZE];
    unsigned char tmp_buf[2048];
    size_t sub_len = 0, pub_len = 0, sig_len = 0;
    size_t len = 0;
    x509_req_name *cur = ctx->subject;
    asn1_named_data *cur_ext = ctx->extensions;

    c = tmp_buf + 2048 - 1;

    while( cur_ext != NULL )
    {
        size_t ext_len = 0;

        ASN1_CHK_ADD( ext_len, asn1_write_raw_buffer( &c, tmp_buf, cur_ext->val.p,
                                                      cur_ext->val.len ) );
        ASN1_CHK_ADD( ext_len, asn1_write_len( &c, tmp_buf, cur_ext->val.len ) );
        ASN1_CHK_ADD( ext_len, asn1_write_tag( &c, tmp_buf, ASN1_OCTET_STRING ) );

        ASN1_CHK_ADD( ext_len, asn1_write_raw_buffer( &c, tmp_buf, cur_ext->oid.p,
                                                      cur_ext->oid.len ) );
        ASN1_CHK_ADD( ext_len, asn1_write_len( &c, tmp_buf, cur_ext->oid.len ) );
        ASN1_CHK_ADD( ext_len, asn1_write_tag( &c, tmp_buf, ASN1_OID ) );

        ASN1_CHK_ADD( ext_len, asn1_write_len( &c, tmp_buf, ext_len ) );
        ASN1_CHK_ADD( ext_len, asn1_write_tag( &c, tmp_buf, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

        cur_ext = cur_ext->next;

        len += ext_len;
    }

    if( len )
    {
        ASN1_CHK_ADD( len, asn1_write_len( &c, tmp_buf, len ) );
        ASN1_CHK_ADD( len, asn1_write_tag( &c, tmp_buf, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

        ASN1_CHK_ADD( len, asn1_write_len( &c, tmp_buf, len ) );
        ASN1_CHK_ADD( len, asn1_write_tag( &c, tmp_buf, ASN1_CONSTRUCTED | ASN1_SET ) );

        ASN1_CHK_ADD( len, asn1_write_oid( &c, tmp_buf, OID_PKCS9_CSR_EXT_REQ ) );

        ASN1_CHK_ADD( len, asn1_write_len( &c, tmp_buf, len ) );
        ASN1_CHK_ADD( len, asn1_write_tag( &c, tmp_buf, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );
    }

    ASN1_CHK_ADD( len, asn1_write_len( &c, tmp_buf, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( &c, tmp_buf, ASN1_CONSTRUCTED | ASN1_CONTEXT_SPECIFIC ) );

    ASN1_CHK_ADD( pub_len, asn1_write_mpi( &c, tmp_buf, &ctx->rsa->E ) );
    ASN1_CHK_ADD( pub_len, asn1_write_mpi( &c, tmp_buf, &ctx->rsa->N ) );

    ASN1_CHK_ADD( pub_len, asn1_write_len( &c, tmp_buf, pub_len ) );
    ASN1_CHK_ADD( pub_len, asn1_write_tag( &c, tmp_buf, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    if( c - tmp_buf < 1 )
        return( POLARSSL_ERR_ASN1_BUF_TOO_SMALL );

    /*
     *  AlgorithmIdentifier  ::=  SEQUENCE  {
     *       algorithm               OBJECT IDENTIFIER,
     *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
     */
    *--c = 0;
    pub_len += 1;

    ASN1_CHK_ADD( pub_len, asn1_write_len( &c, tmp_buf, pub_len ) );
    ASN1_CHK_ADD( pub_len, asn1_write_tag( &c, tmp_buf, ASN1_BIT_STRING ) );

    ASN1_CHK_ADD( pub_len, asn1_write_algorithm_identifier( &c, tmp_buf, OID_PKCS1_RSA ) );

    len += pub_len;
    ASN1_CHK_ADD( len, asn1_write_len( &c, tmp_buf, pub_len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( &c, tmp_buf, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    while( cur != NULL )
    {
        ASN1_CHK_ADD( sub_len, x509_write_name( &c, tmp_buf, cur->oid, cur->name ) );

        cur = cur->next;
    }

    len += sub_len;
    ASN1_CHK_ADD( len, asn1_write_len( &c, tmp_buf, sub_len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( &c, tmp_buf, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */
    ASN1_CHK_ADD( len, asn1_write_int( &c, tmp_buf, 0 ) );

    ASN1_CHK_ADD( len, asn1_write_len( &c, tmp_buf, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( &c, tmp_buf, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    md( md_info_from_type( ctx->md_alg ), c, len, hash );

    rsa_pkcs1_sign( ctx->rsa, NULL, NULL, RSA_PRIVATE, ctx->md_alg, 0, hash, sig );

    // Generate correct OID
    //
    ret = oid_get_oid_by_sig_alg( POLARSSL_PK_RSA, ctx->md_alg, &sig_oid );

    c2 = buf + size - 1;
    ASN1_CHK_ADD( sig_len, x509_write_sig( &c2, buf, sig_oid, sig, ctx->rsa->len ) );

    c2 -= len;
    memcpy( c2, c, len );

    len += sig_len;
    ASN1_CHK_ADD( len, asn1_write_len( &c2, buf, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( &c2, buf, ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    return( len );
}

#endif
