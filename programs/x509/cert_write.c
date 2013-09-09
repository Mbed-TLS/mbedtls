/*
 *  Certificate generation and signing
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

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "polarssl/config.h"

#include "polarssl/error.h"
#include "polarssl/rsa.h"
#include "polarssl/x509.h"
#include "polarssl/base64.h"
#include "polarssl/x509write.h"
#include "polarssl/oid.h"

#if !defined(POLARSSL_BIGNUM_C) || !defined(POLARSSL_RSA_C) ||         \
    !defined(POLARSSL_X509_WRITE_C) || !defined(POLARSSL_FS_IO)
int main( int argc, char *argv[] )
{
    ((void) argc);
    ((void) argv);

    printf("POLARSSL_BIGNUM_C and/or POLARSSL_RSA_C and/or "
           "POLARSSL_X509_WRITE_C and/or POLARSSL_FS_IO not defined.\n");
    return( 0 );
}
#else

#define DFL_SUBJECT_KEY         "subject.key"
#define DFL_ISSUER_KEY          "ca.key"
#define DFL_SUBJECT_PWD         ""
#define DFL_ISSUER_PWD          ""
#define DFL_OUTPUT_FILENAME     "cert.crt"
#define DFL_SUBJECT_NAME        "CN=Cert,O=PolarSSL,C=NL"
#define DFL_ISSUER_NAME         "CN=CA,O=PolarSSL,C=NL"
#define DFL_NOT_BEFORE          "20010101000000"
#define DFL_NOT_AFTER           "20301231235959"
#define DFL_SERIAL              "1"
#define DFL_IS_CA               0
#define DFL_MAX_PATHLEN         -1
#define DFL_KEY_USAGE           0
#define DFL_NS_CERT_TYPE        0

/*
 * global options
 */
struct options
{
    char *subject_key;          /* filename of the subject key file     */
    char *issuer_key;           /* filename of the issuer key file      */
    char *subject_pwd;          /* password for the subject key file    */
    char *issuer_pwd;           /* password for the issuer key file     */
    char *output_file;          /* where to store the constructed key file  */
    char *subject_name;         /* subject name for certificate         */
    char *issuer_name;          /* issuer name for certificate          */
    char *not_before;           /* validity period not before           */
    char *not_after;            /* validity period not after            */
    char *serial;               /* serial number string                 */
    int is_ca;                  /* is a CA certificate                  */
    int max_pathlen;            /* maximum CA path length               */
    unsigned char key_usage;    /* key usage flags                      */
    unsigned char ns_cert_type; /* NS cert type                         */
} opt;

int write_certificate( x509write_cert *crt, char *output_file )
{
    int ret;
    FILE *f;
    unsigned char output_buf[4096];
    size_t len = 0;

    memset( output_buf, 0, 4096 );
    if( ( ret = x509write_crt_pem( crt, output_buf, 4096 ) ) < 0 )
        return( ret );

    len = strlen( (char *) output_buf );

    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( output_buf, 1, len, f ) != len )
        return( -1 );

    fclose(f);

    return( 0 );
}

#define USAGE \
    "\n usage: cert_write param=<>...\n"                \
    "\n acceptable parameters:\n"                       \
    "    subject_key=%%s      default: subject.key\n"   \
    "    subject_pwd=%%s      default: (empty)\n"       \
    "    issuer_key=%%s       default: ca.key\n"        \
    "    issuer_pwd=%%s       default: (empty)\n"       \
    "    output_file=%%s      default: cert.crt\n"      \
    "    subject_name=%%s     default: CN=Cert,O=PolarSSL,C=NL\n"   \
    "    issuer_name=%%s      default: CN=CA,O=PolarSSL,C=NL\n"     \
    "    serial=%%s           default: 1\n"             \
    "    not_before=%%s       default: 20010101000000\n"\
    "    not_after=%%s        default: 20301231235959\n"\
    "    is_ca=%%d            default: 0 (disabled)\n"  \
    "    max_pathlen=%%d      default: -1 (none)\n"     \
    "    key_usage=%%s        default: (empty)\n"       \
    "                        Comma-separated-list of values:\n"     \
    "                          digital_signature\n"     \
    "                          non_repudiation\n"       \
    "                          key_encipherment\n"      \
    "                          data_encipherment\n"     \
    "                          key_agreement\n"         \
    "                          key_certificate_sign\n"  \
    "                          crl_sign\n"              \
    "    ns_cert_type=%%s     default: (empty)\n"       \
    "                        Comma-separated-list of values:\n"     \
    "                          ssl_client\n"            \
    "                          ssl_server\n"            \
    "                          email\n"                 \
    "                          object_signing\n"        \
    "                          ssl_ca\n"                \
    "                          email_ca\n"              \
    "                          object_signing_ca\n"     \
    "\n"

int main( int argc, char *argv[] )
{
    int ret = 0;
    rsa_context issuer_rsa, subject_rsa;
    char buf[1024];
    int i, j, n;
    char *p, *q, *r;
    x509write_cert crt;
    mpi serial;

    /*
     * Set to sane values
     */
    x509write_crt_init( &crt );
    x509write_crt_set_md_alg( &crt, POLARSSL_MD_SHA1 );
    rsa_init( &issuer_rsa, RSA_PKCS_V15, 0 );
    rsa_init( &subject_rsa, RSA_PKCS_V15, 0 );
    mpi_init( &serial );
    memset( buf, 0, 1024 );

    if( argc == 0 )
    {
    usage:
        printf( USAGE );
        ret = 1;
        goto exit;
    }

    opt.subject_key         = DFL_SUBJECT_KEY;
    opt.issuer_key          = DFL_ISSUER_KEY;
    opt.subject_pwd         = DFL_SUBJECT_PWD;
    opt.issuer_pwd          = DFL_ISSUER_PWD;
    opt.output_file         = DFL_OUTPUT_FILENAME;
    opt.subject_name        = DFL_SUBJECT_NAME;
    opt.issuer_name         = DFL_ISSUER_NAME;
    opt.not_before          = DFL_NOT_BEFORE;
    opt.not_after           = DFL_NOT_AFTER;
    opt.serial              = DFL_SERIAL;
    opt.is_ca               = DFL_IS_CA;
    opt.max_pathlen         = DFL_MAX_PATHLEN;
    opt.key_usage           = DFL_KEY_USAGE;
    opt.ns_cert_type        = DFL_NS_CERT_TYPE;

    for( i = 1; i < argc; i++ )
    {

        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';

        n = strlen( p );
        for( j = 0; j < n; j++ )
        {
            if( argv[i][j] >= 'A' && argv[i][j] <= 'Z' )
                argv[i][j] |= 0x20;
        }

        if( strcmp( p, "subject_key" ) == 0 )
            opt.subject_key = q;
        else if( strcmp( p, "issuer_key" ) == 0 )
            opt.issuer_key = q;
        else if( strcmp( p, "subject_pwd" ) == 0 )
            opt.subject_pwd = q;
        else if( strcmp( p, "issuer_pwd" ) == 0 )
            opt.issuer_pwd = q;
        else if( strcmp( p, "output_file" ) == 0 )
            opt.output_file = q;
        else if( strcmp( p, "subject_name" ) == 0 )
        {
            opt.subject_name = q;
        }
        else if( strcmp( p, "issuer_name" ) == 0 )
        {
            opt.issuer_name = q;
        }
        else if( strcmp( p, "not_before" ) == 0 )
        {
            opt.not_before = q;
        }
        else if( strcmp( p, "not_after" ) == 0 )
        {
            opt.not_after = q;
        }
        else if( strcmp( p, "serial" ) == 0 )
        {
            opt.serial = q;
        }
        else if( strcmp( p, "is_ca" ) == 0 )
        {
            opt.is_ca = atoi( q );
            if( opt.is_ca < 0 || opt.is_ca > 1 )
                goto usage;
        }
        else if( strcmp( p, "max_pathlen" ) == 0 )
        {
            opt.max_pathlen = atoi( q );
            if( opt.max_pathlen < -1 || opt.max_pathlen > 127 )
                goto usage;
        }
        else if( strcmp( p, "key_usage" ) == 0 )
        {
            while( q != NULL )
            {
                if( ( r = strchr( q, ',' ) ) != NULL )
                    *r++ = '\0';

                if( strcmp( q, "digital_signature" ) == 0 )
                    opt.key_usage |= KU_DIGITAL_SIGNATURE;
                else if( strcmp( q, "non_repudiation" ) == 0 )
                    opt.key_usage |= KU_NON_REPUDIATION;
                else if( strcmp( q, "key_encipherment" ) == 0 )
                    opt.key_usage |= KU_KEY_ENCIPHERMENT;
                else if( strcmp( q, "data_encipherment" ) == 0 )
                    opt.key_usage |= KU_DATA_ENCIPHERMENT;
                else if( strcmp( q, "key_agreement" ) == 0 )
                    opt.key_usage |= KU_KEY_AGREEMENT;
                else if( strcmp( q, "key_cert_sign" ) == 0 )
                    opt.key_usage |= KU_KEY_CERT_SIGN;
                else if( strcmp( q, "crl_sign" ) == 0 )
                    opt.key_usage |= KU_CRL_SIGN;
                else
                    goto usage;

                q = r;
            }
        }
        else if( strcmp( p, "ns_cert_type" ) == 0 )
        {
            while( q != NULL )
            {
                if( ( r = strchr( q, ',' ) ) != NULL )
                    *r++ = '\0';

                if( strcmp( q, "ssl_client" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_SSL_CLIENT;
                else if( strcmp( q, "ssl_server" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_SSL_SERVER;
                else if( strcmp( q, "email" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_EMAIL;
                else if( strcmp( q, "object_signing" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_OBJECT_SIGNING;
                else if( strcmp( q, "ssl_ca" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_SSL_CA;
                else if( strcmp( q, "email_ca" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_EMAIL_CA;
                else if( strcmp( q, "object_signing_ca" ) == 0 )
                    opt.ns_cert_type |= NS_CERT_TYPE_OBJECT_SIGNING_CA;
                else
                    goto usage;

                q = r;
            }
        }
        else
            goto usage;
    }

    // Parse serial to MPI
    //
    if( ( ret = mpi_read_string( &serial, 10, opt.serial ) ) != 0 )
    {
#ifdef POLARSSL_ERROR_C
        error_strerror( ret, buf, 1024 );
#endif
        printf( " failed\n  !  mpi_read_string returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    /*
     * 1.0. Check the names for validity
     */
    if( ( ret = x509write_crt_set_subject_name( &crt, opt.subject_name ) ) != 0 )
    {
#ifdef POLARSSL_ERROR_C
        error_strerror( ret, buf, 1024 );
#endif
        printf( " failed\n  !  x509write_crt_set_subject_name returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    if( ( ret = x509write_crt_set_issuer_name( &crt, opt.issuer_name ) ) != 0 )
    {
#ifdef POLARSSL_ERROR_C
        error_strerror( ret, buf, 1024 );
#endif
        printf( " failed\n  !  x509write_crt_set_issuer_name returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    /*
     * 1.1. Load the keys
     */
    printf( "\n  . Loading the subject key ..." );
    fflush( stdout );

    ret = x509parse_keyfile_rsa( &subject_rsa, opt.subject_key, opt.subject_pwd );

    if( ret != 0 )
    {
#ifdef POLARSSL_ERROR_C
        error_strerror( ret, buf, 1024 );
#endif
        printf( " failed\n  !  x509parse_keyfile_rsa returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    x509write_crt_set_subject_key( &crt, &subject_rsa );

    printf( " ok\n" );

    printf( "  . Loading the issuer key ..." );
    fflush( stdout );

    ret = x509parse_keyfile_rsa( &issuer_rsa, opt.issuer_key, opt.issuer_pwd );

    if( ret != 0 )
    {
#ifdef POLARSSL_ERROR_C
        error_strerror( ret, buf, 1024 );
#endif
        printf( " failed\n  !  x509parse_keyfile_rsa returned -x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    x509write_crt_set_issuer_key( &crt, &issuer_rsa );

    printf( " ok\n" );

    printf( "  . Setting certificate values ..." );
    fflush( stdout );

    ret = x509write_crt_set_serial( &crt, &serial );
    if( ret != 0 )
    {
#ifdef POLARSSL_ERROR_C
        error_strerror( ret, buf, 1024 );
#endif
        printf( " failed\n  !  x509write_crt_set_serial returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    ret = x509write_crt_set_validity( &crt, opt.not_before, opt.not_after );
    if( ret != 0 )
    {
#ifdef POLARSSL_ERROR_C
        error_strerror( ret, buf, 1024 );
#endif
        printf( " failed\n  !  x509write_crt_set_validity returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    printf( " ok\n" );

    printf( "  . Adding the Basic Constraints extension ..." );
    fflush( stdout );

    ret = x509write_crt_set_basic_constraints( &crt, opt.is_ca,
                                               opt.max_pathlen );
    if( ret != 0 )
    {
#ifdef POLARSSL_ERROR_C
        error_strerror( ret, buf, 1024 );
#endif
        printf( " failed\n  !  x509write_crt_set_basic_contraints returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    printf( " ok\n" );

    printf( "  . Adding the Subject Key Identifier ..." );
    fflush( stdout );

    ret = x509write_crt_set_subject_key_identifier( &crt );
    if( ret != 0 )
    {
#ifdef POLARSSL_ERROR_C
        error_strerror( ret, buf, 1024 );
#endif
        printf( " failed\n  !  x509write_crt_set_subject_key_identifier returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    printf( " ok\n" );

    printf( "  . Adding the Authority Key Identifier ..." );
    fflush( stdout );

    ret = x509write_crt_set_authority_key_identifier( &crt );
    if( ret != 0 )
    {
#ifdef POLARSSL_ERROR_C
        error_strerror( ret, buf, 1024 );
#endif
        printf( " failed\n  !  x509write_crt_set_authority_key_identifier returned -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    printf( " ok\n" );

    if( opt.key_usage )
    {
        printf( "  . Adding the Key Usage extension ..." );
        fflush( stdout );

        ret = x509write_crt_set_key_usage( &crt, opt.key_usage );
        if( ret != 0 )
        {
#ifdef POLARSSL_ERROR_C
            error_strerror( ret, buf, 1024 );
#endif
            printf( " failed\n  !  x509write_crt_set_key_usage returned -0x%02x - %s\n\n", -ret, buf );
            goto exit;
        }

        printf( " ok\n" );
    }

    if( opt.ns_cert_type )
    {
        printf( "  . Adding the NS Cert Type extension ..." );
        fflush( stdout );

        ret = x509write_crt_set_ns_cert_type( &crt, opt.ns_cert_type );
        if( ret != 0 )
        {
#ifdef POLARSSL_ERROR_C
            error_strerror( ret, buf, 1024 );
#endif
            printf( " failed\n  !  x509write_crt_set_ns_cert_type returned -0x%02x - %s\n\n", -ret, buf );
            goto exit;
        }

        printf( " ok\n" );
    }

    /*
     * 1.2. Writing the request
     */
    printf( "  . Writing the certificate..." );
    fflush( stdout );

    if( ( ret = write_certificate( &crt, opt.output_file ) ) != 0 )
    {
#ifdef POLARSSL_ERROR_C
        error_strerror( ret, buf, 1024 );
#endif
        printf( " failed\n  !  write_certifcate -0x%02x - %s\n\n", -ret, buf );
        goto exit;
    }

    printf( " ok\n" );

exit:
    x509write_crt_free( &crt );
    rsa_free( &subject_rsa );
    rsa_free( &issuer_rsa );
    mpi_free( &serial );

#if defined(_WIN32)
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* POLARSSL_BIGNUM_C && POLARSSL_RSA_C &&
          POLARSSet_serial_X509_WRITE_C && POLARSSL_FS_IO */
