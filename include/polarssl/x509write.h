/**
 * \file x509write.h
 *
 * \brief X509 buffer writing functionality
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
#ifndef POLARSSL_X509_WRITE_H
#define POLARSSL_X509_WRITE_H

#include "config.h"

#include "x509.h"

/**
 * \addtogroup x509_module
 * \{
 */

/**
 * \name X509 Write Error codes
 * \{
 */
#define POLARSSL_ERR_X509WRITE_UNKNOWN_OID                -0x5F80  /**< Requested OID is unknown. */
#define POLARSSL_ERR_X509WRITE_BAD_INPUT_DATA             -0x5F00  /**< Failed to allocate memory. */
#define POLARSSL_ERR_X509WRITE_MALLOC_FAILED              -0x5E80  /**< Failed to allocate memory. */
/* \} name */
/* \} addtogroup x509_module */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup x509_module
 * \{
 */

/**
 * \name Structures for writing X.509 CSRs (Certificate Signing Request) 
 * \{
 */

/**
 * Container for CSR named objects
 */
typedef struct _x509_req_name
{
    char oid[128];
    char name[128];

    struct _x509_req_name *next;
}
x509_req_name;

/**
 * Container for a CSR
 */
typedef struct _x509_csr
{
    rsa_context *rsa;
    x509_req_name *subject;
    md_type_t md_alg;
    asn1_named_data *extensions;
}
x509_csr;

/* \} name */
/* \} addtogroup x509_module */

/**
 * \brief           Initialize a CSR context
 *
 * \param ctx       CSR context to initialize
 */
void x509write_csr_init( x509_csr *ctx );

/**
 * \brief           Set the subject name for a CSR
 *                  Subject names should contain a comma-separated list
 *                  of OID types and values:
 *                  e.g. "C=NL,O=Offspark,CN=PolarSSL Server 1"
 *
 * \param ctx           CSR context to use
 * \param subject_name  subject name to set
 *
 * \return          0 if subject name was parsed successfully, or
 *                  a specific error code
 */
int x509write_csr_set_subject_name( x509_csr *ctx, char *subject_name );

/**
 * \brief           Set the RSA key for a CSR (public key will be included,
 *                  private key used to sign the CSR when writing it)
 *
 * \param ctx       CSR context to use
 * \param rsa       RSA key to include
 */
void x509write_csr_set_rsa_key( x509_csr *ctx, rsa_context *rsa );

/**
 * \brief           Set the MD algorithm to use for the signature
 *                  (e.g. POLARSSL_MD_SHA1)
 *
 * \param ctx       CSR context to use
 * \param md_alg    MD algorithm to use
 */
void x509write_csr_set_md_alg( x509_csr *ctx, md_type_t md_alg );

/**
 * \brief           Set the Key Usage Extension flags
 *                  (e.g. KU_DIGITAL_SIGNATURE | KU_KEY_CERT_SIGN)
 *
 * \param ctx       CSR context to use
 * \param key_usage key usage flags to set
 *
 * \return          0 if successful, or POLARSSL_ERR_X509WRITE_MALLOC_FAILED
 */
int x509write_csr_set_key_usage( x509_csr *ctx, unsigned char key_usage );

/**
 * \brief           Set the Netscape Cert Type flags
 *                  (e.g. NS_CERT_TYPE_SSL_CLIENT | NS_CERT_TYPE_EMAIL)
 *
 * \param ctx           CSR context to use
 * \param ns_cert_type  Netscape Cert Type flags to set
 *
 * \return          0 if successful, or POLARSSL_ERR_X509WRITE_MALLOC_FAILED
 */
int x509write_csr_set_ns_cert_type( x509_csr *ctx, unsigned char ns_cert_type );

/**
 * \brief           Generic function to add to or replace an extension in the CSR
 *
 * \param ctx       CSR context to use
 * \param oid       OID of the extension
 * \param oid_len   length of the OID
 * \param val       value of the extension OCTET STRING
 * \param val_len   length of the value data
 *
 * \return          0 if successful, or a POLARSSL_ERR_X509WRITE_MALLOC_FAILED
 */
int x509write_csr_set_extension( x509_csr *ctx,
                                 const char *oid, size_t oid_len,
                                 const unsigned char *val, size_t val_len );

/**
 * \brief           Free the contents of a CSR context
 *
 * \param ctx       CSR context to free
 */
void x509write_csr_free( x509_csr *ctx );

/**
 * \brief           Write a RSA public key to a PKCS#1 DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param rsa       RSA to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int x509write_pubkey_der( rsa_context *rsa, unsigned char *buf, size_t size );

/**
 * \brief           Write a RSA key to a PKCS#1 DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param rsa       RSA to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int x509write_key_der( rsa_context *rsa, unsigned char *buf, size_t size );

/**
 * \brief           Write a CSR (Certificate Signing Request) to a
 *                  DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       CSR to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int x509write_csr_der( x509_csr *ctx, unsigned char *buf, size_t size );

#if defined(POLARSSL_BASE64_C)
/**
 * \brief           Write a RSA public key to a PKCS#1 PEM string
 *
 * \param rsa       RSA to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 successful, or a specific error code
 */
int x509write_pubkey_pem( rsa_context *rsa, unsigned char *buf, size_t size );

/**
 * \brief           Write a RSA key to a PKCS#1 PEM string
 *
 * \param rsa       RSA to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 successful, or a specific error code
 */
int x509write_key_pem( rsa_context *rsa, unsigned char *buf, size_t size );

/**
 * \brief           Write a CSR (Certificate Signing Request) to a
 *                  PEM string
 *
 * \param ctx       CSR to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 successful, or a specific error code
 */
int x509write_csr_pem( x509_csr *ctx, unsigned char *buf, size_t size );
#endif /* POLARSSL_BASE64_C */

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_X509_WRITE_H */
