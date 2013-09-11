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
 * Container for a CSR
 */
typedef struct _x509write_csr
{
    pk_context *key;
    asn1_named_data *subject;
    md_type_t md_alg;
    asn1_named_data *extensions;
}
x509write_csr;

#define X509_CRT_VERSION_1              0
#define X509_CRT_VERSION_2              1
#define X509_CRT_VERSION_3              2

#define X509_RFC5280_MAX_SERIAL_LEN 32
#define X509_RFC5280_UTC_TIME_LEN   15

/**
 * Container for writing a certificate (CRT)
 */
typedef struct _x509write_cert
{
    int version;
    mpi serial;
    rsa_context *subject_key;
    rsa_context *issuer_key;
    asn1_named_data *subject;
    asn1_named_data *issuer;
    md_type_t md_alg;
    char not_before[X509_RFC5280_UTC_TIME_LEN + 1];
    char not_after[X509_RFC5280_UTC_TIME_LEN + 1];
    asn1_named_data *extensions;
}
x509write_cert;

/* \} addtogroup x509_module */

/**
 * \brief           Initialize a CSR context
 *
 * \param ctx       CSR context to initialize
 */
void x509write_csr_init( x509write_csr *ctx );

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
int x509write_csr_set_subject_name( x509write_csr *ctx, char *subject_name );

/**
 * \brief           Set the key for a CSR (public key will be included,
 *                  private key used to sign the CSR when writing it)
 *
 * \param ctx       CSR context to use
 * \param key       Asymetric key to include
 */
void x509write_csr_set_key( x509write_csr *ctx, pk_context *key );

/**
 * \brief           Set the MD algorithm to use for the signature
 *                  (e.g. POLARSSL_MD_SHA1)
 *
 * \param ctx       CSR context to use
 * \param md_ald    MD algorithm to use
 */
void x509write_csr_set_md_alg( x509write_csr *ctx, md_type_t md_alg );

/**
 * \brief           Set the Key Usage Extension flags
 *                  (e.g. KU_DIGITAL_SIGNATURE | KU_KEY_CERT_SIGN)
 *
 * \param ctx       CSR context to use
 * \param key_usage key usage flags to set
 *
 * \return          0 if successful, or POLARSSL_ERR_X509WRITE_MALLOC_FAILED
 */
int x509write_csr_set_key_usage( x509write_csr *ctx, unsigned char key_usage );

/**
 * \brief           Set the Netscape Cert Type flags
 *                  (e.g. NS_CERT_TYPE_SSL_CLIENT | NS_CERT_TYPE_EMAIL)
 *
 * \param ctx           CSR context to use
 * \param ns_cert_type  Netscape Cert Type flags to set
 *
 * \return          0 if successful, or POLARSSL_ERR_X509WRITE_MALLOC_FAILED
 */
int x509write_csr_set_ns_cert_type( x509write_csr *ctx,
                                    unsigned char ns_cert_type );

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
int x509write_csr_set_extension( x509write_csr *ctx,
                                 const char *oid, size_t oid_len,
                                 const unsigned char *val, size_t val_len );

/**
 * \brief           Free the contents of a CSR context
 *
 * \param ctx       CSR context to free
 */
void x509write_csr_free( x509write_csr *ctx );

/**
 * \brief           Initialize a CRT writing context
 *
 * \param ctx       CRT context to initialize
 */
void x509write_crt_init( x509write_cert *ctx );

/**
 * \brief           Set the verion for a Certificate
 *                  Default: X509_CRT_VERSION_3
 *
 * \param ctx       CRT context to use
 * \param version   version to set (X509_CRT_VERSION_1, X509_CRT_VERSION_2 or
 *                                  X509_CRT_VERSION_3)
 */
void x509write_crt_set_version( x509write_cert *ctx, int version );

/**
 * \brief           Set the serial number for a Certificate.
 *
 * \param ctx       CRT context to use
 * \param serial    serial number to set
 *
 * \return          0 if successful
 */
int x509write_crt_set_serial( x509write_cert *ctx, const mpi *serial );

/**
 * \brief           Set the validity period for a Certificate
 *                  Timestamps should be in string format for UTC timezone
 *                  i.e. "YYYYMMDDhhmmss"
 *                  e.g. "20131231235959" for December 31st 2013
 *                       at 23:59:59
 *
 * \param ctx       CRT context to use
 * \param not_before    not_before timestamp
 * \param not_after     not_after timestamp
 *
 * \return          0 if timestamp was parsed successfully, or
 *                  a specific error code
 */
int x509write_crt_set_validity( x509write_cert *ctx, char *not_before,
                                char *not_after );

/**
 * \brief           Set the issuer name for a Certificate
 *                  Issuer names should contain a comma-separated list
 *                  of OID types and values:
 *                  e.g. "C=NL,O=Offspark,CN=PolarSSL CA"
 *
 * \param ctx           CRT context to use
 * \param issuer_name   issuer name to set
 *
 * \return          0 if issuer name was parsed successfully, or
 *                  a specific error code
 */
int x509write_crt_set_issuer_name( x509write_cert *ctx, char *issuer_name );

/**
 * \brief           Set the subject name for a Certificate
 *                  Subject names should contain a comma-separated list
 *                  of OID types and values:
 *                  e.g. "C=NL,O=Offspark,CN=PolarSSL Server 1"
 *
 * \param ctx           CRT context to use
 * \param subject_name  subject name to set
 *
 * \return          0 if subject name was parsed successfully, or
 *                  a specific error code
 */
int x509write_crt_set_subject_name( x509write_cert *ctx, char *subject_name );

/**
 * \brief           Set the subject public key for the certificate
 *
 * \param ctx       CRT context to use
 * \param rsa       RSA public key to include
 */
void x509write_crt_set_subject_key( x509write_cert *ctx, rsa_context *rsa );

/**
 * \brief           Set the issuer key used for signing the certificate
 *
 * \param ctx       CRT context to use
 * \param rsa       RSA key to sign with
 */
void x509write_crt_set_issuer_key( x509write_cert *ctx, rsa_context *rsa );

/**
 * \brief           Set the MD algorithm to use for the signature
 *                  (e.g. POLARSSL_MD_SHA1)
 *
 * \param ctx       CRT context to use
 * \param md_ald    MD algorithm to use
 */
void x509write_crt_set_md_alg( x509write_cert *ctx, md_type_t md_alg );

/**
 * \brief           Generic function to add to or replace an extension in the
 *                  CRT
 *
 * \param ctx       CRT context to use
 * \param oid       OID of the extension
 * \param oid_len   length of the OID
 * \param critical  if the extension is critical (per the RFC's definition)
 * \param val       value of the extension OCTET STRING
 * \param val_len   length of the value data
 *
 * \return          0 if successful, or a POLARSSL_ERR_X509WRITE_MALLOC_FAILED
 */
int x509write_crt_set_extension( x509write_cert *ctx,
                                 const char *oid, size_t oid_len,
                                 int critical,
                                 const unsigned char *val, size_t val_len );

/**
 * \brief           Set the basicConstraints extension for a CRT
 *
 * \param ctx       CRT context to use
 * \param is_ca     is this a CA certificate
 * \param max_pathlen   maximum length of certificate chains below this
 *                      certificate (only for CA certificates, -1 is
 *                      inlimited)
 *
 * \return          0 if successful, or a POLARSSL_ERR_X509WRITE_MALLOC_FAILED
 */
int x509write_crt_set_basic_constraints( x509write_cert *ctx,
                                         int is_ca, int max_pathlen );

/**
 * \brief           Set the subjectKeyIdentifier extension for a CRT
 *                  Requires that x509write_crt_set_subject_key() has been
 *                  called before
 *
 * \param ctx       CRT context to use
 *
 * \return          0 if successful, or a POLARSSL_ERR_X509WRITE_MALLOC_FAILED
 */
int x509write_crt_set_subject_key_identifier( x509write_cert *ctx );

/**
 * \brief           Set the authorityKeyIdentifier extension for a CRT
 *                  Requires that x509write_crt_set_issuer_key() has been
 *                  called before
 *
 * \param ctx       CRT context to use
 *
 * \return          0 if successful, or a POLARSSL_ERR_X509WRITE_MALLOC_FAILED
 */
int x509write_crt_set_authority_key_identifier( x509write_cert *ctx );

/**
 * \brief           Set the Key Usage Extension flags
 *                  (e.g. KU_DIGITAL_SIGNATURE | KU_KEY_CERT_SIGN)
 *
 * \param ctx       CRT context to use
 * \param key_usage key usage flags to set
 *
 * \return          0 if successful, or POLARSSL_ERR_X509WRITE_MALLOC_FAILED
 */
int x509write_crt_set_key_usage( x509write_cert *ctx, unsigned char key_usage );

/**
 * \brief           Set the Netscape Cert Type flags
 *                  (e.g. NS_CERT_TYPE_SSL_CLIENT | NS_CERT_TYPE_EMAIL)
 *
 * \param ctx           CRT context to use
 * \param ns_cert_type  Netscape Cert Type flags to set
 *
 * \return          0 if successful, or POLARSSL_ERR_X509WRITE_MALLOC_FAILED
 */
int x509write_crt_set_ns_cert_type( x509write_cert *ctx,
                                    unsigned char ns_cert_type );

/**
 * \brief           Free the contents of a CRT write context
 *
 * \param ctx       CRT context to free
 */
void x509write_crt_free( x509write_cert *ctx );

/**
 * \brief           Write a built up certificate to a X509 DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param crt       certificate to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int x509write_crt_der( x509write_cert *ctx, unsigned char *buf, size_t size );

/**
 * \brief           Write a public key to a DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param key       public key to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int x509write_pubkey_der( pk_context *key, unsigned char *buf, size_t size );

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
 * \param rsa       CSR to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 * \param f_rng     RNG function (for signature, see note)
 * \param p_rng     RNG parameter
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 *
 * \note            f_rng may be NULL if RSA is used for signature and the
 *                  signature is made offline (otherwise f_rng is desirable
 *                  for countermeasures against timing attacks).
 *                  ECDSA signatures always require a non-NULL f_rng.
 */
int x509write_csr_der( x509write_csr *ctx, unsigned char *buf, size_t size,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng );

#if defined(POLARSSL_BASE64_C)
/**
 * \brief           Write a built up certificate to a X509 PEM string
 *
 * \param crt       certificate to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 successful, or a specific error code
 */
int x509write_crt_pem( x509write_cert *ctx, unsigned char *buf, size_t size );

/**
 * \brief           Write a public key to a PEM string
 *
 * \param key       public key to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 successful, or a specific error code
 */
int x509write_pubkey_pem( pk_context *key, unsigned char *buf, size_t size );

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
 * \param rsa       CSR to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 * \param f_rng     RNG function (for signature, see note)
 * \param p_rng     RNG parameter
 *
 * \return          0 successful, or a specific error code
 *
 * \note            f_rng may be NULL if RSA is used for signature and the
 *                  signature is made offline (otherwise f_rng is desirable
 *                  for couermeasures against timing attacks).
 *                  ECDSA signatures always require a non-NULL f_rng.
 */
int x509write_csr_pem( x509write_csr *ctx, unsigned char *buf, size_t size,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng );
#endif /* POLARSSL_BASE64_C */

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_X509_WRITE_H */
