/**
 * \file x509.h
 *
 * \brief X.509 certificate and private key decoding
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
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
#ifndef POLARSSL_X509_H
#define POLARSSL_X509_H

#include "polarssl/rsa.h"
#include "polarssl/dhm.h"

/** 
 * @addtogroup x509_module
 * @{ 
 */
 
/**
 * @name ASN1 Error codes
 * These error codes are OR'ed to X509 error codes for
 * higher error granularity. 
 * ASN1 is a standard to specify data structures.
 * @{
 */
#define POLARSSL_ERR_ASN1_OUT_OF_DATA                      0x0014   /**< Out of data when parsing an ASN1 data structure. */
#define POLARSSL_ERR_ASN1_UNEXPECTED_TAG                   0x0016   /**< ASN1 tag was of an unexpected value. */
#define POLARSSL_ERR_ASN1_INVALID_LENGTH                   0x0018   /**< Error when trying to determine the length or invalid length. */
#define POLARSSL_ERR_ASN1_LENGTH_MISMATCH                  0x001A   /**< Actual length differs from expected length. */
#define POLARSSL_ERR_ASN1_INVALID_DATA                     0x001C   /**< Data is invalid. (not used) */
/* @} name */

/** 
 * @name X509 Error codes
 * @{
 */
#define POLARSSL_ERR_X509_FEATURE_UNAVAILABLE              -0x0020  /**< Unavailable feature, e.g. RSA hashing/encryption combination. */
#define POLARSSL_ERR_X509_CERT_INVALID_PEM                 -0x0040  /**< The PEM-encoded certificate contains invalid elements, e.g. invalid character. */ 
#define POLARSSL_ERR_X509_CERT_INVALID_FORMAT              -0x0060  /**< The certificate format is invalid, e.g. different type expected. */
#define POLARSSL_ERR_X509_CERT_INVALID_VERSION             -0x0080  /**< The certificate version element is invalid. */
#define POLARSSL_ERR_X509_CERT_INVALID_SERIAL              -0x00A0  /**< The serial tag or value is invalid. */
#define POLARSSL_ERR_X509_CERT_INVALID_ALG                 -0x00C0  /**< The algorithm tag or value is invalid. */
#define POLARSSL_ERR_X509_CERT_INVALID_NAME                -0x00E0  /**< The name tag or value is invalid. */
#define POLARSSL_ERR_X509_CERT_INVALID_DATE                -0x0100  /**< The date tag or value is invalid. */
#define POLARSSL_ERR_X509_CERT_INVALID_PUBKEY              -0x0120  /**< The pubkey tag or value is invalid (only RSA is supported). */
#define POLARSSL_ERR_X509_CERT_INVALID_SIGNATURE           -0x0140  /**< The signature tag or value invalid. */
#define POLARSSL_ERR_X509_CERT_INVALID_EXTENSIONS          -0x0160  /**< The extension tag or value is invalid. */
#define POLARSSL_ERR_X509_CERT_UNKNOWN_VERSION             -0x0180  /**< Certificate or CRL has an unsupported version number. */
#define POLARSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG             -0x01A0  /**< Signature algorithm (oid) is unsupported. */
#define POLARSSL_ERR_X509_CERT_UNKNOWN_PK_ALG              -0x01C0  /**< Public key algorithm is unsupported (only RSA is supported). */
#define POLARSSL_ERR_X509_CERT_SIG_MISMATCH                -0x01E0  /**< Certificate signature algorithms do not match. (see \c ::x509_cert sig_oid) */
#define POLARSSL_ERR_X509_CERT_VERIFY_FAILED               -0x0200  /**< Certificate verification failed, e.g. CRL, CA or signature check failed. */
#define POLARSSL_ERR_X509_KEY_INVALID_PEM                  -0x0220  /**< PEM key string is not as expected. */
#define POLARSSL_ERR_X509_KEY_INVALID_VERSION              -0x0240  /**< Unsupported RSA key version */
#define POLARSSL_ERR_X509_KEY_INVALID_FORMAT               -0x0260  /**< Invalid RSA key tag or value. */
#define POLARSSL_ERR_X509_KEY_INVALID_ENC_IV               -0x0280  /**< RSA IV is not in hex-format. */
#define POLARSSL_ERR_X509_KEY_UNKNOWN_ENC_ALG              -0x02A0  /**< Unsupported key encryption algorithm. */
#define POLARSSL_ERR_X509_KEY_PASSWORD_REQUIRED            -0x02C0  /**< Private key password can't be empty. */
#define POLARSSL_ERR_X509_KEY_PASSWORD_MISMATCH            -0x02E0  /**< Given private key password does not allow for correct decryption. */
#define POLARSSL_ERR_X509_POINT_ERROR                      -0x0300  /**< Not used. */
#define POLARSSL_ERR_X509_VALUE_TO_LENGTH                  -0x0320  /**< Not used. */
/* @} name */


/**
 * @name X509 Verify codes
 * @{
 */
#define BADCERT_EXPIRED                 1   /**< The certificate validity has expired. */
#define BADCERT_REVOKED                 2   /**< The certificate has been revoked (is on a CRL). */
#define BADCERT_CN_MISMATCH             4   /**< The certificate Common Name (CN) does not match with the expected CN. */
#define BADCERT_NOT_TRUSTED             8   /**< The certificate is not correctly signed by the trusted CA. */
#define BADCRL_NOT_TRUSTED             16   /**< CRL is not correctly signed by the trusted CA. */
#define BADCRL_EXPIRED                 32   /**< CRL is expired. */
/* @} name */


/**
 * @name DER constants
 * These constants comply with DER encoded the ANS1 type tags.
 * DER encoding uses hexadecimal representation.
 * An example DER sequence is:\n
 * - 0x02 -- tag indicating INTEGER
 * - 0x01 -- length in octets
 * - 0x05 -- value
 * Such sequences are typically read into \c ::x509_buf.
 * @{
 */
#define ASN1_BOOLEAN                 0x01
#define ASN1_INTEGER                 0x02
#define ASN1_BIT_STRING              0x03
#define ASN1_OCTET_STRING            0x04
#define ASN1_NULL                    0x05
#define ASN1_OID                     0x06
#define ASN1_UTF8_STRING             0x0C
#define ASN1_SEQUENCE                0x10
#define ASN1_SET                     0x11
#define ASN1_PRINTABLE_STRING        0x13
#define ASN1_T61_STRING              0x14
#define ASN1_IA5_STRING              0x16
#define ASN1_UTC_TIME                0x17
#define ASN1_GENERALIZED_TIME        0x18
#define ASN1_UNIVERSAL_STRING        0x1C
#define ASN1_BMP_STRING              0x1E
#define ASN1_PRIMITIVE               0x00
#define ASN1_CONSTRUCTED             0x20
#define ASN1_CONTEXT_SPECIFIC        0x80
/* @} name */
/* @} addtogroup x509_module */

/*
 * various object identifiers
 */
#define X520_COMMON_NAME                3
#define X520_COUNTRY                    6
#define X520_LOCALITY                   7
#define X520_STATE                      8
#define X520_ORGANIZATION              10
#define X520_ORG_UNIT                  11
#define PKCS9_EMAIL                     1

#define X509_OUTPUT_DER              0x01
#define X509_OUTPUT_PEM              0x02
#define PEM_LINE_LENGTH                72
#define X509_ISSUER                  0x01
#define X509_SUBJECT                 0x02

#define OID_X520                "\x55\x04"
#define OID_CN                  "\x55\x04\x03"
#define OID_PKCS1               "\x2A\x86\x48\x86\xF7\x0D\x01\x01"
#define OID_PKCS1_RSA           "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"
#define OID_PKCS1_RSA_SHA       "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05"
#define OID_PKCS9               "\x2A\x86\x48\x86\xF7\x0D\x01\x09"
#define OID_PKCS9_EMAIL         "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01"

/** 
 * @addtogroup x509_module
 * @{ */

/**
 * @name Structures for parsing X.509 certificates and CRLs
 * @{
 */
 
/** 
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef struct _x509_buf
{
    int tag;                /**< ASN1 type, e.g. ASN1_UTF8_STRING. */
    int len;                /**< ASN1 length, e.g. in octets. */
    unsigned char *p;       /**< ASN1 data, e.g. in ASCII. */
}
x509_buf;

/**
 * Container for ASN1 named information objects. 
 * It allows for Relative Distinguished Names (e.g. cn=polarssl,ou=code,etc.).
 */
typedef struct _x509_name
{
    x509_buf oid;               /**< The object identifier. */
    x509_buf val;               /**< The named value. */
    struct _x509_name *next;    /**< The next named information object. */
}
x509_name;

/** Container for date and time (precision in seconds). */
typedef struct _x509_time
{
    int year, mon, day;         /**< Date. */
    int hour, min, sec;         /**< Time. */
}
x509_time;

/** 
 * Container for an X.509 certificate. The certificate may be chained.
 */
typedef struct _x509_cert
{
    x509_buf raw;               /**< The raw certificate data (DER). */
    x509_buf tbs;               /**< The raw certificate body (DER). The part that is To Be Signed. */

    int version;                /**< The X.509 version. (0=v1, 1=v2, 2=v3) */
    x509_buf serial;            /**< Unique id for certificate issued by a specific CA. */
    x509_buf sig_oid1;          /**< Signature algorithm, e.g. sha1RSA */

    x509_buf issuer_raw;        /**< The raw issuer data (DER). Used for quick comparison. */
    x509_buf subject_raw;       /**< The raw subject data (DER). Used for quick comparison. */

    x509_name issuer;           /**< The parsed issuer data (named information object). */
    x509_name subject;          /**< The parsed subject data (named information object). */

    x509_time valid_from;       /**< Start time of certificate validity. */
    x509_time valid_to;         /**< End time of certificate validity. */

    x509_buf pk_oid;            /**< Subject public key info. Includes the public key algorithm and the key itself. */
    rsa_context rsa;            /**< Container for the RSA context. Only RSA is supported for public keys at this time. */

    x509_buf issuer_id;         /**< Optional X.509 v2/v3 issuer unique identifier. */
    x509_buf subject_id;        /**< Optional X.509 v2/v3 subject unique identifier. */
    x509_buf v3_ext;            /**< Optional X.509 v3 extensions. Only Basic Contraints are supported at this time. */

    int ca_istrue;              /**< Optional Basic Constraint extension value: 1 if this certificate belongs to a CA, 0 otherwise. */
    int max_pathlen;            /**< Optional Basic Constraint extension value: The maximum path length to the root certificate. */

    x509_buf sig_oid2;          /**< Signature algorithm. Must match sig_oid1. */
    x509_buf sig;               /**< Signature: hash of the tbs part signed with the private key. */
    int sig_alg;                /**< Internal representation of the signature algorithm, e.g. SIG_RSA_MD2 */

    struct _x509_cert *next;    /**< Next certificate in the CA-chain. */ 
}
x509_cert;

/** 
 * Certificate revocation list entry. 
 * Contains the CA-specific serial numbers and revocation dates.
 */
typedef struct _x509_crl_entry
{
    x509_buf raw;

    x509_buf serial;

    x509_time revocation_date;

    x509_buf entry_ext;

    struct _x509_crl_entry *next;
}
x509_crl_entry;

/** 
 * Certificate revocation list structure. 
 * Every CRL may have multiple entries.
 */
typedef struct _x509_crl
{
    x509_buf raw;           /**< The raw certificate data (DER). */
    x509_buf tbs;           /**< The raw certificate body (DER). The part that is To Be Signed. */

    int version;
    x509_buf sig_oid1;

    x509_buf issuer_raw;    /**< The raw issuer data (DER). */

    x509_name issuer;       /**< The parsed issuer data (named information object). */

    x509_time this_update;  
    x509_time next_update;

    x509_crl_entry entry;   /**< The CRL entries containing the certificate revocation times for this CA. */

    x509_buf crl_ext;

    x509_buf sig_oid2;
    x509_buf sig;
    int sig_alg;

    struct _x509_crl *next; 
}
x509_crl;
/** @} name Structures for parsing X.509 certificates and CRLs */
/** @} addtogroup x509_module */

/**
 * @name Structures for writing X.509 certificates.
 * XvP: commented out as they are not used.
 * - <tt>typedef struct _x509_node x509_node;</tt>
 * - <tt>typedef struct _x509_raw x509_raw;</tt>
 */
/*
typedef struct _x509_node
{
    unsigned char *data;
    unsigned char *p;
    unsigned char *end;

    size_t len;
}
x509_node;

typedef struct _x509_raw
{
    x509_node raw;
    x509_node tbs;

    x509_node version;
    x509_node serial;
    x509_node tbs_signalg;
    x509_node issuer;
    x509_node validity;
    x509_node subject;
    x509_node subpubkey;

    x509_node signalg;
    x509_node sign;
}
x509_raw;
*/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name Functions to read in DHM parameters, a certificate, CRL or private RSA key
 * @{
 */

/** @ingroup x509_module */
/**
 * \brief          Parse one or more certificates and add them
 *                 to the chained list
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the certificate data
 * \param buflen   size of the buffer
 *
 * \return         0 if successful, or a specific X509 error code
 */
int x509parse_crt( x509_cert *chain, const unsigned char *buf, int buflen );

/** @ingroup x509_module */
/**
 * \brief          Load one or more certificates and add them
 *                 to the chained list
 *
 * \param chain    points to the start of the chain
 * \param path     filename to read the certificates from
 *
 * \return         0 if successful, or a specific X509 error code
 */
int x509parse_crtfile( x509_cert *chain, const char *path );

/** @ingroup x509_module */
/**
 * \brief          Parse one or more CRLs and add them
 *                 to the chained list
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the CRL data
 * \param buflen   size of the buffer
 *
 * \return         0 if successful, or a specific X509 error code
 */
int x509parse_crl( x509_crl *chain, const unsigned char *buf, int buflen );

/** @ingroup x509_module */
/**
 * \brief          Load one or more CRLs and add them
 *                 to the chained list
 *
 * \param chain    points to the start of the chain
 * \param path     filename to read the CRLs from
 *
 * \return         0 if successful, or a specific X509 error code
 */
int x509parse_crlfile( x509_crl *chain, const char *path );

/** @ingroup x509_module */
/**
 * \brief          Parse a private RSA key
 *
 * \param rsa      RSA context to be initialized
 * \param key      input buffer
 * \param keylen   size of the buffer
 * \param pwd      password for decryption (optional)
 * \param pwdlen   size of the password
 *
 * \return         0 if successful, or a specific X509 error code
 */
int x509parse_key( rsa_context *rsa,
                   const unsigned char *key, int keylen,
                   const unsigned char *pwd, int pwdlen );

/** @ingroup x509_module */
/**
 * \brief          Load and parse a private RSA key
 *
 * \param rsa      RSA context to be initialized
 * \param path     filename to read the private key from
 * \param password password to decrypt the file (can be NULL)
 *
 * \return         0 if successful, or a specific X509 error code
 */
int x509parse_keyfile( rsa_context *rsa, const char *path,
                       const char *password );

/** @ingroup x509_module */
/**
 * \brief          Parse DHM parameters
 *
 * \param dhm      DHM context to be initialized
 * \param dhmin    input buffer
 * \param dhminlen size of the buffer
 *
 * \return         0 if successful, or a specific X509 error code
 */
int x509parse_dhm( dhm_context *dhm, const unsigned char *dhmin, int dhminlen );

/** @ingroup x509_module */
/**
 * \brief          Load and parse DHM parameters
 *
 * \param dhm      DHM context to be initialized
 * \param path     filename to read the DHM Parameters from
 *
 * \return         0 if successful, or a specific X509 error code
 */
int x509parse_dhmfile( dhm_context *rsa, const char *path );

/** @} name Functions to read in DHM parameters, a certificate, CRL or private RSA key */



/**
 * \brief          Store the certificate DN in printable form into buf;
 *                 no more than size characters will be written.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param dn       The X509 name to represent
 *
 * \return         The amount of data written to the buffer, or -1 in
 *                 case of an error.
 */
int x509parse_dn_gets( char *buf, size_t size, const x509_name *dn );

/**
 * \brief          Returns an informational string about the
 *                 certificate.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param prefix   A line prefix
 * \param crt      The X509 certificate to represent
 *
 * \return         The amount of data written to the buffer, or -1 in
 *                 case of an error.
 */
int x509parse_cert_info( char *buf, size_t size, const char *prefix,
                         const x509_cert *crt );

/**
 * \brief          Returns an informational string about the
 *                 CRL.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param prefix   A line prefix
 * \param crl      The X509 CRL to represent
 *
 * \return         The amount of data written to the buffer, or -1 in
 *                 case of an error.
 */
int x509parse_crl_info( char *buf, size_t size, const char *prefix,
                        const x509_crl *crl );

/**
 * \brief          Check a given x509_time against the system time and check
 *                 if it is valid.
 *
 * \param time     x509_time to check
 *
 * \return         Return 0 if the x509_time is still valid,
 *                 or 1 otherwise.
 */
int x509parse_time_expired( const x509_time *time );

/**
 * @name Functions to verify a certificate
 * @{
 */
/** @ingroup x509_module */
/**
 * \brief          Verify the certificate signature
 *
 * \param crt      a certificate to be verified
 * \param trust_ca the trusted CA chain
 * \param ca_crl   the CRL chain for trusted CA's
 * \param cn       expected Common Name (can be set to
 *                 NULL if the CN must not be verified)
 * \param flags    result of the verification
 * \param f_vrfy   verification function
 * \param p_vrfy   verification parameter
 *
 * \return         0 if successful or POLARSSL_ERR_X509_SIG_VERIFY_FAILED,
 *                 in which case *flags will have one or more of
 *                 the following values set:
 *                      BADCERT_EXPIRED --
 *                      BADCERT_REVOKED --
 *                      BADCERT_CN_MISMATCH --
 *                      BADCERT_NOT_TRUSTED
 *
 * \note           TODO: add two arguments, depth and crl
 */
int x509parse_verify( x509_cert *crt,
                      x509_cert *trust_ca,
                      x509_crl *ca_crl,
                      const char *cn, int *flags,
                      int (*f_vrfy)(void *, x509_cert *, int, int),
                      void *p_vrfy );

/** @} name Functions to verify a certificate */



/**
 * @name Functions to clear a certificate, CRL or private RSA key 
 * @{
 */
/** @ingroup x509_module */
/**
 * \brief          Unallocate all certificate data
 *
 * \param crt      Certificate chain to free
 */
void x509_free( x509_cert *crt );

/** @ingroup x509_module */
/**
 * \brief          Unallocate all CRL data
 *
 * \param crl      CRL chain to free
 */
void x509_crl_free( x509_crl *crl );

/** @} name Functions to clear a certificate, CRL or private RSA key */


/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int x509_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* x509.h */
