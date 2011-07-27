/**
 * \file ssl.h
 *
 * \brief SSL/TLS functions.
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
#ifndef POLARSSL_SSL_H
#define POLARSSL_SSL_H

#include <time.h>

#include "polarssl/net.h"
#include "polarssl/dhm.h"
#include "polarssl/rsa.h"
#include "polarssl/md5.h"
#include "polarssl/sha1.h"
#include "polarssl/x509.h"
#include "polarssl/config.h"

#if defined(POLARSSL_PKCS11_C)
#include "polarssl/pkcs11.h"
#endif

#if defined(_MSC_VER) && !defined(inline)
#define inline _inline
#else
#if defined(__ARMCC_VERSION) && !defined(inline)
#define inline __inline
#endif /* __ARMCC_VERSION */
#endif /*_MSC_VER */

/*
 * SSL Error codes
 */
#define POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE               -0x7080  /**< The requested feature is not available. */
#define POLARSSL_ERR_SSL_BAD_INPUT_DATA                    -0x7100  /**< Bad input parameters to function. */
#define POLARSSL_ERR_SSL_INVALID_MAC                       -0x7180  /**< Verification of the message MAC failed. */
#define POLARSSL_ERR_SSL_INVALID_RECORD                    -0x7200  /**< An invalid SSL record was received. */
#define POLARSSL_ERR_SSL_CONN_EOF                          -0x7280  /**< The connection indicated an EOF. */
#define POLARSSL_ERR_SSL_UNKNOWN_CIPHER                    -0x7300  /**< An unknown cipher was received. */
#define POLARSSL_ERR_SSL_NO_CIPHER_CHOSEN                  -0x7380  /**< The server has no ciphersuites in common with the client. */
#define POLARSSL_ERR_SSL_NO_SESSION_FOUND                  -0x7400  /**< No session to recover was found. */
#define POLARSSL_ERR_SSL_NO_CLIENT_CERTIFICATE             -0x7480  /**< No client certification received from the client, but required by the authentication mode. */
#define POLARSSL_ERR_SSL_CERTIFICATE_TOO_LARGE             -0x7500  /**< Our own certificate(s) is/are too large to send in an SSL message.*/
#define POLARSSL_ERR_SSL_CERTIFICATE_REQUIRED              -0x7580  /**< The own certificate is not set, but needed by the server. */
#define POLARSSL_ERR_SSL_PRIVATE_KEY_REQUIRED              -0x7600  /**< The own private key is not set, but needed. */
#define POLARSSL_ERR_SSL_CA_CHAIN_REQUIRED                 -0x7680  /**< No CA Chain is set, but required to operate. */
#define POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE                -0x7700  /**< An unexpected message was received from our peer. */
#define POLARSSL_ERR_SSL_FATAL_ALERT_MESSAGE               -0x7780  /**< A fatal alert message was received from our peer. */
#define POLARSSL_ERR_SSL_PEER_VERIFY_FAILED                -0x7800  /**< Verification of our peer failed. */
#define POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY                 -0x7880  /**< The peer notified us that the connection is going to be closed. */
#define POLARSSL_ERR_SSL_BAD_HS_CLIENT_HELLO               -0x7900  /**< Processing of the ClientHello handshake message failed. */
#define POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO               -0x7980  /**< Processing of the ServerHello handshake message failed. */
#define POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE                -0x7A00  /**< Processing of the Certificate handshake message failed. */
#define POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST        -0x7A80  /**< Processing of the CertificateRequest handshake message failed. */
#define POLARSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE        -0x7B00  /**< Processing of the ServerKeyExchange handshake message failed. */
#define POLARSSL_ERR_SSL_BAD_HS_SERVER_HELLO_DONE          -0x7B80  /**< Processing of the ServerHelloDone handshake message failed. */
#define POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE        -0x7C00  /**< Processing of the ClientKeyExchange handshake message failed. */
#define POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_DHM_RP -0x7C80  /**< Processing of the ClientKeyExchange handshake message failed in DHM Read Public. */
#define POLARSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_DHM_CS -0x7D00  /**< Processing of the ClientKeyExchange handshake message failed in DHM Calculate Secret. */
#define POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY         -0x7D80  /**< Processing of the CertificateVerify handshake message failed. */
#define POLARSSL_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC         -0x7E00  /**< Processing of the ChangeCipherSpec handshake message failed. */
#define POLARSSL_ERR_SSL_BAD_HS_FINISHED                   -0x7E80  /**< Processing of the Finished handshake message failed. */

/*
 * Various constants
 */
#define SSL_MAJOR_VERSION_3             3
#define SSL_MINOR_VERSION_0             0   /*!< SSL v3.0 */
#define SSL_MINOR_VERSION_1             1   /*!< TLS v1.0 */
#define SSL_MINOR_VERSION_2             2   /*!< TLS v1.1 */

#define SSL_IS_CLIENT                   0
#define SSL_IS_SERVER                   1
#define SSL_COMPRESS_NULL               0

#define SSL_VERIFY_NONE                 0
#define SSL_VERIFY_OPTIONAL             1
#define SSL_VERIFY_REQUIRED             2

#define SSL_MAX_CONTENT_LEN         16384

/*
 * Allow an extra 512 bytes for the record header
 * and encryption overhead (counter + MAC + padding).
 */
#define SSL_BUFFER_LEN (SSL_MAX_CONTENT_LEN + 512)

/*
 * Supported ciphersuites
 */
#define SSL_RSA_RC4_128_MD5          0x04
#define SSL_RSA_RC4_128_SHA          0x05
#define SSL_RSA_DES_168_SHA          0x0A
#define SSL_EDH_RSA_DES_168_SHA      0x16
#define SSL_RSA_AES_128_SHA          0x2F
#define SSL_EDH_RSA_AES_128_SHA      0x33
#define SSL_RSA_AES_256_SHA          0x35
#define SSL_EDH_RSA_AES_256_SHA      0x39

#define SSL_RSA_CAMELLIA_128_SHA     0x41
#define SSL_EDH_RSA_CAMELLIA_128_SHA 0x45
#define SSL_RSA_CAMELLIA_256_SHA     0x84
#define SSL_EDH_RSA_CAMELLIA_256_SHA 0x88

/*
 * Message, alert and handshake types
 */
#define SSL_MSG_CHANGE_CIPHER_SPEC     20
#define SSL_MSG_ALERT                  21
#define SSL_MSG_HANDSHAKE              22
#define SSL_MSG_APPLICATION_DATA       23

#define SSL_ALERT_LEVEL_WARNING         1
#define SSL_ALERT_LEVEL_FATAL           2

#define SSL_ALERT_MSG_CLOSE_NOTIFY           0
#define SSL_ALERT_MSG_UNEXPECTED_MESSAGE    10
#define SSL_ALERT_MSG_BAD_RECORD_MAC        20
#define SSL_ALERT_MSG_DECRYPTION_FAILED     21
#define SSL_ALERT_MSG_RECORD_OVERFLOW       22
#define SSL_ALERT_MSG_DECOMPRESSION_FAILURE 30
#define SSL_ALERT_MSG_HANDSHAKE_FAILURE     40
#define SSL_ALERT_MSG_NO_CERT               41
#define SSL_ALERT_MSG_BAD_CERT              42
#define SSL_ALERT_MSG_UNSUPPORTED_CERT      43
#define SSL_ALERT_MSG_CERT_REVOKED          44
#define SSL_ALERT_MSG_CERT_EXPIRED          45
#define SSL_ALERT_MSG_CERT_UNKNOWN          46
#define SSL_ALERT_MSG_ILLEGAL_PARAMETER     47
#define SSL_ALERT_MSG_UNKNOWN_CA            48
#define SSL_ALERT_MSG_ACCESS_DENIED         49
#define SSL_ALERT_MSG_DECODE_ERROR          50
#define SSL_ALERT_MSG_DECRYPT_ERROR         51
#define SSL_ALERT_MSG_EXPORT_RESTRICTION    60
#define SSL_ALERT_MSG_PROTOCOL_VERSION      70
#define SSL_ALERT_MSG_INSUFFICIENT_SECURITY 71
#define SSL_ALERT_MSG_INTERNAL_ERROR        80
#define SSL_ALERT_MSG_USER_CANCELED         90
#define SSL_ALERT_MSG_NO_RENEGOTIATION     100

#define SSL_HS_HELLO_REQUEST            0
#define SSL_HS_CLIENT_HELLO             1
#define SSL_HS_SERVER_HELLO             2
#define SSL_HS_CERTIFICATE             11
#define SSL_HS_SERVER_KEY_EXCHANGE     12
#define SSL_HS_CERTIFICATE_REQUEST     13
#define SSL_HS_SERVER_HELLO_DONE       14
#define SSL_HS_CERTIFICATE_VERIFY      15
#define SSL_HS_CLIENT_KEY_EXCHANGE     16
#define SSL_HS_FINISHED                20

/*
 * TLS extensions
 */
#define TLS_EXT_SERVERNAME              0
#define TLS_EXT_SERVERNAME_HOSTNAME     0

/*
 * SSL state machine
 */
typedef enum
{
    SSL_HELLO_REQUEST,
    SSL_CLIENT_HELLO,
    SSL_SERVER_HELLO,
    SSL_SERVER_CERTIFICATE,
    SSL_SERVER_KEY_EXCHANGE,
    SSL_CERTIFICATE_REQUEST,
    SSL_SERVER_HELLO_DONE,
    SSL_CLIENT_CERTIFICATE,
    SSL_CLIENT_KEY_EXCHANGE,
    SSL_CERTIFICATE_VERIFY,
    SSL_CLIENT_CHANGE_CIPHER_SPEC,
    SSL_CLIENT_FINISHED,
    SSL_SERVER_CHANGE_CIPHER_SPEC,
    SSL_SERVER_FINISHED,
    SSL_FLUSH_BUFFERS,
    SSL_HANDSHAKE_OVER
}
ssl_states;

typedef struct _ssl_session ssl_session;
typedef struct _ssl_context ssl_context;

/*
 * This structure is used for session resuming.
 */
struct _ssl_session
{
    time_t start;               /*!< starting time      */
    int ciphersuite;            /*!< chosen ciphersuite */
    size_t length;              /*!< session id length  */
    unsigned char id[32];       /*!< session identifier */
    unsigned char master[48];   /*!< the master secret  */
    ssl_session *next;          /*!< next session entry */
};

struct _ssl_context
{
    /*
     * Miscellaneous
     */
    int state;                  /*!< SSL handshake: current state     */

    int major_ver;              /*!< equal to  SSL_MAJOR_VERSION_3    */
    int minor_ver;              /*!< either 0 (SSL3) or 1 (TLS1.0)    */

    int max_major_ver;          /*!< max. major version from client   */
    int max_minor_ver;          /*!< max. minor version from client   */

    /*
     * Callbacks (RNG, debug, I/O, verification)
     */
    int  (*f_rng)(void *);
    void (*f_dbg)(void *, int, const char *);
    int (*f_recv)(void *, unsigned char *, size_t);
    int (*f_send)(void *, const unsigned char *, size_t);
    int (*f_vrfy)(void *, x509_cert *, int, int);

    void *p_rng;                /*!< context for the RNG function     */
    void *p_dbg;                /*!< context for the debug function   */
    void *p_recv;               /*!< context for reading operations   */
    void *p_send;               /*!< context for writing operations   */
    void *p_vrfy;               /*!< context for verification */

    /*
     * Session layer
     */
    int resume;                         /*!<  session resuming flag   */
    int timeout;                        /*!<  sess. expiration time   */
    ssl_session *session;               /*!<  current session data    */
    int (*s_get)(ssl_context *);        /*!<  (server) get callback   */
    int (*s_set)(ssl_context *);        /*!<  (server) set callback   */

    /*
     * Record layer (incoming data)
     */
    unsigned char *in_ctr;      /*!< 64-bit incoming message counter  */
    unsigned char *in_hdr;      /*!< 5-byte record header (in_ctr+8)  */
    unsigned char *in_msg;      /*!< the message contents (in_hdr+5)  */
    unsigned char *in_offt;     /*!< read offset in application data  */

    int in_msgtype;             /*!< record header: message type      */
    size_t in_msglen;           /*!< record header: message length    */
    size_t in_left;             /*!< amount of data read so far       */

    size_t in_hslen;            /*!< current handshake message length */
    int nb_zero;                /*!< # of 0-length encrypted messages */

    /*
     * Record layer (outgoing data)
     */
    unsigned char *out_ctr;     /*!< 64-bit outgoing message counter  */
    unsigned char *out_hdr;     /*!< 5-byte record header (out_ctr+8) */
    unsigned char *out_msg;     /*!< the message contents (out_hdr+5) */

    int out_msgtype;            /*!< record header: message type      */
    size_t out_msglen;          /*!< record header: message length    */
    size_t out_left;            /*!< amount of data not yet written   */

    /*
     * PKI layer
     */
    rsa_context *rsa_key;               /*!<  own RSA private key     */
#if defined(POLARSSL_PKCS11_C)
    pkcs11_context *pkcs11_key;         /*!<  own PKCS#11 RSA private key */
#endif
    x509_cert *own_cert;                /*!<  own X.509 certificate   */
    x509_cert *ca_chain;                /*!<  own trusted CA chain    */
    x509_crl *ca_crl;                   /*!<  trusted CA CRLs         */
    x509_cert *peer_cert;               /*!<  peer X.509 cert chain   */
    const char *peer_cn;                /*!<  expected peer CN        */

    int endpoint;                       /*!<  0: client, 1: server    */
    int authmode;                       /*!<  verification mode       */
    int client_auth;                    /*!<  flag for client auth.   */
    int verify_result;                  /*!<  verification result     */

    /*
     * Crypto layer
     */
    dhm_context dhm_ctx;                /*!<  DHM key exchange        */
    md5_context fin_md5;                /*!<  Finished MD5 checksum   */
    sha1_context fin_sha1;              /*!<  Finished SHA-1 checksum */

    int do_crypt;                       /*!<  en(de)cryption flag     */
    int *ciphersuites;                  /*!<  allowed ciphersuites    */
    size_t pmslen;                      /*!<  premaster length        */
    unsigned int keylen;                /*!<  symmetric key length    */
    size_t minlen;                      /*!<  min. ciphertext length  */
    size_t ivlen;                       /*!<  IV length               */
    size_t maclen;                      /*!<  MAC length              */

    unsigned char randbytes[64];        /*!<  random bytes            */
    unsigned char premaster[256];       /*!<  premaster secret        */

    unsigned char iv_enc[16];           /*!<  IV (encryption)         */
    unsigned char iv_dec[16];           /*!<  IV (decryption)         */

    unsigned char mac_enc[32];          /*!<  MAC (encryption)        */
    unsigned char mac_dec[32];          /*!<  MAC (decryption)        */

    unsigned long ctx_enc[128];         /*!<  encryption context      */
    unsigned long ctx_dec[128];         /*!<  decryption context      */

    /*
     * TLS extensions
     */
    unsigned char *hostname;
    size_t         hostname_len;
};

#ifdef __cplusplus
extern "C" {
#endif

extern int ssl_default_ciphersuites[];

/**
 * \brief Returns the list of ciphersuites supported by the SSL/TLS module.
 *
 * \return              a statically allocated array of ciphersuites, the last
 *                      entry is 0.
 */
static inline const int *ssl_list_ciphersuites( void )
{
    return ssl_default_ciphersuites;
}

/**
 * \brief               Return the name of the ciphersuite associated with the given
 *                      ID
 *
 * \param ciphersuite_id SSL ciphersuite ID
 *
 * \return              a string containing the ciphersuite name
 */
const char *ssl_get_ciphersuite_name( const int ciphersuite_id );

/**
 * \brief               Return the ID of the ciphersuite associated with the given
 *                      name
 *
 * \param ciphersuite_name SSL ciphersuite name
 *
 * \return              the ID with the ciphersuite or 0 if not found
 */
int ssl_get_ciphersuite_id( const char *ciphersuite_name );

/**
 * \brief          Initialize an SSL context
 *
 * \param ssl      SSL context
 *
 * \return         0 if successful, or 1 if memory allocation failed
 */
int ssl_init( ssl_context *ssl );

/**
 * \brief          Set the current endpoint type
 *
 * \param ssl      SSL context
 * \param endpoint must be SSL_IS_CLIENT or SSL_IS_SERVER
 */
void ssl_set_endpoint( ssl_context *ssl, int endpoint );

/**
 * \brief          Set the certificate verification mode
 *
 * \param ssl      SSL context
 * \param authmode can be:
 *
 *  SSL_VERIFY_NONE:      peer certificate is not checked (default),
 *                        this is insecure and SHOULD be avoided.
 *
 *  SSL_VERIFY_OPTIONAL:  peer certificate is checked, however the
 *                        handshake continues even if verification failed;
 *                        ssl_get_verify_result() can be called after the
 *                        handshake is complete.
 *
 *  SSL_VERIFY_REQUIRED:  peer *must* present a valid certificate,
 *                        handshake is aborted if verification failed.
 */
void ssl_set_authmode( ssl_context *ssl, int authmode );

/**
 * \brief          Set the verification callback (Optional).
 *
 *                 If set, the verification callback is called once for every
 *                 certificate in the chain. The verification function has the
 *                 following parameter: (void *parameter, x509_cert certificate,
 *                 int certifcate_depth, int preverify_ok). It should
 *                 return 0 on SUCCESS.
 *
 * \param ssl      SSL context
 * \param f_vrfy   verification function
 * \param p_vrfy   verification parameter
 */
void ssl_set_verify( ssl_context *ssl,
                     int (*f_vrfy)(void *, x509_cert *, int, int),
                     void *p_vrfy );

/**
 * \brief          Set the random number generator callback
 *
 * \param ssl      SSL context
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 */
void ssl_set_rng( ssl_context *ssl,
                  int (*f_rng)(void *),
                  void *p_rng );

/**
 * \brief          Set the debug callback
 *
 * \param ssl      SSL context
 * \param f_dbg    debug function
 * \param p_dbg    debug parameter
 */
void ssl_set_dbg( ssl_context *ssl,
                  void (*f_dbg)(void *, int, const char *),
                  void  *p_dbg );

/**
 * \brief          Set the underlying BIO read and write callbacks
 *
 * \param ssl      SSL context
 * \param f_recv   read callback
 * \param p_recv   read parameter
 * \param f_send   write callback
 * \param p_send   write parameter
 */
void ssl_set_bio( ssl_context *ssl,
        int (*f_recv)(void *, unsigned char *, size_t), void *p_recv,
        int (*f_send)(void *, const unsigned char *, size_t), void *p_send );

/**
 * \brief          Set the session callbacks (server-side only)
 *
 * \param ssl      SSL context
 * \param s_get    session get callback
 * \param s_set    session set callback
 */
void ssl_set_scb( ssl_context *ssl,
                  int (*s_get)(ssl_context *),
                  int (*s_set)(ssl_context *) );

/**
 * \brief          Set the session resuming flag, timeout and data
 *
 * \param ssl      SSL context
 * \param resume   if 0 (default), the session will not be resumed
 * \param timeout  session timeout in seconds, or 0 (no timeout)
 * \param session  session context
 */
void ssl_set_session( ssl_context *ssl, int resume, int timeout,
                      ssl_session *session );

/**
 * \brief               Set the list of allowed ciphersuites
 *
 * \param ssl           SSL context
 * \param ciphersuites  0-terminated list of allowed ciphersuites
 */
void ssl_set_ciphersuites( ssl_context *ssl, int *ciphersuites );

/**
 * \brief          Set the data required to verify peer certificate
 *
 * \param ssl      SSL context
 * \param ca_chain trusted CA chain
 * \param ca_crl   trusted CA CRLs
 * \param peer_cn  expected peer CommonName (or NULL)
 *
 * \note           TODO: add two more parameters: depth and crl
 */
void ssl_set_ca_chain( ssl_context *ssl, x509_cert *ca_chain,
                       x509_crl *ca_crl, const char *peer_cn );

/**
 * \brief          Set own certificate and private key
 *
 * \param ssl      SSL context
 * \param own_cert own public certificate
 * \param rsa_key  own private RSA key
 */
void ssl_set_own_cert( ssl_context *ssl, x509_cert *own_cert,
                       rsa_context *rsa_key );

#if defined(POLARSSL_PKCS11_C)
/**
 * \brief          Set own certificate and PKCS#11 private key
 *
 * \param ssl      SSL context
 * \param own_cert own public certificate
 * \param pkcs11_key    own PKCS#11 RSA key
 */
void ssl_set_own_cert_pkcs11( ssl_context *ssl, x509_cert *own_cert,
                       pkcs11_context *pkcs11_key );
#endif

/**
 * \brief          Set the Diffie-Hellman public P and G values,
 *                 read as hexadecimal strings (server-side only)
 *
 * \param ssl      SSL context
 * \param dhm_P    Diffie-Hellman-Merkle modulus
 * \param dhm_G    Diffie-Hellman-Merkle generator
 *
 * \return         0 if successful
 */
int ssl_set_dh_param( ssl_context *ssl, const char *dhm_P, const char *dhm_G );

/**
 * \brief          Set the Diffie-Hellman public P and G values,
 *                 read from existing context (server-side only)
 *
 * \param ssl      SSL context
 * \param dhm_ctx  Diffie-Hellman-Merkle context
 *
 * \return         0 if successful
 */
int ssl_set_dh_param_ctx( ssl_context *ssl, dhm_context *dhm_ctx );

/**
 * \brief          Set hostname for ServerName TLS Extension
 *                 
 *
 * \param ssl      SSL context
 * \param hostname the server hostname
 *
 * \return         0 if successful
 */
int ssl_set_hostname( ssl_context *ssl, const char *hostname );

/**
 * \brief          Return the number of data bytes available to read
 *
 * \param ssl      SSL context
 *
 * \return         how many bytes are available in the read buffer
 */
size_t ssl_get_bytes_avail( const ssl_context *ssl );

/**
 * \brief          Return the result of the certificate verification
 *
 * \param ssl      SSL context
 *
 * \return         0 if successful, or a combination of:
 *                      BADCERT_EXPIRED
 *                      BADCERT_REVOKED
 *                      BADCERT_CN_MISMATCH
 *                      BADCERT_NOT_TRUSTED
 */
int ssl_get_verify_result( const ssl_context *ssl );

/**
 * \brief          Return the name of the current ciphersuite
 *
 * \param ssl      SSL context
 *
 * \return         a string containing the ciphersuite name
 */
const char *ssl_get_ciphersuite( const ssl_context *ssl );

/**
 * \brief          Return the current SSL version (SSLv3/TLSv1/etc)
 *
 * \param ssl      SSL context
 *
 * \return         a string containing the SSL version
 */
const char *ssl_get_version( const ssl_context *ssl );

/**
 * \brief          Perform the SSL handshake
 *
 * \param ssl      SSL context
 *
 * \return         0 if successful, POLARSSL_ERR_NET_WANT_READ,
 *                 POLARSSL_ERR_NET_WANT_WRITE, or a specific SSL error code.
 */
int ssl_handshake( ssl_context *ssl );

/**
 * \brief          Read at most 'len' application data bytes
 *
 * \param ssl      SSL context
 * \param buf      buffer that will hold the data
 * \param len      how many bytes must be read
 *
 * \return         This function returns the number of bytes read, 0 for EOF,
 *                 or a negative error code.
 */
int ssl_read( ssl_context *ssl, unsigned char *buf, size_t len );

/**
 * \brief          Write exactly 'len' application data bytes
 *
 * \param ssl      SSL context
 * \param buf      buffer holding the data
 * \param len      how many bytes must be written
 *
 * \return         This function returns the number of bytes written,
 *                 or a negative error code.
 *
 * \note           When this function returns POLARSSL_ERR_NET_WANT_WRITE,
 *                 it must be called later with the *same* arguments,
 *                 until it returns a positive value.
 */
int ssl_write( ssl_context *ssl, const unsigned char *buf, size_t len );

/**
 * \brief          Notify the peer that the connection is being closed
 *
 * \param ssl      SSL context
 */
int ssl_close_notify( ssl_context *ssl );

/**
 * \brief          Free an SSL context
 *
 * \param ssl      SSL context
 */
void ssl_free( ssl_context *ssl );

/*
 * Internal functions (do not call directly)
 */
int ssl_handshake_client( ssl_context *ssl );
int ssl_handshake_server( ssl_context *ssl );

int ssl_derive_keys( ssl_context *ssl );
void ssl_calc_verify( ssl_context *ssl, unsigned char hash[36] );

int ssl_read_record( ssl_context *ssl );
/**
 * \return         0 if successful, POLARSSL_ERR_SSL_CONN_EOF on EOF or
 *                 another negative error code.
 */
int ssl_fetch_input( ssl_context *ssl, size_t nb_want );

int ssl_write_record( ssl_context *ssl );
int ssl_flush_output( ssl_context *ssl );

int ssl_parse_certificate( ssl_context *ssl );
int ssl_write_certificate( ssl_context *ssl );

int ssl_parse_change_cipher_spec( ssl_context *ssl );
int ssl_write_change_cipher_spec( ssl_context *ssl );

int ssl_parse_finished( ssl_context *ssl );
int ssl_write_finished( ssl_context *ssl );

#ifdef __cplusplus
}
#endif

#endif /* ssl.h */
