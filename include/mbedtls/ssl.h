/**
 * \file ssl.h
 *
 * \brief SSL/TLS functions.
 *
 *  Copyright (C) 2006-2014, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
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
#ifndef MBEDTLS_SSL_H
#define MBEDTLS_SSL_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "bignum.h"
#include "ecp.h"

#include "ssl_ciphersuites.h"

#if defined(MBEDTLS_MD5_C)
#include "md5.h"
#endif

#if defined(MBEDTLS_SHA1_C)
#include "sha1.h"
#endif

#if defined(MBEDTLS_SHA256_C)
#include "sha256.h"
#endif

#if defined(MBEDTLS_SHA512_C)
#include "sha512.h"
#endif

// for session tickets
#if defined(MBEDTLS_AES_C)
#include "aes.h"
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#include "x509_crt.h"
#include "x509_crl.h"
#endif

#if defined(MBEDTLS_DHM_C)
#include "dhm.h"
#endif

#if defined(MBEDTLS_ECDH_C)
#include "ecdh.h"
#endif

#if defined(MBEDTLS_ZLIB_SUPPORT)
#include "zlib.h"
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
#include "timing.h"
#endif

#if defined(MBEDTLS_HAVE_TIME)
#include <time.h>
#endif

/* For convenience below and in programs */
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) ||                           \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED) ||                       \
    defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED) ||                       \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
#define MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) ||                     \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) ||                   \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
#define MBEDTLS_KEY_EXCHANGE__SOME__ECDHE_ENABLED
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
#define MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE               -0x7080  /**< The requested feature is not available. */
#define MBEDTLS_ERR_SSL_BAD_INPUT_DATA                    -0x7100  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_SSL_INVALID_MAC                       -0x7180  /**< Verification of the message MAC failed. */
#define MBEDTLS_ERR_SSL_INVALID_RECORD                    -0x7200  /**< An invalid SSL record was received. */
#define MBEDTLS_ERR_SSL_CONN_EOF                          -0x7280  /**< The connection indicated an EOF. */
#define MBEDTLS_ERR_SSL_UNKNOWN_CIPHER                    -0x7300  /**< An unknown cipher was received. */
#define MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN                  -0x7380  /**< The server has no ciphersuites in common with the client. */
#define MBEDTLS_ERR_SSL_NO_RNG                            -0x7400  /**< No RNG was provided to the SSL module. */
#define MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE             -0x7480  /**< No client certification received from the client, but required by the authentication mode. */
#define MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE             -0x7500  /**< Our own certificate(s) is/are too large to send in an SSL message. */
#define MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED              -0x7580  /**< The own certificate is not set, but needed by the server. */
#define MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED              -0x7600  /**< The own private key or pre-shared key is not set, but needed. */
#define MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED                 -0x7680  /**< No CA Chain is set, but required to operate. */
#define MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE                -0x7700  /**< An unexpected message was received from our peer. */
#define MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE               -0x7780  /**< A fatal alert message was received from our peer. */
#define MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED                -0x7800  /**< Verification of our peer failed. */
#define MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY                 -0x7880  /**< The peer notified us that the connection is going to be closed. */
#define MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO               -0x7900  /**< Processing of the ClientHello handshake message failed. */
#define MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO               -0x7980  /**< Processing of the ServerHello handshake message failed. */
#define MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE                -0x7A00  /**< Processing of the Certificate handshake message failed. */
#define MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST        -0x7A80  /**< Processing of the CertificateRequest handshake message failed. */
#define MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE        -0x7B00  /**< Processing of the ServerKeyExchange handshake message failed. */
#define MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE          -0x7B80  /**< Processing of the ServerHelloDone handshake message failed. */
#define MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE        -0x7C00  /**< Processing of the ClientKeyExchange handshake message failed. */
#define MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP     -0x7C80  /**< Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Read Public. */
#define MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS     -0x7D00  /**< Processing of the ClientKeyExchange handshake message failed in DHM / ECDH Calculate Secret. */
#define MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY         -0x7D80  /**< Processing of the CertificateVerify handshake message failed. */
#define MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC         -0x7E00  /**< Processing of the ChangeCipherSpec handshake message failed. */
#define MBEDTLS_ERR_SSL_BAD_HS_FINISHED                   -0x7E80  /**< Processing of the Finished handshake message failed. */
#define MBEDTLS_ERR_SSL_MALLOC_FAILED                     -0x7F00  /**< Memory allocation failed */
#define MBEDTLS_ERR_SSL_HW_ACCEL_FAILED                   -0x7F80  /**< Hardware acceleration function returned with error */
#define MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH              -0x6F80  /**< Hardware acceleration function skipped / left alone data */
#define MBEDTLS_ERR_SSL_COMPRESSION_FAILED                -0x6F00  /**< Processing of the compression / decompression failed */
#define MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION           -0x6E80  /**< Handshake protocol not within min/max boundaries */
#define MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET         -0x6E00  /**< Processing of the NewSessionTicket handshake message failed. */
#define MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED            -0x6D80  /**< Session ticket has expired. */
#define MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH                  -0x6D00  /**< Public key type mismatch (eg, asked for RSA key exchange and presented EC key) */
#define MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY                  -0x6C80  /**< Unknown identity received (eg, PSK identity) */
#define MBEDTLS_ERR_SSL_INTERNAL_ERROR                    -0x6C00  /**< Internal error (eg, unexpected failure in lower-level module) */
#define MBEDTLS_ERR_SSL_COUNTER_WRAPPING                  -0x6B80  /**< A counter would wrap (eg, too many messages exchanged). */
#define MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO       -0x6B00  /**< Unexpected message at ServerHello in renegotiation. */
#define MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED             -0x6A80  /**< DTLS client must retry for hello verification */
#define MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL                  -0x6A00  /**< A buffer is too small to receive or write a message */
#define MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE             -0x6980  /**< None of the common ciphersuites is usable (eg, no suitable certificate, see debug messages). */
#define MBEDTLS_ERR_SSL_WANT_READ                         -0x6900  /**< Connection requires a read call. */
#define MBEDTLS_ERR_SSL_WANT_WRITE                        -0x6880  /**< Connection requires a write call. */
#define MBEDTLS_ERR_SSL_TIMEOUT                           -0x6800  /**< The operation timed out. */

/*
 * Various constants
 */
#define MBEDTLS_SSL_MAJOR_VERSION_3             3
#define MBEDTLS_SSL_MINOR_VERSION_0             0   /*!< SSL v3.0 */
#define MBEDTLS_SSL_MINOR_VERSION_1             1   /*!< TLS v1.0 */
#define MBEDTLS_SSL_MINOR_VERSION_2             2   /*!< TLS v1.1 */
#define MBEDTLS_SSL_MINOR_VERSION_3             3   /*!< TLS v1.2 */

#define MBEDTLS_SSL_TRANSPORT_STREAM            0   /*!< TLS      */
#define MBEDTLS_SSL_TRANSPORT_DATAGRAM          1   /*!< DTLS     */

/* Determine minimum supported version */
#define MBEDTLS_SSL_MIN_MAJOR_VERSION           MBEDTLS_SSL_MAJOR_VERSION_3

#if defined(MBEDTLS_SSL_PROTO_SSL3)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_0
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_1
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1_1)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_2
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#define MBEDTLS_SSL_MIN_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_3
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
#endif /* MBEDTLS_SSL_PROTO_TLS1_1 */
#endif /* MBEDTLS_SSL_PROTO_TLS1   */
#endif /* MBEDTLS_SSL_PROTO_SSL3   */

/* Determine maximum supported version */
#define MBEDTLS_SSL_MAX_MAJOR_VERSION           MBEDTLS_SSL_MAJOR_VERSION_3

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#define MBEDTLS_SSL_MAX_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_3
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1_1)
#define MBEDTLS_SSL_MAX_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_2
#else
#if defined(MBEDTLS_SSL_PROTO_TLS1)
#define MBEDTLS_SSL_MAX_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_1
#else
#if defined(MBEDTLS_SSL_PROTO_SSL3)
#define MBEDTLS_SSL_MAX_MINOR_VERSION           MBEDTLS_SSL_MINOR_VERSION_0
#endif /* MBEDTLS_SSL_PROTO_SSL3   */
#endif /* MBEDTLS_SSL_PROTO_TLS1   */
#endif /* MBEDTLS_SSL_PROTO_TLS1_1 */
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

/* RFC 6066 section 4, see also mfl_code_to_length in ssl_tls.c
 * NONE must be zero so that memset()ing structure to zero works */
#define MBEDTLS_SSL_MAX_FRAG_LEN_NONE           0   /*!< don't use this extension   */
#define MBEDTLS_SSL_MAX_FRAG_LEN_512            1   /*!< MaxFragmentLength 2^9      */
#define MBEDTLS_SSL_MAX_FRAG_LEN_1024           2   /*!< MaxFragmentLength 2^10     */
#define MBEDTLS_SSL_MAX_FRAG_LEN_2048           3   /*!< MaxFragmentLength 2^11     */
#define MBEDTLS_SSL_MAX_FRAG_LEN_4096           4   /*!< MaxFragmentLength 2^12     */
#define MBEDTLS_SSL_MAX_FRAG_LEN_INVALID        5   /*!< first invalid value        */

#define MBEDTLS_SSL_IS_CLIENT                   0
#define MBEDTLS_SSL_IS_SERVER                   1

#define MBEDTLS_SSL_IS_NOT_FALLBACK             0
#define MBEDTLS_SSL_IS_FALLBACK                 1

#define MBEDTLS_SSL_EXTENDED_MS_DISABLED        0
#define MBEDTLS_SSL_EXTENDED_MS_ENABLED         1

#define MBEDTLS_SSL_ETM_DISABLED                0
#define MBEDTLS_SSL_ETM_ENABLED                 1

#define MBEDTLS_SSL_COMPRESS_NULL               0
#define MBEDTLS_SSL_COMPRESS_DEFLATE            1

#define MBEDTLS_SSL_VERIFY_NONE                 0
#define MBEDTLS_SSL_VERIFY_OPTIONAL             1
#define MBEDTLS_SSL_VERIFY_REQUIRED             2

#define MBEDTLS_SSL_INITIAL_HANDSHAKE           0
#define MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS   1   /* In progress */
#define MBEDTLS_SSL_RENEGOTIATION_DONE          2   /* Done or aborted */
#define MBEDTLS_SSL_RENEGOTIATION_PENDING       3   /* Requested (server only) */

#define MBEDTLS_SSL_LEGACY_RENEGOTIATION        0
#define MBEDTLS_SSL_SECURE_RENEGOTIATION        1

#define MBEDTLS_SSL_RENEGOTIATION_DISABLED      0
#define MBEDTLS_SSL_RENEGOTIATION_ENABLED       1

#define MBEDTLS_SSL_ANTI_REPLAY_DISABLED        0
#define MBEDTLS_SSL_ANTI_REPLAY_ENABLED         1

#define MBEDTLS_SSL_RENEGOTIATION_NOT_ENFORCED  -1
#define MBEDTLS_SSL_RENEGO_MAX_RECORDS_DEFAULT  16

#define MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION     0
#define MBEDTLS_SSL_LEGACY_ALLOW_RENEGOTIATION  1
#define MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE      2

#define MBEDTLS_SSL_TRUNC_HMAC_DISABLED         0
#define MBEDTLS_SSL_TRUNC_HMAC_ENABLED          1
#define MBEDTLS_SSL_TRUNCATED_HMAC_LEN          10  /* 80 bits, rfc 6066 section 7 */

#define MBEDTLS_SSL_SESSION_TICKETS_DISABLED     0
#define MBEDTLS_SSL_SESSION_TICKETS_ENABLED      1

#define MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED    0
#define MBEDTLS_SSL_CBC_RECORD_SPLITTING_ENABLED     1

#define MBEDTLS_SSL_ARC4_ENABLED                0
#define MBEDTLS_SSL_ARC4_DISABLED               1

/*
 * DTLS retransmission states, see RFC 6347 4.2.4
 *
 * The SENDING state is merged in PREPARING for initial sends,
 * but is distinct for resends.
 *
 * Note: initial state is wrong for server, but is not used anyway.
 */
#define MBEDTLS_SSL_RETRANS_PREPARING       0
#define MBEDTLS_SSL_RETRANS_SENDING         1
#define MBEDTLS_SSL_RETRANS_WAITING         2
#define MBEDTLS_SSL_RETRANS_FINISHED        3

/*
 * Default range for DTLS retransmission timer value, in milliseconds.
 * RFC 6347 4.2.4.1 says from 1 second to 60 seconds.
 */
#define MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MIN    1000
#define MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MAX   60000

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in config.h or define them on the compiler command line.
 * \{
 */

#if !defined(MBEDTLS_SSL_DEFAULT_TICKET_LIFETIME)
#define MBEDTLS_SSL_DEFAULT_TICKET_LIFETIME     86400 /**< Lifetime of session tickets (if enabled) */
#endif

/*
 * Size of the input / output buffer.
 * Note: the RFC defines the default size of SSL / TLS messages. If you
 * change the value here, other clients / servers may not be able to
 * communicate with you anymore. Only change this value if you control
 * both sides of the connection and have it reduced at both sides, or
 * if you're using the Max Fragment Length extension and you know all your
 * peers are using it too!
 */
#if !defined(MBEDTLS_SSL_MAX_CONTENT_LEN)
#define MBEDTLS_SSL_MAX_CONTENT_LEN         16384   /**< Size of the input / output buffer */
#endif

/* \} name SECTION: Module settings */

/*
 * Allow extra bytes for record, authentication and encryption overhead:
 * counter (8) + header (5) + IV(16) + MAC (16-48) + padding (0-256)
 * and allow for a maximum of 1024 of compression expansion if
 * enabled.
 */
#if defined(MBEDTLS_ZLIB_SUPPORT)
#define MBEDTLS_SSL_COMPRESSION_ADD          1024
#else
#define MBEDTLS_SSL_COMPRESSION_ADD             0
#endif

#if defined(MBEDTLS_ARC4_C) || defined(MBEDTLS_CIPHER_MODE_CBC)
/* Ciphersuites using HMAC */
#if defined(MBEDTLS_SHA512_C)
#define MBEDTLS_SSL_MAC_ADD                 48  /* SHA-384 used for HMAC */
#elif defined(MBEDTLS_SHA256_C)
#define MBEDTLS_SSL_MAC_ADD                 32  /* SHA-256 used for HMAC */
#else
#define MBEDTLS_SSL_MAC_ADD                 20  /* SHA-1   used for HMAC */
#endif
#else
/* AEAD ciphersuites: GCM and CCM use a 128 bits tag */
#define MBEDTLS_SSL_MAC_ADD                 16
#endif

#if defined(MBEDTLS_CIPHER_MODE_CBC)
#define MBEDTLS_SSL_PADDING_ADD            256
#else
#define MBEDTLS_SSL_PADDING_ADD              0
#endif

#define MBEDTLS_SSL_BUFFER_LEN  ( MBEDTLS_SSL_MAX_CONTENT_LEN               \
                        + MBEDTLS_SSL_COMPRESSION_ADD               \
                        + 29 /* counter + header + IV */    \
                        + MBEDTLS_SSL_MAC_ADD                       \
                        + MBEDTLS_SSL_PADDING_ADD                   \
                        )

/*
 * Length of the verify data for secure renegotiation
 */
#if defined(MBEDTLS_SSL_PROTO_SSL3)
#define MBEDTLS_SSL_VERIFY_DATA_MAX_LEN 36
#else
#define MBEDTLS_SSL_VERIFY_DATA_MAX_LEN 12
#endif

/*
 * Signaling ciphersuite values (SCSV)
 */
#define MBEDTLS_SSL_EMPTY_RENEGOTIATION_INFO    0xFF   /**< renegotiation info ext */
#define MBEDTLS_SSL_FALLBACK_SCSV_VALUE         0x5600 /**< draft-ietf-tls-downgrade-scsv-00 */

/*
 * Supported Signature and Hash algorithms (For TLS 1.2)
 * RFC 5246 section 7.4.1.4.1
 */
#define MBEDTLS_SSL_HASH_NONE                0
#define MBEDTLS_SSL_HASH_MD5                 1
#define MBEDTLS_SSL_HASH_SHA1                2
#define MBEDTLS_SSL_HASH_SHA224              3
#define MBEDTLS_SSL_HASH_SHA256              4
#define MBEDTLS_SSL_HASH_SHA384              5
#define MBEDTLS_SSL_HASH_SHA512              6

#define MBEDTLS_SSL_SIG_ANON                 0
#define MBEDTLS_SSL_SIG_RSA                  1
#define MBEDTLS_SSL_SIG_ECDSA                3

/*
 * Client Certificate Types
 * RFC 5246 section 7.4.4 plus RFC 4492 section 5.5
 */
#define MBEDTLS_SSL_CERT_TYPE_RSA_SIGN       1
#define MBEDTLS_SSL_CERT_TYPE_ECDSA_SIGN    64

/*
 * Message, alert and handshake types
 */
#define MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC     20
#define MBEDTLS_SSL_MSG_ALERT                  21
#define MBEDTLS_SSL_MSG_HANDSHAKE              22
#define MBEDTLS_SSL_MSG_APPLICATION_DATA       23

#define MBEDTLS_SSL_ALERT_LEVEL_WARNING         1
#define MBEDTLS_SSL_ALERT_LEVEL_FATAL           2

#define MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY           0  /* 0x00 */
#define MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE    10  /* 0x0A */
#define MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC        20  /* 0x14 */
#define MBEDTLS_SSL_ALERT_MSG_DECRYPTION_FAILED     21  /* 0x15 */
#define MBEDTLS_SSL_ALERT_MSG_RECORD_OVERFLOW       22  /* 0x16 */
#define MBEDTLS_SSL_ALERT_MSG_DECOMPRESSION_FAILURE 30  /* 0x1E */
#define MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE     40  /* 0x28 */
#define MBEDTLS_SSL_ALERT_MSG_NO_CERT               41  /* 0x29 */
#define MBEDTLS_SSL_ALERT_MSG_BAD_CERT              42  /* 0x2A */
#define MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT      43  /* 0x2B */
#define MBEDTLS_SSL_ALERT_MSG_CERT_REVOKED          44  /* 0x2C */
#define MBEDTLS_SSL_ALERT_MSG_CERT_EXPIRED          45  /* 0x2D */
#define MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN          46  /* 0x2E */
#define MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER     47  /* 0x2F */
#define MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA            48  /* 0x30 */
#define MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED         49  /* 0x31 */
#define MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR          50  /* 0x32 */
#define MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR         51  /* 0x33 */
#define MBEDTLS_SSL_ALERT_MSG_EXPORT_RESTRICTION    60  /* 0x3C */
#define MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION      70  /* 0x46 */
#define MBEDTLS_SSL_ALERT_MSG_INSUFFICIENT_SECURITY 71  /* 0x47 */
#define MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR        80  /* 0x50 */
#define MBEDTLS_SSL_ALERT_MSG_INAPROPRIATE_FALLBACK 86  /* 0x56 */
#define MBEDTLS_SSL_ALERT_MSG_USER_CANCELED         90  /* 0x5A */
#define MBEDTLS_SSL_ALERT_MSG_NO_RENEGOTIATION     100  /* 0x64 */
#define MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT      110  /* 0x6E */
#define MBEDTLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME    112  /* 0x70 */
#define MBEDTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY 115  /* 0x73 */
#define MBEDTLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL 120 /* 0x78 */

#define MBEDTLS_SSL_HS_HELLO_REQUEST            0
#define MBEDTLS_SSL_HS_CLIENT_HELLO             1
#define MBEDTLS_SSL_HS_SERVER_HELLO             2
#define MBEDTLS_SSL_HS_HELLO_VERIFY_REQUEST     3
#define MBEDTLS_SSL_HS_NEW_SESSION_TICKET       4
#define MBEDTLS_SSL_HS_CERTIFICATE             11
#define MBEDTLS_SSL_HS_SERVER_KEY_EXCHANGE     12
#define MBEDTLS_SSL_HS_CERTIFICATE_REQUEST     13
#define MBEDTLS_SSL_HS_SERVER_HELLO_DONE       14
#define MBEDTLS_SSL_HS_CERTIFICATE_VERIFY      15
#define MBEDTLS_SSL_HS_CLIENT_KEY_EXCHANGE     16
#define MBEDTLS_SSL_HS_FINISHED                20

/*
 * TLS extensions
 */
#define MBEDTLS_TLS_EXT_SERVERNAME                   0
#define MBEDTLS_TLS_EXT_SERVERNAME_HOSTNAME          0

#define MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH          1

#define MBEDTLS_TLS_EXT_TRUNCATED_HMAC               4

#define MBEDTLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES   10
#define MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS     11

#define MBEDTLS_TLS_EXT_SIG_ALG                     13

#define MBEDTLS_TLS_EXT_ALPN                        16

#define MBEDTLS_TLS_EXT_ENCRYPT_THEN_MAC            22 /* 0x16 */
#define MBEDTLS_TLS_EXT_EXTENDED_MASTER_SECRET  0x0017 /* 23 */

#define MBEDTLS_TLS_EXT_SESSION_TICKET              35

#define MBEDTLS_TLS_EXT_RENEGOTIATION_INFO      0xFF01

/*
 * TLS extension flags (for extensions with outgoing ServerHello content
 * that need it (e.g. for RENEGOTIATION_INFO the server already knows because
 * of state of the renegotiation flag, so no indicator is required)
 */
#define MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT (1 << 0)

/*
 * Size defines
 */
#if !defined(MBEDTLS_PSK_MAX_LEN)
#define MBEDTLS_PSK_MAX_LEN            32 /* 256 bits */
#endif

/* Dummy type used only for its size */
union mbedtls_ssl_premaster_secret
{
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED)
    unsigned char _pms_rsa[48];                         /* RFC 5246 8.1.1 */
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)
    unsigned char _pms_dhm[MBEDTLS_MPI_MAX_SIZE];      /* RFC 5246 8.1.2 */
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED)    || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)  || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED)     || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
    unsigned char _pms_ecdh[MBEDTLS_ECP_MAX_BYTES];    /* RFC 4492 5.10 */
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
    unsigned char _pms_psk[4 + 2 * MBEDTLS_PSK_MAX_LEN];       /* RFC 4279 2 */
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
    unsigned char _pms_dhe_psk[4 + MBEDTLS_MPI_MAX_SIZE
                                 + MBEDTLS_PSK_MAX_LEN];       /* RFC 4279 3 */
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    unsigned char _pms_rsa_psk[52 + MBEDTLS_PSK_MAX_LEN];      /* RFC 4279 4 */
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
    unsigned char _pms_ecdhe_psk[4 + MBEDTLS_ECP_MAX_BYTES
                                   + MBEDTLS_PSK_MAX_LEN];     /* RFC 5489 2 */
#endif
};

#define MBEDTLS_PREMASTER_SIZE     sizeof( union mbedtls_ssl_premaster_secret )

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generic function pointers for allowing external RSA private key
 * implementations.
 */
typedef int (*mbedtls_rsa_decrypt_func)( void *ctx, int mode, size_t *olen,
                        const unsigned char *input, unsigned char *output,
                        size_t output_max_len );
typedef int (*mbedtls_rsa_sign_func)( void *ctx,
                     int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                     int mode, mbedtls_md_type_t md_alg, unsigned int hashlen,
                     const unsigned char *hash, unsigned char *sig );
typedef size_t (*mbedtls_rsa_key_len_func)( void *ctx );

/*
 * SSL state machine
 */
typedef enum
{
    MBEDTLS_SSL_HELLO_REQUEST,
    MBEDTLS_SSL_CLIENT_HELLO,
    MBEDTLS_SSL_SERVER_HELLO,
    MBEDTLS_SSL_SERVER_CERTIFICATE,
    MBEDTLS_SSL_SERVER_KEY_EXCHANGE,
    MBEDTLS_SSL_CERTIFICATE_REQUEST,
    MBEDTLS_SSL_SERVER_HELLO_DONE,
    MBEDTLS_SSL_CLIENT_CERTIFICATE,
    MBEDTLS_SSL_CLIENT_KEY_EXCHANGE,
    MBEDTLS_SSL_CERTIFICATE_VERIFY,
    MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC,
    MBEDTLS_SSL_CLIENT_FINISHED,
    MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC,
    MBEDTLS_SSL_SERVER_FINISHED,
    MBEDTLS_SSL_FLUSH_BUFFERS,
    MBEDTLS_SSL_HANDSHAKE_WRAPUP,
    MBEDTLS_SSL_HANDSHAKE_OVER,
    MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET,
    MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT,
}
mbedtls_ssl_states;

typedef struct mbedtls_ssl_session mbedtls_ssl_session;
typedef struct mbedtls_ssl_context mbedtls_ssl_context;
typedef struct mbedtls_ssl_transform mbedtls_ssl_transform;
typedef struct mbedtls_ssl_handshake_params mbedtls_ssl_handshake_params;
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
typedef struct mbedtls_ssl_ticket_keys mbedtls_ssl_ticket_keys;
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
typedef struct mbedtls_ssl_key_cert mbedtls_ssl_key_cert;
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
typedef struct mbedtls_ssl_flight_item mbedtls_ssl_flight_item;
#endif

/*
 * This structure is used for storing current session data.
 */
struct mbedtls_ssl_session
{
#if defined(MBEDTLS_HAVE_TIME)
    time_t start;               /*!< starting time      */
#endif
    int ciphersuite;            /*!< chosen ciphersuite */
    int compression;            /*!< chosen compression */
    size_t length;              /*!< session id length  */
    unsigned char id[32];       /*!< session identifier */
    unsigned char master[48];   /*!< the master secret  */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt *peer_cert;        /*!< peer X.509 cert chain */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
    uint32_t verify_result;          /*!<  verification result     */

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    unsigned char *ticket;      /*!< RFC 5077 session ticket */
    size_t ticket_len;          /*!< session ticket length   */
    uint32_t ticket_lifetime;   /*!< ticket lifetime hint    */
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    unsigned char mfl_code;     /*!< MaxFragmentLength negotiated by peer */
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
    int trunc_hmac;             /*!< flag for truncated hmac activation   */
#endif /* MBEDTLS_SSL_TRUNCATED_HMAC */

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    int encrypt_then_mac;       /*!< flag for EtM activation                */
#endif
};

/*
 * This structure contains a full set of runtime transform parameters
 * either in negotiation or active.
 */
struct mbedtls_ssl_transform
{
    /*
     * Session specific crypto layer
     */
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
                                        /*!<  Chosen cipersuite_info  */
    unsigned int keylen;                /*!<  symmetric key length    */
    size_t minlen;                      /*!<  min. ciphertext length  */
    size_t ivlen;                       /*!<  IV length               */
    size_t fixed_ivlen;                 /*!<  Fixed part of IV (AEAD) */
    size_t maclen;                      /*!<  MAC length              */

    unsigned char iv_enc[16];           /*!<  IV (encryption)         */
    unsigned char iv_dec[16];           /*!<  IV (decryption)         */

#if defined(MBEDTLS_SSL_PROTO_SSL3)
    /* Needed only for SSL v3.0 secret */
    unsigned char mac_enc[20];          /*!<  SSL v3.0 secret (enc)   */
    unsigned char mac_dec[20];          /*!<  SSL v3.0 secret (dec)   */
#endif /* MBEDTLS_SSL_PROTO_SSL3 */

    mbedtls_md_context_t md_ctx_enc;            /*!<  MAC (encryption)        */
    mbedtls_md_context_t md_ctx_dec;            /*!<  MAC (decryption)        */

    mbedtls_cipher_context_t cipher_ctx_enc;    /*!<  encryption context      */
    mbedtls_cipher_context_t cipher_ctx_dec;    /*!<  decryption context      */

    /*
     * Session specific compression layer
     */
#if defined(MBEDTLS_ZLIB_SUPPORT)
    z_stream ctx_deflate;               /*!<  compression context     */
    z_stream ctx_inflate;               /*!<  decompression context   */
#endif
};

/*
 * This structure contains the parameters only needed during handshake.
 */
struct mbedtls_ssl_handshake_params
{
    /*
     * Handshake specific crypto variables
     */
    int sig_alg;                        /*!<  Hash algorithm for signature   */
    int cert_type;                      /*!<  Requested cert type            */
    int verify_sig_alg;                 /*!<  Signature algorithm for verify */
#if defined(MBEDTLS_DHM_C)
    mbedtls_dhm_context dhm_ctx;                /*!<  DHM key exchange        */
#endif
#if defined(MBEDTLS_ECDH_C)
    mbedtls_ecdh_context ecdh_ctx;              /*!<  ECDH key exchange       */
#endif
#if defined(MBEDTLS_ECDH_C) || defined(MBEDTLS_ECDSA_C)
    const mbedtls_ecp_curve_info **curves;      /*!<  Supported elliptic curves */
#endif
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    unsigned char *psk;                 /*!<  PSK from the callback         */
    size_t psk_len;                     /*!<  Length of PSK from callback   */
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_key_cert *key_cert;     /*!< chosen key/cert pair (server)  */
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    mbedtls_ssl_key_cert *sni_key_cert; /*!< key/cert list from SNI         */
    mbedtls_x509_crt *sni_ca_chain;     /*!< trusted CAs from SNI callback  */
    mbedtls_x509_crl *sni_ca_crl;       /*!< trusted CAs CRLs from SNI      */
#endif
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    unsigned int out_msg_seq;           /*!<  Outgoing handshake sequence number */
    unsigned int in_msg_seq;            /*!<  Incoming handshake sequence number */

    unsigned char *verify_cookie;       /*!<  Cli: HelloVerifyRequest cookie
                                              Srv: unused                    */
    unsigned char verify_cookie_len;    /*!<  Cli: cookie length
                                              Srv: flag for sending a cookie */

    unsigned char *hs_msg;              /*!<  Reassembled handshake message  */

    uint32_t retransmit_timeout;        /*!<  Current value of timeout       */
    unsigned char retransmit_state;     /*!<  Retransmission state           */
    mbedtls_ssl_flight_item *flight;            /*!<  Current outgoing flight        */
    mbedtls_ssl_flight_item *cur_msg;           /*!<  Current message in flight      */
    unsigned int in_flight_start_seq;   /*!<  Minimum message sequence in the
                                              flight being received          */
    mbedtls_ssl_transform *alt_transform_out;   /*!<  Alternative transform for
                                              resending messages             */
    unsigned char alt_out_ctr[8];       /*!<  Alternative record epoch/counter
                                              for resending messages         */
#endif

    /*
     * Checksum contexts
     */
#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_1)
       mbedtls_md5_context fin_md5;
      mbedtls_sha1_context fin_sha1;
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_SHA256_C)
    mbedtls_sha256_context fin_sha256;
#endif
#if defined(MBEDTLS_SHA512_C)
    mbedtls_sha512_context fin_sha512;
#endif
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */

    void (*update_checksum)(mbedtls_ssl_context *, const unsigned char *, size_t);
    void (*calc_verify)(mbedtls_ssl_context *, unsigned char *);
    void (*calc_finished)(mbedtls_ssl_context *, unsigned char *, int);
    int  (*tls_prf)(const unsigned char *, size_t, const char *,
                    const unsigned char *, size_t,
                    unsigned char *, size_t);

    size_t pmslen;                      /*!<  premaster length        */

    unsigned char randbytes[64];        /*!<  random bytes            */
    unsigned char premaster[MBEDTLS_PREMASTER_SIZE];
                                        /*!<  premaster secret        */

    int resume;                         /*!<  session resume indicator*/
    int max_major_ver;                  /*!< max. major version client*/
    int max_minor_ver;                  /*!< max. minor version client*/
    int cli_exts;                       /*!< client extension presence*/

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    int new_session_ticket;             /*!< use NewSessionTicket?    */
#endif /* MBEDTLS_SSL_SESSION_TICKETS */
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    int extended_ms;                    /*!< use Extended Master Secret? */
#endif
};

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
/*
 * Parameters needed to secure session tickets
 */
struct mbedtls_ssl_ticket_keys
{
    unsigned char key_name[16];     /*!< name to quickly discard bad tickets */
    mbedtls_aes_context enc;                /*!< encryption context                  */
    mbedtls_aes_context dec;                /*!< decryption context                  */
    unsigned char mac_key[16];      /*!< authentication key                  */
    uint32_t ticket_lifetime;
};
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
/*
 * List of certificate + private key pairs
 */
struct mbedtls_ssl_key_cert
{
    mbedtls_x509_crt *cert;                 /*!< cert                       */
    mbedtls_pk_context *key;                /*!< private key                */
    mbedtls_ssl_key_cert *next;             /*!< next key/cert pair         */
};
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
/*
 * List of handshake messages kept around for resending
 */
struct mbedtls_ssl_flight_item
{
    unsigned char *p;       /*!< message, including handshake headers   */
    size_t len;             /*!< length of p                            */
    unsigned char type;     /*!< type of the message: handshake or CCS  */
    mbedtls_ssl_flight_item *next;  /*!< next handshake message(s)              */
};
#endif /* MBEDTLS_SSL_PROTO_DTLS */

/**
 * SSL/TLS configuration to be shared between mbedtls_ssl_context structures.
 */
typedef struct
{
    /* Group items by size (largest first) to minimize padding overhead */

    /*
     * Pointers
     */

    const int *ciphersuite_list[4]; /*!< allowed ciphersuites per version   */

    /** Callback for printing debug output                                  */
    void (*f_dbg)(void *, int, const char *);
    void *p_dbg;                    /*!< context for the debug function     */

    /** Callback for getting (pseudo-)random numbers                        */
    int  (*f_rng)(void *, unsigned char *, size_t);
    void *p_rng;                    /*!< context for the RNG function       */

    /** Callback to retrieve a session from the cache                       */
    int (*f_get_cache)(void *, mbedtls_ssl_session *);
    /** Callback to store a session into the cache                          */
    int (*f_set_cache)(void *, const mbedtls_ssl_session *);
    void *p_cache;                  /*!< context for cache callbacks        */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    /** Callback for setting cert according to SNI extension                */
    int (*f_sni)(void *, mbedtls_ssl_context *, const unsigned char *, size_t);
    void *p_sni;                    /*!< context for SNI callback           */
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    /** Callback to customize X.509 certificate chain verification          */
    int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *);
    void *p_vrfy;                   /*!< context for X.509 verify calllback */
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    /** Callback to retrieve PSK key from identity                          */
    int (*f_psk)(void *, mbedtls_ssl_context *, const unsigned char *, size_t);
    void *p_psk;                    /*!< context for PSK callback           */
#endif

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
    /** Callback to create & write a cookie for ClientHello veirifcation    */
    int (*f_cookie_write)( void *, unsigned char **, unsigned char *,
                           const unsigned char *, size_t );
    /** Callback to verify validity of a ClientHello cookie                 */
    int (*f_cookie_check)( void *, const unsigned char *, size_t,
                           const unsigned char *, size_t );
    void *p_cookie;                 /*!< context for the cookie callbacks   */
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_key_cert *key_cert; /*!< own certificate/key pair(s)        */
    mbedtls_x509_crt *ca_chain;     /*!< trusted CAs                        */
    mbedtls_x509_crl *ca_crl;       /*!< trusted CAs CRLs                   */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_SET_CURVES)
    const mbedtls_ecp_group_id *curve_list; /*!< allowed curves             */
#endif

#if defined(MBEDTLS_DHM_C)
    mbedtls_mpi dhm_P;              /*!< prime modulus for DHM              */
    mbedtls_mpi dhm_G;              /*!< generator for DHM                  */
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    unsigned char *psk;             /*!< pre-shared key                     */
    size_t         psk_len;         /*!< length of the pre-shared key       */
    unsigned char *psk_identity;    /*!< identity for PSK negotiation       */
    size_t         psk_identity_len;/*!< length of identity                 */
#endif

#if defined(MBEDTLS_SSL_ALPN)
    const char **alpn_list;         /*!< ordered list of protocols          */
#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_ticket_keys *ticket_keys;       /*!<  keys for ticket encryption */
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

    /*
     * Numerical settings (int then char)
     */

    uint32_t read_timeout;          /*!< timeout for mbedtls_ssl_read (ms)  */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    uint32_t hs_timeout_min;        /*!< initial value of the handshake
                                         retransmission timeout (ms)        */
    uint32_t hs_timeout_max;        /*!< maximum value of the handshake
                                         retransmission timeout (ms)        */
#endif

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    int renego_max_records;         /*!< grace period for renegotiation     */
    unsigned char renego_period[8]; /*!< value of the record counters
                                         that triggers renegotiation        */
#endif

#if defined(MBEDTLS_SSL_DTLS_BADMAC_LIMIT)
    unsigned int badmac_limit;      /*!< limit of records with a bad MAC    */
#endif

    unsigned char max_major_ver;    /*!< max. major version used            */
    unsigned char max_minor_ver;    /*!< max. minor version used            */
    unsigned char min_major_ver;    /*!< min. major version used            */
    unsigned char min_minor_ver;    /*!< min. minor version used            */

    /*
     * Flags (bitfields)
     */

    unsigned int endpoint : 1;      /*!< 0: client, 1: server               */
    unsigned int transport : 1;     /*!< stream (TLS) or datagram (DTLS)    */
    unsigned int authmode : 2;      /*!< MBEDTLS_SSL_VERIFY_XXX             */
    /* needed even with renego disabled for LEGACY_BREAK_HANDSHAKE          */
    unsigned int allow_legacy_renegotiation : 2 ; /*!< MBEDTLS_LEGACY_XXX   */
#if defined(MBEDTLS_ARC4_C)
    unsigned int arc4_disabled : 1; /*!< blacklist RC4 ciphersuites?        */
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    unsigned int mfl_code : 3;      /*!< desired fragment length            */
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    unsigned int encrypt_then_mac : 1 ; /*!< negotiate encrypt-then-mac?    */
#endif
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    unsigned int extended_ms : 1;   /*!< negotiate extended master secret?  */
#endif
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    unsigned int anti_replay : 1;   /*!< detect and prevent replay?         */
#endif
#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
    unsigned int cbc_record_splitting : 1;  /*!< do cbc record splitting    */
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    unsigned int disable_renegotiation : 1; /*!< disable renegotiation?     */
#endif
#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
    unsigned int trunc_hmac : 1;    /*!< negotiate truncated hmac?          */
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    unsigned int session_tickets : 1;   /*!< use session tickets?           */
#endif
#if defined(MBEDTLS_SSL_FALLBACK_SCSV) && defined(MBEDTLS_SSL_CLI_C)
    unsigned int fallback : 1;      /*!< is this a fallback?                */
#endif
}
mbedtls_ssl_config;

struct mbedtls_ssl_context
{
    const mbedtls_ssl_config *conf; /*!< configuration information          */

    /*
     * Miscellaneous
     */
    int state;                  /*!< SSL handshake: current state     */
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    int renego_status;          /*!< Initial, in progress, pending?   */
    int renego_records_seen;    /*!< Records since renego request, or with DTLS,
                                  number of retransmissions of request if
                                  renego_max_records is < 0           */
#endif

    int major_ver;              /*!< equal to  MBEDTLS_SSL_MAJOR_VERSION_3    */
    int minor_ver;              /*!< either 0 (SSL3) or 1 (TLS1.0)    */

#if defined(MBEDTLS_SSL_DTLS_BADMAC_LIMIT)
    unsigned badmac_seen;       /*!< records with a bad MAC received    */
#endif

    /*
     * Callbacks
     */
    int (*f_send)(void *, const unsigned char *, size_t);
    int (*f_recv)(void *, unsigned char *, size_t);
    int (*f_recv_timeout)(void *, unsigned char *, size_t, uint32_t);
    void *p_bio;                /*!< context for I/O operations   */

    /*
     * Session layer
     */
    mbedtls_ssl_session *session_in;            /*!<  current session data (in)   */
    mbedtls_ssl_session *session_out;           /*!<  current session data (out)  */
    mbedtls_ssl_session *session;               /*!<  negotiated session data     */
    mbedtls_ssl_session *session_negotiate;     /*!<  session data in negotiation */

    mbedtls_ssl_handshake_params *handshake;    /*!<  params required only during
                                              the handshake process        */

    /*
     * Record layer transformations
     */
    mbedtls_ssl_transform *transform_in;        /*!<  current transform params (in)   */
    mbedtls_ssl_transform *transform_out;       /*!<  current transform params (in)   */
    mbedtls_ssl_transform *transform;           /*!<  negotiated transform params     */
    mbedtls_ssl_transform *transform_negotiate; /*!<  transform params in negotiation */

    /*
     * Timers
     */
    void *p_timer;              /*!< context for the timer callbacks */
    void (*f_set_timer)(void *, uint32_t, uint32_t); /*!< set timer callback */
    int (*f_get_timer)(void *); /*!< get timer callback             */

    /*
     * Record layer (incoming data)
     */
    unsigned char *in_buf;      /*!< input buffer                     */
    unsigned char *in_ctr;      /*!< 64-bit incoming message counter
                                     TLS: maintained by us
                                     DTLS: read from peer             */
    unsigned char *in_hdr;      /*!< start of record header           */
    unsigned char *in_len;      /*!< two-bytes message length field   */
    unsigned char *in_iv;       /*!< ivlen-byte IV                    */
    unsigned char *in_msg;      /*!< message contents (in_iv+ivlen)   */
    unsigned char *in_offt;     /*!< read offset in application data  */

    int in_msgtype;             /*!< record header: message type      */
    size_t in_msglen;           /*!< record header: message length    */
    size_t in_left;             /*!< amount of data read so far       */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    uint16_t in_epoch;          /*!< DTLS epoch for incoming records  */
    size_t next_record_offset;  /*!< offset of the next record in datagram
                                     (equal to in_left if none)       */
#endif
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    uint64_t in_window_top;     /*!< last validated record seq_num    */
    uint64_t in_window;         /*!< bitmask for replay detection     */
#endif

    size_t in_hslen;            /*!< current handshake message length,
                                     including the handshake header   */
    int nb_zero;                /*!< # of 0-length encrypted messages */
    int record_read;            /*!< record is already present        */

    /*
     * Record layer (outgoing data)
     */
    unsigned char *out_buf;     /*!< output buffer                    */
    unsigned char *out_ctr;     /*!< 64-bit outgoing message counter  */
    unsigned char *out_hdr;     /*!< start of record header           */
    unsigned char *out_len;     /*!< two-bytes message length field   */
    unsigned char *out_iv;      /*!< ivlen-byte IV                    */
    unsigned char *out_msg;     /*!< message contents (out_iv+ivlen)  */

    int out_msgtype;            /*!< record header: message type      */
    size_t out_msglen;          /*!< record header: message length    */
    size_t out_left;            /*!< amount of data not yet written   */

#if defined(MBEDTLS_ZLIB_SUPPORT)
    unsigned char *compress_buf;        /*!<  zlib data buffer        */
#endif
#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
    signed char split_done;     /*!< current record already splitted? */
#endif

    /*
     * PKI layer
     */
    int client_auth;                    /*!<  flag for client auth.   */
    int verify_result;                  /*!<  verification result     */

    /*
     * User settings
     */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    char *hostname;             /*!< expected peer CN for verification
                                     (and SNI if available)                 */
#endif

#if defined(MBEDTLS_SSL_ALPN)
    const char *alpn_chosen;    /*!<  negotiated protocol                   */
#endif

    /*
     * Information for DTLS hello verify
     */
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
    unsigned char  *cli_id;         /*!<  transport-level ID of the client  */
    size_t          cli_id_len;     /*!<  length of cli_id                  */
#endif

    /*
     * Secure renegotiation
     */
    /* needed to know when to send extension on server */
    int secure_renegotiation;           /*!<  does peer support legacy or
                                              secure renegotiation           */
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    size_t verify_data_len;             /*!<  length of verify data stored   */
    char own_verify_data[MBEDTLS_SSL_VERIFY_DATA_MAX_LEN]; /*!<  previous handshake verify data */
    char peer_verify_data[MBEDTLS_SSL_VERIFY_DATA_MAX_LEN]; /*!<  previous handshake verify data */
#endif
};

#if defined(MBEDTLS_SSL_HW_RECORD_ACCEL)

#define MBEDTLS_SSL_CHANNEL_OUTBOUND    0
#define MBEDTLS_SSL_CHANNEL_INBOUND     1

extern int (*mbedtls_ssl_hw_record_init)(mbedtls_ssl_context *ssl,
                const unsigned char *key_enc, const unsigned char *key_dec,
                size_t keylen,
                const unsigned char *iv_enc,  const unsigned char *iv_dec,
                size_t ivlen,
                const unsigned char *mac_enc, const unsigned char *mac_dec,
                size_t maclen);
extern int (*mbedtls_ssl_hw_record_activate)(mbedtls_ssl_context *ssl, int direction);
extern int (*mbedtls_ssl_hw_record_reset)(mbedtls_ssl_context *ssl);
extern int (*mbedtls_ssl_hw_record_write)(mbedtls_ssl_context *ssl);
extern int (*mbedtls_ssl_hw_record_read)(mbedtls_ssl_context *ssl);
extern int (*mbedtls_ssl_hw_record_finish)(mbedtls_ssl_context *ssl);
#endif /* MBEDTLS_SSL_HW_RECORD_ACCEL */

/**
 * \brief Returns the list of ciphersuites supported by the SSL/TLS module.
 *
 * \return              a statically allocated array of ciphersuites, the last
 *                      entry is 0.
 */
const int *mbedtls_ssl_list_ciphersuites( void );

/**
 * \brief               Return the name of the ciphersuite associated with the
 *                      given ID
 *
 * \param ciphersuite_id SSL ciphersuite ID
 *
 * \return              a string containing the ciphersuite name
 */
const char *mbedtls_ssl_get_ciphersuite_name( const int ciphersuite_id );

/**
 * \brief               Return the ID of the ciphersuite associated with the
 *                      given name
 *
 * \param ciphersuite_name SSL ciphersuite name
 *
 * \return              the ID with the ciphersuite or 0 if not found
 */
int mbedtls_ssl_get_ciphersuite_id( const char *ciphersuite_name );

/**
 * \brief          Initialize an SSL context
 *                 Just makes the context ready for mbetls_ssl_setup() or
 *                 mbedtls_ssl_free()
 *
 * \param ssl      SSL context
 */
void mbedtls_ssl_init( mbedtls_ssl_context *ssl );

/**
 * \brief          Set up an SSL context for use
 *
 * \note           No copy of the configuration context is made, it can be
 *                 shared by many mbedtls_ssl_context structures.
 *
 * \warning        Modifying the conf structure after is has been used in this
 *                 function is unsupported!
 *
 * \param ssl      SSL context
 * \param conf     SSL configuration to use
 *
 * \return         0 if successful, or MBEDTLS_ERR_SSL_MALLOC_FAILED if
 *                 memory allocation failed
 */
int mbedtls_ssl_setup( mbedtls_ssl_context *ssl,
                       const mbedtls_ssl_config *conf );

/**
 * \brief          Reset an already initialized SSL context for re-use
 *                 while retaining application-set variables, function
 *                 pointers and data.
 *
 * \param ssl      SSL context
 * \return         0 if successful, or POLASSL_ERR_SSL_MALLOC_FAILED,
                   MBEDTLS_ERR_SSL_HW_ACCEL_FAILED or
 *                 MBEDTLS_ERR_SSL_COMPRESSION_FAILED
 */
int mbedtls_ssl_session_reset( mbedtls_ssl_context *ssl );

/**
 * \brief          Set the current endpoint type
 *
 * \param conf     SSL configuration
 * \param endpoint must be MBEDTLS_SSL_IS_CLIENT or MBEDTLS_SSL_IS_SERVER
 */
void mbedtls_ssl_conf_endpoint( mbedtls_ssl_config *conf, int endpoint );

/**
 * \brief           Set the transport type (TLS or DTLS).
 *                  Default: TLS
 *
 * \note            For DTLS, you must either provide a recv callback that
 *                  doesn't block, or one that handles timeouts, see
 *                  \c mbedtls_ssl_set_bio(). You also need to provide timer
 *                  callbacks with \c mbedtls_ssl_set_timer_cb().
 *
 * \param conf      SSL configuration
 * \param transport transport type:
 *                  MBEDTLS_SSL_TRANSPORT_STREAM for TLS,
 *                  MBEDTLS_SSL_TRANSPORT_DATAGRAM for DTLS.
 */
void mbedtls_ssl_conf_transport( mbedtls_ssl_config *conf, int transport );

/**
 * \brief          Set the certificate verification mode
 *                 Default: NONE on server, REQUIRED on client
 *
 * \param conf     SSL configuration
 * \param authmode can be:
 *
 *  MBEDTLS_SSL_VERIFY_NONE:      peer certificate is not checked
 *                        (default on server)
 *                        (insecure on client)
 *
 *  MBEDTLS_SSL_VERIFY_OPTIONAL:  peer certificate is checked, however the
 *                        handshake continues even if verification failed;
 *                        mbedtls_ssl_get_verify_result() can be called after the
 *                        handshake is complete.
 *
 *  MBEDTLS_SSL_VERIFY_REQUIRED:  peer *must* present a valid certificate,
 *                        handshake is aborted if verification failed.
 *
 * \note On client, MBEDTLS_SSL_VERIFY_REQUIRED is the recommended mode.
 * With MBEDTLS_SSL_VERIFY_OPTIONAL, the user needs to call mbedtls_ssl_get_verify_result() at
 * the right time(s), which may not be obvious, while REQUIRED always perform
 * the verification as soon as possible. For example, REQUIRED was protecting
 * against the "triple handshake" attack even before it was found.
 */
void mbedtls_ssl_conf_authmode( mbedtls_ssl_config *conf, int authmode );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
/**
 * \brief          Set the verification callback (Optional).
 *
 *                 If set, the verify callback is called for each
 *                 certificate in the chain. For implementation
 *                 information, please see \c x509parse_verify()
 *
 * \param conf     SSL configuration
 * \param f_vrfy   verification function
 * \param p_vrfy   verification parameter
 */
void mbedtls_ssl_conf_verify( mbedtls_ssl_config *conf,
                     int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                     void *p_vrfy );
#endif /* MBEDTLS_X509_CRT_PARSE_C */

/**
 * \brief          Set the random number generator callback
 *
 * \param conf     SSL configuration
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 */
void mbedtls_ssl_conf_rng( mbedtls_ssl_config *conf,
                  int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng );

/**
 * \brief          Set the debug callback
 *
 * \param conf     SSL configuration
 * \param f_dbg    debug function
 * \param p_dbg    debug parameter
 */
void mbedtls_ssl_conf_dbg( mbedtls_ssl_config *conf,
                  void (*f_dbg)(void *, int, const char *),
                  void  *p_dbg );

/**
 * \brief          Set the underlying BIO callbacks for write, read and
 *                 read-with-timeout.
 *
 * \param ssl      SSL context
 * \param p_bio    parameter (context) shared by BIO callbacks
 * \param f_send   write callback
 * \param f_recv   read callback
 * \param f_recv_timeout blocking read callback with timeout.
 *                 The last argument is the timeout in milliseconds,
 *                 0 means no timeout
 *
 * \note           One of f_recv or f_recv_timeout can be NULL, in which case
 *                 the other is used. If both are non-NULL, f_recv_timeout is
 *                 used and f_recv is ignored (as if it were NULL).
 *
 * \note           The two most common use cases are:
 *                 - non-blocking I/O, f_recv != NULL, f_recv_timeout == NULL
 *                 - blocking I/O, f_recv == NULL, f_recv_timout != NULL
 *
 * \note           For DTLS, you need to provide either a non-NULL
 *                 f_recv_timeout callback, or a f_recv that doesn't block.
 */
void mbedtls_ssl_set_bio( mbedtls_ssl_context *ssl,
        void *p_bio,
        int (*f_send)(void *, const unsigned char *, size_t),
        int (*f_recv)(void *, unsigned char *, size_t),
        int (*f_recv_timeout)(void *, unsigned char *, size_t, uint32_t) );

/**
 * \brief          Set the timeout period for mbedtls_ssl_read()
 *                 (Default: no timeout.)
 *
 * \param conf     SSL configuration context
 * \param timeout  Timeout value in milliseconds.
 *                 Use 0 for no timeout (default).
 *
 * \note           With blocking I/O, this will only work if a non-NULL
 *                 \c f_recv_timeout was set with \c mbedtls_ssl_set_bio().
 *                 With non-blocking I/O, this will only work if timer
 *                 callbacks were set with \c mbedtls_ssl_set_timer_cb().
 *
 * \note           With non-blocking I/O, you may also skip this function
 *                 altogether and handle timeouts at the application layer.
 */
void mbedtls_ssl_conf_read_timeout( mbedtls_ssl_config *conf, uint32_t timeout );

/**
 * \brief          Set the timer callbacks
 *                 (Mandatory for DTLS.)
 *
 * \param ssl      SSL context
 * \param p_timer  parameter (context) shared by timer callback
 * \param f_set_timer   set timer callback
 *                 Accepts an intermediate and a final delay in milliseconcs
 *                 If the final delay is 0, cancels the running timer.
 * \param f_get_timer   get timer callback. Must return:
 *                 -1 if cancelled
 *                 0 if none of the delays is expired
 *                 1 if the intermediate delay only is expired
 *                 2 if the final delay is expired
 */
void mbedtls_ssl_set_timer_cb( mbedtls_ssl_context *ssl,
                               void *p_timer,
                               void (*f_set_timer)(void *, uint32_t int_ms, uint32_t fin_ms),
                               int (*f_get_timer)(void *) );

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
/**
 * \brief          Set client's transport-level identification info.
 *                 (Server only. DTLS only.)
 *
 *                 This is usually the IP address (and port), but could be
 *                 anything identify the client depending on the underlying
 *                 network stack. Used for HelloVerifyRequest with DTLS.
 *                 This is *not* used to route the actual packets.
 *
 * \param ssl      SSL context
 * \param info     Transport-level info identifying the client (eg IP + port)
 * \param ilen     Length of info in bytes
 *
 * \note           An internal copy is made, so the info buffer can be reused.
 *
 * \return         0 on success,
 *                 MBEDTLS_ERR_SSL_BAD_INPUT_DATA if used on client,
 *                 MBEDTLS_ERR_SSL_MALLOC_FAILED if out of memory.
 */
int mbedtls_ssl_set_client_transport_id( mbedtls_ssl_context *ssl,
                                 const unsigned char *info,
                                 size_t ilen );

/**
 * \brief          Callback type: generate a cookie
 *
 * \param ctx      Context for the callback
 * \param p        Buffer to write to,
 *                 must be updated to point right after the cookie
 * \param end      Pointer to one past the end of the output buffer
 * \param info     Client ID info that was passed to
 *                 \c mbedtls_ssl_set_client_transport_id()
 * \param ilen     Length of info in bytes
 *
 * \return         The callback must return 0 on success,
 *                 or a negative error code.
 */
typedef int mbedtls_ssl_cookie_write_t( void *ctx,
                                unsigned char **p, unsigned char *end,
                                const unsigned char *info, size_t ilen );

/**
 * \brief          Callback type: verify a cookie
 *
 * \param ctx      Context for the callback
 * \param cookie   Cookie to verify
 * \param clen     Length of cookie
 * \param info     Client ID info that was passed to
 *                 \c mbedtls_ssl_set_client_transport_id()
 * \param ilen     Length of info in bytes
 *
 * \return         The callback must return 0 if cookie is valid,
 *                 or a negative error code.
 */
typedef int mbedtls_ssl_cookie_check_t( void *ctx,
                                const unsigned char *cookie, size_t clen,
                                const unsigned char *info, size_t ilen );

/**
 * \brief           Register callbacks for DTLS cookies
 *                  (Server only. DTLS only.)
 *
 *                  Default: dummy callbacks that fail, to force you to
 *                  register working callbacks (and initialize their context).
 *
 *                  To disable HelloVerifyRequest, register NULL callbacks.
 *
 * \warning         Disabling hello verification allows your server to be used
 *                  for amplification in DoS attacks against other hosts.
 *                  Only disable if you known this can't happen in your
 *                  particular environment.
 *
 * \param conf              SSL configuration
 * \param f_cookie_write    Cookie write callback
 * \param f_cookie_check    Cookie check callback
 * \param p_cookie          Context for both callbacks
 */
void mbedtls_ssl_conf_dtls_cookies( mbedtls_ssl_config *conf,
                           mbedtls_ssl_cookie_write_t *f_cookie_write,
                           mbedtls_ssl_cookie_check_t *f_cookie_check,
                           void *p_cookie );
#endif /* MBEDTLS_SSL_DTLS_HELLO_VERIFY */

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
/**
 * \brief          Enable or disable anti-replay protection for DTLS.
 *                 (DTLS only, no effect on TLS.)
 *                 Default: enabled.
 *
 * \param conf     SSL configuration
 * \param mode     MBEDTLS_SSL_ANTI_REPLAY_ENABLED or MBEDTLS_SSL_ANTI_REPLAY_DISABLED.
 *
 * \warning        Disabling this is a security risk unless the application
 *                 protocol handles duplicated packets in a safe way. You
 *                 should not disable this without careful consideration.
 *                 However, if your application already detects duplicated
 *                 packets and needs information about them to adjust its
 *                 transmission strategy, then you'll want to disable this.
 */
void mbedtls_ssl_conf_dtls_anti_replay( mbedtls_ssl_config *conf, char mode );
#endif /* MBEDTLS_SSL_DTLS_ANTI_REPLAY */

#if defined(MBEDTLS_SSL_DTLS_BADMAC_LIMIT)
/**
 * \brief          Set a limit on the number of records with a bad MAC
 *                 before terminating the connection.
 *                 (DTLS only, no effect on TLS.)
 *                 Default: 0 (disabled).
 *
 * \param conf     SSL configuration
 * \param limit    Limit, or 0 to disable.
 *
 * \note           If the limit is N, then the connection is terminated when
 *                 the Nth non-authentic record is seen.
 *
 * \note           Records with an invalid header are not counted, only the
 *                 ones going through the authentication-decryption phase.
 *
 * \note           This is a security trade-off related to the fact that it's
 *                 often relatively easy for an active attacker ot inject UDP
 *                 datagrams. On one hand, setting a low limit here makes it
 *                 easier for such an attacker to forcibly terminated a
 *                 connection. On the other hand, a high limit or no limit
 *                 might make us waste resources checking authentication on
 *                 many bogus packets.
 */
void mbedtls_ssl_conf_dtls_badmac_limit( mbedtls_ssl_config *conf, unsigned limit );
#endif /* MBEDTLS_SSL_DTLS_BADMAC_LIMIT */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
/**
 * \brief          Set retransmit timeout values for the DTLS handshale.
 *                 (DTLS only, no effect on TLS.)
 *
 * \param conf     SSL configuration
 * \param min      Initial timeout value in milliseconds.
 *                 Default: 1000 (1 second).
 * \param max      Maximum timeout value in milliseconds.
 *                 Default: 60000 (60 seconds).
 *
 * \note           Default values are from RFC 6347 section 4.2.4.1.
 *
 * \note           Higher values for initial timeout may increase average
 *                 handshake latency. Lower values may increase the risk of
 *                 network congestion by causing more retransmissions.
 */
void mbedtls_ssl_conf_handshake_timeout( mbedtls_ssl_config *conf, uint32_t min, uint32_t max );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_SRV_C)
/**
 * \brief          Set the session cache callbacks (server-side only)
 *                 If not set, no session resuming is done (except if session
 *                 tickets are enabled too).
 *
 *                 The session cache has the responsibility to check for stale
 *                 entries based on timeout. See RFC 5246 for recommendations.
 *
 *                 Warning: session.peer_cert is cleared by the SSL/TLS layer on
 *                 connection shutdown, so do not cache the pointer! Either set
 *                 it to NULL or make a full copy of the certificate.
 *
 *                 The get callback is called once during the initial handshake
 *                 to enable session resuming. The get function has the
 *                 following parameters: (void *parameter, mbedtls_ssl_session *session)
 *                 If a valid entry is found, it should fill the master of
 *                 the session object with the cached values and return 0,
 *                 return 1 otherwise. Optionally peer_cert can be set as well
 *                 if it is properly present in cache entry.
 *
 *                 The set callback is called once during the initial handshake
 *                 to enable session resuming after the entire handshake has
 *                 been finished. The set function has the following parameters:
 *                 (void *parameter, const mbedtls_ssl_session *session). The function
 *                 should create a cache entry for future retrieval based on
 *                 the data in the session structure and should keep in mind
 *                 that the mbedtls_ssl_session object presented (and all its referenced
 *                 data) is cleared by the SSL/TLS layer when the connection is
 *                 terminated. It is recommended to add metadata to determine if
 *                 an entry is still valid in the future. Return 0 if
 *                 successfully cached, return 1 otherwise.
 *
 * \param conf           SSL configuration
 * \param p_cache        parmater (context) for both callbacks
 * \param f_get_cache    session get callback
 * \param f_set_cache    session set callback
 */
void mbedtls_ssl_conf_session_cache( mbedtls_ssl_config *conf,
        void *p_cache,
        int (*f_get_cache)(void *, mbedtls_ssl_session *),
        int (*f_set_cache)(void *, const mbedtls_ssl_session *) );
#endif /* MBEDTLS_SSL_SRV_C */

#if defined(MBEDTLS_SSL_CLI_C)
/**
 * \brief          Request resumption of session (client-side only)
 *                 Session data is copied from presented session structure.
 *
 * \param ssl      SSL context
 * \param session  session context
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_SSL_MALLOC_FAILED if memory allocation failed,
 *                 MBEDTLS_ERR_SSL_BAD_INPUT_DATA if used server-side or
 *                 arguments are otherwise invalid
 *
 * \sa             mbedtls_ssl_get_session()
 */
int mbedtls_ssl_set_session( mbedtls_ssl_context *ssl, const mbedtls_ssl_session *session );
#endif /* MBEDTLS_SSL_CLI_C */

/**
 * \brief               Set the list of allowed ciphersuites and the preference
 *                      order. First in the list has the highest preference.
 *                      (Overrides all version specific lists)
 *
 *                      The ciphersuites array is not copied, and must remain
 *                      valid for the lifetime of the ssl_config.
 *
 *                      Note: The server uses its own preferences
 *                      over the preference of the client unless
 *                      MBEDTLS_SSL_SRV_RESPECT_CLIENT_PREFERENCE is defined!
 *
 * \param conf          SSL configuration
 * \param ciphersuites  0-terminated list of allowed ciphersuites
 */
void mbedtls_ssl_conf_ciphersuites( mbedtls_ssl_config *conf,
                                   const int *ciphersuites );

/**
 * \brief               Set the list of allowed ciphersuites and the
 *                      preference order for a specific version of the protocol.
 *                      (Only useful on the server side)
 *
 *                      The ciphersuites array is not copied, and must remain
 *                      valid for the lifetime of the ssl_config.
 *
 * \param conf          SSL configuration
 * \param ciphersuites  0-terminated list of allowed ciphersuites
 * \param major         Major version number (only MBEDTLS_SSL_MAJOR_VERSION_3
 *                      supported)
 * \param minor         Minor version number (MBEDTLS_SSL_MINOR_VERSION_0,
 *                      MBEDTLS_SSL_MINOR_VERSION_1 and MBEDTLS_SSL_MINOR_VERSION_2,
 *                      MBEDTLS_SSL_MINOR_VERSION_3 supported)
 *
 * \note                With DTLS, use MBEDTLS_SSL_MINOR_VERSION_2 for DTLS 1.0
 *                      and MBEDTLS_SSL_MINOR_VERSION_3 for DTLS 1.2
 */
void mbedtls_ssl_conf_ciphersuites_for_version( mbedtls_ssl_config *conf,
                                       const int *ciphersuites,
                                       int major, int minor );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
/**
 * \brief          Set the data required to verify peer certificate
 *
 * \param conf     SSL configuration
 * \param ca_chain trusted CA chain (meaning all fully trusted top-level CAs)
 * \param ca_crl   trusted CA CRLs
 */
void mbedtls_ssl_conf_ca_chain( mbedtls_ssl_config *conf,
                               mbedtls_x509_crt *ca_chain,
                               mbedtls_x509_crl *ca_crl );

/**
 * \brief          Set own certificate chain and private key
 *
 * \note           own_cert should contain in order from the bottom up your
 *                 certificate chain. The top certificate (self-signed)
 *                 can be omitted.
 *
 * \note           On server, this function can be called multiple times to
 *                 provision more than one cert/key pair (eg one ECDSA, one
 *                 RSA with SHA-256, one RSA with SHA-1). An adequate
 *                 certificate will be selected according to the client's
 *                 advertised capabilities. In case mutliple certificates are
 *                 adequate, preference is given to the one set by the first
 *                 call to this function, then second, etc.
 *
 * \note           On client, only the first call has any effect.
 *
 * \param conf     SSL configuration
 * \param own_cert own public certificate chain
 * \param pk_key   own private key
 *
 * \return         0 on success or MBEDTLS_ERR_SSL_MALLOC_FAILED
 */
int mbedtls_ssl_conf_own_cert( mbedtls_ssl_config *conf,
                              mbedtls_x509_crt *own_cert,
                              mbedtls_pk_context *pk_key );
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
/**
 * \brief          Set the Pre Shared Key (PSK) and the expected identity name
 *
 * \note           This is mainly useful for clients. Servers will usually
 *                 want to use \c mbedtls_ssl_conf_psk_cb() instead.
 *
 * \param conf     SSL configuration
 * \param psk      pointer to the pre-shared key
 * \param psk_len  pre-shared key length
 * \param psk_identity      pointer to the pre-shared key identity
 * \param psk_identity_len  identity key length
 *
 * \return         0 if successful or MBEDTLS_ERR_SSL_MALLOC_FAILED
 */
int mbedtls_ssl_conf_psk( mbedtls_ssl_config *conf,
                const unsigned char *psk, size_t psk_len,
                const unsigned char *psk_identity, size_t psk_identity_len );


/**
 * \brief          Set the Pre Shared Key (PSK) for the current handshake
 *
 * \note           This should only be called inside the PSK callback,
 *                 ie the function passed to \c mbedtls_ssl_conf_psk_cb().
 *
 * \param ssl      SSL context
 * \param psk      pointer to the pre-shared key
 * \param psk_len  pre-shared key length
 *
 * \return         0 if successful or MBEDTLS_ERR_SSL_MALLOC_FAILED
 */
int mbedtls_ssl_set_hs_psk( mbedtls_ssl_context *ssl,
                            const unsigned char *psk, size_t psk_len );

/**
 * \brief          Set the PSK callback (server-side only).
 *
 *                 If set, the PSK callback is called for each
 *                 handshake where a PSK ciphersuite was negotiated.
 *                 The caller provides the identity received and wants to
 *                 receive the actual PSK data and length.
 *
 *                 The callback has the following parameters: (void *parameter,
 *                 mbedtls_ssl_context *ssl, const unsigned char *psk_identity,
 *                 size_t identity_len)
 *                 If a valid PSK identity is found, the callback should use
 *                 \c mbedtls_ssl_set_hs_psk() on the ssl context to set the
 *                 correct PSK and return 0.
 *                 Any other return value will result in a denied PSK identity.
 *
 * \note           If you set a PSK callback using this function, then you
 *                 don't need to set a PSK key and identity using
 *                 \c mbedtls_ssl_conf_psk().
 *
 * \param conf     SSL configuration
 * \param f_psk    PSK identity function
 * \param p_psk    PSK identity parameter
 */
void mbedtls_ssl_conf_psk_cb( mbedtls_ssl_config *conf,
                     int (*f_psk)(void *, mbedtls_ssl_context *, const unsigned char *,
                                  size_t),
                     void *p_psk );
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_SRV_C)
/**
 * \brief          Set the Diffie-Hellman public P and G values,
 *                 read as hexadecimal strings (server-side only)
 *                 (Default: MBEDTLS_DHM_RFC5114_MODP_2048_[PG])
 *
 * \param conf     SSL configuration
 * \param dhm_P    Diffie-Hellman-Merkle modulus
 * \param dhm_G    Diffie-Hellman-Merkle generator
 *
 * \return         0 if successful
 */
int mbedtls_ssl_conf_dh_param( mbedtls_ssl_config *conf, const char *dhm_P, const char *dhm_G );

/**
 * \brief          Set the Diffie-Hellman public P and G values,
 *                 read from existing context (server-side only)
 *
 * \param conf     SSL configuration
 * \param dhm_ctx  Diffie-Hellman-Merkle context
 *
 * \return         0 if successful
 */
int mbedtls_ssl_conf_dh_param_ctx( mbedtls_ssl_config *conf, mbedtls_dhm_context *dhm_ctx );
#endif /* MBEDTLS_DHM_C */

#if defined(MBEDTLS_SSL_SET_CURVES)
/**
 * \brief          Set the allowed curves in order of preference.
 *                 (Default: all defined curves.)
 *
 *                 On server: this only affects selection of the ECDHE curve;
 *                 the curves used for ECDH and ECDSA are determined by the
 *                 list of available certificates instead.
 *
 *                 On client: this affects the list of curves offered for any
 *                 use. The server can override our preference order.
 *
 *                 Both sides: limits the set of curves used by peer to the
 *                 listed curves for any use (ECDH(E), certificates).
 *
 * \param conf     SSL configuration
 * \param curves   Ordered list of allowed curves,
 *                 terminated by MBEDTLS_ECP_DP_NONE.
 */
void mbedtls_ssl_conf_curves( mbedtls_ssl_config *conf, const mbedtls_ecp_group_id *curves );
#endif /* MBEDTLS_SSL_SET_CURVES */

#if defined(MBEDTLS_X509_CRT_PARSE_C)
/**
 * \brief          Set hostname for ServerName TLS extension
 *                 (client-side only)
 *
 *
 * \param ssl      SSL context
 * \param hostname the server hostname
 *
 * \return         0 if successful or MBEDTLS_ERR_SSL_MALLOC_FAILED
 */
int mbedtls_ssl_set_hostname( mbedtls_ssl_context *ssl, const char *hostname );
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
/**
 * \brief          Set own certificate and key for the current handshake
 *
 * \note           Same as \c mbedtls_ssl_conf_own_cert() but for use within
 *                 the SNI callback.
 *
 * \param ssl      SSL context
 * \param own_cert own public certificate chain
 * \param pk_key   own private key
 *
 * \return         0 on success or MBEDTLS_ERR_SSL_MALLOC_FAILED
 */
int mbedtls_ssl_set_hs_own_cert( mbedtls_ssl_context *ssl,
                                 mbedtls_x509_crt *own_cert,
                                 mbedtls_pk_context *pk_key );

/**
 * \brief          Set the data required to verify peer certificate for the
 *                 current handshake
 *
 * \note           Same as \c mbedtls_ssl_conf_ca_chain() but for use within
 *                 the SNI callback.
 *
 * \param ssl      SSL context
 * \param ca_chain trusted CA chain (meaning all fully trusted top-level CAs)
 * \param ca_crl   trusted CA CRLs
 */
void mbedtls_ssl_set_hs_ca_chain( mbedtls_ssl_context *ssl,
                                  mbedtls_x509_crt *ca_chain,
                                  mbedtls_x509_crl *ca_crl );

/**
 * \brief          Set server side ServerName TLS extension callback
 *                 (optional, server-side only).
 *
 *                 If set, the ServerName callback is called whenever the
 *                 server receives a ServerName TLS extension from the client
 *                 during a handshake. The ServerName callback has the
 *                 following parameters: (void *parameter, mbedtls_ssl_context *ssl,
 *                 const unsigned char *hostname, size_t len). If a suitable
 *                 certificate is found, the callback should set the
 *                 certificate(s) and key(s) to use with \c
 *                 mbedtls_ssl_set_hs_own_cert() (can be called repeatedly),
 *                 and optionally adjust the CA with \c
 *                 mbedtls_ssl_set_hs_ca_chain() and return 0. The callback
 *                 should return -1 to abort the handshake at this point.
 *
 * \param conf     SSL configuration
 * \param f_sni    verification function
 * \param p_sni    verification parameter
 */
void mbedtls_ssl_conf_sni( mbedtls_ssl_config *conf,
                  int (*f_sni)(void *, mbedtls_ssl_context *, const unsigned char *,
                               size_t),
                  void *p_sni );
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */

#if defined(MBEDTLS_SSL_ALPN)
/**
 * \brief          Set the supported Application Layer Protocols.
 *
 * \param conf     SSL configuration
 * \param protos   NULL-terminated list of supported protocols,
 *                 in decreasing preference order.
 *
 * \return         0 on success, or MBEDTLS_ERR_SSL_BAD_INPUT_DATA.
 */
int mbedtls_ssl_conf_alpn_protocols( mbedtls_ssl_config *conf, const char **protos );

/**
 * \brief          Get the name of the negotiated Application Layer Protocol.
 *                 This function should be called after the handshake is
 *                 completed.
 *
 * \param ssl      SSL context
 *
 * \return         Protcol name, or NULL if no protocol was negotiated.
 */
const char *mbedtls_ssl_get_alpn_protocol( const mbedtls_ssl_context *ssl );
#endif /* MBEDTLS_SSL_ALPN */

/**
 * \brief          Set the maximum supported version sent from the client side
 *                 and/or accepted at the server side
 *                 (Default: MBEDTLS_SSL_MAX_MAJOR_VERSION, MBEDTLS_SSL_MAX_MINOR_VERSION)
 *
 * \note           This ignores ciphersuites from higher versions.
 *
 * \note           With DTLS, use MBEDTLS_SSL_MINOR_VERSION_2 for DTLS 1.0 and
 *                 MBEDTLS_SSL_MINOR_VERSION_3 for DTLS 1.2
 *
 * \param conf     SSL configuration
 * \param major    Major version number (only MBEDTLS_SSL_MAJOR_VERSION_3 supported)
 * \param minor    Minor version number (MBEDTLS_SSL_MINOR_VERSION_0,
 *                 MBEDTLS_SSL_MINOR_VERSION_1 and MBEDTLS_SSL_MINOR_VERSION_2,
 *                 MBEDTLS_SSL_MINOR_VERSION_3 supported)
 */
void mbedtls_ssl_conf_max_version( mbedtls_ssl_config *conf, int major, int minor );

/**
 * \brief          Set the minimum accepted SSL/TLS protocol version
 *                 (Default: TLS 1.0)
 *
 * \note           Input outside of the SSL_MAX_XXXXX_VERSION and
 *                 SSL_MIN_XXXXX_VERSION range is ignored.
 *
 * \note           MBEDTLS_SSL_MINOR_VERSION_0 (SSL v3) should be avoided.
 *
 * \note           With DTLS, use MBEDTLS_SSL_MINOR_VERSION_2 for DTLS 1.0 and
 *                 MBEDTLS_SSL_MINOR_VERSION_3 for DTLS 1.2
 *
 * \param conf     SSL configuration
 * \param major    Major version number (only MBEDTLS_SSL_MAJOR_VERSION_3 supported)
 * \param minor    Minor version number (MBEDTLS_SSL_MINOR_VERSION_0,
 *                 MBEDTLS_SSL_MINOR_VERSION_1 and MBEDTLS_SSL_MINOR_VERSION_2,
 *                 MBEDTLS_SSL_MINOR_VERSION_3 supported)
 */
void mbedtls_ssl_conf_min_version( mbedtls_ssl_config *conf, int major, int minor );

#if defined(MBEDTLS_SSL_FALLBACK_SCSV) && defined(MBEDTLS_SSL_CLI_C)
/**
 * \brief          Set the fallback flag (client-side only).
 *                 (Default: MBEDTLS_SSL_IS_NOT_FALLBACK).
 *
 * \note           Set to MBEDTLS_SSL_IS_FALLBACK when preparing a fallback
 *                 connection, that is a connection with max_version set to a
 *                 lower value than the value you're willing to use. Such
 *                 fallback connections are not recommended but are sometimes
 *                 necessary to interoperate with buggy (version-intolerant)
 *                 servers.
 *
 * \warning        You should NOT set this to MBEDTLS_SSL_IS_FALLBACK for
 *                 non-fallback connections! This would appear to work for a
 *                 while, then cause failures when the server is upgraded to
 *                 support a newer TLS version.
 *
 * \param conf     SSL configuration
 * \param fallback MBEDTLS_SSL_IS_NOT_FALLBACK or MBEDTLS_SSL_IS_FALLBACK
 */
void mbedtls_ssl_conf_fallback( mbedtls_ssl_config *conf, char fallback );
#endif /* MBEDTLS_SSL_FALLBACK_SCSV && MBEDTLS_SSL_CLI_C */

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
/**
 * \brief           Enable or disable Encrypt-then-MAC
 *                  (Default: MBEDTLS_SSL_ETM_ENABLED)
 *
 * \note            This should always be enabled, it is a security
 *                  improvement, and should not cause any interoperability
 *                  issue (used only if the peer supports it too).
 *
 * \param conf      SSL configuration
 * \param etm       MBEDTLS_SSL_ETM_ENABLED or MBEDTLS_SSL_ETM_DISABLED
 */
void mbedtls_ssl_conf_encrypt_then_mac( mbedtls_ssl_config *conf, char etm );
#endif /* MBEDTLS_SSL_ENCRYPT_THEN_MAC */

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
/**
 * \brief           Enable or disable Extended Master Secret negotiation.
 *                  (Default: MBEDTLS_SSL_EXTENDED_MS_ENABLED)
 *
 * \note            This should always be enabled, it is a security fix to the
 *                  protocol, and should not cause any interoperability issue
 *                  (used only if the peer supports it too).
 *
 * \param conf      SSL configuration
 * \param ems       MBEDTLS_SSL_EXTENDED_MS_ENABLED or MBEDTLS_SSL_EXTENDED_MS_DISABLED
 */
void mbedtls_ssl_conf_extended_master_secret( mbedtls_ssl_config *conf, char ems );
#endif /* MBEDTLS_SSL_EXTENDED_MASTER_SECRET */

#if defined(MBEDTLS_ARC4_C)
/**
 * \brief          Disable or enable support for RC4
 *                 (Default: MBEDTLS_SSL_ARC4_DISABLED)
 *
 * \warning        Use of RC4 in (D)TLS has been prohibited by RFC ????
 *                 for security reasons. Use at your own risks.
 *
 * \note           This function will likely be removed in future versions as
 *                 RC4 will then be disabled by default at compile time.
 *
 * \param conf     SSL configuration
 * \param arc4     MBEDTLS_SSL_ARC4_ENABLED or MBEDTLS_SSL_ARC4_DISABLED
 */
void mbedtls_ssl_conf_arc4_support( mbedtls_ssl_config *conf, char arc4 );
#endif /* MBEDTLS_ARC4_C */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
/**
 * \brief          Set the maximum fragment length to emit and/or negotiate
 *                 (Default: MBEDTLS_SSL_MAX_CONTENT_LEN, usually 2^14 bytes)
 *                 (Server: set maximum fragment length to emit,
 *                 usually negotiated by the client during handshake
 *                 (Client: set maximum fragment length to emit *and*
 *                 negotiate with the server during handshake)
 *
 * \param conf     SSL configuration
 * \param mfl_code Code for maximum fragment length (allowed values:
 *                 MBEDTLS_SSL_MAX_FRAG_LEN_512,  MBEDTLS_SSL_MAX_FRAG_LEN_1024,
 *                 MBEDTLS_SSL_MAX_FRAG_LEN_2048, MBEDTLS_SSL_MAX_FRAG_LEN_4096)
 *
 * \return         0 if successful or MBEDTLS_ERR_SSL_BAD_INPUT_DATA
 */
int mbedtls_ssl_conf_max_frag_len( mbedtls_ssl_config *conf, unsigned char mfl_code );
#endif /* MBEDTLS_SSL_MAX_FRAGMENT_LENGTH */

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
/**
 * \brief          Activate negotiation of truncated HMAC
 *                 (Default: MBEDTLS_SSL_TRUNC_HMAC_DISABLED)
 *
 * \param conf     SSL configuration
 * \param truncate Enable or disable (MBEDTLS_SSL_TRUNC_HMAC_ENABLED or
 *                                    MBEDTLS_SSL_TRUNC_HMAC_DISABLED)
 */
void mbedtls_ssl_conf_truncated_hmac( mbedtls_ssl_config *conf, int truncate );
#endif /* MBEDTLS_SSL_TRUNCATED_HMAC */

#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
/**
 * \brief          Enable / Disable 1/n-1 record splitting
 *                 (Default: MBEDTLS_SSL_CBC_RECORD_SPLITTING_ENABLED)
 *
 * \note           Only affects SSLv3 and TLS 1.0, not higher versions.
 *                 Does not affect non-CBC ciphersuites in any version.
 *
 * \param conf     SSL configuration
 * \param split    MBEDTLS_SSL_CBC_RECORD_SPLITTING_ENABLED or
 *                 MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED
 */
void mbedtls_ssl_conf_cbc_record_splitting( mbedtls_ssl_config *conf, char split );
#endif /* MBEDTLS_SSL_CBC_RECORD_SPLITTING */

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
/**
 * \brief          Enable / Disable session tickets
 *                 (Default: MBEDTLS_SSL_SESSION_TICKETS_ENABLED on client,
 *                           MBEDTLS_SSL_SESSION_TICKETS_DISABLED on server)
 *
 * \note           On server, mbedtls_ssl_conf_rng() must be called before this function
 *                 to allow generating the ticket encryption and
 *                 authentication keys.
 *
 * \param conf     SSL configuration
 * \param use_tickets   Enable or disable (MBEDTLS_SSL_SESSION_TICKETS_ENABLED or
 *                                         MBEDTLS_SSL_SESSION_TICKETS_DISABLED)
 *
 * \return         0 if successful,
 *                 or a specific error code (server only).
 */
int mbedtls_ssl_conf_session_tickets( mbedtls_ssl_config *conf, int use_tickets );

/**
 * \brief          Set session ticket lifetime (server only)
 *                 (Default: MBEDTLS_SSL_DEFAULT_TICKET_LIFETIME (86400 secs / 1 day))
 *
 * \param conf     SSL configuration
 * \param lifetime session ticket lifetime
 */
void mbedtls_ssl_conf_session_ticket_lifetime( mbedtls_ssl_config *conf, int lifetime );
#endif /* MBEDTLS_SSL_SESSION_TICKETS */

#if defined(MBEDTLS_SSL_RENEGOTIATION)
/**
 * \brief          Enable / Disable renegotiation support for connection when
 *                 initiated by peer
 *                 (Default: MBEDTLS_SSL_RENEGOTIATION_DISABLED)
 *
 *                 Note: A server with support enabled is more vulnerable for a
 *                 resource DoS by a malicious client. You should enable this on
 *                 a client to enable server-initiated renegotiation.
 *
 * \param conf    SSL configuration
 * \param renegotiation     Enable or disable (MBEDTLS_SSL_RENEGOTIATION_ENABLED or
 *                                             MBEDTLS_SSL_RENEGOTIATION_DISABLED)
 */
void mbedtls_ssl_conf_renegotiation( mbedtls_ssl_config *conf, int renegotiation );
#endif /* MBEDTLS_SSL_RENEGOTIATION */

/**
 * \brief          Prevent or allow legacy renegotiation.
 *                 (Default: MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION)
 *
 *                 MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION allows connections to
 *                 be established even if the peer does not support
 *                 secure renegotiation, but does not allow renegotiation
 *                 to take place if not secure.
 *                 (Interoperable and secure option)
 *
 *                 MBEDTLS_SSL_LEGACY_ALLOW_RENEGOTIATION allows renegotiations
 *                 with non-upgraded peers. Allowing legacy renegotiation
 *                 makes the connection vulnerable to specific man in the
 *                 middle attacks. (See RFC 5746)
 *                 (Most interoperable and least secure option)
 *
 *                 MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE breaks off connections
 *                 if peer does not support secure renegotiation. Results
 *                 in interoperability issues with non-upgraded peers
 *                 that do not support renegotiation altogether.
 *                 (Most secure option, interoperability issues)
 *
 * \param conf     SSL configuration
 * \param allow_legacy  Prevent or allow (SSL_NO_LEGACY_RENEGOTIATION,
 *                                        SSL_ALLOW_LEGACY_RENEGOTIATION or
 *                                        MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE)
 */
void mbedtls_ssl_conf_legacy_renegotiation( mbedtls_ssl_config *conf, int allow_legacy );

#if defined(MBEDTLS_SSL_RENEGOTIATION)
/**
 * \brief          Enforce renegotiation requests.
 *                 (Default: enforced, max_records = 16)
 *
 *                 When we request a renegotiation, the peer can comply or
 *                 ignore the request. This function allows us to decide
 *                 whether to enforce our renegotiation requests by closing
 *                 the connection if the peer doesn't comply.
 *
 *                 However, records could already be in transit from the peer
 *                 when the request is emitted. In order to increase
 *                 reliability, we can accept a number of records before the
 *                 expected handshake records.
 *
 *                 The optimal value is highly dependent on the specific usage
 *                 scenario.
 *
 * \note           With DTLS and server-initiated renegotiation, the
 *                 HelloRequest is retransmited every time mbedtls_ssl_read() times
 *                 out or receives Application Data, until:
 *                 - max_records records have beens seen, if it is >= 0, or
 *                 - the number of retransmits that would happen during an
 *                 actual handshake has been reached.
 *                 Please remember the request might be lost a few times
 *                 if you consider setting max_records to a really low value.
 *
 * \warning        On client, the grace period can only happen during
 *                 mbedtls_ssl_read(), as opposed to mbedtls_ssl_write() and mbedtls_ssl_renegotiate()
 *                 which always behave as if max_record was 0. The reason is,
 *                 if we receive application data from the server, we need a
 *                 place to write it, which only happens during mbedtls_ssl_read().
 *
 * \param conf     SSL configuration
 * \param max_records Use MBEDTLS_SSL_RENEGOTIATION_NOT_ENFORCED if you don't want to
 *                 enforce renegotiation, or a non-negative value to enforce
 *                 it but allow for a grace period of max_records records.
 */
void mbedtls_ssl_conf_renegotiation_enforced( mbedtls_ssl_config *conf, int max_records );

/**
 * \brief          Set record counter threshold for periodic renegotiation.
 *                 (Default: 2^64 - 256.)
 *
 *                 Renegotiation is automatically triggered when a record
 *                 counter (outgoing or ingoing) crosses the defined
 *                 threshold. The default value is meant to prevent the
 *                 connection from being closed when the counter is about to
 *                 reached its maximal value (it is not allowed to wrap).
 *
 *                 Lower values can be used to enforce policies such as "keys
 *                 must be refreshed every N packets with cipher X".
 *
 * \param conf     SSL configuration
 * \param period   The threshold value: a big-endian 64-bit number.
 *                 Set to 2^64 - 1 to disable periodic renegotiation
 */
void mbedtls_ssl_conf_renegotiation_period( mbedtls_ssl_config *conf,
                                   const unsigned char period[8] );
#endif /* MBEDTLS_SSL_RENEGOTIATION */

/**
 * \brief          Return the number of data bytes available to read
 *
 * \param ssl      SSL context
 *
 * \return         how many bytes are available in the read buffer
 */
size_t mbedtls_ssl_get_bytes_avail( const mbedtls_ssl_context *ssl );

/**
 * \brief          Return the result of the certificate verification
 *
 * \param ssl      SSL context
 *
 * \return         0 if successful,
 *                 -1 if result is not available (eg because the handshake was
 *                 aborted too early), or
 *                 a combination of BADCERT_xxx and BADCRL_xxx flags, see
 *                 x509.h
 */
uint32_t mbedtls_ssl_get_verify_result( const mbedtls_ssl_context *ssl );

/**
 * \brief          Return the name of the current ciphersuite
 *
 * \param ssl      SSL context
 *
 * \return         a string containing the ciphersuite name
 */
const char *mbedtls_ssl_get_ciphersuite( const mbedtls_ssl_context *ssl );

/**
 * \brief          Return the current SSL version (SSLv3/TLSv1/etc)
 *
 * \param ssl      SSL context
 *
 * \return         a string containing the SSL version
 */
const char *mbedtls_ssl_get_version( const mbedtls_ssl_context *ssl );

/**
 * \brief          Return the (maximum) number of bytes added by the record
 *                 layer: header + encryption/MAC overhead (inc. padding)
 *
 * \param ssl      SSL context
 *
 * \return         Current maximum record expansion in bytes, or
 *                 MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE if compression is
 *                 enabled, which makes expansion much less predictable
 */
int mbedtls_ssl_get_record_expansion( const mbedtls_ssl_context *ssl );

#if defined(MBEDTLS_X509_CRT_PARSE_C)
/**
 * \brief          Return the peer certificate from the current connection
 *
 *                 Note: Can be NULL in case no certificate was sent during
 *                 the handshake. Different calls for the same connection can
 *                 return the same or different pointers for the same
 *                 certificate and even a different certificate altogether.
 *                 The peer cert CAN change in a single connection if
 *                 renegotiation is performed.
 *
 * \param ssl      SSL context
 *
 * \return         the current peer certificate
 */
const mbedtls_x509_crt *mbedtls_ssl_get_peer_cert( const mbedtls_ssl_context *ssl );
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_CLI_C)
/**
 * \brief          Save session in order to resume it later (client-side only)
 *                 Session data is copied to presented session structure.
 *
 * \warning        Currently, peer certificate is lost in the operation.
 *
 * \param ssl      SSL context
 * \param session  session context
 *
 * \return         0 if successful,
 *                 MBEDTLS_ERR_SSL_MALLOC_FAILED if memory allocation failed,
 *                 MBEDTLS_ERR_SSL_BAD_INPUT_DATA if used server-side or
 *                 arguments are otherwise invalid
 *
 * \sa             mbedtls_ssl_set_session()
 */
int mbedtls_ssl_get_session( const mbedtls_ssl_context *ssl, mbedtls_ssl_session *session );
#endif /* MBEDTLS_SSL_CLI_C */

/**
 * \brief          Perform the SSL handshake
 *
 * \param ssl      SSL context
 *
 * \return         0 if successful, MBEDTLS_ERR_SSL_WANT_READ,
 *                 MBEDTLS_ERR_SSL_WANT_WRITE, or a specific SSL error code.
 */
int mbedtls_ssl_handshake( mbedtls_ssl_context *ssl );

/**
 * \brief          Perform a single step of the SSL handshake
 *
 *                 Note: the state of the context (ssl->state) will be at
 *                 the following state after execution of this function.
 *                 Do not call this function if state is MBEDTLS_SSL_HANDSHAKE_OVER.
 *
 * \param ssl      SSL context
 *
 * \return         0 if successful, MBEDTLS_ERR_SSL_WANT_READ,
 *                 MBEDTLS_ERR_SSL_WANT_WRITE, or a specific SSL error code.
 */
int mbedtls_ssl_handshake_step( mbedtls_ssl_context *ssl );

#if defined(MBEDTLS_SSL_RENEGOTIATION)
/**
 * \brief          Initiate an SSL renegotiation on the running connection.
 *                 Client: perform the renegotiation right now.
 *                 Server: request renegotiation, which will be performed
 *                 during the next call to mbedtls_ssl_read() if honored by client.
 *
 * \param ssl      SSL context
 *
 * \return         0 if successful, or any mbedtls_ssl_handshake() return value.
 */
int mbedtls_ssl_renegotiate( mbedtls_ssl_context *ssl );
#endif /* MBEDTLS_SSL_RENEGOTIATION */

/**
 * \brief          Read at most 'len' application data bytes
 *
 * \param ssl      SSL context
 * \param buf      buffer that will hold the data
 * \param len      maximum number of bytes to read
 *
 * \return         This function returns the number of bytes read, 0 for EOF,
 *                 or a negative error code.
 */
int mbedtls_ssl_read( mbedtls_ssl_context *ssl, unsigned char *buf, size_t len );

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
 * \note           When this function returns MBEDTLS_ERR_SSL_WANT_WRITE,
 *                 it must be called later with the *same* arguments,
 *                 until it returns a positive value.
 *
 * \note           If the requested length is greater than the maximum
 *                 fragment length (either the built-in limit or the one set
 *                 or negotiated with the peer), then:
 *                 - with TLS, less bytes than requested are written. (In
 *                 order to write larger messages, this function should be
 *                 called in a loop.)
 *                 - with DTLS, MBEDTLS_ERR_SSL_BAD_INPUT_DATA is returned.
 */
int mbedtls_ssl_write( mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len );

/**
 * \brief           Send an alert message
 *
 * \param ssl       SSL context
 * \param level     The alert level of the message
 *                  (MBEDTLS_SSL_ALERT_LEVEL_WARNING or MBEDTLS_SSL_ALERT_LEVEL_FATAL)
 * \param message   The alert message (SSL_ALERT_MSG_*)
 *
 * \return          0 if successful, or a specific SSL error code.
 */
int mbedtls_ssl_send_alert_message( mbedtls_ssl_context *ssl,
                            unsigned char level,
                            unsigned char message );
/**
 * \brief          Notify the peer that the connection is being closed
 *
 * \param ssl      SSL context
 */
int mbedtls_ssl_close_notify( mbedtls_ssl_context *ssl );

/**
 * \brief          Free referenced items in an SSL context and clear memory
 *
 * \param ssl      SSL context
 */
void mbedtls_ssl_free( mbedtls_ssl_context *ssl );

/**
 * \brief          Initialize an SSL configuration context
 *                 Just makes the context ready for
 *                 mbedtls_ssl_config_defaults() or mbedtls_ssl_free()
 *
 * \note           You need to call mbedtls_ssl_config_defaults() unless you
 *                 manually set all of the relevent fields yourself.
 *
 * \param conf     SSL configuration context
 */
void mbedtls_ssl_config_init( mbedtls_ssl_config *conf );

/**
 * \brief          Load reasonnable default SSL configuration values.
 *                 (You need to call mbedtls_ssl_config_init() first.)
 *
 * \param conf     SSL configuration context
 *
 * \note           See \c mbedtls_ssl_conf_transport() for notes on DTLS.
 *
 * \return         0 if successful, or
 *                 MBEDTLS_ERR_XXX_ALLOC_FAILED on memorr allocation error.
 */
int mbedtls_ssl_config_defaults( mbedtls_ssl_config *conf,
                                 int endpoint, int transport );

/**
 * \brief          Free an SSL configuration context
 *
 * \param conf     SSL configuration context
 */
void mbedtls_ssl_config_free( mbedtls_ssl_config *conf );

/**
 * \brief          Initialize SSL session structure
 *
 * \param session  SSL session
 */
void mbedtls_ssl_session_init( mbedtls_ssl_session *session );

/**
 * \brief          Free referenced items in an SSL session including the
 *                 peer certificate and clear memory
 *
 * \param session  SSL session
 */
void mbedtls_ssl_session_free( mbedtls_ssl_session *session );

/**
 * \brief           Free referenced items in an SSL transform context and clear
 *                  memory
 *
 * \param transform SSL transform context
 */
void mbedtls_ssl_transform_free( mbedtls_ssl_transform *transform );

/**
 * \brief           Free referenced items in an SSL handshake context and clear
 *                  memory
 *
 * \param handshake SSL handshake context
 */
void mbedtls_ssl_handshake_free( mbedtls_ssl_handshake_params *handshake );

/*
 * Internal functions (do not call directly)
 */
int mbedtls_ssl_handshake_client_step( mbedtls_ssl_context *ssl );
int mbedtls_ssl_handshake_server_step( mbedtls_ssl_context *ssl );
void mbedtls_ssl_handshake_wrapup( mbedtls_ssl_context *ssl );

int mbedtls_ssl_send_fatal_handshake_failure( mbedtls_ssl_context *ssl );

void mbedtls_ssl_reset_checksum( mbedtls_ssl_context *ssl );
int mbedtls_ssl_derive_keys( mbedtls_ssl_context *ssl );

int mbedtls_ssl_read_record( mbedtls_ssl_context *ssl );
int mbedtls_ssl_fetch_input( mbedtls_ssl_context *ssl, size_t nb_want );

int mbedtls_ssl_write_record( mbedtls_ssl_context *ssl );
int mbedtls_ssl_flush_output( mbedtls_ssl_context *ssl );

int mbedtls_ssl_parse_certificate( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_certificate( mbedtls_ssl_context *ssl );

int mbedtls_ssl_parse_change_cipher_spec( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_change_cipher_spec( mbedtls_ssl_context *ssl );

int mbedtls_ssl_parse_finished( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_finished( mbedtls_ssl_context *ssl );

void mbedtls_ssl_optimize_checksum( mbedtls_ssl_context *ssl,
                            const mbedtls_ssl_ciphersuite_t *ciphersuite_info );

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int mbedtls_ssl_psk_derive_premaster( mbedtls_ssl_context *ssl, mbedtls_key_exchange_type_t key_ex );
#endif

#if defined(MBEDTLS_PK_C)
unsigned char mbedtls_ssl_sig_from_pk( mbedtls_pk_context *pk );
mbedtls_pk_type_t mbedtls_ssl_pk_alg_from_sig( unsigned char sig );
#endif

mbedtls_md_type_t mbedtls_ssl_md_alg_from_hash( unsigned char hash );

#if defined(MBEDTLS_SSL_SET_CURVES)
int mbedtls_ssl_curve_is_acceptable( const mbedtls_ssl_context *ssl, mbedtls_ecp_group_id grp_id );
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
static inline mbedtls_pk_context *mbedtls_ssl_own_key( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_key_cert *key_cert;

    if( ssl->handshake != NULL && ssl->handshake->key_cert != NULL )
        key_cert = ssl->handshake->key_cert;
    else
        key_cert = ssl->conf->key_cert;

    return( key_cert == NULL ? NULL : key_cert->key );
}

static inline mbedtls_x509_crt *mbedtls_ssl_own_cert( mbedtls_ssl_context *ssl )
{
    mbedtls_ssl_key_cert *key_cert;

    if( ssl->handshake != NULL && ssl->handshake->key_cert != NULL )
        key_cert = ssl->handshake->key_cert;
    else
        key_cert = ssl->conf->key_cert;

    return( key_cert == NULL ? NULL : key_cert->cert );
}

/*
 * Check usage of a certificate wrt extensions:
 * keyUsage, extendedKeyUsage (later), and nSCertType (later).
 *
 * Warning: cert_endpoint is the endpoint of the cert (ie, of our peer when we
 * check a cert we received from them)!
 *
 * Return 0 if everything is OK, -1 if not.
 */
int mbedtls_ssl_check_cert_usage( const mbedtls_x509_crt *cert,
                          const mbedtls_ssl_ciphersuite_t *ciphersuite,
                          int cert_endpoint,
                          uint32_t *flags );
#endif /* MBEDTLS_X509_CRT_PARSE_C */

void mbedtls_ssl_write_version( int major, int minor, int transport,
                        unsigned char ver[2] );
void mbedtls_ssl_read_version( int *major, int *minor, int transport,
                       const unsigned char ver[2] );

static inline size_t mbedtls_ssl_hdr_len( const mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        return( 13 );
#else
    ((void) ssl);
#endif
    return( 5 );
}

static inline size_t mbedtls_ssl_hs_hdr_len( const mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
        return( 12 );
#else
    ((void) ssl);
#endif
    return( 4 );
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
void mbedtls_ssl_send_flight_completed( mbedtls_ssl_context *ssl );
void mbedtls_ssl_recv_flight_completed( mbedtls_ssl_context *ssl );
int mbedtls_ssl_resend( mbedtls_ssl_context *ssl );
#endif

/* Visible for testing purposes only */
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
int mbedtls_ssl_dtls_replay_check( mbedtls_ssl_context *ssl );
void mbedtls_ssl_dtls_replay_update( mbedtls_ssl_context *ssl );
#endif

/* constant-time buffer comparison */
static inline int mbedtls_ssl_safer_memcmp( const void *a, const void *b, size_t n )
{
    size_t i;
    const unsigned char *A = (const unsigned char *) a;
    const unsigned char *B = (const unsigned char *) b;
    unsigned char diff = 0;

    for( i = 0; i < n; i++ )
        diff |= A[i] ^ B[i];

    return( diff );
}

#ifdef __cplusplus
}
#endif

#endif /* ssl.h */
