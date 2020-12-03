/**
 * \file ssl_internal.h
 *
 * \brief Internal functions shared by the SSL modules
 */
/*
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
#ifndef MBEDTLS_SSL_INTERNAL_H
#define MBEDTLS_SSL_INTERNAL_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "ssl.h"
#include "cipher.h"
#include "oid.h"

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

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#include "ecjpake.h"
#endif

#if defined(MBEDTLS_ECP_C)
#include "ecp.h"
#endif

#if defined(MBEDTLS_ECDH_C)
#include "ecdh.h"
#endif

#if defined(MBEDTLS_USE_TINYCRYPT)
#include "tinycrypt/ecc.h"
#include "tinycrypt/ecc_dh.h"
#endif

#if defined(__GNUC__) || defined(__arm__)
#define MBEDTLS_ALWAYS_INLINE __attribute__((always_inline))
#define MBEDTLS_NO_INLINE __attribute__((noinline))
#else
#define MBEDTLS_ALWAYS_INLINE
#define MBEDTLS_NO_INLINE
#endif

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/* The public option is negative for backwards compatibility,
 * but internally a poisitive option is more convenient. */
#if !defined(MBEDTLS_SSL_PROTO_NO_TLS)
#define MBEDTLS_SSL_PROTO_TLS
#endif

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

#define MBEDTLS_SSL_MIN_VALID_MINOR_VERSION MBEDTLS_SSL_MINOR_VERSION_1
#define MBEDTLS_SSL_MIN_VALID_MAJOR_VERSION MBEDTLS_SSL_MAJOR_VERSION_3

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

/* Shorthand for restartable ECC */
#if defined(MBEDTLS_ECP_RESTARTABLE) && \
    defined(MBEDTLS_SSL_CLI_C) && \
    defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
#define MBEDTLS_SSL__ECP_RESTARTABLE
#endif

#define MBEDTLS_SSL_INITIAL_HANDSHAKE           0
#define MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS   1   /* In progress */
#define MBEDTLS_SSL_RENEGOTIATION_DONE          2   /* Done or aborted */
#define MBEDTLS_SSL_RENEGOTIATION_PENDING       3   /* Requested (server only) */

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

#if defined(MBEDTLS_ARC4_C) || defined(MBEDTLS_CIPHER_NULL_CIPHER) ||   \
    ( defined(MBEDTLS_CIPHER_MODE_CBC) &&                               \
      ( defined(MBEDTLS_AES_C)      ||                                  \
        defined(MBEDTLS_CAMELLIA_C) ||                                  \
        defined(MBEDTLS_ARIA_C)     ||                                  \
        defined(MBEDTLS_DES_C) ) )
#define MBEDTLS_SSL_SOME_MODES_USE_MAC
#endif

#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
/* Ciphersuites using HMAC */
#if defined(MBEDTLS_SHA512_C)
#define MBEDTLS_SSL_MAC_ADD                 48  /* SHA-384 used for HMAC */
#elif defined(MBEDTLS_SHA256_C)
#define MBEDTLS_SSL_MAC_ADD                 32  /* SHA-256 used for HMAC */
#else
#define MBEDTLS_SSL_MAC_ADD                 20  /* SHA-1   used for HMAC */
#endif
#else /* MBEDTLS_SSL_SOME_MODES_USE_MAC */
/* AEAD ciphersuites: GCM and CCM use a 128 bits tag */
#define MBEDTLS_SSL_MAC_ADD                 16
#endif

#if defined(MBEDTLS_CIPHER_MODE_CBC)
#define MBEDTLS_SSL_PADDING_ADD            256
#else
#define MBEDTLS_SSL_PADDING_ADD              0
#endif

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_MAX_CID_EXPANSION      MBEDTLS_SSL_CID_PADDING_GRANULARITY
#else
#define MBEDTLS_SSL_MAX_CID_EXPANSION        0
#endif

#define MBEDTLS_SSL_PAYLOAD_OVERHEAD ( MBEDTLS_SSL_COMPRESSION_ADD +    \
                                       MBEDTLS_MAX_IV_LENGTH +          \
                                       MBEDTLS_SSL_MAC_ADD +            \
                                       MBEDTLS_SSL_PADDING_ADD +        \
                                       MBEDTLS_SSL_MAX_CID_EXPANSION    \
                                       )

#define MBEDTLS_SSL_IN_PAYLOAD_LEN ( MBEDTLS_SSL_PAYLOAD_OVERHEAD + \
                                     ( MBEDTLS_SSL_IN_CONTENT_LEN ) )

#define MBEDTLS_SSL_OUT_PAYLOAD_LEN ( MBEDTLS_SSL_PAYLOAD_OVERHEAD + \
                                      ( MBEDTLS_SSL_OUT_CONTENT_LEN ) )

/* The maximum number of buffered handshake messages. */
#define MBEDTLS_SSL_MAX_BUFFERED_HS 4

/* Maximum length we can advertise as our max content length for
   RFC 6066 max_fragment_length extension negotiation purposes
   (the lesser of both sizes, if they are unequal.)
 */
#define MBEDTLS_TLS_EXT_ADV_CONTENT_LEN (                            \
        (MBEDTLS_SSL_IN_CONTENT_LEN > MBEDTLS_SSL_OUT_CONTENT_LEN)   \
        ? ( MBEDTLS_SSL_OUT_CONTENT_LEN )                            \
        : ( MBEDTLS_SSL_IN_CONTENT_LEN )                             \
        )

#define MBEDTLS_SSL_FI_FLAG_UNSET       0x0
#define MBEDTLS_SSL_FI_FLAG_SET         0x7F

/*
 * Check that we obey the standard's message size bounds
 */

#if MBEDTLS_SSL_MAX_CONTENT_LEN > 16384
#error "Bad configuration - record content too large."
#endif

#if MBEDTLS_SSL_IN_CONTENT_LEN > MBEDTLS_SSL_MAX_CONTENT_LEN
#error "Bad configuration - incoming record content should not be larger than MBEDTLS_SSL_MAX_CONTENT_LEN."
#endif

#if MBEDTLS_SSL_OUT_CONTENT_LEN > MBEDTLS_SSL_MAX_CONTENT_LEN
#error "Bad configuration - outgoing record content should not be larger than MBEDTLS_SSL_MAX_CONTENT_LEN."
#endif

#if MBEDTLS_SSL_IN_PAYLOAD_LEN > MBEDTLS_SSL_MAX_CONTENT_LEN + 2048
#error "Bad configuration - incoming protected record payload too large."
#endif

#if MBEDTLS_SSL_OUT_PAYLOAD_LEN > MBEDTLS_SSL_MAX_CONTENT_LEN + 2048
#error "Bad configuration - outgoing protected record payload too large."
#endif

/* Calculate buffer sizes */

/* Note: Even though the TLS record header is only 5 bytes
   long, we're internally using 8 bytes to store the
   implicit sequence number. */
#define MBEDTLS_SSL_HEADER_LEN 13

#if !defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_IN_BUFFER_LEN  \
    ( ( MBEDTLS_SSL_HEADER_LEN ) + ( MBEDTLS_SSL_IN_PAYLOAD_LEN ) )
#else
#define MBEDTLS_SSL_IN_BUFFER_LEN  \
    ( ( MBEDTLS_SSL_HEADER_LEN ) + ( MBEDTLS_SSL_IN_PAYLOAD_LEN ) \
      + ( MBEDTLS_SSL_CID_IN_LEN_MAX ) )
#endif

#if !defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_OUT_BUFFER_LEN  \
    ( ( MBEDTLS_SSL_HEADER_LEN ) + ( MBEDTLS_SSL_OUT_PAYLOAD_LEN ) )
#else
#define MBEDTLS_SSL_OUT_BUFFER_LEN                               \
    ( ( MBEDTLS_SSL_HEADER_LEN ) + ( MBEDTLS_SSL_OUT_PAYLOAD_LEN )    \
      + ( MBEDTLS_SSL_CID_OUT_LEN_MAX ) )
#endif

#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
static inline uint32_t mbedtls_ssl_get_output_buflen( const mbedtls_ssl_context *ctx )
{
#if defined (MBEDTLS_SSL_DTLS_CONNECTION_ID)
    return (uint32_t) mbedtls_ssl_get_output_max_frag_len( ctx )
               + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD
               + MBEDTLS_SSL_CID_OUT_LEN_MAX;
#else
    return (uint32_t) mbedtls_ssl_get_output_max_frag_len( ctx )
               + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD;
#endif
}

static inline uint32_t mbedtls_ssl_get_input_buflen( const mbedtls_ssl_context *ctx )
{
#if defined (MBEDTLS_SSL_DTLS_CONNECTION_ID)
    return (uint32_t) mbedtls_ssl_get_input_max_frag_len( ctx )
               + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD
               + MBEDTLS_SSL_CID_IN_LEN_MAX;
#else
    return (uint32_t) mbedtls_ssl_get_input_max_frag_len( ctx )
               + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD;
#endif
}
#endif

#ifdef MBEDTLS_ZLIB_SUPPORT
/* Compression buffer holds both IN and OUT buffers, so should be size of the larger */
#define MBEDTLS_SSL_COMPRESS_BUFFER_LEN (                               \
        ( MBEDTLS_SSL_IN_BUFFER_LEN > MBEDTLS_SSL_OUT_BUFFER_LEN )      \
        ? MBEDTLS_SSL_IN_BUFFER_LEN                                     \
        : MBEDTLS_SSL_OUT_BUFFER_LEN                                    \
        )
#endif

/*
 * TLS extension flags (for extensions with outgoing ServerHello content
 * that need it (e.g. for RENEGOTIATION_INFO the server already knows because
 * of state of the renegotiation flag, so no indicator is required)
 */
#define MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT (1 << 0)
#define MBEDTLS_TLS_EXT_ECJPAKE_KKPP_OK                 (1 << 1)

/*
 * Helpers for code specific to TLS or DTLS.
 *
 * Goals for these helpers:
 *  - generate minimal code, eg don't test if mode is DTLS in a DTLS-only build
 *  - make the flow clear to the compiler, so that in TLS and DTLS combined
 *    builds, when there are two branches, it knows exactly one of them is taken
 *  - preserve readability
 *
 * There are three macros:
 *  - MBEDTLS_SSL_TRANSPORT_IS_TLS( transport )
 *  - MBEDTLS_SSL_TRANSPORT_IS_DTLS( transport )
 *  - MBEDTLS_SSL_TRANSPORT_ELSE
 *
 * The first two are macros rather than static inline functions because some
 * compilers (eg arm-none-eabi-gcc 5.4.1 20160919) don't propagate constants
 * well enough for us with static inline functions.
 *
 * Usage 1 (can replace DTLS with TLS):
 *  #if defined(MBEDTLS_SSL_PROTO_DTLS)
 *  if( MBEDTLS_SSL_TRANSPORT_IS_DTLS( transport ) )
 *      // DTLS-specific code
 *  #endif
 *
 * Usage 2 (can swap DTLS and TLS);
 *  #if defined(MBEDTLS_SSL_PROTO_DTLS)
 *  if( MBEDTLS_SSL_TRANSPORT_IS_DTLS( transport ) )
 *      // DTLS-specific code
 *  MBEDTLS_SSL_TRANSPORT_ELSE
 *  #endif
 *  #if defined(MBEDTLS_SSL_PROTO_TLS)
 *      // TLS-specific code
 *  #endif
 */
#if defined(MBEDTLS_SSL_PROTO_DTLS) && defined(MBEDTLS_SSL_PROTO_TLS) /* both */
#define MBEDTLS_SSL_TRANSPORT__BOTH /* shortcut for future tests */
#define MBEDTLS_SSL_TRANSPORT_IS_TLS( transport ) \
    ( (transport) == MBEDTLS_SSL_TRANSPORT_STREAM )
#define MBEDTLS_SSL_TRANSPORT_IS_DTLS( transport ) \
    ( (transport) == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
#define MBEDTLS_SSL_TRANSPORT_ELSE                  else
#elif defined(MBEDTLS_SSL_PROTO_DTLS) /* DTLS only */
#define MBEDTLS_SSL_TRANSPORT_IS_TLS( transport )   0
#define MBEDTLS_SSL_TRANSPORT_IS_DTLS( transport )  1
#define MBEDTLS_SSL_TRANSPORT_ELSE                  /* empty: no other branch */
#else /* TLS only */
#define MBEDTLS_SSL_TRANSPORT_IS_TLS( transport )   1
#define MBEDTLS_SSL_TRANSPORT_IS_DTLS( transport )  0
#define MBEDTLS_SSL_TRANSPORT_ELSE                  /* empty: no other branch */
#endif /* TLS and/or DTLS */

/* Check if the use of the ExtendedMasterSecret extension
 * is enforced at compile-time. If so, we don't need to
 * track its status in the handshake parameters. */
#if defined(MBEDTLS_SSL_CONF_EXTENDED_MASTER_SECRET)         && \
    defined(MBEDTLS_SSL_CONF_ENFORCE_EXTENDED_MASTER_SECRET) && \
    MBEDTLS_SSL_CONF_EXTENDED_MASTER_SECRET ==                  \
      MBEDTLS_SSL_EXTENDED_MS_ENABLED                        && \
    MBEDTLS_SSL_CONF_ENFORCE_EXTENDED_MASTER_SECRET ==          \
      MBEDTLS_SSL_EXTENDED_MS_ENFORCE_ENABLED
#define MBEDTLS_SSL_EXTENDED_MS_ENFORCED
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
/*
 * Abstraction for a grid of allowed signature-hash-algorithm pairs.
 */
struct mbedtls_ssl_sig_hash_set_t
{
    /* At the moment, we only need to remember a single suitable
     * hash algorithm per signature algorithm. As long as that's
     * the case - and we don't need a general lookup function -
     * we can implement the sig-hash-set as a map from signatures
     * to hash algorithms. */
    mbedtls_md_type_t rsa;
    mbedtls_md_type_t ecdsa;
};
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 &&
          MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

/*
 * This structure contains the parameters only needed during handshake.
 */
struct mbedtls_ssl_handshake_params
{
#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    uint8_t got_peer_pubkey;            /*!< Did we store the peer's public key from its certificate? */
#endif /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */
    volatile uint8_t peer_authenticated;         /*!< Is the peer authenticated? */
    volatile uint8_t hello_random_set;           /*!< Has the hello random been set? */
    volatile uint8_t key_derivation_done;        /*!< Has the key derivation been done? */
    volatile uint8_t premaster_generated;        /*!< Has the PMS been generated? */
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    unsigned char verify_cookie_len;    /*!<  Cli: cookie length
                                              Srv: flag for sending a cookie */
    unsigned char retransmit_state;     /*!<  Retransmission state           */
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    /* The state of CID configuration in this handshake. */

    uint8_t cid_in_use; /*!< This indicates whether the use of the CID extension
                         *   has been negotiated. Possible values are
                         *   #MBEDTLS_SSL_CID_ENABLED and
                         *   #MBEDTLS_SSL_CID_DISABLED. */
    uint8_t peer_cid_len;                                  /*!< The length of
                                                            *   \c peer_cid.  */
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
    uint16_t mtu;                       /*!<  Handshake mtu, used to fragment outgoing messages */

#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
    mbedtls_ssl_sig_hash_set_t hash_algs;             /*!<  Set of suitable sig-hash pairs */
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    mbedtls_ecjpake_context ecjpake_ctx;        /*!< EC J-PAKE key exchange */
#if defined(MBEDTLS_SSL_CLI_C)
    unsigned char *ecjpake_cache;               /*!< Cache for ClientHello ext */
    size_t ecjpake_cache_len;                   /*!< Length of cached data */
#endif
#endif /* MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED */
#if defined(MBEDTLS_ECDH_C)   ||                        \
    defined(MBEDTLS_ECDSA_C)  ||                        \
    defined(MBEDTLS_USE_TINYCRYPT) ||                   \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    uint16_t curve_tls_id;                      /*!< TLS ID of EC for ECDHE. */
#endif

    size_t pmslen;                      /*!<  premaster length        */
    int cli_exts;                       /*!< client extension presence*/

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
    unsigned char *psk;                 /*!<  PSK from the callback         */
    size_t psk_len;                     /*!<  Length of PSK from callback   */
#endif
#if defined(MBEDTLS_SSL__ECP_RESTARTABLE)
    int ecrs_enabled;                   /*!< Handshake supports EC restart? */
    mbedtls_x509_crt_restart_ctx ecrs_ctx;  /*!< restart context            */
    enum { /* this complements ssl->state with info on intra-state operations */
        ssl_ecrs_none = 0,              /*!< nothing going on (yet)         */
        ssl_ecrs_crt_verify,            /*!< Certificate: crt_verify()      */
        ssl_ecrs_cke_ecdh_calc_secret,  /*!< ClientKeyExchange: ECDH step 2 */
        ssl_ecrs_crt_vrfy_sign,         /*!< CertificateVerify: pk_sign()   */
    } ecrs_state;                       /*!< current (or last) operation    */
    mbedtls_x509_crt *ecrs_peer_cert;   /*!< The peer's CRT chain.          */
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    unsigned int out_msg_seq;           /*!<  Outgoing handshake sequence number */
    unsigned int in_msg_seq;            /*!<  Incoming handshake sequence number */

    unsigned char *verify_cookie;       /*!<  Cli: HelloVerifyRequest cookie
                                              Srv: unused                    */
    uint32_t retransmit_timeout;        /*!<  Current value of timeout       */
    mbedtls_ssl_flight_item *flight;    /*!<  Current outgoing flight        */
    mbedtls_ssl_flight_item *cur_msg;   /*!<  Current message in flight      */
    unsigned char *cur_msg_p;           /*!<  Position in current message    */
    unsigned int in_flight_start_seq;   /*!<  Minimum message sequence in the
                                              flight being received          */
    mbedtls_ssl_transform *alt_transform_out;   /*!<  Alternative transform for
                                              resending messages             */
    unsigned char alt_out_ctr[8];       /*!<  Alternative record epoch/counter
                                              for resending messages         */
    struct
    {
        uint8_t seen_ccs;               /*!< Indicates if a CCS message has
                                         *   been seen in the current flight. */

        size_t total_bytes_buffered;    /*!< Cumulative size of heap allocated
                                         *   buffers used for message buffering. */

        struct
        {
            unsigned char *data;
            size_t len;
            unsigned epoch;
        } future_record;

        struct mbedtls_ssl_hs_buffer
        {
            uint8_t is_valid;
            uint8_t is_fragmented;
            uint8_t is_complete;
            unsigned char *data;
            size_t data_len;
        } hs[MBEDTLS_SSL_MAX_BUFFERED_HS];
    } buffering;
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    /* The state of CID configuration in this handshake. */
    unsigned char peer_cid[ MBEDTLS_SSL_CID_OUT_LEN_MAX ]; /*! The peer's CID */
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
#endif /* MBEDTLS_SSL_PROTO_DTLS */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_key_cert *key_cert;     /*!< chosen key/cert pair (server)  */
#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    mbedtls_pk_context peer_pubkey;     /*!< The public key from the peer.  */
#endif /* !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE */

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    int sni_authmode;                   /*!< authmode from SNI callback     */
    mbedtls_ssl_key_cert *sni_key_cert; /*!< key/cert list from SNI         */
    mbedtls_x509_crt *sni_ca_chain;     /*!< trusted CAs from SNI callback  */
    mbedtls_x509_crl *sni_ca_crl;       /*!< trusted CAs CRLs from SNI      */
#endif /* MBEDTLS_SSL_SERVER_NAME_INDICATION */
#endif /* MBEDTLS_X509_CRT_PARSE_C */
    unsigned char randbytes[64];        /*!<  random bytes            */
    unsigned char premaster[MBEDTLS_PREMASTER_SIZE];
                                        /*!<  premaster secret        */

#if !defined(MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE)
    mbedtls_ssl_ciphersuite_handle_t ciphersuite_info;
#endif /* !MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE */

#if !defined(MBEDTLS_SSL_NO_SESSION_RESUMPTION)
    volatile int resume;                /*!<  session resume indicator*/
#endif /* !MBEDTLS_SSL_NO_SESSION_RESUMPTION */

#if defined(MBEDTLS_SSL_SRV_C) &&                        \
    ( defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) ||       \
      defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED ) )
    int max_major_ver;                  /*!< max. major version client*/
    int max_minor_ver;                  /*!< max. minor version client*/
#endif /* MBEDTLS_SSL_SRV_C && ( MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED ||
                                 MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED ) */

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    int new_session_ticket;             /*!< use NewSessionTicket?    */
#endif /* MBEDTLS_SSL_SESSION_TICKETS */
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET) &&      \
    !defined(MBEDTLS_SSL_EXTENDED_MS_ENFORCED)
    int extended_ms;                    /*!< use Extended Master Secret? */
#endif

#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    uint8_t async_in_progress;          /*!< an asynchronous operation is in progress */
#endif /* MBEDTLS_SSL_ASYNC_PRIVATE */

#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    /** Asynchronous operation context. This field is meant for use by the
     * asynchronous operation callbacks (mbedtls_ssl_config::f_async_sign_start,
     * mbedtls_ssl_config::f_async_decrypt_start,
     * mbedtls_ssl_config::f_async_resume, mbedtls_ssl_config::f_async_cancel).
     * The library does not use it internally. */
    void *user_async_ctx;
#endif /* MBEDTLS_SSL_ASYNC_PRIVATE */

#if defined(MBEDTLS_USE_TINYCRYPT)
    uint8_t ecdh_privkey[NUM_ECC_BYTES];
    uint8_t ecdh_peerkey[2*NUM_ECC_BYTES];
#endif /* MBEDTLS_USE_TINYCRYPT */

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

#if defined(MBEDTLS_DHM_C)
    mbedtls_dhm_context dhm_ctx;                /*!<  DHM key exchange        */
#endif
#if defined(MBEDTLS_ECDH_C)
    mbedtls_ecdh_context ecdh_ctx;              /*!<  ECDH key exchange       */
#endif
};

/*
 * Getter functions for fields in mbedtls_ssl_handshake_params which
 * may be statically implied by the configuration and hence be omitted
 * from the structure.
 */
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
static inline int mbedtls_ssl_hs_get_extended_ms(
    mbedtls_ssl_handshake_params const *params )
{
#if !defined(MBEDTLS_SSL_EXTENDED_MS_ENFORCED)
    return( params->extended_ms );
#else
    ((void) params);
    return( MBEDTLS_SSL_EXTENDED_MS_ENABLED );
#endif /* MBEDTLS_SSL_EXTENDED_MS_ENFORCED */
}
#endif /* MBEDTLS_SSL_EXTENDED_MASTER_SECRET */

#if !defined(MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE)
static inline mbedtls_ssl_ciphersuite_handle_t mbedtls_ssl_handshake_get_ciphersuite(
    mbedtls_ssl_handshake_params const *handshake )
{
    return( handshake->ciphersuite_info );
}
#else /* !MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE */
static inline mbedtls_ssl_ciphersuite_handle_t mbedtls_ssl_handshake_get_ciphersuite(
    mbedtls_ssl_handshake_params const *handshake )
{
    ((void) handshake);
    return( MBEDTLS_SSL_CIPHERSUITE_UNIQUE_VALID_HANDLE );
}
#endif /* MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE */

typedef struct mbedtls_ssl_hs_buffer mbedtls_ssl_hs_buffer;

/*
 * Representation of decryption/encryption transformations on records
 *
 * There are the following general types of record transformations:
 * - Stream transformations (TLS versions <= 1.2 only)
 *   Transformation adding a MAC and applying a stream-cipher
 *   to the authenticated message.
 * - CBC block cipher transformations ([D]TLS versions <= 1.2 only)
 *   In addition to the distinction of the order of encryption and
 *   authentication, there's a fundamental difference between the
 *   handling in SSL3 & TLS 1.0 and TLS 1.1 and TLS 1.2: For SSL3
 *   and TLS 1.0, the final IV after processing a record is used
 *   as the IV for the next record. No explicit IV is contained
 *   in an encrypted record. The IV for the first record is extracted
 *   at key extraction time. In contrast, for TLS 1.1 and 1.2, no
 *   IV is generated at key extraction time, but every encrypted
 *   record is explicitly prefixed by the IV with which it was encrypted.
 * - AEAD transformations ([D]TLS versions >= 1.2 only)
 *   These come in two fundamentally different versions, the first one
 *   used in TLS 1.2, excluding ChaChaPoly ciphersuites, and the second
 *   one used for ChaChaPoly ciphersuites in TLS 1.2 as well as for TLS 1.3.
 *   In the first transformation, the IV to be used for a record is obtained
 *   as the concatenation of an explicit, static 4-byte IV and the 8-byte
 *   record sequence number, and explicitly prepending this sequence number
 *   to the encrypted record. In contrast, in the second transformation
 *   the IV is obtained by XOR'ing a static IV obtained at key extraction
 *   time with the 8-byte record sequence number, without prepending the
 *   latter to the encrypted record.
 *
 * In addition to type and version, the following parameters are relevant:
 * - The symmetric cipher algorithm to be used.
 * - The (static) encryption/decryption keys for the cipher.
 * - For stream/CBC, the type of message digest to be used.
 * - For stream/CBC, (static) encryption/decryption keys for the digest.
 * - For AEAD transformations, the size (potentially 0) of an explicit,
 *   random initialization vector placed in encrypted records.
 * - For some transformations (currently AEAD and CBC in SSL3 and TLS 1.0)
 *   an implicit IV. It may be static (e.g. AEAD) or dynamic (e.g. CBC)
 *   and (if present) is combined with the explicit IV in a transformation-
 *   dependent way (e.g. appending in TLS 1.2 and XOR'ing in TLS 1.3).
 * - For stream/CBC, a flag determining the order of encryption and MAC.
 * - The details of the transformation depend on the SSL/TLS version.
 * - The length of the authentication tag.
 *
 * Note: Except for CBC in SSL3 and TLS 1.0, these parameters are
 *       constant across multiple encryption/decryption operations.
 *       For CBC, the implicit IV needs to be updated after each
 *       operation.
 *
 * The struct below refines this abstract view as follows:
 * - The cipher underlying the transformation is managed in
 *   cipher contexts cipher_ctx_{enc/dec}, which must have the
 *   same cipher type. The mode of these cipher contexts determines
 *   the type of the transformation in the sense above: e.g., if
 *   the type is MBEDTLS_CIPHER_AES_256_CBC resp. MBEDTLS_CIPHER_AES_192_GCM
 *   then the transformation has type CBC resp. AEAD.
 * - The cipher keys are never stored explicitly but
 *   are maintained within cipher_ctx_{enc/dec}.
 * - For stream/CBC transformations, the message digest contexts
 *   used for the MAC's are stored in md_ctx_{enc/dec}. These contexts
 *   are unused for AEAD transformations.
 * - For stream/CBC transformations and versions > SSL3, the
 *   MAC keys are not stored explicitly but maintained within
 *   md_ctx_{enc/dec}.
 * - For stream/CBC transformations and version SSL3, the MAC
 *   keys are stored explicitly in mac_enc, mac_dec and have
 *   a fixed size of 20 bytes. These fields are unused for
 *   AEAD transformations or transformations >= TLS 1.0.
 * - For transformations using an implicit IV maintained within
 *   the transformation context, its contents are stored within
 *   iv_{enc/dec}.
 * - The value of ivlen indicates the length of the IV.
 *   This is redundant in case of stream/CBC transformations
 *   which always use 0 resp. the cipher's block length as the
 *   IV length, but is needed for AEAD ciphers and may be
 *   different from the underlying cipher's block length
 *   in this case.
 * - The field fixed_ivlen is nonzero for AEAD transformations only
 *   and indicates the length of the static part of the IV which is
 *   constant throughout the communication, and which is stored in
 *   the first fixed_ivlen bytes of the iv_{enc/dec} arrays.
 *   Note: For CBC in SSL3 and TLS 1.0, the fields iv_{enc/dec}
 *   still store IV's for continued use across multiple transformations,
 *   so it is not true that fixed_ivlen == 0 means that iv_{enc/dec} are
 *   not being used!
 * - minor_ver denotes the SSL/TLS version
 * - For stream/CBC transformations, maclen denotes the length of the
 *   authentication tag, while taglen is unused and 0.
 * - For AEAD transformations, taglen denotes the length of the
 *   authentication tag, while maclen is unused and 0.
 * - For CBC transformations, encrypt_then_mac determines the
 *   order of encryption and authentication. This field is unused
 *   in other transformations.
 *
 */
struct mbedtls_ssl_transform
{
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    uint8_t in_cid_len;
    uint8_t out_cid_len;
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
    /*
     * Session specific crypto layer
     */
    size_t ivlen;                       /*!<  IV length               */
    size_t fixed_ivlen;                 /*!<  Fixed part of IV (AEAD) */
    size_t maclen;                      /*!<  MAC(CBC) len            */
    size_t taglen;                      /*!<  TAG(AEAD) len           */

    unsigned char iv_enc[16];           /*!<  IV (encryption)         */
    unsigned char iv_dec[16];           /*!<  IV (decryption)         */

#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)

#if defined(MBEDTLS_SSL_PROTO_SSL3)
    /* Needed only for SSL v3.0 secret */
    unsigned char mac_enc[20];          /*!<  SSL v3.0 secret (enc)   */
    unsigned char mac_dec[20];          /*!<  SSL v3.0 secret (dec)   */
#endif /* MBEDTLS_SSL_PROTO_SSL3 */

    mbedtls_md_context_t md_ctx_enc;            /*!<  MAC (encryption)        */
    mbedtls_md_context_t md_ctx_dec;            /*!<  MAC (decryption)        */

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    int encrypt_then_mac;       /*!< flag for EtM activation                */
#endif

#endif /* MBEDTLS_SSL_SOME_MODES_USE_MAC */

#if !defined(MBEDTLS_SSL_CONF_FIXED_MINOR_VER)
    int minor_ver;
#endif

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    unsigned char in_cid [ MBEDTLS_SSL_CID_OUT_LEN_MAX ];
    unsigned char out_cid[ MBEDTLS_SSL_CID_OUT_LEN_MAX ];
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

    /*
     * Session specific compression layer
     */
#if defined(MBEDTLS_ZLIB_SUPPORT)
    z_stream ctx_deflate;               /*!<  compression context     */
    z_stream ctx_inflate;               /*!<  decompression context   */
#endif

#if defined(MBEDTLS_SSL_TRANSFORM_OPTIMIZE_CIPHERS)
    unsigned char *key_enc;
    unsigned char *key_dec;
    unsigned int key_bitlen;
    mbedtls_cipher_context_t cipher_ctx;    /*!<  encryption/decryption context */
#if defined(MBEDTLS_VALIDATE_SSL_KEYS_INTEGRITY)
    uint32_t key_enc_hash;                  /*!< hash of the encryption key */
    uint32_t key_dec_hash;                  /*!< hash of the decryption key */
#endif
#else
    mbedtls_cipher_context_t cipher_ctx_enc;    /*!<  encryption context      */
    mbedtls_cipher_context_t cipher_ctx_dec;    /*!<  decryption context      */
#endif
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
    /* We need the Hello random bytes in order to re-derive keys from the
     * Master Secret and other session info, see ssl_populate_transform() */
    unsigned char randbytes[64]; /*!< ServerHello.random+ClientHello.random */
#endif /* MBEDTLS_SSL_CONTEXT_SERIALIZATION */
};

static inline int mbedtls_ssl_transform_get_minor_ver( mbedtls_ssl_transform const *transform )
{
#if !defined(MBEDTLS_SSL_CONF_FIXED_MINOR_VER)
    return( transform->minor_ver );
#else
    ((void) transform);
    return( MBEDTLS_SSL_CONF_FIXED_MINOR_VER );
#endif
}

/*
 * Return 1 if the transform uses an AEAD cipher, 0 otherwise.
 * Equivalently, return 0 if a separate MAC is used, 1 otherwise.
 */
static inline int mbedtls_ssl_transform_uses_aead(
        const mbedtls_ssl_transform *transform )
{
#if defined(MBEDTLS_SSL_SOME_MODES_USE_MAC)
    return( transform->maclen == 0 && transform->taglen != 0 );
#else
    (void) transform;
    return( 1 );
#endif
}

/*
 * Internal representation of record frames
 *
 * Instances come in two flavors:
 * (1) Encrypted
 *     These always have data_offset = 0
 * (2) Unencrypted
 *     These have data_offset set to the amount of
 *     pre-expansion during record protection. Concretely,
 *     this is the length of the fixed part of the explicit IV
 *     used for encryption, or 0 if no explicit IV is used
 *     (e.g. for CBC in TLS 1.0, or stream ciphers).
 *
 * The reason for the data_offset in the unencrypted case
 * is to allow for in-place conversion of an unencrypted to
 * an encrypted record. If the offset wasn't included, the
 * encrypted content would need to be shifted afterwards to
 * make space for the fixed IV.
 *
 */
#if MBEDTLS_SSL_CID_OUT_LEN_MAX > MBEDTLS_SSL_CID_IN_LEN_MAX
#define MBEDTLS_SSL_CID_LEN_MAX MBEDTLS_SSL_CID_OUT_LEN_MAX
#else
#define MBEDTLS_SSL_CID_LEN_MAX MBEDTLS_SSL_CID_IN_LEN_MAX
#endif

typedef struct
{
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    uint8_t cid_len;        /* Length of the CID (0 if not present)          */
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
    uint8_t type;           /* The record content type.                      */
    uint8_t ver[2];         /* SSL/TLS version as present on the wire.
                             * Convert to internal presentation of versions
                             * using mbedtls_ssl_read_version() and
                             * mbedtls_ssl_write_version().
                             * Keep wire-format for MAC computations.        */

    unsigned char *buf;     /* Memory buffer enclosing the record content    */
    size_t buf_len;         /* Buffer length                                 */
    size_t data_offset;     /* Offset of record content                      */
    size_t data_len;        /* Length of record content                      */
    uint8_t ctr[8];         /* In TLS:  The implicit record sequence number.
                             * In DTLS: The 2-byte epoch followed by
                             *          the 6-byte sequence number.
                             * This is stored as a raw big endian byte array
                             * as opposed to a uint64_t because we rarely
                             * need to perform arithmetic on this, but do
                             * need it as a Byte array for the purpose of
                             * MAC computations.                             */
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    unsigned char cid[ MBEDTLS_SSL_CID_LEN_MAX ]; /* The CID                 */
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */
} mbedtls_record;

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

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)

/* Find an entry in a signature-hash set matching a given hash algorithm. */
mbedtls_md_type_t mbedtls_ssl_sig_hash_set_find( mbedtls_ssl_sig_hash_set_t *set,
                                                 mbedtls_pk_type_t sig_alg );
/* Add a signature-hash-pair to a signature-hash set */
void mbedtls_ssl_sig_hash_set_add( mbedtls_ssl_sig_hash_set_t *set,
                                   mbedtls_pk_type_t sig_alg,
                                   mbedtls_md_type_t md_alg );
/* Allow exactly one hash algorithm for each signature. */
void mbedtls_ssl_sig_hash_set_const_hash( mbedtls_ssl_sig_hash_set_t *set,
                                          mbedtls_md_type_t md_alg );

/* Setup an empty signature-hash set */
static inline void mbedtls_ssl_sig_hash_set_init( mbedtls_ssl_sig_hash_set_t *set )
{
    mbedtls_ssl_sig_hash_set_const_hash( set, MBEDTLS_MD_NONE );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_2) &&
          MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED */

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
 * \param ssl       SSL context
 */
void mbedtls_ssl_handshake_free( mbedtls_ssl_context *ssl );

int mbedtls_ssl_handshake_client_step( mbedtls_ssl_context *ssl );
int mbedtls_ssl_handshake_server_step( mbedtls_ssl_context *ssl );
int mbedtls_ssl_handshake_wrapup( mbedtls_ssl_context *ssl );

int mbedtls_ssl_send_fatal_handshake_failure( mbedtls_ssl_context *ssl );

void mbedtls_ssl_reset_checksum( mbedtls_ssl_context *ssl );
int mbedtls_ssl_derive_keys( mbedtls_ssl_context *ssl );

int mbedtls_ssl_handle_message_type( mbedtls_ssl_context *ssl );
int mbedtls_ssl_prepare_handshake_record( mbedtls_ssl_context *ssl );
void mbedtls_ssl_update_handshake_status( mbedtls_ssl_context *ssl );

/**
 * \brief       Update record layer
 *
 *              This function roughly separates the implementation
 *              of the logic of (D)TLS from the implementation
 *              of the secure transport.
 *
 * \param  ssl              The SSL context to use.
 * \param  update_hs_digest This indicates if the handshake digest
 *                          should be automatically updated in case
 *                          a handshake message is found.
 *
 * \return      0 or non-zero error code.
 *
 * \note        A clarification on what is called 'record layer' here
 *              is in order, as many sensible definitions are possible:
 *
 *              The record layer takes as input an untrusted underlying
 *              transport (stream or datagram) and transforms it into
 *              a serially multiplexed, secure transport, which
 *              conceptually provides the following:
 *
 *              (1) Three datagram based, content-agnostic transports
 *                  for handshake, alert and CCS messages.
 *              (2) One stream- or datagram-based transport
 *                  for application data.
 *              (3) Functionality for changing the underlying transform
 *                  securing the contents.
 *
 *              The interface to this functionality is given as follows:
 *
 *              a Updating
 *                [Currently implemented by mbedtls_ssl_read_record]
 *
 *                Check if and on which of the four 'ports' data is pending:
 *                Nothing, a controlling datagram of type (1), or application
 *                data (2). In any case data is present, internal buffers
 *                provide access to the data for the user to process it.
 *                Consumption of type (1) datagrams is done automatically
 *                on the next update, invalidating that the internal buffers
 *                for previous datagrams, while consumption of application
 *                data (2) is user-controlled.
 *
 *              b Reading of application data
 *                [Currently manual adaption of ssl->in_offt pointer]
 *
 *                As mentioned in the last paragraph, consumption of data
 *                is different from the automatic consumption of control
 *                datagrams (1) because application data is treated as a stream.
 *
 *              c Tracking availability of application data
 *                [Currently manually through decreasing ssl->in_msglen]
 *
 *                For efficiency and to retain datagram semantics for
 *                application data in case of DTLS, the record layer
 *                provides functionality for checking how much application
 *                data is still available in the internal buffer.
 *
 *              d Changing the transformation securing the communication.
 *
 *              Given an opaque implementation of the record layer in the
 *              above sense, it should be possible to implement the logic
 *              of (D)TLS on top of it without the need to know anything
 *              about the record layer's internals. This is done e.g.
 *              in all the handshake handling functions, and in the
 *              application data reading function mbedtls_ssl_read.
 *
 * \note        The above tries to give a conceptual picture of the
 *              record layer, but the current implementation deviates
 *              from it in some places. For example, our implementation of
 *              the update functionality through mbedtls_ssl_read_record
 *              discards datagrams depending on the current state, which
 *              wouldn't fall under the record layer's responsibility
 *              following the above definition.
 *
 */
int mbedtls_ssl_read_record( mbedtls_ssl_context *ssl,
                             unsigned update_hs_digest );
int mbedtls_ssl_fetch_input( mbedtls_ssl_context *ssl, size_t nb_want );

int mbedtls_ssl_write_handshake_msg( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_record( mbedtls_ssl_context *ssl, uint8_t force_flush );
int mbedtls_ssl_flush_output( mbedtls_ssl_context *ssl );

int mbedtls_ssl_parse_certificate( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_certificate( mbedtls_ssl_context *ssl );

int mbedtls_ssl_parse_change_cipher_spec( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_change_cipher_spec( mbedtls_ssl_context *ssl );

int mbedtls_ssl_parse_finished( mbedtls_ssl_context *ssl );
int mbedtls_ssl_write_finished( mbedtls_ssl_context *ssl );

void mbedtls_ssl_optimize_checksum( mbedtls_ssl_context *ssl,
                            mbedtls_ssl_ciphersuite_handle_t ciphersuite_info );

int mbedtls_ssl_build_pms( mbedtls_ssl_context *ssl );

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
int mbedtls_ssl_psk_derive_premaster( mbedtls_ssl_context *ssl, mbedtls_key_exchange_type_t key_ex );
#endif

#if defined(MBEDTLS_PK_C)
unsigned char mbedtls_ssl_sig_from_pk( mbedtls_pk_context *pk );
unsigned char mbedtls_ssl_sig_from_pk_alg( mbedtls_pk_type_t type );
mbedtls_pk_type_t mbedtls_ssl_pk_alg_from_sig( unsigned char sig );
#endif

mbedtls_md_type_t mbedtls_ssl_md_alg_from_hash( unsigned char hash );
unsigned char mbedtls_ssl_hash_from_md_alg( int md );

#if defined(MBEDTLS_USE_TINYCRYPT)
int mbedtls_ssl_check_curve_uecc( const mbedtls_ssl_context *ssl,
                                  mbedtls_uecc_group_id grp_id );
#endif

#if defined(MBEDTLS_ECP_C)
int mbedtls_ssl_check_curve( const mbedtls_ssl_context *ssl,
                             mbedtls_ecp_group_id grp_id );
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED)
int mbedtls_ssl_check_sig_hash( const mbedtls_ssl_context *ssl,
                                mbedtls_md_type_t md );
#endif

#if defined(MBEDTLS_KEY_EXCHANGE__WITH_CERT__ENABLED) && defined(MBEDTLS_DELAYED_SERVER_CERT_VERIFICATION)
int ssl_parse_delayed_certificate_verify( mbedtls_ssl_context *ssl,
                                         int authmode,
                                         mbedtls_x509_crt *chain,
                                         void *rs_ctx );
#endif /* MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED && MBEDTLS_DELAYED_SERVER_CERT_VERIFICATION */


static inline int mbedtls_ssl_get_minor_ver( mbedtls_ssl_context const *ssl )
{
#if !defined(MBEDTLS_SSL_CONF_FIXED_MINOR_VER)
    return( ssl->minor_ver );
#else /* !MBEDTLS_SSL_CONF_FIXED_MINOR_VER */
    ((void) ssl);
    return( MBEDTLS_SSL_CONF_FIXED_MINOR_VER );
#endif /* MBEDTLS_SSL_CONF_FIXED_MINOR_VER */
}

static inline int mbedtls_ssl_get_major_ver( mbedtls_ssl_context const *ssl )
{
#if !defined(MBEDTLS_SSL_CONF_FIXED_MAJOR_VER)
    return( ssl->major_ver );
#else /* !MBEDTLS_SSL_CONF_FIXED_MAJOR_VER */
    ((void) ssl);
    return( MBEDTLS_SSL_CONF_FIXED_MAJOR_VER );
#endif /* MBEDTLS_SSL_CONF_FIXED_MAJOR_VER */
}

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
                          mbedtls_ssl_ciphersuite_handle_t ciphersuite,
                          int cert_endpoint,
                          uint32_t *flags );
#endif /* MBEDTLS_X509_CRT_PARSE_C */

static inline size_t mbedtls_ssl_in_hdr_len( const mbedtls_ssl_context *ssl )
{
#if !defined(MBEDTLS_SSL_PROTO__BOTH)
    ((void) ssl);
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( MBEDTLS_SSL_TRANSPORT_IS_DTLS( ssl->conf->transport ) )
    {
        return( 13 );
    }
    MBEDTLS_SSL_TRANSPORT_ELSE
#endif /* MBEDTLS_SSL_PROTO_DTLS */
#if defined(MBEDTLS_SSL_PROTO_TLS)
    {
        return( 5 );
    }
#endif /* MBEDTLS_SSL_PROTO_TLS */
}

static inline size_t mbedtls_ssl_out_hdr_len( const mbedtls_ssl_context *ssl )
{
    return( (size_t) ( ssl->out_iv - ssl->out_hdr ) );
}

static inline size_t mbedtls_ssl_hs_hdr_len( const mbedtls_ssl_context *ssl )
{
#if !defined(MBEDTLS_SSL_PROTO__BOTH)
    ((void) ssl);
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( MBEDTLS_SSL_TRANSPORT_IS_DTLS( ssl->conf->transport ) )
        return( 12 );
    MBEDTLS_SSL_TRANSPORT_ELSE
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS)
        return( 4 );
#endif
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
void mbedtls_ssl_send_flight_completed( mbedtls_ssl_context *ssl );
void mbedtls_ssl_recv_flight_completed( mbedtls_ssl_context *ssl );
int mbedtls_ssl_resend( mbedtls_ssl_context *ssl );
int mbedtls_ssl_flight_transmit( mbedtls_ssl_context *ssl );
#endif

/* Visible for testing purposes only */
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
int mbedtls_ssl_dtls_replay_check( mbedtls_ssl_context const *ssl );
void mbedtls_ssl_dtls_replay_update( mbedtls_ssl_context *ssl );
#endif

int mbedtls_ssl_session_copy( mbedtls_ssl_session *dst,
                              const mbedtls_ssl_session *src );

#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_1)
int mbedtls_ssl_get_key_exchange_md_ssl_tls( mbedtls_ssl_context *ssl,
                                        unsigned char *output,
                                        unsigned char *data, size_t data_len );
#endif /* MBEDTLS_SSL_PROTO_SSL3 || MBEDTLS_SSL_PROTO_TLS1 || \
          MBEDTLS_SSL_PROTO_TLS1_1 */

#if defined(MBEDTLS_SSL_PROTO_TLS1) || defined(MBEDTLS_SSL_PROTO_TLS1_1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_2)
int mbedtls_ssl_get_key_exchange_md_tls1_2( mbedtls_ssl_context *ssl,
                                            unsigned char *hash, size_t *hashlen,
                                            unsigned char *data, size_t data_len,
                                            mbedtls_md_type_t md_alg );
#endif /* MBEDTLS_SSL_PROTO_TLS1 || MBEDTLS_SSL_PROTO_TLS1_1 || \
          MBEDTLS_SSL_PROTO_TLS1_2 */

#if defined(MBEDTLS_SSL_PROTO_TLS)

/*
 * Convert version numbers to/from wire format
 * and, for DTLS, to/from TLS equivalent.
 *
 * For TLS this is the identity.
 * For DTLS, use 1's complement (v -> 255 - v, and then map as follows:
 * 1.0 <-> 3.2      (DTLS 1.0 is based on TLS 1.1)
 * 1.x <-> 3.x+1    for x != 0 (DTLS 1.2 based on TLS 1.2)
 */
MBEDTLS_ALWAYS_INLINE static inline void mbedtls_ssl_write_version(
    int major, int minor, int transport, unsigned char ver[2] )
{
#if !defined(MBEDTLS_SSL_TRANSPORT__BOTH)
    ((void) transport);
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( MBEDTLS_SSL_TRANSPORT_IS_DTLS( transport ) )
    {
        if( minor == MBEDTLS_SSL_MINOR_VERSION_2 )
            --minor; /* DTLS 1.0 stored as TLS 1.1 internally */

        ver[0] = (unsigned char)( 255 - ( major - 2 ) );
        ver[1] = (unsigned char)( 255 - ( minor - 1 ) );
    }
    MBEDTLS_SSL_TRANSPORT_ELSE
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS)
    {
        ver[0] = (unsigned char) major;
        ver[1] = (unsigned char) minor;
    }
#endif
}

MBEDTLS_ALWAYS_INLINE static inline void mbedtls_ssl_read_version(
    int *major, int *minor, int transport, const unsigned char ver[2] )
{
#if !defined(MBEDTLS_SSL_TRANSPORT__BOTH)
    ((void) transport);
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( MBEDTLS_SSL_TRANSPORT_IS_DTLS( transport ) )
    {
        *major = 255 - ver[0] + 2;
        *minor = 255 - ver[1] + 1;

        if( *minor == MBEDTLS_SSL_MINOR_VERSION_1 )
            ++*minor; /* DTLS 1.0 stored as TLS 1.1 internally */
    }
    MBEDTLS_SSL_TRANSPORT_ELSE
#endif /* MBEDTLS_SSL_PROTO_DTLS */
#if defined(MBEDTLS_SSL_PROTO_TLS)
    {
        *major = ver[0];
        *minor = ver[1];
    }
#endif /* MBEDTLS_SSL_PROTO_TLS */
}


MBEDTLS_ALWAYS_INLINE static inline int mbedtls_ssl_ver_leq( int v0, int v1 )
{
    return( v0 <= v1 );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_ssl_ver_lt( int v0, int v1 )
{
    return( v0 < v1 );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_ssl_ver_geq( int v0, int v1 )
{
    return( v0 >= v1 );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_ssl_ver_gt( int v0, int v1 )
{
    return( v0 > v1 );
}

#else /* MBEDTLS_SSL_PROTO_TLS */

/* If only DTLS is enabled, we can match the internal encoding
 * with the standard's encoding of versions. */
static inline void mbedtls_ssl_write_version( int major, int minor,
                                              int transport,
                                              unsigned char ver[2] )
{
    ((void) transport);
    ver[0] = (unsigned char) major;
    ver[1] = (unsigned char) minor;
}

static inline void mbedtls_ssl_read_version( int *major, int *minor,
                                             int transport,
                                             const unsigned char ver[2] )
{
    ((void) transport);
    *major = ver[0];
    *minor = ver[1];
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_ssl_ver_leq( int v0, int v1 )
{
    return( v0 >= v1 );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_ssl_ver_lt( int v0, int v1 )
{
    return( v0 > v1 );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_ssl_ver_geq( int v0, int v1 )
{
    return( v0 <= v1 );
}

MBEDTLS_ALWAYS_INLINE static inline int mbedtls_ssl_ver_gt( int v0, int v1 )
{
    return( v0 < v1 );
}

#endif /* MBEDTLS_SSL_PROTO_TLS */

MBEDTLS_ALWAYS_INLINE static inline size_t mbedtls_ssl_minor_ver_index(
    int ver )
{
    switch( ver )
    {
        case MBEDTLS_SSL_MINOR_VERSION_0:
            return( 0 );
        case MBEDTLS_SSL_MINOR_VERSION_1:
            return( 1 );
        case MBEDTLS_SSL_MINOR_VERSION_2:
            return( 2 );
        case MBEDTLS_SSL_MINOR_VERSION_3:
            return( 3 );
    }
    return( 0 );
}

#ifdef __cplusplus
}
#endif

void mbedtls_ssl_transform_init( mbedtls_ssl_transform *transform );
int mbedtls_ssl_encrypt_buf( mbedtls_ssl_context *ssl,
                             mbedtls_ssl_transform *transform,
                             mbedtls_record *rec,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng );
int mbedtls_ssl_decrypt_buf( mbedtls_ssl_context const *ssl,
                             mbedtls_ssl_transform *transform,
                             mbedtls_record *rec );


/*
 * Accessor functions for optional fields of various structures
 */

static inline int mbedtls_ssl_handshake_get_resume(
        const mbedtls_ssl_handshake_params *handshake )
{
#if !defined(MBEDTLS_SSL_NO_SESSION_RESUMPTION)
    return( handshake->resume );
#else
    (void) handshake;
    return( 0 );
#endif
}

static inline int mbedtls_ssl_get_renego_status(
        const mbedtls_ssl_context *ssl )
{
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    return( ssl->renego_status );
#else
    (void) ssl;
    return( MBEDTLS_SSL_INITIAL_HANDSHAKE );
#endif
}

static inline int mbedtls_ssl_conf_is_renegotiation_enabled(
        const mbedtls_ssl_config *conf )
{
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    return( conf->disable_renegotiation ==
            MBEDTLS_SSL_RENEGOTIATION_ENABLED );
#else
    (void) conf;
    return( 0 );
#endif
}

/*
 * Getter functions for fields in mbedtls_ssl_config which may
 * be fixed at compile time via one of MBEDTLS_SSL_SSL_CONF_XXX.
 */

#if defined(MBEDTLS_SSL_SRV_C)
#if !defined(MBEDTLS_SSL_CONF_CERT_REQ_CA_LIST)
static inline unsigned int mbedtls_ssl_conf_get_cert_req_ca_list(
    mbedtls_ssl_config  const *conf )
{
    return( conf->cert_req_ca_list );
}
#else /* !MBEDTLS_SSL_CONF_CERT_REQ_CA_LIST */
static inline unsigned int mbedtls_ssl_conf_get_cert_req_ca_list(
    mbedtls_ssl_config  const *conf )
{
    ((void) conf);
    return( MBEDTLS_SSL_CONF_CERT_REQ_CA_LIST );
}
#endif /* MBEDTLS_SSL_CONF_CERT_REQ_CA_LIST */
#endif /* MBEDTLS_SSL_SRV_C */

#if !defined(MBEDTLS_SSL_CONF_ENDPOINT)
static inline unsigned int mbedtls_ssl_conf_get_endpoint(
    mbedtls_ssl_config  const *conf )
{
    return( conf->endpoint );
}
#else /* !MBEDTLS_SSL_CONF_ENDPOINT */
static inline unsigned int mbedtls_ssl_conf_get_endpoint(
    mbedtls_ssl_config  const *conf )
{
    ((void) conf);
    return( MBEDTLS_SSL_CONF_ENDPOINT );
}
#endif /* MBEDTLS_SSL_CONF_ENDPOINT */

#if !defined(MBEDTLS_SSL_CONF_TRANSPORT)
static inline unsigned int mbedtls_ssl_conf_get_transport(
    mbedtls_ssl_config const *conf )
{
    return( conf->transport );
}
#else /* !MBEDTLS_SSL_CONF_TRANSPORT */
static inline unsigned int mbedtls_ssl_conf_get_transport(
    mbedtls_ssl_config const *conf )
{
    ((void) conf);
    return( MBEDTLS_SSL_CONF_TRANSPORT );
}
#endif /* MBEDTLS_SSL_CONF_TRANSPORT */

#if !defined(MBEDTLS_SSL_CONF_READ_TIMEOUT)
static inline uint32_t mbedtls_ssl_conf_get_read_timeout(
    mbedtls_ssl_config  const *conf )
{
    return( conf->read_timeout );
}
#else /* !MBEDTLS_SSL_CONF_READ_TIMEOUT */
static inline uint32_t mbedtls_ssl_conf_get_read_timeout(
    mbedtls_ssl_config  const *conf )
{
    ((void) conf);
    return( MBEDTLS_SSL_CONF_READ_TIMEOUT );
}
#endif /* MBEDTLS_SSL_CONF_READ_TIMEOUT */

#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if !defined(MBEDTLS_SSL_CONF_HS_TIMEOUT_MIN)
static inline uint32_t mbedtls_ssl_conf_get_hs_timeout_min(
    mbedtls_ssl_config  const *conf )
{
    return( conf->hs_timeout_min );
}
#else /* !MBEDTLS_SSL_CONF_HS_TIMEOUT_MIN */
static inline uint32_t mbedtls_ssl_conf_get_hs_timeout_min(
    mbedtls_ssl_config  const *conf )
{
    ((void) conf);
    return( MBEDTLS_SSL_CONF_HS_TIMEOUT_MIN );
}
#endif /* MBEDTLS_SSL_CONF_HS_TIMEOUT_MIN */

#if !defined(MBEDTLS_SSL_CONF_HS_TIMEOUT_MAX)
static inline uint32_t mbedtls_ssl_conf_get_hs_timeout_max(
    mbedtls_ssl_config  const *conf )
{
    return( conf->hs_timeout_max );
}
#else /* !MBEDTLS_SSL_CONF_HS_TIMEOUT_MAX */
static inline uint32_t mbedtls_ssl_conf_get_hs_timeout_max(
    mbedtls_ssl_config  const *conf )
{
    ((void) conf);
    return( MBEDTLS_SSL_CONF_HS_TIMEOUT_MAX );
}
#endif /* MBEDTLS_SSL_CONF_HS_TIMEOUT_MAX */
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#if !defined(MBEDTLS_SSL_CONF_CID_LEN)
static inline size_t mbedtls_ssl_conf_get_cid_len(
    mbedtls_ssl_config  const *conf )
{
    return( conf->cid_len );
}
#else /* !MBEDTLS_SSL_CONF_CID_LEN */
static inline size_t mbedtls_ssl_conf_get_cid_len(
    mbedtls_ssl_config  const *conf )
{
    ((void) conf);
    return( MBEDTLS_SSL_CONF_CID_LEN );
}
#endif /* MBEDTLS_SSL_CONF_CID_LEN */

#if !defined(MBEDTLS_SSL_CONF_IGNORE_UNEXPECTED_CID)
static inline unsigned int mbedtls_ssl_conf_get_ignore_unexpected_cid(
    mbedtls_ssl_config  const *conf )
{
    return( conf->ignore_unexpected_cid );
}
#else /* !MBEDTLS_SSL_CONF_IGNORE_UNEXPECTED_CID */
static inline unsigned int mbedtls_ssl_conf_get_ignore_unexpected_cid(
    mbedtls_ssl_config  const *conf )
{
    ((void) conf);
    return( MBEDTLS_SSL_CONF_IGNORE_UNEXPECTED_CID );
}
#endif /* MBEDTLS_SSL_CONF_IGNORE_UNEXPECTED_CID */
#endif /* MBEDTLS_SSL_DTLS_CONNECTION_ID */

#if !defined(MBEDTLS_SSL_CONF_ALLOW_LEGACY_RENEGOTIATION)
static inline unsigned int mbedtls_ssl_conf_get_allow_legacy_renegotiation(
    mbedtls_ssl_config  const *conf )
{
    return( conf->allow_legacy_renegotiation );
}
#else /* !MBEDTLS_SSL_CONF_ALLOW_LEGACY_RENEGOTIATION */
static inline unsigned int mbedtls_ssl_conf_get_allow_legacy_renegotiation(
    mbedtls_ssl_config  const *conf )
{
    ((void) conf);
    return( MBEDTLS_SSL_CONF_ALLOW_LEGACY_RENEGOTIATION );
}
#endif /* MBEDTLS_SSL_CONF_ALLOW_LEGACY_RENEGOTIATION */

#if !defined(MBEDTLS_SSL_CONF_AUTHMODE)
static inline int mbedtls_ssl_conf_get_authmode(
    mbedtls_ssl_config  const *conf )
{
    return( conf->authmode );
}
#else /* !MBEDTLS_SSL_CONF_AUTHMODE */
static inline int mbedtls_ssl_conf_get_authmode(
    mbedtls_ssl_config const *conf )
{
    ((void) conf);
    return( MBEDTLS_SSL_CONF_AUTHMODE );
}
#endif /* MBEDTLS_SSL_CONF_AUTHMODE */

#if defined(MBEDTLS_SSL_DTLS_BADMAC_LIMIT)
#if !defined(MBEDTLS_SSL_CONF_BADMAC_LIMIT)
static inline unsigned int mbedtls_ssl_conf_get_badmac_limit(
    mbedtls_ssl_config  const *conf )
{
    return( conf->badmac_limit );
}
#else /* !MBEDTLS_SSL_CONF_BADMAC_LIMIT */
static inline unsigned int mbedtls_ssl_conf_get_badmac_limit(
    mbedtls_ssl_config  const *conf )
{
    ((void) conf);
    return( MBEDTLS_SSL_CONF_BADMAC_LIMIT );
}
#endif /* MBEDTLS_SSL_CONF_BADMAC_LIMIT */
#endif /* MBEDTLS_SSL_DTLS_BADMAC_LIMIT */

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
#if !defined(MBEDTLS_SSL_CONF_ANTI_REPLAY)
static inline unsigned int mbedtls_ssl_conf_get_anti_replay(
    mbedtls_ssl_config  const *conf )
{
    return( conf->anti_replay );
}
#else /* !MBEDTLS_SSL_CONF_ANTI_REPLAY */
static inline unsigned int mbedtls_ssl_conf_get_anti_replay(
    mbedtls_ssl_config  const *conf )
{
    ((void) conf);
    return( MBEDTLS_SSL_CONF_ANTI_REPLAY );
}
#endif /* MBEDTLS_SSL_CONF_ANTI_REPLAY */
#endif /* MBEDTLS_SSL_DTLS_ANTI_REPLAY */

#if !defined(MBEDTLS_SSL_CONF_SET_TIMER)
static inline mbedtls_ssl_set_timer_t* mbedtls_ssl_get_set_timer(
    mbedtls_ssl_context const *ssl )
{
    return( ssl->f_set_timer );
}
#else /* !MBEDTLS_SSL_CONF_SET_TIMER */

#define mbedtls_ssl_conf_set_timer_func MBEDTLS_SSL_CONF_SET_TIMER
extern void mbedtls_ssl_conf_set_timer_func( void*, uint32_t, uint32_t );

static inline mbedtls_ssl_set_timer_t* mbedtls_ssl_get_set_timer(
    mbedtls_ssl_context const *ssl )
{
    ((void) ssl);
    return ((mbedtls_ssl_set_timer_t*) mbedtls_ssl_conf_set_timer_func);
}
#endif /* MBEDTLS_SSL_CONF_SET_TIMER */

#if !defined(MBEDTLS_SSL_CONF_GET_TIMER)
static inline mbedtls_ssl_get_timer_t* mbedtls_ssl_get_get_timer(
    mbedtls_ssl_context const *ssl )
{
    return( ssl->f_get_timer );
}
#else /* !MBEDTLS_SSL_CONF_GET_TIMER */

#define mbedtls_ssl_conf_get_timer_func MBEDTLS_SSL_CONF_GET_TIMER
extern int mbedtls_ssl_conf_get_timer_func( void* );

static inline mbedtls_ssl_get_timer_t* mbedtls_ssl_get_get_timer(
    mbedtls_ssl_context const *ssl )
{
    ((void) ssl);
    return ((mbedtls_ssl_get_timer_t*) mbedtls_ssl_conf_get_timer_func);
}
#endif /* MBEDTLS_SSL_CONF_GET_TIMER */

#if !defined(MBEDTLS_SSL_CONF_RECV)
static inline mbedtls_ssl_recv_t* mbedtls_ssl_get_recv(
    mbedtls_ssl_context const *ssl )
{
    return( ssl->f_recv );
}
#else /* !MBEDTLS_SSL_CONF_RECV */

#define mbedtls_ssl_conf_recv_func MBEDTLS_SSL_CONF_RECV
extern int mbedtls_ssl_conf_recv_func( void*, unsigned char*, size_t );

static inline mbedtls_ssl_recv_t* mbedtls_ssl_get_recv(
    mbedtls_ssl_context const *ssl )
{
    ((void) ssl);
    return ((mbedtls_ssl_recv_t*) mbedtls_ssl_conf_recv_func);
}
#endif /* MBEDTLS_SSL_CONF_RECV */

#if !defined(MBEDTLS_SSL_CONF_SEND)
static inline mbedtls_ssl_send_t* mbedtls_ssl_get_send(
    mbedtls_ssl_context const *ssl )
{
    return( ssl->f_send );
}
#else /* !MBEDTLS_SSL_CONF_SEND */

#define mbedtls_ssl_conf_send_func MBEDTLS_SSL_CONF_SEND
extern int mbedtls_ssl_conf_send_func( void*, unsigned char const*, size_t );

static inline mbedtls_ssl_send_t* mbedtls_ssl_get_send(
    mbedtls_ssl_context const *ssl )
{
    ((void) ssl);
    return ((mbedtls_ssl_send_t*) mbedtls_ssl_conf_send_func);
}
#endif /* MBEDTLS_SSL_CONF_SEND */

#if !defined(MBEDTLS_SSL_CONF_RECV_TIMEOUT)
static inline mbedtls_ssl_recv_timeout_t* mbedtls_ssl_get_recv_timeout(
    mbedtls_ssl_context const *ssl )
{
    return( ssl->f_recv_timeout );
}
#else /* !MBEDTLS_SSL_CONF_RECV_TIMEOUT */

#define mbedtls_ssl_conf_recv_timeout_func MBEDTLS_SSL_CONF_RECV_TIMEOUT
extern int mbedtls_ssl_conf_recv_timeout_func(
    void*, unsigned char*, size_t, uint32_t );

static inline mbedtls_ssl_recv_timeout_t* mbedtls_ssl_get_recv_timeout(
    mbedtls_ssl_context const *ssl )
{
    ((void) ssl);
    return ((mbedtls_ssl_recv_timeout_t*) mbedtls_ssl_conf_recv_timeout_func);
}
#endif /* MBEDTLS_SSL_CONF_RECV_TIMEOUT */

typedef int mbedtls_frng_t( void*, unsigned char*, size_t );

#if !defined(MBEDTLS_SSL_CONF_RNG)
static inline mbedtls_frng_t* mbedtls_ssl_conf_get_frng(
    mbedtls_ssl_config const *conf )
{
    return( conf->f_rng );
}

static inline void* mbedtls_ssl_conf_get_prng( mbedtls_ssl_config const *conf )
{
    return( conf->p_rng );
}
#else /* !MBEDTLS_SSL_CONF_RNG */
#define mbedtls_ssl_conf_rng_func MBEDTLS_SSL_CONF_RNG
extern int mbedtls_ssl_conf_rng_func( void*, unsigned char*, size_t );

static inline mbedtls_frng_t* mbedtls_ssl_conf_get_frng(
    mbedtls_ssl_config const *conf )
{
    ((void) conf);
    return ((mbedtls_frng_t*) mbedtls_ssl_conf_rng_func);
}

static inline void* mbedtls_ssl_conf_get_prng( mbedtls_ssl_config const *conf )
{
    ((void) conf);
    return( NULL );
}
#endif /* MBEDTLS_SSL_CONF_RNG */

static inline int mbedtls_ssl_conf_get_max_major_ver(
    mbedtls_ssl_config const *conf )
{
#if !defined(MBEDTLS_SSL_CONF_MAX_MAJOR_VER)
    return( conf->max_major_ver );
#else
    ((void) conf);
    return( MBEDTLS_SSL_CONF_MAX_MAJOR_VER );
#endif /* MBEDTLS_SSL_CONF_MAX_MAJOR_VER */
}

static inline int mbedtls_ssl_conf_get_min_major_ver(
    mbedtls_ssl_config const *conf )
{
#if !defined(MBEDTLS_SSL_CONF_MIN_MAJOR_VER)
    return( conf->min_major_ver );
#else /* !MBEDTLS_SSL_CONF_MIN_MAJOR_VER */
    ((void) conf);
    return( MBEDTLS_SSL_CONF_MIN_MAJOR_VER );
#endif /* MBEDTLS_SSL_CONF_MIN_MAJOR_VER */
}

static inline int mbedtls_ssl_conf_get_max_minor_ver(
    mbedtls_ssl_config const *conf )
{
#if !defined(MBEDTLS_SSL_CONF_MAX_MINOR_VER)
    return( conf->max_minor_ver );
#else /* !MBEDTLS_SSL_CONF_MAX_MINOR_VER */
    ((void) conf);
    return( MBEDTLS_SSL_CONF_MAX_MINOR_VER );
#endif /* MBEDTLS_SSL_CONF_MAX_MINOR_VER */
}

static inline int mbedtls_ssl_conf_get_min_minor_ver(
    mbedtls_ssl_config const *conf )
{
#if !defined(MBEDTLS_SSL_CONF_MIN_MINOR_VER)
    return( conf->min_minor_ver );
#else /* !MBEDTLS_SSL_CONF_MIN_MINOR_VER */
    ((void) conf);
    return( MBEDTLS_SSL_CONF_MIN_MINOR_VER );
#endif /* MBEDTLS_SSL_CONF_MIN_MINOR_VER */
}

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
static inline unsigned int mbedtls_ssl_conf_get_ems(
    mbedtls_ssl_config const *conf )
{
#if !defined(MBEDTLS_SSL_CONF_EXTENDED_MASTER_SECRET)
    return( conf->extended_ms );
#else
    ((void) conf);
    return( MBEDTLS_SSL_CONF_EXTENDED_MASTER_SECRET );
#endif /* MBEDTLS_SSL_CONF_EXTENDED_MASTER_SECRET */
}

static inline unsigned int mbedtls_ssl_conf_get_ems_enforced(
    mbedtls_ssl_config const *conf )
{
#if !defined(MBEDTLS_SSL_CONF_ENFORCE_EXTENDED_MASTER_SECRET)
    return( conf->enforce_extended_master_secret );
#else
    ((void) conf);
    return( MBEDTLS_SSL_CONF_ENFORCE_EXTENDED_MASTER_SECRET );
#endif /* MBEDTLS_SSL_CONF_ENFORCE_EXTENDED_MASTER_SECRET */
}
#endif /* MBEDTLS_SSL_EXTENDED_MASTER_SECRET */

/*
 * Macros for the traversal of the list of all enabled ciphersuites.
 * This is implemented as a plain loop in case we have a runtime
 * configurable list of ciphersuites, and as a simple variable
 * instantiation in case a single ciphersuite is enabled at
 * compile-time.
 */
#if !defined(MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE)

#define MBEDTLS_SSL_BEGIN_FOR_EACH_CIPHERSUITE( ssl, ver, info ) \
    {                                                            \
        int const *__id_ptr;                                     \
        for( __id_ptr=(ssl)->conf->ciphersuite_list[             \
                 mbedtls_ssl_minor_ver_index( ver ) ];           \
             *__id_ptr != 0; __id_ptr++ )                        \
        {                                                        \
           const int __id = *__id_ptr;                           \
           mbedtls_ssl_ciphersuite_handle_t info;                \
           info = mbedtls_ssl_ciphersuite_from_id( __id );       \
           if( info == MBEDTLS_SSL_CIPHERSUITE_INVALID_HANDLE )  \
               continue;

#define MBEDTLS_SSL_END_FOR_EACH_CIPHERSUITE  \
        }                                     \
    }

#else /* !MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE */

#define MBEDTLS_SSL_BEGIN_FOR_EACH_CIPHERSUITE( ssl, ver, info )             \
    do {                                                                     \
        const mbedtls_ssl_ciphersuite_handle_t info =                        \
            MBEDTLS_SSL_CIPHERSUITE_UNIQUE_VALID_HANDLE;

#define MBEDTLS_SSL_END_FOR_EACH_CIPHERSUITE    \
    } while( 0 );

#endif /* MBEDTLS_SSL_CONF_SINGLE_CIPHERSUITE */

#if !defined(MBEDTLS_SSL_CONF_SINGLE_EC)

#define MBEDTLS_SSL_BEGIN_FOR_EACH_SUPPORTED_EC_TLS_ID( TLS_ID_VAR )     \
    {                                                                    \
        mbedtls_ecp_group_id const *_gid;                                \
        mbedtls_ecp_curve_info const *_info;                             \
        for( _gid = ssl->conf->curve_list;                               \
             *_gid != MBEDTLS_ECP_DP_NONE; _gid++ )                      \
        {                                                                \
            uint16_t TLS_ID_VAR;                                         \
            _info = mbedtls_ecp_curve_info_from_grp_id( *_gid )   ;      \
            if( _info == NULL )                                          \
                continue;                                                \
            TLS_ID_VAR = _info->tls_id;

#define MBEDTLS_SSL_END_FOR_EACH_SUPPORTED_EC_TLS_ID                    \
        }                                                               \
    }

#define MBEDTLS_SSL_BEGIN_FOR_EACH_SUPPORTED_EC_GRP_ID( EC_ID_VAR )     \
    {                                                                   \
        mbedtls_ecp_group_id const *_gid;                               \
        for( _gid = ssl->conf->curve_list;                              \
             *_gid != MBEDTLS_ECP_DP_NONE; _gid++ )                     \
        {                                                               \
            mbedtls_ecp_group_id EC_ID_VAR = *_gid;                     \

#define MBEDTLS_SSL_END_FOR_EACH_SUPPORTED_EC_GRP_ID                    \
        }                                                               \
    }

#else /* !MBEDTLS_SSL_CONF_SINGLE_EC */

#define MBEDTLS_SSL_BEGIN_FOR_EACH_SUPPORTED_EC_TLS_ID( TLS_ID_VAR )    \
    {                                                                   \
        uint16_t TLS_ID_VAR = MBEDTLS_SSL_CONF_SINGLE_EC_TLS_ID;        \
        ((void) ssl);

#define MBEDTLS_SSL_END_FOR_EACH_SUPPORTED_EC_TLS_ID                    \
    }

#if defined(MBEDTLS_USE_TINYCRYPT)
#define MBEDTLS_SSL_BEGIN_FOR_EACH_SUPPORTED_UECC_GRP_ID( EC_ID_VAR )          \
    {                                                                          \
        mbedtls_uecc_group_id EC_ID_VAR = MBEDTLS_SSL_CONF_SINGLE_UECC_GRP_ID; \
        ((void) ssl);

#define MBEDTLS_SSL_END_FOR_EACH_SUPPORTED_UECC_GRP_ID                    \
    }
#endif /* MBEDTLS_USE_TINYCRYPT */

#if defined(MBEDTLS_ECP_C)
#define MBEDTLS_SSL_BEGIN_FOR_EACH_SUPPORTED_EC_GRP_ID( EC_ID_VAR )         \
    {                                                                       \
        mbedtls_ecp_group_id EC_ID_VAR = MBEDTLS_SSL_CONF_SINGLE_EC_GRP_ID; \
        ((void) ssl);

#define MBEDTLS_SSL_END_FOR_EACH_SUPPORTED_EC_GRP_ID                    \
    }
#endif /* MBEDTLS_ECP_C */

#endif /* MBEDTLS_SSL_CONF_SINGLE_EC */

#if !defined(MBEDTLS_SSL_CONF_SINGLE_SIG_HASH)

#define MBEDTLS_SSL_BEGIN_FOR_EACH_SIG_HASH( MD_VAR )    \
    {                                                                   \
        int const *__md;                                                \
        for( __md = ssl->conf->sig_hashes;                              \
             *__md != MBEDTLS_MD_NONE; __md++ )                         \
        {                                                               \
            mbedtls_md_type_t MD_VAR = (mbedtls_md_type_t) *__md;       \

 #define MBEDTLS_SSL_END_FOR_EACH_SIG_HASH                              \
        }                                                               \
    }

#define MBEDTLS_SSL_BEGIN_FOR_EACH_SIG_HASH_TLS( HASH_VAR )             \
    {                                                                   \
        int const *__md;                                                \
        for( __md = ssl->conf->sig_hashes;                              \
             *__md != MBEDTLS_MD_NONE; __md++ )                         \
        {                                                               \
            unsigned char HASH_VAR;                                     \
            HASH_VAR = mbedtls_ssl_hash_from_md_alg( *__md );

#define MBEDTLS_SSL_END_FOR_EACH_SIG_HASH_TLS                           \
        }                                                               \
    }

#else /* !MBEDTLS_SSL_CONF_SINGLE_SIG_HASH */

#define MBEDTLS_SSL_BEGIN_FOR_EACH_SIG_HASH( MD_VAR )                   \
    {                                                                   \
        mbedtls_md_type_t MD_VAR = MBEDTLS_SSL_CONF_SINGLE_SIG_HASH_MD_ID; \
        ((void) ssl);

#define MBEDTLS_SSL_END_FOR_EACH_SIG_HASH                               \
    }

#define MBEDTLS_SSL_BEGIN_FOR_EACH_SIG_HASH_TLS( HASH_VAR )                \
    {                                                                      \
        unsigned char HASH_VAR = MBEDTLS_SSL_CONF_SINGLE_SIG_HASH_TLS_ID;  \
        ((void) ssl);


#define MBEDTLS_SSL_END_FOR_EACH_SIG_HASH_TLS                           \
    }

#endif /* MBEDTLS_SSL_CONF_SINGLE_SIG_HASH */

/* This internal function can be used to pend a fatal alert for
 * later delivery.
 *
 * The check for pending alerts must be done by calling
 * the function ssl_send_pending_fatal_alert() in ssl_tls.c.
 * Currently, it happens only during the handshake loop and after
 * calling ssl_get_next_record() in the record processing stack.
 *
 * This function must not be called multiple times without
 * sending the pending fatal alerts in between.
 */
MBEDTLS_ALWAYS_INLINE static inline void mbedtls_ssl_pend_fatal_alert(
    mbedtls_ssl_context *ssl,
    unsigned char message )
{
    ssl->pending_fatal_alert_msg = message;
}

/*
 * Getter functions for fields in SSL session.
 */

static inline int mbedtls_ssl_session_get_compression(
    mbedtls_ssl_session const *session )
{
#if defined(MBEDTLS_ZLIB_SUPPORT)
    return( session->compression );
#else
    ( (void) session );
    return( MBEDTLS_SSL_COMPRESS_NULL );
#endif
}

MBEDTLS_ALWAYS_INLINE static inline void mbedtls_ssl_update_checksum(
    mbedtls_ssl_context *ssl,
    const unsigned char *buf, size_t len )
{
#if defined(MBEDTLS_SSL_PROTO_SSL3) || defined(MBEDTLS_SSL_PROTO_TLS1) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_1)
     mbedtls_md5_update_ret( &ssl->handshake->fin_md5 , buf, len );
    mbedtls_sha1_update_ret( &ssl->handshake->fin_sha1, buf, len );
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_SHA256_C)
    mbedtls_sha256_update_ret( &ssl->handshake->fin_sha256, buf, len );
#endif
#if defined(MBEDTLS_SHA512_C)
    mbedtls_sha512_update_ret( &ssl->handshake->fin_sha512, buf, len );
#endif
#endif /* MBEDTLS_SSL_PROTO_TLS1_2 */
}

int mbedtls_ssl_calc_verify( int minor_ver,
                             mbedtls_md_type_t hash,
                             mbedtls_ssl_context const *ssl,
                             unsigned char *dst,
                             size_t *hlen );

#define MBEDTLS_SSL_CHK(f) do { if( ( ret = f ) < 0 ) goto cleanup; } while( 0 )

#if defined(MBEDTLS_USE_TINYCRYPT)
int mbedtls_ssl_ecdh_read_peerkey( mbedtls_ssl_context *ssl,
                                   unsigned char **p, unsigned char *end );
#endif /* MBEDTLS_USE_TINYCRYPT */


/*
 * Point formats, from RFC 4492's enum ECPointFormat
 */
#define MBEDTLS_SSL_EC_PF_UNCOMPRESSED    0   /**< Uncompressed point format. */
#define MBEDTLS_SSL_EC_PF_COMPRESSED      1   /**< Compressed point format. */

/*
 * Some other constants from RFC 4492
 */
#define MBEDTLS_SSL_EC_TLS_NAMED_CURVE    3   /**< The named_curve of ECCurveType. */

#endif /* ssl_internal.h */
