/**
 * \file layer2.h
 *
 * \brief The record layer implementation of the message processing stack.
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

#ifndef MBEDTLS_MPS_RECORD_LAYER_H
#define MBEDTLS_MPS_RECORD_LAYER_H

#include "layer1.h"
#include "common.h"

#include "reader.h"
#include "writer.h"

#include "error.h"
#include "transform.h"

#include <stdint.h>

/*
 * Copied from existing headers -- remove when integrating MPS
 */

#define MBEDTLS_SSL_MAJOR_VERSION_3             3
#define MBEDTLS_SSL_MINOR_VERSION_0             0   /*!< SSL v3.0 */
#define MBEDTLS_SSL_MINOR_VERSION_1             1   /*!< TLS v1.0 */
#define MBEDTLS_SSL_MINOR_VERSION_2             2   /*!< TLS v1.1 */
#define MBEDTLS_SSL_MINOR_VERSION_3             3   /*!< TLS v1.2 */

/* End of external copies to be removed later */

#define MPS_L2_VERSION_UNSPECIFIED 0x3f

#if defined(MBEDTLS_MPS_PROTO_DTLS)
#define MBEDTLS_MPS_ANTI_REPLAY_DISABLED 0
#define MBEDTLS_MPS_ANTI_REPLAY_ENABLED  1
#endif /* MBEDTLS_MPS_PROTO_DTLS */

#define MPS_L2_ALLOW_PAUSABLE_CONTENT_TYPE_WITHOUT_ACCUMULATOR

/*! The type of epoch usage flags */
typedef uint8_t mbedtls_mps_epoch_usage;

/*! This macro generates an epoch usage flag indicating
 *  that the epoch is needed for reading, for a specific
 *  reason that is encoded as an integral parameter.
 *
 *  The prime example for this is the DTLS retransmission
 *  state machine: There's always the epoch of the next
 *  expected incoming message, but we must also detect
 *  retransmission of earlier messages, and potentially
 *  earlier epochs. The DTLS retransmission state machine
 *  can separate these usage reasons through this macro.
 *
 *  Currently, only `0` and `1` are supported as values
 *  for `reason`.
 */
#define MPS_EPOCH_USAGE_READ( reason )  \
    ( (mbedtls_mps_epoch_usage) ( 1u << ( reason ) ) )
#define MPS_EPOCH_USAGE_WRITE( reason ) \
    ( (mbedtls_mps_epoch_usage) ( 1u << ( 2 + ( reason ) ) ) )

#define MPS_EPOCH_READ  MPS_EPOCH_USAGE_READ( 0 )
#define MPS_EPOCH_WRITE MPS_EPOCH_USAGE_WRITE( 0 )

#define MPS_EPOCH_READ_MASK  ( MPS_EPOCH_USAGE_READ( 0 ) | \
                               MPS_EPOCH_USAGE_READ( 1 ) )
#define MPS_EPOCH_WRITE_MASK ( MPS_EPOCH_USAGE_WRITE( 0 ) | \
                               MPS_EPOCH_USAGE_WRITE( 1 ) )

#define MPS_EPOCH_USAGE_ALL ( MPS_EPOCH_READ_MASK | MPS_EPOCH_WRITE_MASK )

struct mbedtls_mps_l2;
typedef struct mbedtls_mps_l2 mbedtls_mps_l2;

/**
 * \brief        Handle to incoming data of a specific content type and epoch.
 */
typedef struct
{
    /*! The type of the incoming data. It is entirely opaque to
     *  Layer 2, that is, no distinction is made between HS, App,
     *  CCS, or Alert records. */
    mbedtls_mps_stored_msg_type_t type;
    /*!< The epoch through which the incoming data is protected. */
    mbedtls_mps_stored_epoch_id epoch;
    mbedtls_reader *rd;           /*!< The reader providing access to the
                                   *   incoming data.                        */
} mps_l2_in;

/**
 * \brief         Handle to outgoing data of a specific content type and epoch.
 */
typedef struct
{
    /*! The type of the outgoing data. It is entirely opaque to Layer 2,
     *  that is, no distinction is made between HS, App, CCS,
     *  or Alert records. */
    mbedtls_mps_stored_msg_type_t type;
    /*!< The epoch through which the outgoing data will be protected. */
    mbedtls_mps_stored_epoch_id epoch;
    mbedtls_writer *wr;           /*!< The writer providing access to the
                                   *   outgoing data buffers.                */
} mps_l2_out;

/* I don't know why E-ACSL allows the following predicates when spelled
 * out but forbids them when they are globally defined. Define them as
 * macros for now... very ugly hack, but anyway... */

#define MPS_L2_BUFPAIR_INV_BUF_VALID( p )       \
    ( \forall integer i; 0 <= i < (p)->buf_len  \
      ==> \valid( (p)->buf+i ) )

#define MPS_L2_BUFPAIR_INV_PAYLOAD_SUBBUF( p )                  \
    ( (p)->data_offset <= (p)->buf_len &&                       \
      (p)->data_len <= (p)->buf_len - (p)->data_offset )

#define MPS_L2_BUFPAIR_INV( p )                  \
    ( MPS_L2_BUFPAIR_INV_BUF_VALID( p ) &&       \
      MPS_L2_BUFPAIR_INV_PAYLOAD_SUBBUF( p ) )

#define MPS_L2_BUFPAIR_INV_ENSURES( p )                 \
    ensures \valid( p );                                \
    ensures MPS_L2_BUFPAIR_INV_BUF_VALID( p );          \
    ensures MPS_L2_BUFPAIR_INV_PAYLOAD_SUBBUF( p );

#define MPS_L2_BUFPAIR_INV_REQUIRES( p )                 \
    requires \valid( p );                                \
    requires MPS_L2_BUFPAIR_INV_BUF_VALID( p );          \
    requires MPS_L2_BUFPAIR_INV_PAYLOAD_SUBBUF( p );

/*! The type of states of readers managed by Layer 2.
 *
 *  Possible values are:
 *  - #MBEDTLS_MPS_L2_READER_STATE_UNSET
 *    The reader does neither manage an incoming Layer 1 record buffer
 *    nor hold back any data for pausing.
 *  - #MBEDTLS_MPS_L2_READER_STATE_PAUSED
 *    The reader doesn't manage an incoming Layer 1 record buffer
 *    but holds back data for pausing.
 *  - #MBEDTLS_MPS_L2_READER_STATE_INTERNAL
 *    The reader manages an incoming Layer 1 record buffer
 *    but is currently not passed to the user.
 *  - #MBEDTLS_MPS_L2_READER_STATE_EXTERNAL
 *    The reader manages an incoming Layer 1 record
 *    buffer and is passed to the user.
 */
typedef uint8_t mbedtls_mps_l2_reader_state;
#define MBEDTLS_MPS_L2_READER_STATE_UNSET    ( (mbedtls_mps_l2_reader_state) 0 )
#define MBEDTLS_MPS_L2_READER_STATE_INTERNAL ( (mbedtls_mps_l2_reader_state) 1 )
#define MBEDTLS_MPS_L2_READER_STATE_EXTERNAL ( (mbedtls_mps_l2_reader_state) 2 )
#if defined(MBEDTLS_MPS_PROTO_TLS)
#define MBEDTLS_MPS_L2_READER_STATE_PAUSED   ( (mbedtls_mps_l2_reader_state) 3 )
#endif /* MBEDTLS_MPS_PROTO_TLS */

/*! The type of state of writers manages by Layer 2.
 *
 *  Possible values are:
 *  - #MBEDTLS_MPS_L2_WRITER_STATE_UNSET
 *    The writer does neither manage an outgoing Layer 1 record buffer
 *    nor hold back any queued data.
 *  - #MBEDTLS_MPS_L2_WRITER_STATE_INTERNAL
 *    The writer manages an outgoing Layer 1 record buffer but
 *    is currently not passed to the user.
 *  - #MBEDTLS_MPS_L2_WRITER_STATE_EXTERNAL
 *    The writer manages an outgoing Layer 1 record buffer and
 *    has been passed to the user.
 *  - #MBEDTLS_MPS_L2_WRITER_STATE_QUEUEING
 *    The writer doesn't manage an outgoing Layer 1 record buffer but
 *    has data queued for transmission (TLS only).
 */
typedef uint8_t mbedtls_mps_l2_writer_state;
#define MBEDTLS_MPS_L2_WRITER_STATE_UNSET    ( (mbedtls_mps_l2_writer_state) 0 )
#define MBEDTLS_MPS_L2_WRITER_STATE_INTERNAL ( (mbedtls_mps_l2_writer_state) 1 )
#define MBEDTLS_MPS_L2_WRITER_STATE_EXTERNAL ( (mbedtls_mps_l2_writer_state) 2 )
#if defined(MBEDTLS_MPS_PROTO_TLS)
#define MBEDTLS_MPS_L2_WRITER_STATE_QUEUEING ( (mbedtls_mps_l2_writer_state) 3 )
#endif /* MBEDTLS_MPS_PROTO_TLS */

/**
 * \brief   Instances of this internal structure represent incoming
 *          data streams of varying content type and epoch.
 */
struct mbedtls_mps_l2_in_internal
{
    /*! The state of the stream. See ::mbedtls_mps_l2_reader_state
     *  for more information. */
    mbedtls_mps_l2_reader_state state;
    /*! The record content type of the incoming data stream. */
    mbedtls_mps_stored_msg_type_t type;
    /*! The epoch through which the data is secured. */
    mbedtls_mps_stored_epoch_id epoch;
    /*! The reader managing the incoming data after decryption. */
    mbedtls_reader rd;
};
typedef struct mbedtls_mps_l2_in_internal mbedtls_mps_l2_in_internal;

/**
 * \brief   Instances of this L2-internal structure represent outgoing
 *          data streams of varying content type and epoch.
 */
struct mbedtls_mps_l2_out_internal
{
    /*! The record content type of the outgoing data stream. */
    mbedtls_mps_stored_msg_type_t type;
    /*! The epoch through which the data is secured. */
    mbedtls_mps_stored_epoch_id epoch;
    /*! The writer managing the incoming data before encryption. */
    mbedtls_writer wr;
};
typedef struct mbedtls_mps_l2_out_internal mbedtls_mps_l2_out_internal;

/* These are constants from the standard and are NOT configurable.
 * For the purpose of configuring the internal maximum record size,
 * see the `max_plain_in/out` values in the Layer 2 configuration
 * below, as well as the configuration of the allocator serving the
 * internal record buffers. */
#define TLS_MAX_PLAINTEXT_LEN        16384
#define TLS_MAX_COMPRESSED_LEN_1_2 ( TLS_MAX_PLAINTEXT_LEN      + 1024 )
#define TLS_MAX_CIPHERTEXT_LEN_1_2 ( TLS_MAX_COMPRESSED_LEN_1_2 + 1024 )
#define TLS_MAX_CIPHERTEXT_LEN_1_3 ( TLS_MAX_PLAINTEXT_LEN      +  256 )

/**
 * \brief    This structure represents a (D)TLS connection state / epoch.
 *
 *           It contains information about the current incoming and outgoing
 *           sequence numbers (including replay protection windows for DTLS)
 *           as well as the record protection mechanism to be used.
 */
struct mbedtls_mps_l2_epoch_t
{
    /*! Information about the usage of incoming and outgoing
     *  sequence numbers for this connection state. */
    union
    {
#if defined(MBEDTLS_MPS_PROTO_TLS)
        struct
        {
            /*! The outgoing record sequence number
             *
             *  This is the implicit record sequence number of
             *  the current or next outgoing record (depending
             *  on whether a record is currently open or not).
             */
            uint32_t out_ctr[2];

            /*! The incoming record sequence number.
             *
             *  This is the implicit record sequence number of
             *  the current or next incoming record (depending
             *  on whether a record is currently open or not).
             */
            uint32_t in_ctr[2];

        } tls;
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
        struct
        {
            /*! The outgoing record sequence number
             *
             *  This is the explicit record sequence number of
             *  the current or next outgoing record (depending
             *  on whether a record is currently open or not).
             */
            uint32_t out_ctr[2];

            /*! The record sequence number of the last valid record.
             *
             *  This must be remembered because a server
             *  replying to a ClientHello with a HelloVerifyRequest
             *  must copy the record sequence number of the ClientHello:
             *
             *  Quoting RFC 6347:
             *    In order to avoid sequence number duplication in case
             *    of multiple HelloVerifyRequests, the server MUST use
             *    the record sequence number in the ClientHello as
             *    the record sequence number in the HelloVerifyRequest.
             */
            uint32_t last_seen[2];

            /*! The replay protection window. */
            struct
            {
                /*! The top of the replay protection window,
                 *  i.e. the highest validated record sequence
                 *  number seen so far. */
                uint32_t in_window_top_hi;
                uint32_t in_window_top_lo;

                /*! The bitmask indicating for which
                 *  record sequence numbers in the interval
                 *  [in_window_top-63, .., in_window_top]
                 *  we have seen a valid record. */
                uint32_t in_window;

            } replay;

        } dtls;
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    } stats;

    /*! The usage flags for the epoch.
     *
     *  This comprises
     *  - user-specified read- and write-flags,
     *  - internal flags set by the implementation to keep
     *    track of the epochs usage.
     *
     *  An epoch with no usage flags is considered unnecessary
     *  and is cleaned up by the epoch 'garbage collection'.
     *
     *  For example:
     *  - The DTLS retransmission state machine might
     *    set read/write flags for an epoch because it's the currently
     *    used epoch, or it's an old epoch which however is still
     *    needed to detect or generate flight retransmissions.
     *  - The implementation might want to track that data is
     *    still pending to be written for some epoch, even if
     *    the user has already marked the epoch as no longer used.
     */
    mbedtls_mps_epoch_usage usage;

    /*! The record protection to be applied to records of this epoch.
     *   A value of \c NULL represents the identity transform. */
    mbedtls_mps_transform_t *transform;

};
typedef struct mbedtls_mps_l2_epoch_t mbedtls_mps_l2_epoch_t;

/**
 * \brief    This structure contains the configuration parameters
 *           for a Layer 2 instance.
 */
struct mbedtls_mps_l2_config
{
    mps_l1 *l1;              /*!< The underlying buffering / datagram layer.  */

#if !defined(MBEDTLS_MPS_CONF_MODE)
    uint8_t mode;            /*!< This specifies whether the Layer 2 instance
                              *   the TLS (0) or DTLS (1) record protocol.    */
#endif /* MBEDTLS_MPS_CONF_MODE */

#if !defined(MBEDTLS_MPS_CONF_VERSION)
    uint8_t version;         /*!< This field indicates the TLS/DTLS version
                              *   the Layer 2 instance uses.
                              *
                              *   This field may initially be unspecified, in
                              *   which case multiple [D]TLS versions can be
                              *   received until the exact [D]TLS version has
                              *   been agreed upon.                           */
#endif /* !MBEDTLS_MPS_CONF_VERSION */

#if !defined(MBEDTLS_MPS_CONF_ANTI_REPLAY)
    uint8_t anti_replay;     /*!< This field indicates whether anti replay
                              *   protection should be applied (DTLS only).
                              *   Possible values are:
                              *   - #MBEDTLS_MPS_L2_ANTI_REPLAY_DISABLED
                              *   - #MBEDTLS_MPS_L2_ANTI_REPLAY_ENABLED.
                              */
#endif /* MBEDTLS_MPS_CONF_ANTI_REPLAY */

#if !defined(MBEDTLS_MPS_CONF_MAX_PLAIN_OUT)
    /*! The maximum length of record plaintext (including inner plaintext
     *  header and padding in TLS 1.3) of outgoing records.                   */
    mbedtls_mps_stored_size_t max_plain_out;
#endif /* MBEDTLS_MPS_CONF_MAX_PLAIN_OUT */

#if !defined(MBEDTLS_MPS_CONF_MAX_PLAIN_IN)
    /*! The Maximum length of record plaintext (including inner plaintext
     *  header and padding in TLS 1.3) of incoming records.                   */
    mbedtls_mps_stored_size_t max_plain_in;
#endif /* MBEDTLS_MPS_CONF_MAX_PLAIN_IN */

#if !defined(MBEDTLS_MPS_CONF_MAX_CIPHER_IN)
    mbedtls_mps_stored_size_t max_cipher_in;
#endif /* MBEDTLS_MPS_CONF_MAX_CIPHER_IN */

#if !defined(MBEDTLS_MPS_CONF_TYPE_FLAG)
    /* The following members are bitflags indexed by record types in
     * the range of 0 .. 31. Record content types >= 32 are not used
     * and considered invalid. */
    uint32_t type_flag;   /*!< This member indicates which record content
                           *   type ID's the Layer 2 instance should allow.
                           *   It is realized as a 32-bit bitflag, with the
                           *   n-th bit (n=0..31) indicating being set if
                           *   the record content type ID n is allowed.
                           *   Incoming record of invalid record content
                           *   types, or attempts to send data of invalid
                           *   content types, are reported through the error
                           *   code MPS_ERR_INVALID_RECORD.                 */
#endif /* !MBEDTLS_MPS_CONF_TYPE_FLAG */

#if defined(MBEDTLS_MPS_PROTO_TLS)
#if !defined(MBEDTLS_MPS_CONF_PAUSE_FLAG)
    uint32_t pause_flag;  /*!< This member defines the record content type
                           *   ID's for which the Layer 2 instance allows
                           *   merging contents of multiple incoming records
                           *   of the same record content type.
                           *   It is realized as a 32-bit bitflag, with the
                           *   n-th bit (n=0..31) indicating being set if
                           *   the record content type ID n is allowed.
                           *   This must be a sub-field of \p type_flag.     */
#endif /* !MBEDTLS_MPS_CONF_PAUSE_FLAG */
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if !defined(MBEDTLS_MPS_CONF_MERGE_FLAG)
    uint32_t merge_flag;  /*!< This member defines the record content type
                           *   ID's for which the Layer 2 instance allows
                           *   multiple messages (that is, data written by
                           *   the user between two calls of mps_l2_write_start
                           *   and mps_l2_write_end) to be merged within
                           *   the same record.
                           *   It is realized as a 32-bit bitflag, with the
                           *   n-th bit (n=0..31) indicating being set if
                           *   the record content type ID n is allowed.
                           *   This must be a sub-field of \p type_flag.     */
#endif /* !MBEDTLS_MPS_CONF_MERGE_FLAG */

#if !defined(MBEDTLS_MPS_CONF_EMPTY_FLAG)
    uint32_t empty_flag;  /*!< This member defines the record content type
                           *   ID's for which the Layer 2 instance allows
                           *   empty records to be sent and received.
                           *   It is realized as a 32-bit bitflag, with the
                           *   n-th bit (n=0..31) indicating being set if
                           *   empty records of content type ID n is allowed.
                           *   This must be a sub-field of \p type_flag.
                           *   If empty records are not allowed, requests
                           *   to send them will be silently ignored, while
                           *   incoming empty records are treated as errors. */
#endif /* !MBEDTLS_MPS_CONF_EMPTY_FLAG */

#if defined(MBEDTLS_MPS_PROTO_TLS)
#define MPS_L2_CONF_INV_PAUSE_FLAG( p )                         \
    ( ( (p)->pause_flag & (p)->type_flag ) == (p)->pause_flag )
#else
#define MPS_L2_CONF_INV_PAUSE_FLAG( p ) 1
#endif /* MBEDTLS_MPS_PROTO_TLS */

#define MPS_L2_CONF_INV_MERGE_FLAG( p )                         \
    ( ( (p)->merge_flag & (p)->type_flag ) == (p)->merge_flag )

#define MPS_L2_CONF_INV_EMPTY_FLAG( p )                         \
    ( ( (p)->empty_flag & (p)->type_flag ) == (p)->empty_flag )


    /* Notes:
     * - Both record size limit values are usually negotiated with
     *   either the maximum_fragment_length extension or the new
     *   record_size_limit extension.
     * - Both limits must not exceed the default value of
     *   TLS_MAX_CONTENT_LEN == 16384.
     * - The values configured here are entirely independent of
     *   the sizes of the internal buffers the implementation uses
     *   to hold records! These are owned by Layer 1 and obtained
     *   from the allocator, and it is the responsibility of the
     *   code orchestrating the various layers to ensure that their
     *   respective thresholds are in sync.
     */

    int (*f_rng)( void *, unsigned char *,
                 size_t );        /*!< A PRNG function.
                                   *   May be \c NULL if the record protection
                                   *   mechanism used by the Layer 2 instance
                                   *   doesn't need random number generation. */
    void *p_rng;                  /*!< A PRNG context for use with \c f_rng.
                                   *   May be \c NULL if \c f_rng is \c NULL or
                                   *   if no context information is needed by
                                   *   the PRNG, or is stored elsewhere.      */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
#if !defined(MBEDTLS_MPS_CONF_BADMAC_LIMIT)
    uint32_t badmac_limit;        /*!< Determines how many records with bad MAC
                                   *   are silently tolerated before an error
                                   *   is raised. Possible values are:
                                   *   - \c 0: Records with bad MAC are always
                                   *     tolerated.
                                   *   - \c n greater \c 0: The n-th record
                                   *     with a bad MAC will lead to an error.
                                   */
#endif /* MBEDTLS_MPS_CONF_BADMAC_LIMIT */
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    /* TLS-1.3-NOTE: A boolean flag needs to be added to indicate whether
     *               Layer 2 should silently discard records that cannot
     *               be authenticated. This is necessary to ignore EarlyData
     *               if the server doesn't support it. */

};
typedef struct mbedtls_mps_l2_config mbedtls_mps_l2_config;

#if !defined(MBEDTLS_MPS_CONF_MODE)
static inline uint8_t
mbedtls_mps_l2_conf_get_mode( mbedtls_mps_l2_config *conf )
{
    return( conf->mode );
}
#else /* !MBEDTLS_MPS_CONF_MODE */
static inline uint8_t
mbedtls_mps_l2_conf_get_mode( mbedtls_mps_l2_config *conf )
{
    ((void) conf);
    return( MBEDTLS_MPS_CONF_MODE );
}
#endif /* MBEDTLS_MPS_CONF_MODE */

#if !defined(MBEDTLS_MPS_CONF_VERSION)
static inline
uint8_t mbedtls_mps_l2_conf_get_version( mbedtls_mps_l2_config *conf )
{
    return( conf->version );
}
#else /* !MBEDTLS_MPS_CONF_VERSION */
static inline
uint8_t mbedtls_mps_l2_conf_get_version( mbedtls_mps_l2_config *conf )
{
    ((void) conf);
    return( MBEDTLS_MPS_CONF_VERSION );
}
#endif /* MBEDTLS_MPS_CONF_VERSION */

#if !defined(MBEDTLS_MPS_CONF_ANTI_REPLAY)
static inline uint8_t mbedtls_mps_l2_conf_get_anti_replay(
    mbedtls_mps_l2_config *conf )
{
    return( conf->anti_replay );
}
#else /* !MBEDTLS_MPS_CONF_ANTI_REPLAY */
static inline uint8_t mbedtls_mps_l2_conf_get_anti_replay(
    mbedtls_mps_l2_config *conf )
{
    ((void) conf);
    return( MBEDTLS_MPS_CONF_ANTI_REPLAY );
}
#endif /* MBEDTLS_MPS_CONF_ANTI_REPLAY */

#if !defined(MBEDTLS_MPS_CONF_MAX_PLAIN_OUT)
static inline mbedtls_mps_stored_size_t mbedtls_mps_l2_conf_get_max_plain_out(
    mbedtls_mps_l2_config *conf )
{
    return( conf->max_plain_out );
}
#else /* !MBEDTLS_MPS_CONF_MAX_PLAIN_OUT */
static inline mbedtls_mps_stored_size_t mbedtls_mps_l2_conf_get_max_plain_out(
    mbedtls_mps_l2_config *conf )
{
    ((void) conf);
    return( MBEDTLS_MPS_CONF_MAX_PLAIN_OUT );
}
#endif /* MBEDTLS_MPS_CONF_MAX_PLAIN_OUT */

#if !defined(MBEDTLS_MPS_CONF_MAX_PLAIN_IN)
static inline mbedtls_mps_stored_size_t mbedtls_mps_l2_conf_get_max_plain_in(
    mbedtls_mps_l2_config *conf )
{
    return( conf->max_plain_in );
}
#else /* !MBEDTLS_MPS_CONF_MAX_PLAIN_IN */
static inline mbedtls_mps_stored_size_t mbedtls_mps_l2_conf_get_max_plain_in(
    mbedtls_mps_l2_config *conf )
{
    ((void) conf);
    return( MBEDTLS_MPS_CONF_MAX_PLAIN_IN );
}
#endif /* MBEDTLS_MPS_CONF_MAX_PLAIN_IN */

#if !defined(MBEDTLS_MPS_CONF_MAX_CIPHER_IN)
static inline mbedtls_mps_stored_size_t mbedtls_mps_l2_conf_get_max_cipher_in(
    mbedtls_mps_l2_config *conf )
{
    return( conf->max_cipher_in );
}
#else /* !MBEDTLS_MPS_CONF_MAX_CIPHER_IN */
static inline mbedtls_mps_stored_size_t mbedtls_mps_l2_conf_get_max_cipher_in(
    mbedtls_mps_l2_config *conf )
{
    ((void) conf);
    return( MBEDTLS_MPS_CONF_MAX_CIPHER_IN );
}
#endif /* MBEDTLS_MPS_CONF_MAX_CIPHER_IN */

#if !defined(MBEDTLS_MPS_CONF_TYPE_FLAG)
static inline uint32_t mbedtls_mps_l2_conf_get_type_flag(
    mbedtls_mps_l2_config *conf )
{
    return( conf->type_flag );
}
#else /* !MBEDTLS_MPS_CONF_TYPE_FLAG */
static inline uint32_t mbedtls_mps_l2_conf_get_type_flag(
    mbedtls_mps_l2_config *conf )
{
    ((void) conf);
    return( MBEDTLS_MPS_CONF_TYPE_FLAG );
}
#endif /* MBEDTLS_MPS_CONF_TYPE_FLAG */

#if defined(MBEDTLS_MPS_PROTO_TLS)
#if !defined(MBEDTLS_MPS_CONF_PAUSE_FLAG)
static inline uint32_t mbedtls_mps_l2_conf_get_pause_flag(
    mbedtls_mps_l2_config *conf )
{
    return( conf->pause_flag );
}
#else /* !MBEDTLS_MPS_CONF_PAUSE_FLAG */
static inline uint32_t mbedtls_mps_l2_conf_get_pause_flag(
    mbedtls_mps_l2_config *conf )
{
    ((void) conf);
    return( MBEDTLS_MPS_CONF_PAUSE_FLAG );
}
#endif /* MBEDTLS_MPS_CONF_PAUSE_FLAG */
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if !defined(MBEDTLS_MPS_CONF_MERGE_FLAG)
static inline uint32_t mbedtls_mps_l2_conf_get_merge_flag(
    mbedtls_mps_l2_config *conf )
{
    return( conf->merge_flag );
}
#else /* !MBEDTLS_MPS_CONF_MERGE_FLAG */
static inline uint32_t mbedtls_mps_l2_conf_get_merge_flag(
    mbedtls_mps_l2_config *conf )
{
    ((void) conf);
    return( MBEDTLS_MPS_CONF_MERGE_FLAG );
}
#endif /* MBEDTLS_MPS_CONF_MERGE_FLAG */

#if !defined(MBEDTLS_MPS_CONF_EMPTY_FLAG)
static inline uint32_t mbedtls_mps_l2_conf_get_empty_flag(
    mbedtls_mps_l2_config *conf )
{
    return( conf->empty_flag );
}
#else /* !MBEDTLS_MPS_CONF_EMPTY_FLAG */
static inline uint32_t mbedtls_mps_l2_conf_get_empty_flag(
    mbedtls_mps_l2_config *conf )
{
    ((void) conf);
    return( MBEDTLS_MPS_CONF_EMPTY_FLAG );
}
#endif /* MBEDTLS_MPS_CONF_EMPTY_FLAG */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
#if !defined(MBEDTLS_MPS_CONF_BADMAC_LIMIT)
static inline uint32_t mbedtls_mps_l2_conf_get_badmac_limit(
    mbedtls_mps_l2_config *conf )
{
    return( conf->badmac_limit );
}
#else /* !MBEDTLS_MPS_CONF_BADMAC_LIMIT */
static inline uint32_t mbedtls_mps_l2_conf_get_badmac_limit(
    mbedtls_mps_l2_config *conf )
{
    ((void) conf);
    return( MBEDTLS_MPS_CONF_BADMAC_LIMIT );
}
#endif /* MBEDTLS_MPS_CONF_BADMAC_LIMIT */
#endif /* MBEDTLS_MPS_PROTO_DTLS */

/**
 * \brief   The context structure for Layer 2 instance.
 */
struct mbedtls_mps_l2
{
     /*! The configuration of the Layer 2 instance. */
    mbedtls_mps_l2_config conf;

    /**
     * \brief The substructure holding all data related
     *        to outgoing records.
     */
    struct
    {
        struct
        {
#if defined(MBEDTLS_MPS_PROTO_TLS)
            /*! The queue for outgoing data of pausable record content types. */
            unsigned char *queue;
            /*! The size of the queue in Bytes. */
            mbedtls_mps_stored_size_t queue_len;

#define MPS_L2_INV_QUEUE_VALID( p )                             \
            ( (p)->out.queue != NULL ==>                        \
              ( \forall integer i; 0 <= i < (p)->out.queue_len  \
                ==> \valid( (p)->out.queue+i ) ) )
#else
#define MPS_L2_INV_QUEUE_VALID( p ) 1
#endif /* MBEDTLS_MPS_PROTO_TLS */

            /** This variable indicates if preparation of a new outgoing record
             *  must be preceded by a flush on the underlying Layer 1 first.
             *
             *  The rationale for having this as a separate field as opposed
             *  to triggering the flush immediately once the necessity arises
             *  is that it allows the user to be in control of which Layer 2 API
             *  calls will require interfacing with the underlying transport. */
            uint8_t clearing;

#define MPS_L2_INV_IF_CLEARING_NO_WRITE( p )                    \
            ( (p)->out.clearing == 1 ==>                        \
              (p)->out.state == MPS_L2_WRITER_STATE_UNSET    || \
              (p)->out.state == MPS_L2_WRITER_STATE_QUEUEING )

            /** This variable indicates if all pending outgoing data
             *  needs to be flushed before the next write can happen.
             *
             * This flag cannot be set while serving a write request. */
            uint8_t flush;

#define MPS_L2_INV_IF_FLUSH_NO_WRITE( p )                       \
            ( (p)->out.flush == 1 ==>                           \
              (p)->out.state == MPS_L2_WRITER_STATE_UNSET    || \
              (p)->out.state == MPS_L2_WRITER_STATE_QUEUEING )

            /* Further explanation on the meaning and difference
             * between `flush` and `clearing`:
             *
             * The `flush` state lives at a higher level than `clearing`:
             * If `flush` is set, Layer 2 must make sure that everything
             * that has been dispatched by the user is delivered before
             * the writing can continue. Internally, this splits into ...
             * (1) ... the data that has been dispatched by the user
             *     but which Layer 2 didn't yet dispatch to Layer 1,
             *     e.g. because Layer 2 waiting to see if it can put
             *     more data in the present record.
             * (2) ... the data that has been dispatched to Layer 1, but
             *     which Layer 1 might not yet have flushed.
             * Handling the `flush` state means dispatching the pending
             * data of type (1) first, ensuring that nothing of type (1)
             * is left, and then calling a flush on Layer 1 to handle
             * the data of type (2).
             *
             * In contrast, `clearing` solely deals with the data
             * of type (2): If it is set, the data of type (2) must
             * be flushed before any progress on writing can be made.
             *
             * Handling `flush` is done by dispatching the data of type (1)
             * to Layer 1, and then setting `clearing` to ensure the handling
             * of data of type (2) through a flush. If no progress can be
             * made on the clearing of (1) because Layer 1 is out of writing
             * space, `clearing` needs to be set in order to flush Layer 1
             * first, emptying (2), before the processing of type (1) data
             * can continue. This flow is implemented in l2_clear_pending().
             *
             */

            /* Layer 2 manages two types of data related to outgoing records:
             *
             * 1) The raw buffers holding the header, plaintext and ciphertext
             *    of the current outgoing record. They are internal and never
             *    passed to the user.
             *    The relevant fields are `hdr`, `hdr_len` and `payload`
             *    and they are explained in more detail below.
             *
             * 2) The structure `writer` representing the ongoing write from
             *    the perspective of the user, consisting of an epoch,
             *    a record content type and a writer object.
             *
             * The basic states during writing are the following:
             * 1. Initially,and whenever no outgoing record has been prepared,
             *    hdr, hdr_len and payload are unset, as is the writer.
             * 2. After preparing an outgoing record, hdr and payload are
             *    set up with buffers from Layer 1, while the writer is UNSET.
             * 3. The writer manages `payload` and is in INTERNAL state,
             *    indicating that is hasn't yet been provided to the user.
             * 4. The writer manages `payload` and is in EXTERNAL state,
             *    indicating that is has been provided to the user who then can
             *    use the writer API to provide the record contents.
             *
             * State 2 is not visible at the API boundary, but used internally
             * as an intermediate step when transitioning between the states,
             * which is done by the following functions:
             *
             * - l2_out_prepare_record transitions from state 1 to 2.
             * - l2_out_dispatch_record transitions from state 2 to 1.
             * - l2_out_track_record transitions from state 2 to 3.
             * - l2_out_release_record transitions from 3 to 2.
             */

            /* Once an outgoing record has been prepared, we're maintaining
             * three buffers:
             * 1. The header buffer, holding the record header in the end.
             * 2. The content buffer, holding the plaintext or ciphertext,
             *    depending on the state of encryption.
             * 3. The work buffer, surrounding the plaintext/ciphertext buffer.
             *
             * The concatenation of header buffer and the work buffer is the
             * write buffer obtained from the underlying Layer 1 instance.
             *
             * During record encryption, the content buffer grows within the
             * work buffer due to the addition of MAC, IV, or the inner
             * plaintext record header in case of TLS 1.3. The offset of the
             * content buffer from the work buffer should be zero after
             * encryption, and is chosen during record preparation to ensure
             * this property.
             *
             * +-----------+---------------------------------------------------+
             * |           |                     +------------------------+    |
             * |  header   |                     | plaintext / ciphertext |    |
             * |           |                     +------------------------+    |
             * |           |                      \__ payload.data_len __/     |
             * |           | payload.data_offset                               |
             * |           |---------------------|                             |
             * +-----------+---------------------------------------------------+
             *  hdr          payload.buf
             * \_ hdr_len _/\______________ payload.buf_len ___________________/
             *
             */

#define MPS_L2_INV_OUT_HDR_VALID( p )                                   \
            ( (p)->out.hdr == NULL ==> (p)->out.hdr_len == 0 ) &&       \
            ( (p)->out.hdr != NULL ==>                                  \
              ( \forall integer i; 0 <= i < (p)->out.hdr_len            \
                ==> \valid( (p)->out.hdr+i ) ) )

#define MPS_L2_INV_OUT_PAYLOAD_VALID( p )               \
            MPS_L2_BUFPAIR_INV( &(p)->out.payload )

#define MPS_L2_INV_OUT_HDR_PAYLOAD_SET                          \
            ( ( (p)->out.hdr == NULL <==> (                     \
                    (p)->out.payload.buf         == NULL &&     \
                    (p)->out.payload.buf_len     == 0    &&     \
                    (p)->out.payload.data_len    == 0    &&     \
                    (p)->out.payload.data_offset == 0 ) ) &&    \
              ( (p)->hdr != NULL ==>                            \
                ( (p)->out.payload.buf ==                       \
                  (p)->out.hdr + (p)->out.hdr_len ) ) )


            /** The address of the header of the current outgoing record,
             *  or \c NULL if there is no such. */
            /* OPTIMIZATION:
             * This is the same as the buffer obtained from
             * Layer 1. Consider removing this reference
             * and querying Layer 1 when it's needed instead. */
            unsigned char *hdr;
            /** The length of the header buffer pointed to by \c hdr.         */
            /* OPTIMIZATION:
             * This can be inferred from the epoch through l2_get_header_len().
             * Consider removing this field. */
            mbedtls_mps_stored_size_t hdr_len;

            /** The buffer pair consisting of content buffer
             *  (plaintext or ciphertext) and work buffer.                    */
            /* OPTIMIZATION:
             * This has overlap with \c hdr: the outer buffer in the
             * \c payload buffer pair always starts at `hdr + hdr_len`.
             * Consider removing this redundancy provided (?) it's possible
             * to do so without sacrifing structure and clarity of the code.  */
            mps_l2_bufpair payload;

            /** The structure through which the content type, the epoch
             *  and the state of plaintext writing of the current outgoing
             *  record is tracked. */
            /* OPTIMIZATION:
             * The fragment managed by the writer the inner
             * buffer in the \c payload buffer pair before
             * encryption. Consider removing this redundancy
             * provided (?) it's possible to do so without
             * sacrificing structure and clarity of the code. */
            mbedtls_mps_l2_out_internal writer;

#define MPS_L2_INV_OUT_WRITER_INV( p )          \
            WRITER_INV( &(p)->out.writer.wr )

            /** The state of the \c writer field. See the documentation of
             *  l2_writer_state for more information.                         */
            mbedtls_mps_l2_writer_state state;

#define MPS_L2_INV_OUT_WRITER_STATE( p )                                \
            ( (p)->out.state == MPS_L2_WRITER_STATE_UNSET    ||         \
                (p)->out.state == MPS_L2_WRITER_STATE_QUEUEING ||       \
                (p)->out.state == MPS_L2_WRITER_STATE_INTERNAL ||       \
                (p)->out.state == MPS_L2_WRITER_STATE_EXTERNAL )

#define MPS_L2_INV_OUT_ACTIVE_IS_VALID( p )                             \
            ( ( (p)->out.state != MPS_L2_WRITER_STATE_UNSET )           \
            ==> ( ( ( (uint32_t) 1u << (p)->out.writer.type ) & (p)->conf.type_flag ) != 0 ) )

#define MPS_L2_INV_OUT_QUEUEING_IS_PAUSABLE( p )                        \
            ( ( (p)->out.state != MPS_L2_WRITER_STATE_QUEUEING )        \
            ==> ( ( ( (uint32_t) 1u << (p)->out.writer.type ) & (p)->conf.pause_flag ) != 0 ) )

        } out;

        /**
         * \brief The substructure holding all data related to incoming records.
         */

        /* OPTIMIZATION:
         * Consider making reading and writing mutually exclusive and using
         * a union for store the incoming and outgoing data structures.
         * Together with the corresponding changes in the other layers, this
         * might save a significant amount of RAM.
         */
        struct
        {
            /* Note: In contrast to the write-side, the read-side of Layer 2 does
             * not remember the raw record buffers obtained from Layer 1 as they
             * can be handled on the stack when a new record is fetched. */

            /** The current TLS implementation allows a single paused reader,
             *  allowing e.g. to pause the reading of a handshake message while
             *  processing other content types; on the other hand, it is not
             *  capable of dealing with a fragmented alert followed by a fragmented
             *  handshake message. However, while allowed in TLS up to version 1.2,
             *  this is more of an academic use case, and the limitation seems
             *  acceptable. In fact, TLS 1.3 forbids any interleaving of record
             *  content types, and for that purpose, a single active or paused
             *  reader would be sufficient.
             *
             *  The Layer 2 implementation doesn't use this directly, but
             *  only through the following internal interface. Re-implement
             *  this interface to change the number of paused readers in TLS.
             *  - mps_l2_readers_active_state
             *  - mps_l2_readers_get_active
             *  - mps_l2_setup_free_slot
             *  - mps_l2_readers_update
             *  - mps_l2_find_paused_slot (TLS only)
             */

            mbedtls_mps_l2_in_internal active;

#if defined(MBEDTLS_MPS_PROTO_TLS)
            /*! The accumulator for incoming data of pausable
             *  record content types.    */
            unsigned char *accumulator;
            /*! The size of the accumulator in Bytes.*/
            mbedtls_mps_stored_size_t acc_len;

            mbedtls_mps_l2_in_internal paused;
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
            uint32_t bad_mac_ctr; /* The number of records with bad MAC that
                                   * have been received so far. DTLS only. */
#endif /* MBEDTLS_MPS_PROTO_DTLS */

        } in;

    } io;

    /**
     * \brief The substructure holding all data related
     *        to connection states / epochs.
     */
    struct
    {
        /* Layer 2 maintains an window of epochs indexed by
         * epoch ID's. The base-ID of the window is stored in \c base, and
         * the actual (offset-indexed) array of epochs is stored in `window`.
         * There should never be more than 2 epochs in simultaneous use, so a
         * window size of 2 should do, but the larger flexibility comes without
         * cost and allows to test if, indeed, despite of the large number
         * of epochs in [D]TLS 1.3, never more than two are used at once. */

        /*! The first epoch ID within the current epoch window. */
        mbedtls_mps_stored_epoch_id base;

#define MPS_L2_INV_EPOCH_WINDOW_VALID( p )                              \
        ( 0 <= (p)->epochs.base                 &&                      \
          (p)->epochs.base < MPS_L2_LIMIT_EPOCH &&                      \
          MPS_L2_LIMIT_EPOCH - (p)->epochs.base >= MBEDTLS_MPS_L2_EPOCH_WINDOW_SIZE )

        /* The offset of the next free epoch slot. */
        mbedtls_mps_epoch_offset_t next;
#define MPS_L2_INV_NEXT_EPOCH_BOUNDS( p )                               \
        ( (p)->epochs.next <= MBEDTLS_MPS_L2_EPOCH_WINDOW_SIZE )

#if defined(MBEDTLS_MPS_PROTO_TLS)
        mbedtls_mps_stored_epoch_id default_in;
        mbedtls_mps_stored_epoch_id default_out;
#endif /* MBEDTLS_MPS_PROTO_TLS */

        /*! The window of connection states for the epochs of ID
         *  <code> base, ..., base +
         *         MBEDTLS_MPS_L2_EPOCH_WINDOW_SIZE - 1.</code> */
        mbedtls_mps_l2_epoch_t window[ MBEDTLS_MPS_L2_EPOCH_WINDOW_SIZE ];


    } epochs;
};

/* I don't know why E-ACSL allows the following predicates when spelled
 * out but forbids them when they are globally defined. Define them as
 * macros for now... very ugly hack, but anyway... */

#define MPS_L2_INV( p )                                                 \
    ( \valid( p )                              &&                       \
      MPS_L2_CONF_INV_EMPTY_FLAG( &(p)->conf ) &&                       \
      MPS_L2_CONF_INV_PAUSE_FLAG( &(p)->conf ) &&                       \
      MPS_L2_CONF_INV_MERGE_FLAG( &(p)->conf ) &&                       \
      MPS_L2_INV_QUEUE_VALID( p )              &&                       \
      MPS_L2_INV_ACCUMULATOR_VALID( p )        &&                       \
      MPS_L2_INV_IF_CLEARING_NO_WRITE( p )     &&                       \
      MPS_L2_INV_IF_FLUSH_NO_WRITE( p )        &&                       \
      MPS_L2_INV_OUT_HDR_VALID( p )            &&                       \
      MPS_L2_INV_OUT_PAYLOAD_VALID( p )        &&                       \
      MPS_L2_INV_OUT_WRITER_INV( p )           &&                       \
      MPS_L2_INV_OUT_WRITER_STATE( p )         &&                       \
      MPS_L2_INV_IN_READER_INV( p )            &&                       \
      MPS_L2_INV_IN_READERS_PERMUTATION( p )   &&                       \
      MPS_L2_INV_IN_ACTIVE_STATE( p )          &&                       \
      MPS_L2_INV_IN_ACTIVE_IS_VALID( p ) &&                             \
      MPS_L2_INV_IN_ACTIVE_IS_MERGEABLE( p ) &&                         \
      MPS_L2_INV_IN_PAUSED_STATE( p )             &&                    \
      MPS_L2_INV_IN_PAUSED_IS_VALID( p )    &&                          \
      MPS_L2_INV_IN_PAUSED_IS_PAUSABLE( p ) &&                          \
      MPS_L2_INV_IN_NO_ACTIVE_PAUSED_NO_OVERLAP( p ) &&                 \
      MPS_L2_INV_EPOCH_WINDOW_VALID( p ) &&                             \
      MPS_L2_INV_NEXT_EPOCH_BOUNDS( p )  &&                             \
      MPS_L2_INV_DEFAULT_IN_VALID( p )  &&                              \
      MPS_L2_INV_DEFAULT_IN_ACTIVE( p ) &&                              \
      MPS_L2_INV_DEFAULT_IN_PAUSED( p ) &&                              \
      MPS_L2_INV_DEFAULT_OUT_VALID( p ) &&                              \
      MPS_L2_INV_DEFAULT_OUT( p ) )

#define MPS_L2_INV_REQUIRES( p )                                        \
    requires \valid( p );                                               \
    requires MPS_L2_CONF_INV_EMPTY_FLAG( &(p)->conf );                  \
    requires MPS_L2_CONF_INV_PAUSE_FLAG( &(p)->conf );                  \
    requires MPS_L2_CONF_INV_MERGE_FLAG( &(p)->conf );                  \
    requires MPS_L1_INV( p->conf.l1 );                                  \
    requires MPS_L2_INV_ACCUMULATOR_VALID( p );                         \
    requires MPS_L2_INV_QUEUE_VALID( p );                               \
    requires MPS_L2_INV_IF_CLEARING_NO_WRITE( p );                      \
    requires MPS_L2_INV_IF_FLUSH_NO_WRITE( p );                         \
    requires MPS_L2_INV_OUT_HDR_VALID( p );                             \
    requires MPS_L2_INV_OUT_PAYLOAD_VALID( p );                         \
    requires MPS_L2_INV_OUT_WRITER_INV( p );                            \
    requires MPS_L2_INV_OUT_WRITER_STATE( p );                          \
    requires MPS_L2_INV_IN_READER_INV( p );                             \
    requires MPS_L2_INV_IN_READERS_PERMUTATION( p );                    \
    requires MPS_L2_INV_IN_ACTIVE_STATE( p );                           \
    requires MPS_L2_INV_IN_ACTIVE_IS_VALID( p );                        \
    requires MPS_L2_INV_IN_ACTIVE_IS_MERGEABLE( p );                    \
    requires MPS_L2_INV_IN_PAUSED_STATE( p );                           \
    requires MPS_L2_INV_IN_PAUSED_IS_VALID( p );                        \
    requires MPS_L2_INV_IN_PAUSED_IS_PAUSABLE( p );                     \
    requires MPS_L2_INV_IN_NO_ACTIVE_PAUSED_NO_OVERLAP( p );            \
    requires MPS_L2_INV_EPOCH_WINDOW_VALID( p );                        \
    requires MPS_L2_INV_NEXT_EPOCH_BOUNDS( p );                         \
    requires MPS_L2_INV_DEFAULT_IN_VALID( p );                          \
    requires MPS_L2_INV_DEFAULT_IN_ACTIVE( p );                         \
    requires MPS_L2_INV_DEFAULT_IN_PAUSED( p );                         \
    requires MPS_L2_INV_DEFAULT_OUT_VALID( p );                         \
    requires MPS_L2_INV_DEFAULT_OUT( p );

#define MPS_L2_INV_ENSURES( p )                                        \
    ensures \valid( p );                                               \
    ensures MPS_L2_CONF_INV_EMPTY_FLAG( &(p)->conf );                  \
    ensures MPS_L2_CONF_INV_PAUSE_FLAG( &(p)->conf );                  \
    ensures MPS_L2_CONF_INV_MERGE_FLAG( &(p)->conf );                  \
    ensures MPS_L2_INV_ACCUMULATOR_VALID( p );                         \
    ensures MPS_L2_INV_QUEUE_VALID( p );                               \
    ensures MPS_L1_INV( p->conf.l1 );                                  \
    ensures MPS_L2_INV_IF_CLEARING_NO_WRITE( p );                      \
    ensures MPS_L2_INV_IF_FLUSH_NO_WRITE( p );                         \
    ensures MPS_L2_INV_OUT_HDR_VALID( p );                             \
    ensures MPS_L2_INV_OUT_PAYLOAD_VALID( p );                         \
    ensures MPS_L2_INV_OUT_WRITER_INV( p );                            \
    ensures MPS_L2_INV_OUT_WRITER_STATE( p );                          \
    ensures MPS_L2_INV_IN_READER_INV( p );                             \
    ensures MPS_L2_INV_IN_READERS_PERMUTATION( p );                    \
    ensures MPS_L2_INV_IN_ACTIVE_STATE( p );                           \
    ensures MPS_L2_INV_IN_ACTIVE_IS_VALID( p );                        \
    ensures MPS_L2_INV_IN_ACTIVE_IS_MERGEABLE( p );                    \
    ensures MPS_L2_INV_IN_PAUSED_STATE( p );                           \
    ensures MPS_L2_INV_IN_PAUSED_IS_VALID( p );                        \
    ensures MPS_L2_INV_IN_PAUSED_IS_PAUSABLE( p );                     \
    ensures MPS_L2_INV_IN_NO_ACTIVE_PAUSED_NO_OVERLAP( p );            \
    ensures MPS_L2_INV_EPOCH_WINDOW_VALID( p );                        \
    ensures MPS_L2_INV_NEXT_EPOCH_BOUNDS( p );                         \
    ensures MPS_L2_INV_DEFAULT_IN_VALID( p );                          \
    ensures MPS_L2_INV_DEFAULT_IN_ACTIVE( p );                         \
    ensures MPS_L2_INV_DEFAULT_IN_PAUSED( p );                         \
    ensures MPS_L2_INV_DEFAULT_OUT_VALID( p );                         \
    ensures MPS_L2_INV_DEFAULT_OUT( p );

/**
 * \brief           This function initializes a Layer 2 context.
 *
 * \param ctx       The address of the Layer 2 context to initialize.
 * \param l1        The address of an initialized Layer 1 context
 *                  to use for reading/writing data.
 * \param mode      The mode of operation for the Layer 2 context.
 *                  Either #MPS_L2_MODE_STREAM if the underlying Layer 0
 *                  transport is a stream transport, or #MPS_L2_MODE_DATAGRAM
 *                  if the underlying Layer 0 transport is a datagram transport.
 * \param max_read  The maximum number of bytes that the user can request
 *                  to read between two consecutive read-commits such that
 *                  Layer 2 still guarantees progress.
 *                  It is implementation- and runtime-specific as to whether
 *                  larger chunks can be fetched, too, but Layer 2 doesn't
 *                  guarantee for it.
 *                  Here, 'guarantee' means that while the user must always
 *                  expect to receive an #MPS_ERR_READER_OUT_OF_DATA or
 *                  #MPS_ERR_WANT_READ error code while reading, closing
 *                  and reopening the read-port in this case must eventually
 *                  lead to success, provided enough data is (eventually)
 *                  available on the underlying transport.
 *                  This TLS-only, i.e. if \p mode is #MPS_L2_MODE_STREAM.
 *                  The value \c 0 is supported and means that the user
 *                  can deal with arbitrarily fragmented incoming data himself.
 * \param max_write The maximum number of bytes that the user can request
 *                  to write between two consecutive write-commits such that
 *                  Layer 2 still guarantees progress.
 *                  It is implementation- and runtime-specific as to whether
 *                  larger chunks can be fetched, too, but Layer 2 doesn't
 *                  guarantee for it.
 *                  Here, 'guarantee' means that while the user must always
 *                  expect to receive an #MPS_ERR_WRITER_OUT_OF_DATA or
 *                  #MPS_ERR_WANT_WRITE error code while writing, closing
 *                  and reopening the write-port in this case must eventually
 *                  lead to success, provided the underlying transport
 *                  is (eventually) available to send the request amount
 *                  of data.
 *                  The value \c 0 is supported and means that the user
 *                  can deal with arbitrarily fragmented outgoing data himself.
 *                  This TLS-only, i.e. if \p mode is #MPS_L2_MODE_STREAM.
 * \param f_rng     The PRNG to use for record protection.
 * \param p_rng     The PRNG context to use \p f_rng with.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 *
 */

/*@
  requires \valid( ctx );
  MPS_L1_INV_REQUIRES( l1 )
  MPS_L2_INV_ENSURES( ctx )
@*/
MBEDTLS_MPS_PUBLIC int mps_l2_init( mbedtls_mps_l2 *ctx, mps_l1 *l1, uint8_t mode,
                            size_t max_read, size_t max_write,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng );

/**
 * \brief          This functions frees a Layer 2 context.
 *
 * \param ctx      The address of the Layer 2 context to free.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 */

/*@
  MPS_L2_INV_REQUIRES( ctx )
@*/
MBEDTLS_MPS_PUBLIC int mps_l2_free( mbedtls_mps_l2 *ctx );

/**
 * \brief          Configure Layer 2 context to accept records
 *                 of a given record content type.
 *
 *                 This function must only be called exactly once
 *                 for each record content type to be used.
 *
 * \param ctx      The address of the Layer 2 context to use.
 * \param type     The record content type to configure.
 * \param split    This parameter indicates whether content of type
 *                 \p type is allowed to be split across multiple records
 *                 (value #MPS_L2_SPLIT_ENABLED) or not
 *                 (value #MPS_L2_SPLIT_DISABLED).
 *                 E.g., handshake messages are allowed to be
 *                 split across multiple records in all versions of TLS,
 *                 while in TLS 1.3 alert messages must not be split.
 *                 See the documentation of the \c pause_flag
 *                 member of ::mps_l2_config for more information.
 * \param pack     This parameter indicates whether successive read/write
 *                 requests for content type \p type is allowed to be served
 *                 from the same record (value #MPS_L2_PACK_ENABLED) or not
 *                 (value #MPS_L2_PACK_DISABLED).
 *                 E.g., multiple handshake messages are allowed to be packed
 *                 in the same record in all versions of TLS, while in TLS 1.3
 *                 a single record must not contain multiple alert messages.
 *                 See the documentation of \c merge_flag
 *                 member of ::mps_l2_config for more information.
 * \param empty    This parameter indicates whether empty records of content
 *                 type \p type are allowed to be sent
 *                 (value #MPS_L2_EMPTY_ALLOWED) or not
 *                 (value #MPS_L2_EMPTY_DISCARD).
 *                 See the documentation of \c empty_flag
 *                 member of ::mps_l2_config for more information.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 */
typedef uint8_t mbedtls_mps_record_split_config_t;
#define MBEDTLS_MPS_SPLIT_DISABLED ( (mbedtls_mps_record_split_config_t) 0 )
#define MBEDTLS_MPS_SPLIT_ENABLED  ( (mbedtls_mps_record_split_config_t) 1 )

typedef uint8_t mbedtls_mps_record_pack_config_t;
#define MBEDTLS_MPS_PACK_DISABLED  ( (mbedtls_mps_record_pack_config_t) 0 )
#define MBEDTLS_MPS_PACK_ENABLED   ( (mbedtls_mps_record_pack_config_t) 1 )

typedef uint8_t mbedtls_mps_record_empty_config_t;
#define MBEDTLS_MPS_EMPTY_FORBIDDEN ( (mbedtls_mps_record_empty_config_t) 0 )
#define MBEDTLS_MPS_EMPTY_ALLOWED   ( (mbedtls_mps_record_empty_config_t) 1 )

/*@
  MPS_L2_INV_REQUIRES( ctx )
  MPS_L2_INV_ENSURES( ctx )
@*/
static inline int mps_l2_config_add_type( mbedtls_mps_l2 *ctx,
                                    mbedtls_mps_msg_type_t type,
                                    mbedtls_mps_record_split_config_t pausing,
                                    mbedtls_mps_record_pack_config_t merging,
                                    mbedtls_mps_record_empty_config_t empty )
{
    uint32_t mask;

    if( type >= MBEDTLS_MPS_MSG_MAX )
        return( MPS_ERR_INVALID_RECORD );

    mask = ( (uint32_t) 1u << type );
    if( mbedtls_mps_l2_conf_get_type_flag( &ctx->conf ) & mask )
        return( MPS_ERR_INVALID_ARGS );

#if !defined(MBEDTLS_MPS_CONF_PAUSE_FLAG)
    ctx->conf.type_flag |= mask;
#endif /* MBEDTLS_MPS_CONF_TYPE_FLAG */

#if defined(MBEDTLS_MPS_PROTO_TLS)
#if !defined(MBEDTLS_MPS_CONF_PAUSE_FLAG)
    ctx->conf.pause_flag |= ( pausing == MBEDTLS_MPS_SPLIT_ENABLED ) * mask;
#endif /* MBEDTLS_MPS_CONF_PAUSE_FLAG */
#else
    ((void) pausing);
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if !defined(MBEDTLS_MPS_CONF_MERGE_FLAG)
    ctx->conf.merge_flag |= ( merging == MBEDTLS_MPS_PACK_ENABLED  ) * mask;
#endif /* !MBEDTLS_MPS_CONF_MERGE_FLAG */

#if !defined(MBEDTLS_MPS_CONF_EMPTY_FLAG)
    ctx->conf.empty_flag |= ( empty   == MBEDTLS_MPS_EMPTY_ALLOWED ) * mask;
#endif /* !MBEDTLS_MPS_CONF_EMPTY_FLAG */

    return( 0 );
}

/**
 * \brief          Configure the TLS/DTLS version to be used
 *                 by a Layer 2 context.
 *
 * \param ctx      The address of the Layer 2 context to use.
 * \param version  The TLS or DTLS version to use.
 *                 TODO: Name the allowed values
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 */

/*@
  MPS_L2_INV_REQUIRES( ctx )
  MPS_L2_INV_ENSURES( ctx )
@*/
MBEDTLS_MPS_PUBLIC int mps_l2_config_version( mbedtls_mps_l2 *ctx, uint8_t version );

/**
 * \brief          Query a Layer 2 context for incoming data.
 *
 * \param ctx      The address of the Layer 2 context to use.
 * \param in       The address at which to store type, epoch
 *                 and content information of the incoming
 *                 data on success.
 *
 * \return         \c 0 on success.
 * \return         #MPS_ERR_WANT_READ if no data is
 *                 available on the underlying transport.
 *                 In this case, the context remains usable, and
 *                 the user should call the function again at a
 *                 later stage (either in a loop or event-driven).
 * \return         Another negative error code on failure.
 *
 */

/*@
  MPS_L2_INV_REQUIRES( ctx )
  MPS_L2_INV_ENSURES( ctx )
@*/
MBEDTLS_MPS_PUBLIC int mps_l2_read_start( mbedtls_mps_l2 *ctx, mps_l2_in *in );

/**
 * \brief          Signal that incoming data previously
 *                 obtained from mps_l2_read_start() has
 *                 been fully processed.
 *
 * \param ctx      The address of the Layer 2 context to use.
 *
 * \return         \c 0 on success.
 * \return         Another negative error code on failure.
 *
 */

/*@
  MPS_L2_INV_REQUIRES( ctx )
  MPS_L2_INV_ENSURES( ctx )
@*/
MBEDTLS_MPS_PUBLIC int mps_l2_read_done( mbedtls_mps_l2 *ctx );

/**
 * \brief          Request to prepare the writing of data of
 *                 given record content type and epoch.
 *
 * \param ctx      The address of the Layer 2 context to use.
 * \param out      The partially filled outgoing data context
 *                 to use. The \c type and \c epoch fields must
 *                 be set by the user and are left unchanged
 *                 by this function; the \c wr field is set to
 *                 the address of a writer object that can be
 *                 used to write the record contents on success.
 *
 * \return         \c 0 on success.
 * \return         Another negative error code on failure.
 *
 */

/*@
  MPS_L2_INV_REQUIRES( ctx )
  MPS_L2_INV_ENSURES( ctx )
@*/
MBEDTLS_MPS_PUBLIC int mps_l2_write_start( mbedtls_mps_l2 *ctx, mps_l2_out *out );

/**
 * \brief          Signal that the writing of outgoing data via
 *                 the handle obtained from mps_l2_write_start()
 *                 is done.
 *
 * \param ctx      The address of the Layer 2 context to use.
 *
 * \note           This function does not guarantee that the
 *                 data is immediately delivered to the underlying
 *                 transport. To ensure this, the user must
 *                 call mps_l2_write_flush().
 *
 * \return         \c 0 on success.
 * \return         Another negative error code on failure.
 *
 */

/*@
  MPS_L2_INV_REQUIRES( ctx )
  MPS_L2_INV_ENSURES( ctx )
@*/
MBEDTLS_MPS_PUBLIC int mps_l2_write_done( mbedtls_mps_l2 *ctx );

/**
 * \brief          Attempt to deliver all outgoing data previously
 *                 dispatched via calls to mps_l2_write_done()
 *                 to the underlying transport.
 *
 * \param ctx      The address of the Layer 2 context to use.
 *
 * \return         \c 0 on success.
 * \return         #MPS_ERR_WANT_WRITE if the underlying transport
 *                 was not ready to send all pending outgoing data.
 *                 In this case, the function should be called
 *                 again until it succeeds.
 * \return         Another negative error code on failure.
 *
 */

/*@
  MPS_L2_INV_REQUIRES( ctx )
  MPS_L2_INV_ENSURES( ctx )
@*/
MBEDTLS_MPS_PUBLIC int mps_l2_write_flush( mbedtls_mps_l2 *ctx );

/**
 * \brief          Configure Layer 2 context to allow communication
 *                 with a given epoch and set the payload protection
 *                 through which the communication should be secured.
 *
 * \param ctx       The Layer 2 context to use.
 * \param transform The context defining the payload protection to apply
 *                  for epoch \p epoch. This is a context processed
 *                  by the \c transform_xxx functions.
 *                  Currently, \p transform must be heap-allocated,
 *                  and this call transfers ownership entirely to
 *                  the Layer 2 context. In particular, no read, write
 *                  or deallocation operation must be performed on
 *                  \p transform by the user after this function has
 *                  been called. This leads to the following asymmetric
 *                  control-flow:
 *                  1. User allocates an ::mbedtls_mps_transform_t instance
 *                     from the heap.
 *                  2. User initializes and configures the instance.
 *                  3. User binds the instance to an epoch ID via
 *                     mps_l2_epoch_add(), thereby transferring the
 *                     ownership to Layer 2.
 *                  4. Layer 2 maintains the transformation and destroys
 *                     and frees it once it becomes unused or the Layer 2
 *                     context is destroyed through a call to mps_l2_free().
 *                  This is analogous to passing a unique_pointer via
 *                  move-semantics in C++.
 * \param epoch     The address to which to write the identifier for
 *                  the keying material on success.
 *
 * \note            In case of TLS, this function modifies the incoming
 *                  epoch ID or the outgoing epoch ID, or both (depending
 *                  on the value of \p usage).
 *
 * \note            Another copy-less alternative would be to
 *                  have the user query Layer 2 for space for a
 *                  fresh ::mbedtls_mps_transform_t instance to be used
 *                  with a to-be-registered epoch ID, and to have an
 *                  API call to Layer 2 to signal when the preparation
 *                  is done and the epoch should become active.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 */

/*@
  MPS_L2_INV_REQUIRES( ctx )
  MPS_L2_INV_ENSURES( ctx )
@*/
MBEDTLS_MPS_PUBLIC int mps_l2_epoch_add( mbedtls_mps_l2 *ctx,
                                 mbedtls_mps_transform_t *transform,
                                 mbedtls_mps_epoch_id *epoch );

/**
 * \brief          Modify the usage configuration for a previously
 *                 added epoch ID.
 *
 * \param ctx      The address of the Layer 2 context to use.
 * \param epoch    The ID of the epoch to configure.
 * \param clear    The usage flags to clear.
 * \param set      The usage flags to set.
 *
 * \note           In case of TLS, this function modifies the incoming
 *                 epoch ID or the outgoing epoch ID, or both (depending
 *                 on the value of \p usage).
 *
 * \return         \c 0 on success.
 *
 */

/*@
  MPS_L2_INV_REQUIRES( ctx )
  MPS_L2_INV_ENSURES( ctx )
@*/
int mps_l2_epoch_usage( mbedtls_mps_l2 *ctx,
                        mbedtls_mps_epoch_id epoch_id,
                        mbedtls_mps_epoch_usage clear,
                        mbedtls_mps_epoch_usage set );

/**
 * \brief          Enforce that the next outgoing record of the
 *                 specified epoch uses a particular record sequence number.
 *
 * \param ctx      The address of the Layer 2 context to use.
 * \param epoch_id The ID of the epoch to configure.
 * \param ctr      The record sequence number to be used for the
 *                 next outgoing record of epoch \p epoch_id.
 *
 * \note           This function constitutes an abstraction break
 *                 but is enforced by the following requirement from RFC 6347:
 *                   Upon receipt of the ServerHello, the client MUST verify
 *                   that the server version values match. In order to avoid
 *                   sequence number duplication in case of multiple
 *                   HelloVerifyRequests, the server MUST use the record
 *                   sequence number in the ClientHello as the record sequence
 *                   number in the HelloVerifyRequest.
 *
 * \return         \c 0 on success.
 *
 */
MBEDTLS_MPS_PUBLIC int mps_l2_force_next_sequence_number( mbedtls_mps_l2 *ctx,
                                                  mbedtls_mps_epoch_id epoch_id,
                                                  uint64_t ctr );

/**
 * \brief          Get the sequence number of last incoming record
 *                 protected with a given epoch.
 *
 * \param ctx      The address of the Layer 2 context to use.
 * \param epoch_id The ID of the epoch to use.
 * \param ctr      The address to write the sequence number of the
 *                 last incoming record of epoch \p epoch_id to.
 *
 * \note           This function constitutes an abstraction break
 *                 but is enforced by the following requirement from RFC 6347:
 *                   Upon receipt of the ServerHello, the client MUST verify
 *                   that the server version values match. In order to avoid
 *                   sequence number duplication in case of multiple
 *                   HelloVerifyRequests, the server MUST use the record
 *                   sequence number in the ClientHello as the record sequence
 *                   number in the HelloVerifyRequest.
 *
 * \return         \c 0 on success.
 *
 */
MBEDTLS_MPS_PUBLIC int mps_l2_get_last_sequence_number( mbedtls_mps_l2 *ctx,
                                                mbedtls_mps_epoch_id epoch_id,
                                                uint64_t *ctr );

#endif /* MBEDTLS_MPS_RECORD_LAYER_H */
