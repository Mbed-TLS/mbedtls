/*
 *  Message Processing Stack, Layer 3 implementation
 *
 *  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#include "../../include/mbedtls/mps/layer3.h"
#include "../../include/mbedtls/mps/trace.h"

#if defined(MBEDTLS_MPS_SEPARATE_LAYERS) ||     \
    defined(MBEDTLS_MPS_TOP_TRANSLATION_UNIT)

#if defined(MBEDTLS_MPS_TRACE)
static int trace_id = TRACE_BIT_LAYER_3;
#endif /* MBEDTLS_MPS_TRACE */

#include <stdlib.h>

/*
 * Forward declarations for some internal functions
 */

/* Reading-related */
static int l3_parse_hs_header( uint8_t mode, mbedtls_reader *rd,
                               mps_l3_hs_in_internal *in );

#if defined(MBEDTLS_MPS_PROTO_TLS)
static int l3_parse_hs_header_tls( mbedtls_reader *rd,
                                   mps_l3_hs_in_internal *in );
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
static int l3_parse_hs_header_dtls( mbedtls_reader *rd,
                                    mps_l3_hs_in_internal *in );
#endif /* MBEDTLS_MPS_PROTO_DTLS */

static int l3_parse_alert( mbedtls_reader *rd,
                           mps_l3_alert_in_internal *alert );
static int l3_parse_ccs( mbedtls_reader *rd );

/* Writing-related */
static int l3_prepare_write( mps_l3 *l3, mbedtls_mps_msg_type_t type,
                             mbedtls_mps_epoch_id epoch );
static int l3_check_clear( mps_l3 *l3 );

#if defined(MBEDTLS_MPS_PROTO_TLS)
static int l3_write_hs_header_tls( mps_l3_hs_out_internal *hs );
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
static int l3_write_hs_header_dtls( mps_l3_hs_out_internal *hs );
#endif /* MBEDTLS_MPS_PROTO_DTLS */

/*
 * Constants and sizes from the [D]TLS standard
 */

#define MPS_TLS_HS_HDR_SIZE 4
#define MPS_TLS_ALERT_SIZE  2
#define MPS_TLS_CCS_SIZE    1

#define MPS_TLS_CCS_VALUE   1

#define MPS_DTLS_HS_HDR_SIZE 13

/*
 * Init & Free API
 */

int mps_l3_init( mps_l3 *l3, mbedtls_mps_l2 *l2, uint8_t mode )
{
    TRACE_INIT( "mps_l3_init" );
    l3->conf.l2 = l2;
    l3->conf.mode = mode;

    l3->in.state = MBEDTLS_MPS_MSG_NONE;
    l3->in.hs.state = MPS_L3_HS_NONE;
    l3->in.raw_in = NULL;

    l3->out.state    = MBEDTLS_MPS_MSG_NONE;
    l3->out.hs.state = MPS_L3_HS_NONE;
    l3->out.raw_out  = NULL;
    l3->out.clearing = 0;

    /* TODO Configure Layer 2
     * - Add allowed record types
     * - Configure constraints for merging, pausing,
     *   and empty records.
     */
    RETURN( 0 );
}

int mps_l3_free( mps_l3 *l3 )
{
    ((void) l3);
    TRACE_INIT( "mps_l3_free" );
    RETURN( 0 );
}

/*
 * Reading API
 */

/* Check if a message is ready to be processed. */
int mps_l3_read_check( mps_l3 *l3 )
{
    return( l3->in.state );
}

/* Attempt to receive an incoming message from Layer 2. */
int mps_l3_read( mps_l3 *l3 )
{
    int res;
    mps_l2_in in;
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type mode = l3->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    TRACE_INIT( "mps_l3_read" );

    /*
     * Outline:
     * 1  If a message is already open for reading,
     *    do nothing and return its type.
     * 2  If no message is currently open for reading, request
     *    incoming data from the underlying Layer 2 context.
     * 3.1 For all content types different from handshake,
     *     call the type-specific parsing function with the
     *     reader returned from Layer 2.
     * 3.2 For handshake messages, check if an incoming handshake
     *     message is currently being paused.
     * 3.2.1 If no: Parse the TLS/DTLS handshake header from the
     *       incoming data reader, setup a new extended reader
     *       with the total message size, and bind it to the incoming
     *       data reader.
     * 3.2.2 If yes (TLS only!)
     *         Fragmentation of handshake messages across multiple records
     *         do not require handshake headers within the subsequent records.
     *         Hence, we can directly bind the incoming data reader to the
     *         extended reader keeping track of global message bounds.
     */

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    /* 1 */
    if( l3->in.state != MBEDTLS_MPS_MSG_NONE )
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    /* 2 */
    /* Request incoming data from Layer 2 context */
    TRACE( trace_comment, "Check for incoming data on Layer 2" );

    res = mps_l2_read_start( l3->conf.l2, &in );
    if( res != 0 )
        RETURN( res );

    TRACE( trace_comment, "Opened incoming datastream" );
    TRACE( trace_comment, "* Epoch: %u", (unsigned) in.epoch );
    TRACE( trace_comment, "* Type:  %u", (unsigned) in.type );
    switch( in.type )
    {
        /* 3.1 */

        case MBEDTLS_MPS_MSG_APP:
            TRACE( trace_comment, "-> Application data" );
            break;

        case MBEDTLS_MPS_MSG_ALERT:
            TRACE( trace_comment, "-> Alert message" );

            /* Attempt to fetch alert.
             *
             * - In TLS, this might fail because the alert
             *   spans a record boundary. In this case,
             *   we need to await more data from subsequent
             *   records before we can parse the alert.
             *   This is transparently handled by Layer 2.
             *
             * - For DTLS, an incomplete alert message
             *   is treated as a fatal error.
             */
            res = l3_parse_alert( in.rd, &l3->in.alert );
            if( res == MBEDTLS_ERR_READER_OUT_OF_DATA )
            {
#if defined(MBEDTLS_MPS_PROTO_DTLS)
                if( MBEDTLS_MPS_IS_DTLS( mode ) )
                {
                    TRACE( trace_error, "Incomplete alert message found -- abort" );
                    RETURN( MPS_ERR_BAD_MSG );
                }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

#if defined(MBEDTLS_MPS_PROTO_TLS)
                if( MBEDTLS_MPS_IS_TLS( mode ) )
                {
                    TRACE( trace_comment, "Not enough data available in record to read alert message" );
                    res = mps_l2_read_done( l3->conf.l2 );
                    if( res != 0 )
                        RETURN( res );

                    /* No records are buffered by Layer 2, so progress depends
                     * on the availability of the underlying transport.
                     *
                     * NOTE: If Layer 2 ever happens to fetch and buffer
                     *       multiple records, this must be changed. */
                    RETURN( MPS_ERR_WANT_READ );
                }
#endif /* MBEDTLS_MPS_PROTO_TLS */
            }
            else if( res != 0 )
                RETURN( res );

            break;

        case MBEDTLS_MPS_MSG_CCS:
            TRACE( trace_comment, "-> CCS message" );

            /* We don't need to consider #MBEDTLS_ERR_READER_OUT_OF_DATA
             * here because the CCS content type does not allow empty
             * records, and hence malicious length-0 records of type CCS
             * will already have been silently skipped over (DTLS) or
             * lead to failure (TLS) by Layer 2. */
            res = l3_parse_ccs( in.rd );
            if( res != 0 )
                RETURN( res );
            break;

        case MBEDTLS_MPS_MSG_ACK:
            /* DTLS-1.3-TODO: Implement */
            RETURN( MPS_ERR_UNSUPPORTED_FEATURE );

        /* 3.2 */

        case MBEDTLS_MPS_MSG_HS:
            TRACE( trace_comment, "-> Handshake message" );

            /*
             * General workings of handshake reading:
             *
             * Like for other content types, Layer 2 provides raw access to
             * records of the handshake content type through readers. When
             * handshake messages are implicitly fragmented across multiple
             * records in TLS, some additional structure outside the scope
             * of Layer 2 has to be allocated to keep track of how much of
             * the current handshake message has already been read. This
             * information can be used to guard against unreasonable read-
             * requests (beyond the bounds of the handshake message),
             * as well as to check whether handshake messages have been
             * entirely processed when they are closed via l3_read_consume.
             *
             * This additional information of total handshake message size
             * as well as global read state is kept within an 'extended'
             * reader object: When initialized, the extended reader is given
             * global message bounds. When Layer 2 provides a reader for
             * handshake contents, this reader is 'bound' to the extended
             * reader, and the extended reader forwards all subsequent read-
             * requests to that reader, while at the same time keeping track
             * of and updating the global reading state.
             *
             * When the reading of a message needs to be paused because the
             * message spans multiple records, the 'raw' Layer 2 reader is
             * 'detached' from the extended reader, but the extended reader
             * itself is kept, and can be bound to another Layer 2 handshake
             * reader once the next message fragment arrives.
             *
             */

            /* Check if a handshake message is currently being paused. */
            switch( l3->in.hs.state )
            {
                /* 3.2.1 */
                case MPS_L3_HS_NONE:
                    TRACE( trace_comment, "No handshake message is currently processed" );

                    /* Attempt to fetch and parse handshake header.
                     *
                     * - In TLS, this might fail because the handshake
                     *   header spans a record boundary. In this case,
                     *   we need to await more data from subsequent
                     *   records before we can parse the handshake header.
                     *   This is transparently handled by Layer 2.
                     *
                     * - For DTLS, an incomplete handshake header
                     *   is treated as a fatal error.
                     */
                    res = l3_parse_hs_header( l3->conf.mode, in.rd,
                                              &l3->in.hs );
                    if( res == MBEDTLS_ERR_READER_OUT_OF_DATA )
                    {
#if defined(MBEDTLS_MPS_PROTO_DTLS)
                        if( MBEDTLS_MPS_IS_DTLS( mode ) )
                        {
                            TRACE( trace_error, "Incomplete handshake header found -- abort" );
                            RETURN( MPS_ERR_BAD_MSG );
                        }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

#if defined(MBEDTLS_MPS_PROTO_TLS)
                        if( MBEDTLS_MPS_IS_TLS( mode ) )
                        {
                            TRACE( trace_comment, "Incomplete handshake header in current record -- wait for more data." );

                            res = mps_l2_read_done( l3->conf.l2 );
                            if( res != 0 )
                                RETURN( res );

                            /* No records are buffered by Layer 2, so progress
                             * depends on the availability of the underlying
                             * transport.
                             *
                             * NOTE: If Layer 2 ever happens to fetch and buffer
                             *       multiple records, this must be changed. */
                            RETURN( MPS_ERR_WANT_READ );
                        }
#endif /* MBEDTLS_MPS_PROTO_TLS */
                    }
                    else if( res != 0 )
                        RETURN( res );

                    /* Setup the extended reader keeping track of the
                     * global message bounds. */
                    TRACE( trace_comment, "Setup extended reader for handshake message" );

                    /* TODO: Think about storing the frag_len in len for DTLS
                     *       to avoid this distinction. */
#if defined(MBEDTLS_MPS_PROTO_TLS)
                    if( MBEDTLS_MPS_IS_TLS( mode ) )
                    {
                        mbedtls_reader_init_ext( &l3->in.hs.rd_ext,
                                                 l3->in.hs.len );
                    }
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
                    if( MBEDTLS_MPS_IS_DTLS( mode ) )
                    {
                        mbedtls_reader_init_ext( &l3->in.hs.rd_ext,
                                                 l3->in.hs.frag_len );
                    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

                    break;

                /* 3.2.2 */
                case MPS_L3_HS_PAUSED:
                    TRACE( trace_comment, "A handshake message currently paused" );
                    if( l3->in.hs.epoch != in.epoch )
                    {
                        /* This should never happen, as we don't allow switching
                         * the incoming epoch while pausing the reading of a
                         * handshake message. But double-check nonetheless. */
                        RETURN( MPS_ERR_INTERNAL_ERROR );
                    }
                    break;

                case MPS_L3_HS_ACTIVE:
                default:
                    /* Should never happen -- if a handshake message
                     * is active, then this must be reflected in the
                     * state variable l3->in.state. */
                    RETURN( MPS_ERR_INTERNAL_ERROR );
            }

            /* Bind the raw reader (supplying record contents) to the
             * extended reader (keeping track of global message bounds). */
            res = mbedtls_reader_attach( &l3->in.hs.rd_ext, in.rd );
            if( res != 0 )
                RETURN( res );

            /* Make changes to internal structures only now
             * that we know that everything went well. */
            l3->in.hs.epoch = in.epoch;
            l3->in.hs.state = MPS_L3_HS_ACTIVE;

            break;

        default:
            /* Should never happen because we configured L2
             * to only accept the above types. */
            RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    l3->in.raw_in = in.rd;
    l3->in.epoch  = in.epoch;
    l3->in.state  = in.type;

    TRACE( trace_comment, "New state" );
    TRACE( trace_comment, "* External state:  %u",
           (unsigned) l3->in.state );
    TRACE( trace_comment, "* Handshake state: %u",
           (unsigned) l3->in.hs.state );

    RETURN( l3->in.state );
}

/* Mark an incoming message as fully processed. */
int mps_l3_read_consume( mps_l3 *l3 )
{
    int res;
    TRACE_INIT( "mps_l3_read_consume" );

    switch( l3->in.state )
    {
#if defined(MBEDTLS_MPS_STATE_VALIDATION)
        case MBEDTLS_MPS_MSG_NONE:
            RETURN( MPS_ERR_UNEXPECTED_OPERATION );
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

        case MBEDTLS_MPS_MSG_HS:
            TRACE( trace_comment, "Finishing handshake message" );
            /* See mps_l3_read for the general description
             * of how the implementation uses extended readers
             * to handle pausing of handshake messages. */

            /* Attempt to close the extended reader.
             * This in particular checks whether the entire
             * message has been fetched and committed. */
            if( mbedtls_reader_check_done( &l3->in.hs.rd_ext ) != 0 )
            {
                TRACE( trace_error, "Attempting to close a not fully processed handshake message." );
                RETURN( MPS_ERR_UNFINISHED_HS_MSG );
            }

            /* Remove reference to raw reader from extended reader. */
            res = mbedtls_reader_detach( &l3->in.hs.rd_ext );
            if( res != 0 )
                RETURN( res );

            /* Reset extended reader. */
            mbedtls_reader_free_ext( &l3->in.hs.rd_ext );

            break;

        case MBEDTLS_MPS_MSG_ALERT:
        case MBEDTLS_MPS_MSG_ACK:
        case MBEDTLS_MPS_MSG_CCS:
        case MBEDTLS_MPS_MSG_APP:
            /* All contents are already committed in parsing functions. */
            break;

        default:
            RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    /* Remove reference to the raw reader borrowed from Layer 2
     * before calling mps_l2_read_done(), which invalidates it. */
    l3->in.raw_in = NULL;

    /* Signal that incoming data is fully processed. */
    res = mps_l2_read_done( l3->conf.l2 );
    if( res != 0 )
        RETURN( res );

    /* Reset state */
    if( l3->in.state == MBEDTLS_MPS_MSG_HS )
        l3->in.hs.state = MPS_L3_HS_NONE;
    l3->in.state = MBEDTLS_MPS_MSG_NONE;
    RETURN( 0 );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
/* Pause the processing of an incoming handshake message. */
int mps_l3_read_pause_handshake( mps_l3 *l3 )
{
    int res;
    TRACE_INIT( "mps_l3_read_pause_handshake" );

    /* See mps_l3_read() for the general description
     * of how the implementation uses extended readers
     * to handle pausing of handshake messages. */

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( l3->in.state != MBEDTLS_MPS_MSG_HS ||
        l3->in.hs.state != MPS_L3_HS_ACTIVE )
    {
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    /* Remove reference to raw reader from extended reader. */
    res = mbedtls_reader_detach( &l3->in.hs.rd_ext );
    if( res != 0 )
        RETURN( res );

    /* Remove reference to the raw reader borrowed from Layer 2
     * before calling mps_l2_read_done(), which invalidates it. */
    l3->in.raw_in = NULL;

    /* Signal to Layer 2 that incoming data is fully processed. */
    res = mps_l2_read_done( l3->conf.l2 );
    if( res != 0 )
        RETURN( res );

    /* Switch to paused state. */
    l3->in.state    = MBEDTLS_MPS_MSG_NONE;
    l3->in.hs.state = MPS_L3_HS_PAUSED;
    RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

/*
 * Record content type specific parsing functions.
 */

/* Handshake */

static int l3_parse_hs_header( uint8_t mode, mbedtls_reader *rd,
                               mps_l3_hs_in_internal *in )
{
#if !defined(MBEDTLS_MPS_PROTO_BOTH)
    ((void) mode);
#endif /* MBEDTLS_MPS_PROTO_BOTH */

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
        return( l3_parse_hs_header_tls( rd, in ) );
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
        return( l3_parse_hs_header_dtls( rd, in ) );
#endif /* MBEDTLS_MPS_PROTO_TLS */

    return( MPS_ERR_INTERNAL_ERROR );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
static int l3_parse_hs_header_tls( mbedtls_reader *rd,
                                   mps_l3_hs_in_internal *in )
{
    int res;
    unsigned char *tmp;

    size_t const tls_hs_hdr_len = 4;

    size_t const tls_hs_type_offset   = 0;
    size_t const tls_hs_length_offset = 1;

    /*

      From RFC 5246 (TLS 1.2):

      enum {
          ..., (255)
      } HandshakeType;

      struct {
          HandshakeType msg_type;
          uint24 length;
          select (HandshakeType) {
              case hello_request:       HelloRequest;
              case client_hello:        ClientHello;
              case server_hello:        ServerHello;
              case certificate:         Certificate;
              case server_key_exchange: ServerKeyExchange;
              case certificate_request: CertificateRequest;
              case server_hello_done:   ServerHelloDone;
              case certificate_verify:  CertificateVerify;
              case client_key_exchange: ClientKeyExchange;
              case finished:            Finished;
          } body;
      } Handshake;

    */

    TRACE_INIT( "l3_parse_hs_header_tls" );

    /* This call might fail for handshake headers spanning
     * multiple records. This will be caught in up in the
     * call chain, and Layer 2 will remember the request
     * in this case and ensure it can be satisfied the next
     * time it signals incoming data of handshake content type.
     * We therefore don't need to save state here. */
    res = mbedtls_reader_get( rd, tls_hs_hdr_len, &tmp, NULL );
    if( res != 0 )
        RETURN( res );

    MPS_READ_UINT8_LE ( tmp + tls_hs_type_offset, &in->type );
    MPS_READ_UINT24_LE( tmp + tls_hs_length_offset, &in->len );

    res = mbedtls_reader_commit( rd );
    if( res != 0 )
        RETURN( res );

    TRACE( trace_comment, "Parsed handshake header" );
    TRACE( trace_comment, "* Type:   %u", (unsigned) in->type );
    TRACE( trace_comment, "* Length: %u", (unsigned) in->len );
    RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
static int l3_parse_hs_header_dtls( mbedtls_reader *rd,
                                    mps_l3_hs_in_internal *in )
{
    int res;
    unsigned char *tmp;

    size_t const dtls_hs_hdr_len         = 13;
    size_t const dtls_hs_type_offset     = 0;
    size_t const dtls_hs_len_offset      = 1;
    size_t const dtls_hs_seq_offset      = 4;
    size_t const dtls_hs_frag_off_offset = 7;
    size_t const dtls_hs_frag_len_offset = 10;

    /*
     *
     * From RFC 6347 (DTLS 1.2):
     *
     *   struct {
     *     HandshakeType msg_type;
     *     uint24 length;
     *     uint16 message_seq;                               // New field
     *     uint24 fragment_offset;                           // New field
     *     uint24 fragment_length;                           // New field
     *     select (HandshakeType) {
     *       case hello_request: HelloRequest;
     *       case client_hello:  ClientHello;
     *       case hello_verify_request: HelloVerifyRequest;  // New type
     *       case server_hello:  ServerHello;
     *       case certificate:Certificate;
     *       case server_key_exchange: ServerKeyExchange;
     *       case certificate_request: CertificateRequest;
     *       case server_hello_done:ServerHelloDone;
     *       case certificate_verify:  CertificateVerify;
     *       case client_key_exchange: ClientKeyExchange;
     *       case finished: Finished;
     *     } body;
     *   } Handshake;
     *
     */

    TRACE_INIT( "parse_hs_header_dtls" );

    res = mbedtls_reader_get( rd, dtls_hs_hdr_len, &tmp, NULL );
    if( res != 0 )
        RETURN( res );

    MPS_READ_UINT8_LE ( tmp + dtls_hs_type_offset, &in->type );
    MPS_READ_UINT24_LE( tmp + dtls_hs_len_offset, &in->len );
    MPS_READ_UINT16_LE( tmp + dtls_hs_seq_offset, &in->seq_nr );
    MPS_READ_UINT24_LE( tmp + dtls_hs_frag_off_offset, &in->frag_offset );
    MPS_READ_UINT24_LE( tmp + dtls_hs_frag_len_offset, &in->frag_len );

    res = mbedtls_reader_commit( rd );
    if( res != 0 )
        RETURN( res );

    /* frag_offset + frag_len cannot overflow within uint32_t
     * since the summands are 24 bit each. */
    if( in->frag_offset + in->frag_len > in->len )
    {
        TRACE( trace_error, "Invalid handshake header: frag_offset (%u) + frag_len (%u) > len (%u)",
               (unsigned)in->frag_offset,
               (unsigned)in->frag_len,
               (unsigned)in->len );
        RETURN( MPS_ERR_BAD_MSG );
    }

    TRACE( trace_comment, "Parsed DTLS handshake header" );
    TRACE( trace_comment, "* Type:        %u", (unsigned) in->type        );
    TRACE( trace_comment, "* Length:      %u", (unsigned) in->len         );
    TRACE( trace_comment, "* Sequence Nr: %u", (unsigned) in->seq_nr      );
    TRACE( trace_comment, "* Frag Offset: %u", (unsigned) in->frag_offset );
    TRACE( trace_comment, "* Frag Length: %u", (unsigned) in->frag_len    );

    RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_DTLS */

/* Alert */

static int l3_parse_alert( mbedtls_reader *rd,
                           mps_l3_alert_in_internal *alert )
{
    int res;
    unsigned char *tmp;
    TRACE_INIT( "l3_parse_alert" );

    /*

      From RFC 5246 (TLS 1.2):

      enum { warning(1), fatal(2), (255) } AlertLevel;
      enum { close_notify(0), ..., (255) } AlertDescription;
      struct {
          AlertLevel level;
          AlertDescription description;
      } Alert;

    */

    /* This call might fail for alert messages spanning
     * two records. This will be caught in up in the
     * call chain, and Layer 2 will remember the request
     * in this case and ensure it can be satisfied the next
     * time it signals incoming data of alert content type.
     * We therefore don't need to save state here. */
    res = mbedtls_reader_get( rd, MPS_TLS_ALERT_SIZE, &tmp, NULL );
    if( res != 0 )
        RETURN( res );

    MPS_READ_UINT8_LE ( tmp + 0, &alert->level );
    MPS_READ_UINT8_LE ( tmp + 1, &alert->type );

    res = mbedtls_reader_commit( rd );
    if( res != 0 )
        RETURN( res );

    TRACE( trace_comment, "Parsed alert message" );
    TRACE( trace_comment, "* Level: %u", (unsigned) alert->level );
    TRACE( trace_comment, "* Type:  %u", (unsigned) alert->type );
    RETURN( 0 );
}

/* CCS */

static int l3_parse_ccs( mbedtls_reader *rd )
{
    int res;
    unsigned char *tmp;
    uint8_t val;
    TRACE_INIT( "l3_parse_ccs" );

    /*

      From RFC 5246 (TLS 1.2):

      struct {
          enum { change_cipher_spec(1), (255) } type;
      } ChangeCipherSpec;

    */

    res = mbedtls_reader_get( rd, MPS_TLS_CCS_SIZE, &tmp, NULL );
    if( res != 0 )
        RETURN( res );

    MPS_READ_UINT8_LE( tmp + 0, &val );

    res = mbedtls_reader_commit( rd );
    if( res != 0 )
        RETURN( res );

    if( val != MPS_TLS_CCS_VALUE )
    {
        TRACE( trace_error, "Bad CCS value %u", (unsigned) val );
        RETURN( MPS_ERR_BAD_MSG );
    }

    TRACE( trace_comment, "Parsed alert message" );
    TRACE( trace_comment, " * Value: %u", MPS_TLS_CCS_VALUE );
    RETURN( 0 );
}

/*
 * API for retrieving read-handles for various content types.
 */

int mps_l3_read_handshake( mps_l3 *l3, mps_l3_handshake_in *hs )
{
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type mode = l3->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    TRACE_INIT( "mps_l3_read_handshake" );

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( l3->in.state    != MBEDTLS_MPS_MSG_HS ||
        l3->in.hs.state != MPS_L3_HS_ACTIVE )
    {
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    hs->epoch  = l3->in.epoch;
    hs->len    = l3->in.hs.len;
    hs->type   = l3->in.hs.type;
    hs->rd_ext = &l3->in.hs.rd_ext;

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        hs->seq_nr      = l3->in.hs.seq_nr;
        hs->frag_offset = l3->in.hs.frag_offset;
        hs->frag_len    = l3->in.hs.frag_len;
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    RETURN( 0 );
}

int mps_l3_read_app( mps_l3 *l3, mps_l3_app_in *app )
{
    TRACE_INIT( "mps_l3_read_app" );
#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( l3->in.state != MBEDTLS_MPS_MSG_APP )
    {
        TRACE( trace_comment, "No application data message opened" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    app->epoch = l3->in.epoch;
    app->rd = l3->in.raw_in;
    RETURN( 0 );
}

int mps_l3_read_alert( mps_l3 *l3, mps_l3_alert_in *alert )
{
    TRACE_INIT( "mps_l3_read_alert" );
#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( l3->in.state != MBEDTLS_MPS_MSG_ALERT )
    {
        TRACE( trace_comment, "No alert message opened" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    alert->epoch = l3->in.epoch;
    alert->type  = l3->in.alert.type;
    alert->level = l3->in.alert.level;
    RETURN( 0 );
}

int mps_l3_read_ccs( mps_l3 *l3, mps_l3_ccs_in *ccs )
{
    TRACE_INIT( "mps_l3_read_ccs" );
#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( l3->in.state != MBEDTLS_MPS_MSG_CCS )
    {
        TRACE( trace_comment, "No CCS message opened" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    ccs->epoch = l3->in.epoch;
    RETURN( 0 );
}

/*
 * Writing API
 */

int mps_l3_flush( mps_l3 *l3 )
{
    TRACE_INIT( "mps_l3_flush" );
    l3->out.clearing = 1;
    RETURN( l3_check_clear( l3 ) );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
static int l3_check_write_hs_hdr_tls( mps_l3 *l3 )
{
    int res;
    mps_l3_hs_out_internal *hs = &l3->out.hs;

    if( hs->hdr != NULL &&
        hs->len != MBEDTLS_MPS_SIZE_UNKNOWN )
    {
        res = l3_write_hs_header_tls( hs );
        if( res != 0 )
            return( res );

        hs->hdr     = NULL;
        hs->hdr_len = 0;
    }

    return( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
static int l3_check_write_hs_hdr_dtls( mps_l3 *l3 )
{
    int res;
    mps_l3_hs_out_internal *hs = &l3->out.hs;

    if( hs->hdr      != NULL &&
        hs->len      != MBEDTLS_MPS_SIZE_UNKNOWN &&
        hs->frag_len != MBEDTLS_MPS_SIZE_UNKNOWN )
    {
        res = l3_write_hs_header_dtls( hs );
        if( res != 0 )
            return( res );

        hs->hdr     = NULL;
        hs->hdr_len = 0;
    }

    return( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_DTLS */

static int l3_check_write_hs_hdr( mps_l3 *l3 )
{
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type mode = l3->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
        return( l3_check_write_hs_hdr_tls( l3 ) );
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
        return( l3_check_write_hs_hdr_dtls( l3 ) );
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    return( MPS_ERR_INTERNAL_ERROR );
}

int mps_l3_write_handshake( mps_l3 *l3, mps_l3_handshake_out *out )
{
    int res;
    int32_t len;
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type mode = l3->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    TRACE_INIT( "l3_write_handshake" );
    TRACE( trace_comment, "Parameters: " );
    TRACE( trace_comment, "* Seq Nr:   %u", (unsigned) out->seq_nr );
    TRACE( trace_comment, "* Epoch:    %u", (unsigned) out->epoch );
    TRACE( trace_comment, "* Type:     %u", (unsigned) out->type );
    TRACE( trace_comment, "* Length:   %u", (unsigned) out->len );
    TRACE( trace_comment, "* Frag Off: %u", (unsigned) out->frag_offset );
    TRACE( trace_comment, "* Frag Len: %u", (unsigned) out->frag_len );

    /*
     * See the documentation of mps_l3_read() for a description
     * of how extended readers are used for handling TLS
     * fragmentation of handshake messages; the case of writers
     * is analogous.
     */

    if( l3->out.hs.state == MPS_L3_HS_PAUSED &&
        ( l3->out.hs.epoch != out->epoch ||
          l3->out.hs.type  != out->type  ||
          l3->out.hs.len   != out->len ) )
    {
        TRACE( trace_error, "Inconsistent parameters on continuation." );
        RETURN( MPS_ERR_INCONSISTENT_ARGS );
    }

    res = l3_prepare_write( l3, MBEDTLS_MPS_MSG_HS, out->epoch );
    if( res != 0 )
        RETURN( res );

    if( l3->out.hs.state == MPS_L3_HS_NONE )
    {
        TRACE( trace_comment, "No handshake message currently paused" );

        l3->out.hs.epoch = out->epoch;
        l3->out.hs.len   = out->len;
        l3->out.hs.type  = out->type;
#if defined(MBEDTLS_MPS_PROTO_DTLS)
        if( MBEDTLS_MPS_IS_DTLS( mode ) )
        {
            l3->out.hs.seq_nr      = out->seq_nr;
            l3->out.hs.frag_len    = out->frag_len;
            l3->out.hs.frag_offset = out->frag_offset;

            /* TODO:
             * The following two checks are internal sanity checks only.
             * Consider removing them after initial testing.
             */

            /* If the total length isn't specified, then
             * then the fragment offset must be 0, and the
             * fragment length must be unspecified, too. */
            if( out->len == MBEDTLS_MPS_SIZE_UNKNOWN &&
                ( out->frag_offset != 0 ||
                  out->frag_len    != MBEDTLS_MPS_SIZE_UNKNOWN ) )
            {
                RETURN( MPS_ERR_INTERNAL_ERROR );
            }

            /* Check that fragment doesn't exceed the total message length. */
            if( out->len      != MBEDTLS_MPS_SIZE_UNKNOWN &&
                out->frag_len != MBEDTLS_MPS_SIZE_UNKNOWN )
            {
                int overflow = out->frag_offset + out->frag_len < out->frag_len;
                if( overflow || out->frag_offset + out->frag_len > out->len )
                {
                    RETURN( MPS_ERR_INTERNAL_ERROR );
                }
            }

            l3->out.hs.hdr_len = MPS_DTLS_HS_HDR_SIZE;
        }
#endif /* MBEDTLS_MPS_PROTO_DTLS */
#if defined(MBEDTLS_MPS_PROTO_TLS)
        if( MBEDTLS_MPS_IS_TLS( mode ) )
            l3->out.hs.hdr_len = MPS_TLS_HS_HDR_SIZE;
#endif /* MBEDTLS_MPS_PROTO_TLS */

        res = mbedtls_writer_get( l3->out.raw_out,
                                  l3->out.hs.hdr_len,
                                  &l3->out.hs.hdr, NULL );

        /* It might happen that we're at the end of a record
         * and there's not enough space left to write the
         * handshake header. In this case, abort the write
         * and make sure Layer 2 is flushed before we attempt
         * again. */
        if( res == MBEDTLS_ERR_WRITER_OUT_OF_DATA )
        {
            TRACE( trace_comment, "Not enough space to write handshake header - flush." );
            /* Remember that we must flush. */
            l3->out.clearing = 1;
            l3->out.state = MBEDTLS_MPS_MSG_NONE;
            res = mps_l2_write_done( l3->conf.l2 );
            if( res != 0 )
                RETURN( res );
            RETURN( MPS_ERR_WANT_WRITE );
        }
        else if( res != 0 )
            RETURN( res );

        /* Write the handshake header if we have
         * complete knowledge about the lengths. */
        res = l3_check_write_hs_hdr( l3 );
        if( res != 0 )
            RETURN( res );

        /* Note: Even if we do not know the total handshake length in
         *       advance, we do not yet commit the handshake header.
         *       The reason is that it might happen that the user finds
         *       that there's not enough space available to make any
         *       progress, and in this case we should abort the write
         *       instead of writing an empty handshake fragment. */

        TRACE( trace_comment, "Setup extended writer for handshake message" );

        /* TODO: Think about storing the frag_len in len for DTLS
         *       to avoid this distinction. */
        /* TODO: If `len` is UNKNOWN this is casted to -1u here,
         *       which is OK but fragile. */
#if defined(MBEDTLS_MPS_PROTO_TLS)
        if( MBEDTLS_MPS_IS_TLS( mode ) )
        {
            mbedtls_writer_init_ext( &l3->out.hs.wr_ext,
                                     out->len );
        }
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
        if( MBEDTLS_MPS_IS_DTLS( mode ) )
        {
            mbedtls_writer_init_ext( &l3->out.hs.wr_ext,
                                     out->frag_len );
        }
#endif /* MBEDTLS_MPS_PROTO_DTLS */
        if( res != 0 )
            RETURN( res );
    }

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
        len = out->frag_len;
#endif /* MBEDTLS_MPS_PROTO_DTLS */
#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
        len = out->len;
#endif /* MBEDTLS_MPS_PROTO_TLS */

    TRACE( trace_comment, "Bind raw writer to extended writer" );
    res = mbedtls_writer_attach( &l3->out.hs.wr_ext, l3->out.raw_out,
                                 len != MBEDTLS_MPS_SIZE_UNKNOWN
                                 ? MBEDTLS_WRITER_EXT_PASS
                                 : MBEDTLS_WRITER_EXT_HOLD );
    if( res != 0 )
        RETURN( res );

    l3->out.hs.state = MPS_L3_HS_ACTIVE;
    out->wr_ext = &l3->out.hs.wr_ext;
    RETURN( 0 );
}

int mps_l3_write_app( mps_l3 *l3, mps_l3_app_out *app )
{
    int res;
    mbedtls_mps_epoch_id epoch = app->epoch;
    TRACE_INIT( "l3_write_app: epoch %u", (unsigned) epoch );

    res = l3_prepare_write( l3, MBEDTLS_MPS_MSG_APP, epoch );
    if( res != 0 )
        RETURN( res );

    app->wr = l3->out.raw_out;
    RETURN( 0 );
}

int mps_l3_write_alert( mps_l3 *l3, mps_l3_alert_out *alert )
{
    int res;
    unsigned char *tmp;
    mbedtls_mps_epoch_id epoch = alert->epoch;
    TRACE_INIT( "l3_write_alert: epoch %u", (unsigned) epoch );

    res = l3_prepare_write( l3, MBEDTLS_MPS_MSG_ALERT, epoch );
    if( res != 0 )
        RETURN( res );

    res = mbedtls_writer_get( l3->out.raw_out, 2, &tmp, NULL );
    if( res == MBEDTLS_ERR_WRITER_OUT_OF_DATA )
    {
        l3->out.clearing = 1;
        l3->out.state = MBEDTLS_MPS_MSG_NONE;
        res = mps_l2_write_done( l3->conf.l2 );
        if( res != 0 )
            RETURN( res );
        RETURN( MPS_ERR_WANT_WRITE );
    }
    else if( res != 0 )
        RETURN( res );

    alert->level = &tmp[0];
    alert->type  = &tmp[1];
    RETURN( 0 );
}

int mps_l3_write_ccs( mps_l3 *l3, mps_l3_ccs_out *ccs )
{
    int res;
    unsigned char *tmp;
    mbedtls_mps_epoch_id epoch = ccs->epoch;
    TRACE_INIT( "l3_write_ccs: epoch %u", (unsigned) epoch );

    res = l3_prepare_write( l3, MBEDTLS_MPS_MSG_CCS, epoch );
    if( res != 0 )
        RETURN( res );

    res = mbedtls_writer_get( l3->out.raw_out, 1, &tmp, NULL );
    if( res == MBEDTLS_ERR_WRITER_OUT_OF_DATA )
    {
        l3->out.clearing = 1;
        l3->out.state = MBEDTLS_MPS_MSG_NONE;
        res = mps_l2_write_done( l3->conf.l2 );
        if( res != 0 )
            RETURN( res );
        RETURN( MPS_ERR_WANT_WRITE );
    }
    else if( res != 0 )
        RETURN( res );

    *tmp = MPS_TLS_CCS_VALUE;
    RETURN( 0 );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
/* Pause the writing of an outgoing handshake message (TLS only). */
int mps_l3_pause_handshake( mps_l3 *l3 )
{
    int res;
    size_t uncommitted;
    TRACE_INIT( "mps_l3_pause_handshake" );

    /* See mps_l3_read() for the general description
     * of how the implementation uses extended readers to
     * handle pausing of handshake messages. The handling
     * of outgoing handshake messages is analogous. */

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( l3->out.state    != MBEDTLS_MPS_MSG_HS       ||
        l3->out.hs.state != MPS_L3_HS_ACTIVE         ||
        l3->out.hs.len   == MBEDTLS_MPS_SIZE_UNKNOWN )
    {
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    /* Remove reference to raw writer from writer. */
    res = mbedtls_writer_detach( &l3->out.hs.wr_ext,
                                 NULL,
                                 &uncommitted );
    if( res != 0 )
        RETURN( res );

    /* We must perform this commit even if commits
     * are passed through, because it might happen
     * that the user pauses the writing before
     * any data has been committed. In this case,
     * we must make sure to commit the handshake header. */
    res = mbedtls_writer_commit_partial( l3->out.raw_out,
                                         uncommitted );
    if( res != 0 )
        RETURN( res );

    /* Remove reference to the raw writer borrowed from Layer 2
     * before calling mps_l2_write_done(), which invalidates it. */
    l3->out.raw_out = NULL;

    /* Signal to Layer 2 that we've finished acquiring and
     * writing to the outgoing data buffers. */
    res = mps_l2_write_done( l3->conf.l2 );
    if( res != 0 )
        RETURN( res );

    /* Switch to paused state. */
    l3->out.hs.state = MPS_L3_HS_PAUSED;
    l3->out.state    = MBEDTLS_MPS_MSG_NONE;
    RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

/* Abort the writing of a handshake message. */
int mps_l3_write_abort_handshake( mps_l3 *l3 )
{
    int res;
    size_t committed;
     TRACE_INIT( "mps_l3_write_abort_handshake" );
#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( l3->out.state  != MBEDTLS_MPS_MSG_HS ||
        l3->out.hs.state != MPS_L3_HS_ACTIVE )
    {
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    /* Remove reference to raw writer from writer. */
    res = mbedtls_writer_detach( &l3->out.hs.wr_ext,
                                 &committed,
                                 NULL );
    if( res != 0 )
        RETURN( res );

    /* Reset extended writer. */
    mbedtls_writer_free_ext( &l3->out.hs.wr_ext );

    if( committed > 0 )
    {
        TRACE( trace_error, "Attempt to abort handshake message parts of which have already been committed." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    /* Remove reference to the raw writer borrowed from Layer 2
     * before calling mps_l2_write_done(), which invalidates it. */
    l3->out.raw_out = NULL;

    /* Signal to Layer 2 that we've finished acquiring and
     * writing to the outgoing data buffers. */
    res = mps_l2_write_done( l3->conf.l2 );
    if( res != 0 )
        RETURN( res );

    l3->out.hs.state = MPS_L3_HS_NONE;
    l3->out.state    = MBEDTLS_MPS_MSG_NONE;
    RETURN( 0 );
}

int mps_l3_dispatch( mps_l3 *l3 )
{
    int res;
    size_t committed;
    size_t uncommitted;
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type mode = l3->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    TRACE_INIT( "mps_l3_dispatch" );

    switch( l3->out.state )
    {
#if defined(MBEDTLS_MPS_STATE_VALIDATION)
        case MBEDTLS_MPS_MSG_NONE:
            RETURN( MPS_ERR_UNEXPECTED_OPERATION );
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

        case MBEDTLS_MPS_MSG_HS:

            TRACE( trace_comment, "Dispatch handshake message" );
            if( l3->out.hs.state != MPS_L3_HS_ACTIVE )
                RETURN( MPS_ERR_INTERNAL_ERROR );

            res = mbedtls_writer_check_done( &l3->out.hs.wr_ext );
            if( res != 0 )
            {
                TRACE( trace_error, "Attempting to close not yet fully written handshake message." );
                RETURN( MPS_ERR_UNFINISHED_HS_MSG );
            }

            res = mbedtls_writer_detach( &l3->out.hs.wr_ext,
                                         &committed,
                                         &uncommitted );
            if( res != 0 )
                RETURN( res );

            /* Reset extended writer. */
            mbedtls_writer_free_ext( &l3->out.hs.wr_ext );

#if defined(MBEDTLS_MPS_PROTO_TLS)
            if( MBEDTLS_MPS_IS_TLS( mode ) )
            {
                if( l3->out.hs.len == MBEDTLS_MPS_SIZE_UNKNOWN )
                    l3->out.hs.len = committed;
            }
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
            if( MBEDTLS_MPS_IS_DTLS( mode ) )
            {
                /* It has been checked in mps_l3_write_handshake()
                 * that if the total length of the handshake message
                 * is unknown, then the fragment length is unknown, too,
                 * and the fragment offset is 0. */
                if( l3->out.hs.len == MBEDTLS_MPS_SIZE_UNKNOWN )
                    l3->out.hs.len = committed;
                if( l3->out.hs.frag_len == MBEDTLS_MPS_SIZE_UNKNOWN )
                    l3->out.hs.frag_len = committed;
            }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

            /* We didn't know the handshake message length
             * in advance and hence couldn't write the header
             * during mps_l3_write_handshake().
             * Write the header now. */
            res = l3_check_write_hs_hdr( l3 );
            if( res != 0 )
                RETURN( res );

            res = mbedtls_writer_commit_partial( l3->out.raw_out,
                                                 uncommitted );
            if( res != 0 )
                RETURN( res );

            l3->out.hs.state = MPS_L3_HS_NONE;
            break;

        case MBEDTLS_MPS_MSG_ALERT:
            TRACE( trace_comment, "alert message" );
            res = mbedtls_writer_commit( l3->out.raw_out );
            if( res != 0 )
                RETURN( res );

            break;

        case MBEDTLS_MPS_MSG_CCS:
            TRACE( trace_comment, "CCS message" );
            res = mbedtls_writer_commit( l3->out.raw_out );
            if( res != 0 )
                RETURN( res );

            break;

        case MBEDTLS_MPS_MSG_APP:
            /* The application data is directly written through
             * the writer. */
            TRACE( trace_comment, "application data message" );
            break;

        default:
            RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    /* Remove reference to the raw writer borrowed from Layer 2
     * before calling mps_l2_write_done(), which invalidates it. */
    l3->out.raw_out = NULL;

    res = mps_l2_write_done( l3->conf.l2 );
    if( res != 0 )
        RETURN( res );

    TRACE( trace_comment, "Done" );
    l3->out.state = MBEDTLS_MPS_MSG_NONE;
    RETURN( 0 );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
static int l3_write_hs_header_tls( mps_l3_hs_out_internal *hs )

{
    unsigned char *buf = hs->hdr;

    size_t const tls_hs_hdr_len = 4;

    size_t const tls_hs_type_offset   = 0;
    size_t const tls_hs_length_offset = 1;

    /*

      From RFC 5246 (TLS 1.2):

      enum {
          ..., (255)
      } HandshakeType;

      struct {
          HandshakeType msg_type;
          uint24 length;
          select (HandshakeType) {
              case hello_request:       HelloRequest;
              case client_hello:        ClientHello;
              case server_hello:        ServerHello;
              case certificate:         Certificate;
              case server_key_exchange: ServerKeyExchange;
              case certificate_request: CertificateRequest;
              case server_hello_done:   ServerHelloDone;
              case certificate_verify:  CertificateVerify;
              case client_key_exchange: ClientKeyExchange;
              case finished:            Finished;
          } body;
      } Handshake;

    */

    TRACE_INIT( "l3_write_hs_hdr_tls, type %u, len %u",
           (unsigned) hs->type, (unsigned) hs->len );

    if( buf == NULL || hs->hdr_len != tls_hs_hdr_len )
    {
        TRACE( trace_error, "Buffer to hold handshake header is of wrong size: Expected %u, have %u",
               (unsigned) tls_hs_hdr_len, (unsigned) hs->hdr_len );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    MPS_L3_WRITE_UINT8_LE ( buf + tls_hs_type_offset,   &hs->type );
    MPS_L3_WRITE_UINT24_LE( buf + tls_hs_length_offset, &hs->len  );

    RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
static int l3_write_hs_header_dtls( mps_l3_hs_out_internal *hs )

{
    unsigned char *buf = hs->hdr;

    size_t const dtls_hs_hdr_len         = 13;
    size_t const dtls_hs_type_offset     = 0;
    size_t const dtls_hs_len_offset      = 1;
    size_t const dtls_hs_seq_offset      = 4;
    size_t const dtls_hs_frag_off_offset = 7;
    size_t const dtls_hs_frag_len_offset = 10;

    /*
     *
     * From RFC 6347 (DTLS 1.2):
     *
     *   struct {
     *     HandshakeType msg_type;
     *     uint24 length;
     *     uint16 message_seq;                               // New field
     *     uint24 fragment_offset;                           // New field
     *     uint24 fragment_length;                           // New field
     *     select (HandshakeType) {
     *       case hello_request: HelloRequest;
     *       case client_hello:  ClientHello;
     *       case hello_verify_request: HelloVerifyRequest;  // New type
     *       case server_hello:  ServerHello;
     *       case certificate:Certificate;
     *       case server_key_exchange: ServerKeyExchange;
     *       case certificate_request: CertificateRequest;
     *       case server_hello_done:ServerHelloDone;
     *       case certificate_verify:  CertificateVerify;
     *       case client_key_exchange: ClientKeyExchange;
     *       case finished: Finished;
     *     } body;
     *   } Handshake;
     *
     */

    TRACE_INIT( "l3_write_hs_hdr_tls, type %u, len %u",
           (unsigned) hs->type, (unsigned) hs->len );

    if( buf == NULL || hs->hdr_len != dtls_hs_hdr_len )
    {
        TRACE( trace_error, "Buffer to hold DTLS handshake header is of wrong size." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    MPS_WRITE_UINT8_LE ( &hs->type,        buf + dtls_hs_type_offset     );
    MPS_WRITE_UINT24_LE( &hs->len,         buf + dtls_hs_len_offset      );
    MPS_WRITE_UINT16_LE( &hs->seq_nr,      buf + dtls_hs_seq_offset      );
    MPS_WRITE_UINT24_LE( &hs->frag_offset, buf + dtls_hs_frag_off_offset );
    MPS_WRITE_UINT24_LE( &hs->frag_len,    buf + dtls_hs_frag_len_offset );

    TRACE( trace_comment, "Wrote DTLS handshake header" );
    TRACE( trace_comment, "* Type:        %u", (unsigned) hs->type        );
    TRACE( trace_comment, "* Length:      %u", (unsigned) hs->len         );
    TRACE( trace_comment, "* Sequence Nr: %u", (unsigned) hs->seq_nr      );
    TRACE( trace_comment, "* Frag Offset: %u", (unsigned) hs->frag_offset );
    TRACE( trace_comment, "* Frag Length: %u", (unsigned) hs->frag_len    );

    RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_DTLS */

/*
 * Flush Layer 2 if requested.
 */
static int l3_check_clear( mps_l3 *l3 )
{
    int res;
    TRACE_INIT( "l3_check_clear" );
    if( l3->out.clearing == 0 )
        RETURN( 0 );

    res = mps_l2_write_flush( l3->conf.l2 );
    if( res != 0 )
        RETURN( res );

    l3->out.clearing = 0;
    RETURN( 0 );
}

/*
 * Request a writer for the respective epoch and content type from Layer 2.
 *
 * This also keeps track of pursuing ongoing but not yet finished flush calls.
 */
static int l3_prepare_write( mps_l3 *l3, mbedtls_mps_msg_type_t port,
                             mbedtls_mps_epoch_id epoch )
{
    int res;
    mps_l2_out out;
    TRACE_INIT( "l3_prepare_write" );
    TRACE( trace_comment, "* Type:  %u", (unsigned) port );
    TRACE( trace_comment, "* Epoch: %u", (unsigned) epoch );

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( l3->out.state != MBEDTLS_MPS_MSG_NONE )
    {
        TRACE( trace_error, "Unexpected state" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

#if !defined(MPS_L3_ALLOW_INTERLEAVED_SENDING)
    if( l3->out.hs.state == MPS_L3_HS_PAUSED && port != MBEDTLS_MPS_MSG_HS )
    {
        TRACE( trace_error, "Interleaving of outgoing messages is disabled." );
        RETURN( MPS_ERR_NO_INTERLEAVING );
    }
#endif

    res = l3_check_clear( l3 );
    if( res != 0 )
        RETURN( res );

    out.epoch = epoch;
    out.type = port;
    res = mps_l2_write_start( l3->conf.l2, &out );
    if( res != 0 )
        RETURN( res );

    l3->out.raw_out = out.wr;
    l3->out.state   = port;
    RETURN( 0 );
}

#endif /* MBEDTLS_MPS_SEPARATE_LAYERS) ||
          MBEDTLS_MPS_TOP_TRANSLATION_UNIT */
