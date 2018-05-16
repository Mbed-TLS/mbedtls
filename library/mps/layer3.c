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

static int trace_id = TRACE_ID_LAYER_3;

#include <stdlib.h>

/*
 * Forward declarations for some internal functions
 */

/* Reading-related */
static int l3_parse_hs_header( uint8_t mode, mbedtls_reader *rd,
                               mps_l3_hs_in_internal *in );
static int l3_parse_hs_header_tls( mbedtls_reader *rd,
                                   mps_l3_hs_in_internal *in );
static int l3_parse_hs_header_dtls( mbedtls_reader *rd,
                                    mps_l3_hs_in_internal *in );
static int l3_parse_alert( mbedtls_reader *rd,
                           mps_l3_alert_in_internal *alert );
static int l3_parse_ccs( mbedtls_reader *rd );

/* Writing-related */
static int l3_prepare_write( mps_l3 *l3, mbedtls_mps_msg_type_t type,
                             mbedtls_mps_epoch_id epoch );
static int l3_check_clear( mps_l3 *l3 );
static int l3_write_hs_header_tls( unsigned char *buf,
                                   size_t buflen,
                                   mps_hs_type type,
                                   uint32_t total_size );

/*
 * Constants and sizes from the [D]TLS standard
 */

#define MPS_TLS_HS_HDR_SIZE 4
#define MPS_TLS_ALERT_SIZE  2
#define MPS_TLS_CCS_SIZE    1

#define MPS_TLS_CCS_VALUE   1

/*
 * Internal parsing/writing macros
 */

#define MPS_L3_READ_UINT24_BE( dst, src )                               \
    do                                                                  \
    {                                                                   \
        *(dst) =                                                        \
            ( (src)[0] << 16 ) +                                        \
            ( (src)[1] <<  8 ) +                                        \
            ( (src)[2] <<  0 );                                         \
    } while( 0 )

#define MPS_L3_READ_UINT8_BE( dst, src )                                \
    do                                                                  \
    {                                                                   \
        *(dst) = (src)[0];                                              \
    } while( 0 )

#define MPS_L3_WRITE_UINT24_BE( dst, src )                              \
    do                                                                  \
    {                                                                   \
        (dst)[0] = ( (src) >> 16 ) & 0xFF;                              \
        (dst)[1] = ( (src) >>  8 ) & 0xFF;                              \
        (dst)[2] = ( (src) >>  0 ) & 0xFF;                              \
    } while( 0 )

#define MPS_L3_WRITE_UINT8_BE( dst, src )                                    \
    do                                                                  \
    {                                                                   \
        (dst)[0] = (src) & 0xFF;                                        \
    } while( 0 )


/*
 * Init & Free API
 */

int mps_l3_init( mps_l3 *l3, mps_l2 *l2, uint8_t mode )
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

    /* 1 */
    if( l3->in.state != MBEDTLS_MPS_MSG_NONE )
        RETURN( l3->in.state );

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

            /* TLS versions prior to TLS 1.3 allow alert messages
             * to span two records. Catch this corner case here.
             *
             * TODO: Add a preprocessor configuration option
             *       controlling the support for this weird
             *       fragmentation, and guard this check accordingly.
             *
             * TODO: For DTLS, this must not be tolerated, either.
             */
            res = l3_parse_alert( in.rd, &l3->in.alert );
            if( res == MBEDTLS_ERR_READER_OUT_OF_DATA )
            {
                TRACE( trace_comment, "Not enough data available in record to read alert message" );
                res = mps_l2_read_done( l3->conf.l2 );
                if( res != 0 )
                    RETURN( res );
                RETURN( MPS_ERR_WANT_READ );
            }
            else if( res != 0 )
                RETURN( res );

            break;

        case MBEDTLS_MPS_MSG_CCS:
            TRACE( trace_comment, "-> CCS message" );

            res = l3_parse_ccs( in.rd );
            if( res != 0 )
                RETURN( res );
            break;

        case MBEDTLS_MPS_MSG_ACK:
            /* TODO: Implement */
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

                    /* Parse handshake header. */

                    /* TLS versions prior to TLS 1.3 allow the handshake header
                     * to span multiple records. Catch this corner case here.
                     *
                     *  TODO: Add a preprocessor configuration option
                     *        controlling the support for this weird
                     *        fragmentation, and guard this check accordingly.
                     *
                     *  TODO: For DTLS, this must not be tolerated, either.
                     */
                    res = l3_parse_hs_header( l3->conf.mode, in.rd,
                                              &l3->in.hs );
                    if( res == MBEDTLS_ERR_READER_OUT_OF_DATA )
                    {
                        TRACE( trace_comment, "Not enough data available in record to read handshake header" );
                        res = mps_l2_read_done( l3->conf.l2 );
                        if( res != 0 )
                            RETURN( res );
                        RETURN( MPS_ERR_WANT_READ );
                    }
                    else if( res != 0 )
                        RETURN( res );

                    /* Setup the extended reader keeping track of the
                     * global message bounds. */
                    TRACE( trace_comment, "Setup extended reader for handshake message" );
                    res = mbedtls_reader_init_ext( &l3->in.hs.rd_ext, l3->in.hs.len );
                    if( res != 0 )
                        RETURN( res );

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
        case MBEDTLS_MPS_MSG_NONE:
            RETURN( MPS_ERR_UNEXPECTED_OPERATION );

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
            res = mbedtls_reader_free_ext( &l3->in.hs.rd_ext );
            if( res != 0 )
                RETURN( res );

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

/* Pause the processing of an incoming handshake message. */
int mps_l3_read_pause_handshake( mps_l3 *l3 )
{
    int res;
    TRACE_INIT( "mps_l3_read_pause_handshake" );

    /* See mps_l3_read() for the general description
     * of how the implementation uses extended readers
     * to handle pausing of handshake messages. */

    if( l3->in.state != MBEDTLS_MPS_MSG_HS )
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    if( l3->in.hs.state != MPS_L3_HS_ACTIVE )
        RETURN( MPS_ERR_INTERNAL_ERROR );

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

/*
 * Record content type specific parsing functions.
 */

/* Handshake */

static int l3_parse_hs_header( uint8_t mode, mbedtls_reader *rd,
                               mps_l3_hs_in_internal *in )
{
    switch( mode )
    {
        case MPS_L3_MODE_STREAM:
            return( l3_parse_hs_header_tls( rd, in ) );
        case MPS_L3_MODE_DATAGRAM:
            return( l3_parse_hs_header_dtls( rd, in ) );
        default:
            return( MPS_ERR_INTERNAL_ERROR );
    }
}

static int l3_parse_hs_header_tls( mbedtls_reader *rd,
                                   mps_l3_hs_in_internal *in )
{
    int res;
    unsigned char *tmp;
    TRACE_INIT( "parse_hs_header_tls" );

    /*

      From RFC 5246 (TLS 1.2):

      enum {
          hello_request(0), client_hello(1), server_hello(2),
          certificate(11), server_key_exchange (12),
          certificate_request(13), server_hello_done(14),
          certificate_verify(15), client_key_exchange(16),
          finished(20), (255)
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

    /* This call might fail for handshake headers spanning
     * multiple records. This will be caught in up in the
     * call chain, and Layer 2 will remember the request
     * in this case and ensure it can be satisfied the next
     * time it signals incoming data of handshake content type.
     * We therefore don't need to save state here. */
    res = mbedtls_reader_get( rd, MPS_TLS_HS_HDR_SIZE, &tmp, NULL );
    if( res != 0 )
        RETURN( res );

    MPS_L3_READ_UINT8_BE ( &in->type, tmp + 0 );
    MPS_L3_READ_UINT24_BE( &in->len,  tmp + 1 );

    res = mbedtls_reader_commit( rd );
    if( res != 0 )
        RETURN( res );

    TRACE( trace_comment, "Parsed handshake header" );
    TRACE( trace_comment, "* Type:   %u", (unsigned) in->type);
    TRACE( trace_comment, "* Length: %u", (unsigned) in->len);
    RETURN( 0 );
}

static int l3_parse_hs_header_dtls( mbedtls_reader *rd,
                                    mps_l3_hs_in_internal *in )
{
    ((void) rd);
    ((void) in);
    /* TODO: Implement */
    return( MPS_ERR_UNSUPPORTED_FEATURE );
}

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

    MPS_L3_READ_UINT8_BE ( &alert->level, tmp + 0 );
    MPS_L3_READ_UINT8_BE ( &alert->type,  tmp + 1 );

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

    MPS_L3_READ_UINT8_BE( &val, tmp + 0 );

    res = mbedtls_reader_commit( rd );
    if( res != 0 )
        RETURN( res );

    if( val != MPS_TLS_CCS_VALUE )
        RETURN( MPS_ERR_BAD_CCS );

    TRACE( trace_comment, "Parsed alert message" );
    TRACE( trace_comment, " * Value: %u", MPS_TLS_CCS_VALUE );
    RETURN( 0 );
}

/*
 * API for retrieving read-handles for various content types.
 */

int mps_l3_read_handshake( mps_l3 *l3, mps_l3_handshake_in *hs )
{
    TRACE_INIT( "mps_l3_read_handshake" );
    if( l3->in.state != MBEDTLS_MPS_MSG_HS )
    {
        TRACE( trace_comment, "No handshake message opened" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }

    if( l3->in.hs.state != MPS_L3_HS_ACTIVE )
        RETURN( MPS_ERR_INTERNAL_ERROR );

    hs->epoch  = l3->in.epoch;
    hs->len    = l3->in.hs.len;
    hs->type   = l3->in.hs.type;
    hs->rd_ext = &l3->in.hs.rd_ext;
    RETURN( 0 );
}

int mps_l3_read_app( mps_l3 *l3, mps_l3_app_in *app )
{
    TRACE_INIT( "mps_l3_read_app" );
    if( l3->in.state != MBEDTLS_MPS_MSG_APP )
    {
        TRACE( trace_comment, "No application data message opened" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }

    app->epoch = l3->in.epoch;
    app->rd = l3->in.raw_in;
    RETURN( 0 );
}

int mps_l3_read_alert( mps_l3 *l3, mps_l3_alert_in *alert )
{
    TRACE_INIT( "mps_l3_read_alert" );
    if( l3->in.state != MBEDTLS_MPS_MSG_ALERT )
    {
        TRACE( trace_comment, "No alert message opened" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }

    alert->epoch = l3->in.epoch;
    alert->type  = l3->in.alert.type;
    alert->level = l3->in.alert.level;
    RETURN( 0 );
}

int mps_l3_read_ccs( mps_l3 *l3, mps_l3_ccs_in *ccs )
{
    TRACE_INIT( "mps_l3_read_ccs" );
    if( l3->in.state != MBEDTLS_MPS_MSG_CCS )
    {
        TRACE( trace_comment, "No CCSmessage opened" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }

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

int mps_l3_write_handshake( mps_l3 *l3, mps_l3_handshake_out *out )
{
    int res;
    mbedtls_mps_epoch_id epoch = out->epoch;
    uint8_t type = out->type;
    int32_t len = out->len;

    TRACE_INIT( "l3_write_handshake" );
    TRACE( trace_comment, "Parameters: " );
    TRACE( trace_comment, "* Epoch:  %u", (unsigned) epoch );
    TRACE( trace_comment, "* Type:   %u", (unsigned) type );
    TRACE( trace_comment, "* Length: %u", (unsigned) len );

    /*
     * See the documentation of mps_l3_read() for a description
     * of how extended readers are used for handling TLS
     * fragmentation of handshake messages; the case of writers
     * is analogous.
     */

    if( l3->out.hs.state == MPS_L3_HS_PAUSED &&
        ( l3->out.hs.epoch != epoch ||
          l3->out.hs.type  != type  ||
          l3->out.hs.len   != len ) )
    {
        RETURN( MPS_ERR_INCONSISTENT_ARGS );
    }

    res = l3_prepare_write( l3, MBEDTLS_MPS_MSG_HS, epoch );
    if( res != 0 )
        RETURN( res );

    if( l3->out.hs.state == MPS_L3_HS_NONE )
    {
        l3->out.hs.epoch = epoch;
        l3->out.hs.len   = len;
        l3->out.hs.type  = type;

        l3->out.hs.hdr_len = MPS_TLS_HS_HDR_SIZE;
        res = mbedtls_writer_get( l3->out.raw_out,
                                  MPS_TLS_HS_HDR_SIZE,
                                  &l3->out.hs.hdr, NULL );
        /* It might happen that we're at the end of a record
         * and there's not enough space left to write the
         * handshake header. In this case, abort the write
         * and make sure Layer 2 is flushed before we attempt
         * again. */
        if( res == MBEDTLS_ERR_WRITER_OUT_OF_DATA )
        {
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

        /* Immediately write and commit the handshake header
         * if the length is already known. If the length is
         * not yet known, postpone it. */
        if( len != MPS_L3_LENGTH_UNKNOWN )
        {
            TRACE( trace_comment, "Handshake length provided: %u",
                   l3->out.hs.len );

            res = l3_write_hs_header_tls( l3->out.hs.hdr,
                                          l3->out.hs.hdr_len,
                                          l3->out.hs.type,
                                          l3->out.hs.len );
            if( res != 0 )
                RETURN( res );

            l3->out.hs.hdr = NULL;
            l3->out.hs.hdr_len = 0;
        }
        else
        {
            TRACE( trace_comment, "Unspecified handshake length" );
        }

        /* Note: Even if we do not know the total handshake length in
         *       advance, we do not yet commit the handshake header.
         *       The reason is that it might happen that the user finds
         *       that there's not enough space available to make any
         *       progress, and in this case we should abort the write
         *       instead of writing an empty handshake fragment. */

        TRACE( trace_comment, "Setup extended writer for handshake message" );
        /* TODO: If `len` is UNKNOWN this is casted to -1u here,
         *       which is OK but fragile. */
        res = mbedtls_writer_init_ext( &l3->out.hs.wr_ext, len );
        if( res != 0 )
            RETURN( res );
    }

    TRACE( trace_comment, "Bind raw writer to extended writer" );
    res = mbedtls_writer_attach( &l3->out.hs.wr_ext, l3->out.raw_out,
                                 len != MPS_L3_LENGTH_UNKNOWN
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
        /* If a writer can be opened, at least 1 byte must be available. */
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }
    else if( res != 0 )
        RETURN( res );

    *tmp = MPS_TLS_CCS_VALUE;
    RETURN( 0 );
}

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

    if( l3->out.state  != MBEDTLS_MPS_MSG_HS ||
        l3->out.hs.len == MPS_L3_LENGTH_UNKNOWN )
    {
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }

    if( l3->out.hs.state != MPS_L3_HS_ACTIVE )
        RETURN( MPS_ERR_INTERNAL_ERROR );

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

/* Abort the writing of a handshake message. */
int mps_l3_abort_handshake( mps_l3 *l3 )
{
    int res;
    size_t committed;
     TRACE_INIT( "mps_l3_abort_handshake" );

    if( l3->out.state  != MBEDTLS_MPS_MSG_HS )
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    if( l3->out.hs.state != MPS_L3_HS_ACTIVE )
        RETURN( MPS_ERR_INTERNAL_ERROR );

    /* Remove reference to raw writer from writer. */
    res = mbedtls_writer_detach( &l3->out.hs.wr_ext,
                                 &committed,
                                 NULL );
    if( res != 0 )
        RETURN( res );

    /* Reset extended writer. */
    res = mbedtls_writer_free_ext( &l3->out.hs.wr_ext );
    if( res != 0 )
        RETURN( res );

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

    TRACE_INIT( "mps_l3_dispatch" );

    switch( l3->out.state )
    {
        case MBEDTLS_MPS_MSG_NONE:
            RETURN( MPS_ERR_UNEXPECTED_OPERATION );

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
            res = mbedtls_writer_free_ext( &l3->out.hs.wr_ext );
            if( res != 0 )
                RETURN( res );

            if( l3->out.hs.len == MPS_L3_LENGTH_UNKNOWN )
            {
                /* We didn't know the handshake message length
                 * in advance and hence couldn't write the header
                 * during mps_l3_write_handshake().
                 * Write the header now. */

                l3->out.hs.len = committed;
                res = l3_write_hs_header_tls( l3->out.hs.hdr,
                                              l3->out.hs.hdr_len,
                                              l3->out.hs.type,
                                              l3->out.hs.len );
                if( res != 0 )
                    RETURN( res );

                l3->out.hs.hdr = NULL;
                l3->out.hs.hdr_len = 0;
            }

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

    l3->out.state = MBEDTLS_MPS_MSG_NONE;
    RETURN( 0 );
}

static int l3_write_hs_header_tls( unsigned char *buf,
                                   size_t buf_len,
                                   mps_hs_type type,
                                   uint32_t total_size )

{
    TRACE_INIT( "l3_write_hs_hdr_tls, type %u, len %u",
           (unsigned) type, (unsigned) total_size );

    if( buf_len != MPS_TLS_HS_HDR_SIZE )
    {
        TRACE( trace_error, "Buffer to hold handshake header is of wrong size." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    MPS_L3_WRITE_UINT8_BE ( buf + 0, type       );
    MPS_L3_WRITE_UINT24_BE( buf + 1, total_size );

    RETURN( 0 );
}

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

    if( l3->out.state != MBEDTLS_MPS_MSG_NONE )
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );

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
