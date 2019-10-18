/*
 *  Message Processing Stack, (Layer 4) implementation
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

#include "../../include/mbedtls/mps/mps.h"
#include "../../include/mbedtls/mps/trace.h"
#include "../../include/mbedtls/mps/common.h"

#include "../../include/mbedtls/platform_util.h"

/* Embed all other MPS translation units into here
 * for release builds on constrained systems to allow
 * inlining and hence significantly smaller code size. */
#if !defined(MBEDTLS_MPS_SEPARATE_LAYERS)
#define MBEDTLS_MPS_TOP_TRANSLATION_UNIT
#include "reader.c"
#include "writer.c"
#include "layer1.c"
#include "layer2.c"
#include "layer3.c"
#endif /* MBEDTLS_MPS_SEPARATE_LAYERS */

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free      free
#endif

#if defined(MBEDTLS_MPS_TRACE)
static int trace_id = TRACE_BIT_LAYER_4;
#endif /* MBEDTLS_MPS_TRACE */

/*
 * Error state handling
 */

/* Convenience macro for the failure handling
 * within internal functions. */
#define MPS_INTERNAL_FAILURE_HANDLER                    \
    exit:                                               \
    RETURN( ret );

/* Convenience macro for the failure handling
 * within functions at MPS-API boundary, which
 * should block the MPS on most errors. */
#define MPS_API_BOUNDARY_FAILURE_HANDLER        \
    exit:                                       \
    mps_generic_failure_handler( mps, ret );    \
    RETURN( ret );                              \

/* Check if the MPS will serve read resp. write API calls.
 * It will e.g. reject this if it is blocked or if the user
 * has already sent/received a closure notification.
 * See also ::mbedtls_mps_connection_state_t.                          */
MBEDTLS_MPS_STATIC int mps_check_read ( mbedtls_mps const *mps );
MBEDTLS_MPS_STATIC int mps_check_write( mbedtls_mps const *mps );

/* Block the MPS, i.e. forbid any further operations.                  */
MBEDTLS_MPS_STATIC void mps_block( mbedtls_mps *mps );

/* Handlers for incoming closure notifications.                        */
MBEDTLS_MPS_STATIC void mps_close_notification_received( mbedtls_mps *mps );

/* Handler for incoming fatal alert.                                   */
MBEDTLS_MPS_STATIC void mps_fatal_alert_received(
    mbedtls_mps *mps, mbedtls_mps_alert_t alert_type );

/* Failure handler at the end of any MPS API function.
 * This checks the return code and potentially blocks the MPS.         */
MBEDTLS_MPS_STATIC void mps_generic_failure_handler(
    mbedtls_mps *mps, int ret );

/* Attempts to deliver a pending alert to the underlying Layer 3.      */
MBEDTLS_MPS_STATIC int mps_handle_pending_alert( mbedtls_mps *mps );

/*
 * Internal flags used to indicate usage of epochs
 */

#define MPS_READ_ACTIVE                   0
#define MPS_READ_RETRANSMISSION_DETECTION 1

#define MPS_WRITE_ACTIVE         0
#define MPS_WRITE_RETRANSMISSION 1

/*
 * Read/Write preparations
 *
 * Check if the handshake state allows reading/writing,
 * and perform any necessary preparations such as finishing
 * a retransmission.
 */

#define MPS_PAUSED_HS_FORBIDDEN 0
#define MPS_PAUSED_HS_ALLOWED   1

MBEDTLS_MPS_STATIC int mps_prepare_read( mbedtls_mps *mps );
MBEDTLS_MPS_STATIC int mps_prepare_write( mbedtls_mps *mps,
                                          uint8_t allow_paused_hs );
MBEDTLS_MPS_STATIC int mps_clear_pending( mbedtls_mps *mps,
                                          uint8_t allow_paused_hs );

#define MBEDTLS_MPS_ALERT_LEVEL_WARNING         1
#define MBEDTLS_MPS_ALERT_LEVEL_FATAL           2
#define MBEDTLS_MPS_ALERT_MSG_CLOSE_NOTIFY      0

#define MPS_CHK( exp )                            \
    do                                            \
    {                                             \
        if( ( ret = ( exp ) ) < 0 )               \
        {                                         \
            goto exit;                            \
        }                                         \
    } while( 0 )


#if defined(MBEDTLS_MPS_PROTO_DTLS)
/*
 * Outgoing DTLS handshake message fragmentation.
 *
 * This is used both for serving a user write-request
 * and for outgoing flight retransmission.
 */

/*! The type of an outgoing handshake message.
 *
 *  Possible values are:
 *  - #MPS_DTLS_FRAG_OUT_START_USE_L3
 *    In this type, the message writer operates on a buffer obtained from
 *    Layer 3, and only resorts to a separately allocated queue if
 *    necessary and available.
 *    This type is used for messages which don't need to be backed
 *    up for the purpose of retransmission (e.g. because a retransmission
 *    callback is registered for them); for those, it is desirable to work
 *    in place on the buffer(s) obtained from Layer 3 as much as possible.
 *
 *  - #MPS_DTLS_FRAG_OUT_START_QUEUE_ONLY
 *    In this type, the writer operates on a separate queue only. Gradual
 *    copying and dispatching to fragment buffers from Layer 3 happens only
 *    after the message has been fully written to the queue.
 *    This type is used to write messages that need to be backed up for
 *    retransmission; in this case, the backup buffer functions as the
 *    queue, so that the user writing the message directly writes it
 *    it into the backup buffer, avoiding an unnecessary copy.
 *
 *  - #MPS_DTLS_FRAG_OUT_START_FROM_QUEUE
 *    This type is used if an entire message is already present
 *    in a contiguous buffer and solely needs to be dispatched
 *    to Layer 3, without any prior interaction with the user.
 *    In this case, \c queue specifies the message contents.
 *    This type is used for retransmission of messages via raw backups.
 */

typedef uint8_t mps_dtls_outgoing_hs_msg_mode;
#define MPS_DTLS_FRAG_OUT_START_USE_L3     ( (mps_dtls_outgoing_hs_msg_mode) 0 )
#define MPS_DTLS_FRAG_OUT_START_QUEUE_ONLY ( (mps_dtls_outgoing_hs_msg_mode) 1 )
#define MPS_DTLS_FRAG_OUT_START_FROM_QUEUE ( (mps_dtls_outgoing_hs_msg_mode) 2 )

/*
 * The API between outgoing fragmentation and the rest of the MPS code.
*/

/*! Start a new outgoing handshake message.
 *
 *  - The queue to be used for the underlying writer is provided in \c queue.
 *  - The write-mode flag \c mode indicates if the handshake data is already
 *    available and how Layer 3 should be involved when writing the message.
 *    See the documentation of ::mps_dtls_outgoing_hs_msg_mode for more.
 *
 *  This does not interface with the underlying Layer 3 instance,
 *  and any error it returns is fatal.
 *
 *  On success, the state of the internal structure representing
 *  the outgoing handshake message depends on \p mode as follows:
 *  - If \p mode is #MPS_DTLS_FRAG_OUT_START_USE_L3, the outgoing
 *    handshake message structure is in state #MBEDTLS_MPS_HS_PAUSED.
 *  - If \p mode is #MPS_DTLS_FRAG_OUT_START_QUEUE_ONLY, the outgoing
 *    handshake message structure is in state #MBEDTLS_MPS_HS_ACTIVE.
 *  - If \p mode is #MPS_DTLS_FRAG_OUT_START_FROM_QUEUE, the outgoing
 *    handshake message structure is in state #MBEDTLS_MPS_HS_PAUSED.
 */
MBEDTLS_MPS_STATIC int mps_dtls_frag_out_start(
                                    mbedtls_mps_handshake_out_internal *hs,
                                    unsigned char *queue,
                                    mbedtls_mps_size_t queue_len,
                                    mbedtls_mps_msg_metadata *metadata,
                                    mps_dtls_outgoing_hs_msg_mode mode );

/*! Move the outgoing handshake message from state #MBEDTLS_MPS_HS_PAUSED
 *  to state #MBEDTLS_MPS_HS_ACTIVE or #MBEDTLS_MPS_HS_NONE by dispatching
 *  queued content through Layer 3 (if any).
 *
 *  If there is no outgoing handshake message in state #MBEDTLS_MPS_HS_PAUSED,
 *  this function returns immediately.
 *
 *  This function might fail with #MBEDTLS_MPS_WANT_READ.
 *
 *  If this function succeeds, the outgoing handshake message is either
 *  in state #MBEDTLS_MPS_HS_NONE (if it was in state #MBEDTLS_MPS_HS_NONE
 *  beforehand, or if it was in state #MBEDTLS_MPS_HS_PAUSED with the entire
 *  message content queued) or #MBEDTLS_MPS_HS_ACTIVE (if it was in state
 *  #MBEDTLS_MPS_HS_ACTIVE beforehand, or if it was in state
 *  #MBEDTLS_MPS_HS_PAUSED and the message hasn't been fully written yet).
 */
MBEDTLS_MPS_STATIC int mps_dtls_frag_out_unpause( mbedtls_mps *mps,
                                      uint8_t allow_active_hs );

/*  The combination of mps_dtls_frag_out_close() and
 *  mps_dtls_frag_out_dispatch() moves the outgoing handshake
 *  message structure from state #MBEDTLS_MPS_HS_ACTIVE to state
 *  #MBEDTLS_MPS_HS_NONE or #MBEDTLS_MPS_HS_PAUSED.
 *
 *  mps_dtls_frag_out_close() revokes the output buffer
 *  from the user-facing writer.
 *
 *  mps_dtls_frag_out_dispatch() dispatches the next
 *  fragment to Layer 3.
 */
MBEDTLS_MPS_STATIC int mps_dtls_frag_out_close( mbedtls_mps *mps );
MBEDTLS_MPS_STATIC int mps_dtls_frag_out_dispatch( mbedtls_mps *mps );

/* TODO: Document */
MBEDTLS_MPS_STATIC int mps_dtls_frag_out_bind( mbedtls_mps *mps );

/*
 * State interface for the retransmission state machine
 */

MBEDTLS_MPS_ALWAYS_INLINE int mps_handshake_state_transition(
    mbedtls_mps *mps,
    mbedtls_mps_flight_state_t old,
    mbedtls_mps_flight_state_t new );

MBEDTLS_MPS_ALWAYS_INLINE mbedtls_mps_flight_state_t
mps_get_handshake_state( mbedtls_mps *mps )
{
    /* NOTE: To RAM, and likely also some code on Thumb, it should
     *       be considered to allocate the retransmission state machine
     *       only when a handshake is active -- in this case, this
     *       function should check whether it's present first, and
     *       return MBEDTLS_MPS_FLIGHT_DONE if not. */
    return( mps->dtls.state );
}

/*
 * Read interface to the retransmission state machine.
 */

MBEDTLS_MPS_STATIC
int mps_retransmission_finish_incoming_message( mbedtls_mps *mps );
MBEDTLS_MPS_STATIC
int mps_retransmission_pause_incoming_message( mbedtls_mps *mps );
MBEDTLS_MPS_STATIC
int mbedtls_mps_retransmission_handle_incoming_fragment( mbedtls_mps *mps );

/*
 * Incoming flight retransmission detection
 */

/* Check whether an incoming handshake message is a
 * retransmission from the previous incoming flight. */
MBEDTLS_MPS_STATIC int mps_retransmit_in_check( mbedtls_mps *mps,
                                    mps_l3_handshake_in *hs );
/* Remember a handshake message in the current incoming flight
 * to be able to detect subsequent retransmissions. */
MBEDTLS_MPS_STATIC int mps_retransmit_in_remember( mbedtls_mps *mps,
                                       mbedtls_mps_handshake_in *hs_in,
                                       uint8_t seq_nr );
/* Initialize the structure used to remember incoming flights. */
MBEDTLS_MPS_STATIC int mps_retransmit_in_init( mbedtls_mps *mps );
/* Free the structure used to remember incoming flights. */
MBEDTLS_MPS_STATIC int mps_retransmit_in_free( mbedtls_mps *mps );
/* Clear memory of last incoming flight. Used when receiving the
 * first message in a new incoming flight, at which point we can
 * remove all memory of the last incoming flight. */
MBEDTLS_MPS_STATIC int mps_retransmit_in_forget( mbedtls_mps *mps );

/* TODO: Document */
MBEDTLS_MPS_STATIC int mps_check_retransmit( mbedtls_mps *mps );

/*
 * Retransmission timer handling
 */

MBEDTLS_MPS_STATIC int mps_retransmission_timer_stop( mbedtls_mps *mps );
MBEDTLS_MPS_STATIC int mps_retransmission_timer_update( mbedtls_mps *mps );
MBEDTLS_MPS_STATIC int mps_retransmission_timer_check( mbedtls_mps *mps );
MBEDTLS_MPS_STATIC int mps_retransmission_timer_increase_timeout(
    mbedtls_mps *mps );

/*
 * Sending of outgoing flights.
 */

MBEDTLS_MPS_STATIC int mps_out_flight_init( mbedtls_mps *mps );
MBEDTLS_MPS_STATIC int mps_out_flight_free( mbedtls_mps *mps );
MBEDTLS_MPS_STATIC int mps_out_flight_msg_start(
    mbedtls_mps *mps, mbedtls_mps_retransmission_handle **handle );
MBEDTLS_MPS_STATIC int mps_out_flight_msg_done( mbedtls_mps *mps );

/*
 * Message retransmission handles
 */

MBEDTLS_MPS_STATIC void mbedtls_mps_retransmission_handle_init(
    mbedtls_mps_retransmission_handle *handle );
MBEDTLS_MPS_STATIC void mbedtls_mps_retransmission_handle_free(
    mbedtls_mps_retransmission_handle *handle );
MBEDTLS_MPS_STATIC int mbedtls_mps_retransmission_handle_resend(
    mbedtls_mps *mps, mbedtls_mps_retransmission_handle *handle );
MBEDTLS_MPS_STATIC int mbedtls_mps_retransmission_handle_resend_empty(
    mbedtls_mps *mps, mbedtls_mps_retransmission_handle *handle );

/*
 * Outgoing flight retransmission
 */

MBEDTLS_MPS_STATIC int mps_retransmit_out( mbedtls_mps *mps );
MBEDTLS_MPS_STATIC int mps_retransmit_out_core( mbedtls_mps *mps,
                                                uint8_t mode );

/*
 * Incoming flight retransmission request
 *
 * (In DTLS 1.0 and 1.2, this is done by resending the last
 *  outgoing flight; in DTLS 1.3, it's done using ACK's.)
 */

MBEDTLS_MPS_STATIC int mps_request_resend( mbedtls_mps *mps );

/*
 * DTLS reassembly and future message buffering
 */

MBEDTLS_MPS_STATIC int mps_reassembly_init( mbedtls_mps *mps );
MBEDTLS_MPS_STATIC int mps_reassembly_free( mbedtls_mps *mps );

MBEDTLS_MPS_STATIC int mps_reassembly_feed( mbedtls_mps *mps, mps_l3_handshake_in *hs );
MBEDTLS_MPS_STATIC int mps_reassembly_get_seq( mbedtls_mps *mps, uint8_t *seq_nr );

MBEDTLS_MPS_STATIC int mps_reassembly_next_msg_complete( mbedtls_mps *mps );

MBEDTLS_MPS_STATIC int mps_reassembly_check( mbedtls_mps *mps );
MBEDTLS_MPS_STATIC int mps_reassembly_read( mbedtls_mps *mps,
                                mbedtls_mps_handshake_in *in );
MBEDTLS_MPS_STATIC int mps_reassembly_done( mbedtls_mps *mps );
MBEDTLS_MPS_STATIC int mps_reassembly_pause( mbedtls_mps *mps );

MBEDTLS_MPS_STATIC int mps_reassembly_forget( mbedtls_mps *mps );

#define MBEDTLS_MPS_RETRANSMISSION_HANDLE_UNFINISHED -1
#define MBEDTLS_MPS_REASSEMBLY_FEED_NEED_MORE        -1

#define MPS_RETRANSMIT_ONLY_EMPTY_FRAGMENTS 0
#define MPS_RETRANSMIT_FULL_FLIGHT          1

#define MPS_INITIAL_HS_SEQ_NR 0

#endif /* MBEDTLS_MPS_PROTO_DTLS */

/*
 * Preparations before a new incoming message can be fetched,
 * or a new outgoing message can be prepared.
 */

MBEDTLS_MPS_STATIC int mps_clear_pending( mbedtls_mps *mps,
                              uint8_t allow_active_hs )
{
    int ret = 0;
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_conf_get_mode( &mps->conf );

    TRACE_INIT( "mps_clear_pending, allow_active_hs %u",
                (unsigned) allow_active_hs );

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        /* If present, dispatch queueing handshake data. */
        MPS_CHK( mps_dtls_frag_out_unpause( mps, allow_active_hs ) );
    }
#else
    ((void) mode);
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    /* Attempt to send any pending alerts. */
    MPS_CHK( mps_handle_pending_alert( mps ) );

    /* Note: Once an alert has been sent, no further write operations are
     *       possible, as the alert was either fatal, or it indicated the
     *       closure of the write side of the connection.
     *       Therefore, we can safely handle pending handshake messages
     *       first before handling the alert. */

    if( mps->out.flush == 1 )
    {
        TRACE( trace_comment, "A flush was requested" );
        MPS_CHK( mps_l3_flush( mps->conf.l3 ) );
        mps->out.flush = 0;
    }

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_prepare_read( mbedtls_mps *mps )
{
    int ret;
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_conf_get_mode( &mps->conf );
    TRACE_INIT( "mps_prepare_read" );

    /* Check that MPS isn't blocked or has its reading side closed. */
    ret = mps_check_read( mps );
    if( ret != 0 )
        RETURN( ret );

    /* Layer 4 forbids reading while writing. */
#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( mps->out.state != MBEDTLS_MPS_MSG_NONE )
    {
        TRACE( trace_error, "Refuse to start reading while writing message." );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
#if defined(MBEDTLS_MPS_STATE_VALIDATION)
        /* Reject read requests when sending flights. */
        if( MBEDTLS_MPS_STATE_EITHER_OR(
                mps_get_handshake_state( mps ),
                MBEDTLS_MPS_FLIGHT_SEND,
                MBEDTLS_MPS_FLIGHT_PREPARE ) )
        {
            TRACE( trace_error, "Refuse read request when sending flights." );
            MPS_CHK( MBEDTLS_ERR_MPS_INTERNAL_ERROR );
        }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

        /* Check if the timer expired, and take appropriate action
         * (e.g. start a retransmission or send a retransmission
         *  request). */
        MPS_CHK( mps_retransmission_timer_check( mps ) );

        /* Check if a retransmission is ongoing (might be one just triggered
         * by the previous call to mps_retransmission_timer_check(), or an
         * earlier one that hasn't yet completed. */
        MPS_CHK( mps_check_retransmit( mps ) );
    }
#else
    ((void) mode);
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    /* If a flush is pending, ensure that all outgoing data
     * gets delivered before allowing the next read request.
     * Do not allow partially sent handshake messages. */
    MPS_CHK( mps_clear_pending( mps, MPS_PAUSED_HS_FORBIDDEN ) );

    /* Note: At this point, we might still have data dispatched but
     *       not yet flushed to the underlying transport, which is
     *       deliberate.
     *
     *       Flushing all dispatched outgoing data on each read would
     *       not be desirable in case an application protocol is used
     *       for which multiple messages can fit into a single DTLS-datagram,
     *       and for which incoming messages might trigger independent
     *       responses. In this case, a peer might loop on reading a
     *       message and writing a response, and it, if space permits,
     *       it is desirable to handle multiple such read-write
     *       with a single incoming/outgoing datagram, which
     *       wouldn't be possible if MPS always flushed outgoing
     *       data before reading.
     *
     *       When switching from sending to receiving state during
     *       a handshake, though, a flush is implicit, so subsequent
     *       reads will only commence once the last outgoing flight
     *       has been fully delivered.
     *
     * TODO: If the I/O buffers are shared, all dispatched data
     *       must be flushed before the next read can commence.
     *       Implement this!
     */

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_prepare_write( mbedtls_mps *mps,
                              uint8_t allow_paused_hs )
{
    int ret = 0;
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_conf_get_mode( &mps->conf );
    TRACE_INIT( "mps_prepare_write" );

    ret = mps_check_write( mps );
    if( ret != 0 )
        RETURN( ret );

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( mps->out.state != MBEDTLS_MPS_MSG_NONE )
    {
        TRACE( trace_error, "Write port %u already open",
               (unsigned) mps->out.state );
        MPS_CHK( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    /* If a flush is pending, ensure that all outgoing data
     * gets delivered before allowing the next write request. */
    MPS_CHK( mps_clear_pending( mps, allow_paused_hs ) );
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        /* Reject send requests when receiving flights.
         * Note that this does not apply to fatal alerts:
         * those are sent through mbedtls_mps_send_fatal()
         * which does not call this function. */
#if defined(MBEDTLS_MPS_STATE_VALIDATION)
        if( MBEDTLS_MPS_FLIGHT_STATE_EITHER_OR(
                mps_get_handshake_state( mps ),
                MBEDTLS_MPS_FLIGHT_AWAIT,
                MBEDTLS_MPS_FLIGHT_RECEIVE ) )
        {
            TRACE( trace_error, "Attempt to send message in an unexpected flight state %u",
                   (unsigned) mps_get_handshake_state( mps ) );
            MPS_CHK( MBEDTLS_ERR_MPS_INTERNAL_ERROR );
        }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

        /* In state #MBEDTLS_MPS_FLIGHT_FINALIZE, check if
         * the timer has expired and we can wrapup the flight-exchange. */
        MPS_CHK( mps_retransmission_timer_check( mps ) );
    }
#else
    ((void) mode);
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    MPS_INTERNAL_FAILURE_HANDLER
}

/*
 * Implementation of error and closure handling.
 */

/* Error/Closure state modifying functions */

/* Block the MPS */
MBEDTLS_MPS_STATIC void mps_block( mbedtls_mps *mps )
{
    mps->state = MBEDTLS_MPS_STATE_BLOCKED;
}

/* Handle an error code from an internal library call. */
MBEDTLS_MPS_STATIC void mps_generic_failure_handler( mbedtls_mps *mps, int ret )
{
    uint8_t idx;
    int whitelist[] = {
        0,
        MPS_ERR_WANT_READ,
        MPS_ERR_WANT_WRITE
    };

    for( idx=0; idx < sizeof( whitelist ) / sizeof( int ); idx++ )
    {
        if( ret == whitelist[idx] )
            return;
    }

    /* Remember error and block MPS. */
    mps->blocking_reason = MBEDTLS_MPS_ERROR_INTERNAL_ERROR;
    mps->blocking_info.err = ret;
    mps_block( mps );
}

/* Send fatal alert and block MPS. */
int mbedtls_mps_send_fatal( mbedtls_mps *mps, mbedtls_mps_alert_t alert_type )
{
    int ret;
    TRACE_INIT( "mbedtls_mps_send_fatal, type %d", alert_type );

    ret = mps_check_write( mps );
    if( ret != 0 )
        RETURN( ret );

    /* Remember the reason for blocking. */
    mps->blocking_reason = MBEDTLS_MPS_ERROR_ALERT_SENT;
    mps->blocking_info.alert = alert_type;

    /* Move to blocked state to ensure that no further operations can be
     * performed even if something goes wrong when sending the alert. */
    mps_block( mps );

    /* Attempt to send alert. */
    TRACE( trace_comment, "Pend fatal alert" );
    mps->alert_pending = 1;
    MPS_CHK( mbedtls_mps_flush( mps ) );

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

/* React to a fatal alert from the peer. */
MBEDTLS_MPS_STATIC void mps_fatal_alert_received( mbedtls_mps *mps,
                                      mbedtls_mps_alert_t alert_type )
{
    switch( mps->state )
    {
        case MBEDTLS_MPS_STATE_OPEN:
        case MBEDTLS_MPS_STATE_READ_ONLY:

            mps->blocking_reason = MBEDTLS_MPS_ERROR_ALERT_RECEIVED;
            mps->blocking_info.alert = alert_type;

            mps_block( mps );
            break;

        default:
            /* This function should not be called if the
             * MPS cannot be used for reading. */
            break;
    }
}

/* React to a close notification from the peer. */
MBEDTLS_MPS_STATIC void mps_close_notification_received( mbedtls_mps *mps )
{
    switch( mps->state )
    {
        case MBEDTLS_MPS_STATE_OPEN:
            mps->state = MBEDTLS_MPS_STATE_WRITE_ONLY;
            break;

        case MBEDTLS_MPS_STATE_READ_ONLY:
            mps->state = MBEDTLS_MPS_STATE_CLOSED;
            break;

        default:
            /* This function should not be called if the
             * MPS cannot be used for reading. */
            break;
    }
}

MBEDTLS_MPS_STATIC int mps_handle_pending_alert( mbedtls_mps *mps )
{
    int ret;
    mps_l3_alert_out alert;
    TRACE_INIT( "mps_handle_pending_alert" );

    if( mps->alert_pending == 0 )
    {
        TRACE( trace_comment, "No alert pending" );
        RETURN( 0 );
    }

    alert.epoch = mps->out_epoch;
    /* This might fail, but we only reset `mps->alert_pending`
     * on success, so in this case we'll retry sending the alert
     * on a subsequent call to mps_flush(). */
    MPS_CHK( mps_l3_write_alert( mps->conf.l3, &alert ) );

    if( MBEDTLS_MPS_STATE_EITHER_OR( mps->state,
                                     MBEDTLS_MPS_STATE_READ_ONLY,
                                     MBEDTLS_MPS_STATE_CLOSED ) )
    {
        TRACE( trace_comment, "Report orderly closure of write-side to peer." );
        *alert.level = MBEDTLS_MPS_ALERT_LEVEL_WARNING;
        *alert.type  = MBEDTLS_MPS_ALERT_MSG_CLOSE_NOTIFY;
    }
    else if( mps->state == MBEDTLS_MPS_STATE_BLOCKED &&
             mps->blocking_reason == MBEDTLS_MPS_ERROR_ALERT_SENT )
    {
        TRACE( trace_comment, "Report fatal alert to peer." );
        *alert.level = MBEDTLS_MPS_ALERT_LEVEL_FATAL;
        *alert.type  = mps->blocking_info.alert;
    }
    else
    {
        /* Should never happen. */
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    MPS_CHK( mps_l3_dispatch( mps->conf.l3 ) );

    mps->alert_pending = 0;
    mps->out.flush = 1;

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

/* Close the write-side of the MPS and inform the peer. */
int mbedtls_mps_close( mbedtls_mps *mps )
{
    int ret;
    TRACE_INIT( "mbedtls_mps_close" );

    switch( mps->state )
    {
        case MBEDTLS_MPS_STATE_OPEN:
            TRACE( trace_comment, "Moving from open to read-only state" );
            mps->state = MBEDTLS_MPS_STATE_READ_ONLY;
            break;

        case MBEDTLS_MPS_STATE_WRITE_ONLY:
            TRACE( trace_comment, "Moving from write-only to closed state" );
            mps->state = MBEDTLS_MPS_STATE_CLOSED;
            break;

        default:
            RETURN( MBEDTLS_ERR_MPS_BLOCKED );
    }

    /* Attempt to send the alert - this works regardless
     * of whether data is still pending to be delivered;
     * in that case, the pending data will be flushed first
     * before writing and dispatching the alert. */
    TRACE( trace_comment, "Pend closure alert" );
    mps->alert_pending = 1;
    MPS_CHK( mbedtls_mps_flush( mps ) );

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

/*
 * Error/Closure state informing functions.
  */

/* Check if the MPS can be used for reading. */
MBEDTLS_MPS_STATIC int mps_check_read( mbedtls_mps const *mps )
{
    TRACE_INIT( "mps_check_read, state %d", mps->state );

    if( MBEDTLS_MPS_STATE_EITHER_OR( mps->state,
                                     MBEDTLS_MPS_STATE_OPEN,
                                     MBEDTLS_MPS_STATE_READ_ONLY ) )
    {
        TRACE( trace_comment, "Reading possible" );
        RETURN( 0 );
    }

    TRACE( trace_error, "Read-side blocked" );
    RETURN( MBEDTLS_ERR_MPS_BLOCKED );
}

/* Check if the MPS can be used for writing. */
MBEDTLS_MPS_STATIC int mps_check_write( mbedtls_mps const *mps )
{
    TRACE_INIT( "mps_check_write, state %d", mps->state );

    if( MBEDTLS_MPS_STATE_EITHER_OR( mps->state,
                                     MBEDTLS_MPS_STATE_OPEN,
                                     MBEDTLS_MPS_STATE_WRITE_ONLY ) )
    {
        TRACE( trace_comment, "Writing possible" );
        RETURN( 0 );
    }

    TRACE( trace_error, "Write-side blocked" );
    RETURN( MBEDTLS_ERR_MPS_BLOCKED );
}

/*
 * MPS maintenance functions.
 */

int mbedtls_mps_init( mbedtls_mps *mps,
                      mps_l3 *l3,
                      uint8_t mode,
                      size_t max_write )
{
    TRACE_INIT( "mbedtls_mps_init" );

    mps->conf.l3   = l3;

#if !defined(MBEDTLS_MPS_CONF_MODE)
    mps->conf.mode = mode;
#else
    ((void) mode);
#if defined(MBEDTLS_MPS_ASSERT)
    if( mode != MBEDTLS_MPS_CONF_MODE )
    {
        TRACE( trace_error, "Protocol passed to mps_l3_init() doesn't match " \
               "hardcoded protocol." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */
#endif /* !MBEDTLS_MPS_CONF_MODE */

#if !defined(MBEDTLS_MPS_CONF_HS_TIMEOUT_MAX)
    mps->conf.hs_timeout_max = 16000;
#endif /* !MBEDTLS_MPS_CONF_HS_TIMEOUT_MAX */

#if !defined(MBEDTLS_MPS_CONF_HS_TIMEOUT_MIN)
    mps->conf.hs_timeout_max = 250;
#endif /* !MBEDTLS_MPS_CONF_HS_TIMEOUT_MIN */

    mps->conf.f_get_timer = NULL;
    mps->conf.f_set_timer = NULL;
    mps->conf.p_timer     = NULL;

    mps->in_epoch  = MBEDTLS_MPS_EPOCH_NONE;
    mps->out_epoch = MBEDTLS_MPS_EPOCH_NONE;

    mps->alert_pending = 0;
    mps->state = MBEDTLS_MPS_STATE_OPEN;
    mps->blocking_reason = MBEDTLS_MPS_ERROR_UNKNOWN;

    mps->in.state  = MBEDTLS_MPS_MSG_NONE;
    mps->in.flags  = 0;
    mps->out.state = MBEDTLS_MPS_MSG_NONE;
    mps->out.flush = 0;

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    mps->dtls.io.out.hs.state  = MBEDTLS_MPS_HS_NONE;
    mps->dtls.state            = MBEDTLS_MPS_FLIGHT_DONE;
    mps->dtls.retransmit_state = MBEDTLS_MPS_RETRANSMIT_NONE;

    mps_out_flight_init( mps );
    mps_retransmit_in_init( mps );
    mps_reassembly_init( mps );

    if( max_write > 0 )
    {
        unsigned char *queue = NULL;
        TRACE( trace_comment, "Allocating L4 writer queue of size %u Bytes",
               (unsigned) max_write );

        queue = calloc( 1, max_write );
        if( queue == NULL )
        {
            TRACE( trace_error, "Failed to allocate L4 writer queue." );
            RETURN( MPS_ERR_ALLOC_FAILED );
        }

        mps->dtls.io.out.hs.queue_len = max_write;
        mps->dtls.io.out.hs.queue     = queue;
    }
#else
    ((void) max_write);
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    RETURN( 0 );
}

int mbedtls_mps_free( mbedtls_mps *mps )
{
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    mps_out_flight_free( mps );
    mps_retransmit_in_free( mps );
    mps_reassembly_free( mps );
    free( mps->dtls.io.out.hs.queue );
#else
    ((void) mps);
#endif /* MBEDTLS_MPS_PROTO_DTLS */
    return( 0 );
}

/*
 * MPS reading functions.
 */

int mbedtls_mps_read( mbedtls_mps *mps )
{
    int ret;
    mbedtls_mps_msg_type_t msg;
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_conf_get_mode( &mps->conf );
    TRACE_INIT( "mbedtls_mps_read" );

    /* Take care of numerous checks that need to be performed
     * before we can fetch a new message:
     * - Check that MPS isn't blocked or closed.
     * - Flush any pending outgoing handshake messages.
     * - Complete any ongoing flight retransmissions or
     *   retransmission requests, or trigger such if the
     *   retransmission timer has fired.
     */
    MPS_CHK( mps_prepare_read( mps ) );

    /* Note: In contrast to many other state checks, we deliberately
     * tolerate calling mps_read() while a message is already open.
     * This is used when it's not clear which handshake message to
     * expect next: In this case, the state coordination function can
     * peek at the next message's content and call the corresonding
     * handler, which in turn doesn't need to know that the message
     * has already been opened and may call mps_read() again instead,
     * like any other handler function for states where the next
     * expected message is unambiguous. */
    if( mps->in.state != MBEDTLS_MPS_MSG_NONE )
    {
        TRACE( trace_comment, "Message of type %d already open",
               mps->in.state );
        RETURN( mps->in.state );
    }

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    /* Check if a future message has been buffered. */
    if( MBEDTLS_MPS_FLIGHT_STATE_EITHER_OR(
            mps_get_handshake_state( mps ),
            MBEDTLS_MPS_FLIGHT_RECVINIT,
            MBEDTLS_MPS_FLIGHT_RECEIVE ) )
    {
        ret = mps_reassembly_check( mps );
        MPS_CHK( ret );
        if( ret == 0 )
        {
            mps->in.state = MBEDTLS_MPS_MSG_HS;
            RETURN( MBEDTLS_MPS_MSG_HS );
        }
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    /* Fetch a new message (fragment) from Layer 3. */
    MPS_CHK( mps_l3_read( mps->conf.l3 ) );

    /* Go through the various message types:
     * - Fatal alerts and (non-fatal) closure notifications are handled here,
     *   while other non-fatal alerts are passed to the user.
     * - For DTLS 1.3, ACK messages are passed to and handled by the
     *   retransmission state machine and are never passed forward to the user.
     * - Handshake message fragments are fed to the
     *   retransmission state machine, which may ...
     *   (1) pass it through if it's an entire handshake message
     *       of expected epoch and sequence number.
     *   (2) trigger retransmission if it's recognized as a
     *       retransmission from an old flight.
     *   (3) fetch the contents and add it to the message reassembler,
     *       in case it's a proper fragment of a handshake message,
     *       and potentially return the fully reassembled message.
     *   (4) buffer it if it's a future message and the retransmission
     *       state machine supports it.
     *   (5) ignore otherwise.
     *   In any case, the retransmission state machine will signal
     *   whether the new fragment leads to a message being deliverable
     *   to the user or not.
     * - Application data messages are always forwarded to the user.
     */

    msg = (unsigned) ret;
    ret = 0;
    switch( msg )
    {
        case MBEDTLS_MPS_MSG_CCS:
        {
            mps_l3_ccs_in ccs_l3;

            TRACE( trace_comment, "ChangeCipherSpec message received from Layer 3." );
            MPS_CHK( mps_l3_read_ccs( mps->conf.l3, &ccs_l3 ) );

            /* For DTLS, Layer 3 might be configured to pass through
             * records on multiple epochs for the purpose of detection
             * of flight retransmissions.
             *
             * CCS messages, however, should always be discarded
             * if they're not secured through the current incoming epoch.
             */

            MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );

            if( ccs_l3.epoch != mps->in_epoch )
            {
                /* The exit handler will retry the read. */
                MPS_CHK( MBEDTLS_ERR_MPS_BAD_EPOCH );
            }

            mps->in.state = MBEDTLS_MPS_MSG_CCS;
            RETURN( MBEDTLS_MPS_MSG_CCS );
        }

        case MBEDTLS_MPS_MSG_ALERT:
        {
            mps_l3_alert_in alert;

            TRACE( trace_comment, "ChangeCipherSpec message received from Layer 3." );
            MPS_CHK( mps_l3_read_alert( mps->conf.l3, &alert ) );

            /* For DTLS, Layer 3 might be configured to pass through
             * records on multiple epochs for the purpose of detection
             * of flight retransmissions.
             *
             * Alert messages, however, should always be discarded
             * if they're not secured through the current incoming epoch.
             */

            MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );

            if( alert.epoch != mps->in_epoch )
            {
                /* The exit handler will retry the read. */
                MPS_CHK( MBEDTLS_ERR_MPS_BAD_EPOCH );
            }

            switch( alert.level )
            {
                case MBEDTLS_MPS_ALERT_LEVEL_FATAL:
                    TRACE( trace_comment, "Alert is fatal of type %d",
                           alert.type );
                    mps_fatal_alert_received( mps, alert.type );
                    RETURN( MBEDTLS_ERR_MPS_FATAL_ALERT_RECEIVED );
                    break;

                case MBEDTLS_MPS_ALERT_LEVEL_WARNING:

                    TRACE( trace_comment, "Alert is a warning of type %d",
                           alert.type );

                    if( alert.type == MBEDTLS_MPS_ALERT_MSG_CLOSE_NOTIFY )
                    {
                        TRACE( trace_comment, "Close notification received" );
                        mps_close_notification_received( mps );
                        RETURN( MBEDTLS_ERR_MPS_CLOSE_NOTIFY );
                    }
                    mps->in.data.alert = alert.type;

                    mps->in.state = MBEDTLS_MPS_MSG_ALERT;
                    RETURN( MBEDTLS_MPS_MSG_ALERT );
                    break;

                default:
                    ret = MBEDTLS_ERR_MPS_INVALID_ALERT;
                    break;
            }

            break;
        }

        case MBEDTLS_MPS_MSG_ACK:
        {
            /* 2. ACK messages (DTLS 1.3)
             * Not yet implemented. */
            MPS_CHK( MPS_ERR_UNSUPPORTED_FEATURE );
            break;
        }

        case MBEDTLS_MPS_MSG_HS:
        {
            TRACE( trace_comment, "Received a handshake (fragment) from Layer 3" );

            /* Pass message fragment to retransmission state machine
             * and check if it leads to a handshake message being ready
             * to be passed to the user.
             *
             * This is trivial for TLS, in which case handshake messages
             * are always forwarded. We keep the call here for uniformity;
             * in TLS-only builds the compiler will be able to inline
             * and optimize it.
             *
             * It is the responsibility of the reassembly module to
             * deal with the distinction between new messages and
             * the continuation of paused ones.
             */
#if defined(MBEDTLS_MPS_PROTO_TLS)
            if( MBEDTLS_MPS_IS_TLS( mode ) )
            {
                /* In TLS, we transparently forward the data from Layer 3. */
                mps->in.state = MBEDTLS_MPS_MSG_HS;
                RETURN( MBEDTLS_MPS_MSG_HS );
            }
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
            if( MBEDTLS_MPS_IS_DTLS( mode ) )
            {
                /* DTLS */
                ret = mbedtls_mps_retransmission_handle_incoming_fragment( mps );
                if( ret == 0 )
                {
                    TRACE( trace_comment, "New handshake message ready to be passed to the user." );

                    mps->in.state = MBEDTLS_MPS_MSG_HS;
                    RETURN( MBEDTLS_MPS_MSG_HS );
                }
                else if( ret == MBEDTLS_ERR_MPS_NO_FORWARD )
                {
                    TRACE( trace_comment, "Handshake message consumed by retransmission state machine." );
                    MPS_CHK( MPS_ERR_WANT_READ );
                }
                MPS_CHK( ret );
            }
#endif /* MBEDTLS_MPS_PROTO_DTLS */
            break;
        }

        case MBEDTLS_MPS_MSG_APP:
        {
            mps_l3_app_in app_l3;
            MPS_CHK( mps_l3_read_app( mps->conf.l3, &app_l3 ) );

            /* For DTLS, Layer 3 might be configured to pass through
             * records on multiple epochs for the purpose of detection
             * of flight retransmissions.
             *
             * Application data, however, should always be discarded
             * if it's not secured through the current incoming epoch.
             */

            if( app_l3.epoch != mps->in_epoch )
            {
                /* The exit handler will retry the read. */
                MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );
                MPS_CHK( MBEDTLS_ERR_MPS_BAD_EPOCH );
            }
            mps->in.data.app = app_l3.rd;

            mps->in.state    = MBEDTLS_MPS_MSG_APP;
            RETURN( MBEDTLS_MPS_MSG_APP );
        }

        default:
            MPS_CHK( MBEDTLS_ERR_MPS_INTERNAL_ERROR );
            break;
    }

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

int mbedtls_mps_read_check( mbedtls_mps const *mps )
{
    int ret;

    ret = mps_check_read( mps );
    if( ret != 0 )
        return( ret );

    return( mps->in.state );
}

int mbedtls_mps_read_handshake( mbedtls_mps *mps,
                                mbedtls_mps_handshake_in *hs )
{
    int ret;
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_conf_get_mode( &mps->conf );
    TRACE_INIT( "mbedtls_mps_read_handshake" );

    ret = mps_check_read( mps );
    if( ret != 0 )
        RETURN( ret );

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( mps->in.state != MBEDTLS_MPS_MSG_HS )
        MPS_CHK( MPS_ERR_UNEXPECTED_OPERATION );
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

#if defined(MBEDTLS_MPS_PROTO_TLS)
    MBEDTLS_MPS_IF_TLS( mode )
    {
        /* TLS */
        mps_l3_handshake_in hs_l3;
        MPS_CHK( mps_l3_read_handshake( mps->conf.l3, &hs_l3 ) );

        hs->length = hs_l3.len;
        hs->type   = hs_l3.type;
        hs->handle = hs_l3.rd_ext;
        hs->addlen = 0; /* No additional data in TLS */
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
    {
        MPS_CHK( mps_reassembly_read( mps, hs ) );
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

int mbedtls_mps_read_application( mbedtls_mps *mps,
                                  mbedtls_reader **rd )
{
    int ret;
    ret = mps_check_read( mps );
    if( ret != 0 )
        return( ret );

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( mps->in.state != MBEDTLS_MPS_MSG_APP )
        return( MPS_ERR_UNEXPECTED_OPERATION );
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    *rd = mps->in.data.app;
    return( 0 );
}

int mbedtls_mps_read_alert( mbedtls_mps const *mps,
                            mbedtls_mps_alert_t *alert_type )
{
    int ret;

    ret = mps_check_read( mps );
    if( ret != 0 )
        return( ret );

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( mps->in.state != MBEDTLS_MPS_MSG_ALERT )
        return( MPS_ERR_UNEXPECTED_OPERATION );
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    *alert_type = mps->in.data.alert;
    return( 0 );
}

int mbedtls_mps_read_set_flags( mbedtls_mps *mps, mbedtls_mps_msg_flags flags )
{
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_conf_get_mode( &mps->conf );
    TRACE_INIT( "mbedtls_mps_write_set_flags" );
    TRACE( trace_comment, "* Flags: %02x", (unsigned) flags );

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( mps->in.state == MBEDTLS_MPS_MSG_NONE )
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    /* The logic layer may call this function even for TLS,
     * in which case it does nothing. That's to prevent the
     * handshake logic code to be cluttered with TLS vs. DTLS
     * distinctions. */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
        mps->in.flags = flags;
#else
    ((void) mode);
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    RETURN( 0 );
}

int mbedtls_mps_read_pause( mbedtls_mps *mps )
{
    int ret;
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_conf_get_mode( &mps->conf );

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( mps->in.state != MBEDTLS_MPS_MSG_HS )
        return( MPS_ERR_UNEXPECTED_OPERATION );
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    ret = mps_check_read( mps );
    if( ret != 0 )
        return( ret );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        /* TLS */
        MPS_CHK( mps_l3_read_pause_handshake( mps->conf.l3 ) );
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        /* DTLS */
        MPS_CHK( mps_retransmission_pause_incoming_message( mps ) );
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    mps->in.state = MBEDTLS_MPS_MSG_NONE;

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

int mbedtls_mps_read_consume( mbedtls_mps *mps )
{
    int ret;
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_conf_get_mode( &mps->conf );
    TRACE_INIT( "mbedtls_mps_read_consume" );

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( mps->in.state == MBEDTLS_MPS_MSG_NONE )
        return( MPS_ERR_UNEXPECTED_OPERATION );
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    ret = mps_check_read( mps );
    if( ret != 0 )
        RETURN( ret );

    switch( mps->in.state )
    {
        case MBEDTLS_MPS_MSG_HS:

#if defined(MBEDTLS_MPS_PROTO_TLS)
            if( MBEDTLS_MPS_IS_TLS( mode ) )
            {
                /* TLS */
                MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );
            }
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
            if( MBEDTLS_MPS_IS_DTLS( mode ) )
            {
                /* DTLS
                 *
                 * Notify the retransmission state machine.
                 *
                 * Note that not all handshake messages passed to the user are
                 * related to an incoming fragment currently opened on Layer 3
                 * -- for example, when buffering out-of-order messages, the
                 * retransmission state machine will serve buffered messages
                 * from internal copies, and consuming them does not involve any
                 * interaction with Layer 3.
                 */
                MPS_CHK( mps_retransmission_finish_incoming_message( mps ) );
            }
#endif /* MBEDTLS_MPS_PROTO_DTLS */
            break;

        case MBEDTLS_MPS_MSG_APP:
            MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );
            break;

        case MBEDTLS_MPS_MSG_CCS:
        case MBEDTLS_MPS_MSG_ALERT:
            /* Alerts and CCS's are signalled as consumed
             * to Layer 3 in mbedtls_mps_read(). */
            break;

#if defined(MBEDTLS_MPS_ASSERT)
        default:
            MPS_CHK( MBEDTLS_ERR_MPS_INTERNAL_ERROR );
#endif /* MBEDTLS_MPS_ASSERT */
    }

    TRACE( trace_comment, "New incoming state: NONE" );
    mps->in.state = MBEDTLS_MPS_MSG_NONE;

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

int mbedtls_mps_read_dependencies( mbedtls_mps *mps,
                                   mbedtls_mps_dependencies *flags )
{
    ((void) mps);
    ((void) flags);
    return( MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED );
}

int mbedtls_mps_get_sequence_number( mbedtls_mps *mps, uint8_t seq[8] )
{
    ((void) mps);
    ((void) seq);
    return( MBEDTLS_ERR_MPS_OPTION_UNSUPPORTED );
}

/*
 * MPS writing functions.
 */

int mbedtls_mps_write_set_flags( mbedtls_mps *mps, mbedtls_mps_msg_flags flags )
{
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_conf_get_mode( &mps->conf );
    TRACE_INIT( "mbedtls_mps_write_set_flags" );
    TRACE( trace_comment, "* Flags: %02x", (unsigned) flags );

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( mps->out.state == MBEDTLS_MPS_MSG_NONE )
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    /* The logic layer may call this function even for TLS,
     * in which case it does nothing. That's to prevent the
     * handshake logic code to be cluttered with TLS vs. DTLS
     * distinctions. */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
        mps->dtls.io.out.flags = flags;
#else
    ((void) mode);
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    RETURN( 0 );
}

int mbedtls_mps_write_handshake( mbedtls_mps *mps,
                                 mbedtls_mps_handshake_out *hs_new,
                                 mbedtls_mps_write_cb_t cb,
                                 mbedtls_mps_write_cb_ctx_t *cb_ctx )
{
    /* TODO:
     * Currently, when this function returns MPS_WANT_WRITE,
     * the user cannot know to what extend the user-facing state of MPS has
     * changed:
     * - If Layer 4 handshake data is pending to be flushed but the
     *   underlying transport isn't ready, the function will return
     *   MPS_WANT_WRITE without having changed the user-facing state of MPS.
     * - If Layer 3 handshake data is pending to be flushed, this function
     *   returns MPS_WANT_WRITE _after_ changing the flight state.
     *
     * This should be made uniform.
     */

    int ret;
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_conf_get_mode( &mps->conf );

    TRACE_INIT( "mbedtls_mps_write_handshake, type %u, length %u",
                (unsigned) hs_new->type, (unsigned) hs_new->length );

    MPS_CHK( mps_prepare_write( mps, MPS_PAUSED_HS_ALLOWED ) );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        /* TLS
         * Write a handshake message on Layer 3 and forward the writer. */
        mps_l3_handshake_out hs_l3;

        /* Retransmission isn't needed in TLS. */
        ((void) cb);
        ((void) cb_ctx);

        hs_l3.epoch = mps->out_epoch;
        hs_l3.type  = hs_new->type;
        hs_l3.len   = hs_new->length;

        MPS_CHK( mps_l3_write_handshake( mps->conf.l3, &hs_l3 ) );

        hs_new->handle = hs_l3.wr_ext;
        hs_new->addlen = 0;
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        /* DTLS */
        mbedtls_mps_handshake_out_internal * const hs = &mps->dtls.io.out.hs;

        /* We have to deal with the situation where a flight-exchange finished
         * with an outgoing flight of ours, and we attempt to start another one
         * while still being unsure whether the peer has received our last
         * flight (i.e., we're in state #MBEDTLS_MPS_FLIGHT_FINALIZE).
         *
         * We are currently ignoring the missing acknowledgement
         * and start a new handshake assuming that our peer sees
         * the previous one as completed.
         *
         * This was also the behavior of the previous messaging stack.
         *
         * TODO: Test this!
         */
        if( mps_get_handshake_state( mps )
              == MBEDTLS_MPS_FLIGHT_FINALIZE )
        {
            TRACE( trace_comment, "Last flight-exchange complete for us, but not necessarily for peer - ignore." );
            MPS_CHK( mps_handshake_state_transition(
                         mps,
                         MBEDTLS_MPS_FLIGHT_FINALIZE,
                         MBEDTLS_MPS_FLIGHT_DONE ) );
        }
        else if( mps_get_handshake_state( mps )
                   == MBEDTLS_MPS_FLIGHT_RECVINIT )
        {
            MPS_CHK( mps_handshake_state_transition(
                         mps,
                         MBEDTLS_MPS_FLIGHT_RECVINIT,
                         MBEDTLS_MPS_FLIGHT_DONE ) );
        }

        /* No `else` because we want to fall through. */
        if( mps_get_handshake_state( mps )
              == MBEDTLS_MPS_FLIGHT_DONE )
        {
            TRACE( trace_comment, "No flight-exchange in progress. Start a new one" );
            mps->dtls.seq_nr = MPS_INITIAL_HS_SEQ_NR;
            MPS_CHK( mps_handshake_state_transition(
                         mps,
                         MBEDTLS_MPS_FLIGHT_DONE,
                         MBEDTLS_MPS_FLIGHT_SEND ) );
        }
        else if( mps_get_handshake_state( mps )
                   == MBEDTLS_MPS_FLIGHT_PREPARE )
        {
            MPS_CHK( mps_handshake_state_transition(
                         mps,
                         MBEDTLS_MPS_FLIGHT_PREPARE,
                         MBEDTLS_MPS_FLIGHT_SEND ) );
        }

        /* Check if a handshake message is currently paused or not. */
        if( hs->state == MBEDTLS_MPS_HS_ACTIVE )
        {
            mbedtls_mps_msg_metadata * const metadata = hs->metadata;
            TRACE( trace_comment, "Handshake message has been paused - continue" );

            /* Check consistency of parameters and forward to the user. */
            /* OPTIMIZATION: Consider ignoring the metadata passed on
             * continuation calls (and documentin that). */
            if( metadata->len  != hs_new->length ||
                metadata->type != hs_new->type )
            {
                TRACE( trace_error, "Inconsistent parameters on continuation of handshake write." );
                MPS_CHK( MPS_ERR_INVALID_ARGS );
            }
        }
        else if( hs->state == MBEDTLS_MPS_HS_NONE )
        {
            mbedtls_mps_retransmission_handle *handle;
            unsigned char *queue;
            size_t queue_len;
            uint8_t write_mode;

            TRACE( trace_comment, "No handshake message paused - start a new one." );

            /* No handshake message is paused -- start a new one.
             *
             * This differs considerably depending on whether retransmission of
             * the new handshake message shall happen on the basis of a raw
             * backup or on the basis of a retransmission callback:
             *
             * - Retransmission via raw backup
             *   If we have to backup the entire handshake message anyhow,
             *   we should have it written to its target backup buffer first,
             *   and only afterwards dispatch that buffer through potentially
             *   fragmented handhake messages. This is realized here by
             *   feeding an empty buffer to the message writer passed to the
             *   user and by registering the message backup buffer as the queue
             *   for that writer. This way, the user directly writes into the
             *   backup buffer, and once it's done, actual dispatching is done
             *   by repeatedly requesting handshake fragments from Layer 3 and
             *   feed()-ing their contents to the writer until the entire
             *   queue has been dispatched.
             *
             * - Retransmission via callback
             *   If we don't need to backup the message, we follow the same
             *   strategy as in the rest of MPS of trying to directly perform
             *   the write on the target record buffer to avoid unnecessary
             *   allocation and copying. This is done by requesting a new
             *   handshake fragment from Layer 3 and registering its content
             *   buffer with the handshake writer passed to the user, alongside
             *   a queue buffer of size configurable by the user. When the
             *   user subsequently provides the message contents, it first
             *   writes into the record buffer and then into the queue
             *   (if present).
             */

            /* Request to add a new message to the current outgoing flight
             * and setup the handle controlling potential retransmissions. */

            /* This allocates a fresh retransmission handle and sets the
             * sequence number for the next outgoing handshake message. */
            MPS_CHK( mps_out_flight_msg_start( mps, &handle ) );

            /* Remember the handshake message metadata.
             * Note that the handshake sequence number has already
             * been set through mps_out_flight_msg_start(). */
            handle->metadata.epoch  = mps->out_epoch;
            handle->metadata.type   = hs_new->type;
            /* Note: We do support unknown lengths here. In this case,
             *       we set the actual length later. */
            handle->metadata.len    = hs_new->length;

            /* Distinguish between messages retransmitted by backup
             * and those retransmitted by a callback.                  */
            if( cb == NULL )
            {
                /* Retransmission via raw backup. */
                size_t backup_len;
                unsigned char *backup_buf;

                TRACE( trace_comment, "Retransmission via raw backup" );
                handle->handle_type = MBEDTLS_MPS_RETRANSMISSION_HANDLE_HS_RAW;

                /* Infer length for backup buffer. */
                if( handle->metadata.len != MBEDTLS_MPS_SIZE_UNKNOWN )
                {
                    TRACE( trace_comment, "Total handshake length known: %u",
                           (unsigned) hs_new->length );
#if defined(MBEDTLS_MPS_ASSERT)
                    if( handle->metadata.len > MBEDTLS_MPS_MAX_HS_LENGTH )
                    {
                        TRACE( trace_error, "Bad handshake length" );
                        MPS_CHK( MBEDTLS_ERR_MPS_INTERNAL_ERROR );
                    }
#endif /* MBEDTLS_MPS_ASSERT */
                    backup_len = handle->metadata.len;
                }
                else
                {
                    TRACE( trace_comment, "Total handshake length unknown, use backup buffer of maximum size %u",
                           (unsigned) MBEDTLS_MPS_MAX_HS_LENGTH );
                    backup_len = MBEDTLS_MPS_MAX_HS_LENGTH;
                }

                /* TODO: Switch to allocator interface. */
                backup_buf = mbedtls_calloc( 1, backup_len );
                if( backup_buf == NULL )
                {
                    TRACE( trace_error, "Error allocating backup buffer" );
                    MPS_CHK( MBEDTLS_ERR_MPS_OUT_OF_MEMORY );
                }
                handle->handle.raw.buf = backup_buf;
                handle->handle.raw.len = backup_len;

                write_mode = MPS_DTLS_FRAG_OUT_START_QUEUE_ONLY;
                queue      = backup_buf;
                queue_len  = backup_len;
            }
            else
            {
                /* Retransmission via callback. */
                TRACE( trace_comment, "Retransmission via callback" );
                handle->handle_type =
                    MBEDTLS_MPS_RETRANSMISSION_HANDLE_HS_CALLBACK;

                /* For now, demand that the total length is known.
                 * To support unknown length for messages using a
                 * retransmission callbacks, we need a way to set the
                 * total message length at Layer 3 after we have started
                 * a handshake write (shouldn't be difficult). */
                if( handle->metadata.len == MBEDTLS_MPS_SIZE_UNKNOWN )
                {
                    TRACE( trace_error, "Handshake messages with retransmission callback and unknown size not supported." );
                    RETURN( MPS_ERR_INVALID_ARGS );
                }

                handle->handle.callback.cb  = cb;
                handle->handle.callback.ctx = cb_ctx;

                write_mode = MPS_DTLS_FRAG_OUT_START_USE_L3;
                queue      = hs->queue;
                queue_len  = hs->queue_len;
            }

            /* Setup the structure representing the new handshake message.
             * Note that this does not interface with Layer 3, and every
             * error is fatal. */
            MPS_CHK( mps_dtls_frag_out_start( hs, queue, queue_len,
                                              &handle->metadata,
                                              write_mode ) );

            /* This may interface with Layer 3 and potentially return
             * MBEDTLS_MPS_ERR_WANT_WRITE. */
            MPS_CHK( mps_dtls_frag_out_unpause( mps, MPS_PAUSED_HS_ALLOWED ) );
        }
#if defined(MBEDTLS_MPS_ASSERT)
        else
        {
            TRACE( trace_error, "Expecting HS state to be ACTIVE or NONE in body of write_handshake()" );
            MPS_CHK( MPS_ERR_INTERNAL_ERROR );
        }
#endif /* MBEDTLS_MPS_ASSERT */

        /* Add the sequence number to the handshake handle, exposed
         * opaquely only to allow it to enter checksum computations. */
        MPS_WRITE_UINT16_BE( &hs->metadata->seq_nr, hs_new->add );
        hs_new->addlen = sizeof( uint16_t );
        hs_new->handle = &hs->wr_ext;
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */
    mps->out.state = MBEDTLS_MPS_MSG_HS;

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

int mbedtls_mps_write_application( mbedtls_mps *mps,
                                   mbedtls_writer **app )
{
    int ret;
    mps_l3_app_out out_l3;
    MPS_CHK( mps_prepare_write( mps, MPS_PAUSED_HS_FORBIDDEN ) );

    out_l3.epoch = mps->out_epoch;
    MPS_CHK( mps_l3_write_app( mps->conf.l3, &out_l3 ) );

    *app = out_l3.wr;

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

int mbedtls_mps_write_alert( mbedtls_mps *mps,
                             mbedtls_mps_alert_t alert_type )
{
    int ret;
    mps_l3_alert_out alert_l3;
    MPS_CHK( mps_prepare_write( mps, MPS_PAUSED_HS_FORBIDDEN ) );

    alert_l3.epoch = mps->out_epoch;
    MPS_CHK( mps_l3_write_alert( mps->conf.l3, &alert_l3 ) );

    *alert_l3.level = MBEDTLS_MPS_ALERT_LEVEL_WARNING;
    *alert_l3.type = alert_type;

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

int mbedtls_mps_write_ccs( mbedtls_mps *mps )
{
    int ret;
    mps_l3_ccs_out ccs_l3;
    MPS_CHK( mps_prepare_write( mps, MPS_PAUSED_HS_FORBIDDEN ) );

    ccs_l3.epoch = mps->out_epoch;
    MPS_CHK( mps_l3_write_ccs( mps->conf.l3, &ccs_l3 ) );

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

int mbedtls_mps_write_pause( mbedtls_mps *mps )
{
    int ret;
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_conf_get_mode( &mps->conf );
    TRACE_INIT( "mbedtls_mps_write_pause" );

    ret = mps_check_write( mps );
    if( ret != 0 )
        RETURN( ret );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        MPS_CHK( mps_l3_pause_handshake( mps->conf.l3 ) );
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        /* DTLS */
        if( mps->dtls.io.out.hs.state != MBEDTLS_MPS_HS_ACTIVE )
            MPS_CHK( MPS_ERR_INTERNAL_ERROR );

        /* Check that the handshake message is not yet fully written. */
        if( mbedtls_writer_check_done( &mps->dtls.io.out.hs.wr_ext ) == 0 )
        {
            TRACE( trace_error, "Attempt to pause a fully written handshake message." );
            MPS_CHK( MPS_ERR_INTERNAL_ERROR );
        }

        /* Dispatch the current fragment. */
        MPS_CHK( mps_dtls_frag_out_close( mps ) );
        MPS_CHK( mps_dtls_frag_out_dispatch( mps ) );
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    mps->out.state = MBEDTLS_MPS_MSG_NONE;

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

int mbedtls_mps_dispatch( mbedtls_mps *mps )
{
    int ret;
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_conf_get_mode( &mps->conf );
    TRACE_INIT( "mbedtls_mps_dispatch" );

    ret = mps_check_write( mps );
    if( ret != 0 )
        RETURN( ret );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        /* TLS */
        MPS_CHK( mps_l3_dispatch( mps->conf.l3 ) );
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        /* DTLS */
        uint8_t flags;

        if( mps->out.state == MBEDTLS_MPS_MSG_NONE )
        {
            TRACE( trace_error, "No message open" );
            MPS_CHK( MPS_ERR_INTERNAL_ERROR );
        }

        if( mps->out.state != MBEDTLS_MPS_MSG_HS )
        {
            /* Everything apart from handshake messages
             * is just forwarded to Layer 3. */
            MPS_CHK( mps_l3_dispatch( mps->conf.l3 ) );
        }
        else
        {
            /* Handshake message */

            if( mps->dtls.io.out.hs.state != MBEDTLS_MPS_HS_ACTIVE )
                MPS_CHK( MPS_ERR_INTERNAL_ERROR );

            /* Check that the handshake message has been fully written. */
            MPS_CHK( mbedtls_writer_check_done( &mps->dtls.io.out.hs.wr_ext ) );

            /* Wrapup and dispatch the message. */
            MPS_CHK( mps_dtls_frag_out_close( mps ) );
            MPS_CHK( mps_dtls_frag_out_dispatch( mps ) );

            /* Update outgoing flight state. */
            MPS_CHK( mps_out_flight_msg_done( mps ) );
        }

        /* Update retransmission state machine. */
        flags = mps->dtls.io.out.flags & MBEDTLS_MPS_FLIGHT_MASK;
        if( flags == MBEDTLS_MPS_FLIGHT_END      ||
            flags == MBEDTLS_MPS_FLIGHT_FINISHED )
        {
            mps->dtls.wait.retransmit_timeout =
                mbedtls_mps_conf_get_hs_timeout_min( &mps->conf );

            if( flags == MBEDTLS_MPS_FLIGHT_END )
            {
                TRACE( trace_comment, "Message finishes the flight, move from SEND to AWAIT state." );
                MPS_CHK( mps_handshake_state_transition(
                             mps,
                             MBEDTLS_MPS_FLIGHT_SEND,
                             MBEDTLS_MPS_FLIGHT_AWAIT ) );
            }
            else
            {
                TRACE( trace_comment, "Message finishes the flight-exchange, move from SEND to FINALIZE state." );
                MPS_CHK( mps_handshake_state_transition(
                             mps,
                             MBEDTLS_MPS_FLIGHT_SEND,
                             MBEDTLS_MPS_FLIGHT_FINALIZE ) );
            }

            MPS_CHK( mps_retransmission_timer_update( mps ) );
        }
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    mps->out.state = MBEDTLS_MPS_MSG_NONE;

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

int mbedtls_mps_flush( mbedtls_mps *mps )
{
    int ret;
    TRACE_INIT( "mbedtls_mps_flush" );

    mps->out.flush = 1;
    MPS_CHK( mps_clear_pending( mps, MPS_PAUSED_HS_ALLOWED ) );

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

int mbedtls_mps_write_dependencies( mbedtls_mps *mps,
                                    mbedtls_mps_dependencies *flags )
{
    ((void) mps);
    ((void) flags);
    return( MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED );
}

int mbedtls_mps_force_sequence_number( mbedtls_mps *mps, uint8_t seq[8] )
{
    ((void) mps);
    ((void) seq);
    return( MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED );
}

/*
 * MPS security parameter configuration
 */

int mbedtls_mps_add_key_material( mbedtls_mps *mps,
                                  mbedtls_mps_transform_t *params,
                                  mbedtls_mps_epoch_id *id )
{
    int ret;
    TRACE_INIT( "mbedtls_mps_add_key_material" );
    MPS_CHK( mps_l3_epoch_add( mps->conf.l3, params, id ) );

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

int mbedtls_mps_set_incoming_keys( mbedtls_mps *mps,
                                   mbedtls_mps_epoch_id id )
{
    int ret;
    TRACE_INIT( "mbedtls_mps_set_incoming_keys, epoch %d", (int) id );

    /* Clear 'active epoch' usage for old epoch and set it for new. */
    if( mps->in_epoch != MBEDTLS_MPS_EPOCH_NONE )
    {
        MPS_CHK( mps_l3_epoch_usage( mps->conf.l3, mps->in_epoch,
                                     MPS_EPOCH_USAGE_READ(
                                         MPS_READ_ACTIVE ), 0 ) );
    }
    MPS_CHK( mps_l3_epoch_usage( mps->conf.l3, id, 0,
                                 MPS_EPOCH_USAGE_READ(
                                     MPS_READ_ACTIVE ) ) );
    mps->in_epoch = id;

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

int mbedtls_mps_set_outgoing_keys( mbedtls_mps *mps,
                                   mbedtls_mps_epoch_id id )
{
    int ret;
    TRACE_INIT( "mbedtls_mps_set_outgoing_keys, epoch %d", (int) id );

    /* Clear 'active epoch' usage for old epoch and set it for new. */
    if( mps->out_epoch != MBEDTLS_MPS_EPOCH_NONE )
    {
        MPS_CHK( mps_l3_epoch_usage( mps->conf.l3, mps->out_epoch,
                                     MPS_EPOCH_USAGE_WRITE(
                                         MPS_WRITE_ACTIVE ), 0 ) );
    }
    MPS_CHK( mps_l3_epoch_usage( mps->conf.l3, id, 0,
                                 MPS_EPOCH_USAGE_WRITE(
                                     MPS_WRITE_ACTIVE ) ) );
    mps->out_epoch = id;

    MPS_API_BOUNDARY_FAILURE_HANDLER
}

mbedtls_mps_connection_state_t mbedtls_mps_connection_state(
    mbedtls_mps const *mps )
{
    return( mps->state );
}

/* int mbedtls_mps_error_state( mbedtls_mps const *mps, */
/*                              mbedtls_mps_blocking_info_t *info ) */
/* { */
/*     /\* TODO *\/ */
/*     return( 0 ); */
/* } */

/*
 *
 * DTLS specific functions
 *
 */

#if defined(MBEDTLS_MPS_PROTO_DTLS)

MBEDTLS_MPS_STATIC int mps_retransmission_timer_increase_timeout( mbedtls_mps *mps )
{
    uint32_t new_timeout, cur_timeout, max_timeout;
    uint8_t overflow;
    TRACE_INIT( "mps_retransmit_timer_increase_timeout" );

    cur_timeout = mps->dtls.wait.retransmit_timeout;

    max_timeout = mbedtls_mps_conf_get_hs_timeout_max( &mps->conf );
    if( cur_timeout >= max_timeout )
        RETURN( 0 /* -1 */ );

    new_timeout = 2 * cur_timeout;

    /* Avoid arithmetic overflow and range overflow */
    overflow = ( new_timeout < cur_timeout );
    if( overflow || new_timeout > max_timeout )
        new_timeout = max_timeout;

    mps->dtls.wait.retransmit_timeout = new_timeout;
    TRACE( trace_comment, "Update timeout value to %u milliseonds",
           (unsigned) new_timeout );

    RETURN( 0 );
}

MBEDTLS_MPS_STATIC int mps_retransmission_timer_update( mbedtls_mps *mps )
{
    void*                     const timer_ctx = mps->conf.p_timer;
    mbedtls_mps_set_timer_t * const set_timer = mps->conf.f_set_timer;
    TRACE_INIT( "mps_retransmission_timer_update" );

    if( set_timer == NULL )
    {
        TRACE( trace_comment, "No timer configured" );
        RETURN( 0 );
    }

    set_timer( timer_ctx, mps->dtls.wait.retransmit_timeout / 4,
               mps->dtls.wait.retransmit_timeout );

    RETURN( 0 );
}

MBEDTLS_MPS_STATIC int mps_retransmission_timer_stop( mbedtls_mps *mps )
{
    void*                     const timer_ctx = mps->conf.p_timer;
    mbedtls_mps_set_timer_t * const set_timer = mps->conf.f_set_timer;
    TRACE_INIT( "mps_retransmission_timer_stop" );

    if( set_timer == NULL )
    {
        TRACE( trace_comment, "No timer configured" );
        RETURN( 0 );
    }

    set_timer( timer_ctx, 0, 0 );
    RETURN( 0 );
}

MBEDTLS_MPS_STATIC int mps_retransmission_timer_check( mbedtls_mps *mps )
{
    int ret = 0;
    void*                     const timer_ctx = mps->conf.p_timer;
    mbedtls_mps_get_timer_t * const get_timer = mps->conf.f_get_timer;
    TRACE_INIT( "mps_retransmission_timer_check" );

    if( get_timer != NULL && get_timer( timer_ctx ) == 2 )
    {
        TRACE( trace_comment, "Retransmission timer fired" );
        mps_retransmission_timer_stop( mps );
        switch( mps_get_handshake_state( mps ) )
        {
            case MBEDTLS_MPS_FLIGHT_AWAIT:
                /* TODO: Extract to function */
                TRACE( trace_comment, "Trigger retransmission of last outgoing flight." );
                mps->dtls.retransmit_state   = MBEDTLS_MPS_RETRANSMIT_RESEND;
                mps->dtls.wait.resend_offset = 0;
                break;

            case MBEDTLS_MPS_FLIGHT_RECEIVE:
                /* TODO: Extract to function */
                TRACE( trace_comment, "Trigger sending retransmission request to peer." );
                mps->dtls.retransmit_state   = MBEDTLS_MPS_RETRANSMIT_REQUEST_RESEND;
                mps->dtls.wait.resend_offset = 0;
                break;

            case MBEDTLS_MPS_FLIGHT_FINALIZE:
                /* TODO: Extract to function, share code
                 * with mbedtls_mps_write_handshake(). */
                MPS_CHK( mps_handshake_state_transition(
                             mps,
                             MBEDTLS_MPS_FLIGHT_FINALIZE,
                             MBEDTLS_MPS_FLIGHT_DONE ) );

            default:
                break;
        }
    }

exit:
    RETURN( ret );
}

MBEDTLS_MPS_STATIC int mps_check_retransmit( mbedtls_mps *mps )
{
    int ret;
    mbedtls_mps_retransmit_state_t state = mps->dtls.retransmit_state;

    if( state == MBEDTLS_MPS_RETRANSMIT_NONE )
        return( 0 );

    if( state == MBEDTLS_MPS_RETRANSMIT_RESEND )
        ret = mps_retransmit_out( mps );
    else
    {
#if defined(MBEDTLS_MPS_ASSERT)
    if( state != MBEDTLS_MPS_RETRANSMIT_REQUEST_RESEND )
        return( MPS_ERR_INTERNAL_ERROR );
#endif /* MBEDTLS_MPS_ASSERT */

        ret = mps_request_resend( mps );
    }
    MPS_CHK( ret );

    mps->dtls.retransmit_state = MBEDTLS_MPS_RETRANSMIT_NONE;
    MPS_CHK( mps_retransmission_timer_increase_timeout( mps ) );
    MPS_CHK( mps_retransmission_timer_update( mps ) );

exit:
    return( ret );
}

/*
 * Incoming flight retransmission detection
 */

MBEDTLS_MPS_STATIC int mps_recognition_info_match(
    mbedtls_mps_recognition_info *info, mps_l3_handshake_in *hs_in )
{
    if( info->epoch  == hs_in->epoch &&
        info->seq_nr == hs_in->seq_nr )
    {
        return( 0 );
    }
    return( -1 );
}

MBEDTLS_MPS_STATIC int mps_retransmit_in_check( mbedtls_mps *mps,
                                                mps_l3_handshake_in *hs )
{
    uint8_t flight_len, msg_idx;
    uint8_t match_idx, match_status;

    mbedtls_mps_recognition_info *info;
    uint8_t *status;

    /*
     * Please consult the documentation of
     * ::mbedtls_mps::dtls::retransmission_detection
     * for more information on the retransmission detection
     * strategy applied here.
     */

    TRACE_INIT( "mps_retransmit_in_check" );
    TRACE( trace_comment, "Seq Nr: %u", hs->seq_nr );
    TRACE( trace_comment, "Type:   %u", hs->type   );
    TRACE( trace_comment, "Length: %u", hs->len    );

    /* We only consider handshake fragments with offset 0. */
    if( hs->frag_offset != 0 )
        RETURN( 0 );

    flight_len = mps->dtls.retransmission_detection.flight_len;
    info       = &mps->dtls.retransmission_detection.msgs[0];
    match_idx  = 0xff;
    for( msg_idx=0; msg_idx < flight_len; msg_idx++, info++ )
    {
        if( mps_recognition_info_match( info, hs ) == 0 )
        {
            match_idx = msg_idx;
            break;
        }
    }

    if( match_idx == 0xff )
        RETURN( 0 );

    TRACE( trace_comment, "Retransmission of %u-th message detected",
           (unsigned) match_idx );

    status = &mps->dtls.retransmission_detection.msg_state[match_idx];
    match_status = *status;
    if( match_status == MBEDTLS_MPS_RETRANSMISSION_DETECTION_ENABLED )
    {
        /* Observed a retransmission - move all messages to 'on hold'
         * state to omit triggering multiple retransmissions from a
         * single retransmission of the peer. */
        TRACE( trace_comment, "Retransmission active for message"
               " - retransmit and put all other messages on hold." );

        status = &mps->dtls.retransmission_detection.msg_state[0];
        for( msg_idx=0; msg_idx < flight_len; msg_idx++, status++ )
            *status = MBEDTLS_MPS_RETRANSMISSION_DETECTION_ON_HOLD;

        RETURN( MBEDTLS_ERR_MPS_FLIGHT_RETRANSMISSION );
    }
    else
    {
        /* Re-activate retransmission detection for message. */
        TRACE( trace_comment, "Retransmission currently put on hold "
               "for this messsage - reactivate." );
        *status = MBEDTLS_MPS_RETRANSMISSION_DETECTION_ENABLED;
        RETURN( 0 );
    }
}

MBEDTLS_MPS_STATIC int mps_retransmit_in_remember( mbedtls_mps *mps,
                                       mbedtls_mps_handshake_in *hs_in,
                                       uint8_t seq_nr )
{
    int ret = 0;
    size_t msg_idx;
    mbedtls_mps_recognition_info *next_info;
    TRACE_INIT( "mps_retransmit_in_remember" );

    /* Currently, we are basing retransmission detection
     * on epoch and sequence number only. */
    ((void) hs_in);

    msg_idx = mps->dtls.retransmission_detection.flight_len;
    if( msg_idx == MBEDTLS_MPS_MAX_FLIGHT_LENGTH )
        MPS_CHK( MBEDTLS_ERR_MPS_FLIGHT_TOO_LONG );

    next_info = &mps->dtls.retransmission_detection.msgs[ msg_idx ];

    next_info->epoch  = mps->in_epoch;
    next_info->seq_nr = seq_nr;

    mps->dtls.retransmission_detection.msg_state[msg_idx] =
        MBEDTLS_MPS_RETRANSMISSION_DETECTION_ENABLED;

    mps->dtls.retransmission_detection.flight_len++;

    /* Keep an epoch as long as we might still receive
     * retransmissions using that epoch. */
    MPS_CHK( mps_l3_epoch_usage( mps->conf.l3,
                   mps->in_epoch,
                   0,
                   MPS_EPOCH_USAGE_READ(
                       MPS_READ_RETRANSMISSION_DETECTION ) ) );

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_retransmit_in_init( mbedtls_mps *mps )
{
    mps->dtls.retransmission_detection.flight_len = 0;
    return( 0 );
}

MBEDTLS_MPS_STATIC int mps_retransmit_in_free( mbedtls_mps *mps )
{
    int ret = 0;
    uint8_t flight_len, msg_idx;
    mbedtls_mps_recognition_info *info;
    TRACE_INIT( "mps_retransmit_in_free" );

    flight_len = mps->dtls.retransmission_detection.flight_len;
    info       = &mps->dtls.retransmission_detection.msgs[0];

    TRACE( trace_comment, "Flight length: %u", (unsigned) flight_len );
    for( msg_idx=0; msg_idx < flight_len; msg_idx++, info++ )
    {
        TRACE( trace_comment,
               "Epoch %u no longer needed for retransmission detection",
               (unsigned) info->epoch );

        MPS_CHK( mps_l3_epoch_usage( mps->conf.l3,
                    info->epoch,
                    MPS_EPOCH_USAGE_READ(
                        MPS_READ_RETRANSMISSION_DETECTION ),
                    0 ) );
    }

    mps->dtls.retransmission_detection.flight_len = 0;

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_retransmit_in_forget( mbedtls_mps *mps )
{
    int ret = 0;
    TRACE_INIT( "mps_retransmit_in_forget" );
    MPS_CHK( mps_retransmit_in_free( mps ) );
    MPS_CHK( mps_retransmit_in_init( mps ) );
    MPS_INTERNAL_FAILURE_HANDLER
}

/*
 * Implementation of reassembly submodule.
 */

/*
 * Mark bits in bitmask (used for DTLS HS reassembly)
 */
MBEDTLS_MPS_STATIC void mps_bitmask_set( unsigned char *mask, size_t first_bit,
                                         size_t bitlen )
{
    /* Set one bit a time and (tail-)recurse. This is not efficient,
     * but short, and this part of the code isn't time critical. */
    size_t first_byte = first_bit >> 3;
    size_t byte_frac = first_bit & 0x7;

    if( bitlen-- == 0 )
        return;

    mask += first_byte;
    *mask &= ~( 1u << byte_frac );

    return( mps_bitmask_set( mask, byte_frac + 1, bitlen ) );
}

/*
 * Check that bitmask is full
 */
MBEDTLS_MPS_STATIC int mps_bitmask_check( unsigned char *mask, size_t len )
{
    /* This function assumes that `mask` points to a bitmask of length
     * `len / 8 + 1` Bytes, even if `len % 8 == 0`. */
    size_t byte_len = len / 8 + 1;
    while( byte_len != 0 )
    {
        uint8_t const cur_byte = *mask;
        if( cur_byte != 0x0 )
            return( -1 );
        byte_len--;
        mask++;
    }

    return( 0 );
}

MBEDTLS_MPS_STATIC int mps_reassembly_feed( mbedtls_mps *mps,
                                mps_l3_handshake_in *hs )
{
    int ret = 0;
    uint8_t seq_nr, seq_nr_offset;
    mbedtls_mps_reassembly * const in = &mps->dtls.io.in.incoming;
    mbedtls_mps_msg_reassembly * reassembly;

    TRACE_INIT( "mps_reassembly_feed" );
    TRACE( trace_comment, "* Sequence number: %u", hs->seq_nr      );
    TRACE( trace_comment, "* Type:            %u", hs->type        );
    TRACE( trace_comment, "* Total length:    %u", hs->len         );
    TRACE( trace_comment, "* Fragment offset: %u", hs->frag_offset );
    TRACE( trace_comment, "* Fragment length: %u", hs->frag_len    );
    TRACE( trace_comment, "Sequence number of next HS message: %u",
           (unsigned) mps->dtls.seq_nr );

#if defined(MBEDTLS_MPS_ASSERT)
    if( ! MBEDTLS_MPS_FLIGHT_STATE_EITHER_OR(
            mps_get_handshake_state( mps ),
            MBEDTLS_MPS_FLIGHT_RECVINIT,
            MBEDTLS_MPS_FLIGHT_RECEIVE ) )
    {
        TRACE( trace_error, "Trying to use reassembly module outside of "
                            "RECEIVE and RECVINIT state." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */

    seq_nr = hs->seq_nr;
    seq_nr_offset = seq_nr - mps->dtls.seq_nr;

    /* Check if the sequence number belongs to the window
     * of messages that we're currently buffering - in particular,
     * if buffering is disabled, this checks if the fragment
     * belongs to the next handshake message. */
    if( seq_nr < mps->dtls.seq_nr ||
        seq_nr_offset >= 1 + MBEDTLS_MPS_FUTURE_MESSAGE_BUFFERS )
    {
        unsigned char *tmp;

        TRACE( trace_error, "Sequence number %u outside current window [%u,%u]",
          (unsigned) seq_nr, (unsigned) mps->dtls.seq_nr,
          (unsigned) ( mps->dtls.seq_nr + MBEDTLS_MPS_FUTURE_MESSAGE_BUFFERS ) );

        /* Layer 3 will error out if we don't fully consume a fragment,
         * so fetch and commit it even if we don't consider the contents. */
        /* TODO: This could be moved to an 'abort' function on Layer 3. */
        MPS_CHK( mbedtls_reader_get_ext( hs->rd_ext, hs->frag_len,
                                         &tmp, NULL ) );
        MPS_CHK( mbedtls_reader_commit_ext( hs->rd_ext ) );
        MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );
        RETURN( MBEDTLS_MPS_REASSEMBLY_FEED_NEED_MORE );
    }

    /* Check if the message has already been initialized. */
    reassembly = &in->reassembly[ seq_nr_offset ];

    if( reassembly->status == MBEDTLS_MPS_REASSEMBLY_NO_FRAGMENTATION )
    {
        TRACE( trace_error, "Attempt to feed a fragment for a message that has previously been fully received." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    if( reassembly->status == MBEDTLS_MPS_REASSEMBLY_NONE )
    {
        uint8_t complete_msg;

        /* Sequence number not seen before. */
        TRACE( trace_comment, "Sequence number %u not seen before - setup reassembly structure.",
               (unsigned) seq_nr );

        reassembly->epoch  = hs->epoch;
        reassembly->length = hs->len;
        reassembly->type   = hs->type;

        /* If we have actually received the entire message, and it
         * is the one we expect next, don't use reassembly but forward
         * the reader from Layer 3. */
        complete_msg = ( hs->frag_offset == 0 ) &&
                       ( hs->frag_len    == hs->len );
        if( seq_nr_offset == 0 && complete_msg )
        {
            TRACE( trace_comment, "Received next expected handshake message in a single fragment." );
            reassembly->status = MBEDTLS_MPS_REASSEMBLY_NO_FRAGMENTATION;
            reassembly->data.rd_ext_l3 = hs->rd_ext;
            RETURN( 0 );
        }
        else
        {
            size_t bitmask_len, msg_len;
            unsigned char *bitmask;
            unsigned char *buf;
            TRACE( trace_comment, "Feed handshake message into reassembler." );

            /* For proper fragments of the next expected message,
             * or for any fragments (even full ones) belonging
             * to future messages, use a reassembly window. */

            msg_len     = hs->len;
            /* Slightly overapproximate the size of the bitmask, at the
             * benefit of simplifying the call to mps_bitmask_set() below
             * as well as the implementation of mps_bitmask_check(). */
            bitmask_len = msg_len / 8 + 2;
            buf         = mbedtls_calloc( 1, msg_len + bitmask_len );
            bitmask     = buf + msg_len;

            if( buf == NULL )
                MPS_CHK( MBEDTLS_ERR_MPS_OUT_OF_MEMORY );

            memset( bitmask, 0xFF, bitmask_len );
            mps_bitmask_set( bitmask, msg_len, 8 );

            reassembly->data.window.bitmask     = bitmask;
            reassembly->data.window.buf_len     = msg_len;
            reassembly->data.window.buf         = buf;

            reassembly->status = MBEDTLS_MPS_REASSEMBLY_WINDOW;
        }
    }
    else
    {
        /* Check consistency of parameters across fragments. */
        if( hs->epoch != reassembly->epoch ||
            hs->type  != reassembly->type  ||
            hs->len   != reassembly->length )
        {
            TRACE( trace_error, "Inconsistent parameters (%u,%u,%u) != (%u,%u,%u) for fragments of HS msg of sequence number %u",
                   (unsigned) hs->epoch,        (unsigned) hs->type,
                   (unsigned) hs->len,          (unsigned) reassembly->epoch,
                   (unsigned) reassembly->type, (unsigned) reassembly->length,
                   (unsigned) seq_nr );
            MPS_CHK( MBEDTLS_ERR_MPS_BAD_FRAGMENTATION );
        }
    }

    /* We don't have to check frag_offset and frag_len,
     * as this is already done by Layer 3. */

    /* No `else` because we want to fall through in case the
     * initial status was #MPS_REASSEMBLY_NONE. */
    if( reassembly->status == MBEDTLS_MPS_REASSEMBLY_WINDOW )
    {
        unsigned char* bitmask = reassembly->data.window.bitmask;
        unsigned char *frag_content;
        TRACE( trace_comment, "Contribute to ongoing reassembly." );

        MPS_CHK( mbedtls_reader_get_ext( hs->rd_ext, hs->frag_len,
                                         &frag_content, NULL ) );
        memcpy( reassembly->data.window.buf + hs->frag_offset,
                frag_content, hs->frag_len );
        MPS_CHK( mbedtls_reader_commit_ext( hs->rd_ext ) );
        MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );

        if( bitmask != NULL )
        {
            /* Add the fragment to the current reassembly window. */
            mps_bitmask_set( bitmask, hs->frag_offset, hs->frag_len );

            /* Check if message is complete now. */
            if( mps_bitmask_check( bitmask, hs->len ) == 0 )
            {
                /* Free bitmask to indicate that the message is complete. */
                TRACE( trace_comment, "Message fully reassembled." );
                reassembly->data.window.bitmask = NULL;
                MPS_CHK( mps_reassembly_next_msg_complete( mps ) );
            }
            else
            {
                TRACE( trace_comment, "Reassembly incomplete -- need more fragments." );
                RETURN( MBEDTLS_MPS_REASSEMBLY_FEED_NEED_MORE );
            }
        }

        if( seq_nr_offset != 0 )
            RETURN( MBEDTLS_MPS_REASSEMBLY_FEED_NEED_MORE );
    }

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_reassembly_free( mbedtls_mps *mps )
{
    ((void) mps);
    TRACE_INIT( "mps_reassembly_free" );

#if defined(MBEDTLS_MPS_ASSERT)
    if( ! MBEDTLS_MPS_FLIGHT_STATE_EITHER_OR(
            mps_get_handshake_state( mps ),
            MBEDTLS_MPS_FLIGHT_RECVINIT,
            MBEDTLS_MPS_FLIGHT_RECEIVE ) )
    {
        TRACE( trace_error, "Trying to use reassembly module outside of "
                            "RECEIVE and RECVINIT state." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */

    RETURN( 0 );
}

MBEDTLS_MPS_STATIC int mps_reassembly_init( mbedtls_mps *mps )
{
    uint8_t idx;
    for( idx = 0; idx < 1 + MBEDTLS_MPS_FUTURE_MESSAGE_BUFFERS; idx++ )
    {
        mps->dtls.io.in.incoming.reassembly[idx].status =
            MBEDTLS_MPS_REASSEMBLY_NONE;
    }

    return( 0 );
}

MBEDTLS_MPS_STATIC int mps_reassembly_get_seq( mbedtls_mps *mps,
                                   uint8_t *seq_nr )
{
    TRACE_INIT( "mps_reassembly_get_seq" );

#if defined(MBEDTLS_MPS_ASSERT)
    if( ! MBEDTLS_MPS_FLIGHT_STATE_EITHER_OR(
            mps_get_handshake_state( mps ),
            MBEDTLS_MPS_FLIGHT_RECVINIT,
            MBEDTLS_MPS_FLIGHT_RECEIVE ) )
    {
        TRACE( trace_error, "Trying to use reassembly module outside of "
                            "RECEIVE and RECVINIT state." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */

    *seq_nr = mps->dtls.seq_nr;
    RETURN( 0 );
}

MBEDTLS_MPS_STATIC int mps_reassembly_check( mbedtls_mps *mps )
{
    mbedtls_mps_reassembly const * in;
    mbedtls_mps_msg_reassembly const * reassembly;
    TRACE_INIT( "mps_reassembly_check" );

#if defined(MBEDTLS_MPS_ASSERT)
    if( ! MBEDTLS_MPS_FLIGHT_STATE_EITHER_OR(
            mps_get_handshake_state( mps ),
            MBEDTLS_MPS_FLIGHT_RECVINIT,
            MBEDTLS_MPS_FLIGHT_RECEIVE ) )
    {
        TRACE( trace_error, "Trying to use reassembly module outside of "
                            "RECEIVE and RECVINIT state." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */

    in = &mps->dtls.io.in.incoming;
    reassembly = &in->reassembly[0];

    switch( reassembly->status )
    {
        case MBEDTLS_MPS_REASSEMBLY_NO_FRAGMENTATION:
            RETURN( 0 );

        case MBEDTLS_MPS_REASSEMBLY_WINDOW:
            if( reassembly->data.window.bitmask == NULL )
                RETURN( 0 );

            /* Deliberately fall through here. */
        default:
            RETURN( 1 );
    }

}

MBEDTLS_MPS_STATIC int mps_reassembly_read( mbedtls_mps *mps,
                                mbedtls_mps_handshake_in *hs )
{
    int ret = 0;
    mbedtls_mps_reassembly * const in = &mps->dtls.io.in.incoming;
    mbedtls_mps_msg_reassembly * reassembly = &in->reassembly[0];
    TRACE_INIT( "mps_reassembly_read" );

#if defined(MBEDTLS_MPS_ASSERT)
    if( ! MBEDTLS_MPS_FLIGHT_STATE_EITHER_OR(
            mps_get_handshake_state( mps ),
            MBEDTLS_MPS_FLIGHT_RECVINIT,
            MBEDTLS_MPS_FLIGHT_RECEIVE ) )
    {
        TRACE( trace_error, "Trying to use reassembly module outside of "
                            "RECEIVE and RECVINIT state." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */

    hs->length = reassembly->length;
    hs->type   = reassembly->type;
    TRACE( trace_comment, "Length: %u", (unsigned) hs->length );
    TRACE( trace_comment, "Type:   %u", (unsigned) hs->type   );

    /* TODO: Add additional data (sequence number). */

    if( reassembly->status == MBEDTLS_MPS_REASSEMBLY_NO_FRAGMENTATION )
    {
        TRACE( trace_comment, "Handshake message received as single fragment on Layer 3 - pass on to user." );
        /* The message has been received in a single fragment
         * from Layer 3, and we can pass that on to the user. */
        hs->handle = reassembly->data.rd_ext_l3;
    }
    else if( reassembly->status == MBEDTLS_MPS_REASSEMBLY_WINDOW &&
             reassembly->data.window.bitmask == NULL )
    {
        TRACE( trace_comment, "Fully reassembled handshake messaged" );
        hs->handle = &in->rd_ext;
    }
    else
    {
        /* We should never call this function unless we know
         * that a message is ready. */
        TRACE( trace_comment, "Should never call mps_reassembly_read unless it is known that a message is ready." );
        MPS_CHK( MPS_ERR_INTERNAL_ERROR );
    }

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_reassembly_done( mbedtls_mps *mps )
{
    int ret = 0;
    uint8_t idx;
    mbedtls_mps_reassembly * const in = &mps->dtls.io.in.incoming;
    mbedtls_mps_msg_reassembly * reassembly = &in->reassembly[0];
    TRACE_INIT( "mps_reassembly_done" );

#if defined(MBEDTLS_MPS_ASSERT)
    if( ! MBEDTLS_MPS_FLIGHT_STATE_EITHER_OR(
            mps_get_handshake_state( mps ),
            MBEDTLS_MPS_FLIGHT_RECVINIT,
            MBEDTLS_MPS_FLIGHT_RECEIVE ) )
    {
        TRACE( trace_error, "Trying to use reassembly module outside of "
                            "RECEIVE and RECVINIT state." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */

    if( reassembly->status == MBEDTLS_MPS_REASSEMBLY_WINDOW )
    {
        mbedtls_free( reassembly->data.window.buf );
        /* The bitmask is freed as soon as the fragmentation completes. */

        MPS_CHK( mbedtls_reader_check_done( &in->rd_ext ) );
        mbedtls_reader_free_ext( &in->rd_ext );
        mbedtls_reader_free    ( &in->rd     );
    }
    else
    {
        MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );
    }

    /* Shift array of reassembly structures. */
#if MBEDTLS_MPS_FUTURE_MESSAGE_BUFFERS > 0
    for( idx = 0; idx < MBEDTLS_MPS_FUTURE_MESSAGE_BUFFERS; idx++ )
        in->reassembly[idx] = in->reassembly[idx + 1];
#else
    ((void) idx);
#endif

    reassembly = &in->reassembly[ MBEDTLS_MPS_FUTURE_MESSAGE_BUFFERS ];
    reassembly->status = MBEDTLS_MPS_REASSEMBLY_NONE;

    mps->dtls.seq_nr++;
    if( mps->dtls.seq_nr == MBEDTLS_MPS_LIMIT_SEQUENCE_NUMBER )
    {
        TRACE( trace_error, "Reached maximum incoming sequence number %u",
               (unsigned) MBEDTLS_MPS_LIMIT_SEQUENCE_NUMBER );
        MPS_CHK( MBEDTLS_ERR_MPS_COUNTER_WRAP );
    }

    MPS_CHK( mps_reassembly_next_msg_complete( mps ) );

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_reassembly_next_msg_complete( mbedtls_mps *mps )
{
    int ret = 0;
    mbedtls_mps_reassembly * const in = &mps->dtls.io.in.incoming;
    mbedtls_mps_msg_reassembly * const reassembly = &in->reassembly[0];
    TRACE_INIT( "mps_reassembly_next_msg_complete" );

#if defined(MBEDTLS_MPS_ASSERT)
    if( ! MBEDTLS_MPS_FLIGHT_STATE_EITHER_OR(
            mps_get_handshake_state( mps ),
            MBEDTLS_MPS_FLIGHT_RECVINIT,
            MBEDTLS_MPS_FLIGHT_RECEIVE ) )
    {
        TRACE( trace_error, "Trying to use reassembly module outside of "
                            "RECEIVE and RECVINIT state." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */

    if( reassembly->status == MBEDTLS_MPS_REASSEMBLY_WINDOW &&
        reassembly->data.window.bitmask == NULL )
    {
        TRACE( trace_comment, "Next message already fully available." );
        mbedtls_reader_init( &in->rd, NULL, 0 );
        mbedtls_reader_init_ext( &in->rd_ext, reassembly->length );
        MPS_CHK( mbedtls_reader_attach( &in->rd_ext, &in->rd ) );
        MPS_CHK( mbedtls_reader_feed( &in->rd,
                                      reassembly->data.window.buf,
                                      reassembly->data.window.buf_len ) );
    }
    else
    {
        TRACE( trace_comment, "Next message not yet available." );
    }

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_reassembly_pause( mbedtls_mps *mps )
{
    ((void) mps);
    TRACE_INIT( "mps_reassembly_pause" );

#if defined(MBEDTLS_MPS_ASSERT)
    if( ! MBEDTLS_MPS_FLIGHT_STATE_EITHER_OR(
            mps_get_handshake_state( mps ),
            MBEDTLS_MPS_FLIGHT_RECVINIT,
            MBEDTLS_MPS_FLIGHT_RECEIVE ) )
    {
        TRACE( trace_error, "Trying to use reassembly module outside of "
                            "RECEIVE and RECVINIT state." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */

    RETURN( MPS_ERR_UNSUPPORTED_FEATURE );
}

MBEDTLS_MPS_STATIC int mps_reassembly_forget( mbedtls_mps *mps )
{
    uint8_t idx;
    int ret = 0;
    mbedtls_mps_reassembly * const in = &mps->dtls.io.in.incoming;
    TRACE_INIT( "mps_reassembly_forget" );

#if defined(MBEDTLS_MPS_ASSERT)
    if( ! MBEDTLS_MPS_FLIGHT_STATE_EITHER_OR(
            mps_get_handshake_state( mps ),
            MBEDTLS_MPS_FLIGHT_RECVINIT,
            MBEDTLS_MPS_FLIGHT_RECEIVE ) )
    {
        TRACE( trace_error, "Trying to use reassembly module outside of "
                            "RECEIVE and RECVINIT state." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */

    /* Check that there are no more buffered messages.
     * This catches the situation where the peer sends
     * more messages than expected. */
#if MBEDTLS_MPS_FUTURE_MESSAGE_BUFFERS > 0
    for( idx = 0; idx < MBEDTLS_MPS_FUTURE_MESSAGE_BUFFERS; idx++ )
        {
            if( in->reassembly[idx].status != MBEDTLS_MPS_REASSEMBLY_NONE )
                MPS_CHK( MPS_ERR_INTERNAL_ERROR );
        }
#else
    ((void) idx);
    ((void) in);
    MPS_CHK( 0 );
#endif

    MPS_INTERNAL_FAILURE_HANDLER
}

/*
 * Outgoing flight retransmission
 */

MBEDTLS_MPS_STATIC int mps_retransmit_out( mbedtls_mps *mps )
{
    return( mps_retransmit_out_core( mps, MPS_RETRANSMIT_FULL_FLIGHT ) );
}

MBEDTLS_MPS_STATIC int mps_retransmit_out_core( mbedtls_mps *mps,
                                    uint8_t mode )
{
    int ret = 0;
    uint8_t offset;
    mbedtls_mps_retransmission_handle *handle;
    TRACE_INIT( "mps_retransmit_out" );

    if( mps->dtls.wait.resend_offset == 0 )
    {
        TRACE( trace_comment, "Start retransmission of last outgoing flight of length %u",
               (unsigned) mps->dtls.outgoing.flight_len );
    }
    else
    {
        TRACE( trace_comment, "Continue retransmission of last outgoing flight of length %u at message %u.",
               (unsigned) mps->dtls.outgoing.flight_len,
               (unsigned) mps->dtls.wait.resend_offset );
    }

    offset = mps->dtls.wait.resend_offset;
    handle = &mps->dtls.outgoing.backup[offset];

    while( offset < mps->dtls.outgoing.flight_len )
    {
        TRACE( trace_comment, "Retransmitting message %u of last outgoing flight.",
               (unsigned) offset );

        if( mode == MPS_RETRANSMIT_FULL_FLIGHT )
        {
            ret = mbedtls_mps_retransmission_handle_resend( mps, handle );
            if( ret != 0 && ret != MBEDTLS_MPS_RETRANSMISSION_HANDLE_UNFINISHED )
                MPS_CHK( ret );
        }
        else /* if( mode == MPS_RETRANSMIT_ONLY_EMPTY_FRAGMENTS ) */
        {
            ret = mbedtls_mps_retransmission_handle_resend_empty( mps, handle );
        }

        if( ret == 0 )
        {
            /* TODO: Ensure and document some progress guarantee here
             *       to exclude the possibility of infinite looping! */
            offset++;
            handle++;
        }
    }

    MPS_CHK( mbedtls_mps_flush( mps ) );

exit:
    mps->dtls.wait.resend_offset = offset;

    /* No failure handler for internal functions. */
    RETURN( ret );
}

/*
 * Incoming flight retransmission request
 *
 * (In DTLS 1.0 and 1.2, this is done by resending the last
 *  outgoing flight; in DTLS 1.3, it's done using ACK's.)
 */

MBEDTLS_MPS_STATIC int mps_request_resend( mbedtls_mps *mps )
{
    TRACE_INIT( "mps_request_send" );
    /* TLS-1.3-NOTE: This needs to be handled through ACK's
     *               in DTLS 1.3. */
    RETURN( mps_retransmit_out_core( mps,
                                     MPS_RETRANSMIT_ONLY_EMPTY_FRAGMENTS ) );
}

static inline const char * mps_flight_state_to_string(
    mbedtls_mps_flight_state_t state )
{
    switch( state )
    {
        case MBEDTLS_MPS_FLIGHT_AWAIT:
            return( "AWAIT" );
        case MBEDTLS_MPS_FLIGHT_SEND:
            return( "SEND" );
        case MBEDTLS_MPS_FLIGHT_RECVINIT:
            return( "RECVINIT" );
        case MBEDTLS_MPS_FLIGHT_RECEIVE:
            return( "RECEIVE" );
        case MBEDTLS_MPS_FLIGHT_FINALIZE:
            return( "FINALIZE" );
        case MBEDTLS_MPS_FLIGHT_PREPARE:
            return( "PREPARE" );
        case MBEDTLS_MPS_FLIGHT_DONE:
            return( "DONE" );
        default:
            return( "UNKNOWN" );
    }
}

MBEDTLS_MPS_INLINE
/* Perform a retransmisison state machine transition and
 * all necessary initialization/freeing of internal structures.
 *
 * The `old` state parameter indicates the expected current state
 * of the state machine and is hence redundant in ordinary runs;
 * it is passed solely as a safeguard.
 */
int mps_handshake_state_transition( mbedtls_mps *mps,
                                    mbedtls_mps_flight_state_t old,
                                    mbedtls_mps_flight_state_t new )
{
    int ret = 0;
    TRACE_INIT( "mps_handshake_state_transition, old %u (%s), new %u (%s)",
                (unsigned) old, mps_flight_state_to_string( old ),
                (unsigned) new, mps_flight_state_to_string( new ) );
#if defined(MBEDTLS_MPS_ASSERT)
    if( mps_get_handshake_state( mps ) != old )
    {
        TRACE( trace_error, "Mismatched flight state: expected %u (%s), got %u (%s)",
               (unsigned) old, mps_flight_state_to_string( old ),
               (unsigned) mps_get_handshake_state( mps ),
               mps_flight_state_to_string(
                   mps_get_handshake_state( mps ) ) );
        MPS_CHK( MBEDTLS_ERR_MPS_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */

    if( old == MBEDTLS_MPS_FLIGHT_AWAIT &&
        new == MBEDTLS_MPS_FLIGHT_RECEIVE )
    {
        /* The first message not recognized as a retransmission implicitly
         * acknowledges the last outgoing flight. We may therefore forget
         * about the last incoming flight and make space for the new one. */
        MPS_CHK( mps_retransmit_in_forget( mps ) );

        MPS_CHK( mps_reassembly_init( mps ) );
    }
    else
    if( old == MBEDTLS_MPS_FLIGHT_DONE &&
        new == MBEDTLS_MPS_FLIGHT_RECVINIT )
    {
        MPS_CHK( mps_reassembly_init( mps ) );
    }
    else
    if( old == MBEDTLS_MPS_FLIGHT_DONE &&
        new == MBEDTLS_MPS_FLIGHT_SEND )
    {
        MPS_CHK( mps_out_flight_init( mps ) );
        MPS_CHK( mps_retransmit_in_init( mps ) );
    }
    else
    if( old == MBEDTLS_MPS_FLIGHT_FINALIZE &&
        new == MBEDTLS_MPS_FLIGHT_DONE )
    {
        mps_retransmission_timer_stop( mps );
        MPS_CHK( mps_out_flight_free( mps ) );
        MPS_CHK( mps_retransmit_in_free( mps ) );
    }
    else
    if( old == MBEDTLS_MPS_FLIGHT_RECVINIT &&
        new == MBEDTLS_MPS_FLIGHT_RECEIVE )
    {
        MPS_CHK( mps_out_flight_init( mps ) );
        MPS_CHK( mps_retransmit_in_init( mps ) );
        mps->dtls.wait.retransmit_timeout =
                mbedtls_mps_conf_get_hs_timeout_min( &mps->conf );
        MPS_CHK( mps_retransmission_timer_update( mps ) );
    }
    else
    if( old == MBEDTLS_MPS_FLIGHT_RECVINIT &&
        new == MBEDTLS_MPS_FLIGHT_DONE )
    {
        /* Clear the reassembly module; this fails if we attempt
         * to close a flight if there are still some future messages
         * buffered; this could happen e.g. if a Client sends its
         * ClientKeyExchange immediately after the ClientHello,
         * not waiting until it has received the ServerHello,
         * and the server receives and buffer the ClientKeyExchange
         * before the ClientHello.
         *
         * TODO: Does this endanger compatibility? */
        MPS_CHK( mps_reassembly_forget( mps ) );

        /* It is possible that we have already received some handshake
         * message fragments from the peer -- delete these. See the
         * documentation of mbedtls_mps_retransmission_handle_incoming_fragment()
         * for more information on this choice of behavior. */
        MPS_CHK( mps_reassembly_free( mps ) );
    }
    else
    if( old == MBEDTLS_MPS_FLIGHT_RECEIVE &&
        new == MBEDTLS_MPS_FLIGHT_PREPARE )
    {
        /* Clear memory of last outgoing flight.
         * NOTE: Logically, we should remove this when switching from state
         *       #MBEDTLS_MPS_FLIGHT_AWAIT to #MBEDTLS_MPS_FLIGHT_RECEIVE;
         *       see the corresponding comments in
         *       \c mbedtls_mps_retransmission_handle_incoming_fragment()
         *       for more. */
        MPS_CHK( mps_out_flight_free( mps ) );

        /* As for RECVINIT -> DONE */
        MPS_CHK( mps_reassembly_forget( mps ) );
        MPS_CHK( mps_reassembly_free( mps ) );

        /* Keep memory of last incoming flight intact. */
    }
    else
    if( old == MBEDTLS_MPS_FLIGHT_PREPARE &&
        new == MBEDTLS_MPS_FLIGHT_SEND )
    {
        MPS_CHK( mps_out_flight_init( mps ) );
    }
    else
    if( old == MBEDTLS_MPS_FLIGHT_RECEIVE &&
        new == MBEDTLS_MPS_FLIGHT_DONE )
    {
        MPS_CHK( mps_out_flight_free( mps ) );
        MPS_CHK( mps_retransmit_in_free( mps ) );
        MPS_CHK( mps_reassembly_free( mps ) );
        MPS_CHK( mps_reassembly_init( mps ) );
    }
    else
    if( old == MBEDTLS_MPS_FLIGHT_SEND &&
        new == MBEDTLS_MPS_FLIGHT_AWAIT )
    {
    }
    else
    if( old == MBEDTLS_MPS_FLIGHT_SEND &&
        new == MBEDTLS_MPS_FLIGHT_FINALIZE )
    {
    }
    else
#if defined(MBEDTLS_MPS_ASSERT)
    {
        TRACE( trace_error, "Unknown state transition!" );
        MPS_CHK( MBEDTLS_ERR_MPS_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */

    mps->dtls.state = new;

    TRACE( trace_comment, "State transition from %u to %u done.",
           (unsigned) old, (unsigned) new );
    MPS_INTERNAL_FAILURE_HANDLER
}

/*
 * Main interface to the reading side of the retransmission state machine.
 */

MBEDTLS_MPS_STATIC
int mbedtls_mps_retransmission_handle_incoming_fragment( mbedtls_mps *mps )
{
    int ret = 0;
    mps_l3_handshake_in hs_l3;
    TRACE_INIT( "mps_retransmission_handle_incoming_fragment" );

    /*
     * When we reach this code-path, the flight state is either
     * #MBEDTLS_MPS_FLIGHT_RECEIVE, #MBEDTLS_MPS_FLIGHT_FINALIZE
     * #MBEDTLS_MPS_FLIGHT_DONE. We comment on them separately:
     * - #MBEDTLS_MPS_FLIGHT_FINALIZE
     *   In this case, the incoming fragment might either be a
     *   retransmission from the last incoming flight, or the
     *   initiation of a new handshake. It is only after we have
     *   checked that it is not a retransmission that we may
     *   wrapup the current handshake and start a new one.
     * - #MBEDTLS_MPS_FLIGHT_DONE
     *   In case an entire, non-fragmented handshake message arrives,
     *   we pass it to the user and switch to receiving state.
     *   However, if a fragmented message arrives, it's not
     *   clear how to behave -- concretely, imagine the following DTLS
     *   scenario: After the initial handshake has completed, the
     *   client sends multiple ClientHello fragments to the server in order
     *   to start a renegotiation, but only some reach the server.
     *   At the same time, the server attempts to start a renegotiation
     *   by sending a HelloRequest. There are options to deal with that:
     *   1 MPS switches to Receiving state silently as soon as it
     *     receives the first ClientHello fragment(s). Consequently,
     *     it blocks the server's attempt to send the HelloRequest
     *     (sending in Receiving state is not allowed).
     *     This is not optimal because from the server's perspective
     *     no handshake is in progress, hence it should be possible to
     *     start a new one via writing a HelloRequest.
     *   2 MPS remembers the ClientHello fragments, but does not yet
     *     switch to Receive state. When the server attempts to send
     *     the HelloRequest, all buffered fragments are erased and
     *     MPS switches to send state as if nothing had been received.
     *     This is not optimal because it will lead to the client
     *     receiving a HelloRequest when expecting a ServerHello,
     *     and also to the dropping of the fragments of the ClientHello
     *     that have already been received.
     *   While both alternatives have their drawback, variant 2
     *   seems preferable because it introduces no problems that
     *   were not already there beforehand: It might be that Client
     *   and Server start renegotiation simultaenously and that the
     *   ClientHello gets lost entirely, leading to the same situation
     *   as in variant 2. In contrast, variant 1 adds the undesirable
     *   possibility of the user's perception of the flight state
     *   getting out of sync with the actual flight state.
     */

    TRACE( trace_comment, "Fetch new fragment from Layer 3" );
    MPS_CHK( mps_l3_read_handshake( mps->conf.l3, &hs_l3 ) );

    /* 1. Check if the message is recognized as a retransmission
     *    from an old flight. */

    if( MBEDTLS_MPS_FLIGHT_STATE_EITHER_OR(
            mps_get_handshake_state( mps ),
            MBEDTLS_MPS_FLIGHT_AWAIT,
            MBEDTLS_MPS_FLIGHT_FINALIZE ) )
    {
        TRACE( trace_comment, "Check if the fragment is a retransmission from an old flight." );
        ret = mps_retransmit_in_check( mps, &hs_l3 );

        if( ret == MBEDTLS_ERR_MPS_FLIGHT_RETRANSMISSION )
        {
            mbedtls_reader_ext *hs_rd_ext;
            unsigned char *tmp;

            /* Message is a retransmission from the last incoming flight. */
            TRACE( trace_comment, "Retransmission detected - retransmit last flight." );

            /* Layer 3 will error out if we don't fully consume a fragment,
             * so fetch and commit it even if we don't consider the contents. */
            /* TODO: This could be moved to an 'abort' function on Layer 3. */
            hs_rd_ext = hs_l3.rd_ext;
            MPS_CHK( mbedtls_reader_get_ext( hs_rd_ext, hs_l3.frag_len, &tmp, NULL ) );
            MPS_CHK( mbedtls_reader_commit_ext( hs_rd_ext ) );

            /* Mark handshake fragment as processed before starting
             * the retransmission, which might return WANT_WRITE. */
            MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );

            /* TODO: Extract to function */
            mps->dtls.retransmit_state = MBEDTLS_MPS_RETRANSMIT_RESEND;
            mps->dtls.wait.resend_offset = 0;

            MPS_CHK( mps_check_retransmit( mps ) );
            MPS_CHK( MBEDTLS_ERR_MPS_NO_FORWARD );
        }
        else
            MPS_CHK( ret );

        TRACE( trace_comment, "Fragment not recognized as a retransmission." );

        /* Logically, we should also be able to forget about our last
         * outgoing flight, because we know that our peer has already
         * fully received it. However, in DTLS 1.0 and 1.2, the only
         * way to inform the peer that messages from his next flight
         * are missing is by retransmitting our own last outgoing
         * flight, so we have to keep that until we switch to state
         * #MBEDTLS_MPS_FLIGHT_SEND.
         * In DTLS 1.3, we can get rid of the last outgoing flight
         * already here, which is allows a considerable saving of RAM.
         *
         * NOTE: What we could do as a remedy is to retransmit
         *       empty fragments of the messages of the last
         *       flight in case we want to request a retransmission
         *       from the peer. This way, we could free the raw
         *       backup buffers at this point.
         */

        if( mps_get_handshake_state( mps ) == MBEDTLS_MPS_FLIGHT_AWAIT )
        {
            TRACE( trace_comment, "Switch from AWAIT to RECEIVE state" );
            MPS_CHK( mps_handshake_state_transition( mps,
                                                 MBEDTLS_MPS_FLIGHT_AWAIT,
                                                 MBEDTLS_MPS_FLIGHT_RECEIVE ) );
        }
        else /* if( mps_get_handshake_state( mps )
                      == MBEDTLS_MPS_FLIGHT_FINALIZE ) */
        {
            TRACE( trace_comment, "Switch from FINALIZE to DONE state" );
            MPS_CHK( mps_handshake_state_transition( mps,
                                                 MBEDTLS_MPS_FLIGHT_FINALIZE,
                                                 MBEDTLS_MPS_FLIGHT_DONE ) );
        }
    }

    if( mps_get_handshake_state( mps ) == MBEDTLS_MPS_FLIGHT_DONE )
    {
        mbedtls_mps_hs_seq_nr_t seq_nr = hs_l3.seq_nr;

        /* Only start handshakes with initial handshake fragments.
         *
         * This is a heuristic to deal especially with the following situation:
         * If a DTLS server receives a proper fragment of a ClientHello message
         * without cookie, which is large enough to determine that there's no
         * cookie to follow, then the server might send its HelloVerifyRequest
         * straight away and reset in order to avoid allocation of state.
         * If subsequent later fragments of the ClientHello are still in flight,
         * they might be received by the re-started server earlier than the new
         * ClientHello that contains the cookie, and they would therefore
         * mistakenly be viewed as initiating a new handshake. In particular,
         * they would miscalibrate the server's initial handshake sequence number
         * to 0, leading to discarding or indefinite buffering of the new
         * ClientHello+Cookie, which will have handshake sequence number 1.
         *
         * To deal with this situation, we only consider initial fragments
         * when starting new handshakes.
         *
         * NOTE: So far, MPS is _not_ DoS resistant in the face of fragmented
         *       ClientHello's: If a proper fragment of a ClientHello comes in,
         *       it be fed into a new reassembly structure as for any other message.
         *       This needs to be changed at some point. */
        if( hs_l3.frag_offset != 0 )
        {
            mbedtls_reader_ext *hs_rd_ext;
            unsigned char *tmp;

            TRACE( trace_comment, "Discard non-initial fragments outside of handshake." );

            /* Layer 3 will error out if we don't fully consume a fragment,
             * so fetch and commit it even if we don't consider the contents. */
            /* TODO: This could be moved to an 'abort' function on Layer 3. */
            hs_rd_ext = hs_l3.rd_ext;
            MPS_CHK( mbedtls_reader_get_ext( hs_rd_ext, hs_l3.frag_len, &tmp, NULL ) );
            MPS_CHK( mbedtls_reader_commit_ext( hs_rd_ext ) );

            MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );
            MPS_CHK( MBEDTLS_ERR_MPS_NO_FORWARD );
        }

        /* DTLS suffers from the following ambiguity:
         * For the purpose of DoS mitigation a server receiving
         * a cookieless ClientHello may reply with a HelloVerifyRequest
         * including a cookie and wait for the client to
         * retransmit the ClientHello+Cookie before allocating any state
         * and continuing with the actual handshake. In this scenario,
         * the second ClientHello and the ServerHello shall have
         * sequence number 1 according to Sect 4.2.2 of RFC 6347.
         * This is in conflict with the requirement that the server
         * must not maintain state after sending its HelloVerifyRequest,
         * as initially both the incoming and outgoing handshake sequence
         * numbers are 0.
         *
         * MPS deals with this ambiguity in the same way as the
         * previous messaging layer implementation does, by accepting
         * any sequence number for an incoming handshake message initiating
         * a handshake, and always using the same sequence number for its reply.
         */
        mps->dtls.seq_nr = seq_nr;
        MPS_CHK( mps_handshake_state_transition( mps,
                                               MBEDTLS_MPS_FLIGHT_DONE,
                                               MBEDTLS_MPS_FLIGHT_RECVINIT ) );
    }

    /* 2. Feed the handshake fragment into the reassembly module.
     *
     * TLS-1.3-NOTE: In DTLS-1.3, we have to record the record
     *               sequence number of the incoming fragment
     *               somewhere to send ACK messages.
     *
     * To this end, we need to distinguish between handshake fragments that
     * belonged to the incoming flight but did not yet allow to complete
     * the next handshake message, and those that were dropped because
     * they were irrelevant: The former may be ACK'ed, the latter not.
     *
     * Also, the reassembly module should indicate 'disruption' in the
     * flight receival to allow to decide when to ACK the messages received
     * so far -- quoting DTLS 1.3 Draft 28:
     *
     * > Implementations have some discretion about when to
     * > generate ACKs, but it is RECOMMENDED that they do so under two
     * > circumstances:
     * > -  When they receive a message or fragment which is out of order,
     * >    either because it is not the next expected message or because it
     * >    is not the next piece of the current message.  Implementations
     * >    MUST NOT send ACKs for handshake messages which they discard as
     * >    out-of-order, because otherwise those messages will not be
     * >    retransmitted.
     * > -  When they have received part of a flight and do not immediately
     * >    receive the rest of the flight (which may be in the same UDP
     * >    datagram).  A reasonable approach here is to set a timer for 1/4
     * >    the current retransmit timer value when the first record in the
     * >    flight is received and then send an ACK when that timer expires.
     *
     */

    TRACE( trace_comment, "Feed fragment into reassembly module." );
    ret = mps_reassembly_feed( mps, &hs_l3 );
    if( ret == MBEDTLS_MPS_REASSEMBLY_FEED_NEED_MORE )
    {
        /* The current fragment didn't lead to the next handshake
         * message being ready. That might be because it contributed
         * to a future message, or because the next message isn't
         * fully reassembled yet. */
        MPS_CHK( MBEDTLS_ERR_MPS_NO_FORWARD );
    }
    else
        MPS_CHK( ret );

    if( mps_get_handshake_state( mps ) == MBEDTLS_MPS_FLIGHT_RECVINIT )
    {
        uint64_t rec_ctr;

        MPS_CHK( mps_handshake_state_transition(
                     mps,
                     MBEDTLS_MPS_FLIGHT_RECVINIT,
                     MBEDTLS_MPS_FLIGHT_RECEIVE ) );

        /* TODO: Move this logic to Layer 2 -- mirror the sequence
         * number when the first operation is the receipt of an
         * incoming record. That avoids the abstraction break
         * and saves some code. */
        MPS_CHK( mps_l3_get_last_sequence_number( mps->conf.l3,
                                                  hs_l3.epoch,
                                                  &rec_ctr ) );

        TRACE( trace_comment, "Mirror record sequence number %u when responding to initial message.",
               (unsigned) rec_ctr );
        MPS_CHK( mps_l3_force_next_sequence_number( mps->conf.l3,
                                                    hs_l3.epoch,
                                                    rec_ctr ) );
    }

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_retransmission_finish_incoming_message( mbedtls_mps *mps )
{
    int ret;
    uint8_t flags;
    uint8_t seq_nr;
    TRACE_INIT( "mps_retransmission_finish_incoming_message" );

    /* Remember parts of message to detect retransmission.
     * Currently, we're only remembering the epoch and the
     * sequence number, so we don't need the actual HS handle
     * here. This might change in the future. */
    MPS_CHK( mps_reassembly_get_seq( mps, &seq_nr ) );
    MPS_CHK( mps_retransmit_in_remember( mps, NULL, seq_nr ) );

    /* Inform the buffering submodule that the newest message has been read. */
    MPS_CHK( mps_reassembly_done( mps ) );

    /* Update retransmission state machine. */
    flags = mps->in.flags & MBEDTLS_MPS_FLIGHT_MASK;
    if( flags == MBEDTLS_MPS_FLIGHT_END     ||
        flags == MBEDTLS_MPS_FLIGHT_FINISHED )
    {
        MPS_CHK( mps_retransmission_timer_stop( mps ) );
    }

    if( flags == MBEDTLS_MPS_FLIGHT_END )
    {
        TRACE( trace_comment, "Incoming message ends a flight. Switch to PREPARE state." );

        MPS_CHK( mps_handshake_state_transition(
                     mps,
                     MBEDTLS_MPS_FLIGHT_RECEIVE,
                     MBEDTLS_MPS_FLIGHT_PREPARE ) );
    }
    else if( flags == MBEDTLS_MPS_FLIGHT_FINISHED )
    {
        TRACE( trace_comment, "Incoming message ends a flight-exchange. Switch to DONE state." );
        MPS_CHK( mps_handshake_state_transition(
                     mps,
                     MBEDTLS_MPS_FLIGHT_RECEIVE,
                     MBEDTLS_MPS_FLIGHT_DONE ) );
    }
    else
    {
        TRACE( trace_comment, "Incoming message not the last one in its flight. Keep RECEIVE state." );
    }

    mps->in.flags = 0;

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_retransmission_pause_incoming_message( mbedtls_mps *mps )
{
    int ret = 0;
    MPS_CHK( mps_reassembly_pause( mps ) );
    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_out_flight_init( mbedtls_mps *mps )
{
    mps->dtls.io.out.flags      = 0;
    mps->dtls.outgoing.flight_len = 0;
    return( 0 );
}

MBEDTLS_MPS_STATIC int mps_out_flight_free( mbedtls_mps *mps )
{
    int ret = 0;
    uint8_t idx, flight_len;
    mbedtls_mps_retransmission_handle *handle;
    TRACE_INIT( "mps_out_flight_free" );

    flight_len =  mps->dtls.outgoing.flight_len;
    handle     = &mps->dtls.outgoing.backup[0];
    TRACE( trace_comment, "Flight length: %u", (unsigned) flight_len );

    for( idx=0; idx < flight_len; idx++, handle++ )
    {
        mbedtls_mps_epoch_id cur_epoch =
            handle->metadata.epoch;

        MPS_CHK( mps_l3_epoch_usage( mps->conf.l3, cur_epoch,
                                     MPS_EPOCH_USAGE_WRITE(
                                         MPS_WRITE_RETRANSMISSION ), 0 ) );

        mbedtls_mps_retransmission_handle_free( handle );
    }

    mps->dtls.outgoing.flight_len = 0;

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC void mbedtls_mps_retransmission_handle_init(
    mbedtls_mps_retransmission_handle *handle )
{
    handle->handle_type = MBEDTLS_MPS_RETRANSMISSION_HANDLE_NONE;
}

MBEDTLS_MPS_STATIC void mbedtls_mps_retransmission_handle_free(
    mbedtls_mps_retransmission_handle *handle )
{
    switch( handle->handle_type )
    {
        case MBEDTLS_MPS_RETRANSMISSION_HANDLE_HS_RAW:
        {
            unsigned char *buf;
            size_t buflen;

            buf    = handle->handle.raw.buf;
            buflen = handle->handle.raw.len;
            mbedtls_platform_zeroize( buf, buflen );

            free( buf );
            break;
        }
        default:
            break;
    }

    mbedtls_platform_zeroize( handle, sizeof( *handle ) );
}

MBEDTLS_MPS_STATIC int mbedtls_mps_retransmission_handle_resend_empty(
    mbedtls_mps *mps, mbedtls_mps_retransmission_handle *handle )
{
    int ret = 0;
    mps_l3_handshake_out hs_out_l3;
    TRACE_INIT( "mps_retransmission_handle_resend_empty" );

    hs_out_l3.epoch       = handle->metadata.epoch;
    hs_out_l3.frag_len    = 0;
    hs_out_l3.frag_offset = 0;
    hs_out_l3.len         = handle->metadata.len;
    hs_out_l3.seq_nr      = handle->metadata.seq_nr;
    hs_out_l3.type        = handle->metadata.type;
    MPS_CHK( mps_l3_write_handshake( mps->conf.l3, &hs_out_l3 ) );
    /* Don't write anything. */
    MPS_CHK( mps_l3_dispatch( mps->conf.l3 ) );

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mbedtls_mps_retransmission_handle_resend( mbedtls_mps *mps,
                                    mbedtls_mps_retransmission_handle *handle )
{
    int ret = 0;
    mbedtls_mps_handshake_out_internal * const hs = &mps->dtls.io.out.hs;

    TRACE_INIT( "mps_retransmission_handle_resend" );
    switch( handle->handle_type )
    {
        case MBEDTLS_MPS_RETRANSMISSION_HANDLE_HS_RAW:
        {
            unsigned char * backup_buf    = handle->handle.raw.buf;
            mbedtls_mps_size_t backup_len = handle->handle.raw.len;

            TRACE( trace_comment, "Retransmission via raw backup" );

            MPS_CHK( mps_clear_pending( mps, MPS_PAUSED_HS_FORBIDDEN ) );

            MPS_CHK( mps_dtls_frag_out_start( hs, backup_buf, backup_len,
                                        &handle->metadata,
                                        MPS_DTLS_FRAG_OUT_START_QUEUE_ONLY ) );

            MPS_CHK( mbedtls_writer_get_ext( &hs->wr_ext,
                                             backup_len,
                                             &backup_buf,
                                             NULL ) );
            MPS_CHK( mbedtls_writer_commit_ext( &hs->wr_ext ) );

            MPS_CHK( mps_dtls_frag_out_close( mps ) );
            MPS_CHK( mps_dtls_frag_out_dispatch( mps ) );
            break;
        }

        case MBEDTLS_MPS_RETRANSMISSION_HANDLE_HS_CALLBACK:
        {
            int cb_unfinished = 0;
            mbedtls_mps_write_cb_t      const cb  = handle->handle.callback.cb;
            mbedtls_mps_write_cb_ctx_t* const ctx = handle->handle.callback.ctx;
            TRACE( trace_comment, "Retransmission via callback" );

            MPS_CHK( mps_clear_pending( mps, MPS_PAUSED_HS_ALLOWED ) );

            if( mps->dtls.io.out.hs.state == MBEDTLS_MPS_HS_NONE )
            {
                TRACE( trace_comment, "Open new outgoing handshake message." );
                MPS_CHK( mps_dtls_frag_out_start( hs,
                                           hs->queue,
                                           hs->queue_len,
                                           &handle->metadata,
                                           MPS_DTLS_FRAG_OUT_START_USE_L3 ) );

                /* We now have a message handle in PAUSED state for the
                 * handshake message to be retransmitted. We handle this
                 * situation in the same way as the case where the callback
                 * has been called at least once but didn't yet finish
                 * the message. */
                ret = MBEDTLS_MPS_RETRANSMISSION_HANDLE_UNFINISHED;
                break;
            }
            else
            {
                TRACE( trace_comment, "Retransmission in progress -- continue." );
            }

            /* Call retransmission callback. */
            ret = cb( ctx, &hs->wr_ext );
            if( ret == MBEDTLS_MPS_RETRANSMISSION_CALLBACK_PAUSE )
                cb_unfinished = 1;
            else
                MPS_CHK( ret );

            MPS_CHK( mps_dtls_frag_out_close( mps ) );
            MPS_CHK( mps_dtls_frag_out_dispatch( mps ) );

            if( cb_unfinished == 1 )
            {
                ret = MBEDTLS_MPS_RETRANSMISSION_HANDLE_UNFINISHED;
            }
            break;
        }

        case MBEDTLS_MPS_RETRANSMISSION_HANDLE_CCS:
        {
            mps_l3_ccs_out ccs_l3;
            TRACE( trace_comment, "CCS retransmission" );
            MPS_CHK( mps_clear_pending( mps, MPS_PAUSED_HS_FORBIDDEN ) );

            ccs_l3.epoch = handle->metadata.epoch;
            MPS_CHK( mps_l3_write_ccs( mps->conf.l3, &ccs_l3 ) );
            MPS_CHK( mps_l3_dispatch( mps->conf.l3 ) );
            break;
        }
#if defined(MBEDTLS_MPS_ASSERT)
        default:
            MPS_CHK( MPS_ERR_INTERNAL_ERROR );
            break;
#endif /* MBEDTLS_MPS_ASSERT */
    }

    MPS_INTERNAL_FAILURE_HANDLER
}


MBEDTLS_MPS_STATIC int mps_dtls_frag_out_unpause( mbedtls_mps *mps,
                                      uint8_t allow_active_hs )
{
    int ret;
    TRACE_INIT( "mps_dtls_frag_out_unpause" );

    if( mps->dtls.io.out.hs.state != MBEDTLS_MPS_HS_PAUSED )
    {
        TRACE( trace_comment, "No handshake data queueing to be dispatched - skip." );
        RETURN( 0 );
    }

    /* In theory, this could loop indefinitely if we happen
     * to configure Layer 1 in such a way that the record
     * plaintext size is precisely 13 bytes.
     * It must be ensured that the Layer 1 buffer never
     * gets configured to be that small. */
    do
    {
        TRACE( trace_comment, "Fetch new HS fragment from Layer 3 to dispatch queued data." );

        ret = mps_dtls_frag_out_bind( mps );
        if( ret == 0 )
            break;
        if( ret != MBEDTLS_ERR_WRITER_NEED_MORE )
            MPS_CHK( ret );

        MPS_CHK( mps_dtls_frag_out_dispatch( mps ) );
        TRACE( trace_comment, "More data queueing" );

    } while( mps->dtls.io.out.hs.state == MBEDTLS_MPS_HS_PAUSED );

#if defined(MBEDTLS_MPS_ASSERT)
    if( mps->dtls.io.out.hs.state != MBEDTLS_MPS_HS_ACTIVE )
    {
        TRACE( trace_error, "Handshake state not ACTIVE after clearing." );
        MPS_CHK( MPS_ERR_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */

    /* Check if the handshake message has been fully written. */
    if( mbedtls_writer_check_done( &mps->dtls.io.out.hs.wr_ext ) == 0 )
    {
        TRACE( trace_comment, "Handshake message fully written." );
        MPS_CHK( mps_dtls_frag_out_close( mps ) );
        MPS_CHK( mps_dtls_frag_out_dispatch( mps ) );

        mbedtls_writer_free( &mps->dtls.io.out.hs.wr );
        mbedtls_writer_free_ext( &mps->dtls.io.out.hs.wr_ext );

        TRACE( trace_comment, "New outgoing handshake message state: MBEDTLS_MPS_HS_NONE." );
        mps->dtls.io.out.hs.state = MBEDTLS_MPS_HS_NONE;
    }
    else
    {
        /* TODO: Think about the classification of this error
         * again. Is it always an internal error, or can this
         * be triggered by malformed input data as well? */
#if defined(MBEDTLS_MPS_ASSERT)
        if( !allow_active_hs )
        {
            TRACE( trace_error, "Caller doesn't allow active handshake after this call." );
            MPS_CHK( MPS_ERR_INTERNAL_ERROR );
        }
#else
        ((void)allow_active_hs);
#endif /* MBEDTLS_MPS_ASSERT */

        TRACE( trace_comment, "Handshake message not yet fully written -- keep it open" );
    }

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_dtls_frag_out_bind( mbedtls_mps *mps )
{
    int ret;
    unsigned char *frag;
    mbedtls_mps_size_t frag_len, remaining;
    mps_l3_handshake_out l3_hs;
    mbedtls_mps_handshake_out_internal * const hs = &mps->dtls.io.out.hs;
    mbedtls_mps_msg_metadata * const metadata = mps->dtls.io.out.hs.metadata;

    TRACE_INIT( "mps_dtls_frag_out_bind" );

    /* Request a new handshake fragment from Layer 3. */
    l3_hs.type        = metadata->type;
    l3_hs.epoch       = metadata->epoch;
    l3_hs.seq_nr      = metadata->seq_nr;
    l3_hs.len         = metadata->len;
    l3_hs.frag_offset = hs->offset;
    l3_hs.frag_len    = MBEDTLS_MPS_SIZE_UNKNOWN;
    MPS_CHK( mps_l3_write_handshake( mps->conf.l3, &l3_hs ) );

    /* Extract buffer for remaining handshake content from
     * reader obtained from Layer 3. */
    hs->wr_ext_l3 = l3_hs.wr_ext;
    TRACE( trace_comment, "Get maximum length buffer from Layer 3 and feed it to writer." );
    if( metadata->len == MBEDTLS_MPS_SIZE_UNKNOWN )
        remaining = MBEDTLS_MPS_SIZE_MAX;
    else
        remaining = metadata->len - hs->offset;
    MPS_CHK( mbedtls_writer_get_ext( hs->wr_ext_l3, remaining,
                                     &frag, &frag_len ) );
    hs->frag_len = frag_len;
    TRACE( trace_comment, "Received buffer of length %u from Layer 3.",
           (unsigned) frag_len );

    /* Feed the buffer into the user-facing writer
     * used to write the handshake message. */
    ret = mbedtls_writer_feed( &hs->wr, frag, frag_len );
    if( ret == MBEDTLS_ERR_WRITER_NEED_MORE )
    {
        TRACE( trace_comment, "The Layer 3 buffer is not large enough to dispatch all queued data." );
        MPS_CHK( mbedtls_writer_commit_ext( hs->wr_ext_l3 ) );
        MPS_CHK( MBEDTLS_ERR_WRITER_NEED_MORE );
    }

    TRACE( trace_comment, "New outgoing handshake message state: MBEDTLS_MPS_HS_ACTIVE." );
    hs->state = MBEDTLS_MPS_HS_ACTIVE;

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_dtls_frag_out_close( mbedtls_mps *mps )
{
    int ret;
    size_t frag_len, bytes_queued, remaining;
    mbedtls_mps_handshake_out_internal * const hs = &mps->dtls.io.out.hs;
    mbedtls_mps_msg_metadata * const metadata = hs->metadata;
    TRACE_INIT( "mps_dtls_frag_out_close" );

    /* Revoke the Layer 3 fragment buffer from the writer
     * and see how much has been written to it, and how much
     * is potentially still pending. */
    MPS_CHK( mbedtls_writer_reclaim( &hs->wr, &frag_len, &bytes_queued,
                                     MBEDTLS_WRITER_RECLAIM_FORCE ) );
    TRACE( trace_comment, "* Fragment length: %u", (unsigned) frag_len );
    TRACE( trace_comment, "* Bytes queued:    %u", (unsigned) bytes_queued );

    TRACE( trace_comment, "* Total length:    %u", (unsigned) metadata->len );
    TRACE( trace_comment, "* Fragment offset: %u", (unsigned) hs->offset );

    if( hs->wr_ext_l3 != NULL )
    {
#if defined(MBEDTLS_MPS_ASSERT)
        {
            mbedtls_mps_size_t const hs_frag_len  = hs->frag_len;
            mbedtls_mps_size_t const metadata_len = metadata->len;
            /* Sanity check -- should never fail */
            if( frag_len > hs_frag_len               ||
                frag_len > metadata_len - hs->offset )
            {
                TRACE( trace_comment, "Writer claims to have written more data than what's available in the current fragment -- should never happen" );
                RETURN( MPS_ERR_INTERNAL_ERROR );
            }
        }
#endif /* MBEDTLS_MPS_ASSERT */

        remaining = hs->frag_len - frag_len;
        TRACE( trace_comment, "%u bytes unwritten in fragment",
               (unsigned) remaining );

        /* Inform Layer 3 about how much has been written,
         * and dispatch the fragment. */
        MPS_CHK( mbedtls_writer_commit_partial_ext( hs->wr_ext_l3,
                                                    remaining ) );
        hs->frag_len = frag_len;
        hs->state = MBEDTLS_MPS_HS_PAUSED;
    }
    else
    {
#if defined(MBEDTLS_MPS_ASSERT)
        if( frag_len != 0 )
            MPS_CHK( MPS_ERR_INTERNAL_ERROR );

        if( metadata->len != MBEDTLS_MPS_SIZE_UNKNOWN &&
            (unsigned) metadata->len != bytes_queued )
        {
            /* This is an internal error and not a usage error,
             * because it is checked in mbedtls_mps_dispatch()
             * that the extended writer is done, i.e. has written
             * the entire message. */
            TRACE( trace_error, "Handshake message size initially specified as %u, but only %u written.",
                   (unsigned) metadata->len, (unsigned) bytes_queued );
            MPS_CHK( MPS_ERR_INTERNAL_ERROR );
        }
#endif /* MBEDTLS_MPS_ASSERT */

        TRACE( trace_comment, "Total handshake length: %u",
               (unsigned) bytes_queued );
        metadata->len = bytes_queued;

        TRACE( trace_comment, "New outgoing handshake message state: MBEDTLS_MPS_HS_PAUSED." );
        hs->state  = MBEDTLS_MPS_HS_PAUSED;
    }

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_dtls_frag_out_dispatch( mbedtls_mps *mps )
{
    int ret = 0;
    mbedtls_mps_handshake_out_internal * const hs = &mps->dtls.io.out.hs;
#if defined(MBEDTLS_MPS_TRACE)
    mbedtls_mps_msg_metadata * const metadata = hs->metadata;
#endif /* MBEDTLS_MPS_TRACE */
    TRACE_INIT( "mps_dtls_frag_out_dispatch" );

    if( mps->dtls.io.out.hs.wr_ext_l3 != NULL )
    {
        TRACE( trace_comment, " * Sequence number: %u",
               (unsigned) metadata->seq_nr );
        TRACE( trace_comment, " * Fragment offset: %u",
               (unsigned) hs->offset );
        TRACE( trace_comment, " * Fragment length: %u",
               (unsigned) hs->frag_len );
        TRACE( trace_comment, " * Total length   : %u",
               (unsigned) metadata->len );

        MPS_CHK( mps_l3_dispatch( mps->conf.l3 ) );

        hs->offset    += hs->frag_len;
        hs->wr_ext_l3  = NULL;
        hs->frag_len   = 0;
    }

    TRACE( trace_comment, "Done" );
    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_dtls_frag_out_start( mbedtls_mps_handshake_out_internal *hs,
                                    unsigned char *queue,
                                    mbedtls_mps_size_t queue_len,
                                    mbedtls_mps_msg_metadata *metadata,
                                    mps_dtls_outgoing_hs_msg_mode mode )
{
    int ret = 0;
    mbedtls_mps_size_t msg_len;
    TRACE_INIT( "mps_dtls_frag_out_start, type %u, length %u",
                (unsigned) metadata->type, (unsigned) metadata->len );

#if defined(MBEDTLS_MPS_ASSERT)
    if( hs->state != MBEDTLS_MPS_HS_NONE )
    {
        TRACE( trace_comment, "Attempt to start a new outgoing handshake message while another one is still not finished." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }
#endif /* MBEDTLS_MPS_ASSERT */

    hs->metadata = metadata;
    hs->offset = 0;
    hs->wr_ext_l3 = NULL;

    /* Initialize (extended) writer serving the user's write requests. */
    msg_len = metadata->len;
    mbedtls_writer_init( &hs->wr, queue, queue_len );
    mbedtls_writer_init_ext( &hs->wr_ext, msg_len );
    MPS_CHK( mbedtls_writer_attach( &hs->wr_ext, &hs->wr,
                                    MBEDTLS_WRITER_EXT_PASS ) );

    if( mode == MPS_DTLS_FRAG_OUT_START_USE_L3 )
    {
        hs->state = MBEDTLS_MPS_HS_PAUSED;
    }
    else /* if( mode == MPS_DTLS_FRAG_OUT_START_QUEUE_ONLY ) */
    {
        /* Feed an empty buffer to serve write requests from the queue only. */
        MPS_CHK( mbedtls_writer_feed( &hs->wr, NULL, 0 ) );
        hs->state = MBEDTLS_MPS_HS_ACTIVE;
    }

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_out_flight_msg_start( mbedtls_mps *mps,
                                     mbedtls_mps_retransmission_handle **handle )
{
    int ret = 0;
    uint8_t cur_flight_len;
    uint8_t cur_seq_nr;
    mbedtls_mps_retransmission_handle *hdl;
    TRACE_INIT( "mps_out_flight_msg_start" );

    TRACE( trace_comment,
           "Add a new message to the current outgoing flight, seq nr %u",
           (unsigned) mps->dtls.seq_nr );

    cur_flight_len = mps->dtls.outgoing.flight_len;
    if( cur_flight_len == MBEDTLS_MPS_MAX_FLIGHT_LENGTH )
    {
        TRACE( trace_error, "Outgoing flight has reached its maximum length %u",
               (unsigned) MBEDTLS_MPS_MAX_FLIGHT_LENGTH );
        MPS_CHK( MBEDTLS_ERR_MPS_FLIGHT_TOO_LONG );
    }

    cur_seq_nr = mps->dtls.seq_nr;
    if( cur_seq_nr == MBEDTLS_MPS_LIMIT_SEQUENCE_NUMBER )
    {
        TRACE( trace_error, "Reached maximum outgoing sequence number %u",
               (unsigned) MBEDTLS_MPS_LIMIT_SEQUENCE_NUMBER );
        MPS_CHK( MBEDTLS_ERR_MPS_COUNTER_WRAP );
    }

    mps->dtls.outgoing.flight_len = cur_flight_len + 1;
    mps->dtls.io.out.flags = 0;

    hdl = &mps->dtls.outgoing.backup[ cur_flight_len ];
    mbedtls_mps_retransmission_handle_init( hdl );
    hdl->metadata.seq_nr = cur_seq_nr;
    *handle = hdl;

    MPS_INTERNAL_FAILURE_HANDLER
}

MBEDTLS_MPS_STATIC int mps_out_flight_msg_done( mbedtls_mps *mps )
{
    int ret;
    TRACE_INIT( "mps_out_flight_msg_done" );

    MPS_CHK( mps_l3_epoch_usage( mps->conf.l3,
                                 mps->out_epoch,
                                 0,
                                 MPS_EPOCH_USAGE_WRITE(
                                     MPS_WRITE_RETRANSMISSION ) ) );

    /* It has been checked in mps_out_flight_msg_start()
     * that this does not wrap. */
    mps->dtls.seq_nr++;

    MPS_INTERNAL_FAILURE_HANDLER
}

#endif /* MBEDTLS_MPS_PROTO_DTLS */
