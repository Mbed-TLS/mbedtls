
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

static int trace_id = TRACE_ID_LAYER_4;

static int mps_check_read ( mbedtls_mps const *mps );
static int mps_check_write( mbedtls_mps const *mps );
static int mps_check_ready( mbedtls_mps const *mps );
static void mps_block( mbedtls_mps *mps );
static void mps_close_notification_received( mbedtls_mps *mps );
static void mps_fatal_alert_received( mbedtls_mps *mps,
                                     mbedtls_mps_alert_t alert_type );
static void mps_generic_failure_handler( mbedtls_mps *mps, int ret );
static int mps_handle_pending_alert( mbedtls_mps *mps );

static int mps_rsm_new_hs_out( mbedtls_mps *mps,
                               mbedtls_mps_handshake_out *hs );
static int mps_rsm_hs_in_done( mbedtls_mps *mps );
static int mps_rsm_new_hs_in( mbedtls_mps *mps );
static int mps_rsm_get_hs_in( mbedtls_mps *mps,
                              mbedtls_mps_handshake_in *hs );

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

/*
 * Implementation of error and closure handling.
 */

/* Error/Closure state modifying functions */

/* Block the MPS */
static void mps_block( mbedtls_mps *mps )
{
    mps->state = MBEDTLS_MPS_STATE_BLOCKED;
}

/* Handle an error code from an internal library call. */
static void mps_generic_failure_handler( mbedtls_mps *mps, int ret )
{
    /* TODO:
     * We need to white-list some errors here, for example those
     * signalling that the underlying transport isn't available.
     */

    if( ret != 0 )
    {
        /* Remember error and block MPS. */
        mps->blocking_info.reason = MBEDTLS_MPS_ERROR_INTERNAL_ERROR;
        mps->blocking_info.info.err = ret;
        mps_block( mps );
    }
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
    mps->blocking_info.reason = MBEDTLS_MPS_ERROR_ALERT_SENT;
    mps->blocking_info.info.alert = alert_type;

    /* Move to blocked state to ensure that no further operations can be
     * performed even if something goes wrong when sending the alert. */
    mps_block( mps );

    /* Attempt to send alert. */
    mps->alert_pending = 1;
    MPS_CHK( mps_handle_pending_alert( mps ) );

exit:
    mps_generic_failure_handler( mps, ret );
    RETURN( ret );
}

/* React to a fatal alert from the peer. */
static void mps_fatal_alert_received( mbedtls_mps *mps,
                                      mbedtls_mps_alert_t alert_type )
{
    switch( mps->state )
    {
        case MBEDTLS_MPS_STATE_OPEN:
        case MBEDTLS_MPS_STATE_READ_ONLY:

            mps->blocking_info.reason = MBEDTLS_MPS_ERROR_ALERT_RECEIVED;
            mps->blocking_info.info.alert = alert_type;

            mps_block( mps );
            break;

        default:
            /* This function should not be called if the
             * MPS cannot be used for reading. */
            break;
    }

}

/* React to a close notification from the peer. */
static void mps_close_notification_received( mbedtls_mps *mps )
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

static int mps_handle_pending_alert( mbedtls_mps *mps )
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
    MPS_CHK( mps_l3_write_alert( mps->conf.l3, &alert ) );

    if( mps->state == MBEDTLS_MPS_STATE_READ_ONLY ||
        mps->state == MBEDTLS_MPS_STATE_CLOSED )
    {
        TRACE( trace_comment, "Report orderly closure of write-side to peer." );
        *alert.level = MBEDTLS_MPS_ALERT_LEVEL_WARNING;
        *alert.type  = MBEDTLS_MPS_ALERT_MSG_CLOSE_NOTIFY;
    }
    else if( mps->state == MBEDTLS_MPS_STATE_BLOCKED &&
             mps->blocking_info.reason == MBEDTLS_MPS_ERROR_ALERT_SENT )
    {
        TRACE( trace_comment, "Report fatal alert to peer." );
        *alert.level = MBEDTLS_MPS_ALERT_LEVEL_FATAL;
        *alert.type  = mps->blocking_info.info.alert;
    }
    else
    {
        /* Should never happen. */
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    MPS_CHK( mps_l3_dispatch( mps->conf.l3 ) );
    mps->alert_pending = 0;

    MPS_CHK( mps_l3_flush( mps->conf.l3 ) );

exit:
    mps_generic_failure_handler( mps, ret );
    RETURN( ret );
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
    mps->alert_pending = 1;
    MPS_CHK( mps_handle_pending_alert( mps ) );

exit:
    mps_generic_failure_handler( mps, ret );
    RETURN( ret );
}

/* Error/Closure state informing functions. */

/* Check if the MPS can be used for reading and writing. */
static int mps_check_ready( mbedtls_mps const *mps )
{
    TRACE_INIT( "mps_check_ready, state %d", mps->state );
    if( mps->state == MBEDTLS_MPS_STATE_OPEN )
    {
        TRACE( trace_comment, "MPS open for reading and writing." );
        RETURN( 0 );
    }

    TRACE( trace_error, "MPS is blocked or connection has been partially closed." );
    RETURN( MBEDTLS_ERR_MPS_BLOCKED );
}

/* Check if the MPS can be used for reading. */
static int mps_check_read( mbedtls_mps const *mps )
{
    TRACE_INIT( "mps_check_read, state %d", mps->state );

    if( mps->state == MBEDTLS_MPS_STATE_OPEN ||
        mps->state == MBEDTLS_MPS_STATE_READ_ONLY )
    {
        TRACE( trace_comment, "Reading possible" );
        RETURN( 0 );
    }

    TRACE( trace_error, "Read-side blocked" );
    RETURN( MBEDTLS_ERR_MPS_BLOCKED );
}

/* Check if the MPS can be used for writing. */
static int mps_check_write( mbedtls_mps const *mps )
{
    TRACE_INIT( "mps_check_write, state %d", mps->state );

    if( mps->state == MBEDTLS_MPS_STATE_OPEN ||
        mps->state == MBEDTLS_MPS_STATE_WRITE_ONLY )
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
                      uint8_t mode )
{
    TRACE_INIT( "mbedtls_mps_init" );

    mps->conf.l3   = l3;
    mps->conf.mode = mode;

    mps->in_epoch  = MPS_EPOCH_NONE;
    mps->out_epoch = MPS_EPOCH_NONE;

    mps->state = MBEDTLS_MPS_STATE_OPEN;
    mps->blocking_info.reason = MBEDTLS_MPS_ERROR_NONE;

    mps->in.state = MBEDTLS_MPS_MSG_NONE;
    RETURN( 0 );
}

int mbedtls_mps_free( mbedtls_mps *mps )
{
    ((void) mps);
    return( 0 );
}

/*
 * MPS reading functions.
 */

int mbedtls_mps_read( mbedtls_mps *mps )
{
    int ret;
    TRACE_INIT( "mbedtls_mps_read" );

    ret = mps_check_read( mps );
    if( ret != 0 )
        RETURN( ret );

    if( mps->in.state != MBEDTLS_MPS_MSG_NONE )
    {
        TRACE( trace_comment, "Message of type %d already open",
               mps->in.state);
        RETURN( mps->in.state );
    }

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
     *       and potentially RETURN the fully reassembled message.
     *   (4) buffer it if it's a future message and the retransmission
     *       state machine supports it.
     *   (5) ignore otherwise.
     *   In any case, the retransmission state machine will signal
     *   whether the new fragment leads to a message being deliverable
     *   to the user or not.
     * - Application data messages are always forwarded to the user.
     */
    switch( ret )
    {
        case MBEDTLS_MPS_MSG_CCS:
        {
            mps_l3_ccs_in ccs_l3;
            MPS_CHK( mps_l3_read_ccs( mps->conf.l3, &ccs_l3 ) );

            /* For DTLS, Layer 3 might be configured to pass through
             * records on multiple epochs for the purpose of detection
             * of flight retransmissions.
             *
             * CCS messages, however, should always be discarded
             * if it's not secured through the current incoming epoch.
             */

            if( ccs_l3.epoch != mps->in_epoch )
                RETURN( MBEDTLS_ERR_MPS_BAD_EPOCH );

            mps->in.state = MBEDTLS_MPS_MSG_CCS;
            MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );
            RETURN( MBEDTLS_MPS_MSG_CCS );
        }

        case MBEDTLS_MPS_MSG_ALERT:
        {
            mps_l3_alert_in alert;
            TRACE( trace_comment, "Received an alert from Layer 3" );

            MPS_CHK( mps_l3_read_alert( mps->conf.l3, &alert ) );

            /* For DTLS, Layer 3 might be configured to pass through
             * records on multiple epochs for the purpose of detection
             * of flight retransmissions.
             *
             * CCS messages, however, should always be discarded
             * if it's not secured through the current incoming epoch.
             */
            if( alert.epoch != mps->in_epoch )
                RETURN( MBEDTLS_ERR_MPS_BAD_EPOCH );

            MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );

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

                    mps->in.state = MBEDTLS_MPS_MSG_ALERT;
                    mps->in.data.alert = alert.type;

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
            break;
        }

        case MBEDTLS_MPS_MSG_HS:
        {
            /* Pass message fragment to retransmission state machine
             * and check if it leads to a handshake message being ready
             * to be passed to the user.
             *
             * This is trivial for TLS, in which case handshake messages
             * are always forwarded. We keep the call here for uniformity;
             * in TLS-only builds the compiler will be able to inline
             * and optimize it. */
            ret = mps_rsm_new_hs_in( mps );

            if( ret == 0 )
            {
                TRACE( trace_comment, "New handshake message ready to be passed to the user." );
                RETURN( MBEDTLS_MPS_MSG_HS );
            }
            else if( ret == MBEDTLS_ERR_MPS_NO_FORWARD )
            {
                TRACE( trace_comment, "Handshake message consumed by retransmission state machine." );
                MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );
                RETURN( MBEDTLS_MPS_MSG_NONE );
            }

            /* TODO: Decide where to handle the situation where the
             * retransmission state machine needs to send something,
             * e.g. retransmit a flight, or send an ACK message.
             *
             * Should this be done here or be attempted transparently
             * in mps_rsm_new_hs_in()?
             */

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
                RETURN( MBEDTLS_ERR_MPS_BAD_EPOCH );

            mps->in.state    = MBEDTLS_MPS_MSG_APP;
            mps->in.data.app = app_l3.rd;
            RETURN( MBEDTLS_MPS_MSG_APP );
        }

        default:
            MPS_CHK( MBEDTLS_ERR_MPS_INTERNAL_ERROR );
            break;
    }

exit:

    mps_generic_failure_handler( mps, ret );
    RETURN( ret );
}

int mbedtls_mps_read_check( mbedtls_mps const *mps )
{
    int ret;

    ret = mps_check_read( mps );
    if( ret != 0 )
        return( ret );

    ret = mps_l3_read_check( mps->conf.l3 );
    return( ret );
}

static int mps_rsm_new_hs_in( mbedtls_mps *mps )
{
    int ret = 0;

    if( mps->conf.mode == MBEDTLS_SSL_TRANSPORT_STREAM )
    {
        /* TLS
         * Handshake message are always forwarded to the user.
         */
        mps->in.state = MBEDTLS_MPS_MSG_HS;
    }
    else
    {
        /* DTLS
         * Not yet implemented
         *
         * Implementations might drop messages,
         * trigger retransmissions, buffer them...
         */
        MPS_CHK( MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED );
    }

exit:
    /* No failure handler for internal functions. */
    return( ret );
}

static int mps_rsm_new_hs_out( mbedtls_mps *mps, mbedtls_mps_handshake_out *hs )
{
    int ret = 0;
    mps_l3_handshake_out hs_l3;

    if( mps->conf.mode == MBEDTLS_SSL_TRANSPORT_STREAM )
    {
        /* TLS
         * Attempt to write a handshake message on Layer 3
         * and forward the writer. */

        hs_l3.epoch = mps->out_epoch;
        hs_l3.type  = hs->type;
        hs_l3.len   = hs->length;

        MPS_CHK( mps_l3_write_handshake( mps->conf.l3, &hs_l3 ) );

        hs->handle = hs_l3.wr_ext;
        hs->addlen = 0;
    }
    else
    {
        /* DTLS
         * Not yet implemented
         *
         * Implementations might drop messages,
         * trigger retransmissions, buffer them...
         */
        MPS_CHK( MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED );
    }

exit:
    /* No failure handler for internal functions. */
    return( ret );
}

static int mps_rsm_get_hs_in( mbedtls_mps *mps,
                              mbedtls_mps_handshake_in *hs )
{
    int ret = 0;

    if( mps->conf.mode == MBEDTLS_SSL_TRANSPORT_STREAM )
    {
        /* TLS */

        mps_l3_handshake_in hs_l3;
        MPS_CHK( mps_l3_read_handshake( mps->conf.l3, &hs_l3 ) );

        hs->length = hs_l3.len;
        hs->type   = hs_l3.type;
        hs->handle = hs_l3.rd_ext;
        hs->addlen = 0; /* No additional data in TLS */
    }
    else
    {
        /* DTLS */

        /* Not yet implemented */

        /* Note: For implementations of the retransmission state machine
         * that perform buffering of future messages, this code-path
         * will sometimes fill the target structure `hs` from the buffered
         * messages, and not from the handshake fragment currently
         * opened on Layer 3. In fact, in this case Layer 3 doesn't
         * have any incoming message opened. */

        MPS_CHK( MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED );
    }

exit:
    /* No failure handler for internal functions. */
    return( ret );
}

static int mps_rsm_hs_in_done( mbedtls_mps *mps )
{
    int ret = 0;

    if( mps->conf.mode == MBEDTLS_SSL_TRANSPORT_STREAM )
    {
        /* TLS */
        MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );
    }
    else
    {
        /* DTLS
         *
         * Not yet implemented
         *
         * For retransmission state machines including buffering
         * of future messages, this might lead to immediately re-opening
         * a buffered message without querying Layer 3 for that.
         * Also, marking such a buffered message as done does not
         * include interaction with Layer 3 either. */

        MPS_CHK( MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED );
    }

exit:
    /* No failure handler for internal functions. */
    return( ret );
}

int mbedtls_mps_read_handshake( mbedtls_mps *mps,
                                mbedtls_mps_handshake_in *hs )
{
    int ret;

    ret = mps_check_read( mps );
    if( ret != 0 )
        return( ret );

    if( mps->in.state != MBEDTLS_MPS_MSG_HS )
        return( MBEDTLS_ERR_MPS_PORT_NOT_ACTIVE );

    MPS_CHK( mps_rsm_get_hs_in( mps, hs ) );

exit:

    mps_generic_failure_handler( mps, ret );
    return( ret );
}

int mbedtls_mps_read_application( mbedtls_mps *mps,
                                  mbedtls_reader **rd )
{
    int ret;

    ret = mps_check_read( mps );
    if( ret != 0 )
        return( ret );

    if( mps->in.state != MBEDTLS_MPS_MSG_APP )
        return( MBEDTLS_ERR_MPS_PORT_NOT_ACTIVE );

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

    if( mps->in.state != MBEDTLS_MPS_MSG_APP )
        return( MBEDTLS_ERR_MPS_PORT_NOT_ACTIVE );

    *alert_type = mps->in.data.alert;
    return( 0 );
}

int mbedtls_mps_read_set_flags( mbedtls_mps *mps, mbedtls_mps_msg_flags flags )
{
    ((void) mps);
    ((void) flags);
    return( MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED );
}

int mbedtls_mps_read_pause( mbedtls_mps *mps )
{
    int ret;

    ret = mps_check_read( mps );
    if( ret != 0 )
        return( ret );

    if( mps->in.state != MBEDTLS_MPS_MSG_HS )
        return( MBEDTLS_ERR_MPS_PORT_NOT_ACTIVE );

    /* TLS */
    MPS_CHK( mps_l3_read_pause_handshake( mps->conf.l3 ) );

    /* DTLS TODO: Pausing of handshake messages is not
     *            handled by Layer 3 but has to be done
     *            manually here. */

exit:
    mps_generic_failure_handler( mps, ret );
    return( ret );
}

int mbedtls_mps_read_consume( mbedtls_mps *mps )
{
    int ret;
    ret = mps_check_read( mps );
    if( ret != 0 )
        return( ret );

    switch( mps->in.state )
    {
        case MBEDTLS_MPS_MSG_HS:

            /* Notify the retransmission state machine.
             * Note that not all handshake messages passed
             * to the user are related to an incoming fragment
             * currently opened on Layer 3 -- for example,
             * when buffering out-of-order messages, the
             * retransmission state machine will serve
             * buffered messages from internal copies,
             * and consuming them does not involve any
             * interaction with Layer 3.
             *
             * For TLS, though, this will always
             * just consume from Layer 3. */

            MPS_CHK( mps_rsm_hs_in_done( mps ) );
            break;

        case MBEDTLS_MPS_MSG_APP:
            MPS_CHK( mps_l3_read_consume( mps->conf.l3 ) );
            break;

        case MBEDTLS_MPS_MSG_CCS:
        case MBEDTLS_MPS_MSG_ALERT:
            /* Alerts and CCS's are signalled as consumed
             * to Layer 3 in mbedtls_mps_read(). */
            break;

        default:
            MPS_CHK( MBEDTLS_ERR_MPS_INTERNAL_ERROR );
    }

    mps->in.state = MBEDTLS_MPS_MSG_NONE;

exit:
    mps_generic_failure_handler( mps, ret );
    return( ret );
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
    ((void) mps);
    ((void) flags);
    return( MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED );
}

int mbedtls_mps_write_set_callback( mbedtls_mps *mps, const void *ctx,
                                    mbedtls_mps_write_callback_t *callback )
{
    ((void) mps);
    ((void) ctx);
    ((void) callback);
    return( MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED );
}

int mbedtls_mps_write_handshake( mbedtls_mps *mps,
                                 mbedtls_mps_handshake_out *hs )
{
    int ret;

    /* Does it make sense to allow writing handshake messages
     * if the peer has already indicated that it's write-side
     * is closed? Probably not... */
    ret = mps_check_ready( mps );
    if( ret != 0 )
        return( ret );

    MPS_CHK( mps_rsm_new_hs_out( mps, hs ) );

exit:
    mps_generic_failure_handler( mps, ret );
    return( ret );
}

int mbedtls_mps_write_application( mbedtls_mps *mps,
                                   mbedtls_writer **app )
{
    int ret;
    mps_l3_app_out out_l3;

    ret = mps_check_write( mps );
    if( ret != 0 )
        return( ret );

    out_l3.epoch = mps->out_epoch;
    MPS_CHK( mps_l3_write_app( mps->conf.l3, &out_l3 ) );

    *app = out_l3.wr;

exit:
    mps_generic_failure_handler( mps, ret );
    return( ret );
}

int mbedtls_mps_write_alert( mbedtls_mps *mps,
                             mbedtls_mps_alert_t alert_type )
{
    int ret;
    mps_l3_alert_out alert_l3;

    ret = mps_check_write( mps );
    if( ret != 0 )
        return( ret );

    alert_l3.epoch = mps->out_epoch;
    MPS_CHK( mps_l3_write_alert( mps->conf.l3, &alert_l3 ) );

    *alert_l3.level = MBEDTLS_MPS_ALERT_LEVEL_WARNING;
    *alert_l3.type = alert_type;

exit:
    mps_generic_failure_handler( mps, ret );
    return( ret );
}

int mbedtls_mps_write_ccs( mbedtls_mps *mps )
{
    int ret;
    mps_l3_ccs_out ccs_l3;

    ret = mps_check_write( mps );
    if( ret != 0 )
        return( ret );

    ccs_l3.epoch = mps->out_epoch;
    MPS_CHK( mps_l3_write_ccs( mps->conf.l3, &ccs_l3 ) );

exit:
    mps_generic_failure_handler( mps, ret );
    return( ret );
}

int mbedtls_mps_write_pause( mbedtls_mps *mps )
{
    int ret;

    ret = mps_check_write( mps );
    if( ret != 0 )
        return( ret );

    if( mps->conf.mode == MBEDTLS_SSL_TRANSPORT_STREAM )
    {
        MPS_CHK( mps_l3_pause_handshake( mps->conf.l3 ) );
    }
    else
    {
        MPS_CHK( MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED );
    }

exit:
    mps_generic_failure_handler( mps, ret );
    return( ret );
}

int mbedtls_mps_dispatch( mbedtls_mps *mps )
{
    int ret;

    ret = mps_check_write( mps );
    if( ret != 0 )
        return( ret );

    if( mps->conf.mode == MBEDTLS_SSL_TRANSPORT_STREAM )
    {
        MPS_CHK( mps_l3_dispatch( mps->conf.l3 ) );
    }
    else
    {
        MPS_CHK( MBEDTLS_ERR_MPS_OPERATION_UNSUPPORTED );
    }

exit:
    mps_generic_failure_handler( mps, ret );
    return( ret );
}

int mbedtls_mps_flush( mbedtls_mps *mps )
{
    int ret;
    MPS_CHK( mps_l3_flush( mps->conf.l3 ) );

    /* Check if an alert couldn't be sent previously
     * and attempt to send it now. */
    MPS_CHK( mps_handle_pending_alert( mps ) );

exit:
    mps_generic_failure_handler( mps, ret );
    return( ret );
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
    MPS_CHK( mps_l3_epoch_add( mps->conf.l3, params, id ) );

exit:
    mps_generic_failure_handler( mps, ret );
    return( ret );
}

int mbedtls_mps_set_incoming_keys( mbedtls_mps *mps,
                                   mbedtls_mps_epoch_id id )
{
    int ret;
    TRACE_INIT( "mbedtls_mps_set_incoming_keys, epoch %d", (int) id );
    MPS_CHK( mps_l3_epoch_usage( mps->conf.l3, id, MPS_EPOCH_READ ) );
    mps->in_epoch = id;

exit:
    mps_generic_failure_handler( mps, ret );
    RETURN( ret );
}

int mbedtls_mps_set_outgoing_keys( mbedtls_mps *mps,
                                   mbedtls_mps_epoch_id id )
{
    int ret;
    TRACE_INIT( "mbedtls_mps_set_outgoing_keys, epoch %d", (int) id );
    MPS_CHK( mps_l3_epoch_usage( mps->conf.l3, id, MPS_EPOCH_WRITE ) );
    mps->out_epoch = id;

exit:
    mps_generic_failure_handler( mps, ret );
    RETURN( ret );
}

mbedtls_mps_connection_state_t mbedtls_mps_connection_state(
    mbedtls_mps const *mps )
{
    return( mps->state );
}

int mbedtls_mps_error_state( mbedtls_mps const *mps,
                             mbedtls_mps_blocking_info_t *info )
{
    *info = mps->blocking_info;
    return( 0 );
}
