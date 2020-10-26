/**
 * \file layer3.h
 *
 * \brief The message extraction layer of the message processing stack.
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

#ifndef MBEDTLS_MPS_MESSAGE_EXTRACTION_LAYER_H
#define MBEDTLS_MPS_MESSAGE_EXTRACTION_LAYER_H

#include <stdint.h>

#include "reader.h"
#include "writer.h"

#include "layer2.h"
#include "common.h"

#include "transform.h"
#include "error.h"

/*
 * Layer 3 compile-time configuration
 */

/**
 * \def MPS_L3_ALLOW_INTERLEAVED_SENDING
 *
 * If this macro is set, Layer 3 can be configured to allow
 * interleaving of records when sending messages of different
 * types.
 *
 * For example, the writing of a long handshake message split
 * across multiple records could this way be interleaved with
 * an ApplicationData record.
 *
 * Uncomment to allow interleaving of messages of different types.
 *
 */
#define MPS_L3_ALLOW_INTERLEAVED_SENDING

struct mps_l3;
struct mps_l3_handshake_in;
struct mps_l3_handshake_out;
struct mps_l3_hs_in_internal;
struct mps_l3_hs_out_internal;
struct mps_l3_alert_in;
struct mps_l3_alert_in_internal;
struct mps_l3_alert_out;
struct mps_l3_app_in;
struct mps_l3_app_out;
struct mps_l3_ccs_in;
struct mps_l3_ccs_out;

typedef struct mps_l3 mps_l3;
typedef struct mps_l3_handshake_in mps_l3_handshake_in;
typedef struct mps_l3_handshake_out mps_l3_handshake_out;
typedef struct mps_l3_hs_in_internal mps_l3_hs_in_internal;
typedef struct mps_l3_hs_out_internal mps_l3_hs_out_internal;
typedef struct mps_l3_alert_in mps_l3_alert_in;
typedef struct mps_l3_alert_in_internal mps_l3_alert_in_internal;
typedef struct mps_l3_alert_out mps_l3_alert_out;
typedef struct mps_l3_app_in mps_l3_app_in;
typedef struct mps_l3_app_out mps_l3_app_out;
typedef struct mps_l3_ccs_in mps_l3_ccs_in;
typedef struct mps_l3_ccs_out mps_l3_ccs_out;

typedef enum mps_l3_hs_state
{
    MPS_L3_HS_NONE=0,           /*!< No handshake message is currently
                                 *   active or paused.                       */
    MPS_L3_HS_ACTIVE,           /*!< A handshake message is currently open
                                 *   for reading/writing.                    */
    MPS_L3_HS_PAUSED            /*!< The reading/writing of a handshake
                                 *   message has commenced but been paused.  */
} mps_l3_hs_state;

/**
 * \brief    This structure represents handles to
 *           outgoing handshake messages.
 *
 *           It is used in the following way:
 *           When the user wants to prepare an outgoing
 *           handshake message, he creates an instance
 *           of this structure and sets fields indicating
 *           the intended epoch, handshake type, and
 *           handshake message length. The user then calls
 *           mps_l3_write_handshake() which, on success,
 *           sets the \c wr_ext within this struct to point
 *           to a valid writer that can be used to provide
 *           the actual message contents.
 *
 *           When the writing is done, the user calls
 *           mps_l3_dispatch() to prepare the message for
 *           delivery; if the writing cannot be completed
 *           because the provided writer does not provide
 *           enough space for outgoing data, the write can
 *           be paused via mps_l3_pause_handshake(), and
 *           subsequently be continued via another call to
 *           mps_l3_write_handshake() which must use the
 *           the same epoch, handshake type and length
 *           parameters as the initial one.
 *
 *           The handshake message length must be known
 *           in advance if pausing is needed for the message.
 *           If pausing is not needed, the length field can
 *           be set to #MBEDTLS_MPS_SIZE_UNKNOWN and will be
 *           be determined automatically on closing.
 */
struct mps_l3_handshake_out
{
    /*! The epoch to use to protect the handshake message.
     *  This must be set by the user before calling mps_l3_write_handshake(). */
    mbedtls_mps_stored_epoch_id epoch;

    /*! The handshake message type. This must be set by
     *  the user before calling mps_l3_write_handshake().*/
    mbedtls_mps_stored_hs_type type;

    /*! The handshake sequence number. */
    mbedtls_mps_stored_hs_seq_nr_t seq_nr;

    /*! The total length of the handshake message (regardless of fragmentation),
     *  or #MBEDTLS_MPS_SIZE_UNKNOWN if the length will be determined at
     *  write-time. In this case, pausing is not possible for the handshake
     *  message (because the headers for handshake fragments include the total
     *  length of the handshake message). This must be set by the user
     *  before calling mps_l3_write_handshake(). */
    mbedtls_mps_stored_opt_size_t len;

    /*! The length of the current handshake fragment, or
     *  #MBEDTLS_MPS_SIZE_UNKNOWN if the will be determined at write-time. */
    mbedtls_mps_stored_opt_size_t frag_len;

     /*! The offset of the current fragment from the
      *  beginning of the handshake message.*/
    mbedtls_mps_stored_size_t frag_offset;

    /*! The extended writer providing buffers to which the message
     *  contents can be written, and keeping track of message bounds.
     *  This must be \c NULL when the user calls mps_l3_write_handshake(), which
     *  will modify it to point to a valid extended writer on success. */
    mbedtls_writer_ext *wr_ext;
};

/**
 * \brief    This structure represents handles to
 *           incoming handshake messages.
 *
 *           It is used in the following way:
 *           If a successful call to mps_l3_read() has indicated that
 *           a handshake message has been received (by returning
 *           #MBEDTLS_MPS_MSG_HS), mps_l3_read_handshake() will
 *           provide an instance of this structure giving access
 *           to the epoch, the handshake type, the total length
 *           of the received handshake message, as well as a reader
 *           providing access to the handshake message contents.
 *
 *           When the user is done reading the message, he calls
 *           mps_l3_read_consume(). If the reader within this
 *           structure cannot provide enough data to finish the
 *           processing of the handshake message, the user should
 *           call mps_l3_pause_handshake() to temporaily suspend
 *           the reading. The next successful call to mps_l3_read()
 *           returning #MBEDTLS_MPS_MSG_HS is then guaranteed
 *           to yield a handle that can be used to continue the
 *           processing at the stage where the initial call stopped
 *           (determined by the last call to mps_l3_reader_commit_ext()).
 *
 */
struct mps_l3_handshake_in
{
    /*! The epoch used to protect the handshake message.*/
    mbedtls_mps_stored_epoch_id epoch;

    /*! The handshake message type. */
    mbedtls_mps_stored_hs_type type;

    /*! The total length of the message (regardless of fragmentation). */
    mbedtls_mps_stored_size_t len;

    /*! The length of the current handshake fragment. */
    mbedtls_mps_stored_size_t frag_len;

    /*! The offset of the current fragment from
     *  the beginning of the handshake message.  */
    mbedtls_mps_stored_size_t frag_offset;

    /*! The handshake sequence number.*/
    mbedtls_mps_stored_hs_seq_nr_t seq_nr;

    /*!< The extended reader giving access to the message contents, and
     *   keeping track of message bounds. */
    mbedtls_reader_ext *rd_ext;
};

/**
 * \brief    This structure represents handles to
 *           incoming alert messages.
 *
 *           It is used in the following way:
 *           If a successful call to mps_l3_read() has indicated that
 *           a handshake message has been received (by returning
 *           #MBEDTLS_MPS_MSG_ALERT), mps_l3_read_alert() will
 *           provide an instance of this structure giving access
 *           to the epoch, alert type and alert level.
 *
 *           When the user is done reading the message, he calls
 *           mps_l3_read_consume().
 *
 */
struct mps_l3_alert_in
{
    /*! The epoch used to protect the alert. */
    mbedtls_mps_stored_epoch_id epoch;
    /*! The level of the incoming alert.     */
    uint8_t level;
    /*! The type of the incoming alert.      */
    uint8_t type;
};

struct mps_l3_alert_out
{
    /*! The epoch to use to protect the alert message. Set by user. */
    mbedtls_mps_stored_epoch_id epoch;
    /*! The level of the incoming alert. */
    uint8_t *level;
    /*! The type of the incoming alert. */
    uint8_t *type;
};

/**
 * \brief    This structure represents handles to
 *           incoming application data messages.
 *
 *           It is used in the following way:
 *           If a successful call to mps_l3_read() has indicated that
 *           application data has been received (by returning
 *           #MBEDTLS_MPS_MSG_APP), mps_l3_read_app() will
 *           provide an instance of this structure giving access
 *           to the epoch as well as a reader giving rise to the
 *           actual data.
 *
 *           When the user is done reading the message, he calls
 *           mps_l3_read_consume().
 *
 */
struct mps_l3_app_in
{
    /*! The epoch used to protect the application data. */
    mbedtls_mps_stored_epoch_id epoch;
    mbedtls_reader *rd;
};

struct mps_l3_app_out
{
    /*! The epoch used to protect the application data. Set by the user. */
    mbedtls_mps_stored_epoch_id epoch;
    mbedtls_writer *wr;          /*!< The writer to use to supply the
                                  *   actual application data. Set by MPS. */
};

/**
 * \brief    This structure represents handles to
 *           incoming ChangeCipherSpec (CCS) messages.
 *
 *           It is used in the following way:
 *           If a successful call to mps_l3_read() has indicated that
 *           application data has been received (by returning
 *           #MBEDTLS_MPS_MSG_CCS), mps_l3_read_app() will provide
 *           an instance of this structure giving access to the epoch
 *           used for the CCS message.
 *
 *           When the user is done reading the message, he calls
 *           mps_l3_read_consume().
 *
 * \note     Currently, Layer 3 validates the static single-byte content
 *           of CCS messages and returns an error code from mps_l3_read()
 *           if it doesn't match the value MPS_TLS_CCS_VALUE prescribed
 *           by the standard. We might want to revise this, leaving all
 *           content validation to Layer 4.
 *
 */
struct mps_l3_ccs_in
{
    /*! The epoch used to protect the ChangeCipherSpec message. */
    mbedtls_mps_stored_epoch_id epoch;
};

struct mps_l3_ccs_out
{
    /*!< The epoch to use to protect the CCS message. Set by the user. */
    mbedtls_mps_stored_epoch_id epoch;
};

/*
 * Internal siblings for the structures used by the Layer 3 API.
 */

struct mps_l3_hs_in_internal
{
    /*!< The epoch used to protect the handshake message. */
    mbedtls_mps_stored_epoch_id epoch;
    mps_l3_hs_state state;      /*!< Indicates if the incoming message
                                 *   is currently being paused or not.       */

    /*! The handshake message type. */
    mbedtls_mps_stored_hs_type type;

    /*! The total length of the message (regardless of fragmentation).      */
    mbedtls_mps_stored_size_t len;

    /* DTLS-specific fields. */

    /*! The length of the current handshake fragment, or
     *  #MBEDTLS_MPS_SIZE_UNKNOWN if the will be determined at write-time. */
    mbedtls_mps_stored_opt_size_t frag_len;

    /*! The offset of the current fragment from
     *  the beginning of f the handshake message. */
    mbedtls_mps_stored_size_t frag_offset;

    /*!< The handshake sequence number. */
    mbedtls_mps_stored_hs_seq_nr_t seq_nr;

    mbedtls_reader_ext rd_ext;  /*!< The extended reader giving access to
                                 *   the message contents, but also keeping
                                 *   track of message bounds.                */
};

struct mps_l3_hs_out_internal
{
    /*!< The epoch used to protect the handshake message. */
    mbedtls_mps_stored_epoch_id epoch;

    /*! Indicates if the outgoing message is currently being paused or not. */
    mps_l3_hs_state state;

    /*! The handshake message type. */

    /* OPTIMIZATION:
     * Consider removing handshake metadata from Layer 3.
     * See the corresponding comments in mps.h. */
    mbedtls_mps_stored_hs_type type;

    /*! The total length of the message (regardless of fragmentation),
     *  or #MBEDTLS_MPS_SIZE_UNKNOWN if it is not yet known. */
    mbedtls_mps_stored_opt_size_t len;

    /*! The buffer that should hold the handshake header once
     *  the length of the handshake message is known. */
    unsigned char* hdr;
    /*! The size of the header buffer. */
    mbedtls_mps_stored_size_t hdr_len;

    /*! The extended writer providing buffers to which the message
     *  contents can be written, and keeping track of message bounds. */

    /* OPTIMIZATION:
     * Consider removing the extended writer from Layer 3 and
     * performing bounds checks for handshake messages at Layer 4.
     * See the corresponding comment in mps.h. */
    mbedtls_writer_ext wr_ext;

    /* DTLS-specific fields. */

    /*! The length of the current handshake fragment, or
     *  #MBEDTLS_MPS_SIZE_UNKNOWN if the will be determined at write-time. */
    mbedtls_mps_stored_opt_size_t frag_len;

    /*! The offset of the current fragment from
     *  the beginning of the handshake message.  */
    mbedtls_mps_stored_size_t frag_offset;

    /*! The handshake sequence number. */

    /* OPTIMIZATION:
     * Consider removing handshake metadata from Layer 3.
     * See the corresponding comments in mps.h. */
    mbedtls_mps_stored_hs_seq_nr_t seq_nr;
};

struct mps_l3_alert_in_internal
{
    uint8_t level;               /*!< The level of the incoming alert.     */
    uint8_t type;                /*!< The type of the incoming alert.      */
};

/**
 * \brief    The Layer 3 configuration structure.
 */
typedef struct
{
#if !defined(MBEDTLS_MPS_CONF_MODE)
    uint8_t mode;
#endif /* MBEDTLS_MPS_CONF_MODE */
    mbedtls_mps_l2 *l2;
} mps_l3_config;

#if !defined(MBEDTLS_MPS_CONF_MODE)
static inline uint8_t
mbedtls_mps_l3_conf_get_mode( mps_l3_config *conf )
{
    return( conf->mode );
}
#else /* !MBEDTLS_MPS_CONF_MODE */
static inline uint8_t
mbedtls_mps_l3_conf_get_mode( mps_l3_config *conf )
{
    ((void) conf);
    return( MBEDTLS_MPS_CONF_MODE );
}
#endif /* MBEDTLS_MPS_CONF_MODE */

/**
 * \brief    The Layer 3 context structure.
 */
struct mps_l3
{
    mps_l3_config conf;

    struct
    {
        struct
        {
            /* Global reading state */

            /*! Indicates if and which record type is currently open for reading. */
            mbedtls_mps_stored_msg_type_t state;

            /* Raw record data. */

            /*! Epoch of current incoming message.  */
            mbedtls_mps_stored_epoch_id epoch;
            mbedtls_reader *raw_in; /*!< Reader providing raw access to incoming
                                     *   data of the type indicated by \c state
                                     *   (including headers in case of handshake
                                     *    messages).                             */

            /* Type-specific structures for accessing the contents of
             * of the messages of the given type. */

            mps_l3_hs_in_internal hs;        /*!< Handle to incoming
                                              *   handshake message.              */

            mps_l3_alert_in_internal alert;  /*!< Type + Level of incoming alert. */

        } in;

        struct
        {
            uint8_t clearing;    /*!< This indicates if preparation of a new
                                  *   outgoing record necessitates a flush on
                                  *   the underlying Layer 2 first.
                                  *   The rationale for having this as a separate
                                  *   field as opposed to triggering the flush
                                  *   immediately once the necessity arises is
                                  *   that it allows the user to be in control
                                  *   of which Layer 3 API calls will require
                                  *   interfacing with the underlying transport.  */

            /* Note that there is no distinction between `flush` and `clearing`
             * as in the Layer 2 implementation because Layer 3 doesn't buffer
             * outgoing data but always passes it to Layer 2 immediately.         */

            /* Global writing state */

            /*!< Indicates which record type is currently open for writing. */
            mbedtls_mps_stored_msg_type_t state;

            /* Raw outgoing record data */

            /* OPTIMIZATION:
             * If not NULL, this always points to the writer
             * maintained by the underlying Layer 2 instance.
             * Consider using this instance directly. */
            mbedtls_writer *raw_out; /*!< Writer providing raw access to outgoing
                                      *   data buffers (including such to be used
                                      *   for headers in case of handshake
                                      *   messages).                              */

            /* Type-specific structures */

            /* OPTIMIZATION:
             * Why do we need to store meta-data such as the handshake
             * sequence number here? We should be able to write the
             * handshake header in mps_l3_write_handshake(), and afterwards
             * the sequence number isn't needed anymore -- or is it? */
            mps_l3_hs_out_internal hs; /*!< Handle to outgoing handshake message. */

        } out;

    } io;

};

static inline mbedtls_mps_l2* mbedtls_mps_l3_get_l2( mps_l3 *l3 )
{
    return( l3->conf.l2 );
}

/**
 * \brief         Initialize a Layer 3 context.
 *
 * \param l3      The pointer to the Layer 3 context to be initialized.
 * \param l2      The pointer to the underlying Layer 2 context to
 *                to be used by \p l3.
 * \param mode    The mode of operation for the Layer 3 context:
 *                Either #MBEDTLS_MODE_STREAM for stream transports,
 *                or #MBEDTLS_MPS_MODE_DATAGRAM for datagram transports.
 *
 * \note          Layer 3 doesn't own its underlying Layer 2 context;
 *                the Layer 2 context \p l2 must already be initialized
 *                when calling this function.
 *
 * \return        \c 0 on success.
 * \return        A negative error code on failure.
 */

MBEDTLS_MPS_PUBLIC int mps_l3_init( mps_l3 *l3, mbedtls_mps_l2 *l2, uint8_t mode );

/**
 * \brief         Free a Layer 3 context.
 *
 * \param l3      The pointer to the Layer 3 context to be freed.
 *
 * \note          Layer 3 doesn't own its underlying Layer 2 context;
 *                the latter must be freed separately.
 *
 * \return        \c 0 on success.
 * \return        A negative error code on failure.
 */
MBEDTLS_MPS_PUBLIC int mps_l3_free( mps_l3 *l3 );

/**
 * \brief         Request an incoming message from Layer 3.
 *
 * \param l3      The pointer to the Layer 3 context to use.
 *
 * \return
 *                - One of the positive status codes #MBEDTLS_MPS_MSG_HS,
 *                  #MBEDTLS_MPS_MSG_APP, #MBEDTLS_MPS_MSG_ALERT,
 *                  #MBEDTLS_MPS_MSG_ALERT, #MBEDTLS_MPS_MSG_CCS or
 *                  #MBEDTLS_MPS_MSG_ACK success, indicating which type
 *                  of message has been received.
 *                - A negative error code on failure.
 *
 * \note          To inspect the contents of the message that has been
 *                received, use the appropriate function \c mps_l3_read_xxx;
 *                e.g., the contents of a handshake message can be accessed
 *                via mps_l3_read_handshake().
 *
 */
/* OPTIMIZATION:
 * Subsume mps_l3_read() with mps_l3_read_XXX() by filling
 * an indexed union of mps_l3_in_xxx on success. */
MBEDTLS_MPS_PUBLIC int mps_l3_read( mps_l3 *l3 );

/**
 * \brief       Check if a message has been read.
 *
 * \param l3    The Layer 3 context to use.
 *
 * \return      #MBEDTLS_MPS_MSG_NONE if no message is available.
 * \return      #MBEDTLS_MPS_MSG_APPLICATION, or
 *              #MBEDTLS_MPS_MSG_HANDSHAKE, or
 *              #MBEDTLS_MPS_MSG_ALERT, or
 *              #MBEDTLS_MPS_MSG_CCS,
 *              otherwise, indicating the message's record content type.
 *
 * \note        This function doesn't do any processing and
 *              and only reports if a message is available
 *              through a prior call to mps_l3_read().
 */
MBEDTLS_MPS_PUBLIC int mps_l3_read_check( mps_l3 * l3 );

/**
 * \brief         Get a handle to the contents of an incoming handshake message.
 *
 * \param l3      The pointer to the Layer 3 context.
 * \param hs      The address to hold the address of the handshake handle.
 *
 * \return        \c 0 on success.
 * \return        A negative error code on failure.
 *
 * \note          The handle returned by this function is owned by
 *                the Layer 3 context and must not be freed by the user.
 *                It must also not be used after the read has been acknowledged
 *                through a call to mps_l3_dispatch(), or paused through a
 *                a call to mps_l3_pause_handshake().
 */
/* TODO: Consider making this function static inline
 * to avoid a layer of indirection. */
MBEDTLS_MPS_PUBLIC int mps_l3_read_handshake( mps_l3 *l3, mps_l3_handshake_in *hs );

/**
 * \brief         Get a handle to the contents of an incoming
 *                application data message.
 *
 * \param l3      The pointer to the Layer 3 context.
 * \param app     The address to hold the address of
 *                the application data handle.
 *
 * \return        \c 0 on success.
 * \return        A negative error code on failure.
 *
 * \note          The handle returned by this function is owned by
 *                the Layer 3 context and must not be freed by the user.
 *                It must also not be used after the read has been acknowledged
 *                through a call to mps_l3_dispatch().
 */

MBEDTLS_MPS_PUBLIC int mps_l3_read_app( mps_l3 *l3, mps_l3_app_in *app );

/**
 * \brief         Get a handle to the contents of an incoming alert message.
 *
 * \param l3      The pointer to the Layer 3 context.
 * \param alert   The address to hold the address of the alert handle.
 *
 * \return        \c 0 on success.
 * \return        A negative error code on failure.
 *
 */
MBEDTLS_MPS_PUBLIC int mps_l3_read_alert( mps_l3 *l3, mps_l3_alert_in *alert );

/**
 * \brief         Get a handle to the contents of an incoming CCS message.
 *
 * \param l3      The pointer to the Layer 3 context.
 * \param ccs     The address to hold the address of the alert handle.
 *
 * \return        \c 0 on success.
 * \return        A negative error code on failure.
 *
 */
MBEDTLS_MPS_PUBLIC int mps_l3_read_ccs( mps_l3 *l3, mps_l3_ccs_in *ccs );

#if defined(MBEDTLS_MPS_PROTO_TLS)
/**
 * \brief         Pause the reading of an incoming handshake message.
 *
 *                This function must be called when a handshake message
 *                has been received but the handshake handle returned by
 *                mps_l3_read_handshake() cannot provide the entire
 *                handshake contents. In this case, this function pauses
 *                the processing of the handshake message until it is
 *                continued on the next successful call to mps_l3_read()
 *                signaling incoming handshake data.
 *                It is currently the responsibility of the user to remember
 *                the state of content processing.
 *
 * \param l3      The pointer to the Layer 3 context to use.
 *
 * \return        \c 0 on success.
 * \return        A negative error code on failure.
 *
 * \warning       This call invalidates the handle returned by
 *                mps_l3_read_handshake(). When continuing the reading,
 *                the user must call mps_l3_read_handshake() again to
 *                retrieve the handle to use.
 */
MBEDTLS_MPS_PUBLIC int mps_l3_read_pause_handshake( mps_l3 *l3 );
#endif /* MBEDTLS_MPS_PROTO_TLS */

/**
 * \brief         Conclude the reading of the current incoming message.
 *
 *                This function must be called after the user has successfully
 *                received and processed an incoming message through calls to
 *                mps_l3_read() and potentially \c mps_l3_read_xxx.
 *                It invalidates all content handles associated to the incoming
 *                messages, and puts the Layer 3 context in a state ready for
 *                a next call to mps_l3_read().
 *
 * \param l3      The pointer to the Layer 3 context to use.
 *
 * \return        \c 0 on success.
 * \return        #MPS_ERR_UNFINISHED_HS_MSG if the handshake message
 *                hasn't been fully fetched and committed. In this case,
 *                the state of \p l3 is unchanged; in particular, it
 *                remains intact and can be still be used.
 * \return        Another negative error code for other kinds of failure.
 *
 */
MBEDTLS_MPS_PUBLIC int mps_l3_read_consume( mps_l3 *l3 );

/**
 * \brief           Start writing an outgoing handshake message.
 *
 * \param l3        The pointer to the Layer 3 context to use.
 * \param hs        The address to store the handshake handle at.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 */
MBEDTLS_MPS_PUBLIC int mps_l3_write_handshake( mps_l3 *l3, mps_l3_handshake_out *hs );

/**
 * \brief           Start writing outgoing application data.
 *
 * \param l3        The pointer to the Layer 3 context to use.
 * \param app       The address to store the application data handle at.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 */
MBEDTLS_MPS_PUBLIC int mps_l3_write_app( mps_l3 *l3, mps_l3_app_out *app );

/**
 * \brief           Start writing an outgoing alert message.
 *
 * \param l3        The pointer to Layer 3 context.
 * \param alert     Address to store the alert handle at.
 *
 * \return          \c 0 on success.
 * \return          A negative error code on failure.
 */
MBEDTLS_MPS_PUBLIC int mps_l3_write_alert( mps_l3 *l3, mps_l3_alert_out *alert );

/**
 * \brief           Start writing an outgoing CCS message.
 *
 * \param l3        The pointer to Layer 3 context.
 * \param ccs       Address to store the CCS handle at.
 *
 * \return          0 on success, a negative error code on failure.
 *
 * \note            The contents of a CCS message are determined by the
 *                  the standard, and hence this function does not return
 *                  an actual write-handle. Nonetheless, the writing of a CCS
 *                  message must be concluded by a call to mps_l3_dispatch()
 *                  in the same way as the writing of messages of
 *                  other content types.
 */
MBEDTLS_MPS_PUBLIC int mps_l3_write_ccs( mps_l3 *l3, mps_l3_ccs_out *ccs );

#if defined(MBEDTLS_MPS_PROTO_TLS)
/**
 * \brief           Pause the writing of an outgoing handshake message.
 *
 *                  This function must be called when the writing of an
 *                  outgoing handshake message has commenced, but the write
 *                  handle returned by mps_l3_write_handshake() cannot provide
 *                  enough space to write the entire handshake message contents.
 *                  In this case, this function pauses the writing of the
 *                  handshake message until it is continued on the next
 *                  successful call to mps_l3_write_handshake().
 *
 *                  It is currently the responsibility of the user to remember
 *                  the state of content processing.
 *
 * \param l3        The pointer to Layer 3 context.
 *
 * \return          0 on success, a negative error code on failure.
 *
 * \warning         This call invalidates the handle returned by
 *                  mps_l3_write_handshake(). When continuing the write,
 *                  the user must call mps_l3_write_handshake() again to
 *                  retrieve the handle to use.
 */
MBEDTLS_MPS_PUBLIC int mps_l3_pause_handshake( mps_l3 *l3 );
#endif /* MBEDTLS_MPS_PROTO_TLS */

/**
 * \brief           Abort the writing of an outgoing handshake message.
 *
 *                  After the writing of a handshake message has commenced
 *                  through a successful call to mps_l3_write_handshake(),
 *                  this function can be used to abort the write, as long
 *                  as no data has been committed.
 *
 * \param l3        The pointer to Layer 3 context.
 *
 * \return          0 on success, a negative error code on failure.
 *
 */
MBEDTLS_MPS_PUBLIC int mps_l3_write_abort_handshake( mps_l3 *l3 );

/**
 * \brief         Conclude the writing of the current outgoing message.
 *
 *                This function must be called after the user has requested
 *                the writing of an outgoing message via a successful call to
 *                \c mps_l3_write_xxx and has prepared its contents through the
 *                provided write-handles.
 *
 *                It invalidates all content handles associated to the outgoing
 *                messages, and puts the Layer 3 context in a state ready for
 *                a next call to \c mps_l3_write_xxx.
 *
 * \param l3      Pointer to Layer 3 context.
 *
 * \return        \c 0 on success.
 * \return        A negative error code on failure.
 *
 */
MBEDTLS_MPS_PUBLIC int mps_l3_dispatch( mps_l3 *l3 );

/**
 * \brief         Flush all outgoing messages dispatched so far
 *
 *                This function attempts to deliver all messages previously
 *                dispatched via mps_l3_dispatch() to the underlying transport.
 *                It delivery is not possible immediately, it remembers the
 *                ongoing flush and guarantees that no subsequent write will
 *                commence until the flush has completed.
 *
 * \param l3      Pointer to Layer 3 context.
 *
 * \return        \c 0 on success.
 * \return        #MPS_ERR_WANT_WRITE if the flush couldn't be completed.
 * \return        A different negative error code for other kinds of failure.
 *
 * \note          In case #MPS_ERR_WANT_WRITE is returned, the function can
 *                be called again to retry the flush.
 */
MBEDTLS_MPS_PUBLIC int mps_l3_flush( mps_l3 *l3 );


static inline int mps_l3_epoch_add( mps_l3 *ctx,
                                    mbedtls_mps_transform_t *transform,
                                    mbedtls_mps_epoch_id *epoch )
{
    return( mps_l2_epoch_add( ctx->conf.l2, transform, epoch ) );
}


static inline int mps_l3_epoch_usage( mps_l3 *ctx,
                                      mbedtls_mps_epoch_id epoch_id,
                                      mbedtls_mps_epoch_usage clear,
                                      mbedtls_mps_epoch_usage set )
{
    return( mps_l2_epoch_usage( ctx->conf.l2, epoch_id, clear, set ) );
}

static inline int mps_l3_force_next_sequence_number( mps_l3 *ctx,
                                                mbedtls_mps_epoch_id epoch_id,
                                                uint64_t ctr )
{
    return( mps_l2_force_next_sequence_number( ctx->conf.l2, epoch_id, ctr ) );
}

static inline int mps_l3_get_last_sequence_number( mps_l3 *ctx,
                                                mbedtls_mps_epoch_id epoch_id,
                                                uint64_t *ctr )
{
    return( mps_l2_get_last_sequence_number( ctx->conf.l2, epoch_id, ctr ) );
}

#endif /* MBEDTLS_MPS_MESSAGE_EXTRACTION_LAYER_H */
