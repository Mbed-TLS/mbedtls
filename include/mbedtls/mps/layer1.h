/**
 * \file layer1.h
 *
 * \brief The buffering and datagram layer of the message processing stack.
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

#ifndef MBEDTLS_MPS_BUFFER_LAYER_H
#define MBEDTLS_MPS_BUFFER_LAYER_H

#include <stdio.h>
#include <stdint.h>

#include "common.h"
#include "allocator.h"
#include "error.h"

/*
 * External interface to layer 0
 */
typedef int mps_l0_recv_t( unsigned char *buf, size_t buflen );
typedef int mps_l0_send_t( unsigned char const *buf, size_t buflen );

/*
 *
 * Structure definitions for datagram/stream implementations.
 *
 */

#if defined(MBEDTLS_MPS_PROTO_TLS)

/*
 * Stream-based implementation
 */

/** Context maintaining the reading-side of a stream-based Layer 1 context. */
typedef struct
{
    mps_alloc     *alloc; /*!< The allocator to use to acquire and release
                           *   the read-buffer used by Layer 1.              */
    mps_l0_recv_t *recv;  /*!< The Layer 0 receive callback                  */

    /* OPTIMIZATION:
     * This buffer is already present in the allocator and
     * could be removed here if there was a stub API to access
     * the allocated buffers from the allocator. */
    unsigned char *buf;   /*!< The buffer holding the data read from Layer 0 */
    mbedtls_mps_stored_size_t buf_len;         /*!< The size of \c buf.      */

    /*! Total number of bytes read from the underlying transport so far.
     *  Must not be larger than \c buf_len. */
    mbedtls_mps_stored_size_t bytes_read;

    /*! Total number of bytes provided to the user at the last fetch call if
     *  that call was successful. If it failed, or if mps_l1_fetch() hasn't
     *  been called at all, this is \c 0.
     *
     *  This field determines the read buffer in the abstract state of the
     *  Layer 1 context that the user has to keep in mind.
     *
     *  Must not be larger than bytes_read. */
    mbedtls_mps_stored_size_t bytes_fetched;

} mps_l1_stream_read;

typedef enum
{
    MPS_L1_STREAM_STATUS_READY=0,
    MPS_L1_STREAM_STATUS_FLUSH,
    MPS_L1_STREAM_STATUS_WRITE
} mps_l1_stream_state;

/* NOTE: The following struct allows to buffer outgoing data until a
 *       certain amount is ready. Alternatively, one might transfer
 *       any outgoing data to Layer 0 immediately once ready; this way,
 *       the fields bytes_written and flush wouldn't be needed.
 */

/** Context maintaining the writing-side of a stream-based Layer 1 context.  */
typedef struct
{
    mps_alloc     *alloc;  /*!< The allocator to use to acquire and release
                            *   the write-buffer used by Layer 1.            */
    mps_l0_send_t *send;   /*!< The Layer 0 send callback                    */

    /* OPTIMIZATION:
     * This buffer is already present in the allocator and
     * could be removed here if there was a stub API to access
     * the allocated buffers from the allocator. */
    unsigned char *buf;    /*!< The buffer holding the data to be
                            *   passed to Layer 0                            */
    mbedtls_mps_stored_size_t buf_len;    /*!< The size of \c buf.           */

    /*! Number of bytes written and dispatched by the user.
     *  This must not be larger than buf_len. */
    mbedtls_mps_stored_size_t bytes_ready;

   /*! The number of bytes already transferred to Layer 0 during flushing.
    *  This is only used if status is MPS_L1_STREAM_STATUS_FLUSH;
    *  otherwise, its value is 0.
    *  This must not be larger than bytes_ready. */
    mbedtls_mps_stored_size_t bytes_written;

    /*!< Internal state:
     * - L1_STREAM_STATUS_READY:
     *   Write-buffer can be requested, awaiting write call.
     * - L1_STREAM_STATUS_FLUSH:
     *   Outgoing data is pending to be flushed to Layer 0
     *   before write-buffer can be requested.
     * - L1_STREAM_STATUS_WRITE:
     *   Write-buffer has been passed to the user, awaiting dispatch call.
     */
    mps_l1_stream_state status;

} mps_l1_stream_write;

typedef struct
{
    mps_l1_stream_read  rd;   /*!< Reading-side of the Layer 1 context. */
    mps_l1_stream_write wr;   /*!< Writing-side of the Layer 1 context. */
} mps_l1_stream;

#endif /* MBEDTLS_MPS_PROTO_TLS */

/*
 * Datagram-based implementation
 */

#if defined(MBEDTLS_MPS_PROTO_DTLS)

/** Context maintaining the reading-side of a datagram-based Layer 1 context. */
typedef struct
{
    mps_alloc     *alloc;   /*!< The allocator to use to acquire and release
                             *   the read-buffer used by Layer 1.             */
    mps_l0_recv_t *recv;    /*!< The Layer 0 receive callback                 */

    /* OPTIMIZATION:
     * This buffer is already present in the allocator and
     * could be removed here if there was a stub API to access
     * the allocated buffers from the allocator. */
    unsigned char *buf;     /*!< The buffer holding the datagram received
                             *   from the underlying Layer 0 transport.       */
    /*! The size of \c buf. */
    mbedtls_mps_stored_size_t buf_len;

    /*!< The current read-position within buf. */
    mbedtls_mps_stored_size_t window_base;
    /*! The length of the fragment last handed out to the user in a call to
     *  mps_l1_fetch. If that call was unsuccessful, or if no such call has
     *  been made, the value is \c 0. */
    mbedtls_mps_stored_size_t window_len;


    mbedtls_mps_stored_size_t msg_len;         /*!< The size of the current datagram (or 0
                             *   if none has been fetched yet).               */

} mps_l1_dgram_read;

/** Context maintaining the writing-side of a datagram-based Layer 1 context. */
typedef struct
{
    mps_alloc     *alloc;   /*!< The allocator to use to acquire and release
                             *   the write-buffer used by Layer 1.            */
    mps_l0_send_t *send;    /*!< The Layer 0 receive callback                 */

    /* OPTIMIZATION:
     * This buffer is already present in the allocator and
     * could be removed here if there was a stub API to access
     * the allocated buffers from the allocator. */
    unsigned char *buf;     /*!< The buffer wherein the outgoing data
                             *   should be prepared.                          */

    /*! The size of \c buf. */
    mbedtls_mps_stored_size_t buf_len;
    /*! Number of bytes written and dispatched by the user                  */
    mbedtls_mps_stored_size_t bytes_ready;

    uint8_t flush;          /*!< Indicates if a flush is necessary before
                             *   serving the next write request.              */

} mps_l1_dgram_write;

typedef struct
{
    mps_l1_dgram_read  rd;
    mps_l1_dgram_write wr;
} mps_l1_dgram;

#endif /* MBEDTLS_MPS_PROTO_DTLS */

/*
 * Generic implementation
 */
struct mps_l1
{
    /* Selector for following union
     * Valid values:
     * - MPS_L1_MODE_STREAM
     * - MPS_L1_MODE_DGRAM
     */
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    uint8_t mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    union
    {
#if defined(MBEDTLS_MPS_PROTO_TLS)
        mps_l1_stream stream;
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
        mps_l1_dgram  dgram;
#endif /* MBEDTLS_MPS_PROTO_DTLS */
    } raw;
};
typedef struct mps_l1 mps_l1;

#if !defined(MBEDTLS_MPS_CONF_MODE)
static inline uint8_t
mbedtls_mps_l1_get_mode( mps_l1 *l1 )
{
    return( l1->mode );
}
#else /* !MBEDTLS_MPS_CONF_MODE */
static inline uint8_t
mbedtls_mps_l1_get_mode( mps_l1 *l1 )
{
    ((void) l1);
    return( MBEDTLS_MPS_CONF_MODE );
}
#endif /* MBEDTLS_MPS_CONF_MODE */

/*
 *
 * Layer 1 interface
 *
 */

/**
 * Allocator ID bits used when Layer 1 requests memory from the allocator.
 *
 * The base ID used a layer 1 context uses when interfacing with the underlying
 * allocator is set in the mps_l1_init() function. This ID must always have its
 * lowest bit cleared, allowing for the allocator to use different ID's
 * for reading and writing by setting/clearing bit 0.
 *
 */
#define MPS_L1_ALLOC_ID_MASK      0x1
#define MPS_L1_ALLOC_BUFFER_READ  0
#define MPS_L1_ALLOC_BUFFER_WRITE 1

/*
 * Maintenance
 */

#define MPS_L1_MODE_STREAM     0    /*!< Stream mode of operation   */
#define MPS_L1_MODE_DATAGRAM   1    /*!< Datagram mode of operation */

/**
 * \brief          Initialize a Layer 1 context.
 *
 * \param ctx      The pointer to the Layer 1 context to initialize.
 * \param mode     The mode of operation for the Layer 1 context.
 *                 Possible values are:
 *                 - #MPS_L1_MODE_STREAM, if the underlying Layer 0
 *                   transport is a stream transport.
 *                 - #MPS_L1_MODE_DGRAM, if the underlying Layer 0
 *                   transport is a datagram transport.
 * \param alloc    The allocator context to use to acquire and release
 *                 the read and write buffers used by Layer 1.
 * \param send     The callback to the sending function of the underlying
 *                 Layer 0 transport.
 * \param recv     The callback to the receiving function of the underlying
 *                 Layer 0 transport.
 *
 * \warning        The preconditions listed below are *not* checked in
 *                 a production build. The function's behavior is undefined
 *                 if they are violated.
 *
 * \pre            \p ctx must point to a writable ::mps_l1 instance;
 *                 in particular, it must not be \c NULL.
 * \pre            \p mode must be either #MPS_L1_MODE_STREAM or
 *                 #MPS_L1_MODE_STREAM.
 * \pre            \p alloc must point to an initalized allocator context.
 * \pre            \p send must be a valid function pointer;
 *                 in particular, it must not be \c NULL.
 * \pre            \p recv must be a valid function pointer;
 *                 in particular, it must not be \c NULL.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 */

MBEDTLS_MPS_PUBLIC int mps_l1_init( mps_l1 *ctx, uint8_t mode, mps_alloc *alloc,
                            mps_l0_send_t *send, mps_l0_recv_t *recv );

/**
 * \brief          Free a Layer 1 context.
 *
 * \param ctx      The pointer to the Layer 1 context to free.
 *
 * \pre            \p ctx must point to a writable, initialized
 *                 Layer 1 context.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 *
 */

MBEDTLS_MPS_PUBLIC void mps_l1_free( mps_l1 *ctx );

/*
 * Read interface
 */

/**
 * \brief          Attempt to fetch some amount of data from Layer 1 context.
 *
 * \param ctx      The pointer to the Layer 1 context.
 * \param buf      Address to store the address of the
 *                 incoming data buffer at.
 * \param desired  Amount of data to be fetched.
 *
 * \return         \c 0 on success. In this case, \c *buf points to a
 *                 buffer of size \p desired which is valid until the
 *                 next call to mps_l1_consume() or mps_l1_stash().
 * \return         #MPS_ERR_WANT_READ if not enough data is available on
 *                 the underlying transport. In this case, the Layer 1
 *                 context remains intact, and the call should be repeated once
 *                 more incoming data is ready on the underlying transport.
 * \return         Another negative error code on a different failure.
 *
 */

MBEDTLS_MPS_PUBLIC int mps_l1_fetch( mps_l1 *ctx, unsigned char **buf,
                                     mbedtls_mps_size_t desired );

/**
 * \brief          Mark the previously fetched data as consumed.
 *
 * \param ctx      The pointer to the Layer 1 context.
 *
 * \return         0 on success.
 * \return         A non-zero error code on failure.
 *
 * \warning        All buffers previously obtained by calls to mps_l1_fetch()
 *                 are invalid after this call and must not be accessed anymore.
 */

MBEDTLS_MPS_PUBLIC int mps_l1_consume( mps_l1 *ctx );

#if defined(MBEDTLS_MPS_PROTO_DTLS)
/**
 * \brief          Skip a message unit within a Layer 1 context.
 *                 Discard the currently processed message unit.
 *
 * \param ctx      The pointer to the Layer 1 context.
 *
 * \return         \c 0 on success
 * \return         A negative error code on failure.
 *
 * \note           This function is currently only meaningful for
 *                 datagram-based Layer 1 contexts, in which case
 *                 it should ignore the currently processed datagram.
 */

MBEDTLS_MPS_PUBLIC int mps_l1_skip( mps_l1 *ctx );
#endif /* MBEDTLS_MPS_PROTO_DTLS */

/*
 * Write interface
 */

/**
 * \brief          Request a buffer to provide outgoing data in.
 *
 * \param ctx      The pointer to the Layer 1 context.
 * \param buf      The address to store the address of the
 *                 outgoing data buffer at.
 * \param buflen   The address to store the size of the
 *                 outgoing data buffer at.
 *
 * \return         \c 0 on success
 * \return         #MPS_ERR_WANT_WRITE if data is currently
 *                 pending to be written but the underlying transport
 *                 is not available, or another negative error code on
 *                 different failure.
 *
 * \note           If #MPS_ERR_WANT_WRITE is returned, the Layer 1 context
 *                 remains intact, and the call should be repeated once
 *                 the underlying transport is ready to send more data.
 *
 */

MBEDTLS_MPS_PUBLIC int mps_l1_write( mps_l1 *ctx, unsigned char **buf,
                                     mbedtls_mps_size_t *buflen );

/**
 * \brief          Dispatch data provided in the outgoing data buffer.
 *
 * \param ctx      The pointer to the Layer 1 context.
 * \param len      The amount of data to dispatch.
 * \param pending  The number of bytes now pending to be delivered,
 *                 including the bytes just dispatched. May be \c NULL
 *                 if this information is not required.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 *
 * \warning        This function invalidates the buffers previously
 *                 obtained from calls to mps_l1_write().
 *
 */

MBEDTLS_MPS_PUBLIC int mps_l1_dispatch( mps_l1 *ctx,
                                        mbedtls_mps_size_t len,
                                        mbedtls_mps_size_t *pending );

/**
 * \brief          Deliver all previously dispatched data
 *                 to the underlying transport.
 *
 * \param ctx      The pointer to the Layer 1 context.
 *
 * \return         \c 0 on success.
 * \return         #MPS_ERR_WANT_WRITE if data is currently
 *                 pending to be written but the underlying transport
 *                 is not available, or another negative error code on
 *                 different failure.
 *
 * \note           If #MPS_ERR_WANT_WRITE is returned, the Layer 1 context
 *                 remains intact, and the call should be repeated once
 *                 the underlying transport is ready to send more data.
 *
 * \note           If this function is called and returns #MPS_ERR_WANT_WRITE,
 *                 subsequent calls to mps_l1_write() won't succeed until the
 *                 flushing is complete.
 *
 */

MBEDTLS_MPS_PUBLIC int mps_l1_flush( mps_l1 *ctx );

/**
 * \brief          Check if a read request will necessarily involve
 *                 interaction with the underlying transport.
 *
 *                 If no incoming data is buffered, a read request
 *                 will necessarily involve the underlying transport,
 *                 hence it is safe to wait with the call until
 *                 it is available.
 *
 * \param ctx      The pointer to the Layer 1 context.
 *
 * \return         \c 0 if incoming data is buffered and the next
 *                 read request will be attempted to be served from it.
 * \return         \c -1 if no incoming data is buffered and any read request
 *                 will necessarily involve the underlying transport.
 *
 */

MBEDTLS_MPS_PUBLIC int mps_l1_read_dependency( mps_l1 *ctx );

/**
 * \brief          Check if a write request can be potentially be served
 *                 without interaction with the underlying transport.
 *
 * \param ctx      The pointer to the Layer 1 context.
 *
 * \note           Layer 1 does never transfer dispatched data to the
 *                 underlying transport immediately when mps_l1_dispatch()
 *                 is called. Instead, it transfers it either when the
 *                 user calls mps_l1_flush(), or on a subsequent call to
 *                 mps_l1_write() which finds the internal output buffer
 *                 exceeding an implementation-defined threshold.
 *                 This function indicates if the latter might happen;
 *                 if not, Layer 1 is guaranteed to be able to serve another
 *                 write request via mps_l1_write() without transferring any
 *                 data to the underlying transport first.
 *
 * \return         \c 0 if a write request can potentially be served
 *                 without involving the underlying transport.
 * \return         \c -1 if any write request will involve the underlying
 *                 transport.
 *
 */

MBEDTLS_MPS_PUBLIC int mps_l1_write_dependency( mps_l1 *ctx );


#endif /* MBEDTLS_MPS_BUFFER_LAYER_H */
