/*
 *  Copyright The Mbed TLS Contributors
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

/**
 * \file mps_writer.h
 *
 * \brief This file defines writer objects, which together with their
 *        sibling reader objects form the basis for the communication
 *        between the various layers of the Mbed TLS messaging stack,
 *        as well as the communication between the messaging stack and
 *        the (D)TLS handshake protocol implementation.
 *
 * Writers provide a means of communication between
 * - a 'provider' supplying buffers to hold outgoing data, and
 * - a 'consumer' writing data into these buffers.
 * Both the size of the data buffers the provider prepares and the size of
 * chunks in which the consumer writes the data are variable and may be
 * different. It is the writer's responsibility to do the necessary copying
 * and pointer arithmetic.
 *
 * For example, the provider might be the [D]TLS record layer, offering
 * to protect and transport data in records of varying size (depending
 * on the current configuration and the amount of data left in the current
 * datagram, for example), while the consumer would be the handshake logic
 * layer which needs to write handshake messages. The size of handshake
 * messages are entirely independent of the size of records used to transport
 * them, and the writer helps to both split large handshake messages across
 * multiple records, and to pack multiple small handshake messages into
 * a single record. This example will be elaborated upon in the next paragraph.
 *
 * Basic flow of operation:
 * First, the provider feeds an outgoing data buffer to the writer, transferring
 * it from 'providing' to 'consuming' state; in the example, that would be the
 * record layer providing the plaintext buffer for the next outgoing record. The
 * consumer subsequently fetches parts of the buffer and writes data to them,
 * which might happen multiple times; in the example, the handshake logic
 * layer might request and fill a buffer for each handshake message in the
 * current outgoing flight, and these requests would be served from successive
 * chunks in the same record plaintext buffer if size permits. Once the consumer
 * is done, the provider revokes the writer's access to the data buffer,
 * putting the writer back to providing state, and processes the data provided
 * in the outgoing data buffer; in the example, that would be the record layer
 * encrypting the record and dispatching it to the underlying transport.
 * Afterwards, the provider feeds another outgoing data buffer to the writer
 * and the cycle starts again.
 * In the event that a consumer's request cannot be fulfilled on the basis of
 * the outgoing data buffer provided by the provider (in the example,
 * the handshake layer might attempt to send a 4KB CRT chain but the current
 * record size offers only 2KB), the writer transparently offers a temporary
 * 'queue' buffer to hold the data to the consumer. The contents of this queue
 * buffer will be gradually split among the next outgoing data buffers when
 * the provider subsequently provides them; in the example, the CRT chain would
 * be split among multiple records when the record layer hands more plaintext
 * buffers to the writer. The details of this process are left to the writer
 * and are opaque both to the consumer and to the provider.
 *
 * Abstract models:
 * From the perspective of the consumer, the state of the writer is a
 * potentially empty list of output buffers that the writer has provided
 * to the consumer. New buffers can be requested through calls to
 * mbedtls_mps_writer_get(), while previously obtained output buffers can be
 * marked processed through calls to mbedtls_mps_writer_commit(), emptying the
 * list of output buffers and invalidating them from the consumer's perspective.
 *
 */

#ifndef MBEDTLS_MPS_WRITER_H
#define MBEDTLS_MPS_WRITER_H

#include <stdio.h>
#include <stdint.h>

#include <stdio.h>

#include "mps_common.h"
#include "mps_error.h"

typedef struct mbedtls_mps_writer mbedtls_mps_writer;

/** \brief The type of states for the writer.
 *
 *  Possible values are:
 *  - #MBEDTLS_MPS_WRITER_PROVIDING (initial state)
 *    The writer awaits a buffer for holding outgoing
 *    data to be assigned to it via mbedtls_writer_feed().
 *  - #MBEDTLS_MPS_WRITER_CONSUMING
 *    The writer has a buffer to serve write requests from.
 **/
typedef unsigned char mbedtls_mps_writer_state_t;
#define MBEDTLS_MPS_WRITER_PROVIDING ( (mbedtls_mps_writer_state_t) 0)
#define MBEDTLS_MPS_WRITER_CONSUMING ( (mbedtls_mps_writer_state_t) 1)

struct mbedtls_mps_writer
{
    /** The current buffer to hold outgoing data. */
    unsigned char *out;
    /** The queue buffer from which to serve write requests that would
     *  exceed the current outgoing data buffer's bounds. May be \c NULL. */
    unsigned char *queue;
    /** The size in bytes of the outgoing data buffer \c out. */
    mbedtls_mps_stored_size_t out_len;
    /** The size in bytes of the queue buffer \c queue. */
    mbedtls_mps_stored_size_t queue_len;

    /** The offset from the beginning of the outgoing data buffer indicating
     *  the amount of data that the user has already finished writing.
     *
     *  Note: When a queue buffer is in use, this may be larger than the length
     *        of the outgoing data buffer, and is computed as if the outgoing
     *        data buffer was immediately followed by the queue buffer.
     *
     * This is only used when the writer is in consuming state, i.e.
     * <code>state == MBEDTLS_MPS_WRITER_CONSUMING</code>; in this case, its value
     * is smaller or equal to <code>out_len + queue_len</code>.
     */
    mbedtls_mps_stored_size_t committed;

    /** The offset from the beginning of the outgoing data buffer to the
     *  end of the last fragment handed to the user.
     *
     *  Note: When a queue buffer is in use, this may be larger than the
     *  length of the outgoing data buffer, and is computed as if the outgoing
     *  data buffer was immediately followed by the queue buffer.
     *
     *  This is only used when the writer is in consuming state,
     *  i.e. <code>state == MBEDTLS_MPS_WRITER_CONSUMING</code>; in this case,
     *  its value is smaller or equal to <code>out_len + queue_len</code>.
     */
    mbedtls_mps_stored_size_t end;

    /** In consuming state, this denotes the size of the overlap between the
     *  queue and the current out buffer. If the queue hasn't been used yet,
     *  it is \c 0.
     *
     *  In providing state, this denotes the amount of data from the queue that
     *  has already been copied to some outgoing data buffer.
     */
    mbedtls_mps_stored_size_t queue_next;
    /** The amount of data within the queue buffer that hasn't been copied to
     *  some outgoing data buffer yet. This is only used in providing state, and
     *  if the writer uses a queue (<code>queue != NULL</code>), and in this
     *  case its value is at most <code>queue_len - queue_next</code>.
     */
    mbedtls_mps_stored_size_t queue_remaining;
    /** The writer's state. See ::mbedtls_mps_writer_state_t. */
    mbedtls_mps_writer_state_t state;
};

/**
 * \brief           Initialize a writer object
 *
 * \param writer    The writer to be initialized.
 * \param queue     The buffer to be used as dispatch queue if
 *                  buffer provided via mbedtls_mps_writer_feed()
 *                  isn't sufficient.
 * \param queue_len The size in Bytes of \p queue.
 */
void mbedtls_mps_writer_init( mbedtls_mps_writer *writer,
                              unsigned char *queue,
                              mbedtls_mps_size_t queue_len );

/**
 * \brief           Free a writer object
 *
 * \param writer    The writer to be freed.
 */
void mbedtls_mps_writer_free( mbedtls_mps_writer *writer );

/**
 * \brief           Pass output buffer to the writer.
 *
 *                  This function is used to transition the writer
 *                  from providing to consuming state.
 *
 * \param writer    The writer context to be used.
 * \param buf       The buffer that outgoing data can be written to
 *                  and that the writer should manage.
 * \param buflen    The size in Bytes of \p buf.
 *
 * \return          \c 0 on success. In this case, the writer is
 *                  in consuming state afterwards.
 * \return          #MBEDTLS_ERR_MPS_OPERATION_UNEXPECTED if
 *                  the writer is not in providing state. In this case,
 *                  the writer is unmodified and can still be used.
 *                  In particular, the writer stays in consuming state.
 * \return          #MBEDTLS_ERR_MPS_WRITER_NEED_MORE if the provided
 *                  outgoing data buffer was completely filled by data
 *                  that had been internally queued in the writer.
 *                  In this case, the writer stays in consuming state,
 *                  but the content of the output buffer is ready to be
 *                  dispatched in the same way as after a cycle of calls
 *                  to mbedtls_mps_writer_feed(), mbedtls_mps_writer_get(),
 *                  mbedtls_mps_writer_commit(), mbedtls_mps_writer_reclaim().
 * \return          Another negative error code otherwise. In this case,
 *                  the state of the writer is unspecified and it must
 *                  not be used anymore.
 *
 */
int mbedtls_mps_writer_feed( mbedtls_mps_writer *writer,
                             unsigned char *buf,
                             mbedtls_mps_size_t buflen );

/** The identifier to use in mbedtls_mps_writer_reclaim() to
 *  force the reclamation of the outgoing data buffer even
 *  if there's space remaining.                               */
#define MBEDTLS_MPS_WRITER_RECLAIM_FORCE 1
/** The identifier to use in mbedtls_mps_writer_reclaim() if
 *  the call should only succeed if the current outgoing data
 *  buffer has been fully used up.                            */
#define MBEDTLS_MPS_WRITER_RECLAIM_NO_FORCE 0

/**
 * \brief           Attempt to reclaim output buffer from writer,
 *
 *                  This function is used to transition the writer
 *                  from consuming to providing state.
 *
 * \param writer    The writer context to be used.
 * \param written   The address at which to store the amount of
 *                  outgoing data that has been written to the output
 *                  buffer last passed to mbedtls_mps_writer_feed().
 *                  May be \c NULL if this information is not required.
 * \param queued    The address at which to store the amount of
 *                  outgoing data that has been queued. May be \c NULL
 *                  if this information is not required.
 * \param force     Indicates whether the output buffer should
 *                  be reclaimed even if there's space left.
 *                  Must be either #MBEDTLS_MPS_WRITER_RECLAIM_FORCE
 *                  or #MBEDTLS_MPS_WRITER_RECLAIM_NO_FORCE.
 *
 * \return          \c 0 on success. In this case, the writer is in
 *                  providing state afterwards.
 * \return          #MBEDTLS_ERR_MPS_OPERATION_UNEXPECTED if
 *                  the writer is not in consuming state. In this case,
 *                  the writer is unmodified and can still be used.
 *                  In particular, the writer stays in providing state.
 * \return          #MBEDTLS_ERR_MPS_WRITER_DATA_LEFT if there is space
 *                  left to be written in the output buffer.
 *                  In this case, the writer stays in consuming state.
 * \return          Another negative error code otherwise. In this case,
 *                  the state of the writer is unspecified and it must
 *                  not be used anymore.
 *
 *                  On success or when #MBEDTLS_ERR_MPS_WRITER_DATA_LEFT
 *                  is returned, and if \c queue is not \c NULL, then
 *                  \c *queued contains the number of bytes that
 *                  have been queued internally in the writer and will be
 *                  written to the next buffer(s) that is fed to the writer,
 *
 *                  On success or when #MBEDTLS_ERR_MPS_WRITER_DATA_LEFT
 *                  is returned, and if \c written is not \c NULL, then
 *                  \c *written contains the number of bytes written to
 *                  the output buffer.
 *
 */
int mbedtls_mps_writer_reclaim( mbedtls_mps_writer *writer,
                                mbedtls_mps_size_t *written,
                                mbedtls_mps_size_t *queued,
                                int force );

/**
 * \brief           Signal that all output buffers previously obtained
 *                  from mbedtls_mps_writer_get() have been or will have
 *                  been written when mbedtls_mps_writer_reclaim() is
 *                  called.
 *
 *                  This function must only be called when the writer
 *                  is in consuming state.
 *
 * \param writer    The writer context to use.
 *
 * \return          \c 0 on success. In this case, the writer
 *                  stays in consuming state.
 * \return          #MBEDTLS_ERR_MPS_OPERATION_UNEXPECTED
 *                  if the writer is not in consuming state.
 *                  In this case, the writer is unchanged and
 *                  can still be used.
 * \return          Another negative error code otherwise. In this case,
 *                  the state of the writer is unspecified and it must
 *                  not be used anymore.
 *
 */
int mbedtls_mps_writer_commit( mbedtls_mps_writer *writer );

/**
 * \brief           Signal which parts of the output buffers previously
 *                  obtained from mbedtls_mps_writer_get() have been or
 *                  will have been written when mbedtls_mps_writer_reclaim()
 *                  is called.
 *
 *                  This function must only be called when the writer
 *                  is in consuming state.
 *
 * \note            This function is necessary when the user requested
 *                  an overly large write buffer via mbedtls_mps_writer_get()
 *                  (e.g. because the necessary buffer size wasn't known
 *                  upfront) and only parts of it were actually written.
 *
 * \param writer    The writer context to use.
 * \param omit      The number of bytes at the end of the last output
 *                  buffer obtained from mbedtls_mps_writer_get() that should
 *                  not be committed.
 *
 * \return          \c 0 on success. In this case, the writer
 *                  stays in consuming state.
 * \return          #MBEDTLS_ERR_MPS_OPERATION_UNEXPECTED
 *                  if the writer is not in consuming state.
 *                  In this case, the writer is unchanged and
 *                  can still be used.
 * \return          Another negative error code otherwise. In this case,
 *                  the state of the writer is unspecified and it must
 *                  not be used anymore.
 *
 */
int mbedtls_mps_writer_commit_partial( mbedtls_mps_writer *writer,
                                       mbedtls_mps_size_t omit );

/**
 * \brief           Request buffer to hold outbound data.
 *
 *                  This function must only be called when the writer
 *                  is in consuming state.
 *
 * \param writer    The writer context to use.
 * \param desired   The desired size of the outgoing data buffer.
 * \param buffer    The address at which to store the address
 *                  of the outgoing data buffer on success.
 * \param buflen    The address at which to store the actual
 *                  size of the outgoing data buffer on success.
 *                  May be \c NULL (see below).
 *
 * \note            If \p buflen is \c NULL, the function fails
 *                  if it cannot provide an outgoing data buffer
 *                  of the requested size \p desired.
 *
 * \return          \c 0 on success. In this case, the writer
 *                  stays in consuming state.
 * \return          #MBEDTLS_ERR_MPS_OPERATION_UNEXPECTED
 *                  if the writer is not in consuming state.
 *                  In this case, the writer is unchanged and
 *                  can still be used.
 * \return          #MBEDTLS_ERR_MPS_WRITER_OUT_OF_DATA if there is not
 *                  enough space available to serve the request.
 *                  In this case, the writer remains intact, and
 *                  additional space can be provided by reclaiming
 *                  the current output buffer via mbedtls_mps_writer_reclaim()
 *                  and feeding a new one via mbedtls_mps_writer_feed().
 * \return          Another negative error code otherwise. In this case,
 *                  the state of the writer is unspecified and it must
 *                  not be used anymore.
 *
 */
int mbedtls_mps_writer_get( mbedtls_mps_writer *writer,
                            mbedtls_mps_size_t desired,
                            unsigned char **buffer,
                            mbedtls_mps_size_t *buflen );

#endif /* MBEDTLS_MPS_WRITER_H */
