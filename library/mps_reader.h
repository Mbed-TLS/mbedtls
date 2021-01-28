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
 * \file reader.h
 *
 * \brief This file defines reader objects, which together with their
 *        sibling writer objects form the basis for the communication
 *        between the various layers of the Mbed TLS messaging stack,
 *        as well as the communication between the messaging stack and
 *        the (D)TLS handshake protocol implementation.
 *
 * Readers provide a means of transferring incoming data from
 * a 'producer' providing it in chunks of arbitrary size, to
 * a 'consumer' which fetches and processes it in chunks of
 * again arbitrary, and potentially different, size.
 *
 * Readers can be seen as datagram-to-stream converters,
 * and they abstract away the following two tasks from the user:
 * 1. The pointer arithmetic of stepping through a producer-
 *    provided chunk in smaller chunks.
 * 2. The merging of incoming data chunks in case the
 *    consumer requests data in larger chunks than what the
 *    producer provides.
 *
 * The basic abstract flow of operation is the following:
 * - Initially, the reader is in 'producing mode'.
 * - The producer hands an incoming data buffer to the reader,
 *   moving it from 'producing' to 'consuming' mode.
 * - The consumer subsequently fetches and processes the buffer
 *   content. Once that's done -- or partially done and a consumer's
 *   requests can't be fulfilled -- the producer revokes the reader's
 *   access to the incoming data buffer, putting the reader back to
 *   producing mode.
 * - The producer subsequently gathers more incoming data and hands
 *   it to reader until the latter switches back to consuming mode
 *   if enough data is available for the last consumer request to
 *   be satisfiable.
 * - Repeat the above.
 *
 * From the perspective of the consumer, the state of the
 * reader is a potentially empty list of input buffers that
 * the reader has provided to the consumer.
 * New buffers can be requested through calls to mbedtls_mps_reader_get(),
 * while previously obtained input buffers can be marked processed
 * through calls to mbedtls_mps_reader_consume(), emptying the list of
 * input buffers and invalidating them from the consumer's perspective.
 * The consumer need not be aware of the distinction between consumer
 * and producer mode, because he only interfaces with the reader
 * when the latter is in consuming mode.
 *
 * From the perspective of the producer, the state of the reader
 * is one of the following:
 * - Attached: An incoming data buffer is currently
 *             being managed by the reader, and
 * - Unset: No incoming data buffer is currently
 *          managed by the reader, and all previously
 *          handed incoming data buffers have been
 *          fully processed.
 * - Accumulating: No incoming data buffer is currently
 *                 managed by the reader, but some data
 *                 from the previous incoming data buffer
 *                 hasn't been processed yet and is internally
 *                 held back.
 * The Unset and Accumulating states belong to producing mode,
 * while the Attached state belongs to consuming mode.
 *
 * Transitioning from Unset or Accumulating to Attached is
 * done via calls to mbedtls_mps_reader_feed(), while transitioning
 * from Consuming to either Unset or Accumulating (depending
 * on what has been processed) is done via mbedtls_mps_reader_reclaim().
 *
 * The following diagram depicts the producer-state progression:
 *
 *        +------------------+             reclaim
 *        |      Unset       +<-------------------------------------+       get
 *        +--------|---------+                                      |   +------+
 *                 |                                                |   |      |
 *                 |                                                |   |      |
 *                 |                feed                  +---------+---+--+   |
 *                 +-------------------------------------->    Attached    <---+
 *                                                        |       /        |
 *                 +-------------------------------------->    Consuming   <---+
 *                 |     feed, enough data available      +---------+---+--+   |
 *                 |     to serve previous consumer request         |   |      |
 *                 |                                                |   |      |
 *        +--------+---------+                                      |   +------+
 *   +---->   Accumulating   |<-------------------------------------+    commit
 *   |    +---+--------------+      reclaim, previous read request
 *   |        |                        couldn't be fulfilled
 *   |        |
 *   +--------+
 *     feed, need more data to serve
 *     previous consumer request
 *
 */

#ifndef MBEDTLS_READER_H
#define MBEDTLS_READER_H

#include <stdio.h>

#include "mps_common.h"
#include "mps_error.h"

struct mbedtls_mps_reader;
typedef struct mbedtls_mps_reader mbedtls_mps_reader;

/*
 * Structure definitions
 */

struct mbedtls_mps_reader
{
    unsigned char *frag;  /*!< The fragment of incoming data managed by
                           *   the reader; it is provided to the reader
                           *   through mbedtls_mps_reader_feed(). The reader
                           *   does not own the fragment and does not
                           *   perform any allocation operations on it,
                           *   but does have read and write access to it.   */
    mbedtls_mps_stored_size_t frag_len;
                          /*!< The length of the current fragment.
                           *   Must be 0 if \c frag == \c NULL.             */
    mbedtls_mps_stored_size_t commit;
                          /*!< The offset of the last commit, relative
                           *   to the first byte in the accumulator.
                           *   This is only used when the reader is in
                           *   consuming mode, i.e. frag != NULL;
                           *   otherwise, its value is \c 0.                */
    mbedtls_mps_stored_size_t end;
                          /*!< The offset of the end of the last chunk
                           *   passed to the user through a call to
                           *   mbedtls_mps_reader_get(), relative to the first
                           *   byte in the accumulator.
                           *   This is only used when the reader is in
                           *   consuming mode, i.e. \c frag != \c NULL;
                           *   otherwise, its value is \c 0.                */
    mbedtls_mps_stored_size_t pending;
                          /*!< The amount of incoming data missing on the
                           *   last call to mbedtls_mps_reader_get().
                           *   In particular, it is \c 0 if the last call
                           *   was successful.
                           *   If a reader is reclaimed after an
                           *   unsuccessful call to mbedtls_mps_reader_get(),
                           *   this variable is used to have the reader
                           *   remember how much data should be accumulated
                           *   before the reader can be passed back to
                           *   the user again.
                           *   This is only used when the reader is in
                           *   consuming mode, i.e. \c frag != \c NULL;
                           *   otherwise, its value is \c 0.                */

    /* The accumulator is only needed if we need to be able to pause
     * the reader. A few bytes could be saved by moving this to a
     * separate struct and using a pointer here. */

    unsigned char *acc;   /*!< The accumulator is used to gather incoming
                           *   data if a read-request via mbedtls_mps_reader_get()
                           *   cannot be served from the current fragment.   */
    mbedtls_mps_stored_size_t acc_len;
                           /*!< The total size of the accumulator.           */
    mbedtls_mps_stored_size_t acc_avail;
                          /*!< The number of bytes currently gathered in
                           *   the accumulator. This is both used in
                           *   producing and in consuming mode:
                           *   While producing, it is increased until
                           *   it reaches the value of \c acc_remaining below.
                           *   While consuming, it is used to judge if a
                           *   read request can be served from the
                           *   accumulator or not.
                           *   Must not be larger than acc_len.              */
    union
    {
        mbedtls_mps_stored_size_t acc_remaining;
                              /*!< This indicates the amount of data still
                               *   to be gathered in the accumulator. It is
                               *   only used in producing mode.
                               *   Must be at most acc_len - acc_available.  */
        mbedtls_mps_stored_size_t frag_offset;
                              /*!< This indicates the offset of the current
                               *   fragment from the beginning of the
                               *   accumulator.
                               *   It is only used in consuming mode.
                               *   Must not be larger than \c acc_avail.     */
    } acc_share;
};

/*
 * API organization:
 * A reader object is usually prepared and maintained
 * by some lower layer and passed for usage to an upper
 * layer, and the API naturally splits according to which
 * layer is supposed to use the respective functions.
 */

/*
 * Maintenance API (Lower layer)
 */

/**
 * \brief           Initialize a reader object
 *
 * \param reader    The reader to be initialized.
 * \param acc       The buffer to be used as a temporary accumulator
 *                  in case read requests through mbedtls_mps_reader_get()
 *                  exceed the buffer provided by mbedtls_mps_reader_feed().
 *                  This buffer is owned by the caller and exclusive use
 *                  for reading and writing is given to the reade for the
 *                  duration of the reader's lifetime. It is thus the caller's
 *                  responsibility to maintain (and not touch) the buffer for
 *                  the lifetime of the reader, and to properly zeroize and
 *                  free the memory after the reader has been destroyed.
 * \param acc_len   The size in Bytes of \p acc.
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_READER_XXX error code on failure.
 */
int mbedtls_mps_reader_init( mbedtls_mps_reader *reader,
                             unsigned char *acc,
                             mbedtls_mps_size_t acc_len );

/**
 * \brief           Free a reader object
 *
 * \param reader    The reader to be freed.
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_READER_XXX error code on failure.
 */
int mbedtls_mps_reader_free( mbedtls_mps_reader *reader );

/**
 * \brief           Pass chunk of data for the reader to manage.
 *
 * \param reader    The reader context to use. The reader must be
 *                  in producing state.
 * \param buf       The buffer to be managed by the reader.
 * \param buflen    The size in Bytes of \p buffer.
 *
 * \return          \c 0 on success. In this case, the reader will be
 *                  moved to consuming state, and ownership of \p buf
 *                  will be passed to the reader until mbedtls_mps_reader_reclaim()
 *                  is called.
 * \return          \c MBEDTLS_ERR_MPS_READER_NEED_MORE if more input data is
 *                  required to fulfill a previous request to mbedtls_mps_reader_get().
 *                  In this case, the reader remains in producing state and
 *                  takes no ownership of the provided buffer (an internal copy
 *                  is made instead).
 * \return          Another negative \c MBEDTLS_ERR_READER_XXX error code on
 *                  different kinds of failures.
 */
int mbedtls_mps_reader_feed( mbedtls_mps_reader *reader,
                             unsigned char *buf,
                             mbedtls_mps_size_t buflen );

/**
 * \brief           Reclaim reader's access to the current input buffer.
 *
 * \param reader    The reader context to use. The reader must be
 *                  in producing state.
 * \param paused    If not \c NULL, the intger at address \p paused will be
 *                  modified to indicate whether the reader has been paused
 *                  (value \c 1) or not (value \c 0). Pausing happens if there
 *                  is uncommitted data and a previous request to
 *                  mbedtls_mps_reader_get() has exceeded the bounds of the
 *                  input buffer.
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_READER_XXX error code on failure.
 */
int mbedtls_mps_reader_reclaim( mbedtls_mps_reader *reader,
                                mbedtls_mps_size_t *paused );

/*
 * Usage API (Upper layer)
 */

/**
 * \brief           Request data from the reader.
 *
 * \param reader    The reader context to use. The reader must
 *                  in consuming state.
 * \param desired   The desired amount of data to be read, in Bytes.
 * \param buffer    The address to store the buffer pointer in.
 *                  This must not be \c NULL.
 * \param buflen    The address to store the actual buffer
 *                  length in, or \c NULL.
 *
 * \return          \c 0 on success. In this case, \c *buf holds the
 *                  address of a buffer of size \c *buflen
 *                  (if \c buflen != \c NULL) or \c desired
 *                  (if \c buflen == \c NULL). The user hass ownership
 *                  of the buffer until the next call to mbedtls_mps_reader_commit().
 *                  or mbedtls_mps_reader_reclaim().
 * \return          #MBEDTLS_ERR_MPS_READER_OUT_OF_DATA if there is not enough
 *                  data available to serve the read request. In this case,
 *                  the reader remains intact, and additional data can be
 *                  provided by reclaiming the current input buffer via
 *                  mbedtls_mps_reader_reclaim() and feeding a new one via
 *                  mbedtls_mps_reader_feed().
 * \return          Another negative \c MBEDTLS_ERR_READER_XXX error
 *                  code for different kinds of failure.
 *
 * \note            Passing \c NULL as \p buflen is a convenient way to
 *                  indicate that fragmentation is not tolerated.
 *                  It's functionally equivalent to passing a valid
 *                  address as buflen and checking \c *buflen == \c desired
 *                  afterwards.
 */
int mbedtls_mps_reader_get( mbedtls_mps_reader *reader,
                            mbedtls_mps_size_t desired,
                            unsigned char **buffer,
                            mbedtls_mps_size_t *buflen );

/**
 * \brief           Signal that all input buffers previously obtained
 *                  from mbedtls_writer_get() are fully processed.
 *
 *                  This function marks the previously fetched data as fully
 *                  processed and invalidates their respective buffers.
 *
 * \param reader    The reader context to use.
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_READER_XXX error code on failure.
 *
 * \warning         Once this function is called, you must not use the
 *                  pointers corresponding to the committed data anymore.
 *
 */
int mbedtls_mps_reader_commit( mbedtls_mps_reader *reader );

#endif /* MBEDTLS_READER_H */
