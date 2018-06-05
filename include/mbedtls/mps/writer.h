/**
 * \file writer.h
 *
 * \brief This file defines writer objects, which together with
 *        their sibling reader objects form the basis for the communication
 *        between the various layers of the Mbed TLS messaging stack,
 *        as well as the communication between the messaging stack and
 *        the (D)TLS handshake protocol implementation.
 *
 * Writers provide a means of communication between an
 * entity (the 'provider' in the following) providing buffers
 * to which outgoing data can be written, and an entity
 * (the 'consumer' in the following) consuming them by writing
 * the actual data into it.
 * Both the size of the data buffers the provider prepares
 * and the size of chunks in which the consumer writes the
 * data are variable and may be different.
 * It is the writer's responsibility to do the
 * necessary copying and pointer arithmetic.
 *
 * The basic flow of operation is that the provider feeds
 * an outgoing data buffer to the writer, transferring it from
 * 'providing' to 'consuming' mode. The consumer subsequently
 * fetches parts of the buffer and writes data to them.
 * Once that's done, the provider revokes the writer's access
 * to the outgoing data buffer, putting the writer back to
 * providing mode; the provider may then continue processing
 * (e.g. dispatching) the data provided in the outgoing data buffer.
 * After that, the provider feeds another outgoing data buffer
 * to the writer and the cycle starts again.
 * In the event that a consumer's request cannot be fulfilled
 * on the basis of the outgoing data buffer provided by the
 * provider, the writer may provide a temporary 'queue' buffer
 * instead. In this case, the queue buffer will be copied to the
 * outgoing data buffers when the provider subsequently provides
 * them. The details of this are opaque to the consumer and the
 * provider, but it means that if the provider feeds an outgoing
 * data buffer to the writer, the writer might entirely fill it
 * immediately on the basis of what has been queued internally.
 *
 * From the perspective of the consumer, the state of the
 * writer is a potentially empty list of output buffers that
 * the writer has provided to the consumer.
 * New buffers can be requested through calls to mbedtls_writer_get(),
 * while previously obtained output buffers can be marked processed
 * through calls to mbedtls_writer_commit(), emptying the list of
 * output buffers and invalidating them from the consumer's perspective.
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
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_WRITER_H
#define MBEDTLS_WRITER_H

#include <stdio.h>

struct mbedtls_writer;
typedef struct mbedtls_writer mbedtls_writer;

struct mbedtls_writer_ext;
typedef struct mbedtls_writer_ext mbedtls_writer_ext;

/*
 * Error codes returned from the writer.
 */

/** An attempt was made to reclaim a buffer from the writer,
 *  but the buffer hasn't been fully used up, yet.            */
#define MBEDTLS_ERR_WRITER_DATA_LEFT             -0x1
/** The validation of input parameters failed.                */
#define MBEDTLS_ERR_WRITER_INVALID_ARG           -0x2
/** The provided outgoing data buffer was not large enough to
 *  hold all queued data that's currently pending to be
 *  delivered.                                                */
#define MBEDTLS_ERR_WRITER_NEED_MORE             -0x3
/** The requested operation is not possible
 *  in the current state of the writer.                       */
#define MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION  -0x4
/** The remaining amount of space for outgoing data is not
 *  sufficient to serve the user's request. The current
 *  outgoing data buffer must be reclaimed, dispatched,
 *  and a fresh outgoing data buffer must be fed to the
 *  writer.                                                   */
#define MBEDTLS_ERR_WRITER_OUT_OF_DATA           -0x5
/** A write-request was issued to the extended writer that
 *  exceeds the bounds of the most recently added group.      */
#define MBEDTLS_ERR_WRITER_BOUNDS_VIOLATION      -0x9
/** The extended writer has reached the maximum number of
 *  groups, and another group cannot be added.                */
#define MBEDTLS_ERR_WRITER_TOO_MANY_GROUPS       -0xa

/** The identifier to use in mbedtls_writer_reclaim() to
 *  force the reclamation of the outgoing data buffer even
 *  if there's space remaining.                               */
#define MBEDTLS_WRITER_RECLAIM_FORCE 1
/** The identifier to use in mbedtls_writer_reclaim() if
 *  the call should only succeed if the current outgoing data
 *  buffer has been fully used up.                            */
#define MBEDTLS_WRITER_RECLAIM_NO_FORCE 0

/** The maximum number of nested groups that can be opened
 *  in an extended writer.                                    */
#define MBEDTLS_WRITER_MAX_GROUPS 5

struct mbedtls_writer
{
    unsigned char *out;  /*!< The current buffer to hold outgoing data.      */
    size_t out_len;      /*!< The size in bytes of the outgoing data buffer. */

    size_t commit;       /*!< The offset from the beginning of the outgoing
                          *   data buffer indicating the amount of data that
                          *   the user has already finished writing.
                          *   Note: When a queue buffer is in use, this may
                          *   be larger than the length of the outgoing data
                          *   buffer, and is computed as if the outgoing data
                          *   buffer was immediately followed by the queue
                          *   buffer.
                          *   This is only used when the writer is in consuming
                          *   mode, i.e. out != \c NULL; in this case, its value
                          *   is smaller or equal to out_len + queue_len.    */
    size_t end;          /*!< The offset from the beginning of the outgoing
                          *   data buffer of the end of the last fragment
                          *   handed to the user.
                          *   Note: When a queue buffer is in use, this may
                          *   be larger than the length of the outgoing data
                          *   buffer, and is computed as if the outgoing data
                          *   buffer was immediately followed by the queue
                          *   buffer.
                          *   This is only used when the writer is in consuming
                          *   mode, i.e. out != \c NULL; in this case, its value
                          *   is smaller or equal to out_len + queue_len.    */

    unsigned char *queue;  /*!< The queue buffer from which to serve write
                            *   requests that would exceed the current
                            *   outgoing data buffer's bounds.
                            *   May be \c NULL.                              */
    size_t queue_len;      /*!< The length of the queue.                     */

    size_t queue_next;      /*!< In consuming mode, this denotes the size of the
                             *   overlap between the queue and the current out
                             *   buffer, once end > out_len. If end < out_len,
                             *   its value is 0.
                             *   In providing mode, this denotes the amount of
                             *   data from the queue that has already been
                             *   copied to some outgoing data buffer.        */
    size_t queue_remaining; /*!< The amount of data within the queue buffer
                             *   that hasn't been copied to some outgoing
                             *   data buffer yet. This is only used in
                             *   providing mode, and if the writer uses a
                             *   queue (queue != \c NULL), and in this case its
                             *   value is at most queue_len - queue_next.    */
};

/*
 * E-ACSL invariants for writer
 */

/* I don't know why E-ACSL allows the following predicates when spelled
 * out but forbids them when they are globally defined. Define them as
 * macros for now... ugly hack, but anyway. */

#define WRITER_INV_FRAG_VALID( p )                      \
    ( (p)->out != NULL ==>                              \
      ( \forall integer i; 0 <= i < (p)->out_len        \
        ==> \valid( (p)->out+i ) ) )

#define WRITER_INV_FRAG_UNSET_VARS_ZERO( p )       \
    ( (p)->out == NULL ==>                         \
      ( (p)->out_len  == 0 &&                      \
        (p)->commit   == 0 &&                      \
        (p)->end      == 0 ) )

#define WRITER_INV_COMMIT( p )                  \
    ( (p)->commit <= (p)->out_len + (p)->queue_len )

#define WRITER_INV_END( p )                  \
    ( (p)->end <= (p)->out_len + (p)->queue_len )

#define WRITER_INV_QUEUE_VALID( p )                      \
    ( (p)->queue != NULL ==>                             \
      ( (p)->queue_len > 0 &&                            \
        ( \forall integer i; 0 <= i < (p)->queue_len     \
          ==> \valid( (p)->queue+i ) ) ) )

#define WRITER_INV_QUEUE_UNSET_VARS_ZERO( p )                  \
    ( ( (p)->queue == NULL ) ==>                               \
      ( (p)->queue_len  == 0      &&                           \
        (p)->queue_next == 0      &&                           \
        (p)->queue_remaining == 0 ) )

#define WRITER_INV_QUEUE_AVAIL( p )             \
    ( (p)->queue_next <= (p)->queue_len )

#define WRITER_INV_QUEUE_AVAIL_BOUND( p )                \
    ( ( (p)->out != NULL && (p)->end > (p)->out_len )    \
      ==> ( (p)->queue_len - (p)->queue_next >=          \
            (p)->end - (p)->out_len ) )

#define WRITER_INV_QUEUE_AVAIL_UNSET( p )                \
    ( ( (p)->out != NULL && (p)->end <= (p)->out_len )   \
      ==> (p)->queue_next == 0 )

#define WRITER_INV_QUEUE_REMAINING( p )                                 \
    ( (p)->queue_remaining <= (p)->queue_len - (p)->queue_next )

#define WRITER_INV_QUEUE_REMAINING_UNSET( p )                   \
    ( (p)->out != NULL ) ==> ( (p)->queue_remaining == 0 ) )

#define WRITER_INV( p )                             \
    ( WRITER_INV_FRAG_VALID( p )            &&      \
      WRITER_INV_COMMIT( p )                &&      \
      WRITER_INV_END( p )                   &&      \
      WRITER_INV_FRAG_UNSET_VARS_ZERO( p )  &&      \
      WRITER_INV_QUEUE_VALID( p )           &&      \
      WRITER_INV_QUEUE_UNSET_VARS_ZERO( p ) &&      \
      WRITER_INV_QUEUE_AVAIL( p )           &&      \
      WRITER_INV_QUEUE_AVAIL_UNSET( p )     &&      \
      WRITER_INV_QUEUE_AVAIL_BOUND( p )     &&      \
      WRITER_INV_QUEUE_REMAINING( p ) )

#define WRITER_INV_ENSURES( p )                            \
    ensures \valid( p );                                   \
    ensures WRITER_INV_FRAG_VALID( p );                    \
    ensures WRITER_INV_COMMIT( p );                        \
    ensures WRITER_INV_END( p );                           \
    ensures WRITER_INV_FRAG_UNSET_VARS_ZERO( p );          \
    ensures WRITER_INV_QUEUE_VALID( p );                   \
    ensures WRITER_INV_QUEUE_UNSET_VARS_ZERO( p );         \
    ensures WRITER_INV_QUEUE_AVAIL( p );                   \
    ensures WRITER_INV_QUEUE_AVAIL_UNSET( p );             \
    ensures WRITER_INV_QUEUE_AVAIL_BOUND( p );             \
    ensures WRITER_INV_QUEUE_REMAINING( p );

#define WRITER_INV_REQUIRES( p )                            \
    requires \valid( p );                                   \
    requires WRITER_INV_FRAG_VALID( p );                    \
    requires WRITER_INV_COMMIT( p );                        \
    requires WRITER_INV_END( p );                           \
    requires WRITER_INV_FRAG_UNSET_VARS_ZERO( p );          \
    requires WRITER_INV_QUEUE_VALID( p );                   \
    requires WRITER_INV_QUEUE_UNSET_VARS_ZERO( p );         \
    requires WRITER_INV_QUEUE_AVAIL( p );                   \
    requires WRITER_INV_QUEUE_AVAIL_UNSET( p );             \
    requires WRITER_INV_QUEUE_AVAIL_BOUND( p );             \
    requires WRITER_INV_QUEUE_REMAINING( p );

struct mbedtls_writer_ext
{
    unsigned cur_grp; /*!< The 0-based index of the currently active group.
                       *   The group of index 0 always exists and represents
                       *   the entire logical message buffer.                 */
    size_t grp_end[MBEDTLS_WRITER_MAX_GROUPS];
                      /*!< The offsets marking the ends of the currently
                       *   active groups. The first cur_grp + 1 entries are
                       *   valid and always weakly descending (subsequent
                       *   groups are subgroups of their predecessors ones).  */

    mbedtls_writer *wr; /*!< The underlying writer object - may be NULL.      */
    size_t ofs_fetch;   /*!< The offset of the first byte of the next chunk.  */
    size_t ofs_commit;  /*!< The offset of first byte beyond
                         *   the last committed chunk .*/
};

#define WRITER_EXT_INV_CUR_GRP_VALID( p )               \
    ( (p)->cur_grp < MBEDTLS_WRITER_MAX_GROUPS )

#define WRITER_EXT_INV_GRP_DESCENDING( p )             \
    ( \forall integer i; 0 < i <= (p)->cur_grp ==>     \
      (p)->grp_end[i - 1] >= (p)->grp_end[i] )

#define WRITER_EXT_INV_ROOT_GROUP_BOUNDS( p )   \
    ( (p)->ofs_fetch <= (p)->grp_end[0] )

#define WRITER_EXT_INV_COMMIT_FETCH( p )        \
    ( (p)->ofs_commit <= (p)->ofs_fetch )

#define WRITER_EXT_INV_COMMIT_FETCH_DETACHED( p )   \
    ( (p)->wr == NULL ==>                           \
      ( (p)->ofs_commit <= (p)->ofs_fetch ) )

#define WRITER_EXT_INV_ENSURES( p )                     \
    ensures WRITER_EXT_INV_CUR_GRP_VALID( p );          \
    ensures WRITER_EXT_INV_GRP_DESCENDING( p );         \
    ensures WRITER_EXT_INV_ROOT_GROUP_BOUNDS( p );      \
    ensures WRITER_EXT_INV_COMMIT_FETCH( p );           \
    ensures WRITER_EXT_INV_COMMIT_FETCH_DETACHED( p );

#define WRITER_EXT_INV_REQUIRES( p )                     \
    requires WRITER_EXT_INV_CUR_GRP_VALID( p );          \
    requires WRITER_EXT_INV_GRP_DESCENDING( p );         \
    requires WRITER_EXT_INV_ROOT_GROUP_BOUNDS( p );      \
    requires WRITER_EXT_INV_COMMIT_FETCH( p );           \
    requires WRITER_EXT_INV_COMMIT_FETCH_DETACHED( p );

/**
 * \brief           Initialize a writer object
 *
 * \param writer    The writer to be initialized.
 * \param queue     The buffer to be used as dispatch queue if
 *                  buffer provided via mbedtls_writer_feed()
 *                  isn't sufficient.
 * \param queue_len The size of the \p queue buffer.
 *
 * \return          \c 0 on success.
 * \return          A negative error code \c MBEDTLS_ERR_WRITER_XXX on failure.
 */
/*@
  requires \valid( writer );
  requires ( queue != NULL ==>
             ( queue_len > 0 &&
               \forall integer i; 0 <= i < queue_len
                 ==> \valid( queue + i ) ) );
  WRITER_INV_ENSURES(writer)
  @*/
int mbedtls_writer_init( mbedtls_writer *writer,
                         unsigned char *queue, size_t queue_len );

/**
 * \brief           Free a writer object
 *
 * \param writer    The writer to be freed.
 *
 * \return          \c 0 on success.
 * \return          A negative error code \c MBEDTLS_ERR_WRITER_XXX on failure.
 */
/*@
  WRITER_INV_REQUIRES(writer)
  @*/
int mbedtls_writer_free( mbedtls_writer *writer );

/**
 * \brief           Pass output buffer to the writer.
 *
 *                  This function is used to transition the writer
 *                  from providing to consuming mode.
 *
 * \param writer    The writer context to be used.
 * \param buf       The buffer that outgoing data can be written to
 *                  and that the writer should manage.
 * \param buflen    The length of the outgoing data buffer.
 *
 * \return          \c 0 on success. In this case, the writer is
 *                  in consuming mode afterwards.
 * \return          #MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION if
 *                  the writer is not in providing mode. In this case,
 *                  the writer is unmodified and can still be used.
 *                  In particular, the writer stays in consuming mode.
 * \return          #MBEDTLS_ERR_WRITER_NEED_MORE if the provided
 *                  outgoing data buffer was completely filled by data
 *                  that had been internally queued in the writer.
 *                  In this case, the writer stays in consuming mode,
 *                  but the content of the output buffer is ready to be
 *                  dispatched in the same way as after a cycle of calls
 *                  to mbedtls_writer_feed(), mbedtls_writer_get(),
 *                  mbedtls_writer_commit(), mbedtls_writer_reclaim().
 * \return          Another negative error code otherwise. In this case,
 *                  the state of the writer is unspecified and it must
 *                  not be used anymore.
 *
 */
/*@
  WRITER_INV_REQUIRES(writer)
  requires ( \forall integer i; 0 <= i < buflen
                 ==> \valid( buf + i ) );

  WRITER_INV_ENSURES(writer)
  @*/
int mbedtls_writer_feed( mbedtls_writer *writer,
                         unsigned char *buf, size_t buflen );

/**
 * \brief           Attempt to reclaim output buffer from writer,
 *
 *                  This function is used to transition the writer
 *                  from consuming to providing mode.
 *
 * \param writer    The writer context to be used.
 * \param queued    The address at which to store the amount of
 *                  outgoing data that has been queued. May be NULL
 *                  if this information is not required.
 * \param force     Indicates whether the output buffer should
 *                  be reclaimed even if there's space left.
 *                  Must be either #MBEDTLS_WRITER_RECLAIM_FORCE
 *                  or #MBEDTLS_WRITER_RECLAIM_NO_FORCE.
 *
 * \return          \c 0 on success. In this case, the writer is in
 *                  providing mode afterwards.
 * \return          #MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION if
 *                  the writer is not in consuming mode. In this case,
 *                  the writer is unmodified and can still be used.
 *                  In particular, the writer stays in providing mode.
 * \return          #MBEDTLS_ERR_WRITER_DATA_LEFT if there is space
 *                  left to be written in the output buffer.
 *                  In this case, the writer stays in consuming mode.
 * \return          Another negative error code otherwise. In this case,
 *                  the state of the writer is unspecified and it must
 *                  not be used anymore.
 *
 *                  On success, \c *queued contains the number of bytes that
 *                  have been queued internally in the writer and will be
 *                  written to the next buffer(s) that is fed to the writer.
 *
 */
/*@
  WRITER_INV_REQUIRES(writer)
  WRITER_INV_ENSURES(writer)
  @*/
int mbedtls_writer_reclaim( mbedtls_writer *writer, size_t *queued,
                            size_t *written, int force );

/**
 * \brief           Check how many bytes have already been written
 *                  to the current output buffer.
 *
 * \param writer    Writer context
 * \param written   Pointer to receive amount of data already written.
 *
 * \return          \c 0 on success.
 * \return          A negative error code \c MBEDTLS_ERR_WRITER_XXX on failure.
 *
 */
int mbedtls_writer_bytes_written( mbedtls_writer *writer, size_t *written );

/**
 * \brief           Signal that all output buffers previously obtained
 *                  from mbedtls_writer_get() are ready to be dispatched.
 *
 *                  This function must only be called when the writer
 *                  is in consuming mode.
 *
 * \param writer    The writer context to use.
 *
 * \note            After this function has been called, all
 *                  output buffers obtained from prior calls to
 *                  mbedtls_writer_get() are invalid and must not
 *                  be used anymore.
 *
 * \return          \c 0 on success. In this case, the writer
 *                  stays in consuming mode.
 * \return          #MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION
 *                  if the writer is not in consuming mode.
 *                  In this case, the writer is unchanged and
 *                  can still be used.
 * \return          Another negative error code otherwise. In this case,
 *                  the state of the writer is unspecified and it must
 *                  not be used anymore.
 *
 */
/*@
  WRITER_INV_REQUIRES(writer)
  WRITER_INV_ENSURES(writer)
  @*/
int mbedtls_writer_commit( mbedtls_writer *writer );

/**
 * \brief           Signal that parts of the output buffers obtained
 *                  from mbedtls_writer_get() are ready to be dispatched.
 *
 *                  This function must only be called when the writer
 *                  is in consuming mode.
 *
 * \param writer    The writer context to use.
 * \param omit      The number of bytes at the end of the last output
 *                  buffer obtained from mbedtls_writer_get() that should
 *                  not be committed.
 *
 * \note            After this function has been called, all
 *                  output buffers obtained from prior calls to
 *                  mbedtls_writer_get() are invalid and must not
 *                  be used anymore.
 *
 * \return          \c 0 on success. In this case, the writer
 *                  stays in consuming mode.
 * \return          #MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION
 *                  if the writer is not in consuming mode.
 *                  In this case, the writer is unchanged and
 *                  can still be used.
 * \return          Another negative error code otherwise. In this case,
 *                  the state of the writer is unspecified and it must
 *                  not be used anymore.
 *
 */

/*@
  WRITER_INV_REQUIRES(writer)
  WRITER_INV_ENSURES(writer)
  @*/
int mbedtls_writer_commit_partial( mbedtls_writer *writer, size_t omit );

/**
 * \brief           Request buffer to hold outbound data.
 *
 *                  This function must only be called when the writer
 *                  is in consuming mode.
 *
 * \param writer    The writer context to use.
 * \param desired   The desired size of the outgoing data buffer.
 * \param buffer    The address at which to store the address
 *                  of the outgoing data buffer on success.
 * \param buflen    The address at which to store the actual
 *                  size of the outgoing data buffer on success.
 *                  May be \c NULL (see below).
 *
 * \note            If \p buflen is NULL, the function fails
 *                  if it cannot provide an outgoing data buffer
 *                  of the requested size \p desired.
 *
 * \return          \c 0 on success. In this case, the writer
 *                  stays in consuming mode.
 * \return          #MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION
 *                  if the writer is not in consuming mode.
 *                  In this case, the writer is unchanged and
 *                  can still be used.
 * \return          #MBEDTLS_ERR_WRITER_OUT_OF_SPACE if there is not
 *                  enough space available to serve the request.
 *                  In this case, the writer remains intact, and
 *                  additional space can be provided by reclaiming
 *                  the current output buffer via mbedtls_writer_reclaim()
 *                  and feeding a new one via mbedtls_writer_feed().
 * \return          Another negative error code otherwise. In this case,
 *                  the state of the writer is unspecified and it must
 *                  not be used anymore.
 *
 */

/*@
  requires \valid( buffer );
  requires ( buflen == NULL ) || \valid( buflen );
  WRITER_INV_REQUIRES(writer)
  WRITER_INV_ENSURES(writer)
  @*/
int mbedtls_writer_get( mbedtls_writer *writer, size_t desired,
                        unsigned char **buffer, size_t *buflen );

/**
 * \brief           Initialize an extended writer object
 *
 * \param writer    The extended writer context to initialize.
 * \param size      The total size of the logical buffer to
 *                  be managed by the extended writer.
 *
 * \return          \c 0 on success.
 * \return          A negative error code \c MBEDTLS_ERR_WRITER_XXX on failure.
 *
 */

/*@
  requires \valid( writer );
  WRITER_EXT_INV_ENSURES( writer )
  @*/
int mbedtls_writer_init_ext( mbedtls_writer_ext *writer,
                             size_t size );

/**
 * \brief           Free an extended writer object
 *
 * \param writer    The extended writer context to be freed.
 *
 * \return          \c 0 on success.
 * \return          A negative error code \c MBEDTLS_ERR_WRITER_XXX on failure.
 *
 */
/*@
  WRITER_EXT_INV_REQUIRES( writer )
  @*/
int mbedtls_writer_free_ext( mbedtls_writer_ext *writer );

/**
 * \brief           Request buffer to hold outbound data.
 *
 * \param writer    The extended writer context to use.
 * \param desired   The desired size of the outgoing data buffer.
 * \param buffer    The address at which to store the address
 *                  of the outgoing data buffer on success.
 * \param buflen    The address at which to store the actual
 *                  size of the outgoing data buffer on success.
 *                  May be NULL (see below).
 *
 * \note            If \p buflen is \c NULL, the function fails
 *                  if it cannot provide an outgoing data buffer
 *                  of the requested size \p desired.
 *
 * \return          \c 0 on success. In this case, \c *buf holds the
 *                  address of a buffer of size \c *buflen
 *                  (if \c buflen != NULL) or \p desired
 *                  (if \c buflen is \c NULL).
 * \return          #MBEDTLS_ERR_WRITER_BOUNDS_VIOLATION if the write
 *                  request exceeds the bounds of the current group.
 *
 */

/*@
  requires \valid( buffer );
  requires ( buflen == NULL ) || \valid( buflen );
  WRITER_EXT_INV_REQUIRES(writer)
  WRITER_EXT_INV_ENSURES(writer)
  @*/
int mbedtls_writer_get_ext( mbedtls_writer_ext *writer, size_t desired,
                            unsigned char **buffer, size_t *buflen );

/**
 * \brief           Signal that all output buffers previously obtained
 *                  from mbedtls_writer_get() are ready to be dispatched.
 *
 * \param writer    The extended writer context to use.
 *
 * \note            After this function has been called, all
 *                  output buffers obtained from prior calls to
 *                  mbedtls_writer_get() are invalid and must not
 *                  be accessed anymore.
 *
 * \return          \c 0 on success.
 * \return          A negative error code \c MBEDTLS_ERR_WRITER_XXX on failure.
 *
 */
/*@
  WRITER_EXT_INV_REQUIRES(writer)
  WRITER_EXT_INV_ENSURES(writer)
  @*/
int mbedtls_writer_commit_ext( mbedtls_writer_ext *writer );

/**
 * \brief            Open a new logical subbuffer.
 *
 * \param writer     The extended writer context to use.
 * \param group_size The offset of the end of the subbuffer
 *                   from the end of the last successful fetch.
 *
 * \return           \c 0 on success.
 * \return           #MBEDTLS_ERR_WRITER_BOUNDS_VIOLATION if
 *                   the new group is not contained in the
 *                   current group. In this case, the extended
 *                   writer is unchanged and hence remains intact.
 * \return           #MBEDTLS_ERR_WRITER_TOO_MANY_GROUPS if the internal
 *                   threshold for the maximum number of groups exceeded.
 *                   This is an internal error, and it should be
 *                   statically verifiable that it doesn't occur.
 * \return           Another negative error code otherwise.
 *
 */
/*@
  WRITER_EXT_INV_REQUIRES(writer)
  WRITER_EXT_INV_ENSURES(writer)
  @*/
int mbedtls_writer_group_open( mbedtls_writer_ext *writer,
                               size_t group_size );

/**
 * \brief            Close the most recently opened logical subbuffer.
 *
 * \param writer     The extended writer context to use.
 *
 * \return           \c 0 on success.
 * \return           #MBEDTLS_ERR_WRITER_BOUNDS_VIOLATION if
 *                   the current logical subbuffer hasn't been
 *                   fully fetched and committed.
 * \return           #MBEDTLS_ERR_WRITER_NO_GROUP if there is no
 *                   group opened currently.
 * \return           Another negative error code otherwise.
 *
 */
/*@
  WRITER_EXT_INV_REQUIRES(writer)
  WRITER_EXT_INV_ENSURES(writer)
  @*/
int mbedtls_writer_group_close( mbedtls_writer_ext *writer );

/**
 * \brief           Attach a writer to an extended writer.
 *
 *                  Once a writer has been attached to an extended writer,
 *                  subsequent calls to mbedtls_writer_commit_ext() and
 *                  mbedtls_writer_get_ext() will be routed through the
 *                  corresponding calls to mbedtls_writer_commit() resp.
 *                  mbedtls_writer_get() after the extended writer has
 *                  done its bounds checks.
 *
 * \param wr_ext    The extended writer context to use.
 * \param wr        The writer to bind to the extended writer \p wr_ext.
 *
 * \return          \c 0 on success.
 * \return          A negative error code \c MBEDTLS_ERR_WRITER_XXX on failure.
 *
 */
/*@
  WRITER_EXT_INV_REQUIRES(wr_ext)
  WRITER_INV_REQUIRES(wr)
  WRITER_EXT_INV_ENSURES(wr_ext)
  @*/
int mbedtls_writer_attach( mbedtls_writer_ext *wr_ext,
                           mbedtls_writer *wr );
/**
 * \brief            Detach a writer from an extended writer.
 *
 * \param wr_ext     The extended writer context to use.
 *
 * \return           \c 0 on success.
 * \return           A negative error code \c MBEDTLS_ERR_WRITER_XXX on failure.
 *
 */
/*@
  WRITER_EXT_INV_REQUIRES(wr_ext)
  WRITER_EXT_INV_ENSURES(wr_ext)
  @*/
int mbedtls_writer_detach( mbedtls_writer_ext *wr_ext );

/**
 * \brief            Check if the extended writer is finished processing
 *                   the logical buffer it was setup with.
 *
 * \param wr_ext     The extended writer context to use.
 *
 * \return           \c 0 if all groups opened via mbedtls_writer_group_open()
 *                   have been closed via mbedtls_writer_group_close(),
 *                   and the entire logical buffer as defined by the \c size
 *                   argument in mbedtls_writer_init_ext() has been processed.
 * \return           A negative \c MBEDTLS_ERR_WRITER_XXX error code otherwise.
 *
 */
/*@
  WRITER_EXT_INV_REQUIRES(writer)
  WRITER_EXT_INV_ENSURES(writer)
  @*/
int mbedtls_writer_check_done( mbedtls_writer_ext *writer );

/* /\** */
/*  * \brief           Get the writer's state */
/*  * */
/*  * \param writer    Writer context */
/*  * */
/*  * \return          The last state set at a call to mbedtls_writer_commit, */
/*  *                  or 0 if the reader is used for the first time and hasn't */
/*  *                  been paused before. */
/*  *\/ */
/* This has been included in the original MPS API specification,
 * but it hasn't been decided yet if we want to keep the state of
 * the writing within the writing or leave it to the user to save it
 * in an appropriate place, e.g. the handshake structure.
 * TODO: Make a decision, and potentially remove this declaration
 *       if the state is saved elsewhere.
 *       If this function is needed, the mbedtls_writer_commit
 *       function should get an additional state argument. */
/* int mbedtls_writer_state( mbedtls_writer_ext *writer ); */

#endif /* MBEDTLS_WRITER_H */
