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
 * New buffers can be requested through calls to mbedtls_reader_get(),
 * while previously obtained input buffers can be marked processed
 * through calls to mbedtls_reader_consume(), emptying the list of
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
 * done via calls to mbedtls_reader_feed(), while transitioning
 * from Consuming to either Unset or Accumulating (depending
 * on what has been processed) is done via mbedtls_reader_reclaim().
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

#ifndef MBEDTLS_READER_H
#define MBEDTLS_READER_H

#include <stdio.h>

struct mbedtls_reader;
typedef struct mbedtls_reader mbedtls_reader;

struct mbedtls_reader_ext;
typedef struct mbedtls_reader_ext mbedtls_reader_ext;

#define MBEDTLS_ERR_READER_DATA_LEFT             -0x1  /*!< An attempt to reclaim the data buffer from a reader failed because
                                                        *   the user hasn't yet read and committed all of it.                             */
#define MBEDTLS_ERR_READER_INVALID_ARG           -0x2  /*!< The parameter validation failed.                                              */
#define MBEDTLS_ERR_READER_NEED_MORE             -0x3  /*!< An attempt to move a reader to consuming mode through mbedtls_reader_feed()
                                                        *   after pausing failed because the provided data is not sufficient to serve the
                                                        *   the read requests that lead to the pausing.                                   */
#define MBEDTLS_ERR_READER_OUT_OF_DATA           -0x5  /*!< A read request failed because not enough data is available in the reader.     */
#define MBEDTLS_ERR_READER_INCONSISTENT_REQUESTS -0x6  /*!< A read request after pausing and reactivating the reader failed because
                                                        *   the request is not in line with the request made prior to pausing. The user
                                                        *   must not change it's 'strategy' after pausing and reactivating a reader.      */
#define MBEDTLS_ERR_READER_UNEXPECTED_OPERATION  -0x7  /*!< The requested operation is not possible in the current state of the reader.   */
#define MBEDTLS_ERR_READER_NEED_ACCUMULATOR      -0x69 /*!< An attempt to reclaim the data buffer from a reader fails because the reader
                                                        *   has no accumulator it can use to backup the data that hasn't been processed.  */
#define MBEDTLS_ERR_READER_ACCUMULATOR_TOO_SMALL -0x6a /*!< An attempt to reclaim the data buffer from a reader fails beacuse the
                                                        *   accumulator passed to the reader is not large enough to hold both the
                                                        *   data that hasn't been processed and the excess of the last read-request.      */

#define MBEDTLS_ERR_READER_BOUNDS_VIOLATION      -0x9  /*!< The attempted operation violates the bounds of the currently active group.    */
#define MBEDTLS_ERR_READER_TOO_MANY_GROUPS       -0xa  /*!< The extended reader has reached the maximum number of groups, and another
                                                        *   group cannot be opened.                                                       */

#define MBEDTLS_READER_MAX_GROUPS 5

/*
 * Structure definitions
 */

struct mbedtls_reader
{
    unsigned char *frag;  /*!< The fragment of incoming data managed by
                           *   the reader; it is provided to the reader
                           *   through mbedtls_reader_fetch(). The reader
                           *   does not own the fragment and does not
                           *   perform any allocation operations on it,
                           *   but does have read and write access to it.   */
    size_t frag_len;      /*!< The length of the current fragment.
                           *   Must be 0 if \c frag == \c NULL.             */
    size_t commit;        /*!< The offset of the last commit, relative
                           *   to the first byte in the accumulator.
                           *   This is only used when the reader is in
                           *   consuming mode, i.e. frag != NULL;
                           *   otherwise, its value is \c 0
                           *   (invariant READER_INV_FRAG_UNSET_VARS_ZERO). */
    size_t end;           /*!< The offset of the end of the last chunk
                           *   passed to the user through a call to
                           *   mbedtls_reader_get(), relative to the first
                           *   byte in the accumulator.
                           *   This is only used when the reader is in
                           *   consuming mode, i.e. \c frag != \c NULL;
                           *   otherwise, its value is \c 0
                           *   (invariant READER_INV_FRAG_UNSET_VARS_ZERO). */
    size_t pending;       /*!< The amount of incoming data missing on the
                           *   last call to mbedtls_reader_get().
                           *   In particular, it is \c 0 if the last call
                           *   was successful.
                           *   If a reader is reclaimed after an
                           *   unsuccessful call to mbedtls_reader_get(),
                           *   this variable is used to have the reader
                           *   remember how much data should be accumulated
                           *   before the reader can be passed back to
                           *   the user again.
                           *   This is only used when the reader is in
                           *   consuming mode, i.e. \c frag != \c NULL;
                           *   otherwise, its value is \c 0
                           *   (invariant READER_INV_FRAG_UNSET_VARS_ZERO). */

    /* This is only needed if we need to be able
     * to pause the reader. A few bytes could be
     * saved by moving this to a separate struct
     * and using a pointer here. */
    unsigned char *acc;   /*!< The accumulator is used to gather incoming
                           *   data if a read-request via mbedtls_reader_get()
                           *   cannot be served from the current fragment.  */
    size_t acc_len;       /*!< The total size of the accumulator.           */
    size_t acc_avail;     /*!< The number of bytes currently gathered in
                           *   the accumulator. This is both used in
                           *   producing and in consuming mode:
                           *   While producing, it is increased until
                           *   it reaches the value of \c acc_remaining below.
                           *   While consuming, it is used to judge if a
                           *   read request can be served from the
                           *   accumulator or not.
                           *   Must not be larger than acc_len
                           *   (invariant READER_INV_ACC_AVAIL).            */
    union
    {
        size_t acc_remaining; /*!< This indicates the amount of data still
                               *   to be gathered in the accumulator. It is
                               *   only used in producing mode.
                               *   Must be at most acc_len - acc_available
                               *   (inv READER_INV_ACC_SET_AVAIL_REMAINING). */
        size_t frag_offset;   /*!< This indicates the offset of the current
                               *   fragment from the beginning of the
                               *   accumulator.
                               *   It is only used in consuming mode.
                               *   Must not be larger than \c acc_avail
                               *   (invariant READER_INV_ACC_CONSUME).      */
    } acc_share;
};

/*
 * Concrete to abstract state mapping:
 *
 * The concrete C-state of the reader maps the abstract producer state
 * in the following way:
 *
 * - The reader is in Attached/Consuming state if and only if frag is not NULL.
 * - If the reader is not in Attached/Consuming state, it is in state Unset
 *   resp. Accumulating if and only if acc_share.acc_remaining is 0 resp. bigger
 *   than 0.
 *
 */

/*
 * E-ACSL invariants for reader
 */

/* I don't know why E-ACSL allows the following predicates when spelled
 * out but forbids them when they are globally defined. Define them as
 * macros for now... ugly hack, but anyway. */

#define READER_INV_FRAG_VALID( p )                       \
    ( (p)->frag != NULL ==>                              \
      ( \forall integer i; 0 <= i < (p)->frag_len        \
        ==> \valid( (p)->frag+i ) ) )

#define READER_INV_FRAG_UNSET_VARS_ZERO( p )       \
    ( (p)->frag == NULL ==>                        \
      ( (p)->frag_len == 0 &&                      \
        (p)->commit   == 0 &&                      \
        (p)->end      == 0 &&                      \
        (p)->pending    == 0 ) )

#define READER_INV_ACC_VALID( p )                        \
    ( (p)->acc != NULL ==>                               \
      ( (p)->acc_len > 0 &&                              \
        ( \forall integer i; 0 <= i < (p)->acc_len       \
          ==> \valid( (p)->acc+i ) ) ) )

#define READER_INV_ACC_UNSET_VARS_ZERO( p )              \
    ( ( (p)->acc == NULL ) ==>                           \
      ( (p)->acc_len   == 0 &&                           \
        (p)->acc_avail == 0 &&                           \
        ( (p)->frag == NULL ==> (p)->acc_share.acc_remaining == 0 ) ) )

#define READER_INV_ACC_AVAIL( p )                   \
    ( (p)->acc_avail <= (p)->acc_len )

#define READER_INV_ACC_REMAINING( p )                 \
    ( (p)->frag == NULL ==>                           \
      (p)->acc_share.acc_remaining <= (p)->acc_len )

#define READER_INV_ACC_PREPARE( p )                \
    ( (p)->frag == NULL ==>                        \
      (p)->acc_share.acc_remaining <=              \
      (p)->acc_len - (p)->acc_avail )

#define READER_INV_ACC_CONSUME( p )                             \
    ( ( (p)->frag != NULL && (p)->acc != NULL ) ==>             \
      ( (p)->acc_share.frag_offset <= (p)->acc_avail ) )

#define READER_INV( p )                       \
    ( \valid( p )                          && \
      READER_INV_FRAG_VALID( p )           && \
      READER_INV_FRAG_UNSET_VARS_ZERO( p ) && \
      READER_INV_ACC_VALID( p )            && \
      READER_INV_ACC_UNSET_VARS_ZERO( p )  && \
      READER_INV_ACC_AVAIL( p )            && \
      READER_INV_ACC_REMAINING( p )        && \
      READER_INV_ACC_PREPARE( p )          && \
      READER_INV_ACC_CONSUME( p ) )

#define READER_INV_ENSURES( p )                      \
    ensures \valid( p );                             \
    ensures READER_INV_FRAG_VALID( p );


#define READER_INV_REQUIRES( p )                      \
    requires \valid ( p );                            \
    requires READER_INV_FRAG_VALID( p );              \
    requires READER_INV_FRAG_UNSET_VARS_ZERO( p );    \
    requires READER_INV_ACC_VALID( p );               \
    requires READER_INV_ACC_UNSET_VARS_ZERO( p );     \
    requires READER_INV_ACC_AVAIL( p );               \
    requires READER_INV_ACC_REMAINING( p );           \
    requires READER_INV_ACC_PREPARE( p );             \
    requires READER_INV_ACC_CONSUME( p );


struct mbedtls_reader_ext
{
    unsigned cur_grp; /*!< The 0-based index of the currently active group.
                       *   The group of index 0 always exists and represents
                       *   the entire logical message buffer.                 */
    size_t grp_end[MBEDTLS_READER_MAX_GROUPS];
                      /*!< The offsets marking the ends of the currently
                       *   active groups. The first cur_grp + 1 entries are
                       *   valid and always weakly descending (subsequent
                       *   groups are subgroups of their predecessors ones).  */

    mbedtls_reader *rd; /*!< Underlying writer object - may be \c NULL.       */
    size_t ofs_fetch;   /*!< The offset of the first byte of the next chunk.  */
    size_t ofs_commit;  /*!< The offset of first byte beyond
                         *   the last committed chunk.                        */
};

#define READER_EXT_INV_CUR_GRP_VALID( p )               \
    ( (p)->cur_grp < MBEDTLS_READER_MAX_GROUPS )

#define READER_EXT_INV_GRP_DESCENDING( p )             \
    ( \forall integer i; 0 < i <= (p)->cur_grp ==>     \
      (p)->grp_end[i - 1] >= (p)->grp_end[i] )

#define READER_EXT_INV_ROOT_GROUP_BOUNDS( p )   \
    ( (p)->ofs_fetch <= (p)->grp_end[0] )

#define READER_EXT_INV_COMMIT_FETCH( p )        \
    ( (p)->ofs_commit <= (p)->ofs_fetch )

#define READER_EXT_INV_COMMIT_FETCH_DETACHED( p )   \
    ( (p)->rd == NULL ==>                           \
      ( (p)->ofs_commit <= (p)->ofs_fetch ) )

#define READER_EXT_INV_ENSURES( p )                     \
    ensures READER_EXT_INV_CUR_GRP_VALID( p );          \
    ensures READER_EXT_INV_GRP_DESCENDING( p );         \
    ensures READER_EXT_INV_ROOT_GROUP_BOUNDS( p );      \
    ensures READER_EXT_INV_COMMIT_FETCH( p );           \
    ensures READER_EXT_INV_COMMIT_FETCH_DETACHED( p );

#define READER_EXT_INV_REQUIRES( p )                     \
    requires READER_EXT_INV_CUR_GRP_VALID( p );          \
    requires READER_EXT_INV_GRP_DESCENDING( p );         \
    requires READER_EXT_INV_ROOT_GROUP_BOUNDS( p );      \
    requires READER_EXT_INV_COMMIT_FETCH( p );           \
    requires READER_EXT_INV_COMMIT_FETCH_DETACHED( p );

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
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_READER_XXX error code on failure.
 */

/*@
  requires \valid( reader );
  requires ( acc != NULL ==>
             ( acc_len > 0 &&
               \forall integer i; 0 <= i < acc_len
                 ==> \valid( acc + i ) ) );
  READER_INV_ENSURES(reader)
@*/
int mbedtls_reader_init( mbedtls_reader *reader,
                         unsigned char *acc, size_t acc_len );

/**
 * \brief           Free a reader object
 *
 * \param reader    The reader to be freed.
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_READER_XXX error code on failure.
 */

/*@
  READER_INV_REQUIRES(reader)
  @*/
int mbedtls_reader_free( mbedtls_reader *reader );

/**
 * \brief           Pass chunk of data for the reader to manage
 *
 * \param reader    The reader context to use.
 * \param buf       The buffer to be managed by the reader.
 * \param buflen    The length of \p buffer
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_READER_XXX error code on failure.
 */

/*@
  READER_INV_REQUIRES(reader)
  requires ( \forall integer i; 0 <= i < buflen
                 ==> \valid( buf + i ) );

  READER_INV_ENSURES(reader)
  @*/
int mbedtls_reader_feed( mbedtls_reader *reader,
                         unsigned char *buf, size_t buflen );

/**
 * \brief           Reclaim reader's access to the current input buffer.
 *
 * \param reader    The reader context to use.
 * \param paused    If not \c NULL, its content will be modified to indicates
 *                  whether the reader has been paused (value \c 1) or not
 *                  (value \c 0).
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_READER_XXX error code on failure.
 */

/*@
  READER_INV_REQUIRES(reader)
  READER_INV_ENSURES(reader)
  @*/
int mbedtls_reader_reclaim( mbedtls_reader *reader, size_t *paused );

/*
 * Usage API (Upper layer)
 */

/**
 * \brief           Fetch a data chunk from the reader
 *
 * \param reader    The reader context to use.
 * \param desired   The desired amount of data to be read.
 * \param buffer    The address to store the buffer pointer in.
 * \param buflen    The address to store the actual buffer
 *                  length in, or \c NULL.
 *
 * \return          \c 0 on success. In this case, \c *buf holds the
 *                  address of a buffer of size \c *buflen
 *                  (if \c buflen != \c NULL) or \c desired
 *                  (if \c buflen == \c NULL).
 * \return          #MBEDTLS_ERR_READER_OUT_OF_DATA if there is not enough
 *                  data available to serve the read request. In this case,
 *                  the reader remains intact, and additional data can be
 *                  provided by reclaiming the current input buffer via
 *                  mbedtls_reader_reclaim() and feeding a new one via
 *                  mbedtls_reader_feed().
 * \return          Another negative \c MBEDTLS_ERR_READER_XXX error
 *                  code for different kinds of failure.
 *
 * \note            Passing \c NULL as \p buflen is a convenient way to
 *                  indicate that fragmentation is not tolerated.
 *                  It's functionally equivalent to passing a valid
 *                  address as buflen and checking \c *buflen == \c desired
 *                  afterwards.
 */

/*@
  requires \valid( buffer );
  requires ( buflen == NULL ) || \valid( buflen );
  READER_INV_REQUIRES(reader)
  READER_INV_ENSURES(reader)
  @*/
int mbedtls_reader_get( mbedtls_reader *reader, size_t desired,
                        unsigned char **buffer, size_t *buflen );

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

/*@
  READER_INV_REQUIRES(reader)
  READER_INV_ENSURES(reader)
  @*/
int mbedtls_reader_commit( mbedtls_reader *reader );

/* /\** */
/*  * \brief                Query for the number of bytes remaining in the */
/*  *                       latest logical sub-buffer. */
/*  * */
/*  * \param   reader       Reader context */
/*  * */
/*  * \return               Number of bytes remaining in the last group */
/*  *                       opened via `mbedtls_reader_group_open`; if there */
/*  *                       is no such, the number of byts remaining in the */
/*  *                       entire message. */
/*  * */
/*  * \note                 This is independent of the number of bytes actually */
/*  *                       internally available within the reader. */
/*  *\/ */
/* This was included in the original MPS API specification,
 * but currently there doesn't seem to be a need for it.
 * TODO: Remove once the MPS integration has been completed
 *       and this function hasn't been used. */
/* size_t mbedtls_reader_bytes_remaining( mbedtls_reader *reader ); */


/*
 * Interface for extended reader
 */

/**
 * \brief           Initialize an extended reader object
 *
 * \param reader    The extended reader context to initialize.
 * \param size      The total size of the logical buffer to
 *                  be managed by the extended reader.
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_READER_XXX error code on failure.
 *
 */
/*@
  requires \valid( reader );
  READER_EXT_INV_ENSURES( reader )
  @*/
int mbedtls_reader_init_ext( mbedtls_reader_ext *reader,
                             size_t size );

/**
 * \brief           Free an extended reader object
 *
 * \param reader    The extended reader context to be freed.
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_READER_XXX error code on failure.
 *
 */
/*@
  READER_EXT_INV_REQUIRES( reader )
  @*/
int mbedtls_reader_free_ext( mbedtls_reader_ext *reader );

/**
 * \brief           Fetch a data chunk from an extended reader
 *
 * \param reader    The extended reader to be used.
 * \param desired   The desired amount of incoming data to be read.
 * \param buffer    The address at which to store the address
 *                  of the incoming data buffer on success.
 * \param buflen    The address at which to store the actual
 *                  size of the incoming data buffer on success.
 *                  May be \c NULL (see below).
 *
 * \return          \c 0 on success. In this case, \c *buf holds the
 *                  address of a buffer of size \c *buflen
 *                  (if \c buflen != NULL) or \p desired
 *                  (if \c buflen == \c NULL).
 * \return          #MBEDTLS_ERR_READER_BOUNDS_VIOLATION if the read
 *                  request exceeds the bounds of the current group.
 * \return          Another negative \c MBEDTLS_ERR_READER_XXX error
 *                  for other kinds of failure.
 *
 * \note            Passing \c NULL as buflen is a convenient way to
 *                  indicate that fragmentation is not tolerated.
 *                  It's functionally equivalent to passing a valid
 *                  address as buflen and checking \c *buflen == \c desired
 *                  afterwards.
 *
 *
 */

/*@
  requires \valid( buffer );
  requires ( buflen == NULL ) || \valid( buflen );
  READER_EXT_INV_REQUIRES(reader)
  READER_EXT_INV_ENSURES(reader)
  @*/
int mbedtls_reader_get_ext( mbedtls_reader_ext *reader, size_t desired,
                            unsigned char **buffer, size_t *buflen );

/**
 * \brief           Signal that all input buffers previously obtained
 *                  from mbedtls_reader_get_ext are fully processed.

 * \param reader    The extended reader context to use.
 *
 *                  This function marks the previously fetched data as fully
 *                  processed and invalidates their respective buffers.
 *
 * \warning         Once this function is called, you must not use the
 *                  pointers corresponding to the committed data anymore.
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_READER_XXX error code on failure.
 *
 */

/*@
  READER_EXT_INV_REQUIRES(reader)
  READER_EXT_INV_ENSURES(reader)
  @*/
int mbedtls_reader_commit_ext( mbedtls_reader_ext *reader );

/**
 * \brief            Open a new logical subbuffer.
 *
 * \param reader     The extended reader context to use.
 * \param group_size The offset of the end of the subbuffer
 *                   from the end of the last successful fetch.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_READER_BOUNDS_VIOLATION if
 *                  the new  group is not contained in the
 *                  current group. In this case, the extended
 *                  reader is unchanged and hence remains intact.
 *                  This is a very important error condition that
 *                  catches e.g. if the length field for some
 *                  substructure (e.g. an extension within a Hello
 *                  message) claims that substructure to be larger
 *                  than the message itself.
 * \return          #MBEDTLS_ERR_READER_TOO_MANY_GROUPS if the internal
 *                  threshold for the maximum number of groups exceeded.
 *                  This is an internal error, and it should be
 *                  statically verifiable that it doesn't occur.
 * \return          Another negative \c MBEDTLS_ERR_READER_XXX error
 *                  for other kinds of failure.
 *
 */

/*@
  READER_EXT_INV_REQUIRES(reader)
  READER_EXT_INV_ENSURES(reader)
  @*/
int mbedtls_reader_group_open( mbedtls_reader_ext *reader,
                               size_t group_size );

/**
 * \brief           Close the most recently opened logical subbuffer.
 *
 * \param reader    The extended reader context to use.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_READER_BOUNDS_VIOLATION if
 *                  the current logical subbuffer hasn't been
 *                  fully fetched and committed.
 * \return          Another negative \c MBEDTLS_ERR_READER_XXX error
 *                  for other kinds of failure.
 *
 */

/*@
  READER_EXT_INV_REQUIRES(reader)
  READER_EXT_INV_ENSURES(reader)
  @*/
int mbedtls_reader_group_close( mbedtls_reader_ext *reader );

/**
 * \brief            Attach a reader to an extended reader.
 *
 *                   Once a reader has been attached to an extended reader,
 *                   subsequent calls to mbedtls_reader_commit_ext and
 *                   mbedtls_reader_get_ext will be routed through the
 *                   corresponding calls to mbedtls_reader_commit resp.
 *                   mbedtls_reader_get after the extended reader has
 *                   done its bounds checks.
 *
 * \param rd_ext     The extended reader context to use.
 * \param rd         The reader to bind to the extended reader \p rd_ext.
 *
 * \return           \c 0 on succes.
 * \return           #MBEDTLS_ERR_READER_DATA_LEFT if there is data
 *                   left uncommitted in the current group.
 * \return           #MBEDTLS_ERR_READER_NO_GROUP if there is no
 *                   group opened currently.
 * \return           Another negative error code for different kinds of failure.
 *
 */

/*@
  READER_EXT_INV_REQUIRES(rd_ext)
  READER_INV_REQUIRES(rd)
  READER_EXT_INV_ENSURES(rd_ext)
  @*/
int mbedtls_reader_attach( mbedtls_reader_ext *rd_ext,
                           mbedtls_reader *rd );

/**
 * \brief           Detach a reader from an extended reader.
 *
 * \param rd_ext    The extended reader context to use.
 *
 * \return          \c 0 on success.
 * \return          A negative \c MBEDTLS_ERR_READER_XXX error code on failure.
 *
 */

/*@
  READER_EXT_INV_REQUIRES(rd_ext)
  READER_EXT_INV_ENSURES(rd_ext)
  @*/
int mbedtls_reader_detach( mbedtls_reader_ext *rd_ext );

/**
 * \brief            Check if the extended reader is finished processing
 *                   the logical buffer it was setup with.
 *
 * \param rd_ext     The extended reader context to use.
 *
 * \return           \c 0 if all groups opened via mbedtls_reader_group_open()
 *                   have been closed via mbedtls_reader_group_close(), and
 *                   the entire logical buffer as defined by the \c size
 *                   argument in mbedtls_reader_init_ext() has been fetched
 *                   and committed.
 * \return           A negative \c MBEDTLS_ERR_READER_XXX error code otherwise.
 *
 */

/*@
  READER_EXT_INV_REQUIRES(rd_ext)
  @*/
int mbedtls_reader_check_done( mbedtls_reader_ext const *rd_ext );

/* /\** */
/*  * \brief           Fetch the reader state */
/*  * */
/*  * \param reader    Reader context */
/*  * \return          The last state set at a call to mbedtls_reader_commit, */
/*  *                  or 0 if the reader is used for the first time and hasn't */
/*  *                  been paused before. */
/*  * */
/*  * TO DISCUSS: */
/*  * We must have a way to hold back information while pausing the */
/*  * processing of a long incoming message. There are two alternatives here: */
/*  * 1) Provide a stack-like interface to save the temporary information */
/*  *    within a reader when pausing a reading process. */
/*  * 2) Save the temporary information in special fields in ssl_handshake. */
/*  *    One could use a union over the temporary structures for all messages, */
/*  *    as only one is needed at a time. */
/*  *\/ */
/* This has been included in the original MPS API specification,
 * but it hasn't been decided yet if we want to keep the state of
 * the reading within the reader or leave it to the user to save it
 * in an appropriate place, e.g. the handshake structure.
 * TODO: Make a decision, and potentially remove this declaration
 *       if the state is saved elsewhere.
 *       If this function is needed, the mbedtls_reader_commit
 *       function should get an additional state argument. */
/* int mbedtls_reader_state( mbedtls_reader_ext *reader ); */

#endif /* MBEDTLS_READER_H */
