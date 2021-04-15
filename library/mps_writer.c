/*
 *  Message Processing Stack, Reader implementation
 *
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

#include "common.h"

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#include "mps_writer.h"
#include "mps_trace.h"

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

#if defined(MBEDTLS_MPS_ENABLE_TRACE)
static int mbedtls_mps_trace_id = MBEDTLS_MPS_TRACE_BIT_WRITER;
#endif /* MBEDTLS_MPS_ENABLE_TRACE */

#define MIN( x, y ) ( ( x ) < ( y ) ? ( x ) : ( y ) )

#include <string.h>

void mbedtls_mps_writer_init( mbedtls_mps_writer *wr,
                              unsigned char *queue,
                              mbedtls_mps_size_t queue_len )
{
    mbedtls_mps_writer dst =  { .state = MBEDTLS_MPS_WRITER_PROVIDING,
                                .out   = NULL,
                                .queue = queue,
                                .out_len   = 0,
                                .queue_len = queue_len,
                                .committed = 0,
                                .end       = 0,
                                .queue_next      = 0,
                                .queue_remaining = 0 };

    *wr = dst;
}

void mbedtls_mps_writer_free( mbedtls_mps_writer *wr )
{
    mbedtls_mps_writer_init( wr, NULL, 0 );
}

int mbedtls_mps_writer_feed( mbedtls_mps_writer *wr,
                             unsigned char *buf,
                             mbedtls_mps_size_t buf_len )
{
    unsigned char *queue;
    mbedtls_mps_size_t copy_from_queue;
    MBEDTLS_MPS_TRACE_INIT( "writer_feed, buflen %u",
                            (unsigned) buf_len );

    /* Feeding is only possible in providing state. */
    MBEDTLS_MPS_STATE_VALIDATE_RAW(
        wr->state == MBEDTLS_MPS_WRITER_PROVIDING,
        "Attempt to feed output buffer to writer outside providing mode." );

    /* Check if there is data in the queue pending to be dispatched. */
    queue = wr->queue;
    copy_from_queue = 0;
    if( queue != NULL )
    {
        mbedtls_mps_size_t queue_next = wr->queue_next;
        mbedtls_mps_size_t queue_remaining = wr->queue_remaining;

        MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                           "Queue data pending to be dispatched: %u",
                           (unsigned) wr->queue_remaining );

        /* Copy as much data from the queue to
         * the provided buffer as possible. */
        copy_from_queue = MIN( queue_remaining, buf_len );
        queue += queue_next;

        if( copy_from_queue > 0 )
        {
            memcpy( buf, queue, copy_from_queue );
            queue_remaining -= copy_from_queue;
        }

        /* Check if, after the last copy, the entire
         * queue has been dispatched. */
        if( queue_remaining > 0 )
        {
            /* More data waiting in the queue */
            MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                               "There are %u bytes remaining in the queue.",
                               (unsigned) queue_remaining );

            queue_next += copy_from_queue;
            wr->queue_remaining = queue_remaining;
            wr->queue_next = queue_next;
            MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_WRITER_NEED_MORE );
        }

        /* The queue is empty. */
        MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                           "Queue has been fully dispatched" );
        wr->queue_next = 0;
        wr->queue_remaining = 0;

        /* NOTE: Currently this returns success if the provided output
         *       buffer is exactly as big as the remaining queue,
         *       in which case there is no space left after the
         *       queue has been copied. Is that intentional? */

    }

    wr->out = buf;
    wr->out_len = buf_len;
    wr->committed = copy_from_queue;
    wr->end = copy_from_queue;
    wr->state = MBEDTLS_MPS_WRITER_CONSUMING;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

static int mps_writer_out_buffer_is_committed( mbedtls_mps_writer *wr )
{
    mbedtls_mps_size_t const committed = wr->committed;
    mbedtls_mps_size_t const out_len   = wr->out_len;

    return( committed >= out_len );
}

static int mps_writer_some_data_in_queue_is_committed( mbedtls_mps_writer *wr )
{
    mbedtls_mps_size_t const committed = wr->committed;
    mbedtls_mps_size_t const out_len   = wr->out_len;
    mbedtls_mps_size_t const overlap   = wr->queue_next;

    return( committed > out_len - overlap );
}

static void mps_writer_copy_queue_to_out_buffer( mbedtls_mps_writer *wr )
{
    mbedtls_mps_size_t queue_size, copy_from_queue;
    mbedtls_mps_size_t queue_overlap, committed, out_len;
    unsigned char * const queue = wr->queue;
    unsigned char * out = wr->out;

    if( !mps_writer_some_data_in_queue_is_committed( wr ) )
        return;

    committed = wr->committed;
    out_len = wr->out_len;
    queue_overlap = wr->queue_next;

    queue_size = committed - ( out_len - queue_overlap );
    copy_from_queue = MIN( queue_overlap, queue_size );

    if( copy_from_queue > 0 )
    {
        out += out_len - queue_overlap;
        memcpy( out, queue, copy_from_queue );
    }
}

int mbedtls_mps_writer_reclaim( mbedtls_mps_writer *wr,
                                mbedtls_mps_size_t *written,
                                mbedtls_mps_size_t *queued,
                                int force )
{
    mbedtls_mps_size_t committed, out_len;
    MBEDTLS_MPS_TRACE_INIT( "writer_reclaim" );
    MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                       " * Force reclaim: %u", (unsigned) force );

    /* Check that the writer is in consuming mode. */
    MBEDTLS_MPS_STATE_VALIDATE_RAW(
        wr->state == MBEDTLS_MPS_WRITER_CONSUMING,
        "Can't reclaim output buffer outside of consuming mode." );

    committed = wr->committed;
    out_len = wr->out_len;

    /* Ignore uncommitted data */
    wr->end = committed;

    if( written != NULL )
        *written = MIN( committed, out_len );

    /* Copy the overlapping head of the queue to the tail of the fragment.  */
    mps_writer_copy_queue_to_out_buffer( wr );

    /* Check if there's space left unused. */
    if( !mps_writer_out_buffer_is_committed( wr ) )
    {
        if( queued != NULL )
            *queued = 0;

        wr->queue_next = 0;

        if( force == MBEDTLS_MPS_WRITER_RECLAIM_NO_FORCE )
            MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_WRITER_DATA_LEFT );
    }
    else
    {
        wr->queue_remaining = committed - out_len;
        if( queued != NULL )
            *queued = wr->queue_remaining;
    }

    wr->end = 0;
    wr->committed = 0;
    wr->out = NULL;
    wr->out_len = 0;
    wr->state = MBEDTLS_MPS_WRITER_PROVIDING;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

static int mps_writer_queue_is_in_use( mbedtls_mps_writer *wr )
{
    mbedtls_mps_size_t const end     = wr->end;
    mbedtls_mps_size_t const out_len = wr->out_len;
    mbedtls_mps_size_t const overlap = wr->queue_next;

    return( end >= out_len - overlap );
}

int mbedtls_mps_writer_get( mbedtls_mps_writer *wr,
                            mbedtls_mps_size_t desired,
                            unsigned char **buffer,
                            mbedtls_mps_size_t *buflen )
{
    unsigned char *out, *queue;
    mbedtls_mps_size_t end, out_len, out_remaining, queue_len;
    mbedtls_mps_size_t queue_next, queue_offset, queue_remaining;
    MBEDTLS_MPS_TRACE_INIT( "writer_get, desired %u", (unsigned) desired );

    MBEDTLS_MPS_STATE_VALIDATE_RAW( wr->state == MBEDTLS_MPS_WRITER_CONSUMING,
                  "Attempt to request write-buffer outside consuming mode." );

    end = wr->end;
    out_len = wr->out_len;

    queue = wr->queue;
    queue_len = wr->queue_len;

    if( !mps_writer_queue_is_in_use( wr ) )
    {
        /* We're still serving from the output buffer.
         * Check if there's enough space left in it. */
        out_remaining = out_len - end;
        MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                           "%u bytes remaining in output buffer",
                           (unsigned) out_remaining );
        if( out_remaining < desired )
        {
            /* Switch to the queue if it offers more space
             * than what's remaining in the output buffer. */
            if( queue != NULL && queue_len > out_remaining )
            {
                MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                                   "switch to queue",
                                   (unsigned) desired, (unsigned) out_remaining );

                wr->queue_next = out_remaining;
                goto use_queue;
            }

            /* Adjust request size if allowed */
            if( buflen == NULL )
            {
                MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                                "not enough data available, no queue present" );
                MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_WRITER_OUT_OF_DATA );
            }

            desired = out_remaining;
        }

        /* We reach this if the (potentially modified) request can be
         * served from the output buffer. */

        out = wr->out;
        out += end;
        end += desired;
        wr->end = end;

        *buffer = out;
        if( buflen != NULL)
            *buflen = desired;

        MBEDTLS_MPS_TRACE_RETURN( 0 );
    }

use_queue:

    MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                       "attempt to serve from queue" );

    /* If we're serving from the queue, queue_next denotes
     * the size of the overlap between queue and output buffer. */
    queue_next = wr->queue_next;
    queue_offset = end - ( out_len - queue_next );

    /* Adjust request size if allowed and queue is too small. */
    queue_remaining = queue_len - queue_offset;
    if( queue_remaining < desired )
    {
        if( buflen == NULL )
        {
            MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                               "not enough space remaining in queue" );
            MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_WRITER_OUT_OF_DATA );
        }

        desired = queue_len - queue_offset;
    }

    MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                       "serving %u bytes from queue", (unsigned) desired );

    end += desired;
    wr->end = end;

    *buffer = queue + queue_offset;
    if( buflen != NULL )
        *buflen = desired;

    MBEDTLS_MPS_TRACE_RETURN( 0 );

}
int mbedtls_mps_writer_commit_partial( mbedtls_mps_writer *wr,
                                   mbedtls_mps_size_t omit )
{
    mbedtls_mps_size_t to_be_committed, committed, end;
    mbedtls_mps_size_t out_len, queue_overlap;
    MBEDTLS_MPS_TRACE_INIT( "writer_commit_partial" );
    MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                       "* Omit %u bytes", (unsigned) omit );

    MBEDTLS_MPS_STATE_VALIDATE_RAW(
        wr->state == MBEDTLS_MPS_WRITER_CONSUMING,
        "Attempt to request write-buffer outside consuming state." );

    committed     = wr->committed;
    end           = wr->end;
    out_len       = wr->out_len;
    queue_overlap = wr->queue_next;

    if( omit > end - committed )
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_WRITER_INVALID_ARG );

    to_be_committed = end - omit;

    if( to_be_committed < out_len - queue_overlap )
        wr->queue_next = 0;

    MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                       "* Last commit:       %u", (unsigned) committed );
    MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                       "* End of last fetch: %u", (unsigned) end );
    MBEDTLS_MPS_TRACE( MBEDTLS_MPS_TRACE_TYPE_COMMENT,
                       "* New commit:        %u", (unsigned) to_be_committed );

    wr->end       = to_be_committed;
    wr->committed = to_be_committed;

    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mbedtls_mps_writer_commit( mbedtls_mps_writer *wr )
{
    return( mbedtls_mps_writer_commit_partial( wr, 0 ) );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
