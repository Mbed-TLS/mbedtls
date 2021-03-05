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
        mbedtls_mps_size_t queue_next, queue_remaining;
        queue_remaining = wr->queue_remaining;
        queue_next = wr->queue_next;
        MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                           "Queue data pending to be dispatched: %u",
                           (unsigned) wr->queue_remaining );

        /* Copy as much data from the queue to
         * the provided buffer as possible. */
        copy_from_queue = queue_remaining;
        if( copy_from_queue > buf_len )
            copy_from_queue = buf_len;
        queue += queue_next;

        if( copy_from_queue != 0 )
            memcpy( buf, queue, copy_from_queue );

        /* Check if, after the last copy, the entire
         * queue has been dispatched. */
        queue_remaining -= copy_from_queue;
        if( queue_remaining > 0 )
        {
            /* More data waiting in the queue */
            MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                               "There are %u bytes remaining in the queue.",
                               (unsigned) queue_remaining );

            queue_next += copy_from_queue;
            wr->queue_remaining = queue_remaining;
            wr->queue_next = queue_next;
            MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_WRITER_NEED_MORE );
        }

        /* The queue is empty. */
        MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment, "Queue is empty" );
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

int mbedtls_mps_writer_reclaim( mbedtls_mps_writer *wr,
                                mbedtls_mps_size_t *olen,
                                mbedtls_mps_size_t *queued,
                                int force )
{
    mbedtls_mps_size_t commit, out_len;
    MBEDTLS_MPS_TRACE_INIT( "writer_reclaim" );
    MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                       " * Force reclaim: %u", (unsigned) force );

    /* Check that the writer is in consuming mode. */
    MBEDTLS_MPS_STATE_VALIDATE_RAW(
        wr->state == MBEDTLS_MPS_WRITER_CONSUMING,
        "Can't reclaim output buffer outside of consuming mode." );

    /* Check if there's space left unused. */
    commit = wr->committed;
    out_len = wr->out_len;

    MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                       "* Committed: %u Bytes", (unsigned) commit );
    MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                       "* Buffer length: %u Bytes", (unsigned) out_len );

    if( commit <= out_len )
    {
        if( olen != NULL )
            *olen = commit;
        if( queued != NULL )
            *queued = 0;

        /* queue_next must be 0 if end <= out_len */
        wr->queue_next = 0;

        if( commit < out_len && force == 0 )
        {
            wr->end = commit;
            MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_WRITER_DATA_LEFT );
        }
    }
    else
    {
        /* The committed parts of the queue that
         * have no overlap with the current outgoing
         * data buffer need to be dispatched on
         * the next call(s) to mbedtls_mps_writer_fetch. */
        wr->queue_remaining = commit - out_len;
        /* No need to modify wr->queue_next */

        if( olen != NULL )
            *olen = out_len;
    }

    if( queued != NULL )
    {
        mbedtls_mps_size_t queue_remaining = wr->queue_remaining;
        MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                           "%u Bytes are queued for dispatching.",
                           (unsigned) wr->queue_remaining );
        *queued = queue_remaining;
    }

    wr->end = 0;
    wr->committed = 0;
    wr->out = NULL;
    wr->out_len = 0;
    wr->state = MBEDTLS_MPS_WRITER_PROVIDING;
    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mbedtls_mps_writer_bytes_written( mbedtls_mps_writer *wr,
                                      mbedtls_mps_size_t *written )
{
    mbedtls_mps_size_t commit;
    MBEDTLS_MPS_TRACE_INIT( "writer_bytes_written" );

    MBEDTLS_MPS_STATE_VALIDATE_RAW(
        wr->state == MBEDTLS_MPS_WRITER_PROVIDING,
        "Attempt to feed output buffer to writer outside providing mode." );

    commit = wr->committed;
    *written = commit;

    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mbedtls_mps_writer_get( mbedtls_mps_writer *wr,
                            mbedtls_mps_size_t desired,
                            unsigned char **buffer,
                            mbedtls_mps_size_t *buflen )
{
    unsigned char *out, *queue;
    mbedtls_mps_size_t end, out_len, out_remaining, queue_len;
    mbedtls_mps_size_t queue_next, queue_offset;
    MBEDTLS_MPS_TRACE_INIT( "writer_get, desired %u", (unsigned) desired );

    MBEDTLS_MPS_STATE_VALIDATE_RAW( wr->state == MBEDTLS_MPS_WRITER_CONSUMING,
                  "Attempt to request write-buffer outside consuming mode." );

    out = wr->out;
    end = wr->end;
    out_len = wr->out_len;

    /* Check if we're already serving from the queue */
    if( end > out_len )
    {
        MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                  "already serving from the queue, attempt to continue" );

        queue_len = wr->queue_len;
        /* If we're serving from the queue, queue_next denotes
         * the size of the overlap between queue and output buffer. */
        queue_next = wr->queue_next;
        queue_offset = queue_next + ( end - out_len );
        MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                   "queue overlap %u, queue used %u, queue remaining %u",
                   (unsigned) queue_next, (unsigned) queue_out,
                           (unsigned) ( queue_len - queue_offset ) );

        if( queue_len - queue_offset < desired )
        {
            if( buflen == NULL )
            {
                MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                                   "not enough space remaining in queue" );
                MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_WRITER_OUT_OF_DATA );
            }
            desired = queue_len - queue_offset;
        }

        MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                           "serving %u bytes from queue", (unsigned) desired );

        queue = wr->queue;
        end += desired;
        wr->end = end;

        *buffer = queue + queue_offset;
        if( buflen != NULL )
            *buflen = desired;

        MBEDTLS_MPS_TRACE_RETURN( 0 );
    }

    /* We're still serving from the output buffer.
     * Check if there's enough space left in it. */
    out_remaining = out_len - end;
    MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                       "%u bytes remaining in output buffer",
                       (unsigned) out_remaining );
    if( out_remaining < desired )
    {
        MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                           "need %u, but only %u remains in write buffer",
                           (unsigned) desired, (unsigned) out_remaining );

        queue     = wr->queue;
        queue_len = wr->queue_len;

        /* Out buffer is too small. Attempt to serve from queue if it is
         * available and larger than the remaining output buffer. */
        if( queue != NULL && queue_len > out_remaining )
        {
            int overflow;

            if( buflen != NULL && desired > queue_len )
                desired = queue_len;

            overflow = ( end + desired < end );
            if( overflow || desired > queue_len )
            {
                MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                         "queue present but too small, need %u but only got %u",
                         (unsigned) desired, (unsigned) queue_len );
                MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_WRITER_OUT_OF_DATA );
            }

            /* Queue large enough, transition to serving from queue. */
            end += desired;
            wr->end = end;

            *buffer = queue;
            if( buflen != NULL )
                *buflen = desired;

            /* Remember the overlap between queue and output buffer. */
            wr->queue_next = out_remaining;
            MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                               "served from queue, qo %u",
                               (unsigned) wr->queue_next );

            MBEDTLS_MPS_TRACE_RETURN( 0 );
        }

        /* No queue present, so serve only what's available
         * in the output buffer, provided the user allows it. */
        if( buflen == NULL )
        {
            MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment, "no queue present" );
            MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_WRITER_OUT_OF_DATA );
        }

        desired = out_remaining;
    }

    /* We reach this if the request can be served from the output buffer. */
    out += end;
    end += desired;
    wr->end = end;

    *buffer = out;
    if( buflen != NULL)
        *buflen = desired;

    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

int mbedtls_mps_writer_commit( mbedtls_mps_writer *wr )
{
    return( mbedtls_mps_writer_commit_partial( wr, 0 ) );
}

int mbedtls_mps_writer_commit_partial( mbedtls_mps_writer *wr,
                                       mbedtls_mps_size_t omit )
{
    mbedtls_mps_size_t to_be_committed, commit, end, queue_overlap;
    mbedtls_mps_size_t out_len, copy_from_queue;
    unsigned char *out, *queue;
    MBEDTLS_MPS_TRACE_INIT( "writer_commit_partial" );
    MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment, "* Omit %u bytes", (unsigned) omit );

    MBEDTLS_MPS_STATE_VALIDATE_RAW(
        wr->state == MBEDTLS_MPS_WRITER_CONSUMING,
        "Attempt to request write-buffer outside consuming mode." );

    out           = wr->out;
    queue_overlap = wr->queue_next;
    commit        = wr->committed;
    end           = wr->end;
    out_len       = wr->out_len;

    if( omit > end - commit )
        MBEDTLS_MPS_TRACE_RETURN( MBEDTLS_ERR_MPS_WRITER_INVALID_ARG );

    to_be_committed = end - omit;

    MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                       "* Last commit:       %u", (unsigned) commit );
    MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                       "* End of last fetch: %u", (unsigned) end );
    MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                       "* New commit:        %u", (unsigned) to_be_committed );

    if( end     > out_len &&
        commit  < out_len &&
        to_be_committed > out_len - queue_overlap )
    {
        /* Copy the beginning of the queue to
         * the end of the outgoing data buffer. */
        copy_from_queue = to_be_committed - ( out_len - queue_overlap );
        if( copy_from_queue > queue_overlap )
            copy_from_queue = queue_overlap;

        MBEDTLS_MPS_TRACE( mbedtls_mps_trace_comment,
                           "copy %u bytes from queue to output buffer",
                           (unsigned) copy_from_queue );

        queue = wr->queue;
        out   += out_len - queue_overlap;
        memcpy( out, queue, copy_from_queue );
    }

    if( to_be_committed < out_len )
        wr->queue_next = 0;

    wr->end       = to_be_committed;
    wr->committed = to_be_committed;

    MBEDTLS_MPS_TRACE_RETURN( 0 );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
