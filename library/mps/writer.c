/*
 *  Message Processing Stack, Writer implementation
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

/* TODO: Use usual include path
 *       This one is just to make flycheck happy */
#include "../../include/mbedtls/mps/writer.h"
#include "../../include/mbedtls/mps/trace.h"
static int trace_id = 4;

#include <string.h>

int mbedtls_writer_init( mbedtls_writer *wr,
                         unsigned char *queue, size_t queue_len )
{
    mbedtls_writer const zero = { NULL, 0, 0, 0, NULL, 0, 0, 0 };
    TRACE_INIT( "writer_init, queue_len %u", (unsigned) queue_len );

    *wr = zero;
    wr->queue = queue;
    wr->queue_len = queue_len;
    RETURN( 0 );
}

int mbedtls_writer_free( mbedtls_writer *wr )
{
    mbedtls_writer const zero = { NULL, 0, 0, 0, NULL, 0, 0, 0 };
    TRACE_INIT( "writer_free" );

    *wr = zero;
    RETURN( 0 );
}

int mbedtls_writer_feed( mbedtls_writer *wr,
                         unsigned char *buf, size_t buf_len )
{
    unsigned char *out, *queue;
    size_t copy_from_queue;
    TRACE_INIT( "writer_feed, buflen %u",
                (unsigned) buf_len );

    /* Feeding is only possible if no output buffer
     * is currently being managed by the writer. */
    out = wr->out;
    if( out != NULL )
        RETURN( MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION );

    if( buf == NULL )
        RETURN( MBEDTLS_ERR_WRITER_INVALID_ARG );

    /* Check if there is data in the queue pending to be dispatched. */
    queue = wr->queue;
    copy_from_queue = 0;
    if( queue != NULL )
    {
        size_t qa, qr;
        qr = wr->queue_remaining;
        qa = wr->queue_next;
        TRACE( trace_comment, "Queue data pending to be dispatched: %u",
               (unsigned) wr->queue_remaining );

        /* Copy as much data from the queue to
         * the provided buffer as possible. */
        copy_from_queue = qr;
        if( copy_from_queue > buf_len )
            copy_from_queue = buf_len;
        queue += qa;
        memcpy( buf, queue, copy_from_queue );
        for( size_t idx = 0; idx < copy_from_queue; idx++ )
        {
            TRACE( trace_comment, "Byte copied from queue %u: %u",
                    (unsigned) idx, queue[idx] );
        }

        /* Check if, after the last copy, the entire
         * queue has been dispatched. */
        qr -= copy_from_queue;
        if( qr > 0 )
        {
            /* More data waiting in the queue */
            TRACE( trace_comment, "There are %u bytes remaining in the queue.",
                   (unsigned) qr );

            qa += copy_from_queue;
            wr->queue_remaining = qr;
            wr->queue_next = qa;
            RETURN( MBEDTLS_ERR_WRITER_NEED_MORE );
        }

        /* The queue is empty. */
        TRACE( trace_comment, "Queue is empty" );
        wr->queue_next = 0;
        wr->queue_remaining = 0;
    }

    wr->out = buf;
    wr->out_len = buf_len;
    wr->commit = copy_from_queue;
    wr->end = copy_from_queue;
    RETURN( 0 );
}

int mbedtls_writer_reclaim( mbedtls_writer *wr, size_t *olen,
                            size_t *queued, int force )
{
    unsigned char *out;
    size_t commit, ol;
    TRACE_INIT( "writer_reclaim, force %u", (unsigned) force );

    /* Check that the reader is in providing mode. */
    out = wr->out;
    if( out == NULL )
        RETURN( MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION );

    /* Check if there's space left unused. */
    commit = wr->commit;
    ol = wr->out_len;
    TRACE( trace_comment, "commit %u, buflen %u",
           (unsigned) commit, (unsigned) ol );
    if( commit <= ol )
    {
        if( olen != NULL )
            *olen = commit;
        if( queued != NULL )
            *queued = 0;

        /* queue_next must be 0 if end <= ol */
        wr->queue_next = 0;

        if( commit < ol && force == 0 )
        {
            wr->end = commit;
            RETURN( MBEDTLS_ERR_WRITER_DATA_LEFT );
        }
    }
    else
    {
        /* The commited parts of the queue that
         * have no overlap with the current outgoing
         * data buffer need to be dispatched on
         * the next call(s) to mbedtls_writer_fetch. */
        wr->queue_remaining = commit - ol;
        /* No need to modify wr->queue_next */

        if( olen != NULL )
            *olen = ol;
    }

    if( queued != NULL )
    {
        size_t qr = wr->queue_remaining;
        TRACE( trace_comment, "queue remaining %u",
                (unsigned) wr->queue_remaining );
        *queued = qr;
    }

    wr->end = 0;
    wr->commit = 0;
    wr->out = NULL;
    wr->out_len = 0;
    RETURN( 0 );
}

int mbedtls_writer_bytes_written( mbedtls_writer *wr, size_t *written )
{
    size_t commit;
    unsigned char *out;
    TRACE_INIT( "writer_bytes_written" );

    /* Check that the reader is in providing mode. */
    out = wr->out;
    if( out == NULL )
        RETURN( MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION );
    commit = wr->commit;
    *written = commit;

    RETURN( 0 );
}

int mbedtls_writer_get( mbedtls_writer *wr, size_t desired,
                        unsigned char **buffer, size_t *buflen )
{
    unsigned char *out, *queue;
    size_t end, ol, or, ql, qn, qo;
    TRACE_INIT( "writer_get, desired %u", (unsigned) desired );

    out = wr->out;
    if( out == NULL )
    {
        TRACE( trace_comment, "unexpected operation" );
        RETURN( MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION );
    }

    end = wr->end;
    ol = wr->out_len;

    /* Check if we're already serving from the queue */
    if( end > ol )
    {
        TRACE( trace_comment, "already serving from the queue, attempt to continue" );

        ql = wr->queue_len;
        /* If we're serving from the queue, queue_next denotes
         * the size of the overlap between queue and output buffer. */
        qn = wr->queue_next;
        qo = qn + ( end - ol );
        TRACE( trace_comment, "queue overlap %u, queue used %u, queue remaining %u",
               (unsigned) qn, (unsigned) qo, (unsigned) ( ql - qo ) );

        if( ql - qo < desired )
        {
            if( buflen == NULL )
            {
                TRACE( trace_comment, "not enough space remaining in queue" );
                RETURN( MBEDTLS_ERR_WRITER_OUT_OF_DATA );
            }
            desired = ql - qo;
        }

        TRACE( trace_comment, "serving %u bytes from queue", (unsigned) desired );

        queue = wr->queue;
        end += desired;
        wr->end = end;

        *buffer = queue + qo;
        if( buflen != NULL )
            *buflen = desired;

        RETURN( 0 );
    }

    /* We're still serving from the output buffer.
     * Check if there's enough space left in it. */
    or = ol - end;
    if( or < desired )
    {
        TRACE( trace_comment, "need %u, but only %u remains in write buffer",
               (unsigned) desired, (unsigned) or );

        queue  = wr->queue;
        ql     = wr->queue_len;

        /* Out buffer is too small. Attempt to serve from queue if it is
         * available and larger than than the remaining output buffer. */
        if( queue != NULL && ql > or )
        {
            int overflow;

            if( buflen != NULL && desired > ql )
                desired = ql;

            overflow = ( end + desired < end );
            if( overflow || desired > ql )
            {
                TRACE( trace_comment, "no queue, or queue too small" );
                RETURN( MBEDTLS_ERR_WRITER_OUT_OF_DATA );
            }

            /* Queue large enough, transition to serving from queue. */
            end += desired;
            wr->end = end;

            *buffer = queue;
            if( buflen != NULL )
                *buflen = desired;

            /* Remember the overlap between queue and output buffer. */
            wr->queue_next = or;
            TRACE( trace_comment, "served from queue, qo %u",
                   (unsigned) wr->queue_next );

            RETURN( 0 );
        }

        /* No queue present, so serve only what's available
         * in the output buffer, provided the user allows it. */
        if( buflen == NULL )
            RETURN( MBEDTLS_ERR_WRITER_OUT_OF_DATA );

        desired = or;
    }

    /* We reach this if the request can be served from the output buffer. */
    out += end;
    end += desired;
    wr->end = end;

    *buffer = out;
    if( buflen != NULL)
        *buflen = desired;

    RETURN( 0 );
}

int mbedtls_writer_commit( mbedtls_writer *wr )
{
    return( mbedtls_writer_commit_partial( wr, 0 ) );
}

int mbedtls_writer_commit_partial( mbedtls_writer *wr,
                                   size_t omit )
{
    size_t to_be_committed, commit, end, queue_overlap;
    size_t out_len, copy_from_queue;
    unsigned char *out, *queue;
    TRACE_INIT( "writer_commit_partial" );
    TRACE( trace_comment, "* Omit %u bytes", (unsigned) omit );

    /* Check that the reader is in providing mode. */
    out = wr->out;
    if( out == NULL )
        RETURN( MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION );

    queue_overlap = wr->queue_next;
    commit        = wr->commit;
    end           = wr->end;
    out_len       = wr->out_len;

    if( omit > end - commit )
        RETURN( MBEDTLS_ERR_WRITER_INVALID_ARG );

    to_be_committed = end - omit;

    TRACE( trace_comment, "* Last commit:       %u", (unsigned) commit );
    TRACE( trace_comment, "* End of last fetch: %u", (unsigned) end );
    TRACE( trace_comment, "* New commit:        %u", (unsigned) to_be_committed );

    if( end     > out_len &&
        commit  < out_len &&
        to_be_committed > out_len - queue_overlap )
    {
        /* Copy the beginning of the queue to
         * the end of the outgoing data buffer. */
        copy_from_queue = to_be_committed - ( out_len - queue_overlap );
        if( copy_from_queue > queue_overlap )
            copy_from_queue = queue_overlap;

        TRACE( trace_comment, "copy %u bytes from queue to output buffer",
               (unsigned) copy_from_queue );

        queue = wr->queue;
        out   += out_len - queue_overlap;
        memcpy( out, queue, copy_from_queue );
    }

    if( to_be_committed < out_len )
        wr->queue_next = 0;

    wr->end    = to_be_committed;
    wr->commit = to_be_committed;

    RETURN( 0 );
}

/*
 * Implementation of extended writer
 */

/* TODO: Consider making (some of) these functions inline. */

int mbedtls_writer_init_ext( mbedtls_writer_ext *wr_ext, size_t size )
{
    mbedtls_writer_ext zero = { 0, { 0 }, NULL, 0, 0, };
    TRACE_INIT( "writer_init_ext, size %d", (unsigned) size );
    *wr_ext = zero;

    wr_ext->grp_end[0] = size;
    RETURN( 0 );
}

int mbedtls_writer_free_ext( mbedtls_writer_ext *rd )
{
    mbedtls_writer_ext zero = { 0, { 0 }, NULL, 0, 0, };
    TRACE_INIT( "writer_free_ext" );

    *rd = zero;
    RETURN( 0 );
}

int mbedtls_writer_get_ext( mbedtls_writer_ext *wr_ext, size_t desired,
                            unsigned char **buffer, size_t *buflen )
{
    int ret;
    size_t logic_avail;
    TRACE_INIT( "writer_get_ext: desired %u", (unsigned) desired );

    if( wr_ext->wr == NULL )
        RETURN( MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION );

    logic_avail = wr_ext->grp_end[wr_ext->cur_grp] - wr_ext->ofs_fetch;
    TRACE( trace_comment, "desired %u, logic_avail %u",
           (unsigned) desired, (unsigned) logic_avail );
    if( desired > logic_avail )
    {
        TRACE( trace_comment, "bounds violation!" );
        RETURN( MBEDTLS_ERR_WRITER_BOUNDS_VIOLATION );
    }

    ret = mbedtls_writer_get( wr_ext->wr, desired, buffer, buflen );
    if( ret != 0 )
        RETURN( ret );

    if( buflen != NULL )
        desired = *buflen;

    TRACE( trace_comment, "increase fetch offset from %u to %u",
           (unsigned) wr_ext->ofs_fetch,
           (unsigned) ( wr_ext->ofs_fetch + desired )  );

    wr_ext->ofs_fetch += desired;
    RETURN( 0 );
}

int mbedtls_writer_commit_ext( mbedtls_writer_ext *wr )
{
    int ret;
    TRACE_INIT( "writer_commit_ext" );

    if( wr->wr == NULL )
        RETURN( MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION );

    ret = mbedtls_writer_commit( wr->wr );
    if( ret != 0 )
        RETURN( ret );

    wr->ofs_commit = wr->ofs_fetch;
    RETURN( 0 );
}

int mbedtls_writer_group_open( mbedtls_writer_ext *wr_ext,
                               size_t group_size )
{
    /* Check how much space is left in the current group */
    size_t const logic_avail =
        wr_ext->grp_end[wr_ext->cur_grp] - wr_ext->ofs_fetch;
    TRACE_INIT( "writer_group_open, size %u", (unsigned) group_size );

    if( wr_ext->cur_grp >= MBEDTLS_WRITER_MAX_GROUPS - 1 )
        RETURN( MBEDTLS_ERR_WRITER_TOO_MANY_GROUPS );

    /* Make sure the new group doesn't exceed the present one */
    if( logic_avail < group_size )
        RETURN( MBEDTLS_ERR_WRITER_BOUNDS_VIOLATION );

    /* Add new group */
    wr_ext->cur_grp++;
    wr_ext->grp_end[wr_ext->cur_grp] = wr_ext->ofs_fetch + group_size;

    RETURN( 0 );
}

int mbedtls_writer_group_close( mbedtls_writer_ext *wr_ext )
{
    /* Check how much space is left in the current group */
    size_t const logic_avail =
        wr_ext->grp_end[wr_ext->cur_grp] - wr_ext->ofs_fetch;
    TRACE_INIT( "writer_group_close" );

    /* Ensure that the group is fully exhausted */
    if( logic_avail != 0 )
        RETURN( MBEDTLS_ERR_WRITER_BOUNDS_VIOLATION );

    if( wr_ext->cur_grp > 0 )
        wr_ext->cur_grp--;

    RETURN( 0 );
}

int mbedtls_writer_attach( mbedtls_writer_ext *wr_ext,
                           mbedtls_writer *wr )
{
    TRACE_INIT( "writer_check_attach" );
    if( wr_ext->wr != NULL )
        RETURN( MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION );

    wr_ext->wr = wr;
    RETURN( 0 );
}

int mbedtls_writer_detach( mbedtls_writer_ext *wr_ext )
{
    TRACE_INIT( "writer_check_detach" );
    if( wr_ext->wr == NULL )
        RETURN( MBEDTLS_ERR_WRITER_UNEXPECTED_OPERATION );

    wr_ext->ofs_fetch = wr_ext->ofs_commit;
    wr_ext->wr = NULL;

    RETURN( 0 );
}

int mbedtls_writer_check_done( mbedtls_writer_ext *wr_ext )
{
    TRACE_INIT( "writer_check_done" );

    if( wr_ext->cur_grp > 0 )
    {
        TRACE( trace_comment, "cur_grp > 0" );
        RETURN( MBEDTLS_ERR_WRITER_BOUNDS_VIOLATION );
    }

    if( wr_ext->ofs_commit != wr_ext->grp_end[0] )
    {
        TRACE( trace_comment, "message not fully committed" );
        RETURN( MBEDTLS_ERR_WRITER_BOUNDS_VIOLATION );
    }

    RETURN( 0 );
}
