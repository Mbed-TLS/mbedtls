/*
 *  Message Processing Stack, Reader implementation
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
#include "../../include/mbedtls/mps/reader.h"
#include "../../include/mbedtls/mps/trace.h"

#if defined(MBEDTLS_MPS_TRACE)
static int trace_id = TRACE_BIT_READER;
#endif /* MBEDTLS_MPS_TRACE */

#include <string.h>

/*
 * GENERAL NOTE ON CODING STYLE
 *
 * The following code intentionally separates memory loads
 * and stores from other operations (arithmetic or branches).
 * This leads to the introduction of many local variables
 * and significantly increases the C-code line count, but
 * should not increase the size of generated assembly.
 *
 * This reason for this is twofold:
 * (1) It will ease verification efforts using the VST
 *     whose program logic cannot directly reason
 *     about instructions containing a load or store in
 *     addition to other operations (e.g. *p = *q or
 *     tmp = *p + 42).
 * (2) Operating on local variables and writing the results
 *     back to the target contexts on success only
 *     allows to maintain structure invariants even
 *     on failure - this in turn has two benefits:
 *     (2.a) If for some reason an error code is not caught
 *           and operation continues, functions are nonetheless
 *           called with sane contexts, reducing the risk
 *           of dangerous behavior.
 *     (2.b) Randomized testing is easier if structures
 *           remain intact even in the face of failing
 *           and/or non-sensical calls.
 *     Moreover, it might even reduce code-size because
 *     the compiler need not write back temporary results
 *     to memory in case of failure.
 *
 */

int mbedtls_reader_init( mbedtls_reader *rd,
                         unsigned char *acc, size_t acc_len )
{
    mbedtls_reader const zero = { NULL, 0, 0, 0, 0, NULL, 0, 0, { 0 } };
    *rd = zero;
    TRACE_INIT( "reader_init, acc len %u", (unsigned) acc_len );

    rd->acc = acc;
    rd->acc_len = acc_len;
    RETURN( 0 );
}

int mbedtls_reader_free( mbedtls_reader *rd )
{
    mbedtls_reader const zero = { NULL, 0, 0, 0, 0, NULL, 0, 0, { 0 } };
    TRACE_INIT( "reader_free" );
    *rd = zero;
    /* TODO: Use reliable way of zeroization, provided
     * zeroization is necessary in the first place. If so,
     * consider also zeroizing the accumulator buffer. */
    RETURN( 0 );
}

int mbedtls_reader_feed( mbedtls_reader *rd, unsigned char *new_frag,
                         size_t new_frag_len )
{
    unsigned char *frag, *acc;
    size_t copy_to_acc;
    TRACE_INIT( "reader_feed, frag %p, len %u",
                new_frag, (unsigned) new_frag_len );

    if( new_frag == NULL )
        RETURN( MBEDTLS_ERR_READER_INVALID_ARG );

    /* Feeding is only possible in producing mode, i.e.
     * if no fragment is currently being processed. */
    frag = rd->frag;
    if( frag != NULL )
        RETURN( MBEDTLS_ERR_READER_UNEXPECTED_OPERATION );

    acc = rd->acc;
    if( acc != NULL )
    {
        size_t aa, ar;

        ar = rd->acc_share.acc_remaining;
        aa = rd->acc_avail;

        copy_to_acc = ar;
        if( copy_to_acc > new_frag_len )
            copy_to_acc = new_frag_len;

        acc += aa;
        memcpy( acc, new_frag, copy_to_acc );

        TRACE( trace_comment, "Copy new data of size %u of %u into accumulator at offset %u",
                (unsigned) copy_to_acc, (unsigned) new_frag_len, (unsigned) aa );

        /* Check if, with the new fragment, we have enough data. */
        ar -= copy_to_acc;
        if( ar > 0 )
        {
            /* Need more data */
            aa += copy_to_acc;
            rd->acc_share.acc_remaining = ar;
            rd->acc_avail = aa;
            RETURN( MBEDTLS_ERR_READER_NEED_MORE );
        }

        TRACE( trace_comment, "Enough data available to serve user request" );

        rd->acc_share.frag_offset = aa;
        aa += copy_to_acc;
        rd->acc_avail = aa;
    }
    else
    {
        rd->acc_share.frag_offset = 0;
    }

    rd->frag = new_frag;
    rd->frag_len = new_frag_len;
    rd->commit = 0;
    rd->end = 0;
    RETURN( 0 );
}


int mbedtls_reader_get( mbedtls_reader *rd, size_t desired,
                        unsigned char **buffer, size_t *buflen )
{
    unsigned char *frag, *acc;
    size_t end, fo, fl, frag_fetched, frag_remaining;
    TRACE_INIT( "reader_get %p, desired %u", rd, (unsigned) desired );

    /* Check that the reader is in consuming mode. */
    frag = rd->frag;
    if( frag == NULL )
    {
        TRACE( trace_error, "The reader is not in consuming mode." );
        RETURN( MBEDTLS_ERR_READER_UNEXPECTED_OPERATION );
    }

    /* The fragment offset indicates the offset of the fragment
     * from the accmulator, if the latter is present. Use a offset
     * of \c 0 if no accumulator is used. */
    acc = rd->acc;
    if( acc == NULL )
        fo = 0;
    else
        fo = rd->acc_share.frag_offset;

    TRACE( trace_comment, "frag_off %u, end %u, acc_avail %d",
            (unsigned) fo, (unsigned) rd->end,
            acc == NULL ? -1 : (int) rd->acc_avail );

    /* Check if we're still serving from the accumulator. */
    end = rd->end;
    if( end < fo )
    {
        TRACE( trace_comment, "Serve the request from the accumulator" );
        if( fo - end < desired )
        {
            /* Illustration of supported and unsupported cases:
             *
             * - Allowed #1
             *
             *                          +-----------------------------------+
             *                          |               frag                |
             *                          +-----------------------------------+
             *
             *             end end+desired
             *              |       |
             *        +-----v-------v-------------+
             *        |          acc              |
             *        +---------------------------+
             *                          |         |
             *                   fo/frag_offset aa/acc_avail
             *
             * - Allowed #2
             *
             *                          +-----------------------------------+
             *                          |               frag                |
             *                          +-----------------------------------+
             *
             *                  end          end+desired
             *                   |                |
             *        +----------v----------------v
             *        |          acc              |
             *        +---------------------------+
             *                          |         |
             *                   fo/frag_offset aa/acc_avail
             *
             * - Not allowed #1 (could be served, but we don't actually use it):
             *
             *                      +-----------------------------------+
             *                      |               frag                |
             *                      +-----------------------------------+
             *
             *              end        end+desired
             *               |             |
             *        +------v-------------v------+
             *        |          acc              |
             *        +---------------------------+
             *                      |              |
             *                fo/frag_offset   aa/acc_avail
             *
             *
             * - Not allowed #2 (can't be served with a contiguous buffer):
             *
             *                      +-----------------------------------+
             *                      |               frag                |
             *                      +-----------------------------------+
             *
             *              end                 end + desired
             *               |                        |
             *        +------v--------------------+   v
             *        |            acc            |
             *        +---------------------------+
             *                      |             |
             *                fo/frag_offset   aa/acc_avail
             *
             * In case of Allowed #1 and #2 we're switching to serve from
             * `frag` starting from the next call to mbedtls_reader_get().
             */

            size_t aa;
            aa = rd->acc_avail;
            if( aa - end != desired )
            {
                /* It might be possible to serve some of these situations by
                 * making additional space in the accumulator, removing those
                 * parts that have already been committed.
                 * On the other hand, this brings additional complexity and
                 * enlarges the code size, while there doesn't seem to be a use
                 * case where we don't attempt exactly the same `get` calls when
                 * resuming on a reader than what we tried before pausing it.
                 * If we believe we adhere to this restricted usage throughout
                 * the library, this check is a good opportunity to
                 * validate this. */
                RETURN( MBEDTLS_ERR_READER_INCONSISTENT_REQUESTS );
            }
        }

        acc += end;
        *buffer = acc;
        if( buflen != NULL )
            *buflen = desired;

        end += desired;
        rd->end = end;
        rd->pending = 0;

        RETURN( 0 );
    }

    /* Attempt to serve the request from the current fragment */
    TRACE( trace_comment, "Serve the request from the current fragment." );

    fl = rd->frag_len;
    frag_fetched = end - fo; /* The amount of data from the current fragment
                              * that has already been passed to the user. */
    frag += frag_fetched;
    frag_remaining = fl - frag_fetched; /* Remaining data in fragment */

    /* Check if we can serve the read request from the fragment. */
    if( frag_remaining < desired )
    {
        TRACE( trace_comment, "There's not enough data in the current fragment to serve the request." );
        /* There's not enough data in the current fragment,
         * so either just RETURN what we have or fail. */
        if( buflen == NULL )
        {
            if( frag_remaining > 0 )
            {
                rd->pending = desired - frag_remaining;
                TRACE( trace_comment, "Remember to collect %u bytes before re-opening",
                       (unsigned) rd->pending );
            }
            RETURN( MBEDTLS_ERR_READER_OUT_OF_DATA );
        }

        desired = frag_remaining;
    }

    /* There's enough data in the current fragment to serve the
     * (potentially modified) read request. */
    *buffer = frag;
    if( buflen != NULL )
        *buflen = desired;

    end += desired;
    rd->end = end;
    rd->pending = 0;
    RETURN( 0 );
}

int mbedtls_reader_commit( mbedtls_reader *rd )
{
    unsigned char *frag, *acc;
    size_t aa, end, fo, shift;
    TRACE_INIT( "reader_commit" );

    /* Check that the reader is in consuming mode. */
    frag = rd->frag;
#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( frag == NULL )
        RETURN( MBEDTLS_ERR_READER_UNEXPECTED_OPERATION );
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    acc = rd->acc;
    end = rd->end;

    if( acc == NULL )
    {
        TRACE( trace_comment, "No accumulator, just shift end" );
        rd->commit = end;
        RETURN( 0 );
    }

    fo = rd->acc_share.frag_offset;
    if( end >= fo )
    {
        TRACE( trace_comment, "Started to serve fragment, get rid of accumulator" );
        shift = fo;
        aa = 0;
    }
    else
    {
        TRACE( trace_comment, "Still serving from accumulator" );
        aa = rd->acc_avail;
        shift = end;
        memmove( acc, acc + shift, aa - shift );
        aa -= shift;
    }

    end -= shift;
    fo -= shift;

    rd->acc_share.frag_offset = fo;
    rd->acc_avail = aa;
    rd->commit = end;
    rd->end = end;

    TRACE( trace_comment, "Final state: (end=commit,fo,avail) = (%u,%u,%u)",
           (unsigned) end, (unsigned) fo, (unsigned) aa );
    RETURN( 0 );
}

int mbedtls_reader_reclaim( mbedtls_reader *rd, size_t *paused )
{
    unsigned char *frag, *acc;
    size_t pending, commit;
    size_t al, fo, fl;
    TRACE_INIT( "reader_reclaim" );

    if( paused != NULL )
        *paused = 0;

    frag = rd->frag;
    if( frag == NULL )
        RETURN( MBEDTLS_ERR_READER_UNEXPECTED_OPERATION );

    acc    = rd->acc;
    pending = rd->pending;
    commit = rd->commit;
    fl     = rd->frag_len;

    if( acc == NULL )
        fo = 0;
    else
        fo = rd->acc_share.frag_offset;

    if( pending == 0 )
    {
        TRACE( trace_comment, "No unsatisfied read-request has been logged." );
        /* Check if there's data left to be consumed. */
        if( commit < fo || commit - fo < fl )
        {
            TRACE( trace_comment, "There is data left to be consumed." );
            rd->end = commit;
            RETURN( MBEDTLS_ERR_READER_DATA_LEFT );
        }
        TRACE( trace_comment, "The fragment has been completely processed and committed." );
    }
    else
    {
        size_t frag_backup_offset;
        size_t frag_backup_len;
        size_t idx;
        TRACE( trace_comment, "There has been an unsatisfied read-request with %u bytes overhead.",
               (unsigned) pending );

        if( acc == NULL )
        {
            TRACE( trace_comment, "No accumulator present" );
            RETURN( MBEDTLS_ERR_READER_NEED_ACCUMULATOR );
        }
        al = rd->acc_len;

        /* Check if the upper layer has already fetched
         * and committed the contents of the accumulator. */
        if( commit < fo )
        {
            /* No, accumulator is still being processed. */
            int overflow;
            TRACE( trace_comment, "Still processing data from the accumulator" );

            overflow =
                ( fo + fl < fo ) || ( fo + fl + pending < fo + fl );
            if( overflow || al < fo + fl + pending )
            {
                rd->end = commit;
                rd->pending = 0;
                TRACE( trace_error, "The accumulator is too small to handle the backup." );
                TRACE( trace_error, "* Remaining size: %u", (unsigned) al );
                TRACE( trace_error, "* Needed: %u (%u + %u + %u)",
                       (unsigned) ( fo + fl + pending ),
                       (unsigned) fo, (unsigned) fl, (unsigned) pending );
                RETURN( MBEDTLS_ERR_READER_ACCUMULATOR_TOO_SMALL );
            }
            frag_backup_offset = 0;
            frag_backup_len = fl;
        }
        else
        {
            /* Yes, the accumulator is already processed. */
            int overflow;
            TRACE( trace_comment, "The accumulator has already been processed" );

            frag_backup_offset = commit;
            frag_backup_len = fl - commit;
            overflow = ( frag_backup_len + pending < pending );

            if( overflow ||
                al - fo < frag_backup_len + pending )
            {
                rd->end = commit;
                rd->pending = 0;
                TRACE( trace_error, "The accumulator is too small to handle the backup." );
                TRACE( trace_error, "* Remaining size: %u", (unsigned) ( al - fo ) );
                TRACE( trace_error, "* Needed: %u (%u + %u)",
                       (unsigned) ( frag_backup_len + pending ),
                       (unsigned) frag_backup_len, (unsigned) pending );
                RETURN( MBEDTLS_ERR_READER_ACCUMULATOR_TOO_SMALL );
            }
        }

        frag += frag_backup_offset;
        acc += fo;
        memcpy( acc, frag, frag_backup_len );

        TRACE( trace_comment, "Backup %u bytes into accumulator",
               (unsigned) frag_backup_len );
        for( idx = 0; idx < frag_backup_len; idx++ )
            TRACE( trace_comment, "Backup[%u]=%u", (unsigned) idx, frag[idx] );

        rd->acc_avail = fo + frag_backup_len;
        rd->acc_share.acc_remaining = pending;

        if( paused != NULL )
            *paused = 1;
    }

    rd->frag     = NULL;
    rd->frag_len = 0;

    rd->commit = 0;
    rd->end    = 0;
    rd->pending  = 0;

    TRACE( trace_comment, "Final state: aa %u, al %u, ar %u",
           (unsigned) rd->acc_avail, (unsigned) rd->acc_len,
           (unsigned) rd->acc_share.acc_remaining );
    RETURN( 0 );
}

/*
 * Implementation of extended reader
 */

/* TODO: Consider making (some of) these functions inline. */

int mbedtls_reader_init_ext( mbedtls_reader_ext *rd_ext, size_t size )
{
    mbedtls_reader_ext zero = { 0, { 0 }, NULL, 0, 0, };
    TRACE_INIT( "reader_init_ext, size %u", (unsigned) size );

    *rd_ext = zero;
    rd_ext->grp_end[0] = size;
    RETURN( 0 );
}

int mbedtls_reader_free_ext( mbedtls_reader_ext *rd )
{
    mbedtls_reader_ext zero = { 0, { 0 }, NULL, 0, 0, };
    TRACE_INIT( "reader_free_ext" );
    *rd = zero;

    RETURN( 0 );
}

int mbedtls_reader_get_ext( mbedtls_reader_ext *rd_ext, size_t desired,
                            unsigned char **buffer, size_t *buflen )
{
    int ret;
    size_t logic_avail;
    TRACE_INIT( "reader_get_ext %p: desired %u", rd_ext, (unsigned) desired );

    if( rd_ext->rd == NULL )
    {
        TRACE( trace_comment, "No raw reader bound to extended reader" );
        RETURN( MBEDTLS_ERR_READER_UNEXPECTED_OPERATION );
    }

    TRACE( trace_comment, "* Fetch offset: %u", (unsigned) rd_ext->ofs_fetch );
    TRACE( trace_comment, "* Group end:    %u",
           (unsigned) rd_ext->grp_end[rd_ext->cur_grp] );
    logic_avail = rd_ext->grp_end[rd_ext->cur_grp] - rd_ext->ofs_fetch;
    if( desired > logic_avail )
    {
        TRACE( trace_comment, "Requesting more data (%u) than logically available (%u)",
               (unsigned) desired, (unsigned) logic_avail );
        RETURN( MBEDTLS_ERR_READER_BOUNDS_VIOLATION );
    }

    ret = mbedtls_reader_get( rd_ext->rd, desired, buffer, buflen );
    if( ret != 0 )
        RETURN( ret );

    if( buflen != NULL )
        desired = *buflen;

    rd_ext->ofs_fetch += desired;
    RETURN( 0 );
}

int mbedtls_reader_commit_ext( mbedtls_reader_ext *rd )
{
    int ret;
    TRACE_INIT( "reader_commit_ext" );

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( rd->rd == NULL )
        RETURN( MBEDTLS_ERR_READER_UNEXPECTED_OPERATION );
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    ret = mbedtls_reader_commit( rd->rd );
    if( ret != 0 )
        RETURN( ret );

    rd->ofs_commit = rd->ofs_fetch;
    RETURN( 0 );
}

int mbedtls_reader_group_open( mbedtls_reader_ext *rd_ext,
                               size_t group_size )
{
    /* Check how much space is left in the current group */
    size_t const logic_avail =
        rd_ext->grp_end[rd_ext->cur_grp] - rd_ext->ofs_fetch;
    TRACE_INIT( "reader_group_open, size %u", (unsigned) group_size );

    if( rd_ext->cur_grp >= MBEDTLS_READER_MAX_GROUPS - 1 )
        RETURN( MBEDTLS_ERR_READER_TOO_MANY_GROUPS );

    /* Make sure the new group doesn't exceed the present one */
    if( logic_avail < group_size )
        RETURN( MBEDTLS_ERR_READER_BOUNDS_VIOLATION );

    /* Add new group */
    rd_ext->cur_grp++;
    rd_ext->grp_end[rd_ext->cur_grp] = rd_ext->ofs_fetch + group_size;

    RETURN( 0 );
}

int mbedtls_reader_group_close( mbedtls_reader_ext *rd_ext )
{
    /* Check how much space is left in the current group */
    size_t const logic_avail =
        rd_ext->grp_end[rd_ext->cur_grp] - rd_ext->ofs_fetch;
    TRACE_INIT( "reader_group_close" );

    /* Ensure that the group is fully exhausted */
    if( logic_avail != 0 )
        RETURN( MBEDTLS_ERR_READER_BOUNDS_VIOLATION );

    if( rd_ext->cur_grp > 0 )
        rd_ext->cur_grp--;

    RETURN( 0 );
}

int mbedtls_reader_attach( mbedtls_reader_ext *rd_ext,
                           mbedtls_reader *rd )
{
    TRACE_INIT( "reader_attach" );
    if( rd_ext->rd != NULL )
        RETURN( MBEDTLS_ERR_READER_UNEXPECTED_OPERATION );

    rd_ext->rd = rd;
    RETURN( 0 );
}

int mbedtls_reader_detach( mbedtls_reader_ext *rd_ext )
{
    TRACE_INIT( "reader_detach" );
    if( rd_ext->rd == NULL )
        RETURN( MBEDTLS_ERR_READER_UNEXPECTED_OPERATION );

    rd_ext->ofs_fetch = rd_ext->ofs_commit;
    rd_ext->rd = NULL;
    RETURN( 0 );
}

int mbedtls_reader_check_done( mbedtls_reader_ext const *rd_ext )
{
    TRACE_INIT( "reader_check_done" );
    if( rd_ext->cur_grp > 0 ||
        rd_ext->ofs_commit != rd_ext->grp_end[0] )
    {
        RETURN( MBEDTLS_ERR_READER_BOUNDS_VIOLATION );
    }

    RETURN( 0 );
}
