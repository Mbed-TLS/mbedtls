/*
 *  Message Processing Stack, Layer 1 implementation
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

#include "mbedtls/mps/layer1.h"
#include "mbedtls/mps/trace.h"

#if defined(MBEDTLS_MPS_SEPARATE_LAYERS) ||     \
    defined(MBEDTLS_MPS_TOP_TRANSLATION_UNIT)

#if defined(MBEDTLS_MPS_TRACE)
static int trace_id = TRACE_BIT_LAYER_1;
#endif /* MBEDTLS_MPS_TRACE */

#include <string.h>

MBEDTLS_MPS_STATIC void l1_release_if_set( unsigned char **buf_ptr,
                               mps_alloc *ctx,
                               mps_alloc_type purpose );
MBEDTLS_MPS_STATIC int l1_acquire_if_unset( unsigned char **buf_ptr,
                                size_t *buflen,
                                mps_alloc *ctx,
                                mps_alloc_type purpose );

#if defined(MBEDTLS_MPS_PROTO_TLS)

MBEDTLS_MPS_INLINE int l1_check_flush_stream( mps_l1_stream_write *p );
MBEDTLS_MPS_INLINE void l1_init_stream_read( mps_l1_stream_read *p,
                                        mps_alloc *ctx,
                                        mps_l0_recv_t *recv );
MBEDTLS_MPS_INLINE void l1_init_stream_write( mps_l1_stream_write *p,
                                         mps_alloc *ctx,
                                         mps_l0_send_t *send );
MBEDTLS_MPS_INLINE void l1_init_stream( mps_l1_stream *p,
                                   mps_alloc *ctx,
                                   mps_l0_send_t *send,
                                   mps_l0_recv_t *recv );
MBEDTLS_MPS_INLINE void l1_free_stream_read( mps_l1_stream_read *p );
MBEDTLS_MPS_INLINE void l1_free_stream_write( mps_l1_stream_write *p );
MBEDTLS_MPS_INLINE void l1_free_stream( mps_l1_stream *p );
MBEDTLS_MPS_INLINE int l1_consume_stream( mps_l1_stream_read *p );
MBEDTLS_MPS_INLINE int l1_flush_stream( mps_l1_stream_write *p );
MBEDTLS_MPS_INLINE int l1_write_stream( mps_l1_stream_write *p,
                                   unsigned char **dst,
                                   size_t *buflen );
MBEDTLS_MPS_INLINE int l1_check_flush_stream( mps_l1_stream_write *p );
MBEDTLS_MPS_INLINE int l1_write_dependency_stream( mps_l1_stream_write *p );
MBEDTLS_MPS_INLINE int l1_read_dependency_stream( mps_l1_stream_read *p );
MBEDTLS_MPS_INLINE int l1_dispatch_stream( mps_l1_stream_write *p,
                                      size_t len, size_t *pending );
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
MBEDTLS_MPS_INLINE int l1_check_flush_dgram( mps_l1_dgram_write *p );
MBEDTLS_MPS_INLINE void l1_init_dgram_read( mps_l1_dgram_read *p,
                                       mps_alloc *ctx,
                                       mps_l0_recv_t *recv );
MBEDTLS_MPS_INLINE void l1_init_dgram_write( mps_l1_dgram_write *p,
                                        mps_alloc *ctx,
                                        mps_l0_send_t *send );
MBEDTLS_MPS_INLINE void l1_init_dgram( mps_l1_dgram *p,
                                  mps_alloc *ctx,
                                  mps_l0_send_t *send,
                                  mps_l0_recv_t *recv );
MBEDTLS_MPS_INLINE void l1_free_dgram_read( mps_l1_dgram_read *p );
MBEDTLS_MPS_INLINE void l1_free_dgram_write( mps_l1_dgram_write *p );
MBEDTLS_MPS_INLINE void l1_free_dgram( mps_l1_dgram *p );
MBEDTLS_MPS_INLINE int l1_ensure_in_dgram( mps_l1_dgram_read *p );
MBEDTLS_MPS_INLINE int l1_write_dependency_dgram( mps_l1_dgram_write *p );
MBEDTLS_MPS_INLINE int l1_read_dependency_dgram( mps_l1_dgram_read *p );
MBEDTLS_MPS_INLINE int l1_fetch_dgram( mps_l1_dgram_read *p,
                                  unsigned char **dst,
                                  size_t len );
MBEDTLS_MPS_INLINE int l1_consume_dgram( mps_l1_dgram_read *p );
MBEDTLS_MPS_INLINE int l1_write_dgram( mps_l1_dgram_write *p,
                                  unsigned char **buf,
                                  size_t *buflen );
MBEDTLS_MPS_INLINE int l1_dispatch_dgram( mps_l1_dgram_write *p, size_t len,
                                     size_t *pending );
MBEDTLS_MPS_INLINE int l1_flush_dgram( mps_l1_dgram_write *p );
#endif /* MBEDTLS_MPS_PROTO_DTLS */

/*
 * GENERAL NOTE ON CODING STYLE
 *
 * The following code intentionally separates memory loads
 * and stores from other operations (arithmetic or branches).
 * This leads to the introduction of many local variables
 * and significantly increases the C-code line count, but
 * should leave the size of generated assembly unchanged.
 *
 * This reason for this is twofold:
 * (1) It could potentially ease verification efforts using
 *     the VST whose program logic cannot directly reason
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
 *
 */

MBEDTLS_MPS_STATIC void l1_release_if_set( unsigned char **buf_ptr,
                              mps_alloc *ctx,
                              mps_alloc_type purpose )
{
    *buf_ptr = NULL;
    mps_alloc_release( ctx, purpose );
}

MBEDTLS_MPS_STATIC int l1_acquire_if_unset( unsigned char **buf_ptr,
                                size_t *buflen,
                                mps_alloc *ctx,
                                mps_alloc_type purpose )
{
    unsigned char *buf = *buf_ptr;
    if( buf != NULL )
        return( 0 );

    return( mps_alloc_acquire( ctx, purpose, buf_ptr, buflen ) );
}

/*
 *
 * Stream-based implementation
 *
 */

#if defined(MBEDTLS_MPS_PROTO_TLS)

/*@
  requires ( p != NULL );
  requires ( recv != NULL );
  MPS_L1_STREAM_READ_INV_ENSURES(p)
@*/
MBEDTLS_MPS_INLINE
void l1_init_stream_read( mps_l1_stream_read *p,
                          mps_alloc *ctx,
                          mps_l0_recv_t *recv )
{
    mps_l1_stream_read const zero = { NULL, NULL, NULL, 0, 0, 0 };
    *p = zero;
    p->recv  = recv;
    p->alloc = ctx;
}

/*@
  requires \valid( p );
  requires ( send != NULL );
  MPS_L1_STREAM_WRITE_INV_ENSURES(p)
@*/
MBEDTLS_MPS_INLINE
void l1_init_stream_write( mps_l1_stream_write *p,
                           mps_alloc *ctx,
                           mps_l0_send_t *send )
{
    mps_l1_stream_write const zero = { NULL, NULL, NULL, 0, 0, 0, 0 };
    *p = zero;
    p->send  = send;
    p->alloc = ctx;
}

MBEDTLS_MPS_INLINE
void l1_init_stream( mps_l1_stream *p, mps_alloc *ctx,
                     mps_l0_send_t *send, mps_l0_recv_t *recv )
{
    l1_init_stream_read ( &p->rd, ctx, recv );
    l1_init_stream_write( &p->wr, ctx, send );
}

/*@
  MPS_L1_STREAM_READ_INV_REQUIRES(p)
@*/
MBEDTLS_MPS_INLINE
void l1_free_stream_read( mps_l1_stream_read *p )
{
    mps_l1_stream_read const zero = { NULL, NULL, NULL, 0, 0, 0 };
    l1_release_if_set( &p->buf, p->alloc, MPS_ALLOC_L1_IN );
    *p = zero;
}

/*@
  MPS_L1_STREAM_WRITE_INV_REQUIRES(p)
@*/
MBEDTLS_MPS_INLINE
void l1_free_stream_write( mps_l1_stream_write *p )
{
    mps_l1_stream_write const zero = { NULL, NULL, NULL, 0, 0, 0, 0 };
    l1_release_if_set( &p->buf, p->alloc, MPS_ALLOC_L1_OUT );
    *p = zero;
}

MBEDTLS_MPS_INLINE
void l1_free_stream( mps_l1_stream *p )
{
    l1_free_stream_read( &p->rd );
    l1_free_stream_write( &p->wr );
}

/*@
  MPS_L1_STREAM_READ_INV_REQUIRES(p)
  MPS_L1_STREAM_READ_INV_ENSURES(p)
@*/
MBEDTLS_MPS_INLINE
int l1_fetch_stream( mps_l1_stream_read *p,
                     unsigned char **dst,
                     size_t len )
{
    int ret;
    size_t bl, br, data_need, data_fetched;
    unsigned char *read_ptr;
    mps_l0_recv_t *recv;
    TRACE_INIT( "l1_fetch_stream, desired %u", (unsigned) len );

    /* OPTIMIZATION:
     * This refers to the potential removal of `buf` from
     * the Layer 0 structure. If we do that, we might change
     * the allocator's allocation function to only take the
     * ID of the allocation, and to add a function querying
     * for the pointer on success. This function should be a
     * simple getter function returning the corresponding
     * field from the allocator, so that the compiler can
     * inline the access here. */

    /* TODO: Remove reinterpret_cast eventually */
    ret = l1_acquire_if_unset( &p->buf, (size_t*) &p->buf_len,
                               p->alloc, MPS_ALLOC_L1_IN );
    if( ret != 0 )
        RETURN( ret );

    read_ptr = p->buf;
    bl = p->buf_len;
    if( len > bl )
        RETURN( MBEDTLS_ERR_MPS_BUFFER_TOO_SMALL );

    br = p->bytes_read;
    if( br <= len )
        data_need = len - br;
    else
        data_need = 0;

    recv = p->recv;
    read_ptr += br;
    while( data_need > 0 )
    {
        TRACE( trace_comment, "attempt to receive %u", (unsigned) data_need );
        ret = recv( read_ptr, data_need );
        if( ret < 0 )
            break;
        TRACE( trace_comment, "got %u", (unsigned) ret );

#if( MAX_INT > SIZE_MAX )
        if( ret > (int) SIZE_MAX )
            RETURN( MBEDTLS_ERR_MPS_BAD_TRANSPORT );
#endif

        /* Now we know that we can safely cast ret to size_t. */
        data_fetched = (size_t) ret;
        ret = 0;

        /* Double-check that the external Layer 0 obeys its spec;
         * if it doesn't, we'd otherwise underflow data_need. */
        if( data_fetched > data_need )
            RETURN( MBEDTLS_ERR_MPS_BAD_TRANSPORT );

        data_need -= data_fetched;
        read_ptr  += data_fetched;
        br        += data_fetched;
    }
    p->bytes_read = br;

    if( ret == 0 )
    {
        *dst = p->buf;
        p->bytes_fetched = len;
    }
    else
        p->bytes_fetched = 0;

    RETURN( ret );
}

/*@
  MPS_L1_STREAM_READ_INV_REQUIRES(p)
  MPS_L1_STREAM_READ_INV_ENSURES(p)
@*/
MBEDTLS_MPS_INLINE
int l1_consume_stream( mps_l1_stream_read *p )
{
    unsigned char *buf;
    size_t bf, br, not_yet_fetched;
    TRACE_INIT( "l1_consume_stream" );

    bf = p->bytes_fetched;
    br = p->bytes_read;
    buf = p->buf;
    not_yet_fetched = br - bf;

    p->bytes_fetched = 0;
    p->bytes_read = not_yet_fetched;

    /* Note:
     * As far as I see, it should never happen that the record-parsing
     * Layer 2 client consumes less than what has been read. We might
     * therefore consider returning an error on that occasion. On the
     * other hand, allowing this use-case makes randomized testing simpler.
     */
    if( not_yet_fetched != 0 )
    {
        memmove( buf, buf + bf, not_yet_fetched );
    }
    else
    {
        l1_release_if_set( &p->buf, p->alloc, MPS_ALLOC_L1_IN );
        p->buf = NULL;
        p->buf_len = 0;
    }

    RETURN( 0 );
}

/*@
  MPS_L1_STREAM_WRITE_INV_REQUIRES(p)
  MPS_L1_STREAM_WRITE_INV_ENSURES(p)
@*/
MBEDTLS_MPS_INLINE
int l1_flush_stream( mps_l1_stream_write *p )
{
    int ret = 0;
    unsigned char *buf;
    size_t br, bw, data_remaining;
    uint8_t status;
    mps_l0_send_t *send;
    TRACE_INIT( "L1 flush stream" );

    /* Flush is called in the following situations:
     * (1) By the user, after data has been dispatched
     *     successfully, and it should be transferred
     *     to Layer 0 despite potentially more space
     *     being available. In this case, the expected
     *     state is MPS_L1_STREAM_STATUS_READY.
     * (2) By mps_l1_write in case a flush is already
     *     in progress, or if a previous call to
     *     mps_l1_dispatch and, subsequently,
     *     l1_check_flush_stream, found a flush necessary.
     *     In this case the state is MPS_L1_STREAM_STATE_FLUSH.
     */
    status = p->status;

    MBEDTLS_MPS_STATE_VALIDATE_RAW( status == MPS_L1_STREAM_STATUS_READY ||
                                    status == MPS_L1_STREAM_STATUS_FLUSH,
                                    "Invalid state in l1_flush_stream()" );

    p->status = MPS_L1_STREAM_STATUS_FLUSH;
    br = p->bytes_ready;
    bw = p->bytes_written;

    buf = p->buf;
    buf += bw;

    send = p->send;
    data_remaining = br - bw;
    while( data_remaining > 0 )
    {
        size_t data_written;

        ret = send( buf, data_remaining );
        if( ret <= 0 )
        {
            TRACE( trace_comment, "send failed with %d", ret );
            /* The underlying transport's send callback should return
             * WANT_WRITE instead of 0 if no data can currently be sent.
             * Fail with a fatal internal error if this spec is not obeyed. */
            if( ret == 0 )
                ret = MBEDTLS_ERR_MPS_BAD_TRANSPORT;
            break;
        }

#if( MAX_INT > SIZE_MAX )
        if( ret > (int) SIZE_MAX )
            RETURN( MBEDTLS_ERR_MPS_BAD_TRANSPORT );
#endif

        /* Now we know that we can safely cast ret to size_t. */
        data_written = (size_t) ret;
        ret = 0;

        /* Double-check that the external Layer 0 obeys its
         * spec to prevent an underflow in data_remaining. */
        if( data_written > data_remaining )
            RETURN( MBEDTLS_ERR_MPS_BAD_TRANSPORT );

        data_remaining -= data_written;
        buf += data_written;
        bw  += data_written;
    }

    if( data_remaining == 0 )
    {
        p->bytes_ready = 0;
        p->bytes_written = 0;
        p->status = MPS_L1_STREAM_STATUS_READY;
    }
    else
        p->bytes_written = bw;

    RETURN( ret );
}

/*@
  MPS_L1_STREAM_WRITE_INV_REQUIRES(p)
  MPS_L1_STREAM_WRITE_INV_ENSURES(p)
@*/
MBEDTLS_MPS_INLINE
int l1_write_stream( mps_l1_stream_write *p,
                     unsigned char **dst, size_t *buflen )
{
    int ret;
    uint8_t status;
    size_t bl, br, data_remaining;
    unsigned char* buf;
    TRACE_INIT( "l1_write_stream" );

    status = p->status;

    /* Check if a flush has been deemed preferable by the
     * flushing strategy (implemented in l1_check_flush_stream
     * and called at the end of mps_l1_dispatch), or if a flush
     * is already in progress but has not yet finished. */
    if( status == MPS_L1_STREAM_STATUS_FLUSH )
    {
        ret = l1_flush_stream( p );
        if( ret != 0 )
            RETURN( ret );
    }

    /* The flush call either succeeded and reset the state
     * to MPS_L1_STREAM_STATUS_READY, or it failed either
     * fatally or because the underlying transport wasn't
     * available, in which case we already returned.
     * So assume the state is MPS_L1_STREAM_STATUS READY. */
    MBEDTLS_MPS_ASSERT_RAW( p->status == MPS_L1_STREAM_STATUS_READY,
                            "Unexpected state are flushing" );

    /* Make sure a write-buffer is available. */
    ret = l1_acquire_if_unset( &p->buf, (size_t*) &p->buf_len,
                               p->alloc, MPS_ALLOC_L1_OUT );
    if( ret != 0 )
        RETURN( ret );

    br = p->bytes_ready;
    bl = p->buf_len;

    buf = p->buf;
    buf += br;
    data_remaining = bl - br;

    /* The flushing strategy should ensure that we should never
     * reach this point if the entire buffer has been dispatched. */
    MBEDTLS_MPS_ASSERT_RAW( data_remaining != 0,
                            "Data remaining despite flush" );

    *dst = buf;
    *buflen = data_remaining;
    p->status = MPS_L1_STREAM_STATUS_WRITE;
    RETURN( 0 );
}

MBEDTLS_MPS_INLINE int l1_write_dependency_stream( mps_l1_stream_write *p )
{
    uint8_t status;

    status = p->status;
    if( status == MPS_L1_STREAM_STATUS_FLUSH )
        return( -1 );

    return( 0 );
}

MBEDTLS_MPS_INLINE int l1_read_dependency_stream( mps_l1_stream_read *p )
{
    ((void) p);
    return( -1 );
}

MBEDTLS_MPS_INLINE
int l1_check_flush_stream( mps_l1_stream_write *p )
{
    /*
     * REMINDER:
     *
     * Remember to update the E-ACSL invariant
     * MPS_L1_STREAM_WRITE_INV_FLUSH_STRATEGY when
     * changing the implementation of this function.
     *
     */

    size_t bl, br;
    br = p->bytes_ready;
    bl = p->buf_len;
    TRACE_INIT( "l1_check_flush_stream:  %u / %u bytes written",
           (unsigned) br, (unsigned) bl );

    /* Several heuristics for flushing are conceivable,
     * the simplest one being to immediately flush once
     * data is available.
     *
     * QUESTION:
     * Is it more efficient to gather a large buffer of
     * outgoing data before calling the underlying stream
     * transport, or should this always be done immediately?
     */
    if( br > 0 && br >= 4 * bl / 5 )
    {
        TRACE( trace_comment, "L1 check flush -- flush" );
        p->status = MPS_L1_STREAM_STATUS_FLUSH;
        RETURN( 0 );
    }

    TRACE( trace_comment, "L1 check flush -- no flush" );
    RETURN( 0 );
}

/*@
  MPS_L1_STREAM_WRITE_INV_REQUIRES(p)
  MPS_L1_STREAM_WRITE_INV_ENSURES(p)
@*/
MBEDTLS_MPS_INLINE
int l1_dispatch_stream( mps_l1_stream_write *p, size_t len, size_t *pending )
{
    size_t bl, br, data_remaining;
    uint8_t status = p->status;
    TRACE_INIT( "L1 dispatch %u", (unsigned) len );

    MBEDTLS_MPS_STATE_VALIDATE_RAW( status == MPS_L1_STREAM_STATUS_WRITE,
                                    "Invalid state in l1_dispatch_stream()" );

    bl = p->buf_len;
    br = p->bytes_ready;
    data_remaining = br - bl;
    if( len > data_remaining )
    {
        TRACE( trace_comment, "out of bounds %u > %u",
               (unsigned) len, (unsigned) data_remaining );
        RETURN( MBEDTLS_ERR_MPS_REQUEST_OUT_OF_BOUNDS );
    }

    br += len;
    p->bytes_ready = br;
    p->status = MPS_L1_STREAM_STATUS_READY;

    if( pending != NULL )
        *pending = br;

    /*
     * NOTE:
     *
     * Currently, a dispatch will *never* immediately
     * transmit data to the underlying transport, but
     * only do so if, subsequently, another l1_write
     * or l1_flush is called.
     * The benefit of this is that there's no danger of
     * mistakenly omitting critical code if a dispatching
     * function fails with the (non-fatal) WANT_WRITE code.
     *
     * COMMENTS WELCOME
     *
     */

    RETURN( l1_check_flush_stream( p ) );
}

#endif /* MBEDTLS_MPS_PROTO_TLS */

/*
 *
 * Datagram-based implementation
 *
 */

#if defined(MBEDTLS_MPS_PROTO_DTLS)

MBEDTLS_MPS_INLINE
void l1_init_dgram_read( mps_l1_dgram_read *p,
                         mps_alloc *ctx,
                         mps_l0_recv_t *recv )
{
    mps_l1_dgram_read const zero = { 0, NULL, NULL, 0, 0, 0, 0 };
    *p = zero;

    p->recv  = recv;
    p->alloc = ctx;
}

MBEDTLS_MPS_INLINE
void l1_init_dgram_write( mps_l1_dgram_write *p,
                          mps_alloc *ctx,
                          mps_l0_send_t *send )
{
    mps_l1_dgram_write const zero = { 0, NULL, NULL, 0, 0, 0 };
    *p = zero;

    p->send  = send;
    p->alloc = ctx;
}

MBEDTLS_MPS_INLINE
void l1_init_dgram( mps_l1_dgram *p,
                    mps_alloc *ctx,
                    mps_l0_send_t *send, mps_l0_recv_t *recv )
{
    l1_init_dgram_read ( &p->rd, ctx, recv );
    l1_init_dgram_write( &p->wr, ctx, send );
}

MBEDTLS_MPS_INLINE
void l1_free_dgram_read( mps_l1_dgram_read *p )
{
    mps_l1_dgram_read const zero = { 0, NULL, NULL, 0, 0, 0, 0 };
    l1_release_if_set( &p->buf, p->alloc, MPS_ALLOC_L1_IN );
    *p = zero;
}

MBEDTLS_MPS_INLINE
void l1_free_dgram_write( mps_l1_dgram_write *p )
{
    mps_l1_dgram_write const zero = { 0, NULL, NULL, 0, 0, 0 };
    l1_release_if_set( &p->buf, p->alloc, MPS_ALLOC_L1_OUT );
    *p = zero;
}

MBEDTLS_MPS_INLINE
void l1_free_dgram( mps_l1_dgram *p )
{
    l1_free_dgram_read ( &p->rd );
    l1_free_dgram_write( &p->wr );
}

/*
 * This function ensures that data is available to be
 * fetched and processed from the datagram reader.
 *
 * Specifically, the following is guaranteed on success:
 * 1. That the reader has acquired a buffer to hold the Layer 0 data.
 * 2. That the reader has received a nonempty datagram from Layer 0.
 *
 * This function is not part of the L1 API but only used
 * as a preparation for the `fetch` function.
 */
MBEDTLS_MPS_INLINE
int l1_ensure_in_dgram( mps_l1_dgram_read *p )
{
    size_t ml, bl;
    unsigned char *buf;
    mps_l0_recv_t *recv;
    int ret;
    TRACE_INIT( "l1_ensure_in_dgram" );

    /* 1. Ensure that a buffer is available to receive data */
    /* TODO: Fix reinterpret cast */
    ret = l1_acquire_if_unset( &p->buf, (size_t*) &p->buf_len,
                               p->alloc, MPS_ALLOC_L1_IN );
    if( ret != 0 )
        RETURN( ret );

    buf = p->buf;
    bl = p->buf_len;

    /* 2. Ensure that a datagram is available */
    ml = p->msg_len;
    if( ml == 0 )
    {
        TRACE( trace_comment, "Request datagram from underlying transport." );
        /* Q: Will the underlying transport error out
         *    if the receive buffer is not large enough
         *    to hold the entire datagram? */
        recv = p->recv;
        ret = recv( buf, bl );
        if( ret <= 0 )
            RETURN( ret );

#if( MAX_INT > SIZE_MAX )
        if( ret > (int) SIZE_MAX )
            RETURN( MBEDTLS_ERR_MPS_BAD_TRANSPORT );
#endif

        /* Now we know that we can safely cast ret to size_t. */
        ml = (size_t) ret;

        /* Double-check that the external Layer 0 obeys its spec. */
        if( ml > bl )
            RETURN( MBEDTLS_ERR_MPS_BAD_TRANSPORT );

        TRACE( trace_comment, "Obtained datagram of size %u", (unsigned) ml );
        p->msg_len = ml;
    }

    RETURN( 0 );
}

MBEDTLS_MPS_INLINE
int l1_fetch_dgram( mps_l1_dgram_read *p,
                    unsigned char **dst,
                    size_t len )
{
    int ret;

    size_t data_need, data_avail;
    size_t wb, wl, ml;

    unsigned char *buf;

    TRACE_INIT( "l1_fetch_dgram, len %u", (unsigned) len );

    ret = l1_ensure_in_dgram( p );
    if( ret != 0 )
        RETURN( ret );

    TRACE( trace_comment, "* Datagram length: %u", (unsigned) p->msg_len     );
    TRACE( trace_comment, "* Window base:     %u", (unsigned) p->window_base );
    TRACE( trace_comment, "* Window length:   %u", (unsigned) p->window_len  );

    wb = p->window_base;
    wl = p->window_len;
    ml = p->msg_len;

    /* As for the previous `ssl_fetch_input`, the semantics of Layer 1 `fetch`
     * is that `fetch N` ensures that, in total, `N` bytes are available.
     * Check how many bytes we have already provided to the user and shift
     * the pointers by what's remaining. */
    if( wl < len )
        data_need = len - wl;
    else
        data_need = 0;

    /* Check how many bytes are left in the current datagram. */
    data_avail = ml - ( wb + wl );
    if( data_need > data_avail )
    {
        TRACE( trace_error, "Read request goes beyond the datagram boundary - requested %u, available %u",
               (unsigned) data_need, (unsigned) data_avail );
        RETURN( MBEDTLS_ERR_MPS_REQUEST_OUT_OF_BOUNDS );
    }

    wl += data_need;
    buf = p->buf;

    p->window_len = wl;
    *dst = buf + wb;
    RETURN( 0 );
}

MBEDTLS_MPS_INLINE
int l1_consume_dgram( mps_l1_dgram_read *p )
{
    int ret;
    size_t wl, wb, ml;

    TRACE_INIT( "l1_consume_dgram" );

    MBEDTLS_MPS_STATE_VALIDATE_RAW( p->buf != NULL,
                "l1_consume_dgram() called, but no datagram available" );

    wb = p->window_base;
    wl = p->window_len;
    ml = p->msg_len;

    if( wb + wl == ml )
    {
        TRACE( trace_comment, "Reached the end of the datagram." );

        /*
         * Releasing the buffer as soon as a datagram
         * has been processed is necessary when we want
         * to try to share read and write buffers. But
         * even if we don't yet attempt this, calling
         * release here is useful to track the usage of the
         * buffers.
         *
         * Note that if this is done, {acquire,release}_buffer
         * shouldn't just forward to malloc/free, as this would
         * lead to an unnecessarily heavy heap usage.
         */
        ret = mps_alloc_release( p->alloc, MPS_ALLOC_L1_IN );
        if( ret != 0 )
            RETURN( ret );

        p->window_base = 0;
        p->window_len  = 0;
        p->msg_len     = 0;
        p->buf         = NULL;
        p->buf_len     = 0;
    }
    else
    {
        TRACE( trace_comment, "More data left in the current datagram." );
        p->window_base = wb + wl;
        p->window_len  = 0;
    }

    RETURN( 0 );
}

MBEDTLS_MPS_INLINE int l1_write_dependency_dgram( mps_l1_dgram_write *p )
{
    uint8_t flush;

    flush = p->flush;
    if( flush )
        return( -1 );

    return( 0 );
}

MBEDTLS_MPS_INLINE int l1_read_dependency_dgram( mps_l1_dgram_read *p )
{
    unsigned char *buf;

    buf = p->buf;
    if( buf == NULL )
        return( -1 );

    return( 0 );
}

MBEDTLS_MPS_INLINE
int l1_write_dgram( mps_l1_dgram_write *p,
                     unsigned char **dst, size_t *dstlen )
{
    int ret;
    unsigned char *buf;
    size_t bl, br;
    uint8_t flush;
    TRACE_INIT( "l1_write_dgram" );

    flush = p->flush;
    if( flush )
    {
        TRACE( trace_comment, "Need to flush first" );
        ret = l1_flush_dgram( p );
        if( ret != 0 )
        {
            TRACE( trace_error, "Flush failed with %d", ret );
            RETURN( ret );
        }
    }

    /* Ensure that a buffer is available to hold them
     * outgoing datagram. */
    /* TODO: Fix reinterpret cast */
    ret = l1_acquire_if_unset( &p->buf, (size_t*) &p->buf_len,
                               p->alloc, MPS_ALLOC_L1_OUT );

    bl = p->buf_len;
    br = p->bytes_ready;

    buf  = p->buf;
    buf += p->bytes_ready;

    *dst    = buf;
    *dstlen = bl - br;
    RETURN( 0 );
}

MBEDTLS_MPS_INLINE
int l1_dispatch_dgram( mps_l1_dgram_write *p, size_t len, size_t *pending )
{
    size_t bl, br;
    TRACE_INIT( "l1_dispatch_dgram, length %u", (unsigned) len );

    MBEDTLS_MPS_STATE_VALIDATE_RAW( p->buf != NULL,
                  "l1_dispatch_dgram() called, but no datagram open" );

    bl = p->buf_len;
    br = p->bytes_ready;

    MBEDTLS_MPS_ASSERT_RAW( len <= bl - br,
                            "l1_dispatch_dgram() length too large" );

    br += len;
    p->bytes_ready = br;
    if( pending != NULL )
        *pending = br;

    RETURN( l1_check_flush_dgram( p ) );
}

MBEDTLS_MPS_INLINE
int l1_check_flush_dgram( mps_l1_dgram_write *p )
{
    size_t bl, br;
    br = p->bytes_ready;
    bl = p->buf_len;
    TRACE_INIT( "l1_check_flush_dgram:  %u / %u bytes written",
           (unsigned) br, (unsigned) bl );

    /* Several heuristics for flushing are conceivable,
     * the simplest one being to immediately flush once
     * data is available. */
    if( br > 0 && br >= 4 * bl / 5 )
    {
        TRACE( trace_comment, "L1 check flush -- flush" );
        p->flush = 1;
        RETURN( 0 );
    }

    TRACE( trace_comment, "L1 check flush -- no flush" );
    RETURN( 0 );
}

MBEDTLS_MPS_INLINE
int l1_flush_dgram( mps_l1_dgram_write *p )
{
    int ret;
    mps_l0_send_t *send;
    unsigned char *buf;
    size_t br;

    TRACE_INIT( "l1_flush_dgram" );

    buf = p->buf;
    if( buf == NULL )
    {
        TRACE( trace_error, "No outgoing datagram open." );
        RETURN( 0 );
    }

    TRACE( trace_comment, "Datagram size: %u", (unsigned) p->bytes_ready );

    br = p->bytes_ready;

    send = p->send;
    ret = send( buf, br );
    if( ret <= 0 )
    {
        TRACE( trace_comment, "send failed with %d", ret );
        /* The underlying transport's send callback should return
         * WANT_WRITE instead of 0 if no data can currently be sent.
         * Fail with a fatal internal error if this spec is not obeyed. */
        if( ret == 0 )
            ret = MBEDTLS_ERR_MPS_BAD_TRANSPORT;

        RETURN( ret );
    }

#if( MAX_INT > SIZE_MAX )
    if( ret > (int) SIZE_MAX )
        RETURN( MBEDTLS_ERR_MPS_BAD_TRANSPORT );
#endif

    if( (size_t) ret != br )
    {
        /* Couldn't deliver the datagram to Layer 0 at once. */
        RETURN( MBEDTLS_ERR_MPS_BAD_TRANSPORT );
    }

    l1_release_if_set( &p->buf, p->alloc, MPS_ALLOC_L1_OUT );

    p->bytes_ready = 0;
    p->buf         = NULL;
    p->buf_len     = 0;

    p->flush = 0;
    RETURN( 0 );
}

#endif /* MBEDTLS_MPS_PROTO_DTLS */

/*
 *
 * Externally visible layer 1 implementation
 * Just a bunch of small wrappers.
 *
 */

/* Q: Generate these functions through a macro?
 *    Doesn't reduce code-size but eases reading. */

int mps_l1_init( mps_l1 *ctx, uint8_t mode, mps_alloc *alloc,
                 mps_l0_send_t *send, mps_l0_recv_t *recv )
{
    TRACE_INIT( "mps_l1_init, mode %u", (unsigned) mode );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    MBEDTLS_MPS_IF_TLS( mode )
        l1_init_stream( &ctx->raw.stream, alloc, send, recv );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
        l1_init_dgram( &ctx->raw.dgram, alloc, send, recv );
#endif /* MBEDTLS_MPS_PROTO_DTLS */

#if defined(MBEDTLS_MPS_PROTO_BOTH)
    ctx->mode = mode;
#else
    ((void) mode);
#endif /* MBEDTLS_MPS_PROTO_BOTH */
    RETURN( 0 );
}

void mps_l1_free( mps_l1 *ctx )
{
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l1_get_mode( ctx );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    MBEDTLS_MPS_IF_TLS( mode )
        l1_free_stream( &ctx->raw.stream );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
        l1_free_dgram( &ctx->raw.dgram );
#endif /* MBEDTLS_MPS_PROTO_DTLS */
}

int mps_l1_fetch( mps_l1 *ctx, unsigned char **buf, size_t desired )
{
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l1_get_mode( ctx );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    MBEDTLS_MPS_IF_TLS( mode )
        return( l1_fetch_stream( &ctx->raw.stream.rd, buf, desired ) );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
        return( l1_fetch_dgram( &ctx->raw.dgram.rd, buf, desired ) );
#endif /* MBEDTLS_MPS_PROTO_DTLS */
}

int mps_l1_consume( mps_l1 *ctx )
{
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l1_get_mode( ctx );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    MBEDTLS_MPS_IF_TLS( mode )
        return( l1_consume_stream( &ctx->raw.stream.rd ) );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
        return( l1_consume_dgram( &ctx->raw.dgram.rd ) );
#endif /* MBEDTLS_MPS_PROTO_DTLS */
}

int mps_l1_write( mps_l1 *ctx, unsigned char **buf, size_t *buflen )
{
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l1_get_mode( ctx );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    MBEDTLS_MPS_IF_TLS( mode )
        return( l1_write_stream( &ctx->raw.stream.wr, buf, buflen ) );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
        return( l1_write_dgram( &ctx->raw.dgram.wr, buf, buflen ) );
#endif /* MBEDTLS_MPS_PROTO_DTLS */
}

int mps_l1_dispatch( mps_l1 *ctx, size_t len, size_t *pending )
{
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l1_get_mode( ctx );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    MBEDTLS_MPS_IF_TLS( mode )
        return( l1_dispatch_stream( &ctx->raw.stream.wr, len, pending ) );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
        return( l1_dispatch_dgram( &ctx->raw.dgram.wr, len, pending ) );
#endif /* MBEDTLS_MPS_PROTO_DTLS */
}

int mps_l1_flush( mps_l1 *ctx )
{
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l1_get_mode( ctx );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    MBEDTLS_MPS_IF_TLS( mode )
        return( l1_flush_stream( &ctx->raw.stream.wr ) );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
        return( l1_flush_dgram( &ctx->raw.dgram.wr ) );
#endif /* MBEDTLS_MPS_PROTO_DTLS */
}

int mps_l1_read_dependency( mps_l1 *ctx )
{
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l1_get_mode( ctx );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    MBEDTLS_MPS_IF_TLS( mode )
        return( l1_read_dependency_stream( &ctx->raw.stream.rd ) );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
        return( l1_read_dependency_dgram( &ctx->raw.dgram.rd ) );
#endif /* MBEDTLS_MPS_PROTO_DTLS */
}

int mps_l1_write_dependency( mps_l1 *ctx )
{
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l1_get_mode( ctx );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    MBEDTLS_MPS_IF_TLS( mode )
        return( l1_write_dependency_stream( &ctx->raw.stream.wr ) );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    MBEDTLS_MPS_ELSE_IF_DTLS( mode )
        return( l1_write_dependency_dgram( &ctx->raw.dgram.wr ) );
#endif /* MBEDTLS_MPS_PROTO_DTLS */
}

#if defined(MBEDTLS_MPS_PROTO_DTLS)
int mps_l1_skip( mps_l1 *ctx )
{
    mps_l1_dgram_read *p;
    mbedtls_mps_transport_type const mode =
        mbedtls_mps_l1_get_mode( ctx );

    TRACE_INIT( "mps_l1_skip" );

    MBEDTLS_MPS_STATE_VALIDATE_RAW( MBEDTLS_MPS_IS_DTLS( mode ),
                                    "mps_l1_skip() only for DTLS." );

    p = &ctx->raw.dgram.rd;
    l1_release_if_set( &p->buf, p->alloc, MPS_ALLOC_L1_IN );

    p->window_base = 0;
    p->window_len  = 0;
    p->msg_len     = 0;
    p->buf         = NULL;
    p->buf_len     = 0;
    RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_DTLS */

#endif /* MBEDTLS_MPS_SEPARATE_LAYERS) ||
          MBEDTLS_MPS_TOP_TRANSLATION_UNIT */
