/*
 *  Message Processing Stack, Layer 2 implementation
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

#include "../../include/mbedtls/mps/layer2.h"
#include "../../include/mbedtls/mps/trace.h"

static int trace_id = TRACE_ID_LAYER_2;

#include <stdlib.h>

static void l2_out_write_version( int major, int minor, int transport,
                              unsigned char ver[2] );
static void l2_read_version( int *major, int *minor, int transport,
                             const unsigned char ver[2] );

/* Reading related */
static int l2_in_fetch_record( mps_l2 *ctx, mps_rec *rec );
static int l2_in_fetch_protected_record( mps_l2 *ctx, mps_rec *rec );
static int l2_in_fetch_protected_record_tls( mps_l2 *ctx, mps_rec *rec );
static int l2_in_fetch_protected_record_dtls12( mps_l2 *ctx, mps_rec *rec );
static int l2_in_release_record( mps_l2 *ctx );

/* Writing related */
static int l2_out_prepare_record( mps_l2 *ctx, mbedtls_mps_epoch_id epoch );
static int l2_out_track_record( mps_l2 *ctx );
static int l2_out_release_record( mps_l2 *ctx, uint8_t force );
static int l2_out_dispatch_record( mps_l2 *ctx );
static int l2_out_write_protected_record( mps_l2 *ctx, mps_rec *rec );
static int l2_out_write_protected_record_tls( mps_l2 *ctx, mps_rec *rec );
static int l2_out_write_protected_record_dtls12( mps_l2 *ctx, mps_rec *rec );
static int l2_out_release_and_dispatch( mps_l2 *ctx, uint8_t force );
static int l2_out_clear_pending( mps_l2 *ctx );

static size_t l2_get_header_len( mps_l2 *ctx, mbedtls_mps_epoch_id epoch );

/* Configuration related */
static int l2_type_can_be_paused( mps_l2 *ctx, uint8_t type );
static int l2_type_can_be_merged( mps_l2 *ctx, uint8_t type );
static int l2_type_is_valid( mps_l2 *ctx, uint8_t type );
static int l2_type_empty_allowed( mps_l2 *ctx, uint8_t type );

static int l2_epoch_check( mps_l2 *ctx, mbedtls_mps_epoch_id epoch,
                           uint8_t purpose );
static int l2_epoch_table_lookup( mps_l2 *ctx, mbedtls_mps_epoch_id epoch,
                                  uint8_t *offset,
                                  mbedtls_mps_transform_t **transform );
static int l2_epoch_check_remove_read( mps_l2 *ctx,
                                       mbedtls_mps_epoch_id epoch );
static int l2_epoch_check_remove_write( mps_l2 *ctx,
                                        mbedtls_mps_epoch_id epoch );
static int l2_epoch_cleanup( mps_l2 *ctx );

/*
 * TODO: Decide and document clearly if the family of `dispatch` functions
 *       on the various layers is allowed to do actual transmission to the
 *       underlying transport or not. This is important, because if it doesn't
 *       -- and instead an explicit call to `flush` must be made -- then `dispatch`
 *       may be called in the middle of a function; if it does, then any call
 *       to `dispatch` must be made re-entrant.
 */

/*
 * TODO: For DTLS, invalid records should be silently skipped. For this,
 *       Layer 1 needs to have a l1_skip function implemented, and Layer 2
 *       should use it at the appropriate places to ensure that, despite
 *       an error code is being returned, the user can continue the Layer 2
 *       context.
 */

static void l2_out_write_version( int major, int minor, int transport,
                       unsigned char ver[2] )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        if( minor == MBEDTLS_SSL_MINOR_VERSION_2 )
            --minor; /* DTLS 1.0 stored as TLS 1.1 internally */

        ver[0] = (unsigned char)( 255 - ( major - 2 ) );
        ver[1] = (unsigned char)( 255 - ( minor - 1 ) );
    }
    else
#else
    ((void) transport);
#endif
    {
        ver[0] = (unsigned char) major;
        ver[1] = (unsigned char) minor;
    }
}

static void l2_read_version( int *major, int *minor, int transport,
                      const unsigned char ver[2] )
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
        *major = 255 - ver[0] + 2;
        *minor = 255 - ver[1] + 1;

        if( *minor == MBEDTLS_SSL_MINOR_VERSION_1 )
            ++*minor; /* DTLS 1.0 stored as TLS 1.1 internally */
    }
    else
#else
    ((void) transport);
#endif
    {
        *major = ver[0];
        *minor = ver[1];
    }
}

int mps_l2_init( mps_l2 *ctx, mps_l1 *l1, uint8_t mode,
                 size_t max_read, size_t max_write,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng )
{
    unsigned char *queue = NULL, *accumulator = NULL;
    mps_l2_bufpair zero_bufpair = { NULL, 0, 0, 0 };
    TRACE_INIT( "l2_init" );

    if( ctx == NULL || l1 == NULL )
        RETURN( MPS_ERR_INVALID_ARGS );

    if( max_write > 0 )
        queue = malloc( max_write );
    if( max_read > 0 )
        accumulator = malloc( max_read );

    if( ( max_write > 0  && queue       == NULL ) ||
        ( max_read  > 0  && accumulator == NULL ) )
    {
        free( queue );
        free( accumulator );
        RETURN( MPS_ERR_ALLOC_FAILED );
    }

    ctx->conf.l1 = l1;
    ctx->conf.mode = mode;
    ctx->conf.version = MPS_L2_VERSION_UNSPECIFIED;
    ctx->conf.type_flag = 0;
    ctx->conf.merge_flag = 0;
    ctx->conf.pause_flag = 0;
    ctx->conf.empty_flag = 0;
    ctx->conf.max_plain_out = 1000;
    ctx->conf.max_plain_in  = 1000;
    ctx->conf.max_cipher_in = 1000;
    ctx->conf.f_rng = f_rng;
    ctx->conf.p_rng = p_rng;

    /* Initialize write-side */
    ctx->out.flush    = 0;
    ctx->out.clearing = 0;
    ctx->out.state = MPS_L2_WRITER_STATE_UNSET;
    ctx->out.queue = queue;
    ctx->out.queue_len = max_write;

    ctx->out.hdr = NULL;
    ctx->out.hdr_len = 0;
    ctx->out.payload = zero_bufpair;

    ctx->out.writer.type = MPS_L2_PORT_NONE;
    ctx->out.writer.epoch = MPS_EPOCH_NONE;
    mbedtls_writer_init( &ctx->out.writer.wr, NULL, 0 );

    /* Initialize read-side */
    ctx->in.accumulator = accumulator;
    ctx->in.acc_len = max_read;
    ctx->in.active_state = MPS_L2_READER_STATE_UNSET;
    ctx->in.paused_state = MPS_L2_READER_STATE_UNSET;
    ctx->in.active = &ctx->in.readers[0];
    ctx->in.paused = &ctx->in.readers[1];

    ctx->in.readers[0].type  = MPS_L2_PORT_NONE;
    ctx->in.readers[0].epoch = MPS_EPOCH_NONE;
    ctx->in.readers[1].type  = MPS_L2_PORT_NONE;
    ctx->in.readers[1].epoch = MPS_EPOCH_NONE;
    mbedtls_reader_init( &ctx->in.readers[0].rd, NULL, 0 );
    mbedtls_reader_init( &ctx->in.readers[1].rd, NULL, 0 );

    ctx->out_ctr = 0;
    ctx->in_ctr = 0;

    ctx->epoch_base = 0;
    ctx->next_epoch = 0;
    for( size_t epoch = 0; epoch < MPS_L2_EPOCH_WINDOW_SIZE; epoch++ )
        ctx->transforms[ ctx->epoch_base + epoch ] = NULL;

    if( mode == MPS_L2_MODE_DATAGRAM )
    {
        for( size_t epoch = 0; epoch < MPS_L2_EPOCH_WINDOW_SIZE; epoch++ )
            ctx->epochs.dtls.state[ ctx->epoch_base + epoch ] = 0;
    }
    else
    {
        ctx->epochs.tls.default_in  = MPS_EPOCH_NONE;
        ctx->epochs.tls.default_out = MPS_EPOCH_NONE;
    }

    RETURN( 0 );
}

int mps_l2_free( mps_l2 *ctx )
{
    ((void) ctx);
    TRACE_INIT( "l2_free" );

    mbedtls_reader_free( &ctx->in.readers[0].rd );
    mbedtls_reader_free( &ctx->in.readers[1].rd );
    mbedtls_writer_free( &ctx->out.writer.wr );

    free( ctx->in.accumulator );
    free( ctx->out.queue );
    ctx->in.accumulator = NULL;
    ctx->in.acc_len = 0;
    ctx->out.queue = NULL;
    ctx->out.queue_len = 0;

    for( size_t epoch = 0; epoch < MPS_L2_EPOCH_WINDOW_SIZE; epoch++ )
    {
        if( ctx->transforms[ epoch ] != NULL )
        {
            transform_free( ctx->transforms[ epoch ] );
            free( ctx->transforms[ epoch] );
            ctx->transforms[ epoch] = NULL;
        }
    }

    RETURN( 0 );
}

int mps_l2_config_version( mps_l2 *ctx, uint8_t ver )
{
    TRACE_INIT( "mps_l2_config_version: %u", (unsigned) ver );
    /* TODO: Add check */
    ctx->conf.version = ver;
    RETURN( 0 );
}

int mps_l2_config_add_type( mps_l2 *ctx, uint8_t type,
                            uint8_t pausing, uint8_t merging, uint8_t empty )
{
    uint64_t mask;
    TRACE_INIT( "mps_l2_config_add_type %u, pausing %u, merging %u",
           (unsigned) type, (unsigned) pausing, (unsigned) merging );

    if( type >= 64 )
        RETURN( MPS_ERR_INVALID_RECORD_TYPE );

    mask = ( (uint64_t) 1u << type );
    if( ctx->conf.type_flag & mask )
        RETURN( MPS_ERR_INVALID_ARGS );

    ctx->conf.type_flag |= mask;
    ctx->conf.pause_flag |= ( pausing == 1 ) * mask;
    ctx->conf.merge_flag |= ( merging == 1 ) * mask;
    ctx->conf.empty_flag |= ( empty   == 1 ) * mask;

    RETURN( 0 );
}

/* Please consult the documentation of mps_l2 for a basic description of the
 * state flow when preapring outgoing records.
 *
 * This function assumes that no outgoing record is currently being processed
 * and prepares L1-owned buffers holding the record header and record plaintext.
 * The latter is subsequently fed to the user-facing writer object (not done
 * in this function). */
static int l2_out_prepare_record( mps_l2 *ctx, mbedtls_mps_epoch_id epoch )
{
    int ret;
    size_t total_sz;
    size_t hdr_len, pre_expansion, post_expansion;
    mbedtls_mps_transform_t *transform;
    unsigned char *hdr;

    TRACE_INIT( "l2_out_prepare, epoch %d", epoch );

    /* Request buffer from Layer 1 to hold entire record. */
    ret = mps_l1_write( ctx->conf.l1, &hdr, &total_sz );
    if( ret != 0 )
    {
        TRACE( trace_comment, "l1_write failed with %d", ret );
        RETURN( ret );
    }

    /* Lookup epoch and get
     * - the record header size, and
     * - the maximum plaintext-to-ciphertext pre- and post-expansion.
     * With this information, the sub-buffer holding the record
     * plaintext before encryption can be calculated. */

    hdr_len = l2_get_header_len( ctx, epoch );

    ret = l2_epoch_table_lookup( ctx, epoch, NULL, &transform );
    if( ret != 0 )
        RETURN( ret );
    transform_get_expansion( transform, &pre_expansion, &post_expansion );

    /* Check for overflow */
    if( hdr_len + pre_expansion < hdr_len ||
        hdr_len + pre_expansion + post_expansion < hdr_len + pre_expansion )
    {
        TRACE( trace_comment, "INTERNAL ERROR on pre- and postexpansion" );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    /* Check if buffer obtained from Layer 1 is large enough to accomodate
     * at least a protected record with plaintext length 1. */
    if( hdr_len + pre_expansion + post_expansion >= total_sz )
    {
        TRACE( trace_comment, "Not enough space for record, need at least %u == ( %u + %u + %u + 1 ) but have only %u",
               (unsigned)( hdr_len + pre_expansion + post_expansion + 1 ),
               (unsigned) hdr_len, (unsigned) pre_expansion, (unsigned) post_expansion,
               (unsigned) total_sz );

        /* TODO: Check that L1 has something to send to avoid an infinite loop
         *       in case L1 is configured with such small buffers that it's
         *       impossible to send a single record. */

        /* Abort the write and remember to flush before the next write. */
        mps_l1_dispatch( ctx->conf.l1, 0 /* Abort := Dispatch nothing */ );
        ctx->out.clearing = 1;

        RETURN( MPS_ERR_WANT_WRITE );
    }

    /* Dissect L1 record buffer into header, ciphertext and plaintext parts.
     * The plaintext sub-buffer can subsequently be fed to the writer which
     * then gets passed to the user, i.e. Layer 3. */
    ctx->out.hdr = hdr;
    ctx->out.hdr_len = hdr_len;
    ctx->out.payload.buf = hdr + hdr_len;
    ctx->out.payload.buf_len = total_sz - hdr_len;
    ctx->out.payload.data_offset = pre_expansion;
    ctx->out.payload.data_len = total_sz - hdr_len -
        pre_expansion - post_expansion;

    TRACE( trace_comment, "New outgoing record successfully prepared." );
    TRACE( trace_comment, " * Max plaintext size: %u",
           (unsigned) ctx->out.payload.data_len );
    TRACE( trace_comment, " * Pre expansion:      %u",
           (unsigned) ctx->out.payload.data_offset );
    RETURN( 0 );
}

/* Please consult the documentation of mps_l2 for a basic description of the
 * state flow when preapring outgoing records.
 *
 * This function assumes that the record header and record plaintext pointers
 * are valid ( := obtained from l2_out_prepare ) and some content has been
 * written to them (in practice, this will be done through the user-facing
 * writer object, but for the purpose of this function this is not important).
 * Further, it is assumed that no other resource holds partial ownership of
 * these buffers (concretely, again, this means that the writer's access to
 * the buffers has already been revoked). It then proceeds to protect the
 * record payload via the transform attached to the record's epoch, writes
 * the header, and dispatches the final record to Layer 1. */
static int l2_out_dispatch_record( mps_l2 *ctx )
{
    int ret;
    mps_rec rec;
    mbedtls_mps_transform_t *transform;
    TRACE_INIT( "l2_out_dispatch_record" );
    TRACE( trace_comment, "Plaintext length: %u",
           (unsigned) ctx->out.payload.data_len );

    if( ctx->out.payload.data_len == 0 )
    {
        TRACE( trace_comment, "Attempt to dispatch an empty record %u.",
               (unsigned) ctx->out.writer.type );
        TRACE( trace_comment, "Empty records allowed for type %u: %u",
               (unsigned) ctx->out.writer.type,
               l2_type_empty_allowed( ctx, ctx->out.writer.type ) );
    }

    /* Silently ignore empty records if such are not allowed
     * for the current record content type. */
    if( ctx->out.payload.data_len == 0 &&
        l2_type_empty_allowed( ctx, ctx->out.writer.type ) == 0 )
    {
        TRACE( trace_comment, "Empty records are not allowed for type %u -> ignore request.",
               ctx->out.writer.type );

        /* dispatch(0) effectively resets the underlying Layer 1. */
        ret = mps_l1_dispatch( ctx->conf.l1, 0 );
        if( ret != 0 )
            RETURN( ret );
    }
    else
    {
        /* Step 1: Prepare the record header structure. */

        /* TODO: Handle the case where the version hasn't been set yet! */

        rec.major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;
        rec.minor_ver = ctx->conf.version;
        rec.buf = ctx->out.payload;
        rec.ctr = ctx->out_ctr;
        rec.epoch = ctx->out.writer.epoch;
        rec.type = ctx->out.writer.type;

        ctx->out_ctr++;

        ret = l2_epoch_table_lookup( ctx, ctx->out.writer.epoch,
                                     NULL, &transform );
        if( ret != 0 )
        {
            TRACE( trace_comment, "Epoch lookup failed" );
            RETURN( ret );
        }

        /* TODO: For TLS 1.3, add TLSPlaintext header, incl. padding. */

        /* Step 2: Apply record payload protection. */
        TRACE( trace_comment, "Encrypt record. The plaintext offset is %u.",
               (unsigned) rec.buf.data_offset );
        ret = transform_encrypt( transform, &rec, ctx->conf.f_rng,
                                 ctx->conf.p_rng );
        if( ret != 0 )
        {
            TRACE( trace_comment, "The record encryption failed with %d", ret );
            RETURN( ret );
        }

        /* Double-check that we have calculated the offset of the
         * plaintext buffer from the ciphertext buffer correctly
         * when preparing the outgoing record.
         * This should always be true, but better err on the safe side. */
        if( rec.buf.data_offset != 0 )
        {
            TRACE( trace_error, "Get non-zero ciphertext offset %u after encryption.",
                   (unsigned) rec.buf.data_offset );
            RETURN( MPS_ERR_INTERNAL_ERROR );
        }

        /* Step 3: Write version- and mode-specific header and send record. */
        ret = l2_out_write_protected_record( ctx, &rec );
        if( ret != 0 )
            RETURN( ret );
    }

    /* Epochs might have been held back because of the pending write. */
    ret = l2_epoch_cleanup( ctx );
    if( ret != 0 )
        RETURN( ret );

    RETURN( 0 );
}

static int l2_out_write_protected_record( mps_l2 *ctx, mps_rec *rec )
{
    int ret = 0;
    mps_l2_bufpair const zero_bufpair = { NULL, 0, 0, 0 };
    TRACE_INIT( "Write protected record" );

    if( ctx->conf.mode == MPS_L2_MODE_STREAM )
    {
        /* The record header structure is the same for all versions
         * of TLS, including TLS 1.3. The only difference is that in
         * TLS 1.3, the record payload needs to be post-processed to
         * remove the plaintext padding.
         * Note padding is treated entirely separatedly from encryption
         * and authentication, while for the use of CBC in earlier versions,
         * it was part of CBC, and AEAD didn't allow padding at all. */
        ret = l2_out_write_protected_record_tls( ctx, rec );
    }
    else if( ctx->conf.mode == MPS_L2_MODE_DATAGRAM )
    {
        /* Only handle DTLS 1.0 and 1.2 for the moment,
         * which have a uniform and simple record header. */
        switch( ctx->conf.version )
        {
            case MBEDTLS_SSL_MINOR_VERSION_2: /* DTLS 1.0 */
            case MBEDTLS_SSL_MINOR_VERSION_3: /* DTLS 1.2 */
                ret = l2_out_write_protected_record_dtls12( ctx, rec );

            /* At some point, add DTLS 1.3 here */

        }
    }
    else
    {
        /* Should never happen. */
        ret = MPS_ERR_INTERNAL_ERROR;
    }

    /* Cleanup internal structure for outgoing data. */
    ctx->out.hdr = NULL;
    ctx->out.hdr_len = 0;
    ctx->out.payload = zero_bufpair;

    RETURN( ret );
}

static int l2_out_write_protected_record_tls( mps_l2 *ctx, mps_rec *rec )
{
    uint8_t * const hdr = ctx->out.hdr;
    size_t const hdr_len = ctx->out.hdr_len;
    TRACE_INIT( "l2_write_protected_record_tls" );

    /* Double-check that we have calculated the header length
     * correctly when preparing the outgoing record.
     * This should always be true, but better err on the safe side. */
    if( hdr_len != 5 )
        RETURN( MPS_ERR_INTERNAL_ERROR );

    /* Header structure is the same for all TLS versions.

       From RFC 5246 - Section 6.2

       struct {
          uint8 major;
          uint8 minor;
       } ProtocolVersion;

       enum {
          change_cipher_spec(20), alert(21), handshake(22),
          application_data(23), (255)
       } ContentType;

       struct {
          ContentType type;
          ProtocolVersion version;
          uint16 length;
          opaque fragment[TLSPlaintext.length];
       } TLSPlaintext;

    */

    hdr[0] = rec->type;

    l2_out_write_version( MBEDTLS_SSL_MAJOR_VERSION_3, ctx->conf.version,
                      ctx->conf.mode, hdr + 1 );

    hdr[3] = ( rec->buf.data_len >> 8 ) & 0xff;
    hdr[4] = ( rec->buf.data_len >> 0 ) & 0xff;

    TRACE( trace_comment, "Write protected record -- DISPATCH" );
    RETURN( mps_l1_dispatch( ctx->conf.l1, hdr_len + rec->buf.data_len ) );
}

static int l2_out_write_protected_record_dtls12( mps_l2 *ctx, mps_rec *rec )
{
    ((void) ctx);
    ((void) rec);
    TRACE_INIT( "l2_write_protected_record_dtls12" );

    /* TODO */
    RETURN( MPS_ERR_UNSUPPORTED_FEATURE );
}

int mps_l2_write_flush( mps_l2 *ctx )
{
    TRACE_INIT( "mps_l2_write_flush, state %u", ctx->out.state );
    if( ctx->out.state == MPS_L2_WRITER_STATE_EXTERNAL )
    {
        TRACE( trace_error, "Unexpected operation" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }

    ctx->out.flush = 1;
    RETURN( l2_out_clear_pending( ctx ) );
}

/* See the documentation of `clearing` and `flush` in layer2.h
 * for more information on the flow of this routine. */
static int l2_out_clear_pending( mps_l2 *ctx )
{
    int ret;
    TRACE_INIT( "l2_out_clear_pending, state %u", (unsigned) ctx->out.state );

    if( ctx->out.clearing == 1 )
    {
        ret = mps_l1_flush( ctx->conf.l1 );
        if( ret != 0 )
            RETURN( ret );
        ctx->out.clearing = 0;
    }

    /* Each iteration strictly reduces the size of the
     * writer's queue, hence the loop must terminate. */
    while( ctx->out.state == MPS_L2_WRITER_STATE_QUEUEING )
    {
        mbedtls_mps_epoch_id queued_epoch;
        queued_epoch = ctx->out.writer.epoch;

        TRACE( trace_comment, "Queued data is pending to be dispatched" );

        /* Prepare an outgoing record to dispatch the queued data */
        ret = l2_out_prepare_record( ctx, queued_epoch );
        if( ret != 0 )
            RETURN( ret );

        ret = l2_out_track_record( ctx );
        if( ret == 0 )
            break;
        else if( ret != MBEDTLS_ERR_WRITER_NEED_MORE )
            RETURN( ret );

        TRACE( trace_comment, "The prepared record was entirely filled with queued data -> dispatch it" );

        /* There's more queued data pending, so just deliver the record. */
        ret = l2_out_dispatch_record( ctx );
        if( ret != 0 )
            RETURN( ret );
    }

    TRACE( trace_comment, "Queue clear" );

    if( ctx->out.flush == 1 )
    {
        TRACE( trace_comment, "A flush was requested requested, state %u",
               (unsigned) ctx->out.state );
        if( ctx->out.state == MPS_L2_WRITER_STATE_INTERNAL )
        {
            ret = l2_out_release_and_dispatch( ctx, MBEDTLS_WRITER_RECLAIM_FORCE );
            if( ret != 0 )
                RETURN( ret );

            /* NOTE:
             * This code is only valid if Layer 1 doesn't attempt partial
             * transmissions to the underlying transport; in other words,
             * if layer 1 starts sending, it must behave as if `flush` had
             * been called, and make sure everything is delivered before
             * the next write can be made.
             * If this is not satisfied, and e.g. Layer 1 might only clear
             * parts of the internal buffers, enough to have free space for
             * new outgoing messages, then it might happen that the call
             * to l2_out_release_and_dispatch above would return WANT_WRITE,
             * thereby terminating this function early, but without having
             * informed Layer 1 that it should flush everything.
             *
             * So: Transmit everything or nothing, but nothing partial.
             */

            /* Epochs might have been held back because of the pending write. */
            ret = l2_epoch_cleanup( ctx );
            if( ret != 0 )
                RETURN( ret );
        }

        ctx->out.clearing = 1;
        ctx->out.flush = 0;
    }

    if( ctx->out.clearing == 1 )
    {
        ret = mps_l1_flush( ctx->conf.l1 );
        if( ret != 0 )
            RETURN( ret );
        ctx->out.clearing = 0;
    }

    RETURN( 0 );
}

int mps_l2_epoch_add( mps_l2 *ctx,
                      mbedtls_mps_transform_t *transform,
                      mbedtls_mps_epoch_id *epoch )
{
    uint8_t epoch_offset;
    TRACE_INIT( "mps_l2_epoch_add" );
    TRACE( trace_comment, "* Transform: %p", transform );

    if( ctx->next_epoch == MPS_L2_LIMIT_EPOCH )
    {
        TRACE( trace_error, "We reached the maximum epoch." );
        RETURN( MPS_ERR_EPOCH_OVERFLOW );
    }

    /* Check that we have space for another epoch. */
    epoch_offset = ctx->next_epoch - ctx->epoch_base;
    if( epoch_offset == MPS_L2_EPOCH_WINDOW_SIZE )
    {
        TRACE( trace_error, "The epoch window is full." );
        RETURN( MPS_ERR_EPOCH_WINDOW_EXCEEDED );
    }
    *epoch = ctx->next_epoch;

    ctx->next_epoch++;
    ctx->transforms[ epoch_offset ] = transform;
    RETURN( 0 );
}

int mps_l2_epoch_usage( mps_l2 *ctx, mbedtls_mps_epoch_id epoch,
                        mbedtls_mps_epoch_usage usage )
{
    int ret;
    uint8_t epoch_offset;

    mbedtls_mps_epoch_id remove_read  = MPS_EPOCH_NONE;
    mbedtls_mps_epoch_id remove_write = MPS_EPOCH_NONE;
    TRACE_INIT( "mps_l2_epoch_usage" );
    TRACE( trace_comment, "* Epoch: %d", epoch );
    TRACE( trace_comment, "* Usage: %u", (unsigned) usage );

    /* 1. Check if the epoch is valid. */

    if( epoch == MPS_EPOCH_NONE || epoch < ctx->epoch_base )
    {
        TRACE( trace_error, "Epoch %d smaller than the base epoch %d.",
               epoch, ctx->epoch_base );
        RETURN( MPS_ERR_INVALID_RECORD_EPOCH );
    }

    epoch_offset = epoch - ctx->epoch_base;
    if( epoch_offset >= MPS_L2_EPOCH_WINDOW_SIZE )
    {
        TRACE( trace_error, "The epoch offset %u (== %d - %d) exceeds the epoch window size %u.",
               (unsigned) epoch_offset, epoch,
               ctx->epoch_base, MPS_L2_EPOCH_WINDOW_SIZE );
        RETURN( MPS_ERR_INVALID_RECORD_EPOCH );
    }

    /* 2. Check if the change of permissions collides with
     *    potential present usage of the epoch. */

    if( ctx->conf.mode == MPS_L2_MODE_STREAM )
    {
        if( ( usage & MPS_EPOCH_READ ) != 0    &&
            ctx->epochs.tls.default_in != epoch )
        {
            remove_read = ctx->epochs.tls.default_in;
            /* Reset record sequence number */
            ctx->in_ctr = 0;
        }

        if( ( usage & MPS_EPOCH_WRITE ) != 0   &&
            ctx->epochs.tls.default_out != epoch )
        {
            remove_write = ctx->epochs.tls.default_out;
            /* Reset record sequence number */
            ctx->out_ctr = 0;
        }
    }
    else
    {
        mbedtls_mps_epoch_usage old_usage =
            ctx->epochs.dtls.state[ epoch_offset ];

        mbedtls_mps_epoch_usage permission_removal = old_usage & ( ~usage );

        /* Check if read or write permissions are being removed. */
        if( ( permission_removal & MPS_EPOCH_READ ) != 0 )
            remove_read = epoch;
        if( ( permission_removal & MPS_EPOCH_WRITE ) != 0 )
            remove_write = epoch;
    }

    if( remove_read != MPS_EPOCH_NONE )
    {
        ret = l2_epoch_check_remove_read( ctx, remove_read );
        if( ret != 0 )
            RETURN( ret );
    }
    if( remove_write != MPS_EPOCH_NONE )
    {
        ret = l2_epoch_check_remove_write( ctx, remove_write );
        if( ret != 0 )
            RETURN( ret );
    }

    /* 3. Apply the change of permissions. */

    if( ctx->conf.mode == MPS_L2_MODE_STREAM )
    {
        if( usage & MPS_EPOCH_READ )
            ctx->epochs.tls.default_in = epoch;
        if( usage & MPS_EPOCH_WRITE )
            ctx->epochs.tls.default_out = epoch;
    }
    else
    {
        ctx->epochs.dtls.state[ epoch_offset ] = usage;
    }

    RETURN( l2_epoch_cleanup( ctx ) );
}

static int l2_epoch_check_remove_write( mps_l2 *ctx,
                                        mbedtls_mps_epoch_id epoch )
{
    int ret;
    TRACE_INIT( "l2_epoch_check_remove_write" );
    TRACE( trace_comment, " * Epoch ID: %u", (unsigned) epoch );

    if( ctx->out.state == MPS_L2_WRITER_STATE_UNSET ||
        ctx->out.writer.epoch != epoch )
    {
        TRACE( trace_comment, "The epoch is currently not used for writing." );
        RETURN( 0 );
    }

    if( ctx->out.state == MPS_L2_WRITER_STATE_EXTERNAL )
    {
        TRACE( trace_error, "The active writer is using the epoch." );
        RETURN( MPS_ERR_EPOCH_CHANGE_REJECTED );
    }

    if( ctx->out.state == MPS_L2_WRITER_STATE_INTERNAL )
    {
        /* An outgoing but not yet dispatched record is open
         * for the given epoch. Dispatch it, so that the epoch
         * is no longer needed. */
        TRACE( trace_comment, "Dispatch current outgoing record." );

        ret = l2_out_release_and_dispatch( ctx, MBEDTLS_WRITER_RECLAIM_FORCE );
        if( ret != 0 )
            RETURN( ret );
    }

    /* Now the outgoing state is UNSET or QUEUEING. */

    TRACE( trace_comment, "The epoch is not actively used for reading." );
    RETURN( 0 );
}

static int l2_epoch_check_remove_read( mps_l2 *ctx, mbedtls_mps_epoch_id epoch )
{
    TRACE_INIT( "l2_epoch_check_remove_read" );
    TRACE( trace_comment, " * Epoch ID: %u", (unsigned) epoch );

    if( ctx->in.active_state == MPS_L2_READER_STATE_EXTERNAL &&
        ctx->in.active->epoch == epoch )
    {
        TRACE( trace_error, "The active reader is using the epoch." );
        RETURN( MPS_ERR_EPOCH_CHANGE_REJECTED );
    }

    if( ctx->in.paused_state == MPS_L2_READER_STATE_PAUSED &&
        ctx->in.paused->epoch == epoch )
    {
        TRACE( trace_error, "The paused reader is using the epoch." );
        RETURN( MPS_ERR_EPOCH_CHANGE_REJECTED );
    }

    /* NOTE:
     * We allow the active reader to be in state MPS_L2_READER_STATE_INTERNAL,
     * i.e. we do not yet error out on this occasion when more incoming data
     * is available for the same epoch.
     * Instead, the error will be triggered on the next call to mps_l2_read(),
     * which will attempt to continue reading from the currently opened record
     * but will find its epoch no longer valid.
     *
     * This covers the scenario where the peer attempts to piggyback
     * a handshake message that should be encrypted with a new epoch
     * on top of a handshake record that's encrypted with a previous
     * epoch, e.g. the EncryptedExtension message piggy backing on the
     * same record as the ServerHello.
     */

    TRACE( trace_comment, "The epoch is not actively used for reading." );
    RETURN( 0 );
}

int mps_l2_write_start( mps_l2 *ctx, mps_l2_out *out )
{
    int ret;
    uint8_t desired_type;
    mbedtls_mps_epoch_id desired_epoch;

    TRACE_INIT( "mps_l2_write_start" );

    if( ctx->out.state == MPS_L2_WRITER_STATE_EXTERNAL )
    {
        TRACE( trace_error, "Unexpected operation" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }

    desired_type = out->type;
    if( l2_type_is_valid( ctx, desired_type ) == 0 )
    {
        TRACE( trace_error, "Message type %d is invalid", desired_type );
        RETURN( MPS_ERR_INVALID_RECORD_TYPE );
    }

    desired_epoch = out->epoch;
    ret = l2_epoch_check( ctx, desired_epoch, MPS_EPOCH_WRITE );
    if( ret != 0 )
        RETURN( ret );

    /* Make sure that no data is queued for dispatching, and that
     * all dispatched data has been delivered by Layer 1 in case
     * a flush has been requested. */
    ret = l2_out_clear_pending( ctx );
    if( ret != 0 )
    {
        TRACE( trace_comment, "l2_out_clear_pending failed with %d", ret );
        RETURN( ret );
    }

    /* State cannot be MPS_L2_WRITER_STATE_QUEUEING anymore now,
     * so it's either INTERNAL or UNSET.
     *
     * If an outgoing record has been prepared, append to it
     * in case both desired type and epoch match. If they don't
     * the record must be dispatched first before a new one
     * can be prepared with the correct type and epoch.
     */
    if( ctx->out.state == MPS_L2_WRITER_STATE_INTERNAL )
    {
        if( ctx->out.writer.type  == desired_type &&
            ctx->out.writer.epoch == desired_epoch )
        {
            TRACE( trace_comment, "Type and epoch of currently open record match -> attach to it" );
            ctx->out.state = MPS_L2_WRITER_STATE_EXTERNAL;
            out->wr = &ctx->out.writer.wr;
            TRACE( trace_comment, "TOTAL: %u, WRITTEN: %u (==%u), REMAINING %u",
                   (unsigned) out->wr->out_len,
                   (unsigned) out->wr->commit, (unsigned) out->wr->end,
                   (unsigned) ( out->wr->out_len - out->wr->commit ) );
            RETURN( 0 );
        }

        TRACE( trace_comment, "Type or epoch of the currently open record don't match -> reclaim and dispatch" );
        ret = l2_out_release_and_dispatch( ctx, MBEDTLS_WRITER_RECLAIM_FORCE );
        if( ret != 0 )
            RETURN( ret );

        /* Continue on success */
    }

    /* State must be MPS_L2_WRITER_STATE_UNSET when we reach this. */

    ret = l2_out_prepare_record( ctx, desired_epoch );
    if( ret != 0 )
        RETURN( ret );
    ctx->out.writer.type  = desired_type;
    ctx->out.writer.epoch = desired_epoch;

    ret = l2_out_track_record( ctx );
    if( ret != 0 )
        RETURN( ret );

    ctx->out.state = MPS_L2_WRITER_STATE_EXTERNAL;
    out->wr = &ctx->out.writer.wr;
    RETURN( 0 );
}

int mps_l2_write_done( mps_l2 *ctx )
{
    int ret;
    TRACE_INIT( "l2_write_done" );
    if( ctx->out.state != MPS_L2_WRITER_STATE_EXTERNAL )
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );

    ctx->out.state = MPS_L2_WRITER_STATE_INTERNAL;

    ret = l2_out_release_and_dispatch( ctx, MBEDTLS_WRITER_RECLAIM_NO_FORCE );
    if( ret != 0 )
        RETURN( ret );

    RETURN( 0 );
}

static int l2_out_track_record( mps_l2 *ctx )
{
    int ret;
    TRACE_INIT( "l2_out_track_record" );

    if( ctx->out.state == MPS_L2_WRITER_STATE_UNSET )
    {
        /* Depending on whether the record content type is pausable,
         * provide a queue to the writer or not. */
        if( l2_type_can_be_paused( ctx, ctx->out.writer.type ) )
        {
            ret = mbedtls_writer_init( &ctx->out.writer.wr, ctx->out.queue,
                                       ctx->out.queue_len );
        }
        else
        {
            ret = mbedtls_writer_init( &ctx->out.writer.wr, NULL, 0 );
        }
        if( ret != 0 )
            RETURN( ret );
    }

    ret = mbedtls_writer_feed( &ctx->out.writer.wr,
                        ctx->out.payload.buf + ctx->out.payload.data_offset,
                        ctx->out.payload.data_len );
    if( ret == 0 )
        ctx->out.state = MPS_L2_WRITER_STATE_INTERNAL;

    RETURN( ret );
}

static int l2_out_release_record( mps_l2 *ctx, uint8_t force )
{
    int ret;
    size_t bytes_written, bytes_queued;
    TRACE_INIT( "l2_out_release_record, force %u, state %u", force,
           (unsigned) ctx->out.state );

    ret = mbedtls_writer_reclaim( &ctx->out.writer.wr, &bytes_written,
                                  &bytes_queued, force );
    if( force == MBEDTLS_WRITER_RECLAIM_NO_FORCE &&
        ret   == MBEDTLS_ERR_WRITER_DATA_LEFT )
    {
        TRACE( trace_comment, "Data left" );
        /* Check if records of the given type may be merged.
         * E.g., in [D]TLS 1.3 multiple multiple alerts must not
         * be placed in a single record. */
        if( l2_type_can_be_merged( ctx, ctx->out.writer.type ) == 1 )
        {
            TRACE( trace_comment, "Can be merged" );
            /* Here's the place to add a heuristic deciding when to dispatch
             * a record even if space is left in the output buffer. For TLS,
             * in principle we can go on with as little as a single byte, but
             * at least for DTLS a minimum should be fixed. */

            if( /* HEURISTIC */ 1 )
            {
                TRACE( trace_comment, "Await more data" );
                RETURN( MBEDTLS_ERR_WRITER_DATA_LEFT );
            }

            /* Fall through if heuristic determines that the current record
             * should be dispatched albeit spacing being left: fall through */
        }

        TRACE( trace_comment, "Type cannot be merged -- forced reclaim" );
        ret = mbedtls_writer_reclaim( &ctx->out.writer.wr, NULL, NULL,
                                      MBEDTLS_WRITER_RECLAIM_FORCE );
        if( ret != 0 )
            RETURN( ret );
    }
    else if( ret != 0 )
        RETURN( ret );

    /* Now it's clear that the record should be dispatched */

    /* Update internal length field and change the writer state. */
    ctx->out.payload.data_len = bytes_written;

    if( bytes_queued > 0 )
    {
        /* The writer has queued data */
        TRACE( trace_comment, "The writer has %u bytes of queued data.",
               (unsigned) bytes_queued );

        /* Double-check that the record content type can indeed be paused. */
        if( l2_type_can_be_paused( ctx, ctx->out.writer.type ) == 0 )
        {
            TRACE( trace_comment, "Content type not pausable -- queue shouldn't"
                   " have been passed to the writer in the first place" );
            RETURN( MPS_ERR_INTERNAL_ERROR );
        }

        ctx->out.state = MPS_L2_WRITER_STATE_QUEUEING;
    }
    else
    {
        /* No data has been queued */
        TRACE( trace_comment, "The writer has no queued data." );

        /* The writer is no longer needed. */
        ret = mbedtls_writer_free( &ctx->out.writer.wr );
        if( ret != 0 )
            RETURN( ret );

        ctx->out.state = MPS_L2_WRITER_STATE_UNSET;
    }

    RETURN( 0 );
}

static int l2_out_release_and_dispatch( mps_l2 *ctx, uint8_t force )
{
    int ret;
    TRACE_INIT( "l2_out_release_and_dispatch, force %u", force );

    /* Attempt to release the current record. */
    ret = l2_out_release_record( ctx, force );
    if( ret != 0 && ret != MBEDTLS_ERR_WRITER_DATA_LEFT )
        RETURN( ret );

    if( ret == 0 )
    {
        TRACE( trace_comment, "Dispatch current outgoing record." );
        ret = l2_out_dispatch_record( ctx );
        if( ret != 0 )
            RETURN( ret );
    }
    else
    {
        TRACE( trace_comment, "Current record need not yet be dispatched." );
    }

    RETURN( 0 );
}

int mps_l2_read_done( mps_l2 *ctx )
{
    int ret;
    mps_l2_in_internal *tmp;
    size_t paused;

    TRACE_INIT( "mps_l2_read_done" );

    /*
     * This only makes sense if the active reader is currently
     * on the user-side, i.e. 'external'; in this case, layer 1
     * has provided us with a record the contents of which the
     * reader manages, so the order of freeing the resources is:
     * first retract the reader's access to the buffer, then
     * mark it as complete to layer 1, retracting our own access.
     *
     * Outline:
     * Attempt to reclaim the record buffer from the active external reader.
     * 1a If unsuccessful because data is left, switch the state of the
     *    active reader from external to internal, but don't do anything else.
     *    We will hand out the reader again on the next call to read_start.
     *    This would e.g. happen if there are multiple handshake messages
     *    within a single record.
     * 1b If unsuccessful because no accumulator is present,
     *    or the accumulator is too small, return a special error code.
     * 2 If successful, check if the active reader has been paused.
     *   2.1 If no: Unset the active reader and return success.
     *              This happens when layer 3 acknowledges the end
     *              of a message at record boundary.
     *   2.2 If yes: Swap active and paused reader, and return success.
     *               In this case, when we read a new record of matching
     *               content type, we'll feed its contents into the
     *               paused reader until the reader becomes ready to be
     *               reactivated, and then it'll be made active again.
     */

    if( ctx->in.active_state != MPS_L2_READER_STATE_EXTERNAL )
    {
        TRACE( trace_comment, "Unexpected operation" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }

    ret = mbedtls_reader_reclaim( &ctx->in.active->rd, &paused );
    if( ret == MBEDTLS_ERR_READER_DATA_LEFT )
    {
        /* 1a */
        TRACE( trace_comment, "There is data remaining in the current incoming record." );
        ctx->in.active_state = MPS_L2_READER_STATE_INTERNAL;
        RETURN( 0 );
    }
    else if( ret == MBEDTLS_ERR_READER_NEED_ACCUMULATOR      ||
             ret == MBEDTLS_ERR_READER_ACCUMULATOR_TOO_SMALL )
    {
        /* 1b */
        if( l2_type_can_be_paused( ctx, ctx->in.active->type ) == 1 )
        {
#if !defined(MPS_L2_ALLOW_PAUSABLE_CONTENT_TYPE_WITHOUT_ACCUMULATOR)
            /* In this configuration, we shouldn't have opened the read
             * port for a pausable record content type in the first
             * place when not also providing an accumulator with it. */
            RETURN( MPS_ERR_INTERNAL_ERROR );
#else
            RETURN( MPS_ERR_PAUSE_REFUSED );
#endif
        }
        RETURN( MPS_ERR_TYPE_CANT_BE_PAUSED );
    }
    else if( ret != 0 )
        RETURN( ret );

    /* 2 */

    TRACE( trace_comment, "Successfully reclaimed the record content buffer." );
    TRACE( trace_comment, "Number of bytes asked for beyond record: %u",
           (unsigned) paused );

    if( paused == 0 )
    {
        /* 2.1 */
        TRACE( trace_comment, "No excess request; releasing record." );

        ret = l2_in_release_record( ctx );
        if( ret != 0 )
            RETURN( ret );

        ret = mbedtls_reader_free( &ctx->in.active->rd );
        if( ret != 0 )
            RETURN( ret );

        ctx->in.active_state = MPS_L2_READER_STATE_UNSET;
        RETURN( 0 );
    }

    /* 2.2 */

    /*
     * At this point, we know that data has been backed up, so
     * we must have provided an accumulator, so the record content
     * type must have been pauseable.
     * Also, we wouldn't have provided the accumulator if a
     * reader had already been paused.
     *
     * Let's double-check this reasoning nonetheless.
     *
     * NOTE: Potentially remove this after review.
     */
    if( l2_type_can_be_paused( ctx, ctx->in.active->type ) == 0 ||
        ctx->in.paused_state != MPS_L2_READER_STATE_UNSET )
    {
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    TRACE( trace_comment, "Switch active and paused reader" );
    ctx->in.active_state = MPS_L2_READER_STATE_UNSET;
    ctx->in.paused_state = MPS_L2_READER_STATE_PAUSED;
    tmp = ctx->in.active;
    ctx->in.active = ctx->in.paused;
    ctx->in.paused = tmp;
    ret = l2_in_release_record( ctx );
    if( ret != 0 )
        RETURN( ret );

    RETURN( 0 );
}

int mps_l2_read_start( mps_l2 *ctx, mps_l2_in *in )
{
    int ret;
    mps_l2_in_internal *tmp;
    mps_rec rec;
    unsigned char *acc;
    size_t acc_len;
    TRACE_INIT( "mps_l2_read_start" );

    /*
     * Outline:
     * 1 If the active reader is set and external, fail with an internal error.
     * 2 If instead the active reader is set and internal (i.e. a record has
     *   been opened but not yet fully processed), ensure the its epoch is still
     *   valid and make it external in this case.
     * 3 If the active reader is unset, attempt to fetch a new record from L1.
     *    If it succeeds:
     *    3.1 If the paused reader is set, check if its type and epoch matches
     *         the type and epoch of the new record.
     *         3.1.1 If yes, feed the new record content into the paused reader.
     *               3.1.1.1 If enough data is ready, make paused reader the active one.
     *               3.1.1.2 If not, return WANT_READ.
     *         3.1.2 If not, fall back to the case 3.2
     *    3.2 If the paused reader is unset or we come from 3.1.2,
     *        setup active reader with new record contents and return it.
     *        Provide an accumulator if and only if the paused reader is unset
     *        and the record content type is pausable. If the option
     *        MPS_L2_ALLOW_PAUSABLE_CONTENT_TYPE_WITHOUT_ACCUMULATOR
     *        is unset, fail if the content type is pausable but the
     *        accumulator is not available.
     */

    /* 1 */
    if( ctx->in.active_state == MPS_L2_READER_STATE_EXTERNAL )
    {
        TRACE( trace_error, "A record is already open and has been passed to the user." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    /* 2 */
    if( ctx->in.active_state == MPS_L2_READER_STATE_INTERNAL )
    {
        TRACE( trace_comment, "A record is already open for reading." );
    }
    else
    {
        /* 3 */

        ret = l2_in_fetch_record( ctx, &rec );
        if( ret != 0 )
            RETURN( ret );

        /* 3.1 */
        /* TLS only */
        if( ctx->conf.mode == MPS_L2_MODE_STREAM               &&
            ctx->in.paused_state == MPS_L2_READER_STATE_PAUSED &&
            ctx->in.paused->type == rec.type )
        {
            TRACE( trace_comment, "A reader is being paused for the received record content type." );
            /* 3.1.1 */

            /* It is not possible to change the incoming epoch when
             * a reader is being paused, hence the epoch of the new
             * record must match. Double-check this nonetheless.
             *
             * NOTE: Potentially remove this check at some point. */
            if( ctx->in.paused->epoch != rec.epoch )
                RETURN( MPS_ERR_INTERNAL_ERROR );

            ret = mbedtls_reader_feed( &ctx->in.paused->rd,
                                       rec.buf.buf + rec.buf.data_offset,
                                       rec.buf.data_len );

            if( ret == MBEDTLS_ERR_READER_NEED_MORE )
            {
                /* 3.1.1.2 */
                ret = l2_in_release_record( ctx );
                if( ret != 0 )
                    RETURN( ret );

                RETURN( MPS_ERR_WANT_READ );
            }
            if( ret != 0 )
                RETURN( ret );

            /* 3.1.1.1 */
            ctx->in.paused_state = MPS_L2_READER_STATE_UNSET;
            tmp = ctx->in.active;
            ctx->in.active = ctx->in.paused;
            ctx->in.paused = tmp;
        }
        else
        /* End TLS only */
        {
            TRACE( trace_comment, "The received content type doesn't match any paused reader." );

            /* 3.1.2 & 3.2 */
            TRACE( trace_comment, "Setup active reader with record content (size %u)",
                   (unsigned) rec.buf.data_len );

            /* Determine whether we should provide an accumulator to the reader. */
            acc = NULL;
            acc_len = 0;
            if( l2_type_can_be_paused( ctx, rec.type ) )
            {
                TRACE( trace_comment, "Record content type can be paused" );
                if( ctx->in.paused_state == MPS_L2_READER_STATE_UNSET )
                {
                    TRACE( trace_comment, "The accumulator is available" );
                    acc = ctx->in.accumulator;
                    acc_len = ctx->in.acc_len;
                }
                else
#if !defined(MPS_L2_ALLOW_PAUSABLE_CONTENT_TYPE_WITHOUT_ACCUMULATOR)
                {
                    TRACE( trace_error,
                           "The accumulator is not available, and don't allow "
                           "to open pausable content types without accumulator." );
                    RETURN( MPS_ERR_MULTIPLE_PAUSING );
                }
#else
                {
                    TRACE( trace_comment, "No accumulator is available, but open nonetheless." );
                }
#endif
            }

            ret = mbedtls_reader_init( &ctx->in.active->rd, acc, acc_len );
            if( ret != 0 )
                RETURN( ret );

            ret = mbedtls_reader_feed( &ctx->in.active->rd,
                                       rec.buf.buf + rec.buf.data_offset,
                                       rec.buf.data_len );
            if( ret != 0 )
                RETURN( ret );

            ctx->in.active->type = rec.type;
            ctx->in.active->epoch = rec.epoch;
        }
    }

    /* Check if the record's epoch is a valid epoch for reading.
     *
     * NOTE: This check MUST even be performed when progressing from
     *       state INTERNAL to EXTERNAL, i.e. when continuing the reading
     *       of an already opened record.
     *       The reason is that there might be epoch
     *       changes between two handshake messages in TLS 1.3, and in
     *       this case the check guards against piggy-backing the next
     *       handshake message -- which should use the new epoch -- in
     *       the same record as the previous one. */

    ret = l2_epoch_check( ctx, ctx->in.active->epoch, MPS_EPOCH_READ );
    if( ret != 0 )
        RETURN( ret );

    in->type = ctx->in.active->type;
    in->epoch = ctx->in.active->epoch;
    in->rd = &ctx->in.active->rd;

    ctx->in.active_state = MPS_L2_READER_STATE_EXTERNAL;

    RETURN( 0 );
}

static int l2_in_release_record( mps_l2 *ctx )
{
    int ret;
    TRACE_INIT( "l2_in_release_record" );

    ret = mps_l1_consume( ctx->conf.l1 );
    if( ret != 0 )
        RETURN( ret );

    /* Increase incoming sequence number (TLS)
     * or update replay protection window (DTLS). */

    if( ctx->conf.mode == MPS_L2_MODE_STREAM )
    {
        if( ++ctx->in_ctr == 0 )
            RETURN( MPS_ERR_COUNTER_WRAP );

        TRACE( trace_comment, "new sequence number %u", (unsigned) ctx->in_ctr );
    }
    else
    {
        /* TODO */
    }

    RETURN( 0 );
}

static int l2_in_fetch_record( mps_l2 *ctx, mps_rec *rec )
{
    int ret;
    mbedtls_mps_transform_t *transform;
    TRACE_INIT( "l2_in_fetch_record" );

    /*
     * Remarks regarding record header parsing
     *
     * There are three major cases:
     * 1) TLS, all versions
     * 2) DTLS 1.0 and 1.2 (adds sequence number and epoch id)
     * 3) DTLS 1.3
     *    This is totally different and much more complicated
     *    than the other cases. The following has to be distinguished:
     *    3.1) Active epoch is 0
     *         Then a DTLSPlaintext header in the same format
     *         as for DTLS <= 1.2 is used.
     *    3.2) Active epoch is > 0
     *         Then a different format with TWO VARIANTS may be used:
     *         3.2.1) DTLSCiphertext
     *         3.3.3) DTLSShortCiphertext
     *         In both cases, the record header doesn't contain
     *         the epoch id and sequence number in full, but only
     *         some of their lower bits.
     *    We don't implement DTLS 1.3 record header parsing at the moment,
     *    as DTLS 1.3 is not yet very mature, but still it's worth being
     *    aware of the dependencies here: For DTLS 1.3, the record header
     *    parsing needs access to a) the current epoch, and b) the full list
     *    of valid epochs and sequence numbers seen so far.
     *    While this is certainly more than just the version field,
     *    it's comforting to note that this information is at least
     *    fully present on Layer 2. so in principle it should be possible
     *    to implement DTLS 1.3 record header parsing as part of Layer 2.
     *
     * In any case, what record header parsing should return in *all* cases
     * is a synthetic record header structure containing the following data:
     * - Record content type
     * - Record length
     * - Version
     * - DTLS: Epoch
     * - DTLS: Record sequence number
     *
     */

    /*
     * Step 1: Read protected record
     */

    ret = l2_in_fetch_protected_record( ctx, rec );
    if( ret != 0 )
    {
        TRACE( trace_comment, "l2_in_fetch_protected_record failed with %d", ret );
        RETURN( ret );
    }

    /*
     * Step 2: Decrypt and authenticate record
     */

    TRACE( trace_comment, "lookup epoch %u", (unsigned) rec->epoch );
    ret = l2_epoch_table_lookup( ctx, rec->epoch, NULL, &transform );
    if( ret != 0 )
    {
        TRACE( trace_comment, "epoch %u lookup failed with %d",
               (unsigned) rec->epoch, ret );
        RETURN( ret );
    }

    TRACE( trace_comment, "decrypt record, transform %p", transform );
    ret = transform_decrypt( transform, rec );
    if( ret != 0 )
    {
        TRACE( trace_comment, "record decryption failed with %d (=-%04x)", ret, -ret );
        RETURN( ret );
    }
    TRACE( trace_comment, "decryption done" );

    /* Validate plaintext length */
    if( rec->buf.data_len > ctx->conf.max_plain_in )
    {
        /* TODO: Release the record */
        RETURN( MPS_ERR_INVALID_RECORD_LENGTH );
    }

    /*
     * Step 3 ([D]TLS 1.3 only): Unpack TLSInnerPlaintext
     * TODO
     */

    RETURN( 0 );
}

static int l2_in_fetch_protected_record( mps_l2 *ctx, mps_rec *rec )
{
    TRACE_INIT( "l2_in_fetch_protected_record" );
    if( ctx->conf.mode == MPS_L2_MODE_STREAM )
    {
        /* The record header structure is the same for all versions
         * of TLS, including TLS 1.3. The only difference is that in
         * TLS 1.3, the record payload needs to be post-processed to
         * remove the plaintext padding.
         * Note padding is treated entirely separatedly from encryption
         * and authentication, while for the use of CBC in earlier versions,
         * it was part of CBC, and AEAD didn't allow padding at all. */
        RETURN( l2_in_fetch_protected_record_tls( ctx, rec ) );
    }

    if( ctx->conf.mode == MPS_L2_MODE_DATAGRAM )
    {
        /* Only handle DTLS 1.0 and 1.2 for the moment,
         * which have a uniform and simple record header. */
        switch( ctx->conf.version )
        {
            case MBEDTLS_SSL_MINOR_VERSION_2: /* DTLS 1.0 */
            case MBEDTLS_SSL_MINOR_VERSION_3: /* DTLS 1.2 */
                RETURN( l2_in_fetch_protected_record_dtls12( ctx, rec ) );

            /* At some point, add DTLS 1.3 here */

        }
    }

    /* Should never happen */
    RETURN( MPS_ERR_INTERNAL_ERROR );
}

static size_t l2_get_header_len( mps_l2 *ctx, mbedtls_mps_epoch_id epoch )
{
    ((void) epoch);
    TRACE_INIT( "l2_get_header_len, %d", epoch );

    if( ctx->conf.mode == MPS_L2_MODE_STREAM )
    {
        RETURN( 5 );
    }

    if( ctx->conf.mode == MPS_L2_MODE_DATAGRAM )
    {
        /* Only handle DTLS 1.0 and 1.2 for the moment,
         * which have a uniform and simple record header. */
        switch( ctx->conf.version )
        {
            case MBEDTLS_SSL_MINOR_VERSION_2: /* DTLS 1.0 */
            case MBEDTLS_SSL_MINOR_VERSION_3: /* DTLS 1.2 */
                RETURN( 13 );

            /* At some point, add DTLS 1.3 here */

        }
    }

    /* Should never happen */
    RETURN( MPS_ERR_INTERNAL_ERROR );
}

static int l2_in_fetch_protected_record_tls( mps_l2 *ctx, mps_rec *rec )
{
    unsigned char *buf; /* Buffer to hold the header, from layer 1 */
    int minor_ver, major_ver;
    uint8_t type;
    uint16_t len;
    int ret;

    TRACE_INIT( "l2_in_fetch_protected_record_tls" );

    /* Header structure is the same for all TLS versions.

       From RFC 5246 - Section 6.2

       struct {
          uint8 major;
          uint8 minor;
       } ProtocolVersion;

       enum {
          change_cipher_spec(20), alert(21), handshake(22),
          application_data(23), (255)
       } ContentType;

       struct {
          ContentType type;
          ProtocolVersion version;
          uint16 length;
          opaque fragment[TLSPlaintext.length];
       } TLSPlaintext;

    */

    /*
     * Read header from layer 1
     */

    ret = mps_l1_fetch( ctx->conf.l1, &buf, 5 );
    if( ret != 0 )
        RETURN( ret );

    /*
     * Validate header fields
     */

    /* Length */
    len = ( buf[3] << 8 ) + buf[4];
    /* TODO: Add length check, at least the architectural bound of 16384 + 2K,
     *       but preferably a transform-dependent bound that'll catch records
     *       with overly long plaintext by considering the maximum expansion
     *       plaintext-to-ciphertext. */

    /* Version */
    l2_read_version( &major_ver, &minor_ver,
                     MBEDTLS_SSL_TRANSPORT_STREAM, &buf[1] );
    if( major_ver != MBEDTLS_SSL_MAJOR_VERSION_3 )
        RETURN( MPS_ERR_INVALID_RECORD_VERSION );
    if( ctx->conf.version != MPS_L2_VERSION_UNSPECIFIED &&
        ctx->conf.version != minor_ver )
        RETURN( MPS_ERR_INVALID_RECORD_VERSION );

    /* Type */
    type = buf[0];
    if( l2_type_is_valid( ctx, type ) == 0 )
    {
        TRACE( trace_error, "Invalid record type received" );
        RETURN( MPS_ERR_INVALID_RECORD_TYPE );
    }

    /*
     * Read record contents from layer 1
     */
    ret = mps_l1_fetch( ctx->conf.l1, &buf, 5 + len );
    if( ret != 0 )
        RETURN( ret );

    /*
     * Write target record structure
     */
    rec->ctr = ctx->in_ctr;
    rec->epoch = ctx->epochs.tls.default_in;
    rec->type = type;
    rec->major_ver = major_ver;
    rec->minor_ver = minor_ver;
    rec->buf.buf = buf + 5;
    rec->buf.buf_len = len;
    rec->buf.data_len = len;
    rec->buf.data_offset = 0;
    RETURN( 0 );
}

static int l2_in_fetch_protected_record_dtls12( mps_l2 *ctx, mps_rec *rec )
{
    int ret;
    unsigned char *hdr; /* Buffer to hold the header, from layer 1 */

    /* For epoch validation */
    uint16_t epoch;
    mbedtls_mps_transform_t *epoch_transform;

    size_t pre_exp, post_exp;

    /* For record content type validation */
    uint8_t type;

    /* For length validation */
    uint16_t len;

    TRACE_INIT( "l2_in_fetch_protected_record_dtls12" );

    /* Steps:
     * 1. Fetch header from layer 1
     * 2. Validate header fields
     * 2. Copy header fields to record structure
     */

    /* Header structure the same for DTLS 1.0 and DTLS 1.2 */
    /* From RFC 6347 - Section 4.1

      struct {
           ContentType type;
           ProtocolVersion version;
           uint16 epoch;                                    // New field
           uint48 sequence_number;                          // New field
           uint16 length;
           opaque fragment[DTLSPlaintext.length];
         } DTLSPlaintext;

    */

    /*
     * 1. Obtain header from Layer 1
     */

    ret = mps_l1_fetch( ctx->conf.l1, &hdr, 13 );
    if( ret != 0 )
        RETURN( ret );

    /*
     * 2. Validate header fields
     */

    /* Validate epoch */
    epoch = ( hdr[3] << 8 ) + hdr[4];

    ret = l2_epoch_table_lookup( ctx, epoch, NULL, &epoch_transform );
    if( ret != 0 )
        RETURN( ret );

    /* Validate ciphertext length. */
    len = ( hdr[11] << 8 ) + hdr[12];
    transform_get_expansion( epoch_transform, &pre_exp, &post_exp );
    if( len > ctx->conf.max_plain_in + pre_exp + post_exp )
    {
        RETURN( MPS_ERR_INVALID_RECORD_LENGTH );
    }

    /* Validate version */
    if( ctx->conf.mode == MPS_L2_MODE_DATAGRAM )
    {
        /* Check major version */
        if( hdr[1] != TLS_MAJOR_VER_DTLS )
            RETURN( MPS_ERR_INVALID_RECORD_VERSION );

        /* Check minor version, but only if version has
         * already been specified. This is important to
         * let through initial records at a stage where
         * the protocol version has not yet been negotiated. */

        /* TODO */
    }
    else
    if( ctx->conf.mode == MPS_L2_MODE_STREAM )
    {
        /* Check major version */
        if( hdr[1] != TLS_MAJOR_VER_TLS )
            RETURN( MPS_ERR_INVALID_RECORD_VERSION );

        /* Check minor version */

        /* TODO */
    }

    /* Validate content type */
    type = hdr[0];
    if( type >= 64 )
        RETURN( MPS_ERR_INVALID_RECORD_TYPE );

    if( l2_type_is_valid( ctx, type ) == 1 )
        RETURN( MPS_ERR_INVALID_RECORD_TYPE );

    /* Validate record sequence number (replay check) */
    /* TODO */

    /*
     * 3. Fill record struct
     */

    rec->type   = hdr[0];
    rec->major_ver = hdr[1];
    rec->minor_ver = hdr[2];
    len = rec->buf.buf_len;

    /* TODO: Write counter */

    RETURN( 0 );
}

static int l2_type_can_be_paused( mps_l2 *ctx, uint8_t type )
{
    return( ( ctx->conf.pause_flag & ( 1u << type ) ) != 0 );
}

static int l2_type_can_be_merged( mps_l2 *ctx, uint8_t type )
{
    return( ( ctx->conf.merge_flag & ( 1u << type ) ) != 0 );
}

static int l2_type_is_valid( mps_l2 *ctx, uint8_t type )
{
    return( type < 64 && ( ctx->conf.type_flag & ( 1u << type ) ) != 0 );
}

static int l2_type_empty_allowed( mps_l2 *ctx, uint8_t type )
{
    return( ( type < 64 ) &&
            ( ctx->conf.empty_flag & ( ( (uint64_t) 1u ) << type ) ) != 0 );
}

static int l2_epoch_check( mps_l2 *ctx, mbedtls_mps_epoch_id epoch,
                           uint8_t purpose )
{
    int ret;
    uint8_t epoch_offset;
    uint8_t epoch_usage;

    TRACE_INIT( "l2_epoch_check for epoch %d, purpose %u",
           epoch, (unsigned) purpose );

    ret = l2_epoch_table_lookup( ctx, epoch, &epoch_offset, NULL );
    if( ret != 0 )
        RETURN( ret );

    if( ctx->conf.mode == MPS_L2_MODE_DATAGRAM )
    {
        epoch_usage = ctx->epochs.dtls.state[ epoch_offset ];
        /* TODO: MPS_EPOCH_VALID is only referenced here.
         *       What do we need / use it for? */
        if( ( MPS_EPOCH_VALID & epoch_usage ) == 0 ||
            ( purpose & epoch_usage ) != purpose )
        {
            TRACE( trace_comment, "epoch usage not allowed" );
            RETURN( MPS_ERR_INVALID_RECORD_EPOCH );
        }
    }
    else
    {
        if( purpose == MPS_EPOCH_READ &&
            ctx->epochs.tls.default_in != epoch )
        {
            TRACE( trace_comment, "epoch not the default incoming one" );
            RETURN( MPS_ERR_INVALID_RECORD_EPOCH );
        }

        if( purpose == MPS_EPOCH_WRITE &&
            ctx->epochs.tls.default_out != epoch )
        {
            TRACE( trace_comment, "epoch not the default outgoing one" );
            RETURN( MPS_ERR_INVALID_RECORD_EPOCH );
        }
    }

    RETURN( 0 );
}

static int l2_epoch_cleanup( mps_l2 *ctx )
{
    uint8_t shift, id;
    mbedtls_mps_epoch_id max_shift;

    TRACE_INIT( "l2_epoch_cleanup" );

    if( ctx->conf.mode == MPS_L2_MODE_STREAM )
    {
        /* TLS */
        /* An epoch is in use if it's either the default incoming
         * or the default outgoing epoch, or if there is outgoing
         * data queued on that epoch.
         */
        mbedtls_mps_epoch_id queued_epoch = MPS_EPOCH_NONE;
        if( ctx->out.state == MPS_L2_WRITER_STATE_QUEUEING )
        {
            queued_epoch = ctx->out.writer.epoch;
            TRACE( trace_comment, "Epoch %u still has data pending to be delivered -> Don't clean up",
                   (unsigned) queued_epoch );
        }

        for( id = 0; id < MPS_L2_EPOCH_WINDOW_SIZE; id++ )
        {
            mbedtls_mps_epoch_id epoch = ctx->epoch_base + id;
            if( ctx->transforms[id] != NULL &&
                epoch != ctx->epochs.tls.default_in  &&
                epoch != ctx->epochs.tls.default_out &&
                epoch != queued_epoch )
            {
                TRACE( trace_comment, "Epoch %d (offset %u, base %d, transform %p) is no longer needed -> Cleanup",
                       ctx->epoch_base + id,
                       (unsigned) ( id ), ctx->epoch_base,
                       ctx->transforms[id] );
                transform_free( ctx->transforms[id] );
                free( ctx->transforms[id] );
                ctx->transforms[id] = NULL;
            }
            else
            {
                if( epoch == ctx->epochs.tls.default_in )
                    TRACE( trace_comment, "Epoch %d is the current incoming epoch",
                           epoch );
                if( epoch == ctx->epochs.tls.default_out )
                    TRACE( trace_comment, "Epoch %d is the current outgoing epoch",
                           epoch );
                if( epoch == queued_epoch )
                    TRACE( trace_comment, "Epoch %d still has queued data pending to be delivered",
                           epoch );

                break;
            }
        }
    }
    else
    {
        /* DTLS */
        /* An epoch is in use if it's flags are not empty.
         * There is no queueing of outgoing data in DTLS. */
        for( id = 0; id < MPS_L2_EPOCH_WINDOW_SIZE; id++ )
        {
            if( ctx->epochs.dtls.state[id] == 0 )
            {
                TRACE( trace_comment, "epoch %u (off %u, base %u, p %p) no longer needed!",
                       (unsigned) ( ctx->epoch_base + id ),
                       (unsigned) ( id ), (unsigned) ( ctx->epoch_base ),
                       ctx->transforms[id] );
                transform_free( ctx->transforms[ id ] );
                free( ctx->transforms[id] );
                ctx->transforms[id] = NULL;
            }
            else
            {
                break;
            }
        }
    }

    /* Shift the epoch window if it has unset epochs in the beginning. */
    for( shift = 0; shift < MPS_L2_EPOCH_WINDOW_SIZE &&
                    ctx->transforms[shift] == NULL; shift++ );

    if( shift == 0 )
    {
        TRACE( trace_comment, "Cannot get rid of any epoch." );
        RETURN( 0 );
    }

    max_shift = MPS_L2_LIMIT_EPOCH -
        ( ctx->epoch_base + MPS_L2_EPOCH_WINDOW_SIZE );
    if( shift >= max_shift )
    {
        TRACE( trace_comment, "Cannot shift epoch window further." );
        shift = max_shift;
    }

    TRACE( trace_comment, "Can get rid of the first %u epochs; clearing.", (unsigned) shift );
    ctx->epoch_base += shift;

    for( id = 0; id < MPS_L2_EPOCH_WINDOW_SIZE; id++ )
    {
        if( MPS_L2_EPOCH_WINDOW_SIZE - id > shift )
            ctx->transforms[id] = ctx->transforms[id + shift];
        else
            ctx->transforms[id] = NULL;

        TRACE( trace_comment, "New transform address at offset %u: %p",
               (unsigned) id, ctx->transforms[id] );

    }

    TRACE( trace_comment, "Epoch cleanup done" );
    RETURN( 0 );
}

static int l2_epoch_table_lookup( mps_l2 *ctx, mbedtls_mps_epoch_id epoch,
                                  uint8_t *offset,
                                  mbedtls_mps_transform_t **transform )
{
    uint8_t epoch_offset;
    TRACE_INIT( "l2_epoch_lookup" );
    TRACE( trace_comment, "* Epoch:  %d", epoch );

    if( epoch == MPS_EPOCH_NONE )
    {
        TRACE( trace_comment, "The epoch is unset." );
        RETURN( MPS_ERR_INVALID_RECORD_EPOCH );
    }
    else if( epoch < ctx->epoch_base )
    {
        TRACE( trace_comment, "The epoch is below the epoch base." );
        RETURN( MPS_ERR_INVALID_RECORD_EPOCH );
    }

    epoch_offset = epoch - ctx->epoch_base;
    TRACE( trace_comment, "* Offset: %u", (unsigned) epoch_offset );

    if( epoch_offset >= MPS_L2_EPOCH_WINDOW_SIZE )
    {
        TRACE( trace_error, "The epoch is outside the epoch window." );
        RETURN( MPS_ERR_EPOCH_WINDOW_EXCEEDED );
    }

    if( transform != NULL )
        *transform = ctx->transforms[ epoch_offset ];

    if( offset != NULL )
        *offset = epoch_offset;

    RETURN( 0 );
}
