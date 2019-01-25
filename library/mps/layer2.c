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

#if defined(MBEDTLS_MPS_SEPARATE_LAYERS) ||     \
    defined(MBEDTLS_MPS_TOP_TRANSLATION_UNIT)

#if defined(MBEDTLS_MPS_TRACE)
static int trace_id = TRACE_BIT_LAYER_2;
#endif /* MBEDTLS_MPS_TRACE */

#include <stdlib.h>
#include <string.h>

static void l2_out_write_version( int major, int minor,
                                  mbedtls_mps_transport_type transport,
                                  unsigned char ver[2] );
static void l2_read_version( int *major, int *minor,
                             mbedtls_mps_transport_type transport,
                             const unsigned char ver[2] );

/* Reading related */
static int l2_in_fetch_record( mbedtls_mps_l2 *ctx, mps_rec *rec );
static int l2_in_fetch_protected_record( mbedtls_mps_l2 *ctx, mps_rec *rec );
#if defined(MBEDTLS_MPS_PROTO_TLS)
static int l2_in_fetch_protected_record_tls( mbedtls_mps_l2 *ctx,
                                             mps_rec *rec );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
static int l2_in_fetch_protected_record_dtls12( mbedtls_mps_l2 *ctx,
                                                mps_rec *rec );
static int l2_handle_invalid_record( mbedtls_mps_l2 *ctx, int ret );
#endif /* MBEDTLS_MPS_PROTO_DTLS */
static int l2_in_release_record( mbedtls_mps_l2 *ctx );

/* Writing related */
static int l2_out_prepare_record( mbedtls_mps_l2 *ctx,
                                  mbedtls_mps_epoch_id epoch );
static int l2_out_track_record( mbedtls_mps_l2 *ctx );
static int l2_out_release_record( mbedtls_mps_l2 *ctx, uint8_t force );
static int l2_out_dispatch_record( mbedtls_mps_l2 *ctx );
static int l2_out_write_protected_record( mbedtls_mps_l2 *ctx, mps_rec *rec );
#if defined(MBEDTLS_MPS_PROTO_TLS)
static int l2_out_write_protected_record_tls( mbedtls_mps_l2 *ctx,
                                              mps_rec *rec );
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
static int l2_out_write_protected_record_dtls12( mbedtls_mps_l2 *ctx,
                                                 mps_rec *rec );
#endif /* MBEDTLS_MPS_PROTO_DTLS */
static int l2_out_release_and_dispatch( mbedtls_mps_l2 *ctx, uint8_t force );
static int l2_out_clear_pending( mbedtls_mps_l2 *ctx );

static size_t l2_get_header_len( mbedtls_mps_l2 *ctx,
                                 mbedtls_mps_epoch_id epoch );

/* Configuration related */
/* OPTIMIZATION: The flexibility of Layer 2 in terms of valid types,
 *               pausing, merging, and the acceptance of empty records
 *               is nice for testing, but on a low-profile production build
 *               targeted at a specific version of [D]TLS, code can be saved
 *               by implementing the l2_type_can_be_yyy() functions in a
 *               static way (comparing against a mask / list of types fixed
 *               at compile-time). */
#if defined(MBEDTLS_MPS_PROTO_TLS)
static int l2_type_can_be_paused( mbedtls_mps_l2 *ctx,
                                  mbedtls_mps_msg_type_t type );
#endif /* MBEDTLS_MPS_PROTO_TLS */
static int l2_type_can_be_merged( mbedtls_mps_l2 *ctx,
                                  mbedtls_mps_msg_type_t type );
static int l2_type_is_valid( mbedtls_mps_l2 *ctx,
                             mbedtls_mps_msg_type_t type );
static int l2_type_empty_allowed( mbedtls_mps_l2 *ctx,
                                  mbedtls_mps_msg_type_t type );

/*
 * Epoch handling
 */

static void l2_epoch_free( mbedtls_mps_l2_epoch_t *epoch );
static void l2_epoch_init( mbedtls_mps_l2_epoch_t *epoch );

/* Check if an epoch can be used for a given purpose. */
static int l2_epoch_check( mbedtls_mps_l2 *ctx,
                           mbedtls_mps_epoch_id epoch,
                           uint8_t purpose );

/* Lookup the transform associated to an epoch.
 *
 * The epoch ID is fully untrusted (this function is called
 * as part of replay protection for not yet authenticated
 * records).
 */
static int l2_epoch_lookup( mbedtls_mps_l2 *ctx,
                            mbedtls_mps_epoch_id epoch_id,
                            mbedtls_mps_l2_epoch_t **epoch );

/* Check if some epochs are no longer needed and can be removed. */
static int l2_epoch_cleanup( mbedtls_mps_l2 *ctx );

/* Check if removal of the read-permission for an epoch
 * is possible and prepare for it. */
static int l2_epoch_check_remove_read( mbedtls_mps_l2 *ctx,
                                       mbedtls_mps_epoch_id epoch );

/* Check if removal of the write-permission for an epoch
 * is possible and prepare for it. */
static int l2_epoch_check_remove_write( mbedtls_mps_l2 *ctx,
                                        mbedtls_mps_epoch_id epoch );

static int l2_epoch_lookup_internal( mbedtls_mps_l2 *ctx,
                                     mbedtls_mps_epoch_id epoch_id,
                                     uint8_t *offset,
                                     mbedtls_mps_l2_epoch_t **transform );

/*
 * Sequence number handling
 */

#if defined(MBEDTLS_MPS_PROTO_TLS)
static int l2_tls_in_get_epoch_and_counter( mbedtls_mps_l2 *ctx,
                                            uint16_t *dst_epoch,
                                            uint64_t *dst_ctr );
#endif /* MBEDTLS_MPS_PROTO_TLS */

static int l2_in_update_counter( mbedtls_mps_l2 *ctx,
                                 uint16_t epoch,
                                 uint32_t ctr_hi,
                                 uint32_t ctr_lo );

static int l2_out_get_and_update_rec_seq( mbedtls_mps_l2 *ctx,
                                          uint16_t epoch_id,
                                          uint32_t *dst_ctr );

/*
 * DTLS replay protection
 */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
static int l2_counter_replay_check( mbedtls_mps_l2 *ctx,
                                    mbedtls_mps_epoch_id epoch,
                                    uint32_t ctr_hi,
                                    uint32_t ctr_lo );
#endif /* MBEDTLS_MPS_PROTO_DTLS */

static void l2_out_write_version( int major, int minor,
                                  mbedtls_mps_transport_type transport,
                                  unsigned char ver[2] )
{
#if !defined(MBEDTLS_MPS_PROTO_BOTH)
    ((void) transport);
#endif

    /* The goal of this guard-salad is to not include any mode checks in case
     * only one of TLS or DTLS is enabled.
     * The present solution, however, is not very readable, and I'd be glad
     * about suggestions on how to improve this. */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( transport ) )
    {
        if( minor == MBEDTLS_SSL_MINOR_VERSION_2 )
            --minor; /* DTLS 1.0 stored as TLS 1.1 internally */

        ver[0] = (unsigned char)( 255 - ( major - 2 ) );
        ver[1] = (unsigned char)( 255 - ( minor - 1 ) );
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( transport ) )
    {
        ver[0] = (unsigned char) major;
        ver[1] = (unsigned char) minor;
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */
}

static void l2_read_version( int *major, int *minor,
                             mbedtls_mps_transport_type transport,
                             const unsigned char ver[2] )
{
#if !defined(MBEDTLS_MPS_PROTO_BOTH)
    ((void) transport);
#endif

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( transport ) )
    {
        *major = 255 - ver[0] + 2;
        *minor = 255 - ver[1] + 1;

        if( *minor == MBEDTLS_SSL_MINOR_VERSION_1 )
            ++*minor; /* DTLS 1.0 stored as TLS 1.1 internally */
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( transport ) )
    {
        *major = ver[0];
        *minor = ver[1];
    }
#endif
}

static void mps_l2_readers_init( mbedtls_mps_l2 *ctx )
{
    ctx->in.active.state = MBEDTLS_MPS_L2_READER_STATE_UNSET;
    mbedtls_reader_init( &ctx->in.active.rd, NULL, 0 );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    ctx->in.paused.state = MBEDTLS_MPS_L2_READER_STATE_UNSET;
    mbedtls_reader_init( &ctx->in.paused.rd, NULL, 0 );
#endif /* MBEDTLS_MPS_PROTO_TLS */
}

static void mps_l2_readers_free( mbedtls_mps_l2 *ctx )
{
    ctx->in.active.state = MBEDTLS_MPS_L2_READER_STATE_UNSET;
    mbedtls_reader_free( &ctx->in.active.rd );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    ctx->in.paused.state = MBEDTLS_MPS_L2_READER_STATE_UNSET;
    mbedtls_reader_free( &ctx->in.paused.rd );
#endif /* MBEDTLS_MPS_PROTO_TLS */
}

static int mps_l2_readers_close_active( mbedtls_mps_l2 *ctx )
{
    mbedtls_reader_free( &ctx->in.active.rd );
    ctx->in.active.state = MBEDTLS_MPS_L2_READER_STATE_UNSET;
    return( 0 );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
static int mps_l2_readers_pause_active( mbedtls_mps_l2 *ctx )
{
    mbedtls_mps_l2_in_internal tmp;

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
    if( ctx->in.paused.state != MBEDTLS_MPS_L2_READER_STATE_UNSET )
        return( MPS_ERR_INTERNAL_ERROR );

    tmp = ctx->in.active;
    ctx->in.active = ctx->in.paused;
    ctx->in.paused = tmp;

    ctx->in.active.state = MBEDTLS_MPS_L2_READER_STATE_UNSET;
    ctx->in.paused.state = MBEDTLS_MPS_L2_READER_STATE_PAUSED;

    return( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

static mbedtls_mps_l2_reader_state mps_l2_readers_active_state(
    mbedtls_mps_l2 *ctx )
{
    return( ctx->in.active.state );
}

static mbedtls_mps_l2_in_internal* mps_l2_readers_get_active(
    mbedtls_mps_l2 *ctx )
{
    return( &ctx->in.active );
}

static inline void mps_l2_readers_update( mbedtls_mps_l2 *ctx )
{
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        ((void) ctx);
        return;
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        /* Swap active and paused reader if the paused
         * reader has been activated. */
        if( ctx->in.paused.state == MBEDTLS_MPS_L2_READER_STATE_INTERNAL )
        {
            mbedtls_mps_l2_in_internal tmp = ctx->in.active;
            ctx->in.active = ctx->in.paused;
            ctx->in.paused = tmp;
        }
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
static inline mbedtls_mps_l2_in_internal *mps_l2_find_paused_slot(
    mbedtls_mps_l2 *ctx, mbedtls_mps_msg_type_t type )
{
    if( ctx->in.paused.state == MBEDTLS_MPS_L2_READER_STATE_PAUSED )
    {
        if( ctx->in.paused.type == type )
            return( &ctx->in.paused );
    }
    return( NULL );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

static inline mbedtls_mps_l2_in_internal *mps_l2_setup_free_slot(
    mbedtls_mps_l2 *ctx, mbedtls_mps_msg_type_t type,
    mbedtls_mps_epoch_id epoch )
{
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    /* This assumes that there is no active slot. Hence, in case
     * of DTLS, we can statically return the address of the single
     * available slot. */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        mbedtls_reader_init( &ctx->in.active.rd, NULL, 0 );
        ctx->in.active.type = type;
        ctx->in.active.epoch = epoch;
        return( &ctx->in.active );
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        unsigned char *acc = NULL;
        mbedtls_mps_size_t acc_len = 0;

        if( l2_type_can_be_paused( ctx, type ) )
        {
            TRACE( trace_comment, "Record content type can be paused" );
            if( ctx->in.paused.state == MBEDTLS_MPS_L2_READER_STATE_UNSET )
            {
                TRACE( trace_comment, "The accumulator (size %u) is available",
                       (unsigned) ctx->in.acc_len );
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
        }
#endif /* MPS_L2_ALLOW_PAUSABLE_CONTENT_TYPE_WITHOUT_ACCUMULATOR */

        mbedtls_reader_init( &ctx->in.active.rd, acc, acc_len );
        ctx->in.active.type = type;
        ctx->in.active.epoch = epoch;
        return( &ctx->in.active );
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

    return( NULL );
}

int mps_l2_init( mbedtls_mps_l2 *ctx, mps_l1 *l1,
                 mbedtls_mps_transport_type mode,
                 size_t max_read, size_t max_write,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng )
{
    /* TODO: Make this more compact; zeroize the Layer 2
     *       structure first and then only correct those
     *       fields where 0 is not proper initialization. */

#if defined(MBEDTLS_MPS_PROTO_TLS)
    unsigned char *queue = NULL, *accumulator = NULL;
#endif /* MBEDTLS_MPS_PROTO_TLS */

    mps_l2_bufpair zero_bufpair = { NULL, 0, 0, 0 };
    TRACE_INIT( "l2_init" );

#if defined(MBEDTLS_MPS_PROTO_TLS)
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
#else
    ((void) max_read);
    ((void) max_write);
#endif /* MBEDTLS_MPS_PROTO_TLS */

    ctx->conf.l1 = l1;
    ctx->conf.mode = mode;

    /* TODO: Allow setting an arbitrary version,
     *       as well as an initially unspecified one. */
    ctx->conf.version = MBEDTLS_SSL_MINOR_VERSION_3;
    ctx->conf.type_flag = 0;
    ctx->conf.merge_flag = 0;
#if defined(MBEDTLS_MPS_PROTO_TLS)
    ctx->conf.pause_flag = 0;
#endif /* MBEDTLS_MPS_PROTO_TLS */
    ctx->conf.empty_flag = 0;
    ctx->conf.max_plain_out = 1000;
    ctx->conf.max_plain_in  = 1000;
    ctx->conf.max_cipher_in = 1000;
    ctx->conf.f_rng = f_rng;
    ctx->conf.p_rng = p_rng;
    ctx->conf.badmac_limit = 0;

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    ctx->conf.anti_replay = MBEDTLS_MPS_ANTI_REPLAY_ENABLED;
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    /* Initialize write-side */
    ctx->out.flush    = 0;
    ctx->out.clearing = 0;
    ctx->out.state = MBEDTLS_MPS_L2_WRITER_STATE_UNSET;
#if defined(MBEDTLS_MPS_PROTO_TLS)
    ctx->out.queue = queue;
    ctx->out.queue_len = max_write;
#endif /* MBEDTLS_MPS_PROTO_TLS */

    ctx->out.hdr = NULL;
    ctx->out.hdr_len = 0;
    ctx->out.payload = zero_bufpair;

    ctx->out.writer.type = MBEDTLS_MPS_MSG_NONE;
    ctx->out.writer.epoch = MBEDTLS_MPS_EPOCH_NONE;
    mbedtls_writer_init( &ctx->out.writer.wr, NULL, 0 );

    /* Initialize read-side */
#if defined(MBEDTLS_MPS_PROTO_TLS)
    ctx->in.accumulator = accumulator;
    ctx->in.acc_len = max_read;
#endif /* MBEDTLS_MPS_PROTO_TLS */
    mps_l2_readers_init( ctx );

    ctx->in.bad_mac_ctr = 0;

    /* Initialize epochs */

    memset( &ctx->epochs, 0, sizeof( ctx->epochs ) );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        ctx->epochs.permissions.tls.default_in  = MBEDTLS_MPS_EPOCH_NONE;
        ctx->epochs.permissions.tls.default_out = MBEDTLS_MPS_EPOCH_NONE;
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

    RETURN( 0 );
}

int mps_l2_free( mbedtls_mps_l2 *ctx )
{
    size_t offset;
    ((void) ctx);
    TRACE_INIT( "l2_free" );

    mps_l2_readers_free( ctx );
    mbedtls_writer_free( &ctx->out.writer.wr );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    free( ctx->in.accumulator );
    free( ctx->out.queue );

    ctx->in.accumulator = NULL;
    ctx->in.acc_len = 0;
    ctx->out.queue = NULL;
    ctx->out.queue_len = 0;
#endif /* MBDTLS_MPS_PROTO_TLS */

    for( offset = 0; offset < MPS_L2_EPOCH_WINDOW_SIZE; offset++ )
        l2_epoch_free( &ctx->epochs.window[offset] );

    RETURN( 0 );
}

int mps_l2_config_version( mbedtls_mps_l2 *ctx, uint8_t ver )
{
    TRACE_INIT( "mps_l2_config_version: %u", (unsigned) ver );
    /* TODO: Add check */
    ctx->conf.version = ver;
    RETURN( 0 );
}

/* Please consult the documentation of mbedtls_mps_l2 for a basic
 * description of the state flow when preparing outgoing records.
 *
 * This function assumes that no outgoing record is currently being processed
 * and prepares L1-owned buffers holding the record header and record plaintext.
 * The latter is subsequently fed to the user-facing writer object (not done
 * in this function). */
static int l2_out_prepare_record( mbedtls_mps_l2 *ctx,
                                  mbedtls_mps_epoch_id epoch_id )
{
    int ret;
    uint8_t overflow; /* Helper variable to detect arithmetic overflow. */

    unsigned char *rec_buf; /* The buffer received from Layer 1
                             * to which we write the record.       */
    size_t total_sz;        /* The total size of rec_buf in bytes. */
    size_t hdr_len;         /* The length of the record header.    */
    size_t pre_expansion;   /* The amount of data (in bytes) that
                             * the transform protecting the record
                             * adds in front of the plaintext.     */
    size_t post_expansion;  /* The amount of data (in bytes) that
                             * the transform protecting the record
                             * adds beyond the plaintext.          */

    mbedtls_mps_l2_epoch_t *epoch;

    TRACE_INIT( "l2_out_prepare, epoch %d", epoch_id );

    /* Request buffer from Layer 1 to hold entire record. */
    ret = mps_l1_write( ctx->conf.l1, &rec_buf, &total_sz );
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

    hdr_len = l2_get_header_len( ctx, epoch_id );

    ret = l2_epoch_lookup( ctx, epoch_id, &epoch );
    if( ret != 0 )
        RETURN( ret );

    transform_get_expansion( epoch->transform,
                             &pre_expansion,
                             &post_expansion );

    /* Check for overflow */
    overflow = 0;
    overflow |= ( hdr_len + pre_expansion < hdr_len );
    overflow |= ( ( hdr_len + pre_expansion ) + post_expansion <
                    hdr_len + pre_expansion );
    if( overflow )
    {
        TRACE( trace_comment, "INTERNAL ERROR on pre- and postexpansion, len %u, pre-expansion %u, post-expansion %u",
               (unsigned) hdr_len, (unsigned) pre_expansion, (unsigned) post_expansion );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    /* Check if buffer obtained from Layer 1 is large enough to accomodate
     * at least a protected record with plaintext length 1. */
    if( hdr_len + pre_expansion + post_expansion >= total_sz )
    {
        size_t bytes_pending;
        TRACE( trace_comment, "Not enough space for to hold a non-empty record." );
        TRACE( trace_comment, "Need at least %u ( %u header + %u pre-expansion + %u post-expansion + 1 plaintext ) byte, but have only %u bytes available.",
               (unsigned)( hdr_len + pre_expansion + post_expansion + 1 ),
               (unsigned) hdr_len,
               (unsigned) pre_expansion,
               (unsigned) post_expansion,
               (unsigned) total_sz );

        /* Abort the write and remember to flush before the next write. */
        mps_l1_dispatch( ctx->conf.l1, 0 /* Abort := Dispatch nothing */,
                         &bytes_pending );
        ctx->out.clearing = 1;

        /* OPTIMIZATION: This is an assertion. Consider moving
         *               it to debug-only modes. */
        if( bytes_pending == 0 )
        {
            /* If Layer 1 has no bytes pending but doesn't have enough space
             * to allow a record of size 1 to be sent, something must be
             * ill-configured. */
            TRACE( trace_error, "Layer 1 doesn't have any data pending to be written but cannot serve a buffer large enough to hold a non-empty record. Abort." );
            RETURN( MPS_ERR_BUFFER_TOO_SMALL );
        }

        RETURN( MPS_ERR_WANT_WRITE );
    }

    /* Dissect L1 record buffer into header, ciphertext and plaintext parts.
     * The plaintext sub-buffer can subsequently be fed to the writer which
     * then gets passed to the user, i.e. Layer 3. */

    ctx->out.hdr     = rec_buf;
    ctx->out.hdr_len = hdr_len;

    ctx->out.payload.buf     = rec_buf + hdr_len;
    ctx->out.payload.buf_len = total_sz - hdr_len;

    ctx->out.payload.data_offset = pre_expansion;
    ctx->out.payload.data_len    = total_sz -
        ( hdr_len + pre_expansion + post_expansion );

    TRACE( trace_comment, "New outgoing record successfully prepared." );
    TRACE( trace_comment, " * Max plaintext size: %u",
           (unsigned) ctx->out.payload.data_len );
    TRACE( trace_comment, " * Pre expansion:      %u",
           (unsigned) ctx->out.payload.data_offset );
    RETURN( 0 );
}

/* Please consult the documentation of mbedtls_mps_l2 for a basic description
 * of the state flow when preapring outgoing records.
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
static int l2_out_dispatch_record( mbedtls_mps_l2 *ctx )
{
    int ret;
    mps_rec rec;
    mbedtls_mps_l2_epoch_t *epoch;
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
        ret = mps_l1_dispatch( ctx->conf.l1, 0, NULL );
        if( ret != 0 )
            RETURN( ret );
    }
    else
    {
        /* Step 1: Prepare the record header structure. */

        /* TODO: Handle the case where the version hasn't been set yet! */

        rec.major_ver = MBEDTLS_SSL_MAJOR_VERSION_3;
        rec.minor_ver = ctx->conf.version;
        rec.buf       = ctx->out.payload;
        rec.epoch     = ctx->out.writer.epoch;
        rec.type      = ctx->out.writer.type;
        l2_out_get_and_update_rec_seq( ctx, rec.epoch, rec.ctr );

        TRACE( trace_comment, "Record header fields:" );
        TRACE( trace_comment, "* Sequence number: %u", (unsigned) rec.ctr   );
        TRACE( trace_comment, "* Epoch:           %u", (unsigned) rec.epoch );
        TRACE( trace_comment, "* Type:            %u", (unsigned) rec.type  );

        ret = l2_epoch_lookup( ctx, ctx->out.writer.epoch, &epoch );
        if( ret != 0 )
        {
            TRACE( trace_comment, "Epoch lookup failed" );
            RETURN( ret );
        }

        /* TLS-1.3-NOTE: Add TLSPlaintext header, incl. padding. */

        /* Step 2: Apply record payload protection. */
        TRACE( trace_comment, "Encrypt record. The plaintext offset is %u.",
               (unsigned) rec.buf.data_offset );
        ret = transform_encrypt( epoch->transform, &rec, ctx->conf.f_rng,
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

static int l2_out_write_protected_record( mbedtls_mps_l2 *ctx, mps_rec *rec )
{
    int ret = 0;
    mps_l2_bufpair const zero_bufpair = { NULL, 0, 0, 0 };
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type mode = ctx->conf.mode;
#endif

    TRACE_INIT( "Write protected record" );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
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
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        /* Only handle DTLS 1.0 and 1.2 for the moment,
         * which have a uniform and simple record header. */
        switch( ctx->conf.version )
        {
            case MBEDTLS_SSL_MINOR_VERSION_2: /* DTLS 1.0 */
            case MBEDTLS_SSL_MINOR_VERSION_3: /* DTLS 1.2 */
                ret = l2_out_write_protected_record_dtls12( ctx, rec );

            /* TLS-1.3-NOTE: Add DTLS-1.3 here */

        }
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    /* Cleanup internal structure for outgoing data. */
    ctx->out.hdr = NULL;
    ctx->out.hdr_len = 0;
    ctx->out.payload = zero_bufpair;

    RETURN( ret );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
static int l2_out_write_protected_record_tls( mbedtls_mps_l2 *ctx, mps_rec *rec )
{
    uint8_t * const hdr     = ctx->out.hdr;
    size_t    const hdr_len = ctx->out.hdr_len;

    size_t const tls_rec_hdr_len = 5;

    const size_t tls_rec_type_offset = 0;
    const size_t tls_rec_ver_offset  = 1;
    const size_t tls_rec_len_offset  = 3;

    TRACE_INIT( "l2_write_protected_record_tls" );

    /* Double-check that we have calculated the header length
     * correctly when preparing the outgoing record.
     * This should always be true, but better err on the safe side. */
    if( hdr_len != tls_rec_hdr_len )
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

    /* Write record content type. */
    MPS_WRITE_UINT8_LE( &rec->type, hdr + tls_rec_type_offset );

    /* Write record version. */
    l2_out_write_version( rec->major_ver,
                          rec->minor_ver,
                          MBEDTLS_MPS_MODE_STREAM,
                          hdr + tls_rec_ver_offset );

    /* Write ciphertext length. */
    MPS_WRITE_UINT16_LE( &rec->buf.data_len, hdr + tls_rec_len_offset );

    TRACE( trace_comment, "Write protected record -- DISPATCH" );
    RETURN( mps_l1_dispatch( ctx->conf.l1, hdr_len + rec->buf.data_len,
                             NULL ) );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
static int l2_out_write_protected_record_dtls12( mbedtls_mps_l2 *ctx,
                                                 mps_rec *rec )
{
    uint8_t * const hdr     = ctx->out.hdr;
    size_t    const hdr_len = ctx->out.hdr_len;

    /* Header structure the same for DTLS 1.0 and DTLS 1.2.

       From RFC 6347 - Section 4.1

       struct {
            ContentType type;
            ProtocolVersion version;
            uint16 epoch;
            uint48 sequence_number;
            uint16 length;
            opaque fragment[DTLSPlaintext.length];
          } DTLSPlaintext;

    */

    size_t const dtls_rec_hdr_len      = 13;

    size_t const dtls_rec_type_offset  = 0;
    size_t const dtls_rec_ver_offset   = 1;
    size_t const dtls_rec_epoch_offset = 3;
    size_t const dtls_rec_seq_offset   = 5;
    size_t const dtls_rec_len_offset   = 11;

    TRACE_INIT( "l2_write_protected_record_dtls12" );

    /* Double-check that we have calculated the header length
     * correctly when preparing the outgoing record.
     * This should always be true, but better err on the safe side. */
    if( hdr_len != dtls_rec_hdr_len )
        RETURN( MPS_ERR_INTERNAL_ERROR );

    /* Write record content type. */
    MPS_WRITE_UINT8_LE( &rec->type, hdr + dtls_rec_type_offset );

    /* Write record version. */
    l2_out_write_version( rec->major_ver,
                          rec->minor_ver,
                          MBEDTLS_MPS_MODE_DATAGRAM,
                          hdr + dtls_rec_ver_offset );

    /* Epoch */
    MPS_WRITE_UINT16_LE( &rec->epoch, hdr + dtls_rec_epoch_offset );

    /* Record sequence number */
    MPS_WRITE_UINT16_LE( &rec->ctr[0], hdr + dtls_rec_seq_offset );
    MPS_WRITE_UINT32_LE( &rec->ctr[1], hdr + dtls_rec_seq_offset + 2 );

    /* Write ciphertext length. */
    MPS_WRITE_UINT16_LE( &rec->buf.data_len, hdr + dtls_rec_len_offset );

    TRACE( trace_comment, "Write protected record -- DISPATCH" );
    RETURN( mps_l1_dispatch( ctx->conf.l1, hdr_len + rec->buf.data_len,
                             NULL ) );
}
#endif /* MBEDTLS_MPS_PROTO_DTLS */

int mps_l2_write_flush( mbedtls_mps_l2 *ctx )
{
    TRACE_INIT( "mps_l2_write_flush, state %u", ctx->out.state );

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( ctx->out.state == MBEDTLS_MPS_L2_WRITER_STATE_EXTERNAL )
    {
        TRACE( trace_error, "Unexpected operation" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    ctx->out.flush = 1;
    RETURN( l2_out_clear_pending( ctx ) );
}

/* See the documentation of `clearing` and `flush` in layer2.h
 * for more information on the flow of this routine. */
static int l2_out_clear_pending( mbedtls_mps_l2 *ctx )
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

#if defined(MBEDTLS_MPS_PROTO_TLS)
    /* Each iteration strictly reduces the size of the
     * writer's queue, hence the loop must terminate. */
    while( ctx->out.state == MBEDTLS_MPS_L2_WRITER_STATE_QUEUEING )
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
#endif /* MBEDTLS_MPS_PROTO_TLS */

    TRACE( trace_comment, "Queue clear" );

    if( ctx->out.flush == 1 )
    {
        TRACE( trace_comment, "A flush was requested requested, state %u",
               (unsigned) ctx->out.state );
        if( ctx->out.state == MBEDTLS_MPS_L2_WRITER_STATE_INTERNAL )
        {
            ret = l2_out_release_and_dispatch( ctx,
                                               MBEDTLS_WRITER_RECLAIM_FORCE );
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

int mps_l2_write_start( mbedtls_mps_l2 *ctx, mps_l2_out *out )
{
    int ret;
    uint8_t desired_type;
    mbedtls_mps_epoch_id desired_epoch;

    TRACE_INIT( "mps_l2_write_start" );

    /* We must not attempt to write multiple records simultaneously.
     * If this happens, the layer most likely forgot to dispatch
     * the last outgoing record. */
#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( ctx->out.state == MBEDTLS_MPS_L2_WRITER_STATE_EXTERNAL )
    {
        TRACE( trace_error, "Unexpected operation" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    /* Check if the requested record content type is valid. */
    /* OPTIMIZATION: This is an assertion; consider moving
     *               it to debug-only builds. */
    desired_type = out->type;
    if( l2_type_is_valid( ctx, desired_type ) == 0 )
    {
        TRACE( trace_error, "Message type %d is invalid", desired_type );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    /* Check if the requested epoch is valid for writing. */
    desired_epoch = out->epoch;
    ret = l2_epoch_check( ctx, desired_epoch, MPS_EPOCH_WRITE );
    if( ret != 0 )
        RETURN( ret );

    /* Make sure that no data is queueing for dispatching, and that
     * all dispatched data has been delivered by Layer 1 in case
     * a flush has been requested.
     * Please consult the documentation of ::mps_l2 for further information. */
    ret = l2_out_clear_pending( ctx );
    if( ret != 0 )
    {
        TRACE( trace_comment, "l2_out_clear_pending failed with %d", ret );
        RETURN( ret );
    }

    /* If l2_out_clear_pending() succeeds, it guarantees that the
     * write state is not MBEDTLS_MPS_L2_WRITER_STATE_QUEUEING anymore.
     * Hence, it's either INTERNAL or UNSET. */

    /*
     * If an outgoing record has already been prepared but not yet dispatched,
     * append to it in case both the requested type and the epoch match.
     *
     * If they don't match, the current record must be dispatched first before
     * a new one can be prepared with the requested type and epoch.
     */
    if( ctx->out.state == MBEDTLS_MPS_L2_WRITER_STATE_INTERNAL )
    {
        if( ctx->out.writer.type  == desired_type &&
            ctx->out.writer.epoch == desired_epoch )
        {
            TRACE( trace_comment,
                   "Type and epoch match currently open record -> attach." );
            ctx->out.state = MBEDTLS_MPS_L2_WRITER_STATE_EXTERNAL;
            out->wr = &ctx->out.writer.wr;

            TRACE( trace_comment, "* Total size of record buffer: %u Bytes",
                   (unsigned) out->wr->out_len );
            TRACE( trace_comment, "* Committed: %u Bytes",
                   (unsigned) out->wr->committed );
            TRACE( trace_comment, "* Written: %u Bytes",
                   (unsigned) out->wr->end );
            TRACE( trace_comment, "* Remaining: %u Bytes",
                   (unsigned) ( out->wr->out_len - out->wr->committed ) );
            RETURN( 0 );
        }

        TRACE( trace_comment, "Type or epoch doesn't match open record." );
        ret = l2_out_release_and_dispatch( ctx, MBEDTLS_WRITER_RECLAIM_FORCE );
        if( ret != 0 )
            RETURN( ret );

        /* The old record has been dispatched by now, and we fall through
         * to open a new one for the requested type and epoch. */
    }

    /* State must be MBEDTLS_MPS_L2_WRITER_STATE_UNSET when we reach this. */

    /* Prepare raw buffers from Layer 1 to hold the new record. */
    ret = l2_out_prepare_record( ctx, desired_epoch );
    if( ret != 0 )
        RETURN( ret );

    ctx->out.writer.type  = desired_type;
    ctx->out.writer.epoch = desired_epoch;

    /* Bind buffers to the writer passed to the user. */
    ret = l2_out_track_record( ctx );
    if( ret != 0 )
        RETURN( ret );

    ctx->out.state = MBEDTLS_MPS_L2_WRITER_STATE_EXTERNAL;
    out->wr = &ctx->out.writer.wr;
    RETURN( 0 );
}

int mps_l2_write_done( mbedtls_mps_l2 *ctx )
{
    int ret;
    TRACE_INIT( "l2_write_done" );

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( ctx->out.state != MBEDTLS_MPS_L2_WRITER_STATE_EXTERNAL )
    {
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    ctx->out.state = MBEDTLS_MPS_L2_WRITER_STATE_INTERNAL;

    ret = l2_out_release_and_dispatch( ctx, MBEDTLS_WRITER_RECLAIM_NO_FORCE );
    if( ret != 0 )
        RETURN( ret );

    RETURN( 0 );
}

static int l2_out_track_record( mbedtls_mps_l2 *ctx )
{
    int ret;
    TRACE_INIT( "l2_out_track_record" );

    if( ctx->out.state == MBEDTLS_MPS_L2_WRITER_STATE_UNSET )
    {
#if defined(MBEDTLS_MPS_PROTO_TLS)
        /* Depending on whether the record content type is pausable,
         * provide a queue to the writer or not. */
        if( l2_type_can_be_paused( ctx, ctx->out.writer.type ) )
        {
            mbedtls_writer_init( &ctx->out.writer.wr,
                                 ctx->out.queue,
                                 ctx->out.queue_len );
        }
        else
#endif /* MBEDTLS_MPS_PROTO_TLS */
        {
            mbedtls_writer_init( &ctx->out.writer.wr, NULL, 0 );
        }
    }

    ret = mbedtls_writer_feed( &ctx->out.writer.wr,
                        ctx->out.payload.buf + ctx->out.payload.data_offset,
                        ctx->out.payload.data_len );
    if( ret != 0 )
    {
        TRACE( trace_error, "mbedtls_writer_feed failed with %d", ret );
        RETURN( ret );
    }

    ctx->out.state = MBEDTLS_MPS_L2_WRITER_STATE_INTERNAL;
    RETURN( 0 );
}

static int l2_out_release_record( mbedtls_mps_l2 *ctx, uint8_t force )
{
    int ret;
    mbedtls_mps_size_t bytes_written, bytes_queued;
    mbedtls_mps_msg_type_t type;
    TRACE_INIT( "l2_out_release_record, force %u, state %u", force,
           (unsigned) ctx->out.state );

    ret = mbedtls_writer_reclaim( &ctx->out.writer.wr, &bytes_written,
                                  &bytes_queued, force );
    if( force == MBEDTLS_WRITER_RECLAIM_NO_FORCE &&
        ret   == MBEDTLS_ERR_WRITER_DATA_LEFT )
    {
        TRACE( trace_comment, "There's space left in the current outgoing record." );
        type = ctx->out.writer.type;

        /* Check if records of the given type may be merged.
         * E.g., in [D]TLS 1.3 multiple multiple alerts must not
         * be placed in a single record. */
        if( l2_type_can_be_merged( ctx, type ) == 1 )
        {
            TRACE( trace_comment, "Multiple messages of type %u can be merged in a single record.", (unsigned) type );
            /* Here's the place to add a heuristic deciding when to dispatch
             * a record even if space is left in the output buffer. For TLS,
             * in principle we can go on with as little as a single byte, but
             * at least for DTLS a minimum should be fixed. */

            if( /* HEURISTIC */ 1 )
            {
                TRACE( trace_comment, "Postpone dispatching to potentially merge further messages into this record." );
                RETURN( MBEDTLS_ERR_WRITER_DATA_LEFT );
            }

            TRACE( trace_comment, "Not enough space remaining to wait for another message oftype %u - dispatch.", (unsigned) type );

            /* Fall through if heuristic determines that the current record
             * should be dispatched albeit spacing being left: fall through */
        }

        TRACE( trace_comment, "Messages of type %u can either not be merged, or there's not enough space remaining in the current record -- force reclaim.", (unsigned) type );
        ret = mbedtls_writer_reclaim( &ctx->out.writer.wr, NULL, NULL,
                                      MBEDTLS_WRITER_RECLAIM_FORCE );
        if( ret != 0 )
            RETURN( ret );
    }
    else if( ret != 0 )
        RETURN( ret );

    /* Now it's clear that the record should be dispatched */

#if defined(MBEDTLS_MPS_PROTO_TLS)
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

        ctx->out.state = MBEDTLS_MPS_L2_WRITER_STATE_QUEUEING;
    }
    else
#endif /* MBEDTLS_MPS_PROTO_TLS */
    {
        /* No data has been queued */
        TRACE( trace_comment, "The writer has no queued data." );

        /* The writer is no longer needed. */
        mbedtls_writer_free( &ctx->out.writer.wr );

        ctx->out.state = MBEDTLS_MPS_L2_WRITER_STATE_UNSET;
    }

    /* Update internal length field and change the writer state. */
    ctx->out.payload.data_len = bytes_written;
    RETURN( 0 );
}

static int l2_out_release_and_dispatch( mbedtls_mps_l2 *ctx, uint8_t force )
{
    int ret;
    TRACE_INIT( "l2_out_release_and_dispatch, force %u", force );

    /* Attempt to detach the underlying record write-buffer from the writer.
     * This fails if there is sufficient space left in the buffer. */
    ret = l2_out_release_record( ctx, force );
    if( ret != 0 && ret != MBEDTLS_ERR_WRITER_DATA_LEFT )
        RETURN( ret );

    if( ret == 0 )
    {
        /* The write-buffer is detached from the writer, hence
         * can be dispatched to Layer 1. */
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

int mps_l2_read_done( mbedtls_mps_l2 *ctx )
{
    int ret;
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    mbedtls_mps_l2_in_internal * active;
#if defined(MBEDTLS_MPS_PROTO_TLS)
    mbedtls_mps_size_t paused;
    mbedtls_mps_size_t * const paused_ptr = &paused;
#else
    mbedtls_mps_size_t * const paused_ptr = NULL;
#endif /* MBEDTLS_MPS_PROTO_TLS */

    TRACE_INIT( "mps_l2_read_done" );

    /* This only makes sense if the active reader is currently
     * on the user-side, i.e. 'external'. Everything else is
     * a violation of the API. */

#if defined(MBEDTLS_MPS_STATE_VALIDATION)
    if( mps_l2_readers_active_state( ctx )
        != MBEDTLS_MPS_L2_READER_STATE_EXTERNAL )
    {
        TRACE( trace_comment, "Unexpected operation" );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_STATE_VALIDATION */

    /*
     * Layer 1 has provided the record the contents of which the
     * reader manages, so the order of freeing the resources is:
     * First retract the reader's access to the buffer, then
     * mark it as complete to Layer 1 (retracting our own access).
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
     *   2.2 If yes (TLS only): Swap active and paused reader, and return
     *               success. In this case, when we read a new record of
     *               matching content type, we'll feed its contents into
     *               the paused reader until the reader becomes ready to
     *               be reactivated, and then it'll be made active again.
     */


    active = mps_l2_readers_get_active( ctx );
    ret = mbedtls_reader_reclaim( &active->rd, paused_ptr );
    if( ret == MBEDTLS_ERR_READER_DATA_LEFT )
    {
        /* 1a */
        TRACE( trace_comment, "There is data remaining in the current incoming record." );

        /* Check if the content type is configured to allow packing of
         * multiple chunks of data in the same record. */
        if( l2_type_can_be_merged( ctx, active->type ) == 0 )
        {
            TRACE( trace_error, "Record content type %u does not allow multiple reads from the same record.",
                   (unsigned) active->type );
            RETURN( MPS_ERR_INVALID_CONTENT_MERGE );
        }

        active->state = MBEDTLS_MPS_L2_READER_STATE_INTERNAL;
        RETURN( 0 );
    }
    else
#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) &&
        ( ret == MBEDTLS_ERR_READER_NEED_ACCUMULATOR      ||
          ret == MBEDTLS_ERR_READER_ACCUMULATOR_TOO_SMALL ) )
    {
        /* 1b */
        if( l2_type_can_be_paused( ctx, active->type ) == 1 )
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
    else
#endif /* MBEDTLS_MPS_PROTO_TLS */
    if( ret != 0 )
        RETURN( ret );

    /* 2 */

    TRACE( trace_comment, "Detached record buffer from reader - release record from Layer 1." );
    ret = l2_in_release_record( ctx );
    if( ret != 0 )
        RETURN( ret );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( paused == 0 )
#endif /* MBEDTLS_MPS_PROTO_TLS */
    {
        /* 2.1 */
        TRACE( trace_comment, "No pausing - close active reader." );
        RETURN( mps_l2_readers_close_active( ctx ) );
    }

#if defined(MBEDTLS_MPS_PROTO_TLS)
    /* 2.2 (TLS only) */
    TRACE( trace_comment, "Pause active reader." );
    RETURN( mps_l2_readers_pause_active( ctx ) );
#endif /* MBEDTLS_MPS_PROTO_TLS */
}

#if defined(MBEDTLS_MPS_PROTO_DTLS)
static int l2_handle_invalid_record( mbedtls_mps_l2 *ctx, int ret )
{
    /* This function assumes that the mode has been checked
     * to be MBEDTLS_MPS_MODE_DATAGRAM and hence omits this check here. */

    TRACE_INIT( "mps_l2_handle_invalid_record" );
    if( ret == MPS_ERR_INVALID_RECORD )
    {
        TRACE( trace_error, "Record with invalid header received -- discard" );
    }
    else if( ret == MPS_ERR_REPLAYED_RECORD )
    {
        TRACE( trace_error, "Record caught by replay protection -- discard" );
    }
    else /* ret == MPS_ERR_INVALID_MAC */
    {
        TRACE( trace_error, "Record with invalid MAC received -- discard" );
        ctx->in.bad_mac_ctr++;
        if( ctx->conf.badmac_limit != 0 &&
            ctx->in.bad_mac_ctr >= ctx->conf.badmac_limit )
        {
            TRACE( trace_error, "Bad-MAC-limit %u reached.",
                   (unsigned) ctx->conf.badmac_limit );
            RETURN( MPS_ERR_INVALID_MAC );
        }
    }

    /* Silently discard datagrams containing invalid records. */
    RETURN( mps_l1_skip( ctx->conf.l1 ) );
}
#endif /* MBEDTLS_MPS_PROTO_DTLS */

int mps_l2_read_start( mbedtls_mps_l2 *ctx, mps_l2_in *in )
{
    int ret;
    mbedtls_mps_l2_reader_state current_state;
    mbedtls_mps_l2_in_internal *active;
    TRACE_INIT( "mps_l2_read_start" );

    /*
     * Outline:
     * 1 If the active reader is set and external, fail with an internal error.
     * 2 If instead the active reader is set and internal (i.e. a record has
     *   been opened but not yet fully processed), ensure the its epoch is still
     *   valid and make it external in this case.
     * 3 If the active reader is unset, attempt to fetch and decrypt
     *   a new record from L1. If it succeeds:
     *   3.1 (TLS only) Check if there is a paused reader for the incoming
     *       content type and epoch.
     *        3.1.1 If yes, feed the new record content into the paused reader.
     *              3.1.1.1 If enough data is ready, activate reader and return.
     *              3.1.1.2 If not, keep the reader paused and return WANT_READ.
     *        3.1.2 If not, fall back to the case 3.2
     *   3.2 If the paused reader is unset or we come from 3.1.2,
     *       setup active reader with new record contents and return it.
     *       Provide an accumulator if and only if the paused reader is unset
     *       and the record content type is pausable. If the option
     *       MPS_L2_ALLOW_PAUSABLE_CONTENT_TYPE_WITHOUT_ACCUMULATOR
     *       is unset, fail if the content type is pausable but the
     *       accumulator is not available.
     */

    current_state = mps_l2_readers_active_state( ctx );

    /* 1 */
    if( current_state == MBEDTLS_MPS_L2_READER_STATE_EXTERNAL )
    {
        TRACE( trace_error, "A record is already open and has been passed to the user." );
        RETURN( MPS_ERR_INTERNAL_ERROR );
    }

    /* 2 */
    if( current_state == MBEDTLS_MPS_L2_READER_STATE_INTERNAL )
    {
        TRACE( trace_comment, "A record is already open for reading." );
    }
    else
    {
        /* 3 */

#if defined(MBEDTLS_MPS_PROTO_BOTH)
        mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

        /* The slot we attempt to use to store payload from the new record. */
        mbedtls_mps_l2_in_internal *slot = NULL;
        mps_rec rec;

        ret = l2_in_fetch_record( ctx, &rec );

        /* For DTLS, silently discard datagrams containing records
         * which have an invalid header field or can't be authenticated. */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
        if( MBEDTLS_MPS_IS_DTLS( mode ) &&
            ( ret == MPS_ERR_REPLAYED_RECORD ||
              ret == MPS_ERR_INVALID_RECORD  ||
              ret == MPS_ERR_INVALID_MAC ) )
        {
            ret = l2_handle_invalid_record( ctx, ret );
            if( ret != 0 )
                RETURN( ret );

            TRACE( trace_comment, "Signal that the processing should be retried." );
            /* It is OK to return #MPS_ERR_WANT_READ here because we have
             * discarded the entire underlying datagram, hence progress can
             * only be made once another datagram is available.
             *
             * NOTE: If Layer 1 ever buffers more than one datagram,
             *       this needs to be reconsidered. */
            RETURN( MPS_ERR_WANT_READ );
        }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

        /* TLS-1.3-NOTE
         * If the server does not support EarlyData is must silently
         * ignore the early ApplicationData records that the client
         * sends.
         *
         * This needs the following adaptions to the code:
         * - There should be a dynamically configurable option
         *   to silently discard unauthenticated records.
         * - If this option is set and if l2_in_fetch_record()
         *   returns INVALID_MAC, we should not forward this error
         *   here but instead call l2_release_record() and return
         *   MPS_ERR_CONTINUE_PROCESSING.
         */

        if( ret != 0 )
            RETURN( ret );

        /*
         * Update record sequence numbers and replay protection.
         */

        ret = l2_in_update_counter( ctx, rec.epoch, rec.ctr[0], rec.ctr[1] );
        if( ret != 0 )
            RETURN( ret );

        /*
         * Check if the record is empty, and if yes,
         * if empty records are allowed for the given content type.
         */

        if( rec.buf.data_len == 0 )
        {
            TRACE( trace_comment, "Record is empty" );
            if( l2_type_empty_allowed( ctx, rec.type ) == 0 )
            {
                /* As for other kinds of invalid records in DTLS,
                 * ignore the entire datagram. */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
                if( MBEDTLS_MPS_IS_DTLS( mode ) )
                {
                    if( ( ret = mps_l1_skip( ctx->conf.l1 ) ) != 0 )
                        RETURN( ret );

                    /* NOTE: As above, if Layer 1 ever buffers more than
                     *       one datagram, returning #MPS_ERR_WANT_READ
                     *       here needs to be reconsidered. */
                    RETURN( MPS_ERR_WANT_READ );
                }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

                RETURN( MPS_ERR_INVALID_RECORD );
            }
        }

        /* 3.1 */
        /* Attempt to attach to a paused reader. */
#if defined(MBEDTLS_MPS_PROTO_TLS)
        if( MBEDTLS_MPS_IS_TLS( mode ) )
        {
            slot = mps_l2_find_paused_slot( ctx, rec.type );
            if( slot != NULL )
            {
                /* 3.1.1 */
                TRACE( trace_comment, "A reader is being paused for the received record content type." );

                /* It is not possible to change the incoming epoch when
                 * a reader is being paused, hence the epoch of the new
                 * record must match. Double-check this nonetheless.
                 *
                 * NOTE: Potentially remove this check at some point. */
                if( ctx->in.paused.epoch != rec.epoch )
                {
                    TRACE( trace_error, "The paused epoch doesn't match the incoming epoch." );
                    RETURN( MPS_ERR_INTERNAL_ERROR );
                }
            }
        }
#endif /* MBEDTLS_MPS_PROTO_TLS */

        /* In case of DTLS, this is always true, and the compiler
         * should be able to eliminate this (test?). */
        if( slot == NULL )
        {
            /* 3.2 */
            /* Feed the payload into a fresh reader. */
            slot = mps_l2_setup_free_slot( ctx, rec.type, rec.epoch );
            if( slot == NULL )
            {
                /* This should never happen with the current implementation,
                 * but it might if we switch the TLS implementation to use
                 * a single pausable slot only. In the latter case, we'd reach
                 * the present code-path in case of interleaving of records of
                 * different content types. */
                TRACE( trace_error, "No free slot available to store incoming record payload." );
                RETURN( MPS_ERR_INTERNAL_ERROR );
            }
        }

        /* 3.1.1 and 3.2 */
        /* Feed record payload into target slot; might be either
         * a fresh or a matching paused slot. */
        ret = mbedtls_reader_feed( &slot->rd,
                                   rec.buf.buf + rec.buf.data_offset,
                                   rec.buf.data_len );
#if defined(MBEDTLS_MPS_PROTO_TLS)
        if( MBEDTLS_MPS_IS_TLS( mode ) &&
            ret == MBEDTLS_ERR_READER_NEED_MORE )
        {
            /* 3.1.1.2 */
            ret = l2_in_release_record( ctx );
            if( ret != 0 )
                RETURN( ret );

            /* It is OK to return #MPS_ERR_WANT_READ here because the
             * present code-path is TLS-only, and in TLS we never
             * internally buffer more than one record. As we're done
             * with the current record, progress can only be made if
             * the underlying transport signals more incoming data
             * available, which is precisely what #MPS_ERR_WANT_READ
             * indicates.
             *
             * NOTE: If Layer 1 ever changes to request and buffer more
             *       data than what we asked for, this needs to be
             *       reconsidered.
             */
            RETURN( MPS_ERR_WANT_READ );
        }
        else
#endif /* MBEDTLS_MPS_PROTO_TLS */
        if( ret != 0 )
            RETURN( ret );

        /* 3.1.1.1 or 3.2 */
        slot->state = MBEDTLS_MPS_L2_READER_STATE_INTERNAL;
        mps_l2_readers_update( ctx );
    }

    /* If we end up here, there's data available to be returned to
     * the caller: It might be more data from an old incoming record
     * that hasn't been fully read yet, or data from a newly fetched
     * record. */

    active = mps_l2_readers_get_active( ctx );

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

    ret = l2_epoch_check( ctx, active->epoch, MPS_EPOCH_READ );
    if( ret != 0 )
        RETURN( ret );

    in->type  = active->type;
    in->epoch = active->epoch;
    in->rd    = &active->rd;

    active->state = MBEDTLS_MPS_L2_READER_STATE_EXTERNAL;
    RETURN( 0 );
}

static int l2_in_release_record( mbedtls_mps_l2 *ctx )
{
    int ret;
    TRACE_INIT( "l2_in_release_record" );

    ret = mps_l1_consume( ctx->conf.l1 );
    if( ret != 0 )
        RETURN( ret );

    RETURN( 0 );
}

static int l2_in_fetch_record( mbedtls_mps_l2 *ctx, mps_rec *rec )
{
    int ret;
    mbedtls_mps_l2_epoch_t *epoch;

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
     *    fully present on Layer 2, so in principle it should be possible
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

    if( ( ret = l2_in_fetch_protected_record( ctx, rec ) ) != 0 )
        RETURN( ret );

    /*
     * Step 2: Decrypt and authenticate record
     */

    TRACE( trace_comment, "lookup epoch %u", (unsigned) rec->epoch );
    if( ( ret = l2_epoch_lookup( ctx, rec->epoch,
                                 &epoch ) ) != 0 )
    {
        RETURN( ret );
    }

    TRACE( trace_comment, "Decrypt record" );
    ret = transform_decrypt( epoch->transform, rec );
    if( ret != 0 )
    {
        TRACE( trace_comment, "Decryption failed with: %d", (int) ret );
        RETURN( ret );
    }

    /* Validate plaintext length */
    if( rec->buf.data_len > ctx->conf.max_plain_in )
    {
        /* TODO: Release the record */
        RETURN( MPS_ERR_INVALID_RECORD );
    }

    /*
     * TLS-1.3-NOTE
     * Step 3: Unpack TLSInnerPlaintext
     */

    RETURN( 0 );
}

static int l2_in_fetch_protected_record( mbedtls_mps_l2 *ctx, mps_rec *rec )
{
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    TRACE_INIT( "l2_in_fetch_protected_record" );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
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
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        /* Only handle DTLS 1.0 and 1.2 for the moment,
         * which have a uniform and simple record header. */
        switch( ctx->conf.version )
        {
            case MBEDTLS_SSL_MINOR_VERSION_2: /* DTLS 1.0 */
            case MBEDTLS_SSL_MINOR_VERSION_3: /* DTLS 1.2 */
                RETURN( l2_in_fetch_protected_record_dtls12( ctx, rec ) );

            /* TLS-1.3-NOTE: At some point, add DTLS 1.3 here */
        }
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    /* Should never happen */
    RETURN( MPS_ERR_INTERNAL_ERROR );
}

static size_t l2_get_header_len( mbedtls_mps_l2 *ctx, mbedtls_mps_epoch_id epoch )
{
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    size_t const dtls12_rec_hdr_len = 13;
#endif /* MBEDTLS_MPS_PROTO_DTLS */
#if defined(MBEDTLS_MPS_PROTO_TLS)
    size_t const  tls12_rec_hdr_len  = 5;
#endif /* MBEDTLS_MPS_PROTO_TLS */

    ((void) epoch);
    TRACE_INIT( "l2_get_header_len, %d", epoch );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        RETURN( tls12_rec_hdr_len );
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */
#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        /* OPTIMIZATION:
         * As long as we're only supporting DTLS 1.0 and 1.2
         * which share the same record header, remove this
         * switch to save a few bytes? */

        /* Only handle DTLS 1.0 and 1.2 for the moment,
         * which have a uniform and simple record header. */
        switch( ctx->conf.version )
        {
            case MBEDTLS_SSL_MINOR_VERSION_2: /* DTLS 1.0 */
            case MBEDTLS_SSL_MINOR_VERSION_3: /* DTLS 1.2 */
                RETURN( dtls12_rec_hdr_len );

            default:
                TRACE( trace_error, "Invalid DTLS version %u -- expected DTLS 1.0 (%u) or DTLS 1.2 (%u)",
                       (unsigned) ctx->conf.version,
                       MBEDTLS_SSL_MINOR_VERSION_2,
                       MBEDTLS_SSL_MINOR_VERSION_3 );
            /* TLS-1.3-NOTE: At some point, add DTLS 1.3 here */
        }
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    /* Should never happen */
    RETURN( MPS_ERR_INTERNAL_ERROR );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
static int l2_in_fetch_protected_record_tls( mbedtls_mps_l2 *ctx, mps_rec *rec )
{
    int ret;

    /* Buffer to hold the record header; will be obtained from Layer 1 */
    unsigned char *buf;

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

    const size_t tls_rec_hdr_len     = 5;

    const size_t tls_rec_type_offset = 0;
    const size_t tls_rec_ver_offset  = 1;
    const size_t tls_rec_len_offset  = 3;

    /* Record fields */
    int minor_ver, major_ver;
    mbedtls_mps_msg_type_t type;
    uint16_t len;

    TRACE_INIT( "l2_in_fetch_protected_record_tls" );

    /*
     * Fetch TLS record header from Layer 1
     */

    ret = mps_l1_fetch( ctx->conf.l1, &buf, tls_rec_hdr_len );
    if( ret != 0 )
        RETURN( ret );

    /*
     * Read and validate header fields
     */

    /* Record content type */
    MPS_READ_UINT8_LE( buf + tls_rec_type_offset, &type );
    if( l2_type_is_valid( ctx, type ) == 0 )
    {
        TRACE( trace_error, "Invalid record type received" );
        RETURN( MPS_ERR_INVALID_RECORD );
    }

    /* Version */
    l2_read_version( &major_ver, &minor_ver,
                     MBEDTLS_MPS_MODE_STREAM,
                     buf + tls_rec_ver_offset );

    if( major_ver != MBEDTLS_SSL_MAJOR_VERSION_3 )
    {
        TRACE( trace_error, "Invalid major record version %u received, expected %u",
               (unsigned) major_ver, MBEDTLS_SSL_MAJOR_VERSION_3 );
        RETURN( MPS_ERR_INVALID_RECORD );
    }

    /* Initially, the server doesn't know which DTLS version
     * the client will use for its ClientHello message, so
     * Layer 2 must be configurable to allow arbitrary TLS
     * versions. This is done through the initial version
     * value MPS_L2_VERSION_UNSPECIFIED. */
    if( ctx->conf.version != MPS_L2_VERSION_UNSPECIFIED &&
        ctx->conf.version != minor_ver )
    {
        TRACE( trace_error, "Invalid minor record version %u received, expected %u",
               (unsigned) minor_ver, ctx->conf.version );
        RETURN( MPS_ERR_INVALID_RECORD );
    }

    /* Length */
    MPS_READ_UINT16_LE( buf + tls_rec_len_offset, &len );
    /* TODO: Add length check, at least the architectural bound of 16384 + 2K,
     *       but preferably a transform-dependent bound that'll catch records
     *       with overly long plaintext by considering the maximum expansion
     *       plaintext-to-ciphertext. */

    /*
     * Read record contents from Layer 1
     */
    ret = mps_l1_fetch( ctx->conf.l1, &buf,
                        tls_rec_hdr_len + len );
    if( ret != 0 )
        RETURN( ret );

    /*
     * Write target record structure
     */

    /* For TLS-1.3, we must not increment the in_ctr here
     * because (in contrast to prior versions of TLS), records
     * may be silently dismissed on authentication failure,
     * and in this case the record sequence number should stay
     * unmodified.
     *
     * Instead, postpone updating the incoming record sequence
     * number to the point where the record has been successfully
     * authenticated.
     */

    ret = l2_tls_in_get_epoch_and_counter( ctx, &rec->epoch, &rec->ctr );
    if( ret != 0 )
        RETURN( ret );

    TRACE( trace_comment, "* Record epoch:  %u", (unsigned) rec->epoch );
    TRACE( trace_comment, "* Record number: %u", (unsigned) rec->ctr );

    rec->type      = type;
    rec->major_ver = major_ver;
    rec->minor_ver = minor_ver;

    rec->buf.buf         = buf + tls_rec_hdr_len;
    rec->buf.buf_len     = len;
    rec->buf.data_offset = 0;
    rec->buf.data_len    = len;

    RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

static int l2_in_update_counter( mbedtls_mps_l2 *ctx,
                                 uint16_t epoch_id,
                                 uint32_t ctr_hi,
                                 uint32_t ctr_lo )
{
    int ret;
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif
    mbedtls_mps_l2_epoch_t *epoch;

    ret = l2_epoch_lookup( ctx, epoch_id, &epoch );
    if( ret != 0 )
        return( ret );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        epoch->stats.tls.in_ctr = ctr + 1;
        if( epoch->stats.tls.in_ctr == 0 )
            return( MPS_ERR_COUNTER_WRAP );
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        epoch->stats.dtls.last_seen[0] = ctr_hi;
        epoch->stats.dtls.last_seen[1] = ctr_lo;
        if( ctx->conf.anti_replay == MBEDTLS_MPS_ANTI_REPLAY_ENABLED )
        {
            uint32_t window_top_hi, window_top_lo;
            uint32_t window;
            uint32_t flag = 1u;

            window_top_hi = epoch->stats.dtls.replay.in_window_top_hi;
            window_top_lo = epoch->stats.dtls.replay.in_window_top_lo;
            window     = epoch->stats.dtls.replay.in_window;

            if( ctr_hi > window_top_hi )
            {
                window_top_hi = ctr_hi;
                window_top_lo = ctr_lo;
            }
            else if( ctr_lo > window_top_lo )
            {
                /* Update window_top and the contents of the window */
                uint32_t shift = ctr_lo - window_top_lo;
                window <<= shift;
                window_top_lo = ctr_lo;
            }
            else
            {
                /* Mark that number as seen in the current window */
                uint32_t bit = window_top_lo - ctr_lo;
                flag <<= bit;
            }
            window |= flag;

            epoch->stats.dtls.replay.in_window_top_lo = window_top_lo;
            epoch->stats.dtls.replay.in_window_top_hi = window_top_hi;
            epoch->stats.dtls.replay.in_window = window;
        }
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    return( 0 );
}

#if defined(MBEDTLS_MPS_PROTO_TLS)
static int l2_tls_in_get_epoch_and_counter( mbedtls_mps_l2 *ctx,
                                            uint16_t *dst_epoch,
                                            uint64_t *dst_ctr )
{
    uint8_t  offset;
    uint16_t epoch;
    uint64_t ctr;
    TRACE_INIT( "l2_tls_in_get_epoch_and_counter" );

    epoch   = ctx->epochs.base;
    offset  = ctx->epochs.permissions.tls.default_in;
    epoch  += offset;

    TRACE( trace_comment, "* Base:   %u", (unsigned) ctx->epochs.base );
    TRACE( trace_comment, "* Offset: %u", (unsigned) offset );

    ctr = ctx->epochs.window[ offset ].stats.tls.in_ctr;

    *dst_epoch = epoch;
    *dst_ctr   = ctr;

    RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

static int l2_out_get_and_update_rec_seq( mbedtls_mps_l2 *ctx,
                                          uint16_t epoch_id,
                                          uint32_t *dst_ctr )
{
    int ret;
    uint32_t *src_ctr;
    mbedtls_mps_l2_epoch_t *epoch;
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif

    ret = l2_epoch_lookup( ctx, epoch_id, &epoch );
    if( ret != 0 )
        return( ret );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
        src_ctr = epoch->stats.tls.out_ctr;
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
        src_ctr = epoch->stats.dtls.out_ctr;
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    dst_ctr[0] = src_ctr[0];
    dst_ctr[1] = src_ctr[1];

    src_ctr[0]++;
    if( src_ctr[0] == 0 )
    {
        src_ctr[1]++;
        if( src_ctr[1] == 0 )
            return( MPS_ERR_COUNTER_WRAP );
    }

    return( 0 );
}

#if defined(MBEDTLS_MPS_PROTO_DTLS)
static int l2_in_fetch_protected_record_dtls12( mbedtls_mps_l2 *ctx,
                                                mps_rec *rec )
{
    int ret;

    /* Buffer to hold the DTLS record header; will be obtained from Layer 1 */
    unsigned char *buf;

    /* Header structure the same for DTLS 1.0 and DTLS 1.2.

       From RFC 6347 - Section 4.1

       struct {
            ContentType type;
            ProtocolVersion version;
            uint16 epoch;
            uint48 sequence_number;
            uint16 length;
            opaque fragment[DTLSPlaintext.length];
          } DTLSPlaintext;

    */

    size_t const dtls_rec_hdr_len      = 13;

    size_t const dtls_rec_type_offset  = 0;
    size_t const dtls_rec_ver_offset   = 1;
    size_t const dtls_rec_epoch_offset = 3;
    size_t const dtls_rec_seq_offset   = 5;
    size_t const dtls_rec_len_offset   = 11;

    /* Record fields */
    uint8_t  type;
    int      minor_ver, major_ver;
    uint16_t epoch;
    uint32_t seq_nr[2];
    uint16_t len;

    TRACE_INIT( "l2_in_fetch_protected_record_dtls12" );

    /*
     * Fetch DTLS record header from Layer 1
     */

    ret = mps_l1_fetch( ctx->conf.l1, &buf, dtls_rec_hdr_len );
    if( ret != 0 )
        RETURN( ret );

    /*
     * Read and validate header fields
     */

    /* Record content type */
    MPS_READ_UINT8_LE( buf + dtls_rec_type_offset, &type );
    if( l2_type_is_valid( ctx, type ) == 0 )
    {
        TRACE( trace_error, "Invalid record type received" );
        RETURN( MPS_ERR_INVALID_RECORD );
    }

    /* Version */
    l2_read_version( &major_ver, &minor_ver,
                     MBEDTLS_MPS_MODE_DATAGRAM,
                     buf + dtls_rec_ver_offset );

    if( major_ver != MBEDTLS_SSL_MAJOR_VERSION_3 )
    {
        TRACE( trace_error, "Invalid major record version %u received, expected %u",
               (unsigned) major_ver, MBEDTLS_SSL_MAJOR_VERSION_3 );
        RETURN( MPS_ERR_INVALID_RECORD );
    }

    /* Initially, the server doesn't know which DTLS version
     * the client will use for its ClientHello message, so
     * Layer 2 must be configurable to allow arbitrary TLS
     * versions. This is done through the initial version
     * value MPS_L2_VERSION_UNSPECIFIED. */
    if( ctx->conf.version != MPS_L2_VERSION_UNSPECIFIED &&
        ctx->conf.version != minor_ver )
    {
        TRACE( trace_error, "Invalid minor record version %u received, expected %u",
               (unsigned) minor_ver, ctx->conf.version );
        RETURN( MPS_ERR_INVALID_RECORD );
    }

    /* Epoch */
    MPS_READ_UINT16_LE( buf + dtls_rec_epoch_offset, &epoch );

    ret = l2_epoch_check( ctx, epoch, MPS_EPOCH_READ );
    if( ret == MPS_ERR_INVALID_EPOCH )
        ret = MPS_ERR_INVALID_RECORD;
    if( ret != 0 )
        RETURN( ret );

    /* Record sequence number */
    MPS_READ_UINT16_LE( buf + dtls_rec_seq_offset,     &seq_nr[0] );
    MPS_READ_UINT32_LE( buf + dtls_rec_seq_offset + 2, &seq_nr[1] );
    if( l2_counter_replay_check( ctx, epoch, seq_nr[0], seq_nr[1] ) != 0 )
    {
        TRACE( trace_error, "Replayed record -- ignore" );
        RETURN( MPS_ERR_REPLAYED_RECORD );
    }

    /* Length */
    MPS_READ_UINT16_LE( buf + dtls_rec_len_offset, &len );
    /* TODO: Add length check, at least the architectural bound of 16384 + 2K,
     *       but preferably a transform-dependent bound that'll catch records
     *       with overly long plaintext by considering the maximum expansion
     *       plaintext-to-ciphertext. */

    /*
     * Read record contents from Layer 1
     */
    ret = mps_l1_fetch( ctx->conf.l1, &buf,
                        dtls_rec_hdr_len + len );

    if( ret == MPS_ERR_REQUEST_OUT_OF_BOUNDS )
    {
        TRACE( trace_error, "Claimed record length exceeds datagram bounds." );
        ret = MPS_ERR_INVALID_RECORD;
    }

    if( ret != 0 )
        RETURN( ret );

    /*
     * 3. Fill record struct
     */

    rec->type      = type;
    rec->major_ver = major_ver;
    rec->minor_ver = minor_ver;
    rec->epoch     = epoch;
    rec->ctr[0]    = seq_nr[0];
    rec->ctr[1]    = seq_nr[1];

    TRACE( trace_comment, "* Record epoch:  %u", (unsigned) rec->epoch );
    TRACE( trace_comment, "* Record number: %u", (unsigned) rec->ctr );

    rec->buf.buf         = buf + dtls_rec_hdr_len;
    rec->buf.buf_len     = len;
    rec->buf.data_offset = 0;
    rec->buf.data_len    = len;

    RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_DTLS */

/* Record content type validation */
static int l2_type_is_valid( mbedtls_mps_l2 *ctx,
                             mbedtls_mps_msg_type_t type )
{
    uint32_t const mask = ((uint32_t) 1u) << type;
    uint32_t const flag = ctx->conf.type_flag;
    /* type <= MBEDTLS_MPS_MSG_MAX == 31 is automatic if flag & mask != 0. */
    return( ( flag & mask ) != 0 );
}

/* Check if a valid record content type can be paused.
 * This assumes that the provided type is at least valid,
 * and in particular smaller than 64. */

#if defined(MBEDTLS_MPS_PROTO_TLS)
static int l2_type_can_be_paused( mbedtls_mps_l2 *ctx,
                                  mbedtls_mps_msg_type_t type )
{
    /* Regardless of the configuration, pausing is only
     * allowed for stream transports. */
    uint32_t const mask = ((uint32_t) 1u) << type;
    uint32_t const flag = ctx->conf.pause_flag;

#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    return( MBEDTLS_MPS_IS_TLS( mode ) &&
            ( flag & mask ) != 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

/* Check if a valid record content type allows merging of data.
 * This assumes that the provided type is at least valid,
 * and in particular smaller than 32. */
static int l2_type_can_be_merged( mbedtls_mps_l2 *ctx,
                                  mbedtls_mps_msg_type_t type )
{
    uint32_t const mask = ((uint32_t) 1u) << type;
    uint32_t const flag = ctx->conf.merge_flag;
    return( ( flag & mask ) != 0 );
}

/* Check if a valid record content type allows empty records.
 * This assumes that the provided type is at least valid,
 * and in particular smaller than 64. */
static int l2_type_empty_allowed( mbedtls_mps_l2 *ctx,
                                  mbedtls_mps_msg_type_t type )
{
    uint32_t const mask = ((uint32_t) 1u) << type;
    uint32_t const flag = ctx->conf.empty_flag;
    return( ( flag & mask ) != 0 );
}

static void l2_epoch_free( mbedtls_mps_l2_epoch_t *epoch )
{
    if( epoch->transform != NULL )
    {
        transform_free( epoch->transform );
        free( epoch->transform );
    }

    memset( epoch, 0, sizeof( mbedtls_mps_l2_epoch_t ) );
}

static void l2_epoch_init( mbedtls_mps_l2_epoch_t *epoch )
{
    memset( epoch, 0, sizeof( mbedtls_mps_l2_epoch_t ) );
}

int mps_l2_epoch_add( mbedtls_mps_l2 *ctx,
                      mbedtls_mps_transform_t *transform,
                      mbedtls_mps_epoch_id *epoch_id )
{
    uint8_t next_offset = ctx->epochs.next;
    TRACE_INIT( "mps_l2_epoch_add" );

    if( next_offset == MPS_L2_EPOCH_WINDOW_SIZE )
    {
        TRACE( trace_error, "The epoch window of size %u is full.",
               (unsigned) MPS_L2_EPOCH_WINDOW_SIZE );
        RETURN( MPS_ERR_EPOCH_WINDOW_EXCEEDED );
    }
    *epoch_id = ctx->epochs.base + next_offset;

    l2_epoch_init( &ctx->epochs.window[next_offset] );
    ctx->epochs.window[next_offset].transform = transform;
    ctx->epochs.next++;
    RETURN( 0 );
}

int mps_l2_epoch_usage( mbedtls_mps_l2 *ctx, mbedtls_mps_epoch_id epoch,
                        mbedtls_mps_epoch_usage usage )
{
    int ret;
    uint8_t epoch_offset;
    mbedtls_mps_epoch_id remove_read  = MBEDTLS_MPS_EPOCH_NONE;
    mbedtls_mps_epoch_id remove_write = MBEDTLS_MPS_EPOCH_NONE;
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif

    TRACE_INIT( "mps_l2_epoch_usage" );
    TRACE( trace_comment, "* Epoch: %d", epoch );
    TRACE( trace_comment, "* Usage: %u", (unsigned) usage );

    /* 1. Check if the epoch is valid. */

    ret = l2_epoch_lookup_internal( ctx, epoch, &epoch_offset, NULL );
    if( ret != 0 )
        RETURN( ret );

    /* 2. Check if the change of permissions collides with
     *    potential present usage of the epoch. */

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        if( ( usage & MPS_EPOCH_READ ) != 0    &&
            ctx->epochs.permissions.tls.default_in != epoch_offset )
        {
            remove_read =
                ctx->epochs.base + ctx->epochs.permissions.tls.default_in;
        }

        if( ( usage & MPS_EPOCH_WRITE ) != 0   &&
            ctx->epochs.permissions.tls.default_out != epoch_offset )
        {
            remove_write =
                ctx->epochs.base + ctx->epochs.permissions.tls.default_out;
        }
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        mbedtls_mps_epoch_usage old_usage =
            ctx->epochs.permissions.dtls[ epoch_offset ];

        mbedtls_mps_epoch_usage permission_removal = old_usage & ( ~usage );

        /* Check if read or write permissions are being removed. */
        if( ( permission_removal & MPS_EPOCH_READ ) != 0 )
            remove_read = epoch;
        if( ( permission_removal & MPS_EPOCH_WRITE ) != 0 )
            remove_write = epoch;
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    if( remove_read != MBEDTLS_MPS_EPOCH_NONE )
    {
        ret = l2_epoch_check_remove_read( ctx, remove_read );
        if( ret != 0 )
            RETURN( ret );
    }
    if( remove_write != MBEDTLS_MPS_EPOCH_NONE )
    {
        ret = l2_epoch_check_remove_write( ctx, remove_write );
        if( ret != 0 )
            RETURN( ret );
    }

    /* 3. Apply the change of permissions. */

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        if( usage & MPS_EPOCH_READ )
            ctx->epochs.permissions.tls.default_in = epoch_offset;
        if( usage & MPS_EPOCH_WRITE )
            ctx->epochs.permissions.tls.default_out = epoch_offset;
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        ctx->epochs.permissions.dtls[ epoch_offset ] = usage;
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    RETURN( l2_epoch_cleanup( ctx ) );
}

static int l2_epoch_check_remove_write( mbedtls_mps_l2 *ctx,
                                        mbedtls_mps_epoch_id epoch )
{
    int ret;
    TRACE_INIT( "l2_epoch_check_remove_write" );
    TRACE( trace_comment, " * Epoch ID: %u", (unsigned) epoch );

    if( ctx->out.state == MBEDTLS_MPS_L2_WRITER_STATE_UNSET ||
        ctx->out.writer.epoch != epoch )
    {
        TRACE( trace_comment, "The epoch is currently not used for writing." );
        RETURN( 0 );
    }

    if( ctx->out.state == MBEDTLS_MPS_L2_WRITER_STATE_EXTERNAL )
    {
        TRACE( trace_error, "The active writer is using the epoch." );
        RETURN( MPS_ERR_EPOCH_CHANGE_REJECTED );
    }

    if( ctx->out.state == MBEDTLS_MPS_L2_WRITER_STATE_INTERNAL )
    {
        /* An outgoing but not yet dispatched record is open
         * for the given epoch. Dispatch it, so that the epoch
         * is no longer needed. */
        TRACE( trace_comment, "Dispatch current outgoing record." );

        ret = l2_out_release_and_dispatch( ctx, MBEDTLS_WRITER_RECLAIM_FORCE );
        if( ret != 0 )
            RETURN( ret );

        TRACE( trace_comment, "Epoch %u is no longer used for writing.",
               (unsigned) epoch );
    }

    /* Now the outgoing state is UNSET or QUEUEING. */

    TRACE( trace_comment, "The write permission for epoch %u can be removed.",
           (unsigned) epoch );
    RETURN( 0 );
}

static int l2_epoch_check_remove_read( mbedtls_mps_l2 *ctx,
                                       mbedtls_mps_epoch_id epoch )
{
    TRACE_INIT( "l2_epoch_check_remove_read" );
    TRACE( trace_comment, " * Epoch ID: %u", (unsigned) epoch );

    if( ctx->in.active.state == MBEDTLS_MPS_L2_READER_STATE_EXTERNAL &&
        ctx->in.active.epoch == epoch )
    {
        TRACE( trace_error, "The active reader is using the epoch." );
        RETURN( MPS_ERR_EPOCH_CHANGE_REJECTED );
    }

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( ctx->in.paused.state == MBEDTLS_MPS_L2_READER_STATE_PAUSED &&
        ctx->in.paused.epoch == epoch )
    {
        TRACE( trace_error, "The paused reader is using the epoch." );
        RETURN( MPS_ERR_EPOCH_CHANGE_REJECTED );
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

    /* NOTE:
     * We allow the active reader to be in state
     * #MBEDTLS_MPS_L2_READER_STATE_INTERNAL, i.e. we do not yet error out
     * on this occasion when more incoming data is available for the same epoch.
     * Instead, the error will be triggered on the next call to mps_l2_read(),
     * which will attempt to continue reading from the currently opened record
     * but will find its epoch no longer valid.
     *
     * This covers the scenario where the peer attempts to piggyback
     * a handshake message that should be encrypted with a new epoch
     * on top of a handshake record that's encrypted with a previous
     * epoch, e.g. the EncryptedExtension message piggy backing on the
     * same record as the ServerHello.
     *
     */

    TRACE( trace_comment, "The epoch is not actively used for reading." );
    RETURN( 0 );
}

/*
 * This function checks whether an epoch is valid
 * and available for reading or writing.
 */
static int l2_epoch_check( mbedtls_mps_l2 *ctx,
                           mbedtls_mps_epoch_id epoch,
                           uint8_t purpose )
{
    int ret;
    uint8_t epoch_offset;
    uint8_t epoch_usage;
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    TRACE_INIT( "l2_epoch_check for epoch %d, purpose %u",
           epoch, (unsigned) purpose );

    ret = l2_epoch_lookup_internal( ctx, epoch, &epoch_offset, NULL );
    if( ret != 0 )
        RETURN( ret );

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        epoch_usage = ctx->epochs.permissions.dtls[ epoch_offset ];
        if( ( purpose & epoch_usage ) != purpose )
        {
            TRACE( trace_comment, "epoch usage not allowed" );
            RETURN( MPS_ERR_INVALID_RECORD );
        }
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        if( purpose == MPS_EPOCH_READ &&
            ctx->epochs.permissions.tls.default_in != epoch_offset )
        {
            TRACE( trace_comment, "epoch not the default incoming one" );
            RETURN( MPS_ERR_INVALID_RECORD );
        }

        if( purpose == MPS_EPOCH_WRITE &&
            ctx->epochs.permissions.tls.default_out != epoch_offset )
        {
            TRACE( trace_comment, "epoch not the default outgoing one" );
            RETURN( MPS_ERR_INVALID_RECORD );
        }
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

    RETURN( 0 );
}

/*
 * This functions detects and frees epochs that are no longer needed.
 *
 * Whether an epoch is 'needed' or not is jugded as follows:
 *
 * - Epochs with non-zero permissions are needed because they might
 *   be used for reading/writing in the future.
 *
 * - An epoch for which an outgoing record is open internally or externally,
 *   or for which more outgoing data is pending to be dispatched, is needed.
 *
 * - An epoch for which an incoming record is open externally,
 *   or for which more incoming data is pending to be received, is needed.
 *
 * NOTE: An internally but not externally open incoming record (i.e. a record
 *       that has been authenticated and decrypted, but for which no read-handle
 *       is currently available to the user) is *not* considered a usage
 *       for the epoch to which it belongs - that's because all interfacing
 *       with the epoch to which it belongs is done at the time of
 *       authentication and decryption.
 *
 * The following invariants hold which simplify checking of these conditions:
 * - An internally or externally open outgoing record belongs to an epoch with
 *   write permissions: An outgoing record is prepared in mps_l2_write_start()
 *   only if desired epoch has write-permissions, and if mps_l2_epoch_usage()
 *   is called to remove write-permissions for an epoch,
 *   l2_epoch_check_remove_write() checks that no outgoing record is externally
 *   open for it, and dispatches a internally open ones.
 * - An epoch for which outgoing data is pending to be dispatched
 *   has write permissions.
 * - An externally open incoming record belongs to an epoch with read
 *   permissions.
 * - An epoch for which incoming data is pending to be received
 *   has read permissions.
 *
 * In summary, in addition to read and write permissions the only epochs
 * that are in use are those for which outgoing data is pending to be
 * dispatched, which is only possible in TLS. This explains the checks below.
 *
 */
static int l2_epoch_cleanup( mbedtls_mps_l2 *ctx )
{
    uint8_t shift = 0, offset;
    mbedtls_mps_epoch_id max_shift;
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    TRACE_INIT( "l2_epoch_cleanup" );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        /* TLS */
        /* An epoch is in use if it's either the default incoming
         * or the default outgoing epoch, or if there is outgoing
         * data queued on that epoch.
         */
        int16_t queued_epoch_offset = -1;
        if( ctx->out.state == MBEDTLS_MPS_L2_WRITER_STATE_QUEUEING )
        {
            queued_epoch_offset = ctx->out.writer.epoch - ctx->epochs.base;
            TRACE( trace_comment, "Epoch %u still has data pending to be delivered -> Don't clean up",
                   (unsigned) queued_epoch_offset );
        }

        for( offset = 0; offset < ctx->epochs.next; offset++ )
        {
            if( offset != ctx->epochs.permissions.tls.default_in  &&
                offset != ctx->epochs.permissions.tls.default_out &&
                (int16_t) offset != queued_epoch_offset )
            {
                TRACE( trace_comment, "Epoch %d (offset %u, base %d) is no longer needed",
                       (unsigned) ( ctx->epochs.base + offset ),
                       (unsigned) ( offset ),
                       (unsigned) ( ctx->epochs.base ) );

                l2_epoch_free( &ctx->epochs.window[offset] );
            }
            else
            {
                if( offset == ctx->epochs.permissions.tls.default_in )
                {
                    TRACE( trace_comment, "Epoch %d is the current incoming epoch",
                           ctx->epochs.base + offset );
                }
                if( offset == ctx->epochs.permissions.tls.default_out )
                {
                    TRACE( trace_comment, "Epoch %d is the current outgoing epoch",
                           ctx->epochs.base + offset );
                }
                if( (int16_t) offset == queued_epoch_offset )
                {
                    TRACE( trace_comment, "Epoch %d still has queued data pending to be delivered",
                           ctx->epochs.base + offset );
                }

                break;
            }
        }

        shift = offset;
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        /* DTLS */
        /* An epoch is in use if its flags are not empty.
         * There is no queueing of outgoing data in DTLS. */
        for( offset = 0; offset < ctx->epochs.next; offset++ )
        {
            if( ctx->epochs.permissions.dtls[offset] == 0 )
            {
                TRACE( trace_comment, "epoch %u (off %u, base %u) no longer needed",
                       (unsigned) ( ctx->epochs.base + offset ),
                       (unsigned) ( offset ),
                       (unsigned) ( ctx->epochs.base ) );

                l2_epoch_free( &ctx->epochs.window[offset] );
            }
            else
            {
#if defined(MBEDTLS_MPS_TRACE)
                mbedtls_mps_epoch_id epoch = ctx->epochs.base + offset;
                if( ctx->epochs.permissions.dtls[offset] & MPS_EPOCH_READ )
                {
                    TRACE( trace_comment, "Epoch %d can be used for reading.",
                           epoch );
                }
                if( ctx->epochs.permissions.dtls[offset] & MPS_EPOCH_WRITE )
                {
                    TRACE( trace_comment, "Epoch %d can be used for writing.",
                           epoch );
                }
#endif /* MBEDTLS_MPS_TRACE */
                break;
            }
        }

        shift = offset;
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    if( shift == 0 )
    {
        TRACE( trace_comment, "Cannot get rid of any epoch." );
        RETURN( 0 );
    }

    max_shift = MBEDTLS_MPS_EPOCH_MAX -
        ( ctx->epochs.base + MPS_L2_EPOCH_WINDOW_SIZE );
    if( shift >= max_shift )
    {
        TRACE( trace_comment, "Cannot shift epoch window further." );
        shift = max_shift;
    }

    TRACE( trace_comment, "Can get rid of the first %u epochs; clearing.",
           (unsigned) shift );

    ctx->epochs.base += shift;
    ctx->epochs.next -= shift;

    TRACE( trace_comment, "* New base: %u", (unsigned) ctx->epochs.base );

    /* Shift epochs. */
    for( offset = 0; offset < MPS_L2_EPOCH_WINDOW_SIZE; offset++ )
    {
        if( MPS_L2_EPOCH_WINDOW_SIZE - offset > shift )
            ctx->epochs.window[offset] = ctx->epochs.window[offset + shift];
        else
            l2_epoch_init( &ctx->epochs.window[offset] );
    }

    /* Shift permissions */

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        ctx->epochs.permissions.tls.default_in  -= shift;
        ctx->epochs.permissions.tls.default_out -= shift;
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
    if( MBEDTLS_MPS_IS_DTLS( mode ) )
    {
        for( offset = 0; offset < MPS_L2_EPOCH_WINDOW_SIZE; offset++ )
        {
            if( MPS_L2_EPOCH_WINDOW_SIZE - offset > shift )
                ctx->epochs.permissions.dtls[offset] =
                    ctx->epochs.permissions.dtls[offset + shift];
            else
                ctx->epochs.permissions.dtls[offset] = 0;
        }
    }
#endif /* MBEDTLS_MPS_PROTO_DTLS */

    TRACE( trace_comment, "Epoch cleanup done" );
    RETURN( 0 );
}

static int l2_epoch_lookup( mbedtls_mps_l2 *ctx,
                            mbedtls_mps_epoch_id epoch_id,
                            mbedtls_mps_l2_epoch_t **epoch )
{
    return( l2_epoch_lookup_internal( ctx, epoch_id, NULL, epoch ) );
}

static int l2_epoch_lookup_internal( mbedtls_mps_l2 *ctx,
                                     mbedtls_mps_epoch_id epoch_id,
                                     uint8_t *offset,
                                     mbedtls_mps_l2_epoch_t **epoch )
{
    uint8_t epoch_offset;
    TRACE_INIT( "l2_epoch_lookup" );
    TRACE( trace_comment, "* Epoch:  %d", epoch_id );

    if( epoch_id == MBEDTLS_MPS_EPOCH_NONE )
    {
        TRACE( trace_comment, "The epoch is unset." );
        RETURN( MPS_ERR_INVALID_EPOCH );
    }
    else if( epoch_id < ctx->epochs.base )
    {
        TRACE( trace_comment, "The epoch %u is below the epoch base %u.",
               (unsigned) epoch_id, (unsigned) ctx->epochs.base );
        RETURN( MPS_ERR_INVALID_EPOCH );
    }

    epoch_offset = epoch_id - ctx->epochs.base;
    TRACE( trace_comment, "* Offset: %u", (unsigned) epoch_offset );

    if( epoch_offset >= ctx->epochs.next )
    {
        TRACE( trace_error, "The epoch is outside the epoch window." );
        RETURN( MPS_ERR_INVALID_EPOCH );
    }

    if( epoch != NULL )
        *epoch = &ctx->epochs.window[ epoch_offset ];

    if( offset != NULL )
        *offset = epoch_offset;

    RETURN( 0 );
}

/*
 * DTLS replay protection
 */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
static int l2_counter_replay_check( mbedtls_mps_l2 *ctx,
                                    mbedtls_mps_epoch_id epoch_id,
                                    uint32_t ctr_hi,
                                    uint32_t ctr_lo )
{
    int ret;
    uint32_t bit;
    mbedtls_mps_l2_epoch_t *epoch;
    uint32_t window_top_hi, window_top_lo;
    uint32_t window;
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    TRACE_INIT( "l2_counter_replay_check, epoch %u, ctr %u",
                (unsigned) epoch_id, (unsigned) ctr );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
        RETURN( 0 );
#endif /* MBEDTLS_MPS_PROTO_TLS */

    if( ctx->conf.anti_replay == MBEDTLS_MPS_ANTI_REPLAY_DISABLED )
    {
        RETURN( 0 );
    }

    ret = l2_epoch_lookup( ctx, epoch_id, &epoch );
    if( ret != 0 )
        RETURN( ret );

    window_top_hi = epoch->stats.dtls.replay.in_window_top_hi;
    window_top_lo = epoch->stats.dtls.replay.in_window_top_lo;
    window = epoch->stats.dtls.replay.in_window;

    if( ctr_hi > window_top_hi )
    {
        TRACE( trace_comment, "Record sequence number larger than everything seen so far." );
        RETURN( 0 );
    }
    else if( ctr_hi < window_top_hi )
    {
        /* Don't maintain window across 32-bit boundaries. */
        TRACE( trace_comment, "Record sequence number too old -- drop" );
        RETURN( -1 );
    }

    bit = window_top_lo - ctr_lo;
    if( bit >= 32 )
    {
        TRACE( trace_comment, "Record sequence number too old -- drop" );
        RETURN( -1 );
    }

    if( ( window & ( (uint32_t) 1u << bit ) ) != 0 )
    {
        TRACE( trace_comment, "Record sequence number seen before -- drop" );
        RETURN( -1 );
    }

    TRACE( trace_comment, "Record sequence number within window and not seen so far." );
    RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_DTLS */

#if defined(MBEDTLS_MPS_PROTO_DTLS)
int mps_l2_force_next_sequence_number( mbedtls_mps_l2 *ctx,
                                       mbedtls_mps_epoch_id epoch_id,
                                       uint64_t ctr )
{
    int ret;
    mbedtls_mps_l2_epoch_t *epoch;
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    TRACE_INIT( "mps_l2_force_next_sequence_number, epoch %u, ctr %u",
                (unsigned) epoch_id, (unsigned) ctr );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        TRACE( trace_error, "Sequence number forcing only needed and allowed in DTLS." );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

    ret = l2_epoch_lookup( ctx, epoch_id, &epoch );
    if( ret != 0 )
        RETURN( ret );


    epoch->stats.dtls.out_ctr[0] = (uint32_t)( ctr >> 32 );
    epoch->stats.dtls.out_ctr[1] = (uint32_t) ctr;
    RETURN( 0 );
}

int mps_l2_get_last_sequence_number( mbedtls_mps_l2 *ctx,
                                     mbedtls_mps_epoch_id epoch_id,
                                     uint64_t *ctr )
{
    int ret;
    mbedtls_mps_l2_epoch_t *epoch;
#if defined(MBEDTLS_MPS_PROTO_BOTH)
    mbedtls_mps_transport_type const mode = ctx->conf.mode;
#endif /* MBEDTLS_MPS_PROTO_BOTH */

    TRACE_INIT( "mps_l2_get_last_sequence_number, epoch %u",
                (unsigned) epoch_id );

#if defined(MBEDTLS_MPS_PROTO_TLS)
    if( MBEDTLS_MPS_IS_TLS( mode ) )
    {
        TRACE( trace_error, "Sequence number retrieval only needed and allowed in DTLS." );
        RETURN( MPS_ERR_UNEXPECTED_OPERATION );
    }
#endif /* MBEDTLS_MPS_PROTO_TLS */

    ret = l2_epoch_lookup( ctx, epoch_id, &epoch );
    if( ret != 0 )
        RETURN( ret );

    *ctr  = ((uint64_t) epoch->stats.dtls.last_seen[0]) << 32;
    *ctr |=  (uint64_t) epoch->stats.dtls.last_seen[1];
    RETURN( 0 );
}
#endif /* MBEDTLS_MPS_PROTO_TLS */

#endif /* MBEDTLS_MPS_SEPARATE_LAYERS) ||
          MBEDTLS_MPS_TOP_TRANSLATION_UNIT */
