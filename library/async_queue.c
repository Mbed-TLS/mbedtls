/*
 *  Asynchronous operation abstraction layer
 *
 *  Copyright (C) 2017, ARM Limited, All Rights Reserved
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_ASYNC_QUEUE_C)
#include "mbedtls/async.h"
#include "mbedtls/async_queue.h"

#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}



struct mbedtls_async_queue_element
{
    mbedtls_async_queue_t *queue;
    struct mbedtls_async_queue_element *prev;
    struct mbedtls_async_queue_element *next;
    mbedtls_async_context_t *async;
    void *data;
};

#if 0
static void mbedtls_async_queue_async_progress( mbedtls_async_context_t *async );
static void mbedtls_async_queue_async_free( mbedtls_async_context_t *async );
static void mbedtls_async_queue_async_cancel( mbedtls_async_context_t *async );
#endif

static mbedtls_async_info_t mbedtls_async_queue_info =
{
#if 0
    mbedtls_async_queue_async_free,
    mbedtls_async_queue_async_cancel,
    mbedtls_async_queue_async_progress,
#else
    NULL,
    NULL,
    NULL,
#endif
};

#if 0
static void mbedtls_async_queue_async_progress( mbedtls_async_context_t *async )
{
    mbedtls_async_queue_element_t *elt =
        mbedtls_async_get_data( async, &mbedtls_async_queue_info );
    mbedtls_async_resume( elt->async );
}

static void mbedtls_async_queue_async_free( mbedtls_async_context_t *async )
{
    mbedtls_async_queue_element_t *elt =
        mbedtls_async_get_data( async, &mbedtls_async_queue_info );
    mbedtls_async_release( elt->async );
}

static void mbedtls_async_queue_async_cancel( mbedtls_async_context_t *async )
{
    mbedtls_async_queue_element_t *elt =
        mbedtls_async_get_data( async, &mbedtls_async_queue_info );
    mbedtls_async_cancel( elt->async );
}
#endif

mbedtls_async_context_t *mbedtls_async_queue_add( mbedtls_async_queue_t *queue,
                                                  void *data,
                                                  mbedtls_async_cookie_t cookie )
{
    mbedtls_async_queue_element_t *elt;
    mbedtls_async_context_t *async;
    elt = mbedtls_calloc( 1, sizeof( mbedtls_async_queue_element_t ) );
    if( elt == NULL )
        return( NULL );
    async = mbedtls_async_alloc( &mbedtls_async_queue_info );
    if( async == NULL )
    {
        mbedtls_free( elt );
        return( NULL );
    }
    mbedtls_async_set_data( async, &mbedtls_async_queue_info, elt );
    mbedtls_async_set_cookie( async, cookie );
    elt->queue = queue;
    elt->prev = queue->tail;
    elt->next = NULL;
    elt->async = async;
    elt->data = data;
    queue->tail = elt;
    if( queue->head == NULL )
        queue->head = elt;
    return( async );
}

void mbedtls_async_queue_remove( mbedtls_async_queue_element_t *elt )
{
    if( elt->next != NULL )
        elt->next->prev = elt->prev;
    if( elt->prev != NULL )
        elt->prev->next = elt->next;
    if( elt == elt->queue->tail )
        elt->queue->tail = elt->prev;
    if( elt == elt->queue->head )
        elt->queue->head = elt->next;
    mbedtls_async_release( elt->async );
    mbedtls_free( elt );
}

mbedtls_async_context_t *mbedtls_async_queue_element_get_data(
    mbedtls_async_queue_element_t *elt )
{
    return( elt->data );
}

void mbedtls_async_queue_init( mbedtls_async_queue_t *queue )
{
    queue->head = NULL;
    queue->tail = NULL;
}

void mbedtls_async_queue_free( mbedtls_async_queue_t *queue )
{
    while( queue->head != NULL )
    {
        mbedtls_async_queue_remove( queue->head );
    }
}



#if defined(MBEDTLS_PK_C)

#include "mbedtls/pk.h"
#include "mbedtls/pk_info.h"

typedef struct
{
    mbedtls_pk_context *underlying_pk;
    mbedtls_async_queue_t *queue;
} mbedtls_pk_queued_pk_t;

typedef struct
{
    mbedtls_pk_context *underlying_pk;
    mbedtls_md_type_t md_alg;
    unsigned char *input_buffer;
    size_t input_size;
    unsigned char *output_buffer;
    size_t output_size;
    int (*f_rng)(void *, unsigned char *, size_t);
    void *p_rng;
} mbedtls_pk_queued_async_t;

static size_t pk_queued_get_bitlen( const void *ctx_arg )
{
    const mbedtls_pk_queued_pk_t *ctx = ctx_arg;
    return( mbedtls_pk_get_bitlen( ctx->underlying_pk ) );
}

static int pk_queued_can_do( const void *ctx_arg, mbedtls_pk_type_t type )
{
    const mbedtls_pk_queued_pk_t *ctx = ctx_arg;
    return( mbedtls_pk_can_do( ctx->underlying_pk, type ) );
}

static size_t pk_queued_signature_size( const void *ctx_arg )
{
    const mbedtls_pk_queued_pk_t *ctx = ctx_arg;
    return( mbedtls_pk_signature_size( ctx->underlying_pk ) );
}

static int pk_queued_verify( void *ctx_arg, mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len )
{
    mbedtls_pk_queued_pk_t *ctx = ctx_arg;
    return( mbedtls_pk_verify( ctx->underlying_pk, md_alg,
                               hash, hash_len, sig, sig_len ) );
}

static int pk_queued_encrypt( void *ctx_arg,
                              const unsigned char *input, size_t ilen,
                              unsigned char *output, size_t *olen, size_t osize,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    mbedtls_pk_queued_pk_t *ctx = ctx_arg;
    return( mbedtls_pk_encrypt( ctx->underlying_pk, input, ilen,
                                output, olen, osize, f_rng, p_rng ) );
}

static int pk_queued_decrypt( void *ctx_arg,
                              const unsigned char *input, size_t ilen,
                              unsigned char *output, size_t *olen, size_t osize,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng )
{
    mbedtls_pk_queued_pk_t *ctx = ctx_arg;
    return( mbedtls_pk_decrypt( ctx->underlying_pk, input, ilen,
                                output, olen, osize, f_rng, p_rng ) );
}

static void *pk_queued_alloc( void )
{
    return( mbedtls_calloc( 1, sizeof( mbedtls_pk_queued_pk_t ) ) );
}

static void pk_queued_free( void *ctx_arg )
{
    mbedtls_pk_queued_pk_t *ctx = ctx_arg;
    mbedtls_zeroize( ctx, sizeof( *ctx ) );
    mbedtls_free( ctx );
}

static const mbedtls_async_info_t mbedtls_pk_queued_async_info = {
    NULL,
    NULL,
    NULL,
};

mbedtls_async_context_t *pk_queued_async_alloc( const void *ctx_arg )
{
    mbedtls_async_context_t *async;
    mbedtls_pk_queued_async_t *async_data;
    (void) ctx_arg;
    async = mbedtls_async_alloc( &mbedtls_pk_queued_async_info );
    if( async == NULL )
        return( NULL );
    async_data = mbedtls_calloc( 1, sizeof( *async_data ) );
    if( async_data == NULL )
    {
        mbedtls_async_release( async );
        return( NULL );
    }
    mbedtls_async_set_data( async, &mbedtls_pk_queued_async_info, async_data );
    return( async );
}

int pk_queued_async_start( void *ctx_arg,
                           mbedtls_async_context_t *async_ctx,
                           mbedtls_async_op_t op,
                           mbedtls_md_type_t md_alg,
                           const unsigned char *input_buffer,
                           size_t input_size,
                           unsigned char *output_buffer,
                           size_t output_size,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng )
{
    mbedtls_pk_queued_pk_t *pk_ctx = ctx_arg;
    mbedtls_pk_queued_async_t *async_data =
        mbedtls_async_get_data( async_ctx, &mbedtls_pk_queued_async_info );
    mbedtls_async_cookie_t cookie = {0, 0};
    if( op != MBEDTLS_ASYNC_OP_PK_SIGN )
        return( MBEDTLS_ERR_PK_TYPE_MISMATCH );
    async_data->underlying_pk = pk_ctx->underlying_pk;
    async_data->input_buffer = mbedtls_calloc( 1, input_size );
    if( async_data->input_buffer == NULL )
        return( MBEDTLS_ERR_PK_ALLOC_FAILED );
    memcpy( async_data->input_buffer, input_buffer, input_size );
    async_data->input_size = input_size;
    async_data->md_alg = md_alg;
    async_data->output_buffer = output_buffer;
    async_data->output_size = output_size;
    mbedtls_async_set_output_buffer( async_ctx, output_buffer, output_size );
    async_data->f_rng = f_rng;
    async_data->p_rng = p_rng;
    mbedtls_async_queue_add( pk_ctx->queue, async_ctx, cookie );
    return( MBEDTLS_ERR_ASYNC_IN_PROGRESS );
}

static const mbedtls_pk_info_t mbedtls_pk_queued_info = {
    MBEDTLS_PK_OPAQUE,
    "queued_operations",
    pk_queued_get_bitlen,
    pk_queued_can_do,
    pk_queued_signature_size,
    pk_queued_verify,
    NULL, // sign is asynchronous only
    pk_queued_decrypt,
    pk_queued_encrypt,
    NULL, // check_pair is not implemented
    pk_queued_alloc,
    pk_queued_free,
    NULL, // debug is not implemented
    pk_queued_async_alloc,
    pk_queued_async_start,
};

int mbedtls_pk_setup_queued( mbedtls_pk_context *pk,
                             mbedtls_pk_context *underlying_pk,
                             mbedtls_async_queue_t *queue )
{
    int ret;
    ret = mbedtls_pk_setup( pk, &mbedtls_pk_queued_info );
    if( ret == 0 )
    {
        mbedtls_pk_queued_pk_t *pk_ctx = pk->pk_ctx;
        pk_ctx->underlying_pk = underlying_pk;
        pk_ctx->queue = queue;
    }
    return( ret );
}

mbedtls_async_context_t *mbedtls_pk_start_queued(
    mbedtls_async_queue_element_t *elt )
{
    mbedtls_async_context_t *async_ctx;
    mbedtls_pk_queued_async_t *async_data;
    mbedtls_async_context_t *starting;
    int ret;
    async_ctx = mbedtls_async_queue_element_get_data( elt );
    if( async_ctx == NULL )
        return( NULL );
    async_data = mbedtls_async_get_data( async_ctx,
                                         &mbedtls_pk_queued_async_info );
    if( async_data == NULL )
        return( NULL );
    starting = mbedtls_pk_async_alloc( async_data->underlying_pk );
    if( starting == NULL )
        return( NULL );
    switch( mbedtls_async_operation_type( async_ctx ) )
    {
        case MBEDTLS_ASYNC_OP_PK_SIGN:
            ret = mbedtls_pk_async_sign( async_data->underlying_pk,
                                         async_data->md_alg,
                                         async_data->input_buffer,
                                         async_data->input_size,
                                         async_data->output_buffer,
                                         async_data->output_size,
                                         starting,
                                         async_data->f_rng,
                                         async_data->p_rng );
            if( ret == MBEDTLS_ERR_ASYNC_BAD_STATE )
            {
                mbedtls_async_release( starting );
                return( NULL );
            }
            return( starting );
        default:
            return( NULL );
    }
}

#endif /* MBEDTLS_PK_C */

#endif /* MBEDTLS_ASYNC_QUEUE_C */
