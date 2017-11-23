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

#if defined(MBEDTLS_ASYNC_C)
#include "mbedtls/async.h"

#include <limits.h>

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif /* !MBEDTLS_THREADING_C */


enum mbedtls_async_state
{
    MBEDTLS_ASYNC_STATE_INIT = 0,
    MBEDTLS_ASYNC_STATE_STARTED,
    MBEDTLS_ASYNC_STATE_COMPLETED,
    MBEDTLS_ASYNC_STATE_CANCELLED,
    MBEDTLS_ASYNC_STATE_DETACHED,
};

struct mbedtls_async_context
{
    const struct mbedtls_async_info *info;
    mbedtls_async_op_t op;
    enum mbedtls_async_state state;
    int status;
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t mutex;
#endif /* MBEDTLS_THREADING_C */
    void *output_buffer;
    size_t output_size;
    size_t output_length;
    mbedtls_async_cookie_t cookie;
    void *data;
};

/* A note on the locking strategy for asynchronous contexts
 *
 * It is expected that in many applications, asynchronous contexts are
 * accessed from different threads: one thread that initiates the operation
 * and accesses the result, and another thread that performs the operation.
 * For the most part, the state of the context indicates who owns it: it's
 * owned by the initiator until the operation is started and after the
 * operation completes, and by the performer while the operation is ongoing.
 * However, cancellation complicates this, as it's triggered by the initiator
 * while the performer owns the context.
 *
 * Therefore:
 *
 * - It is not necessary to use any locks while setting up the inputs of
 *   an operation in INIT state, or while reading the outputs of an operation
 *   in COMPLETED state.
 * - It is necessary to hold the lock to access a context if it may contain
 *   an ongoing operation. In particular, it is necessary to hold the lock:
 *
 *       - to query or change the status from an in-progress state;
 *       - to access the outputs of the operation.
 */

#if defined(MBEDTLS_THREADING_C)
static inline int async_lock( mbedtls_async_context_t *async )
{
    return( mbedtls_mutex_lock( &async->mutex ) );
}
static inline int async_unlock( mbedtls_async_context_t *async )
{
    return( mbedtls_mutex_unlock( &async->mutex ) );
}
#else /* !MBEDTLS_THREADING_C */
static inline int async_lock( mbedtls_async_context_t *async )
{
    (void) async;
    return( 0 );
}
static inline int async_unlock( mbedtls_async_context_t *async )
{
    (void) async;
    return( 0 );
}
#endif /* !MBEDTLS_THREADING_C */
#define LOCK_OR_RETURN( async )                                 \
    do                                                          \
    {                                                           \
        int lock_ret_ = async_lock( async );                    \
        if( lock_ret_ != 0 )                                    \
            return( lock_ret_ );                                \
    }                                                           \
    while ( 0 )
#define UNLOCK_AND_RETURN( async, expr )        \
    do                                          \
    {                                           \
        int return_value_ = ( expr );           \
        async_unlock( async );                  \
        return( return_value_ );                \
    }                                           \
    while( 0 )

const mbedtls_async_info_t mbedtls_async_synchronous_info =
{
    NULL,
    NULL,
    NULL,
};

mbedtls_async_context_t *mbedtls_async_alloc( const mbedtls_async_info_t *info )
{
    mbedtls_async_context_t *async;
    if( info == NULL )
        return( NULL );
    async = mbedtls_calloc( 1, sizeof( mbedtls_async_context_t ) );
    if( async == NULL )
        return( NULL );
    async->info = info;
    /* The caller shouldn't be asking for the status of an operation that
       they haven't started yet, hence BAD_STATE. */
    async->status = MBEDTLS_ERR_ASYNC_BAD_STATE;
#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_init( &async->mutex );
#endif /* MBEDTLS_THREADING_C */
    return( async );
}

/* free; must not be ongoing */
static void mbedtls_async_free( mbedtls_async_context_t *async )
{
    if( async == NULL )
        return;
    if( async->info->free != NULL )
        async->info->free( async );
#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_free( &async->mutex );
#endif /* MBEDTLS_THREADING_C */
    mbedtls_zeroize( async, sizeof( *async ) );
    mbedtls_free( async );
}

/* request cancellation */
int mbedtls_async_cancel( mbedtls_async_context_t *async )
{
    LOCK_OR_RETURN( async );
    if( async->state == MBEDTLS_ASYNC_STATE_STARTED )
    {
        if( async->info->cancel != NULL )
            async->info->cancel( async );
        async->state = MBEDTLS_ASYNC_STATE_CANCELLED;
    }
    UNLOCK_AND_RETURN( async, async->status );
}

/* cancel if ongoing; free memory when cancelled */
void mbedtls_async_release( mbedtls_async_context_t *async )
{
    if( async == NULL )
        return;
    (void) async_lock( async );
    switch( async->state )
    {
        case MBEDTLS_ASYNC_STATE_INIT:
        case MBEDTLS_ASYNC_STATE_COMPLETED:
        case MBEDTLS_ASYNC_STATE_DETACHED:
            mbedtls_async_free( async );
            break;
        default:
            async->state = MBEDTLS_ASYNC_STATE_DETACHED;
            break;
    }
    (void) async_unlock( async );
}

/* try making progress */
int mbedtls_async_resume( mbedtls_async_context_t *async )
{
    LOCK_OR_RETURN( async );
    if( async->state == MBEDTLS_ASYNC_STATE_STARTED )
        if( async->info->progress != NULL )
            async->info->progress( async );
    UNLOCK_AND_RETURN( async, async->status );
}

/* reset */
int mbedtls_async_reset( mbedtls_async_context_t *async )
{
    LOCK_OR_RETURN( async );
    switch( async->state )
    {
        case MBEDTLS_ASYNC_STATE_INIT:
            UNLOCK_AND_RETURN( async, 0 );
        case MBEDTLS_ASYNC_STATE_COMPLETED:
            async->status = MBEDTLS_ERR_ASYNC_BAD_STATE;
            async->op = MBEDTLS_ASYNC_OP_NULL;
            async->output_buffer = NULL;
            async->output_size = 0;
            async->output_length = 0;
            UNLOCK_AND_RETURN( async, 0 );
        default:
            UNLOCK_AND_RETURN( async, MBEDTLS_ERR_ASYNC_BAD_STATE );
    }
}

/* get current status */
int mbedtls_async_status( mbedtls_async_context_t *async )
{
    LOCK_OR_RETURN( async );
    /* Note that async->status contains the actual status of the
     * operation if the context is in COMPLETED state. In other
     * states, we make sure to place an appropriate value in the
     * status field: MBEDTLS_ERR_ASYNC_BAD_STATE for a context where
     * an operation hasn't started yet, andMBEDTLS_ERR_ASYNC_IN_PROGRESS
     * if there is an operation in progress. */
    UNLOCK_AND_RETURN( async, async->status );
}

/* get ongoing or completeted operation type (NULL if not started) */
mbedtls_async_op_t mbedtls_async_operation_type( const mbedtls_async_context_t *async )
{
    switch( async->state )
    {
        case MBEDTLS_ASYNC_STATE_STARTED:
        case MBEDTLS_ASYNC_STATE_COMPLETED:
        case MBEDTLS_ASYNC_STATE_CANCELLED:
        case MBEDTLS_ASYNC_STATE_DETACHED:
            return( async->op );
            break;
        default:
            return( MBEDTLS_ASYNC_OP_NULL );
            break;
    }
}


/* set output buffer in context structure */
int mbedtls_async_set_output_buffer( mbedtls_async_context_t *async,
                                     void *buf, size_t size )
{
    if( async->state != MBEDTLS_ASYNC_STATE_INIT )
        return( MBEDTLS_ERR_ASYNC_BAD_STATE );
    async->output_buffer = buf;
    async->output_size = size;
    return( 0 );
}

/* set state to started in context structure */
int mbedtls_async_set_started( mbedtls_async_context_t *async,
                               mbedtls_async_op_t op )
{
    LOCK_OR_RETURN( async );
    if( async->state != MBEDTLS_ASYNC_STATE_INIT )
        UNLOCK_AND_RETURN( async, MBEDTLS_ERR_ASYNC_BAD_STATE );
    async->op = op;
    async->state = MBEDTLS_ASYNC_STATE_STARTED;
    async->status = MBEDTLS_ERR_ASYNC_IN_PROGRESS;
    UNLOCK_AND_RETURN( async, 0 );
}

/* set state to completed in context structure */
int mbedtls_async_set_completed( mbedtls_async_context_t *async,
                                 int status,
                                 size_t output_length )
{
    LOCK_OR_RETURN( async );
    switch( async->state )
    {
    case MBEDTLS_ASYNC_STATE_STARTED:
    case MBEDTLS_ASYNC_STATE_CANCELLED:
        async->state = MBEDTLS_ASYNC_STATE_COMPLETED;
        async->status = status;
        async->output_length = output_length;
        UNLOCK_AND_RETURN( async, 0 );
    case MBEDTLS_ASYNC_STATE_DETACHED:
        mbedtls_async_free( async );
        UNLOCK_AND_RETURN( async, 0 );
    default:
        UNLOCK_AND_RETURN( async, MBEDTLS_ERR_ASYNC_BAD_STATE );
    }
}

/* get output length from completed operation */
size_t mbedtls_async_get_output_length( const mbedtls_async_context_t *async )
{
    return( async->output_length );
}

/* get private data */
void *mbedtls_async_get_data( const mbedtls_async_context_t *async,
                              const mbedtls_async_info_t *info )
{
    if( async->info != info )
        return( NULL );
    return( async->data );
}

/* set private data */
void mbedtls_async_set_data( mbedtls_async_context_t *async,
                             const mbedtls_async_info_t *info,
                             void *data )
{
    if( async->info == info )
        async->data = data;
}

/* get cookie */
mbedtls_async_cookie_t mbedtls_async_get_cookie(
    const mbedtls_async_context_t *async )
{
    return( async->cookie );
}

/* set cookie */
void mbedtls_async_set_cookie( mbedtls_async_context_t *async,
                               mbedtls_async_cookie_t cookie )
{
    async->cookie = cookie;
}

/* lock context and get output buffer */
int mbedtls_async_lock_output( mbedtls_async_context_t *async,
                               void **buf, size_t *size )
{
    *buf = NULL;
    *size = 0;
    LOCK_OR_RETURN( async );
    if( async->status != MBEDTLS_ASYNC_STATE_STARTED )
        UNLOCK_AND_RETURN( async, MBEDTLS_ERR_ASYNC_BAD_STATE );
    *buf = async->output_buffer;
    *size = async->output_size;
    return( 0 );
}

/* unlock context */
void mbedtls_async_unlock_output( mbedtls_async_context_t *async )
{
    (void) async_unlock( async );
}

#endif /* MBEDTLS_ASYNC_C */
