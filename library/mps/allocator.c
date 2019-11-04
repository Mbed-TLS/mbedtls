/*
 *  Message Processing Stack, Allocator implementation
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

#include "../../include/mbedtls/mps/allocator.h"

#include <stdlib.h>

int mps_alloc_init( mps_alloc *ctx,
                    size_t l1_len )
{
    ctx->l1_in_len  = l1_len;
    ctx->l1_out_len = l1_len;

    ctx->l1_in  = malloc( l1_len );
    ctx->l1_out = malloc( l1_len );
    if( ctx->l1_in == NULL || ctx->l1_out == NULL )
    {
        free( ctx->l1_in );
        free( ctx->l1_out );
        ctx->l1_in = ctx->l1_out = NULL;
        return( MBEDTLS_ERR_MPS_ALLOC_OUT_OF_SPACE );
    }

    ctx->alloc_state = 0;
    return( 0 );
}

int mps_alloc_free( mps_alloc *ctx )
{
    mps_alloc zero = { 0, NULL, 0, NULL, 0 };
    free( ctx->l1_in );
    free( ctx->l1_out );
    *ctx = zero;
    return( 0 );
}

static int alloc_check_flag( mps_alloc *ctx, mps_alloc_type id )
{
    uint32_t const flag = 1u << ( (uint8_t) id );
    if( ( ctx->alloc_state & flag ) != 0 )
        return( 1 );
    else
        return( 0 );
}

static void alloc_add_flag( mps_alloc *ctx, mps_alloc_type id )
{
    uint32_t const flag = 1u << ( (uint8_t) id );
    ctx->alloc_state |= flag;
}

static void alloc_remove_flag( mps_alloc *ctx, mps_alloc_type id )
{
    uint32_t const flag = 1u << ( (uint8_t) id );
    ctx->alloc_state &= ~flag;
}

int mps_alloc_acquire( mps_alloc *ctx, mps_alloc_type purpose,
                       unsigned char **buf, size_t *buflen )
{
    if( alloc_check_flag( ctx, purpose ) )
        return( MBEDTLS_ERR_MPS_ALLOC_OUT_OF_SPACE );

    switch( purpose )
    {
        case MPS_ALLOC_L1_IN:
            *buf    = ctx->l1_in;
            *buflen = ctx->l1_in_len;
            break;

        case MPS_ALLOC_L1_OUT:
            *buf    = ctx->l1_out;
            *buflen = ctx->l1_out_len;
            break;

        default:
            return( MBEDTLS_ERR_MPS_INTERNAL_ERROR );
            break;
    }

    alloc_add_flag( ctx, purpose );
    return( 0 );
}

int mps_alloc_release( mps_alloc* ctx, mps_alloc_type purpose )
{
    if( alloc_check_flag( ctx, purpose ) == 0 )
        return( MBEDTLS_ERR_MPS_INTERNAL_ERROR );

    if( purpose != MPS_ALLOC_L1_IN  &&
        purpose != MPS_ALLOC_L1_OUT )
    {
        return( MBEDTLS_ERR_MPS_INVALID_ARGS );
    }

    alloc_remove_flag( ctx, purpose );
    return( 0 );
}
