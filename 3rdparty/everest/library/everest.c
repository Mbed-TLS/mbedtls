/*
 *  Interface to code from Project Everest
 *
 *  Copyright 2016-2018 INRIA and Microsoft Corporation
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
 *  This file is part of Mbed TLS (https://tls.mbed.org).
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <string.h>

#include "mbedtls/ecdh.h"

#include "everest/x25519.h"
#include "everest/everest.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

int mbedtls_everest_setup( mbedtls_ecdh_context *ctx, int grp )
{
    if( grp != MBEDTLS_ECP_DP_CURVE25519 )
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    ctx->var = MBEDTLS_ECDH_VARIANT_EVEREST;
    ctx->grp_id = grp;

    ctx->ctx.everest_ecdh.ctx = mbedtls_calloc( 1, sizeof( mbedtls_x25519_context ) );
    mbedtls_x25519_init( ctx->ctx.everest_ecdh.ctx );

    return 0;
}

void mbedtls_everest_free( mbedtls_ecdh_context *ctx )
{
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;

    mbedtls_x25519_free( x25519_ctx );
    mbedtls_free( x25519_ctx );

    ctx->var = MBEDTLS_ECDH_VARIANT_NONE;
    ctx->grp_id = MBEDTLS_ECP_DP_NONE;
}

int mbedtls_everest_make_params( mbedtls_ecdh_context *ctx, size_t *olen,
                                 unsigned char *buf, size_t blen,
                                 int( *f_rng )( void *, unsigned char *, size_t ),
                                 void *p_rng )
{
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;
    if( ctx->var != MBEDTLS_ECDH_VARIANT_EVEREST ) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    return mbedtls_x25519_make_params( x25519_ctx, olen, buf, blen, f_rng, p_rng );
}

int mbedtls_everest_read_params( mbedtls_ecdh_context *ctx,
                                 const unsigned char **buf, const unsigned char *end )
{
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;
    if( ctx->var != MBEDTLS_ECDH_VARIANT_EVEREST ) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    return mbedtls_x25519_read_params( x25519_ctx, buf, end );
}

int mbedtls_everest_get_params( mbedtls_ecdh_context *ctx, const mbedtls_ecp_keypair *key,
    int side )
{
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;
    if( ctx->var != MBEDTLS_ECDH_VARIANT_EVEREST ) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    return mbedtls_x25519_get_params( x25519_ctx, key, side );
}

int mbedtls_everest_make_public( mbedtls_ecdh_context *ctx, size_t *olen,
                                 unsigned char *buf, size_t blen,
                                 int( *f_rng )( void *, unsigned char *, size_t ),
                                 void *p_rng )
{
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;
    if( ctx->var != MBEDTLS_ECDH_VARIANT_EVEREST ) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    return mbedtls_x25519_make_public( x25519_ctx, olen, buf, blen, f_rng, p_rng );
}

int mbedtls_everest_read_public( mbedtls_ecdh_context *ctx,
                                 const unsigned char *buf, size_t blen )
{
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;
    if( ctx->var != MBEDTLS_ECDH_VARIANT_EVEREST ) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    return mbedtls_x25519_read_public ( x25519_ctx, buf, blen );
}

int mbedtls_everest_calc_secret( mbedtls_ecdh_context *ctx, size_t *olen,
                                 unsigned char *buf, size_t blen,
                                 int( *f_rng )( void *, unsigned char *, size_t ),
                                 void *p_rng )
{
    mbedtls_ecdh_context_everest *everest_ctx = &ctx->ctx.everest_ecdh;
    mbedtls_x25519_context *x25519_ctx = ( mbedtls_x25519_context* )everest_ctx->ctx;
    if( ctx->var != MBEDTLS_ECDH_VARIANT_EVEREST ) return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    return mbedtls_x25519_calc_secret( x25519_ctx, olen, buf, blen, f_rng, p_rng );
}
