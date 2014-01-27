/*
 *  HMAC_DRBG implementation (NIST SP 800-90)
 *
 *  Copyright (C) 2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 *  The NIST SP 800-90 DRBGs are described in the following publication.
 *  http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf
 */

#include "polarssl/config.h"

#if defined(POLARSSL_HMAC_DRBG_C)

#include "polarssl/hmac_drbg.h"

/*
 * HMAC_DRBG update, using optional additional data
 */
void hmac_drbg_update( hmac_drbg_context *ctx,
                       const unsigned char *additional, size_t add_len )
{
    size_t md_len = ctx->md_ctx.md_info->size;
    unsigned char rounds = ( additional != NULL && add_len != 0 ) ? 2 : 1;
    unsigned char sep[1];

    for( sep[0] = 0; sep[0] < rounds; sep[0]++ )
    {
        md_hmac_starts( &ctx->md_ctx, ctx->K, md_len );
        md_hmac_update( &ctx->md_ctx, ctx->V, md_len );
        md_hmac_update( &ctx->md_ctx, sep, 1 );
        if( rounds == 2 )
            md_hmac_update( &ctx->md_ctx, additional, add_len );
        md_hmac_finish( &ctx->md_ctx, ctx->K );

        md_hmac_starts( &ctx->md_ctx, ctx->K, md_len );
        md_hmac_update( &ctx->md_ctx, ctx->V, md_len );
        md_hmac_finish( &ctx->md_ctx, ctx->V );
    }
}

/*
 * Simplified HMAC_DRBG initialisation.
 */
int hmac_drbg_init( hmac_drbg_context *ctx,
                    const md_info_t * md_info,
                    const unsigned char *data, size_t data_len )
{
    int ret;

    memset( ctx, 0, sizeof( hmac_drbg_context ) );

    if( ( ret = md_init_ctx( &ctx->md_ctx, md_info ) ) != 0 )
        return( ret );

    memset( ctx->V, 0x01, md_info->size );
    /* ctx->K is already 0 */

    hmac_drbg_update( ctx, data, data_len );

    return( 0 );
}

/*
 * Simplified HMAC_DRBG random function
 */
int hmac_drbg_random( void *p_rng, unsigned char *output, size_t out_len )
{
    hmac_drbg_context *ctx = (hmac_drbg_context *) p_rng;
    size_t md_len = ctx->md_ctx.md_info->size;
    size_t left = out_len;
    unsigned char *out = output;

    while( left != 0 )
    {
        size_t use_len = left > md_len ? md_len : left;

        md_hmac_starts( &ctx->md_ctx, ctx->K, md_len );
        md_hmac_update( &ctx->md_ctx, ctx->V, md_len );
        md_hmac_finish( &ctx->md_ctx, ctx->V );

        memcpy( out, ctx->V, use_len );
        out += use_len;
        left -= use_len;
    }

    hmac_drbg_update( ctx, NULL, 0 );

    return( 0 );
}

/*
 * Free an HMAC_DRBG context
 */
void hmac_drbg_free( hmac_drbg_context *ctx )
{
    if( ctx == NULL )
        return;

    md_free_ctx( &ctx->md_ctx );

    memset( ctx, 0, sizeof( hmac_drbg_context ) );
}


#if defined(POLARSSL_SELF_TEST)

#include <stdio.h>

/*
 * Checkup routine
 */
int hmac_drbg_self_test( int verbose )
{

    if( verbose != 0 )
            printf( "\n" );

    return( 0 );
}
#endif /* POLARSSL_SELF_TEST */

#endif /* POLARSSL_HMAC_DRBG_C */
