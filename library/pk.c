/*
 *  Public Key abstraction layer
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
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

#include "polarssl/config.h"

#include "polarssl/pk.h"
#include "polarssl/pk_wrap.h"

#if defined(POLARSSL_RSA_C)
#include "polarssl/rsa.h"
#endif
#if defined(POLARSSL_ECP_C)
#include "polarssl/ecp.h"
#endif
#if defined(POLARSSL_ECDSA_C)
#include "polarssl/ecdsa.h"
#endif

/*
 * Initialise a pk_context
 */
void pk_init( pk_context *ctx )
{
    if( ctx == NULL )
        return;

    ctx->pk_info = NULL;
    ctx->pk_ctx = NULL;
}

/*
 * Free (the components of) a pk_context
 */
void pk_free( pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL)
        return;

    ctx->pk_info->ctx_free_func( ctx->pk_ctx );
    ctx->pk_ctx = NULL;

    ctx->pk_info = NULL;
}

/*
 * Get pk_info structure from type
 */
const pk_info_t * pk_info_from_type( pk_type_t pk_type )
{
    switch( pk_type ) {
#if defined(POLARSSL_RSA_C)
        case POLARSSL_PK_RSA:
            return &rsa_info;
#endif
#if defined(POLARSSL_ECP_C)
        case POLARSSL_PK_ECKEY:
            return &eckey_info;
        case POLARSSL_PK_ECKEY_DH:
            return &eckeydh_info;
#endif
#if defined(POLARSSL_ECDSA_C)
        case POLARSSL_PK_ECDSA:
            return &ecdsa_info;
#endif
        default:
            return NULL;
    }
}

/*
 * Initialise context
 */
int pk_init_ctx( pk_context *ctx, const pk_info_t *info )
{
    if( ctx == NULL || info == NULL || ctx->pk_info != NULL )
        return( POLARSSL_ERR_PK_BAD_INPUT_DATA );

    if( ( ctx->pk_ctx = info->ctx_alloc_func() ) == NULL )
        return( POLARSSL_ERR_PK_MALLOC_FAILED );

    ctx->pk_info = info;

    return( 0 );
}

/*
 * Tell if a PK can do the operations of the given type
 */
int pk_can_do( pk_context *ctx, pk_type_t type )
{
    /* null of NONE context can't do anything */
    if( ctx == NULL || ctx->pk_info == NULL )
        return( 0 );

    return( ctx->pk_info->can_do( type ) );
}

/*
 * Verify a signature
 */
int pk_verify( pk_context *ctx,
               const unsigned char *hash, const md_info_t *md_info,
               const unsigned char *sig, size_t sig_len )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( POLARSSL_ERR_PK_BAD_INPUT_DATA );

    return( ctx->pk_info->verify_func( ctx->pk_ctx, hash, md_info, sig, sig_len ) );
}

/*
 * Get key size in bits
 */
size_t pk_get_size( const pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( 0 );

    return( ctx->pk_info->get_size( ctx->pk_ctx ) );
}

/*
 * Export debug information
 */
int pk_debug( const pk_context *ctx, pk_debug_item *items )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( POLARSSL_ERR_PK_BAD_INPUT_DATA );

    ctx->pk_info->debug_func( ctx->pk_ctx, items );
    return( 0 );
}

/*
 * Access the PK type name
 */
const char * pk_get_name( const pk_context *ctx )
{
    if( ctx == NULL || ctx->pk_info == NULL )
        return( "invalid PK" );

    return( ctx->pk_info->name );
}
