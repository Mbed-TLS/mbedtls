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

#include "polarssl/rsa.h"
#include "polarssl/ecp.h"
#include "polarssl/pk.h"

#include <stdlib.h>

/*
 * Initialise a pk_context
 */
void pk_init( pk_context *ctx )
{
    if( ctx == NULL )
        return;

    ctx->type = POLARSSL_PK_NONE;
    ctx->data = NULL;
}

/*
 * Free (the components of) a pk_context
 */
void pk_free( pk_context *ctx )
{
    if( ctx == NULL )
        return;

    switch( ctx->type )
    {
        case POLARSSL_PK_NONE:
            break;

        case POLARSSL_PK_RSA:
            rsa_free( ctx->data );
            break;

        case POLARSSL_PK_ECKEY:
        case POLARSSL_PK_ECKEY_DH:
            ecp_keypair_free( ctx->data );
            break;
    }

    ctx->type = POLARSSL_PK_NONE;
    ctx->data = NULL;
}

/*
 * Set a pk_context to a given type
 */
int pk_set_type( pk_context *ctx, pk_type_t type )
{
    size_t size = type == POLARSSL_PK_RSA       ? sizeof( rsa_context )
                : type == POLARSSL_PK_ECKEY     ? sizeof( ecp_keypair )
                : type == POLARSSL_PK_ECKEY_DH  ? sizeof( ecp_keypair )
                : 0;

    if( size == 0 )
        return( 0 );

    if( ( ctx->data = malloc( size ) ) == NULL )
        return( -1 );

    memset( ctx->data, 0, size );
    ctx->type = type;

    return( 0 );
}
