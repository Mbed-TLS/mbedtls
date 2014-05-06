/*
 *  NIST SP800-38C compliant CCM implementation
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
 * Definition of CCM:
 * http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf
 * RFC 3610 "Counter with CBC-MAC (CCM)"
 *
 * Related:
 * RFC 5116 "An Interface and Algorithms for Authenticated Encryption"
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_CCM_C)

#include "polarssl/ccm.h"

/*
 * Initialize context
 */
int ccm_init( ccm_context *ctx, cipher_id_t cipher,
              const unsigned char *key, unsigned int keysize )
{
    int ret;
    const cipher_info_t *cipher_info;

    memset( ctx, 0, sizeof( ccm_context ) );

    cipher_info = cipher_info_from_values( cipher, keysize, POLARSSL_MODE_ECB );
    if( cipher_info == NULL )
        return( POLARSSL_ERR_CCM_BAD_INPUT );

    if( cipher_info->block_size != 16 )
        return( POLARSSL_ERR_CCM_BAD_INPUT );

    if( ( ret = cipher_init_ctx( &ctx->cipher_ctx, cipher_info ) ) != 0 )
        return( ret );

    if( ( ret = cipher_setkey( &ctx->cipher_ctx, key, keysize,
                               POLARSSL_ENCRYPT ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

/*
 * Free context
 */
void ccm_free( ccm_context *ctx )
{
    (void) cipher_free_ctx( &ctx->cipher_ctx );
    memset( ctx, 0, sizeof( ccm_context ) );
}


#if defined(POLARSSL_SELF_TEST) && defined(POLARSSL_AES_C)

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#define polarssl_printf printf
#endif

int ccm_self_test( int verbose )
{
    if( verbose != 0 )
        polarssl_printf( "  CCM: skip\n" );

    if( verbose != 0 )
        polarssl_printf( "\n" );

    return( 0 );
}

#endif /* POLARSSL_SELF_TEST && POLARSSL_AES_C */

#endif /* POLARSSL_CCM_C */
