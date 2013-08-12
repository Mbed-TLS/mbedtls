/*
 *  Public Key abstraction layer: wrapper functions
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

#if defined(POLARSSL_RSA_C)
static int rsa_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_RSA );
}

static int rsa_verify_wrap( void *ctx,
                   const unsigned char *hash, const md_info_t *md_info,
                   const unsigned char *sig, size_t sig_len )
{
    ((void) sig_len);

    return( rsa_pkcs1_verify( (rsa_context *) ctx,
                RSA_PUBLIC, md_info->type, 0, hash, sig ) );
}

const pk_info_t rsa_info = {
    POLARSSL_PK_RSA,
    rsa_can_do,
    rsa_verify_wrap,
};
#endif /* POLARSSL_RSA_C */

#if defined(POLARSSL_ECDSA_C)
int ecdsa_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_ECDSA );
}

int ecdsa_verify_wrap( void *ctx,
                       const unsigned char *hash, const md_info_t *md_info,
                       const unsigned char *sig, size_t sig_len )
{
    return( ecdsa_read_signature( (ecdsa_context *) ctx,
                hash, md_info->size, sig, sig_len ) );
}

const pk_info_t ecdsa_info = {
    POLARSSL_PK_ECDSA,
    ecdsa_can_do,
    ecdsa_verify_wrap,
};
#endif /* POLARSSL_ECDSA_C */

#if defined(POLARSSL_ECP_C)
/*
 * Generic EC key
 */
static int eckey_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_ECKEY ||
            type == POLARSSL_PK_ECKEY_DH ||
            type == POLARSSL_PK_ECDSA );
}

static int eckey_verify_wrap( void *ctx,
                       const unsigned char *hash, const md_info_t *md_info,
                       const unsigned char *sig, size_t sig_len )
{
#if !defined(POLARSSL_ECDSA_C)
    ((void) ctx);
    ((void) hash);
    ((void) md_info);
    ((void) sig);
    ((void) sig_len);

    return( POLARSSL_ERR_PK_TYPE_MISMATCH );
#else
    int ret;
    ecdsa_context ecdsa;

    ecdsa_init( &ecdsa );

    ret = ecdsa_from_keypair( &ecdsa, ctx ) ||
          ecdsa_verify_wrap( &ecdsa, hash, md_info, sig, sig_len );

    ecdsa_free( &ecdsa );

    return( ret );
#endif /* POLARSSL_ECDSA_C */
}

const pk_info_t eckey_info = {
    POLARSSL_PK_ECKEY,
    eckey_can_do,
    eckey_verify_wrap,
};

/*
 * EC key resticted to ECDH
 */
static int eckeydh_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_ECKEY ||
            type == POLARSSL_PK_ECKEY_DH );
}

static int eckeydh_verify_wrap( void *ctx,
                       const unsigned char *hash, const md_info_t *md_info,
                       const unsigned char *sig, size_t sig_len )
{
    ((void) ctx);
    ((void) hash);
    ((void) md_info);
    ((void) sig);
    ((void) sig_len);

    return( POLARSSL_ERR_PK_TYPE_MISMATCH );
}

const pk_info_t eckeydh_info = {
    POLARSSL_PK_ECKEY_DH,
    eckeydh_can_do,
    eckeydh_verify_wrap,
};
#endif /* POLARSSL_ECP_C */
