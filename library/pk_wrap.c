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

#if defined(POLARSSL_MEMORY_C)
#include "polarssl/memory.h"
#else
#include <stdlib.h>
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

#if defined(POLARSSL_RSA_C)
static int rsa_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_RSA );
}

static size_t rsa_get_size( const void * ctx )
{
    return( 8 * ((rsa_context *) ctx)->len );
}

static int rsa_verify_wrap( void *ctx, md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len )
{
    if( sig_len != ((rsa_context *) ctx)->len )
        return( POLARSSL_ERR_RSA_VERIFY_FAILED );

    return( rsa_pkcs1_verify( (rsa_context *) ctx,
                RSA_PUBLIC, md_alg, hash_len, hash, sig ) );
}

static void *rsa_alloc_wrap( void )
{
    void *ctx = polarssl_malloc( sizeof( rsa_context ) );

    if( ctx != NULL )
        rsa_init( (rsa_context *) ctx, 0, 0 );

    return ctx;
}

static void rsa_free_wrap( void *ctx )
{
    rsa_free( (rsa_context *) ctx );
    polarssl_free( ctx );
}

static void rsa_debug( const void *ctx, pk_debug_item *items )
{
    items->type = POLARSSL_PK_DEBUG_MPI;
    items->name = "rsa.N";
    items->value = &( ((rsa_context *) ctx)->N );

    items++;

    items->type = POLARSSL_PK_DEBUG_MPI;
    items->name = "rsa.E";
    items->value = &( ((rsa_context *) ctx)->E );
}

const pk_info_t rsa_info = {
    POLARSSL_PK_RSA,
    "RSA",
    rsa_get_size,
    rsa_can_do,
    rsa_verify_wrap,
    rsa_alloc_wrap,
    rsa_free_wrap,
    rsa_debug,
};
#endif /* POLARSSL_RSA_C */

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

static size_t eckey_get_size( const void *ctx )
{
    return( ((ecp_keypair *) ctx)->grp.pbits );
}

#if defined(POLARSSL_ECDSA_C)
/* Forward declaration */
static int ecdsa_verify_wrap( void *ctx, md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len );

static int eckey_verify_wrap( void *ctx, md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    ecdsa_context ecdsa;

    ecdsa_init( &ecdsa );

    ret = ecdsa_from_keypair( &ecdsa, ctx ) ||
          ecdsa_verify_wrap( &ecdsa, md_alg, hash, hash_len, sig, sig_len );

    ecdsa_free( &ecdsa );

    return( ret );
}
#endif /* POLARSSL_ECDSA_C */

static void *eckey_alloc_wrap( void )
{
    void *ctx = polarssl_malloc( sizeof( ecp_keypair ) );

    if( ctx != NULL )
        ecp_keypair_init( ctx );

    return( ctx );
}

static void eckey_free_wrap( void *ctx )
{
    ecp_keypair_free( (ecp_keypair *) ctx );
    polarssl_free( ctx );
}

static void eckey_debug( const void *ctx, pk_debug_item *items )
{
    items->type = POLARSSL_PK_DEBUG_ECP;
    items->name = "eckey.Q";
    items->value = &( ((ecp_keypair *) ctx)->Q );
}

const pk_info_t eckey_info = {
    POLARSSL_PK_ECKEY,
    "EC",
    eckey_get_size,
    eckey_can_do,
#if defined(POLARSSL_ECDSA_C)
    eckey_verify_wrap,
#else
    NULL,
#endif
    eckey_alloc_wrap,
    eckey_free_wrap,
    eckey_debug,
};

/*
 * EC key resticted to ECDH
 */
static int eckeydh_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_ECKEY ||
            type == POLARSSL_PK_ECKEY_DH );
}

const pk_info_t eckeydh_info = {
    POLARSSL_PK_ECKEY_DH,
    "EC_DH",
    eckey_get_size,         /* Same underlying key structure */
    eckeydh_can_do,
    NULL,
    eckey_alloc_wrap,       /* Same underlying key structure */
    eckey_free_wrap,        /* Same underlying key structure */
    eckey_debug,            /* Same underlying key structure */
};
#endif /* POLARSSL_ECP_C */

#if defined(POLARSSL_ECDSA_C)
static int ecdsa_can_do( pk_type_t type )
{
    return( type == POLARSSL_PK_ECDSA );
}

static int ecdsa_verify_wrap( void *ctx, md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    ((void) md_alg);

    return( ecdsa_read_signature( (ecdsa_context *) ctx,
                hash, hash_len, sig, sig_len ) );
}

static void *ecdsa_alloc_wrap( void )
{
    void *ctx = polarssl_malloc( sizeof( ecdsa_context ) );

    if( ctx != NULL )
        ecdsa_init( (ecdsa_context *) ctx );

    return( ctx );
}

static void ecdsa_free_wrap( void *ctx )
{
    ecdsa_free( (ecdsa_context *) ctx );
    polarssl_free( ctx );
}

const pk_info_t ecdsa_info = {
    POLARSSL_PK_ECDSA,
    "ECDSA",
    eckey_get_size,     /* Compatible key structures */
    ecdsa_can_do,
    ecdsa_verify_wrap,
    ecdsa_alloc_wrap,
    ecdsa_free_wrap,
    eckey_debug,        /* Compatible key structures */
};
#endif /* POLARSSL_ECDSA_C */
