/**
 * \file pk.h
 *
 * \brief Public Key abstraction layer
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

#ifndef POLARSSL_PK_H
#define POLARSSL_PK_H

#include "config.h"

#if defined(POLARSSL_RSA_C)
#include "rsa.h"
#endif

#if defined(POLARSSL_ECP_C)
#include "ecp.h"
#endif

#if defined(POLARSSL_ECDSA_C)
#include "ecdsa.h"
#endif

#define POLARSSL_ERR_PK_MALLOC_FAILED       -0x2F80  /**< Memory alloation failed. */
#define POLARSSL_ERR_PK_TYPE_MISMATCH       -0x2F00  /**< Type mismatch, eg attempt to use a RSA key as EC, or to modify key type */

#if defined(POLARSSL_RSA_C)
/**
 * Quick access to an RSA context inside a PK context.
 *
 * \warning You must make sure the PK context actually holds an RSA context
 * before using this macro!
 */
#define pk_rsa( pk )        ( (rsa_context *) (pk).data )
#endif /* POLARSSL_RSA_C */

#if defined(POLARSSL_ECP_C)
/**
 * Quick access to an EC context inside a PK context.
 *
 * \warning You must make sure the PK context actually holds an EC context
 * before using this macro!
 */
#define pk_ec( pk )         ( (ecp_keypair *) (pk).data )
#endif /* POLARSSL_ECP_C */


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Public key types
 */
typedef enum {
    POLARSSL_PK_NONE=0,
    POLARSSL_PK_RSA,
    POLARSSL_PK_ECKEY,
    POLARSSL_PK_ECKEY_DH,
    POLARSSL_PK_ECDSA,
} pk_type_t;

/**
 * \brief           Public key info
 */
typedef struct
{
    /** Public key type */
    pk_type_t type;

    /** Type name */
    const char *name;

    /** Get key size in bits */
    size_t (*get_size)( void * );

    /** Tell if the context implements this type (eg ECKEY can do ECDSA) */
    int (*can_do)( pk_type_t type );

    /** Verify signature */
    int (*verify_func)( void *ctx,
                        const unsigned char *hash, const md_info_t *md_info,
                        const unsigned char *sig, size_t sig_len );

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );

    /** Free the given context */
    void (*ctx_free_func)( void *ctx );

} pk_info_t;

/**
 * \brief           Public key container
 */
typedef struct
{
    const pk_info_t *   info;       /**< Public key informations */
    pk_type_t           type;       /**< Public key type (temporary) */
    void *              data;       /**< Public key data */
} pk_context;

/**
 * \brief           Initialize a pk_context (as NONE)
 */
void pk_init( pk_context *ctx );

/**
 * \brief           Free a pk_context
 */
void pk_free( pk_context *ctx );

/**
 * \brief           Set a pk_context to a given type
 *
 * \param ctx       Context to initialize
 * \param type      Type of key
 *
 * \note            Once the type of a key has been set, it cannot be reset.
 *                  If you want to do so, you need to use pk_free() first.
 *
 * \return          O on success,
 *                  POLARSSL_ERR_PK_MALLOC_FAILED on memory allocation fail,
 *                  POLARSSL_ERR_PK_TYPE_MISMATCH on attempts to reset type.
 */
int pk_set_type( pk_context *ctx, pk_type_t type );

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_PK_H */
