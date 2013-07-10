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

#define POLARSSL_ERR_PK_MALLOC_FAILED       -0x2F80  /**< Memory alloation failed. */
#define POLARSSL_ERR_PK_TYPE_MISMATCH       -0x2F00  /**< Type mismatch, eg attempt to use a RSA key as EC, or to modify key type */

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
 * \brief           Public key container
 */
typedef struct
{
    pk_type_t   type;       /**< Public key type */
    void *      data;       /**< Public key data */
    int         dont_free;  /**< True if data must not be freed */
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

#if defined(POLARSSL_RSA_C)
/**
 * \brief           Wrap a RSA context in a PK context
 *
 * \param ctx       PK context to initiliaze
 * \param rsa       RSA context to use
 *
 * \note            The PK context must be freshly initialized.
 *
 * \return          O on success,
 *                  POLARSSL_ERR_PK_TYPE_MISMATCH if ctx was not empty.
 */
int pk_wrap_rsa( pk_context *ctx, const rsa_context *rsa);
#endif

#ifdef __cplusplus
}
#endif

#endif /* pk.h */
