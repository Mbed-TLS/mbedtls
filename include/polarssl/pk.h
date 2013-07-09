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

#define POLARSSL_ERR_PK_MALLOC_FAILED       -0x2F80  /**< Memory alloation failed. */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Public key types
 */
typedef enum {
    POLARSSL_PK_NONE=0,
#if defined(POLARSSL_RSA_C)
    POLARSSL_PK_RSA,
#endif
#if defined(POLARSSL_ECP_C)
    POLARSSL_PK_ECKEY,
    POLARSSL_PK_ECKEY_DH,
#endif
} pk_type_t;

/**
 * \brief           Public key container
 */
typedef struct
{
    pk_type_t   type;   /**< Public key type */
    void *      data;   /**< Public key data */
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
 * \return          O on success, or POLARSSL_ERR_PK_MALLOC_FAILED
 */
int pk_set_type( pk_context *ctx, pk_type_t type );

#ifdef __cplusplus
}
#endif

#endif /* pk.h */
