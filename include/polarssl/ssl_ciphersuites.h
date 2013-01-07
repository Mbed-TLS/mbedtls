/**
 * \file ssl_ciphersuites.h
 *
 * \brief SSL Ciphersuites for PolarSSL
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
#ifndef POLARSSL_SSL_CIPHERSUITES_H
#define POLARSSL_SSL_CIPHERSUITES_H

#include "cipher.h"
#include "md.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    POLARSSL_KEY_EXCHANGE_NONE = 0,
    POLARSSL_KEY_EXCHANGE_RSA,
    POLARSSL_KEY_EXCHANGE_DHE_RSA
} key_exchange_type_t;

typedef struct _ssl_ciphersuite_t ssl_ciphersuite_t;

#define POLARSSL_CIPHERSUITE_WEAK   0x01

/**
 * \brief   This structure is used for storing ciphersuite information
 */
struct _ssl_ciphersuite_t
{
    int id;
    const char * name;

    cipher_type_t cipher;
    md_type_t mac;
    key_exchange_type_t key_exchange;

    int min_major_ver;
    int min_minor_ver;
    int max_major_ver;
    int max_minor_ver;

    unsigned char flags;
};

const int *ssl_ciphersuites_list( void );

const ssl_ciphersuite_t *ssl_ciphersuite_from_string( const char *ciphersuite_name );
const ssl_ciphersuite_t *ssl_ciphersuite_from_id( int ciphersuite_id );

#ifdef __cplusplus
}
#endif

#endif /* ssl_ciphersuites.h */
