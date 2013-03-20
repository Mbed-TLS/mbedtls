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

/*
 * Supported ciphersuites (Official IANA names)
 */
#define TLS_RSA_WITH_NULL_MD5                    0x01   /**< Weak! */
#define TLS_RSA_WITH_NULL_SHA                    0x02   /**< Weak! */
#define TLS_RSA_WITH_NULL_SHA256                 0x3B   /**< Weak! */
#define TLS_RSA_WITH_DES_CBC_SHA                 0x09   /**< Weak! Not in TLS 1.2 */
#define TLS_DHE_RSA_WITH_DES_CBC_SHA             0x15   /**< Weak! Not in TLS 1.2 */

#define TLS_RSA_WITH_RC4_128_MD5                 0x04
#define TLS_RSA_WITH_RC4_128_SHA                 0x05

#define TLS_RSA_WITH_3DES_EDE_CBC_SHA            0x0A
#define TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA        0x16

#define TLS_RSA_WITH_AES_128_CBC_SHA             0x2F
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA         0x33
#define TLS_RSA_WITH_AES_256_CBC_SHA             0x35
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA         0x39
#define TLS_RSA_WITH_AES_128_CBC_SHA256          0x3C   /**< TLS 1.2 */
#define TLS_RSA_WITH_AES_256_CBC_SHA256          0x3D   /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256      0x67   /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256      0x6B   /**< TLS 1.2 */

#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA        0x41
#define TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA    0x45
#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA        0x84
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA    0x88
#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256     0xBA   /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 0xBE   /**< TLS 1.2 */
#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256     0xC0   /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 0xC4   /**< TLS 1.2 */

#define TLS_RSA_WITH_AES_128_GCM_SHA256          0x9C
#define TLS_RSA_WITH_AES_256_GCM_SHA384          0x9D
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256      0x9E
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384      0x9F

#define TLS_ECDHE_RSA_WITH_NULL_SHA              0xC010
#define TLS_ECDHE_RSA_WITH_RC4_128_SHA           0xC011
#define TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA      0xC012
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA       0xC013
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA       0xC014

typedef enum {
    POLARSSL_KEY_EXCHANGE_NONE = 0,
    POLARSSL_KEY_EXCHANGE_RSA,
    POLARSSL_KEY_EXCHANGE_DHE_RSA,
    POLARSSL_KEY_EXCHANGE_ECDHE_RSA,
} key_exchange_type_t;

typedef struct _ssl_ciphersuite_t ssl_ciphersuite_t;

#define POLARSSL_CIPHERSUITE_WEAK   0x01    /*<! Weak ciphersuite flag      */
#define POLARSSL_CIPHERSUITE_EC     0x02    /*<! EC-based ciphersuite flag  */

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
