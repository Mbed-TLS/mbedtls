/**
 * \file md_wrap.h
 *
 * \brief Message digest wrappers.
 *
 * \warning This in an internal header. Do not include directly.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
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
#ifndef POLARSSL_MD_WRAP_H
#define POLARSSL_MD_WRAP_H

#if !defined(POLARSSL_CONFIG_FILE)
#include "config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include "md.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Message digest information.
 * Allows message digest functions to be called in a generic way.
 */
struct _md_info_t {
    /** Digest identifier */
    md_type_t type;

    /** Name of the message digest */
    const char * name;

    /** Output length of the digest function */
    int size;

    /** Block length of the digest function */
    int block_size;

    /** Digest initialisation function */
    void (*starts_func)( void *ctx );

    /** Digest update function */
    void (*update_func)( void *ctx, const unsigned char *input, size_t ilen );

    /** Digest finalisation function */
    void (*finish_func)( void *ctx, unsigned char *output );

    /** Generic digest function */
    void (*digest_func)( const unsigned char *input, size_t ilen,
                         unsigned char *output );

    /** Generic file digest function */
    int (*file_func)( const char *path, unsigned char *output );

    /** HMAC Initialisation function */
    void (*hmac_starts_func)( void *ctx, const unsigned char *key,
                              size_t keylen );

    /** HMAC update function */
    void (*hmac_update_func)( void *ctx, const unsigned char *input,
                              size_t ilen );

    /** HMAC finalisation function */
    void (*hmac_finish_func)( void *ctx, unsigned char *output);

    /** HMAC context reset function */
    void (*hmac_reset_func)( void *ctx );

    /** Generic HMAC function */
    void (*hmac_func)( const unsigned char *key, size_t keylen,
                       const unsigned char *input, size_t ilen,
                       unsigned char *output );

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );

    /** Free the given context */
    void (*ctx_free_func)( void *ctx );

    /** Internal use only */
    void (*process_func)( void *ctx, const unsigned char *input );
};

#if defined(POLARSSL_MD2_C)
extern const md_info_t md2_info;
#endif
#if defined(POLARSSL_MD4_C)
extern const md_info_t md4_info;
#endif
#if defined(POLARSSL_MD5_C)
extern const md_info_t md5_info;
#endif
#if defined(POLARSSL_RIPEMD160_C)
extern const md_info_t ripemd160_info;
#endif
#if defined(POLARSSL_SHA1_C)
extern const md_info_t sha1_info;
#endif
#if defined(POLARSSL_SHA256_C)
extern const md_info_t sha224_info;
extern const md_info_t sha256_info;
#endif
#if defined(POLARSSL_SHA512_C)
extern const md_info_t sha384_info;
extern const md_info_t sha512_info;
#endif

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_MD_WRAP_H */
