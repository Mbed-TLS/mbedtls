/**
 * \file md.h
 *
 * \brief Generic message digest wrapper
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
#ifndef POLARSSL_MD_H
#define POLARSSL_MD_H

#include <stddef.h>

#if defined(_MSC_VER) && !defined(inline)
#define inline _inline
#else
#if defined(__ARMCC_VERSION) && !defined(inline)
#define inline __inline
#endif /* __ARMCC_VERSION */
#endif /*_MSC_VER */

#define POLARSSL_ERR_MD_FEATURE_UNAVAILABLE                -0x5080  /**< The selected feature is not available. */
#define POLARSSL_ERR_MD_BAD_INPUT_DATA                     -0x5100  /**< Bad input parameters to function. */
#define POLARSSL_ERR_MD_ALLOC_FAILED                       -0x5180  /**< Failed to allocate memory. */
#define POLARSSL_ERR_MD_FILE_IO_ERROR                      -0x5200  /**< Opening or reading of file failed. */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    POLARSSL_MD_NONE=0,
    POLARSSL_MD_MD2,
    POLARSSL_MD_MD4,
    POLARSSL_MD_MD5,
    POLARSSL_MD_SHA1,
    POLARSSL_MD_SHA224,
    POLARSSL_MD_SHA256,
    POLARSSL_MD_SHA384,
    POLARSSL_MD_SHA512,
    POLARSSL_MD_RIPEMD160,
} md_type_t;

#if defined(POLARSSL_SHA512_C)
#define POLARSSL_MD_MAX_SIZE         64  /* longest known is SHA512 */
#else
#define POLARSSL_MD_MAX_SIZE         32  /* longest known is SHA256 or less */
#endif

/**
 * Opaque struct defined in md_wrap.h
 */
typedef struct _md_info_t md_info_t;

/**
 * Generic message digest context.
 */
typedef struct {
    /** Information about the associated message digest */
    const md_info_t *md_info;

    /** Digest-specific context */
    void *md_ctx;

    /** HMAC part of the context */
    void *hmac_ctx;
} md_context_t;

/**
 * \brief Returns the list of digests supported by the generic digest module.
 *
 * \return          a statically allocated array of digests, the last entry
 *                  is 0.
 */
const int *md_list( void );

/**
 * \brief           Returns the message digest information associated with the
 *                  given digest name.
 *
 * \param md_name   Name of the digest to search for.
 *
 * \return          The message digest information associated with md_name or
 *                  NULL if not found.
 */
const md_info_t *md_info_from_string( const char *md_name );

/**
 * \brief           Returns the message digest information associated with the
 *                  given digest type.
 *
 * \param md_type   type of digest to search for.
 *
 * \return          The message digest information associated with md_type or
 *                  NULL if not found.
 */
const md_info_t *md_info_from_type( md_type_t md_type );

/**
 * \brief           Initialize a md_context (as NONE)
 *                  This should always be called first.
 *                  Prepares the context for md_setup() or md_free().
 */
void md_init( md_context_t *ctx );

/**
 * \brief           Free and clear the internal structures of ctx.
 *                  Can be called at any time after md_init().
 *                  Mandatory once md_setup() has been called.
 */
void md_free( md_context_t *ctx );

#if ! defined(POLARSSL_DEPRECATED_REMOVED)
#if defined(POLARSSL_DEPRECATED_WARNING)
#define DEPRECATED    __attribute__((deprecated))
#else
#define DEPRECATED
#endif
/**
 * \brief           Select MD to use and allocate internal structures.
 *                  Should be called after md_init() or md_free().
 *                  Makes it necessary to call md_free() later.
 *
 * \deprecated      Superseded by md_setup() in 2.0.0
 *
 * \param ctx       Context to set up.
 * \param md_info   Message digest to use.
 *
 * \returns         \c 0 on success,
 *                  \c POLARSSL_ERR_MD_BAD_INPUT_DATA on parameter failure,
 *                  \c POLARSSL_ERR_MD_ALLOC_FAILED memory allocation failure.
 */
int md_init_ctx( md_context_t *ctx, const md_info_t *md_info ) DEPRECATED;
#undef DEPRECATED
#endif /* POLARSSL_DEPRECATED_REMOVED */

/**
 * \brief           Select MD to use and allocate internal structures.
 *                  Should be called after md_init() or md_free().
 *                  Makes it necessary to call md_free() later.
 *
 * \param ctx       Context to set up.
 * \param md_info   Message digest to use.
 * \param hmac      0 to save some meory is HMAC will not be use,
 *                  non-zero is HMAC is going to be used with this context.
 *
 * \returns         \c 0 on success,
 *                  \c POLARSSL_ERR_MD_BAD_INPUT_DATA on parameter failure,
 *                  \c POLARSSL_ERR_MD_ALLOC_FAILED memory allocation failure.
 */
int md_setup( md_context_t *ctx, const md_info_t *md_info, int hmac );

/**
 * \brief           Returns the size of the message digest output.
 *
 * \param md_info   message digest info
 *
 * \return          size of the message digest output.
 */
unsigned char md_get_size( const md_info_t *md_info );

/**
 * \brief           Returns the type of the message digest output.
 *
 * \param md_info   message digest info
 *
 * \return          type of the message digest output.
 */
md_type_t md_get_type( const md_info_t *md_info );

/**
 * \brief           Returns the name of the message digest output.
 *
 * \param md_info   message digest info
 *
 * \return          name of the message digest output.
 */
const char *md_get_name( const md_info_t *md_info );

/**
 * \brief           Prepare the context to digest a new message.
 *                  Generally called after md_setup() or md_finish().
 *                  Followed by md_update().
 *
 * \param ctx       generic message digest context.
 *
 * \returns         0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int md_starts( md_context_t *ctx );

/**
 * \brief           Generic message digest process buffer
 *                  Called between md_starts() and md_finish().
 *                  May be called repeatedly.
 *
 * \param ctx       Generic message digest context
 * \param input     buffer holding the  datal
 * \param ilen      length of the input data
 *
 * \returns         0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int md_update( md_context_t *ctx, const unsigned char *input, size_t ilen );

/**
 * \brief           Generic message digest final digest
 *                  Called after md_update().
 *                  Usually followed by md_free() or md_starts().
 *
 * \param ctx       Generic message digest context
 * \param output    Generic message digest checksum result
 *
 * \returns         0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int md_finish( md_context_t *ctx, unsigned char *output );

/**
 * \brief          Output = message_digest( input buffer )
 *
 * \param md_info  message digest info
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   Generic message digest checksum result
 *
 * \returns        0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
int md( const md_info_t *md_info, const unsigned char *input, size_t ilen,
        unsigned char *output );

/**
 * \brief          Output = message_digest( file contents )
 *
 * \param md_info  message digest info
 * \param path     input file name
 * \param output   generic message digest checksum result
 *
 * \return         0 if successful, POLARSSL_ERR_MD_FILE_OPEN_FAILED if fopen
 *                 failed, POLARSSL_ERR_MD_FILE_READ_FAILED if fread failed,
 *                 POLARSSL_ERR_MD_BAD_INPUT_DATA if md_info was NULL.
 */
int md_file( const md_info_t *md_info, const char *path,
             unsigned char *output );

/**
 * \brief           Set HMAC key and prepare to authenticate a new message.
 *                  Usually called after md_setup() or md_hmac_finish().
 *
 * \param ctx       HMAC context
 * \param key       HMAC secret key
 * \param keylen    length of the HMAC key
 *
 * \returns         0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int md_hmac_starts( md_context_t *ctx, const unsigned char *key,
                    size_t keylen );

/**
 * \brief           Generic HMAC process buffer.
 *                  Called between md_hmac_starts() or md_hmac_reset()
 *                  and md_hmac_finish().
 *                  May be called repeatedly.
 *
 * \param ctx       HMAC context
 * \param input     buffer holding the  data
 * \param ilen      length of the input data
 *
 * \returns         0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int md_hmac_update( md_context_t *ctx, const unsigned char *input,
                    size_t ilen );

/**
 * \brief           Output HMAC.
 *                  Called after md_hmac_update().
 *                  Usually followed my md_hmac_reset(), md_hmac_starts(),
 *                  or md_free().
 *
 * \param ctx       HMAC context
 * \param output    Generic HMAC checksum result
 *
 * \returns         0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int md_hmac_finish( md_context_t *ctx, unsigned char *output);

/**
 * \brief           Prepare to authenticate a new message with the same key.
 *                  Called after md_hmac_finish() and before md_hmac_update().
 *
 * \param ctx       HMAC context to be reset
 *
 * \returns         0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                  verification fails.
 */
int md_hmac_reset( md_context_t *ctx );

/**
 * \brief          Output = Generic_HMAC( hmac key, input buffer )
 *
 * \param md_info  message digest info
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   Generic HMAC-result
 *
 * \returns        0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
int md_hmac( const md_info_t *md_info, const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char *output );

/* Internal use */
int md_process( md_context_t *ctx, const unsigned char *data );

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_MD_H */
