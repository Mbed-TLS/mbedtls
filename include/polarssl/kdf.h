/**
 * Copyright (C) 2014 Virgil Security Inc.
 *
 * This file is part of extension to mbed TLS (http://www.polarssl.org)
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef POLARSSL_KDF_H
#define POLARSSL_KDF_H

#include <string.h>

#include "md.h"

#if defined(_MSC_VER) && !defined(inline)
#define inline _inline
#else
#if defined(__ARMCC_VERSION) && !defined(inline)
#define inline __inline
#endif /* __ARMCC_VERSION */
#endif /*_MSC_VER */

#define POLARSSL_ERR_KDF_BAD_INPUT_DATA                     -0x5F80  /**< Bad input parameters to function. */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    POLARSSL_KDF_NONE=0,
    POLARSSL_KDF_KDF1,
    POLARSSL_KDF_KDF2,
} kdf_type_t;

/**
 * Key derivation function information. Allows Key derivation functions to be called
 * in a generic way.
 */
typedef struct {
    /** Key derivation function identifier */
    kdf_type_t type;

    /** Name of the Key derivation function */
    const char * name;

    /** Key derivation function */
    int (*kdf)(const md_info_t *md_info, const unsigned char *input, size_t ilen,
            unsigned char *output, size_t olen);
} kdf_info_t;

/**
 * \brief Returns the list of key derivation functions supported by the key derivation module.
 *
 * \return          a statically allocated array of key derivation functions, the last entry
 *                  is 0.
 */
const int *kdf_list( void );

/**
 * \brief           Returns the key derivation function information associated with the
 *                  given key derivation function name.
 *
 * \param kdf_name  Name of the key derivation function to search for.
 *
 * \return          The key derivation function information associated with kdf_name or
 *                  NULL if not found.
 */
const kdf_info_t *kdf_info_from_string( const char *kdf_name );

/**
 * \brief           Returns the key derivation function information associated with the
 *                  given key derivation function type.
 *
 * \param kdf_type  type of key derivation function to search for.
 *
 * \return          The key derivation function information associated with kdf_type or
 *                  NULL if not found.
 */
const kdf_info_t *kdf_info_from_type( kdf_type_t kdf_type );

/**
 * \brief           Returns the name of the key derivation function.
 *
 * \param kdf_info  key derivation function info
 *
 * \return          name of the key derivation function.
 */
static inline const char *kdf_get_name( const kdf_info_t *kdf_info )
{
    if( kdf_info == NULL )
        return( NULL );

    return kdf_info->name;
}

/**
 * \brief           Returns the typr of the key derivation function.
 *
 * \param kdf_info  key derivation function info
 *
 * \return          typr of the key derivation function.
 */
static inline kdf_type_t kdf_get_type( const kdf_info_t *kdf_info )
{
    if( kdf_info == NULL )
        return( POLARSSL_KDF_NONE );

    return kdf_info->type;
}

/**
 * \brief          Output = message_key derivation function( input buffer )
 *
 * \param kdf_info  key derivation function info
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   Generic key derivation function checksum result
 *
 * \returns        0 on success, POLARSSL_ERR_MD_BAD_INPUT_DATA if parameter
 *                 verification fails.
 */
int kdf( const kdf_info_t *kdf_info, const md_info_t *md_info, const unsigned char *input, size_t ilen,
        unsigned char *output, size_t olen );

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_KDF_H */
