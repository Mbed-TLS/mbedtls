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

#include "md.h"

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
#define POLARSSL_ERR_PK_TYPE_MISMATCH       -0x2F00  /**< Type mismatch, eg attempt to encrypt with an ECDSA key */
#define POLARSSL_ERR_PK_BAD_INPUT_DATA      -0x2E80  /**< Bad input parameters to function. */

#if defined(POLARSSL_RSA_C)
/**
 * Quick access to an RSA context inside a PK context.
 *
 * \warning You must make sure the PK context actually holds an RSA context
 * before using this macro!
 */
#define pk_rsa( pk )        ( (rsa_context *) (pk).pk_ctx )
#endif /* POLARSSL_RSA_C */

#if defined(POLARSSL_ECP_C)
/**
 * Quick access to an EC context inside a PK context.
 *
 * \warning You must make sure the PK context actually holds an EC context
 * before using this macro!
 */
#define pk_ec( pk )         ( (ecp_keypair *) (pk).pk_ctx )
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
 * \brief           Types for interfacing with the debug module
 */
typedef enum
{
    POLARSSL_PK_DEBUG_NONE = 0,
    POLARSSL_PK_DEBUG_MPI,
    POLARSSL_PK_DEBUG_ECP,
} pk_debug_type;

/**
 * \brief           Item to send to the debug module
 */
typedef struct
{
    pk_debug_type type;
    char *name;
    void *value;
} pk_debug_item;

/** Maximum number of item send for debugging, plus 1 */
#define POLARSSL_PK_DEBUG_MAX_ITEMS 3

/**
 * \brief           Public key information and operations
 */
typedef struct
{
    /** Public key type */
    pk_type_t type;

    /** Type name */
    const char *name;

    /** Get key size in bits */
    size_t (*get_size)( const void * );

    /** Tell if the context implements this type (eg ECKEY can do ECDSA) */
    int (*can_do)( pk_type_t type );

    /** Verify signature */
    int (*verify_func)( void *ctx, md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        const unsigned char *sig, size_t sig_len );

    /** Make signature */
    int (*sign_func)( void *ctx, md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      unsigned char *sig, size_t *sig_len,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

    /** Decrypt message */
    int (*decrypt_func)( void *ctx, const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen, size_t osize,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );

    /** Encrypt message */
    int (*encrypt_func)( void *ctx, const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen, size_t osize,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );

    /** Free the given context */
    void (*ctx_free_func)( void *ctx );

    /** Interface with the debug module */
    void (*debug_func)( const void *ctx, pk_debug_item *items );

} pk_info_t;

/**
 * \brief           Public key container
 */
typedef struct
{
    const pk_info_t *   pk_info;    /**< Public key informations        */
    void *              pk_ctx;     /**< Underlying public key context  */
} pk_context;

/**
 * \brief           Return information associated with the given PK type
 *
 * \param type      PK type to search for.
 *
 * \return          The PK info associated with the type or NULL if not found.
 */
const pk_info_t *pk_info_from_type( pk_type_t pk_type );

/**
 * \brief           Initialize a pk_context (as NONE)
 */
void pk_init( pk_context *ctx );

/**
 * \brief           Initialize a PK context with the information given
 *                  and allocates the type-specific PK subcontext.
 *
 * \param ctx       Context to initialize. Must be empty (type NONE).
 * \param info      Information to use
 *
 * \return          0 on success,
 *                  POLARSSL_ERR_PK_BAD_INPUT_DATA on invalid input,
 *                  POLARSSL_ERR_PK_MALLOC_FAILED on allocation failure.
 */
int pk_init_ctx( pk_context *ctx, const pk_info_t *info );

/**
 * \brief           Free a pk_context
 */
void pk_free( pk_context *ctx );

/**
 * \brief           Get the size in bits of the underlying key
 *
 * \param ctx       Context to use
 *
 * \return          Key size in bits, or 0 on error
 */
size_t pk_get_size( const pk_context *ctx );

/**
 * \brief           Tell if a context can do the operation given by type
 *
 * \param ctx       Context to test
 * \param type      Target type
 *
 * \return          0 if context can't do the operations,
 *                  1 otherwise.
 */
int pk_can_do( pk_context *ctx, pk_type_t type );

/**
 * \brief           Verify signature
 *
 * \param ctx       PK context to use
 * \param md_alg    Hash algorithm used
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 *
 * \return          0 on success (signature is valid),
 *                  or a specific error code.
 */
int pk_verify( pk_context *ctx, md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len );

/**
 * \brief           Make signature
 *
 * \param ctx       PK context to use
 * \param md_alg    Hash algorithm used
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length
 * \param sig       Place to write the signature
 * \param sig_len   Number of bytes written
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 on success, or a specific error code.
 */
int pk_sign( pk_context *ctx, md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Decrypt message
 *
 * \param ctx       PK context to use
 * \param input     Input to decrypt
 * \param ilen      Input size
 * \param output    Decrypted output
 * \param olen      Decrypted message lenght
 * \param osize     Size of the output buffer
 *
 * \return          0 on success, or a specific error code.
 */
int pk_decrypt( pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Encrypt message
 *
 * \param ctx       PK context to use
 * \param input     Message to encrypt
 * \param ilen      Message size
 * \param output    Encrypted output
 * \param olen      Encrypted output length
 * \param osize     Size of the output buffer
 *
 * \return          0 on success, or a specific error code.
 */
int pk_encrypt( pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Export debug information
 *
 * \param ctx       Context to use
 * \param items     Place to write debug items
 *
 * \return          0 on sucess or POLARSSL_ERR_PK_BAD_INPUT_DATA
 */
int pk_debug( const pk_context *ctx, pk_debug_item *items );

/**
 * \brief           Access the type name
 *
 * \param ctx       Context to use
 *
 * \return          Type name on success, or "invalid PK"
 */
const char * pk_get_name( const pk_context *ctx );

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_PK_H */
