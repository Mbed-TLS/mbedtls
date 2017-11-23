/**
 * \file pk_info.h
 *
 * \brief Public Key cryptography abstraction layer: object interface
 *
 *  Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_PK_INFO_H
#define MBEDTLS_PK_INFO_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "pk.h"
#include "async.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Methods that opaque key pair objects must implement.
 *
 * Engines that interface with external cryptographic processors must
 * implement this interface. Platform-specific hardware accelerators
 * that can be used for all keys of a given type should use alternative
 * ("xxx_alt") interfaces instead. This interface allows using different
 * engines for each key.
 *
 * An engine for asymmetric cryptography must implement the interface
 * described in this structure. The interface for the engine may be
 * exposed in one of two ways:
 *
 * - Declare the mbedtls_pk_info_t structure and instruct users to call
 *   mbedtls_pk_setup with that structure.
 * - Keep the mbedtls_pk_info_t structure hidden and declare a function
 *   to call instead of mbedtls_pk_setup. This function should have an
 *   interface of the form
 *    `int mbedtls_pk_setup_myengine(mbedtls_pk_context *, ...)`
 *   where the extra parameters depend on the engine, e.g. handles to keys
 *   stored in an external cryptographic module.
 *
 * Unless otherwise indicated, functions returning int must return an
 * Mbed TLS status code, either 0 for success or a negative value to indicate
 * an error. It is recommended to use the MBEDTLS_ERR_PK_XXX error codes
 * defined in pk.h.
 *
 * Some methods are optional; this is clearly indicated in their description.
 * If a method is optional, then an opaque key implementation may put NULL
 * in the corresponding field. The corresponding function in pk.h will
 * return MBEDTLS_ERR_PK_TYPE_MISMATCH in this case.
 *
 * \note If you are using the PK interface to perform operations on
 * keys, call the functions in pk.h. The interface in this file should only
 * be used by implementers of opaque key engines.
 */
struct mbedtls_pk_info_t
{
    /** Key pair type.
     *
     * mbedtls_pk_get_type() returns this value.
     *
     * For transparent keys, this contains an indication of supported
     * algorithms. For opaque keys, this is \c MBEDTLS_PK_OPAQUE. */
    mbedtls_pk_type_t type;

    /** Type name.
     *
     * mbedtls_pk_get_name() returns this value. It must be a
     * null-terminated string.
     *
     * For transparent keys, this reflects the key type. For opaque keys,
     * this reflects the cryptographic module driver. */
    const char *name;

    /** Get key size in bits.
     *
     * mbedtls_pk_get_bitlen() returns this value.
     *
     * This function cannot fail. */
    size_t (*get_bitlen)( const void *ctx );

    /** Tell if the context implements this type (e.g.\ ECKEY can do ECDSA).
     *
     * mbedtls_pk_can_do() calls this function.
     *
     * This function is only based on the key type. It does not take any
     * usage restrictions into account. */
    int (*can_do)( const void * ctx, mbedtls_pk_type_t type );

    /** Signature size
     *
     * mbedtls_pk_signature_size() returns this value.
     *
     * Opaque implementations may omit this method if they do not support
     * signature. */
    size_t (*signature_size_func)( const void *ctx );

    /** Verify signature
     *
     * mbedtls_pk_verify() calls this function.
     *
     * Opaque implementations may omit this method if they do not support
     * signature verification. */
    int (*verify_func)( void *ctx, mbedtls_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        const unsigned char *sig, size_t sig_len );

    /** Make signature
     *
     * mbedtls_pk_sign() calls this function.
     *
     * Assume that the buffer \c sig has room for
     * \c signature_size_func(ctx) bytes.
     *
     * The arguments \c f_rng and \c p_rng are provided in case the
     * algorithm requires randomization. Implementations are not
     * required to use it if they have their own random source. If \c
     * f_rng is null, the implementation should operate if it can, and
     * return #MBEDTLS_ERR_PK_BAD_INPUT_DATA otherwise.
     *
     * Opaque implementations may omit this method if they do not support
     * signature. */
    int (*sign_func)( void *ctx, mbedtls_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      unsigned char *sig, size_t *sig_len,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng );

    /** Decrypt message
     *
     * mbedtls_pk_decrypt() calls this function.
     *
     * The arguments \c f_rng and \c p_rng are provided in case the
     * algorithm requires randomization. Implementations are not
     * required to use it if they have their own random source. If \c
     * f_rng is null, the implementation should operate if it can, and
     * return #MBEDTLS_ERR_PK_BAD_INPUT_DATA otherwise.
     *
     * Opaque implementations may omit this method if they do not support
     * decryption. */
    int (*decrypt_func)( void *ctx, const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen, size_t osize,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );

    /** Encrypt message
     *
     * mbedtls_pk_decrypt() calls this function.
     *
     * The arguments \c f_rng and \c p_rng are provided in case the
     * algorithm requires randomization. Implementations are not
     * required to use it if they have their own random source. If \c
     * f_rng is null, the implementation should operate if it can, and
     * return #MBEDTLS_ERR_PK_BAD_INPUT_DATA otherwise.
     *
     * Opaque implementations may omit this method if they do not support
     * encryption. */
    int (*encrypt_func)( void *ctx, const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen, size_t osize,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );

    /** Check public-private key pair
     *
     * mbedtls_pk_check_pair() calls this function on the private key pair
     * object \c prv. The other argument \c pub may be of any type, but it
     * is guaranteed to be initialized.
     *
     * Opaque implementations may omit this method. */
    int (*check_pair_func)( const mbedtls_pk_context *pub, const void *prv );

    /** Allocate a new context
     *
     * mbedtls_pk_setup() calls this function.
     *
     * If this function returns NULL, the allocation is considered to
     * have failed and the the object remains uninitialized.
     *
     * Opaque implementations may omit this method. In this case,
     * mbedtls_pk_setup will set the \c pk_ctx field of the mbedtls_pk_context
     * object to NULL, and it is up to an engine-specific setup function to
     * initialize the \c pk_ctx field. This is useful if the size of the
     * memory depends on extra parameters passed to the engine-specific setup
     * function. */
    void * (*ctx_alloc_func)( void );

    /** Free the given context
     *
     * mbedtls_pk_free() calls this function. It must free the data allocated
     * by \b ctx_alloc_func as well as any other resource that belongs to
     * the object.
     * */
    void (*ctx_free_func)( void *ctx );

    /** Interface with the debug module
     *
     * mbedtls_pk_debug() calls this function.
     *
     * Opaque implementations may omit this method. */
    void (*debug_func)( const void *ctx, mbedtls_pk_debug_item *items );

    /** Allocate an asynchronous context
     *
     * mbedtls_pk_async_alloc() calls this function.
     *
     * This method is mandatory if the key pair class supports asynchronous
     * operation. If it is omitted, then mbedtls_pk_async_alloc allocates
     * an asynchronous context that is only capable of synchronous operation,
     * and the \c mbedtls_pk_async_xxx functions will operate synchronously.
     *
     * \param ctx           \c pk_ctx field from the key pair object
     * \return              An asynchronous context suitable for performing
     *                      operations on the given key pair, or NULL if
     *                      there is not enough available memory or if the
     *                      object does not support asynchronous operation.
     */
    mbedtls_async_context_t * (*async_alloc_func)( const void *ctx );

    /** Start an asynchronous operation.
     *
     * This method is optional. If it is present, the \c mbedtls_pk_async_xxx
     * functions call this method. If it is omitted, these functions
     * operate synchronously.
     *
     * \param ctx           \c pk_ctx field from the key pair object
     * \param async_ctx     Asynchronous operation context, guaranteed to
     *                      be in the initial state.
     * \param op            Operation to perform (\c MBEDTLS_ASYNC_OP_PK_XXX)
     * \param md_alg        Hash algorithm. Used for signature and verification
     *                      only. See the description of mbedtls_pk_sign() and
     *                      mbedtls_pk_verify() for details.
     * \param input_buffer  Pointer to the buffer containing the data to sign,
     *                      verify, encrypt or decrypt. This buffer is not
     *                      guaranteed to remain valid after this function
     *                      returns, so make a copy if necessary.
     * \param input_length  Size of the input buffer in bytes.
     * \param output_buffer Pointer where the signature, encryted data or
     *                      decrypted data is to be written. This buffer is
     *                      guaranteed to remain valid until the operation
     *                      is completed or cancelled.
     * \param output_size   Size of the output buffer in bytes.
     * \param f_rng         Random number generator function. May be null.
     * \param p_rng         Context to pass to \c f_rng.
     * \return              - 0 if the operation is completed successfully.
     *                      - \c MBEDTLS_ERR_ASYNC_IN_PROGRESS if the operation
     *                        was set up successfully, but is not completed yet.
     *                      - \c MBEDTLS_ERR_PK_XXX status code for errors
     *                        related to the cryptographic operation.
     *                      - Other \c MBEDTLS_ERR_XXX codes from lower-level
     *                        modules are permitted, but not recommended.
     */
    int (*async_start_func)( void *ctx,
                             mbedtls_async_context_t *async_ctx,
                             mbedtls_async_op_t op,
                             mbedtls_md_type_t md_alg,
                             const unsigned char *input_buffer,
                             size_t input_length,
                             unsigned char *output_buffer,
                             size_t output_size,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng );

};

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PK_INFO_H */
