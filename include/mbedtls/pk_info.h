/**
 * \file pk_info.h
 *
 * \brief Public Key cryptography abstraction layer: engine interface
 *
 *  This file defines the interface which public-key cryptography engines
 *  (PK engines) must implement. A PK engine defines how a public-private
 *  key pair is represented and how to perform cryptographic operations
 *  with it. Mbed TLS contains built-in PK engines implemented either
 *  purely in software or with hardware acceleration support, depending
 *  on the target platform. In addition, it is possible to define custom
 *  opaque key engines that forward operation requests to cryptographic
 *  modules outside Mbed TLS, such as external cryptoprocessors or general
 *  PKCS#11 tokens.
 */
/*
 *  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Methods that opaque key pair objects must implement.
 *
 * Engines that interface with external cryptographic processors must
 * implement this interface. It allows using different engines for each key.
 * Platform-specific hardware accelerators that can be used for all keys of
 * a given type should not use this interface, but rather provide an
 * alternative implementation of the respective cryptographic module - for
 * example to use an RSA accelerator you can define MBEDTLS_RSA_ALT, and
 * provide your own implementation of the RSA module.
 *
 * \warning: If you are using the PK interface to perform operations on
 * keys, call the functions in pk.h. The interface in this file should only
 * be used by implementers of opaque key engines.
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
 *    'int mbedtls_pk_setup_myengine(mbedtls_pk_context *, ...)'
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
 * return #MBEDTLS_ERR_PK_TYPE_MISMATCH in this case.
 *
 *
 * \warning: Do not declare this structure directly! It may be extended in
 * future versions of Mbed TLS. Call the macro
 * MBEDTLS_PK_OPAQUE_INFO_1() instead.
 * This macro is guaranteed to take parameters with the same type
 * and semantics as previous versions and fill any new field of the
 * structure with sensible values.
 */
struct mbedtls_pk_info_t
{
    /** Key pair type.
     *
     * mbedtls_pk_get_type() returns this value.
     *
     * For transparent keys, this contains an indication of supported
     * algorithms. For opaque keys, this is #MBEDTLS_PK_OPAQUE. */
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

    /** Tell if the context implements the algorithm specified by
     * the provided type (e.g. ECKEY can do ECDSA).
     *
     * mbedtls_pk_can_do() calls this function.
     *
     * This function is only based on the key type. It does not take any
     * usage restrictions into account. */
    int (*can_do)( const void * ctx, mbedtls_pk_type_t type );

    /** Upper bound of the signature length
     *
     * mbedtls_pk_get_signature_size() returns this value.
     *
     * In case of an error, or an unsupported key type, 0 should be returned.
     *
     * Opaque implementations may omit this method if they do not support
     * signing. */
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
     * Assumes that the buffer \c sig has room for
     * \c signature_size_func(ctx) bytes.
     *
     * The arguments \c f_rng and \c p_rng are provided in case the
     * algorithm requires randomization. Implementations are not
     * required to use it if they have their own random source. If \c
     * f_rng is null, the implementation should operate if it can, and
     * return #MBEDTLS_ERR_PK_BAD_INPUT_DATA otherwise.
     *
     * Opaque implementations may omit this method if they do not support
     * signing. If this method is provided, so must be
     * \ref mbedtls_pk_info_t.signature_size_func. */
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
     * is guaranteed to be initialized. The implementation is allowed to do
     * a probabilistic and computationally expensive check.
     *
     * If \c prv is an RSA key and \c pub is a transparent RSA key
     * (i.e. \c pub has the type #MBEDTLS_PK_RSA or #MBEDTLS_PK_RSASSA_PSS),
     * then \c check_pair_func must return 0 if the public key is
     * mathematically equivalent to the public part of \c prv, and
     * #MBEDTLS_ERR_RSA_KEY_CHECK_FAILED otherwise.
     *
     * If \c pub is an ECC key and \c pub is a transparent ECC key that can
     * be used for ECDSA (i.e. \c pub has the type #MBEDTLS_PK_ECKEY or
     * #MBEDTLS_PK_ECDSA), then check_pair_func must return 0 if the public
     * key is mathematically equivalent to the public part of prv, and
     * #MBEDTLS_ERR_ECP_BAD_INPUT_DATA otherwise.
     *
     * If \c pub is a transparent key (key of type #MBEDTLS_PK_RSA,
     * #MBEDTLS_PK_RSASSA_PSS, #MBEDTLS_PK_ECKEY or #MBEDTLS_PK_ECDSA) whose
     * type does not match the semantic type of \c prv (RSA, ECC or other),
     * then check_pair_func must return #MBEDTLS_ERR_PK_TYPE_MISMATCH.
     *
     * If \c pub and \c prv are opaque keys from the same engines (i.e. ''),
     * then check_pair_func must return 0, #MBEDTLS_ERR_PK_TYPE_MISMATCH, or
     * #MBEDTLS_ERR_RSA_KEY_CHECK_FAILED or #MBEDTLS_ERR_ECP_BAD_INPUT_DATA
     * as in the case of transparent keys.
     *
     * If \c pub is an opaque key which is not from the same engine as \c prv,
     * then check_pair_func may either return a semantically correct status as
     * in the case of transparent keys, or it may return
     * #MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE.
     *
     * Alternatively, check_pair_func may return another PK, RSA or ECP error
     * code if applicable. */
    int (*check_pair_func)( const mbedtls_pk_context *pub, const mbedtls_pk_context *prv );

    /** Allocate a new context
     *
     * mbedtls_pk_setup() calls this function.
     *
     * If this function returns NULL, the allocation is considered to
     * have failed and the object remains uninitialized.
     *
     * Opaque implementations may omit this method. In this case,
     * mbedtls_pk_setup() will set the \c pk_ctx field of the
     * mbedtls_pk_context object to NULL, and it is up to an engine-specific
     * setup function to initialize the \c pk_ctx field. This is useful if
     * the size of the memory depends on extra parameters passed to the
     * engine-specific setup function. */
    void * (*ctx_alloc_func)( void );

    /** Free the given context
     *
     * mbedtls_pk_free() calls this function. It must free the data allocated
     * by \c ctx_alloc_func as well as any other resource that belongs to
     * the object. */
    void (*ctx_free_func)( void *ctx );

    /** Interface with the debug module
     *
     * mbedtls_pk_debug() calls this function.
     *
     * Opaque implementations may omit this method. */
    void (*debug_func)( const void *ctx, mbedtls_pk_debug_item *items );

};

/**
 * \brief Initializer for opaque key engines
 *
 * Methods that opaque key pair objects must implement.
 *
 * The value of this macro is a suitable initializer for an object of type
 * mbedtls_pk_info_t. It is guaranteed to remain so in future versions of the
 * library, even if the type mbedtls_pk_info_t changes.
 *
 * This macro is suitable for static initializers provided that all of its
 * parameters are constant.
 *
 * \param name For transparent keys, this reflects the key type. For opaque
 *             keys, this reflects the cryptographic module driver.
 * \param get_bitlen \ref mbedtls_pk_info_t.get_bitlen method
 * \param can_do \ref mbedtls_pk_info_t.can_do method
 * \param signature_size_func \ref mbedtls_pk_info_t.signature_size_func method
 * \param verify_func \ref mbedtls_pk_info_t.verify_func method
 * \param sign_func \ref mbedtls_pk_info_t.sign_func method
 * \param decrypt_func \ref mbedtls_pk_info_t.decrypt_func method
 * \param encrypt_func \ref mbedtls_pk_info_t.encrypt_func method
 * \param check_pair_func \ref mbedtls_pk_info_t.check_pair_func method
 * \param ctx_alloc_func \ref mbedtls_pk_info_t.ctx_alloc_func method
 * \param ctx_free_func \ref mbedtls_pk_info_t.ctx_free_func method
 * \param debug_func \ref mbedtls_pk_info_t.debug_func method
 *
 * \return Initializer for an object of type mbedtls_pk_info_t with the
 *         specified field values */
#define MBEDTLS_PK_OPAQUE_INFO_1(               \
    name                                        \
    , get_bitlen                                \
    , can_do                                    \
    , signature_size_func                       \
    , verify_func                               \
    , sign_func                                 \
    , decrypt_func                              \
    , encrypt_func                              \
    , check_pair_func                           \
    , ctx_alloc_func                            \
    , ctx_free_func                             \
    , debug_func                                \
    )                                           \
    {                                           \
        MBEDTLS_PK_OPAQUE                       \
        , name                                  \
        , get_bitlen                            \
        , can_do                                \
        , signature_size_func                   \
        , verify_func                           \
        , sign_func                             \
        , decrypt_func                          \
        , encrypt_func                          \
        , check_pair_func                       \
        , ctx_alloc_func                        \
        , ctx_free_func                         \
        , debug_func                            \
    }

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PK_INFO_H */
