/**
 * \file pk.h
 *
 * \brief Public Key cryptography abstraction layer
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

#ifndef MBEDTLS_PK_H
#define MBEDTLS_PK_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "md.h"

#if defined(MBEDTLS_RSA_C)
#include "rsa.h"
#endif

#if defined(MBEDTLS_ECP_C)
#include "ecp.h"
#endif

#if defined(MBEDTLS_ECDSA_C)
#include "ecdsa.h"
#endif

#if ( defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/** \name Error codes */
/**@{*/

#define MBEDTLS_ERR_PK_ALLOC_FAILED        -0x3F80  /**< Memory allocation failed. */
#define MBEDTLS_ERR_PK_TYPE_MISMATCH       -0x3F00  /**< Type mismatch, eg attempt to encrypt with an ECDSA key */
#define MBEDTLS_ERR_PK_BAD_INPUT_DATA      -0x3E80  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_PK_FILE_IO_ERROR       -0x3E00  /**< Read/write of file failed. */
#define MBEDTLS_ERR_PK_KEY_INVALID_VERSION -0x3D80  /**< Unsupported key version */
#define MBEDTLS_ERR_PK_KEY_INVALID_FORMAT  -0x3D00  /**< Invalid key tag or value. */
#define MBEDTLS_ERR_PK_UNKNOWN_PK_ALG      -0x3C80  /**< Key algorithm is unsupported (only RSA and EC are supported). */
#define MBEDTLS_ERR_PK_PASSWORD_REQUIRED   -0x3C00  /**< Private key password can't be empty. */
#define MBEDTLS_ERR_PK_PASSWORD_MISMATCH   -0x3B80  /**< Given private key password does not allow for correct decryption. */
#define MBEDTLS_ERR_PK_INVALID_PUBKEY      -0x3B00  /**< The pubkey tag or value is invalid (only RSA and EC are supported). */
#define MBEDTLS_ERR_PK_INVALID_ALG         -0x3A80  /**< The algorithm tag or value is invalid. */
#define MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE -0x3A00  /**< Elliptic curve is unsupported (only NIST curves are supported). */
#define MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE -0x3980  /**< Unavailable feature, e.g. RSA disabled for RSA key. */
#define MBEDTLS_ERR_PK_SIG_LEN_MISMATCH    -0x3900  /**< The signature is valid but its length is less than expected. */
#define MBEDTLS_ERR_PK_INVALID_SIGNATURE   -0x3880  /**< Invalid signature */
#define MBEDTLS_ERR_PK_BUFFER_TOO_SMALL    -0x3800  /**< Output buffer too small */
#define MBEDTLS_ERR_PK_NOT_PERMITTED       -0x3780  /**< Operation not permitted */

/**@}*/

#ifdef __cplusplus
extern "C" {
#endif

/** \name Asymmetric cryptography operation contexts */
/**@{*/

/**
 * \brief          Asymmetric operation context types
 */
typedef enum {
    MBEDTLS_PK_NONE=0,          /**< Unused context object */
    MBEDTLS_PK_RSA,             /**< RSA key pair (normal software implementation) with PKCS#1 v1.5 or PSS context */
    MBEDTLS_PK_ECKEY,           /**< ECC key pair with ECDSA context */
    MBEDTLS_PK_ECKEY_DH,        /**< ECC key pair with ECDH context */
    MBEDTLS_PK_ECDSA,           /**< ECC key pair with ECDSA context */
    MBEDTLS_PK_RSA_ALT,         /**< RSA (alternative implementation) */
    MBEDTLS_PK_RSASSA_PSS,      /**< RSA key pair; same context as MBEDTLS_PK_RSA, but used to represent keys with the algorithm identifier id-RSASSA-PSS */
    /** Opaque key pair (cryptographic material held in an external module).
     * This may be an RSA or ECC key or a key of an unrecognized type. Call
     * \c mbedtls_pk_can_do() to check whether a key is of a recognized type. */
    MBEDTLS_PK_OPAQUE,
} mbedtls_pk_type_t;

/**
 * \brief           Options for RSASSA-PSS signature verification.
 *                  See \c mbedtls_rsa_rsassa_pss_verify_ext()
 */
typedef struct
{
    mbedtls_md_type_t mgf1_hash_id;
    int expected_salt_len;

} mbedtls_pk_rsassa_pss_options;

/**
 * \brief           Types for interfacing with the debug module
 */
typedef enum
{
    MBEDTLS_PK_DEBUG_NONE = 0,
    MBEDTLS_PK_DEBUG_MPI,
    MBEDTLS_PK_DEBUG_ECP,
} mbedtls_pk_debug_type;

/**
 * \brief           Item to send to the debug module
 */
typedef struct
{
    mbedtls_pk_debug_type type;
    const char *name;
    void *value;
} mbedtls_pk_debug_item;

/** Maximum number of item send for debugging, plus 1 */
#define MBEDTLS_PK_DEBUG_MAX_ITEMS 3

/**
 * \brief           Key pair information and operations
 */
typedef struct mbedtls_pk_info_t mbedtls_pk_info_t;

/**
 * \brief           Key pair container
 */
typedef struct
{
    const mbedtls_pk_info_t *   pk_info; /**< Algorithm information          */
    void *                      pk_ctx;  /**< Underlying key pair context */
} mbedtls_pk_context;

/**
 * \brief           Access the type name
 *
 * \param ctx       Context to use
 *
 * \return          Type name on success, or "invalid PK"
 */
const char * mbedtls_pk_get_name( const mbedtls_pk_context *ctx );

/**
 * \brief           Get the key type
 *
 * \param ctx       Context to use
 *
 * \return          Type on success, or MBEDTLS_PK_NONE
 *
 * \note            This function returns the type of the key pair object. The
 *                  type encodes the representation of the object as well as
 *                  the operations that it can be used for. To test whether
 *                  the object represents a key of a recognized type such
 *                  as RSA or ECDSA, call \c mbedtls_pk_can_do().
 */
mbedtls_pk_type_t mbedtls_pk_get_type( const mbedtls_pk_context *ctx );

/**
 * \brief           Merge key types with the same representation
 *
 * \param type      Any key type
 * \return          A canonical representative among the types with the
 *                  same key representation. This is \c MBEDTLS_PK_RSA
 *                  for RSA keys using the built-in software engine and
 *                  MBEDTLS_PK_ECKEY for EC keys using the built-in
 *                  software engine. Note that for keys of type
 *                  \c MBEDTLS_PK_OPAQUE, the type does not specify the
 *                  representation.
 */
static inline mbedtls_pk_type_t mbedtls_pk_representation_type( mbedtls_pk_type_t type )
{
    switch( type )
    {
        case MBEDTLS_PK_RSA:
        case MBEDTLS_PK_RSASSA_PSS:
            return( MBEDTLS_PK_RSA );
        case MBEDTLS_PK_ECKEY:
        case MBEDTLS_PK_ECKEY_DH:
        case MBEDTLS_PK_ECDSA:
            return( MBEDTLS_PK_ECKEY );
        default:
            return( type );
    }
}

#if defined(MBEDTLS_RSA_C)
/**
 * Quick access to an RSA context inside a PK context.
 *
 * \warning You must make sure the PK context actually holds a transparent
 * RSA context before using this function! This function is only valid if
 * `mbedtls_pk_get_type(&pk)` is one of \c MBEDTLS_PK_RSA or
 * \c MBEDTLS_PK_RSASSA_PSS.
 */
static inline mbedtls_rsa_context *mbedtls_pk_rsa( const mbedtls_pk_context pk )
{
    mbedtls_pk_type_t type =
        mbedtls_pk_representation_type( mbedtls_pk_get_type( &pk ) );
    if( type == MBEDTLS_PK_RSA )
        return( (mbedtls_rsa_context *)( pk.pk_ctx ) );
    else
        return( NULL );
}
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECP_C)
/**
 * Quick access to an EC context inside a PK context.
 *
 * \warning You must make sure the PK context actually holds a transparent
 * EC context before using this function! This function is only valid if
 * `mbedtls_pk_get_type(&pk)` is one of \c MBEDTLS_PK_ECKEY,
 * \c MBEDTLS_PK_ECKEY_DH or \c MBEDTLS_PK_ECDSA.
 */
static inline mbedtls_ecp_keypair *mbedtls_pk_ec( const mbedtls_pk_context pk )
{
    mbedtls_pk_type_t type =
        mbedtls_pk_representation_type( mbedtls_pk_get_type( &pk ) );
    if( type == MBEDTLS_PK_ECKEY )
        return( (mbedtls_ecp_keypair *)( pk.pk_ctx ) );
    else
        return( NULL );
}
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
/**
 * \brief           Types for RSA-alt abstraction
 */
typedef int (*mbedtls_pk_rsa_alt_decrypt_func)( void *ctx, int mode, size_t *olen,
                    const unsigned char *input, unsigned char *output,
                    size_t output_max_len );
typedef int (*mbedtls_pk_rsa_alt_sign_func)( void *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                    int mode, mbedtls_md_type_t md_alg, unsigned int hashlen,
                    const unsigned char *hash, unsigned char *sig );
typedef size_t (*mbedtls_pk_rsa_alt_key_len_func)( void *ctx );
#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

/**
 * \brief           Return default information associated with the given PK type
 *
 * \param pk_type   PK type to search for.
 *
 * \note            Different PK objects with the same type may have different
 *                  information. This function returns the information needed
 *                  to create a object with the default implementation
 *                  for the given PK operation type (rsa module for an RSA
 *                  context, ecdh module for an ECDH context, ecdsa module for
 *                  an ECDSA context).
 *
 * \return          The PK info associated with the type or NULL if not found.
 */
const mbedtls_pk_info_t *mbedtls_pk_info_from_type( mbedtls_pk_type_t pk_type );

/**
 * \brief           Initialize a mbedtls_pk_context (as NONE)
 */
void mbedtls_pk_init( mbedtls_pk_context *ctx );

/**
 * \brief           Free a mbedtls_pk_context
 */
void mbedtls_pk_free( mbedtls_pk_context *ctx );

/**
 * \brief           Initialize a PK context with the information given
 *                  and allocates the type-specific PK subcontext.
 *
 * \param ctx       Context to initialize. Must be empty (type NONE).
 * \param info      Information to use
 *
 * \return          0 on success,
 *                  MBEDTLS_ERR_PK_BAD_INPUT_DATA on invalid input,
 *                  MBEDTLS_ERR_PK_ALLOC_FAILED on allocation failure.
 *
 * \note            Engines that implement of opaque keys may offer an
 *                  alternative setup function that take engine-dependent
 *                  parameters. If such a function exists, call it
 *                  instead of mbedtls_pk_setup. The implementation-specific
 *                  setup function should call mbedtls_pk_setup internally.
 *
 * \note            For contexts holding an RSA-alt key pair, use
 *                  \c mbedtls_pk_setup_rsa_alt() instead.
 */
int mbedtls_pk_setup( mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info );

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
/**
 * \brief           Initialize an RSA-alt context
 *
 * \param ctx       Context to initialize. Must be empty (type NONE).
 * \param key       RSA key pair pointer
 * \param decrypt_func  Decryption function
 * \param sign_func     Signing function
 * \param key_len_func  Function returning key length in bytes
 *
 * \return          0 on success, or MBEDTLS_ERR_PK_BAD_INPUT_DATA if the
 *                  context wasn't already initialized as RSA_ALT.
 *
 * \note            This function replaces \c mbedtls_pk_setup() for RSA-alt.
 */
int mbedtls_pk_setup_rsa_alt( mbedtls_pk_context *ctx, void * key,
                         mbedtls_pk_rsa_alt_decrypt_func decrypt_func,
                         mbedtls_pk_rsa_alt_sign_func sign_func,
                         mbedtls_pk_rsa_alt_key_len_func key_len_func );
#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

/**
 * \brief           Get the size in bits of the underlying key
 *
 * \param ctx       Context to use
 *
 * \return          Key size in bits, or 0 on error
 */
size_t mbedtls_pk_get_bitlen( const mbedtls_pk_context *ctx );

/**
 * \brief           Get the length in bytes of the underlying key
 * \param ctx       Context to use
 *
 * \note            This returns the minimum number of bytes required to
 *                  store the part of the key that defines its size (modulus
 *                  for RSA, coordinate for ECC). The way the key is stored
 *                  in the context may have a different size.
 *
 * \return          Key length in bytes, or 0 on error
 */
static inline size_t mbedtls_pk_get_len( const mbedtls_pk_context *ctx )
{
    return( ( mbedtls_pk_get_bitlen( ctx ) + 7 ) / 8 );
}

/**
 * \brief           Tell if a context can do the operations given by type
 *
 * \note            This function can be used to identify the type of key
 *                  (e.g. RSA vs ECC), and a superset of permitted
 *                  operations. It is possible that this function returns
 *                  true but some operations are not allowed. For example
 *                  this function always returns true if ctx is an RSA
 *                  context and type is MBEDTLS_PK_RSA, but the key may
 *                  be restricted to any subset of operations among signature,
 *                  verification, encryption and decryption. To determine
 *                  which operations a key allow, attempt the operation and
 *                  check the return status.
 *
 * \param ctx       Context to test
 * \param type      Target type
 *
 * \return          1 if context can do the operations,
 *                  0 otherwise.
 */
int mbedtls_pk_can_do( const mbedtls_pk_context *ctx, mbedtls_pk_type_t type );

/**
 * \brief           Verify signature (including padding if relevant).
 *
 * \param ctx       PK context to use
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 *
 * \return          0 on success (signature is valid),
 *                  MBEDTLS_ERR_PK_SIG_LEN_MISMATCH if the signature is
 *                  valid but its actual length is less than sig_len,
 *                  or a type-specific error code.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  Use \c mbedtls_pk_verify_ext( MBEDTLS_PK_RSASSA_PSS, ... )
 *                  to verify RSASSA_PSS signatures.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            md_alg may be MBEDTLS_MD_NONE, only if hash_len != 0
 */
int mbedtls_pk_verify( mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len );

/**
 * \brief           Verify signature, with options.
 *                  (Includes verification of the padding depending on type.)
 *
 * \param type      Signature type (inc. possible padding type) to verify
 * \param options   Pointer to type-specific options, or NULL
 * \param ctx       PK context to use
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Signature to verify
 * \param sig_len   Signature length
 *
 * \return          0 on success (signature is valid),
 *                  MBEDTLS_ERR_PK_TYPE_MISMATCH if the PK context can't be
 *                  used for this type of signatures,
 *                  MBEDTLS_ERR_PK_SIG_LEN_MISMATCH if the signature is
 *                  valid but its actual length is less than sig_len,
 *                  or a type-specific error code.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            md_alg may be MBEDTLS_MD_NONE, only if hash_len != 0
 *
 * \note            If type is MBEDTLS_PK_RSASSA_PSS, then options must point
 *                  to a mbedtls_pk_rsassa_pss_options structure,
 *                  otherwise it must be NULL.
 */
int mbedtls_pk_verify_ext( mbedtls_pk_type_t type, const void *options,
                   mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len );

/**
 * \brief           Make signature, including padding if relevant.
 *
 * \param ctx       PK context to use - must hold a private key
 * \param md_alg    Hash algorithm used (see notes)
 * \param hash      Hash of the message to sign
 * \param hash_len  Hash length or 0 (see notes)
 * \param sig       Place to write the signature
 * \param sig_len   Number of bytes written to sig
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 on success, or a type-specific error code.
 *
 * \note            The signature buffer \c sig must be of appropriate size
 *                  which can be calculated with \c mbedtls_pk_signature_size.
 *                  Depending on the algorithm, the value returned in
 *                  \c sig_len may be less or equal to the value returned by
 *                  \c mbedtls_pk_signature_size.
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *                  There is no interface in the PK module to make RSASSA-PSS
 *                  signatures yet.
 *
 * \note            If hash_len is 0, then the length associated with md_alg
 *                  is used instead, or an error returned if it is invalid.
 *
 * \note            For RSA, md_alg may be MBEDTLS_MD_NONE if hash_len != 0.
 *                  For ECDSA, md_alg may never be MBEDTLS_MD_NONE.
 */
int mbedtls_pk_sign( mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Calculate the size of a signature made with this key.
 *
 * \param ctx       PK context to use
 *
 * \return          Maximum size in bytes of a signature made with this key.
 */
size_t mbedtls_pk_signature_size( const mbedtls_pk_context *ctx );

/**
 * \brief           Decrypt message (including padding if relevant).
 *
 * \param ctx       PK context to use - must hold a private key
 * \param input     Input to decrypt
 * \param ilen      Input size
 * \param output    Decrypted output
 * \param olen      Decrypted message length
 * \param osize     Size of the output buffer
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *
 * \return          0 on success, or a type-specific error code.
 */
int mbedtls_pk_decrypt( mbedtls_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Encrypt message (including padding if relevant).
 *
 * \param ctx       PK context to use
 * \param input     Message to encrypt
 * \param ilen      Message size
 * \param output    Encrypted output
 * \param olen      Encrypted output length
 * \param osize     Size of the output buffer
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            For RSA keys, the default padding type is PKCS#1 v1.5.
 *
 * \return          0 on success, or a type-specific error code.
 */
int mbedtls_pk_encrypt( mbedtls_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Check if a public-private pair of keys matches.
 *
 * \param pub       Context holding a public key.
 * \param prv       Context holding a private (and public) key.
 *
 * \return          * 0 on success.
 *                  * MBEDTLS_ERR_PK_BAD_INPUT_DATA if one of the contexts
 *                    is ill-formed.
 *                  * MBEDTLS_ERR_PK_TYPE_MISMATCH if the contexts cannot
 *                    represent keys of the same type.
 *                  * MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE if it is impossible
 *                    to determine whether the keys match. This is guaranteed
 *                    not to happen if \c prv is a transparent key pair.
 *                  * Or a type-specific error code.
 *
 * \note            Opaque key types may not implement this function.
 *                  An opaque \c pub never matches a transparent \c prv.
 */
int mbedtls_pk_check_pair( const mbedtls_pk_context *pub, const mbedtls_pk_context *prv );

/**
 * \brief           Export debug information
 *
 * \param ctx       Context to use
 * \param items     Place to write debug items
 *
 * \return          * 0 on success.
 *                  * MBEDTLS_ERR_PK_BAD_INPUT_DATA if the context is ill-formed.
 *                  * MBEDTLS_ERR_PK_TYPE_MISMATCH if the context does not
 *                    support exporting debug information.
 *                  * Or a type-specific error code.
 */
int mbedtls_pk_debug( const mbedtls_pk_context *ctx, mbedtls_pk_debug_item *items );

/**@}*/


#if defined(MBEDTLS_PK_PARSE_C)
/** \ingroup pk_module */
/**
 * \brief           Parse a private key in PEM or DER format
 *
 * \param ctx       key to be initialized
 * \param key       input buffer
 * \param keylen    size of the buffer
 *                  (including the terminating null byte for PEM data)
 * \param pwd       password for decryption (optional)
 * \param pwdlen    size of the password
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedtls_pk_init() or reset with mbedtls_pk_free(). If you need a
 *                  specific key type, check the result with mbedtls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedtls_pk_parse_key( mbedtls_pk_context *ctx,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *pwd, size_t pwdlen );

/** \ingroup pk_module */
/**
 * \brief           Parse a public key in PEM or DER format
 *
 * \param ctx       key to be initialized
 * \param key       input buffer
 * \param keylen    size of the buffer
 *                  (including the terminating null byte for PEM data)
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedtls_pk_init() or reset with mbedtls_pk_free(). If you need a
 *                  specific key type, check the result with mbedtls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedtls_pk_parse_public_key( mbedtls_pk_context *ctx,
                         const unsigned char *key, size_t keylen );

#if defined(MBEDTLS_FS_IO)
/** \ingroup pk_module */
/**
 * \brief           Load and parse a private key
 *
 * \param ctx       key to be initialized
 * \param path      filename to read the private key from
 * \param password  password to decrypt the file (can be NULL)
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedtls_pk_init() or reset with mbedtls_pk_free(). If you need a
 *                  specific key type, check the result with mbedtls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedtls_pk_parse_keyfile( mbedtls_pk_context *ctx,
                      const char *path, const char *password );

/** \ingroup pk_module */
/**
 * \brief           Load and parse a public key
 *
 * \param ctx       key to be initialized
 * \param path      filename to read the public key from
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedtls_pk_init() or reset with mbedtls_pk_free(). If
 *                  you need a specific key type, check the result with
 *                  mbedtls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedtls_pk_parse_public_keyfile( mbedtls_pk_context *ctx, const char *path );
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_PK_PARSE_C */



#if defined(MBEDTLS_PK_WRITE_C)
/** \name Key pair serialization */
/**@{*/

/**
 * \brief           Write a private key to a PKCS#1 or SEC1 DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       private to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int mbedtls_pk_write_key_der( mbedtls_pk_context *ctx, unsigned char *buf, size_t size );

/**
 * \brief           Write a public key to a SubjectPublicKeyInfo DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       public key to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int mbedtls_pk_write_pubkey_der( mbedtls_pk_context *ctx, unsigned char *buf, size_t size );

#if defined(MBEDTLS_PEM_WRITE_C)
/**
 * \brief           Write a public key to a PEM string
 *
 * \param ctx       public key to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 if successful, or a specific error code
 */
int mbedtls_pk_write_pubkey_pem( mbedtls_pk_context *ctx, unsigned char *buf, size_t size );

/**
 * \brief           Write a private key to a PKCS#1 or SEC1 PEM string
 *
 * \param ctx       private to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 if successful, or a specific error code
 */
int mbedtls_pk_write_key_pem( mbedtls_pk_context *ctx, unsigned char *buf, size_t size );
#endif /* MBEDTLS_PEM_WRITE_C */
/**@}*/
#endif /* MBEDTLS_PK_WRITE_C */

/** \name Low-level functions */
/**@{*/
/**
 * \warning You probably do not want to use these unless you are certain you do ;)
 */

#if defined(MBEDTLS_PK_PARSE_C)
/**
 * \brief           Parse a SubjectPublicKeyInfo DER structure
 *
 * \param p         the position in the ASN.1 data
 * \param end       end of the buffer
 * \param pk        the key to fill
 *
 * \return          0 if successful, or a specific PK error code
 */
int mbedtls_pk_parse_subpubkey( unsigned char **p, const unsigned char *end,
                        mbedtls_pk_context *pk );
#endif /* MBEDTLS_PK_PARSE_C */

#if defined(MBEDTLS_PK_WRITE_C)
/**
 * \brief           Write a subjectPublicKey to ASN.1 data
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param key       public key to write away
 *
 * \return          the length written or a negative error code
 */
int mbedtls_pk_write_pubkey( unsigned char **p, unsigned char *start,
                     const mbedtls_pk_context *key );
#endif /* MBEDTLS_PK_WRITE_C */

/*
 * Internal module functions. You probably do not want to use these unless you
 * know you do.
 */
#if defined(MBEDTLS_FS_IO)
int mbedtls_pk_load_file( const char *path, unsigned char **buf, size_t *n );
#endif

/**@}*/

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PK_H */
