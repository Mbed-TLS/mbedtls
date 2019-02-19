/**
 * \file psa/crypto.h
 * \brief Platform Security Architecture cryptography module
 */
/*
 *  Copyright (C) 2018, ARM Limited, All Rights Reserved
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
 */

#ifndef PSA_CRYPTO_H
#define PSA_CRYPTO_H

#include "crypto_platform.h"

#include <stddef.h>

#ifdef __DOXYGEN_ONLY__
/* This __DOXYGEN_ONLY__ block contains mock definitions for things that
 * must be defined in the crypto_platform.h header. These mock definitions
 * are present in this file as a convenience to generate pretty-printed
 * documentation that includes those definitions. */

/** \defgroup platform Implementation-specific definitions
 * @{
 */

/** \brief Key handle.
 *
 * This type represents open handles to keys. It must be an unsigned integral
 * type. The choice of type is implementation-dependent.
 *
 * 0 is not a valid key handle. How other handle values are assigned is
 * implementation-dependent.
 */
typedef _unsigned_integral_type_ psa_key_handle_t;

/**@}*/
#endif /* __DOXYGEN_ONLY__ */

#ifdef __cplusplus
extern "C" {
#endif

/* The file "crypto_types.h" declares types that encode errors,
 * algorithms, key types, policies, etc. */
#include "crypto_types.h"

/* The file "crypto_values.h" declares macros to build and analyze values
 * of integral types defined in "crypto_types.h". */
#include "crypto_values.h"

/** \defgroup initialization Library initialization
 * @{
 */

/**
 * \brief Library initialization.
 *
 * Applications must call this function before calling any other
 * function in this module.
 *
 * Applications may call this function more than once. Once a call
 * succeeds, subsequent calls are guaranteed to succeed.
 *
 * If the application calls other functions before calling psa_crypto_init(),
 * the behavior is undefined. Implementations are encouraged to either perform
 * the operation as if the library had been initialized or to return
 * #PSA_ERROR_BAD_STATE or some other applicable error. In particular,
 * implementations should not return a success status if the lack of
 * initialization may have security implications, for example due to improper
 * seeding of the random number generator.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_INSUFFICIENT_ENTROPY
 */
psa_status_t psa_crypto_init(void);

/**@}*/

/** \defgroup policy Key policies
 * @{
 */

/** The type of the key policy data structure.
 *
 * Before calling any function on a key policy, the application must initialize
 * it by any of the following means:
 * - Set the structure to all-bits-zero, for example:
 *   \code
 *   psa_key_policy_t policy;
 *   memset(&policy, 0, sizeof(policy));
 *   \endcode
 * - Initialize the structure to logical zero values, for example:
 *   \code
 *   psa_key_policy_t policy = {0};
 *   \endcode
 * - Initialize the structure to the initializer #PSA_KEY_POLICY_INIT,
 *   for example:
 *   \code
 *   psa_key_policy_t policy = PSA_KEY_POLICY_INIT;
 *   \endcode
 * - Assign the result of the function psa_key_policy_init()
 *   to the structure, for example:
 *   \code
 *   psa_key_policy_t policy;
 *   policy = psa_key_policy_init();
 *   \endcode
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_key_policy_s psa_key_policy_t;

/** \def PSA_KEY_POLICY_INIT
 *
 * This macro returns a suitable initializer for a key policy object of type
 * #psa_key_policy_t.
 */
#ifdef __DOXYGEN_ONLY__
/* This is an example definition for documentation purposes.
 * Implementations should define a suitable value in `crypto_struct.h`.
 */
#define PSA_KEY_POLICY_INIT {0}
#endif

/** Return an initial value for a key policy that forbids all usage of the key.
 */
static psa_key_policy_t psa_key_policy_init(void);

/** \brief Set the standard fields of a policy structure.
 *
 * Note that this function does not make any consistency check of the
 * parameters. The values are only checked when applying the policy to
 * a key slot with psa_set_key_policy().
 *
 * \param[in,out] policy The key policy to modify. It must have been
 *                       initialized as per the documentation for
 *                       #psa_key_policy_t.
 * \param usage          The permitted uses for the key.
 * \param alg            The algorithm that the key may be used for.
 */
void psa_key_policy_set_usage(psa_key_policy_t *policy,
                              psa_key_usage_t usage,
                              psa_algorithm_t alg);

/** \brief Retrieve the usage field of a policy structure.
 *
 * \param[in] policy    The policy object to query.
 *
 * \return The permitted uses for a key with this policy.
 */
psa_key_usage_t psa_key_policy_get_usage(const psa_key_policy_t *policy);

/** \brief Retrieve the algorithm field of a policy structure.
 *
 * \param[in] policy    The policy object to query.
 *
 * \return The permitted algorithm for a key with this policy.
 */
psa_algorithm_t psa_key_policy_get_algorithm(const psa_key_policy_t *policy);

/** \brief Set the usage policy on a key slot.
 *
 * This function must be called on an empty key slot, before importing,
 * generating or creating a key in the slot. Changing the policy of an
 * existing key is not permitted.
 *
 * Implementations may set restrictions on supported key policies
 * depending on the key type and the key slot.
 *
 * \param handle        Handle to the key whose policy is to be changed.
 * \param[in] policy    The policy object to query.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 *         If the key is persistent, it is implementation-defined whether
 *         the policy has been saved to persistent storage. Implementations
 *         may defer saving the policy until the key material is created.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_ALREADY_EXISTS
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_set_key_policy(psa_key_handle_t handle,
                                const psa_key_policy_t *policy);

/** \brief Get the usage policy for a key slot.
 *
 * \param handle        Handle to the key slot whose policy is being queried.
 * \param[out] policy   On success, the key's policy.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_get_key_policy(psa_key_handle_t handle,
                                psa_key_policy_t *policy);

/**@}*/

/** \defgroup key_management Key management
 * @{
 */

/** \brief Retrieve the lifetime of an open key.
 *
 * \param handle        Handle to query.
 * \param[out] lifetime On success, the lifetime value.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_get_key_lifetime(psa_key_handle_t handle,
                                  psa_key_lifetime_t *lifetime);


/** Allocate a key slot for a transient key, i.e. a key which is only stored
 * in volatile memory.
 *
 * The allocated key slot and its handle remain valid until the
 * application calls psa_close_key() or psa_destroy_key() or until the
 * application terminates.
 *
 * \param[out] handle   On success, a handle to a volatile key slot.
 *
 * \retval #PSA_SUCCESS
 *         Success. The application can now use the value of `*handle`
 *         to access the newly allocated key slot.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *         There was not enough memory, or the maximum number of key slots
 *         has been reached.
 */
psa_status_t psa_allocate_key(psa_key_handle_t *handle);

/** Open a handle to an existing persistent key.
 *
 * Open a handle to a key which was previously created with psa_create_key().
 *
 * \param lifetime      The lifetime of the key. This designates a storage
 *                      area where the key material is stored. This must not
 *                      be #PSA_KEY_LIFETIME_VOLATILE.
 * \param id            The persistent identifier of the key.
 * \param[out] handle   On success, a handle to a key slot which contains
 *                      the data and metadata loaded from the specified
 *                      persistent location.
 *
 * \retval #PSA_SUCCESS
 *         Success. The application can now use the value of `*handle`
 *         to access the newly allocated key slot.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p lifetime is invalid, for example #PSA_KEY_LIFETIME_VOLATILE.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p id is invalid for the specified lifetime.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p lifetime is not supported.
 * \retval #PSA_ERROR_NOT_PERMITTED
 *         The specified key exists, but the application does not have the
 *         permission to access it. Note that this specification does not
 *         define any way to create such a key, but it may be possible
 *         through implementation-specific means.
 */
psa_status_t psa_open_key(psa_key_lifetime_t lifetime,
                          psa_key_id_t id,
                          psa_key_handle_t *handle);

/** Create a new persistent key slot.
 *
 * Create a new persistent key slot and return a handle to it. The handle
 * remains valid until the application calls psa_close_key() or terminates.
 * The application can open the key again with psa_open_key() until it
 * removes the key by calling psa_destroy_key().
 *
 * \param lifetime      The lifetime of the key. This designates a storage
 *                      area where the key material is stored. This must not
 *                      be #PSA_KEY_LIFETIME_VOLATILE.
 * \param id            The persistent identifier of the key.
 * \param[out] handle   On success, a handle to the newly created key slot.
 *                      When key material is later created in this key slot,
 *                      it will be saved to the specified persistent location.
 *
 * \retval #PSA_SUCCESS
 *         Success. The application can now use the value of `*handle`
 *         to access the newly allocated key slot.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_INSUFFICIENT_STORAGE
 * \retval #PSA_ERROR_ALREADY_EXISTS
 *         There is already a key with the identifier \p id in the storage
 *         area designated by \p lifetime.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p lifetime is invalid, for example #PSA_KEY_LIFETIME_VOLATILE.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p id is invalid for the specified lifetime.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p lifetime is not supported.
 * \retval #PSA_ERROR_NOT_PERMITTED
 *         \p lifetime is valid, but the application does not have the
 *         permission to create a key there.
 */
psa_status_t psa_create_key(psa_key_lifetime_t lifetime,
                            psa_key_id_t id,
                            psa_key_handle_t *handle);

/** Close a key handle.
 *
 * If the handle designates a volatile key, destroy the key material and
 * free all associated resources, just like psa_destroy_key().
 *
 * If the handle designates a persistent key, free all resources associated
 * with the key in volatile memory. The key slot in persistent storage is
 * not affected and can be opened again later with psa_open_key().
 *
 * \param handle        The key handle to close.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 */
psa_status_t psa_close_key(psa_key_handle_t handle);

/**@}*/

/** \defgroup import_export Key import and export
 * @{
 */

/**
 * \brief Import a key in binary format.
 *
 * This function supports any output from psa_export_key(). Refer to the
 * documentation of psa_export_public_key() for the format of public keys
 * and to the documentation of psa_export_key() for the format for
 * other key types.
 *
 * This specification supports a single format for each key type.
 * Implementations may support other formats as long as the standard
 * format is supported. Implementations that support other formats
 * should ensure that the formats are clearly unambiguous so as to
 * minimize the risk that an invalid input is accidentally interpreted
 * according to a different format.
 *
 * \param handle      Handle to the slot where the key will be stored.
 *                    It must have been obtained by calling
 *                    psa_allocate_key() or psa_create_key() and must
 *                    not contain key material yet.
 * \param type        Key type (a \c PSA_KEY_TYPE_XXX value). On a successful
 *                    import, the key slot will contain a key of this type.
 * \param[in] data    Buffer containing the key data. The content of this
 *                    buffer is interpreted according to \p type. It must
 *                    contain the format described in the documentation
 *                    of psa_export_key() or psa_export_public_key() for
 *                    the chosen type.
 * \param data_length Size of the \p data buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 *         If the key is persistent, the key material and the key's metadata
 *         have been saved to persistent storage.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The key type or key size is not supported, either by the
 *         implementation in general or in this particular slot.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key slot is invalid,
 *         or the key data is not correctly formatted.
 * \retval #PSA_ERROR_ALREADY_EXISTS
 *         There is already a key in the specified slot.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_INSUFFICIENT_STORAGE
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_STORAGE_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_import_key(psa_key_handle_t handle,
                            psa_key_type_t type,
                            const uint8_t *data,
                            size_t data_length);

/**
 * \brief Destroy a key.
 *
 * This function destroys the content of the key slot from both volatile
 * memory and, if applicable, non-volatile storage. Implementations shall
 * make a best effort to ensure that any previous content of the slot is
 * unrecoverable.
 *
 * This function also erases any metadata such as policies and frees all
 * resources associated with the key.
 *
 * \param handle        Handle to the key slot to erase.
 *
 * \retval #PSA_SUCCESS
 *         The slot's content, if any, has been erased.
 * \retval #PSA_ERROR_NOT_PERMITTED
 *         The slot holds content and cannot be erased because it is
 *         read-only, either due to a policy or due to physical restrictions.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 *         There was an failure in communication with the cryptoprocessor.
 *         The key material may still be present in the cryptoprocessor.
 * \retval #PSA_ERROR_STORAGE_FAILURE
 *         The storage is corrupted. Implementations shall make a best effort
 *         to erase key material even in this stage, however applications
 *         should be aware that it may be impossible to guarantee that the
 *         key material is not recoverable in such cases.
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 *         An unexpected condition which is not a storage corruption or
 *         a communication failure occurred. The cryptoprocessor may have
 *         been compromised.
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_destroy_key(psa_key_handle_t handle);

/**
 * \brief Get basic metadata about a key.
 *
 * \param handle        Handle to the key slot to query.
 * \param[out] type     On success, the key type (a \c PSA_KEY_TYPE_XXX value).
 *                      This may be a null pointer, in which case the key type
 *                      is not written.
 * \param[out] bits     On success, the key size in bits.
 *                      This may be a null pointer, in which case the key size
 *                      is not written.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 *         The handle is to a key slot which does not contain key material yet.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_get_key_information(psa_key_handle_t handle,
                                     psa_key_type_t *type,
                                     size_t *bits);

/**
 * \brief Export a key in binary format.
 *
 * The output of this function can be passed to psa_import_key() to
 * create an equivalent object.
 *
 * If the implementation of psa_import_key() supports other formats
 * beyond the format specified here, the output from psa_export_key()
 * must use the representation specified here, not the original
 * representation.
 *
 * For standard key types, the output format is as follows:
 *
 * - For symmetric keys (including MAC keys), the format is the
 *   raw bytes of the key.
 * - For DES, the key data consists of 8 bytes. The parity bits must be
 *   correct.
 * - For Triple-DES, the format is the concatenation of the
 *   two or three DES keys.
 * - For RSA key pairs (#PSA_KEY_TYPE_RSA_KEYPAIR), the format
 *   is the non-encrypted DER encoding of the representation defined by
 *   PKCS\#1 (RFC 8017) as `RSAPrivateKey`, version 0.
 *   ```
 *   RSAPrivateKey ::= SEQUENCE {
 *       version             INTEGER,  -- must be 0
 *       modulus             INTEGER,  -- n
 *       publicExponent      INTEGER,  -- e
 *       privateExponent     INTEGER,  -- d
 *       prime1              INTEGER,  -- p
 *       prime2              INTEGER,  -- q
 *       exponent1           INTEGER,  -- d mod (p-1)
 *       exponent2           INTEGER,  -- d mod (q-1)
 *       coefficient         INTEGER,  -- (inverse of q) mod p
 *   }
 *   ```
 * - For DSA private keys (#PSA_KEY_TYPE_DSA_KEYPAIR), the format
 *   is the non-encrypted DER encoding of the representation used by
 *   OpenSSL and OpenSSH, whose structure is described in ASN.1 as follows:
 *   ```
 *   DSAPrivateKey ::= SEQUENCE {
 *       version             INTEGER,  -- must be 0
 *       prime               INTEGER,  -- p
 *       subprime            INTEGER,  -- q
 *       generator           INTEGER,  -- g
 *       public              INTEGER,  -- y
 *       private             INTEGER,  -- x
 *   }
 *   ```
 * - For elliptic curve key pairs (key types for which
 *   #PSA_KEY_TYPE_IS_ECC_KEYPAIR is true), the format is
 *   a representation of the private value as a `ceiling(m/8)`-byte string
 *   where `m` is the bit size associated with the curve, i.e. the bit size
 *   of the order of the curve's coordinate field. This byte string is
 *   in little-endian order for Montgomery curves (curve types
 *   `PSA_ECC_CURVE_CURVEXXX`), and in big-endian order for Weierstrass
 *   curves (curve types `PSA_ECC_CURVE_SECTXXX`, `PSA_ECC_CURVE_SECPXXX`
 *   and `PSA_ECC_CURVE_BRAINPOOL_PXXX`).
 *   This is the content of the `privateKey` field of the `ECPrivateKey`
 *   format defined by RFC 5915.
 * - For public keys (key types for which #PSA_KEY_TYPE_IS_PUBLIC_KEY is
 *   true), the format is the same as for psa_export_public_key().
 *
 * \param handle            Handle to the key to export.
 * \param[out] data         Buffer where the key data is to be written.
 * \param data_size         Size of the \p data buffer in bytes.
 * \param[out] data_length  On success, the number of bytes
 *                          that make up the key data.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 * \retval #PSA_ERROR_NOT_PERMITTED
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p data buffer is too small. You can determine a
 *         sufficient buffer size by calling
 *         #PSA_KEY_EXPORT_MAX_SIZE(\c type, \c bits)
 *         where \c type is the key type
 *         and \c bits is the key size in bits.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_export_key(psa_key_handle_t handle,
                            uint8_t *data,
                            size_t data_size,
                            size_t *data_length);

/**
 * \brief Export a public key or the public part of a key pair in binary format.
 *
 * The output of this function can be passed to psa_import_key() to
 * create an object that is equivalent to the public key.
 *
 * This specification supports a single format for each key type.
 * Implementations may support other formats as long as the standard
 * format is supported. Implementations that support other formats
 * should ensure that the formats are clearly unambiguous so as to
 * minimize the risk that an invalid input is accidentally interpreted
 * according to a different format.
 *
 * For standard key types, the output format is as follows:
 * - For RSA public keys (#PSA_KEY_TYPE_RSA_PUBLIC_KEY), the DER encoding of
 *   the representation defined by RFC 3279 &sect;2.3.1 as `RSAPublicKey`.
 *   ```
 *   RSAPublicKey ::= SEQUENCE {
 *      modulus            INTEGER,    -- n
 *      publicExponent     INTEGER  }  -- e
 *   ```
 * - For elliptic curve public keys (key types for which
 *   #PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY is true), the format is the uncompressed
 *   representation defined by SEC1 &sect;2.3.3 as the content of an ECPoint:
 *   Let `m` be the bit size associated with the curve, i.e. the bit size of
 *   `q` for a curve over `F_q`. The representation consists of:
 *      - The byte 0x04;
 *      - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
 *      - `y_P` as a `ceiling(m/8)`-byte string, big-endian.
 *
 * For other public key types, the format is the DER representation defined by
 * RFC 5280 as `SubjectPublicKeyInfo`, with the `subjectPublicKey` format
 * specified below.
 * ```
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm          AlgorithmIdentifier,
 *      subjectPublicKey   BIT STRING  }
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm          OBJECT IDENTIFIER,
 *      parameters         ANY DEFINED BY algorithm OPTIONAL  }
 * ```
 * - For DSA public keys (#PSA_KEY_TYPE_DSA_PUBLIC_KEY),
 *   the `subjectPublicKey` format is defined by RFC 3279 &sect;2.3.2 as
 *   `DSAPublicKey`,
 *   with the OID `id-dsa`,
 *   and with the parameters `DSS-Parms`.
 *   ```
 *   id-dsa OBJECT IDENTIFIER ::= {
 *      iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 1 }
 *
 *   Dss-Parms  ::=  SEQUENCE  {
 *      p                  INTEGER,
 *      q                  INTEGER,
 *      g                  INTEGER  }
 *   DSAPublicKey ::= INTEGER -- public key, Y
 *   ```
 *
 * \param handle            Handle to the key to export.
 * \param[out] data         Buffer where the key data is to be written.
 * \param data_size         Size of the \p data buffer in bytes.
 * \param[out] data_length  On success, the number of bytes
 *                          that make up the key data.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key is neither a public key nor a key pair.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p data buffer is too small. You can determine a
 *         sufficient buffer size by calling
 *         #PSA_KEY_EXPORT_MAX_SIZE(#PSA_KEY_TYPE_PUBLIC_KEY_OF_KEYPAIR(\c type), \c bits)
 *         where \c type is the key type
 *         and \c bits is the key size in bits.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_export_public_key(psa_key_handle_t handle,
                                   uint8_t *data,
                                   size_t data_size,
                                   size_t *data_length);

/** Make a copy of a key.
 *
 * Copy key material from one location to another.
 *
 * This function is primarily useful to copy a key from one location
 * to another, since it populates a key using the material from
 * another key which may have a different lifetime.
 *
 * In an implementation where slots have different ownerships,
 * this function may be used to share a key with a different party,
 * subject to implementation-defined restrictions on key sharing.
 * In this case \p constraint would typically prevent the recipient
 * from exporting the key.
 *
 * The resulting key may only be used in a way that conforms to all
 * three of: the policy of the source key, the policy previously set
 * on the target, and the \p constraint parameter passed when calling
 * this function.
 * - The usage flags on the resulting key are the bitwise-and of the
 *   usage flags on the source policy, the previously-set target policy
 *   and the policy constraint.
 * - If all three policies allow the same algorithm or wildcard-based
 *   algorithm policy, the resulting key has the same algorithm policy.
 * - If one of the policies allows an algorithm and all the other policies
 *   either allow the same algorithm or a wildcard-based algorithm policy
 *   that includes this algorithm, the resulting key allows the same
 *   algorithm.
 *
 * The effect of this function on implementation-defined metadata is
 * implementation-defined.
 *
 * \param source_handle     The key to copy. It must be a handle to an
 *                          occupied slot.
 * \param target_handle     A handle to the target slot. It must not contain
 *                          key material yet.
 * \param[in] constraint    An optional policy constraint. If this parameter
 *                          is non-null then the resulting key will conform
 *                          to this policy in addition to the source policy
 *                          and the policy already present on the target
 *                          slot. If this parameter is null then the
 *                          function behaves in the same way as if it was
 *                          the target policy, i.e. only the source and
 *                          target policies apply.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_ALREADY_EXISTS
 *         \p target already contains key material.
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 *         \p source does not contain key material.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The policy constraints on the source, on the target and
 *         \p constraints are incompatible.
 * \retval #PSA_ERROR_NOT_PERMITTED
 *         The source key is not exportable and its lifetime does not
 *         allow copying it to the target's lifetime.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_INSUFFICIENT_STORAGE
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_copy_key(psa_key_handle_t source_handle,
                          psa_key_handle_t target_handle,
                          const psa_key_policy_t *constraint);

/**@}*/

/** \defgroup hash Message digests
 * @{
 */

/** The type of the state data structure for multipart hash operations.
 *
 * Before calling any function on a hash operation object, the application must
 * initialize it by any of the following means:
 * - Set the structure to all-bits-zero, for example:
 *   \code
 *   psa_hash_operation_t operation;
 *   memset(&operation, 0, sizeof(operation));
 *   \endcode
 * - Initialize the structure to logical zero values, for example:
 *   \code
 *   psa_hash_operation_t operation = {0};
 *   \endcode
 * - Initialize the structure to the initializer #PSA_HASH_OPERATION_INIT,
 *   for example:
 *   \code
 *   psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
 *   \endcode
 * - Assign the result of the function psa_hash_operation_init()
 *   to the structure, for example:
 *   \code
 *   psa_hash_operation_t operation;
 *   operation = psa_hash_operation_init();
 *   \endcode
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_hash_operation_s psa_hash_operation_t;

/** \def PSA_HASH_OPERATION_INIT
 *
 * This macro returns a suitable initializer for a hash operation object
 * of type #psa_hash_operation_t.
 */
#ifdef __DOXYGEN_ONLY__
/* This is an example definition for documentation purposes.
 * Implementations should define a suitable value in `crypto_struct.h`.
 */
#define PSA_HASH_OPERATION_INIT {0}
#endif

/** Return an initial value for a hash operation object.
 */
static psa_hash_operation_t psa_hash_operation_init(void);

/** Set up a multipart hash operation.
 *
 * The sequence of operations to calculate a hash (message digest)
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Initialize the operation object with one of the methods described in the
 *    documentation for #psa_hash_operation_t, e.g. PSA_HASH_OPERATION_INIT.
 * -# Call psa_hash_setup() to specify the algorithm.
 * -# Call psa_hash_update() zero, one or more times, passing a fragment
 *    of the message each time. The hash that is calculated is the hash
 *    of the concatenation of these messages in order.
 * -# To calculate the hash, call psa_hash_finish().
 *    To compare the hash with an expected value, call psa_hash_verify().
 *
 * The application may call psa_hash_abort() at any time after the operation
 * has been initialized.
 *
 * After a successful call to psa_hash_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_hash_update().
 * - A call to psa_hash_finish(), psa_hash_verify() or psa_hash_abort().
 *
 * \param[in,out] operation The operation object to set up. It must have
 *                          been initialized as per the documentation for
 *                          #psa_hash_operation_t and not yet in use.
 * \param alg               The hash algorithm to compute (\c PSA_ALG_XXX value
 *                          such that #PSA_ALG_IS_HASH(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported or is not a hash algorithm.
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (already set up and not
 *         subsequently completed).
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_hash_setup(psa_hash_operation_t *operation,
                            psa_algorithm_t alg);

/** Add a message fragment to a multipart hash operation.
 *
 * The application must call psa_hash_setup() before calling this function.
 *
 * If this function returns an error status, the operation becomes inactive.
 *
 * \param[in,out] operation Active hash operation.
 * \param[in] input         Buffer containing the message fragment to hash.
 * \param input_length      Size of the \p input buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (not set up, or already completed).
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_hash_update(psa_hash_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length);

/** Finish the calculation of the hash of a message.
 *
 * The application must call psa_hash_setup() before calling this function.
 * This function calculates the hash of the message formed by concatenating
 * the inputs passed to preceding calls to psa_hash_update().
 *
 * When this function returns, the operation becomes inactive.
 *
 * \warning Applications should not call this function if they expect
 *          a specific value for the hash. Call psa_hash_verify() instead.
 *          Beware that comparing integrity or authenticity data such as
 *          hash values with a function such as \c memcmp is risky
 *          because the time taken by the comparison may leak information
 *          about the hashed data which could allow an attacker to guess
 *          a valid hash and thereby bypass security controls.
 *
 * \param[in,out] operation     Active hash operation.
 * \param[out] hash             Buffer where the hash is to be written.
 * \param hash_size             Size of the \p hash buffer in bytes.
 * \param[out] hash_length      On success, the number of bytes
 *                              that make up the hash value. This is always
 *                              #PSA_HASH_SIZE(\c alg) where \c alg is the
 *                              hash algorithm that is calculated.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (not set up, or already completed).
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p hash buffer is too small. You can determine a
 *         sufficient buffer size by calling #PSA_HASH_SIZE(\c alg)
 *         where \c alg is the hash algorithm that is calculated.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_hash_finish(psa_hash_operation_t *operation,
                             uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length);

/** Finish the calculation of the hash of a message and compare it with
 * an expected value.
 *
 * The application must call psa_hash_setup() before calling this function.
 * This function calculates the hash of the message formed by concatenating
 * the inputs passed to preceding calls to psa_hash_update(). It then
 * compares the calculated hash with the expected hash passed as a
 * parameter to this function.
 *
 * When this function returns, the operation becomes inactive.
 *
 * \note Implementations shall make the best effort to ensure that the
 * comparison between the actual hash and the expected hash is performed
 * in constant time.
 *
 * \param[in,out] operation     Active hash operation.
 * \param[in] hash              Buffer containing the expected hash value.
 * \param hash_length           Size of the \p hash buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         The expected hash is identical to the actual hash of the message.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The hash of the message was calculated successfully, but it
 *         differs from the expected hash.
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (not set up, or already completed).
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_hash_verify(psa_hash_operation_t *operation,
                             const uint8_t *hash,
                             size_t hash_length);

/** Abort a hash operation.
 *
 * Aborting an operation frees all associated resources except for the
 * \p operation structure itself. Once aborted, the operation object
 * can be reused for another operation by calling
 * psa_hash_setup() again.
 *
 * You may call this function any time after the operation object has
 * been initialized by any of the following methods:
 * - A call to psa_hash_setup(), whether it succeeds or not.
 * - Initializing the \c struct to all-bits-zero.
 * - Initializing the \c struct to logical zeros, e.g.
 *   `psa_hash_operation_t operation = {0}`.
 *
 * In particular, calling psa_hash_abort() after the operation has been
 * terminated by a call to psa_hash_abort(), psa_hash_finish() or
 * psa_hash_verify() is safe and has no effect.
 *
 * \param[in,out] operation     Initialized hash operation.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_BAD_STATE
 *         \p operation is not an active hash operation.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_hash_abort(psa_hash_operation_t *operation);

/** Clone a hash operation.
 *
 * This function copies the state of an ongoing hash operation to
 * a new operation object. In other words, this function is equivalent
 * to calling psa_hash_setup() on \p target_operation with the same
 * algorithm that \p source_operation was set up for, then
 * psa_hash_update() on \p target_operation with the same input that
 * that was passed to \p source_operation. After this function returns, the
 * two objects are independent, i.e. subsequent calls involving one of
 * the objects do not affect the other object.
 *
 * \param[in] source_operation      The active hash operation to clone.
 * \param[in,out] target_operation  The operation object to set up.
 *                                  It must be initialized but not active.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_BAD_STATE
 *         \p source_operation is not an active hash operation.
 * \retval #PSA_ERROR_BAD_STATE
 *         \p target_operation is active.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_hash_clone(const psa_hash_operation_t *source_operation,
                            psa_hash_operation_t *target_operation);

/**@}*/

/** \defgroup MAC Message authentication codes
 * @{
 */

/** The type of the state data structure for multipart MAC operations.
 *
 * Before calling any function on a MAC operation object, the application must
 * initialize it by any of the following means:
 * - Set the structure to all-bits-zero, for example:
 *   \code
 *   psa_mac_operation_t operation;
 *   memset(&operation, 0, sizeof(operation));
 *   \endcode
 * - Initialize the structure to logical zero values, for example:
 *   \code
 *   psa_mac_operation_t operation = {0};
 *   \endcode
 * - Initialize the structure to the initializer #PSA_MAC_OPERATION_INIT,
 *   for example:
 *   \code
 *   psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
 *   \endcode
 * - Assign the result of the function psa_mac_operation_init()
 *   to the structure, for example:
 *   \code
 *   psa_mac_operation_t operation;
 *   operation = psa_mac_operation_init();
 *   \endcode
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_mac_operation_s psa_mac_operation_t;

/** \def PSA_MAC_OPERATION_INIT
 *
 * This macro returns a suitable initializer for a MAC operation object of type
 * #psa_mac_operation_t.
 */
#ifdef __DOXYGEN_ONLY__
/* This is an example definition for documentation purposes.
 * Implementations should define a suitable value in `crypto_struct.h`.
 */
#define PSA_MAC_OPERATION_INIT {0}
#endif

/** Return an initial value for a MAC operation object.
 */
static psa_mac_operation_t psa_mac_operation_init(void);

/** Set up a multipart MAC calculation operation.
 *
 * This function sets up the calculation of the MAC
 * (message authentication code) of a byte string.
 * To verify the MAC of a message against an
 * expected value, use psa_mac_verify_setup() instead.
 *
 * The sequence of operations to calculate a MAC is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Initialize the operation object with one of the methods described in the
 *    documentation for #psa_mac_operation_t, e.g. PSA_MAC_OPERATION_INIT.
 * -# Call psa_mac_sign_setup() to specify the algorithm and key.
 *    The key remains associated with the operation even if the content
 *    of the key slot changes.
 * -# Call psa_mac_update() zero, one or more times, passing a fragment
 *    of the message each time. The MAC that is calculated is the MAC
 *    of the concatenation of these messages in order.
 * -# At the end of the message, call psa_mac_sign_finish() to finish
 *    calculating the MAC value and retrieve it.
 *
 * The application may call psa_mac_abort() at any time after the operation
 * has been initialized.
 *
 * After a successful call to psa_mac_sign_setup(), the application must
 * eventually terminate the operation through one of the following methods:
 * - A failed call to psa_mac_update().
 * - A call to psa_mac_sign_finish() or psa_mac_abort().
 *
 * \param[in,out] operation The operation object to set up. It must have
 *                          been initialized as per the documentation for
 *                          #psa_mac_operation_t and not yet in use.
 * \param handle            Handle to the key to use for the operation.
 * \param alg               The MAC algorithm to compute (\c PSA_ALG_XXX value
 *                          such that #PSA_ALG_IS_MAC(alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 * \retval #PSA_ERROR_NOT_PERMITTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p key is not compatible with \p alg.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported or is not a MAC algorithm.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (already set up and not
 *         subsequently completed).
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_mac_sign_setup(psa_mac_operation_t *operation,
                                psa_key_handle_t handle,
                                psa_algorithm_t alg);

/** Set up a multipart MAC verification operation.
 *
 * This function sets up the verification of the MAC
 * (message authentication code) of a byte string against an expected value.
 *
 * The sequence of operations to verify a MAC is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Initialize the operation object with one of the methods described in the
 *    documentation for #psa_mac_operation_t, e.g. PSA_MAC_OPERATION_INIT.
 * -# Call psa_mac_verify_setup() to specify the algorithm and key.
 *    The key remains associated with the operation even if the content
 *    of the key slot changes.
 * -# Call psa_mac_update() zero, one or more times, passing a fragment
 *    of the message each time. The MAC that is calculated is the MAC
 *    of the concatenation of these messages in order.
 * -# At the end of the message, call psa_mac_verify_finish() to finish
 *    calculating the actual MAC of the message and verify it against
 *    the expected value.
 *
 * The application may call psa_mac_abort() at any time after the operation
 * has been initialized.
 *
 * After a successful call to psa_mac_verify_setup(), the application must
 * eventually terminate the operation through one of the following methods:
 * - A failed call to psa_mac_update().
 * - A call to psa_mac_verify_finish() or psa_mac_abort().
 *
 * \param[in,out] operation The operation object to set up. It must have
 *                          been initialized as per the documentation for
 *                          #psa_mac_operation_t and not yet in use.
 * \param handle            Handle to the key to use for the operation.
 * \param alg               The MAC algorithm to compute (\c PSA_ALG_XXX value
 *                          such that #PSA_ALG_IS_MAC(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 * \retval #PSA_ERROR_NOT_PERMITTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \c key is not compatible with \c alg.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not a MAC algorithm.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (already set up and not
 *         subsequently completed).
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_mac_verify_setup(psa_mac_operation_t *operation,
                                  psa_key_handle_t handle,
                                  psa_algorithm_t alg);

/** Add a message fragment to a multipart MAC operation.
 *
 * The application must call psa_mac_sign_setup() or psa_mac_verify_setup()
 * before calling this function.
 *
 * If this function returns an error status, the operation becomes inactive.
 *
 * \param[in,out] operation Active MAC operation.
 * \param[in] input         Buffer containing the message fragment to add to
 *                          the MAC calculation.
 * \param input_length      Size of the \p input buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (not set up, or already completed).
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_mac_update(psa_mac_operation_t *operation,
                            const uint8_t *input,
                            size_t input_length);

/** Finish the calculation of the MAC of a message.
 *
 * The application must call psa_mac_sign_setup() before calling this function.
 * This function calculates the MAC of the message formed by concatenating
 * the inputs passed to preceding calls to psa_mac_update().
 *
 * When this function returns, the operation becomes inactive.
 *
 * \warning Applications should not call this function if they expect
 *          a specific value for the MAC. Call psa_mac_verify_finish() instead.
 *          Beware that comparing integrity or authenticity data such as
 *          MAC values with a function such as \c memcmp is risky
 *          because the time taken by the comparison may leak information
 *          about the MAC value which could allow an attacker to guess
 *          a valid MAC and thereby bypass security controls.
 *
 * \param[in,out] operation Active MAC operation.
 * \param[out] mac          Buffer where the MAC value is to be written.
 * \param mac_size          Size of the \p mac buffer in bytes.
 * \param[out] mac_length   On success, the number of bytes
 *                          that make up the MAC value. This is always
 *                          #PSA_MAC_FINAL_SIZE(\c key_type, \c key_bits, \c alg)
 *                          where \c key_type and \c key_bits are the type and
 *                          bit-size respectively of the key and \c alg is the
 *                          MAC algorithm that is calculated.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (not set up, or already completed).
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p mac buffer is too small. You can determine a
 *         sufficient buffer size by calling PSA_MAC_FINAL_SIZE().
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_mac_sign_finish(psa_mac_operation_t *operation,
                                 uint8_t *mac,
                                 size_t mac_size,
                                 size_t *mac_length);

/** Finish the calculation of the MAC of a message and compare it with
 * an expected value.
 *
 * The application must call psa_mac_verify_setup() before calling this function.
 * This function calculates the MAC of the message formed by concatenating
 * the inputs passed to preceding calls to psa_mac_update(). It then
 * compares the calculated MAC with the expected MAC passed as a
 * parameter to this function.
 *
 * When this function returns, the operation becomes inactive.
 *
 * \note Implementations shall make the best effort to ensure that the
 * comparison between the actual MAC and the expected MAC is performed
 * in constant time.
 *
 * \param[in,out] operation Active MAC operation.
 * \param[in] mac           Buffer containing the expected MAC value.
 * \param mac_length        Size of the \p mac buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         The expected MAC is identical to the actual MAC of the message.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The MAC of the message was calculated successfully, but it
 *         differs from the expected MAC.
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (not set up, or already completed).
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_mac_verify_finish(psa_mac_operation_t *operation,
                                   const uint8_t *mac,
                                   size_t mac_length);

/** Abort a MAC operation.
 *
 * Aborting an operation frees all associated resources except for the
 * \p operation structure itself. Once aborted, the operation object
 * can be reused for another operation by calling
 * psa_mac_sign_setup() or psa_mac_verify_setup() again.
 *
 * You may call this function any time after the operation object has
 * been initialized by any of the following methods:
 * - A call to psa_mac_sign_setup() or psa_mac_verify_setup(), whether
 *   it succeeds or not.
 * - Initializing the \c struct to all-bits-zero.
 * - Initializing the \c struct to logical zeros, e.g.
 *   `psa_mac_operation_t operation = {0}`.
 *
 * In particular, calling psa_mac_abort() after the operation has been
 * terminated by a call to psa_mac_abort(), psa_mac_sign_finish() or
 * psa_mac_verify_finish() is safe and has no effect.
 *
 * \param[in,out] operation Initialized MAC operation.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_BAD_STATE
 *         \p operation is not an active MAC operation.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_mac_abort(psa_mac_operation_t *operation);

/**@}*/

/** \defgroup cipher Symmetric ciphers
 * @{
 */

/** The type of the state data structure for multipart cipher operations.
 *
 * Before calling any function on a cipher operation object, the application
 * must initialize it by any of the following means:
 * - Set the structure to all-bits-zero, for example:
 *   \code
 *   psa_cipher_operation_t operation;
 *   memset(&operation, 0, sizeof(operation));
 *   \endcode
 * - Initialize the structure to logical zero values, for example:
 *   \code
 *   psa_cipher_operation_t operation = {0};
 *   \endcode
 * - Initialize the structure to the initializer #PSA_CIPHER_OPERATION_INIT,
 *   for example:
 *   \code
 *   psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
 *   \endcode
 * - Assign the result of the function psa_cipher_operation_init()
 *   to the structure, for example:
 *   \code
 *   psa_cipher_operation_t operation;
 *   operation = psa_cipher_operation_init();
 *   \endcode
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_cipher_operation_s psa_cipher_operation_t;

/** \def PSA_CIPHER_OPERATION_INIT
 *
 * This macro returns a suitable initializer for a cipher operation object of
 * type #psa_cipher_operation_t.
 */
#ifdef __DOXYGEN_ONLY__
/* This is an example definition for documentation purposes.
 * Implementations should define a suitable value in `crypto_struct.h`.
 */
#define PSA_CIPHER_OPERATION_INIT {0}
#endif

/** Return an initial value for a cipher operation object.
 */
static psa_cipher_operation_t psa_cipher_operation_init(void);

/** Set the key for a multipart symmetric encryption operation.
 *
 * The sequence of operations to encrypt a message with a symmetric cipher
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Initialize the operation object with one of the methods described in the
 *    documentation for #psa_cipher_operation_t, e.g.
 *    PSA_CIPHER_OPERATION_INIT.
 * -# Call psa_cipher_encrypt_setup() to specify the algorithm and key.
 *    The key remains associated with the operation even if the content
 *    of the key slot changes.
 * -# Call either psa_cipher_generate_iv() or psa_cipher_set_iv() to
 *    generate or set the IV (initialization vector). You should use
 *    psa_cipher_generate_iv() unless the protocol you are implementing
 *    requires a specific IV value.
 * -# Call psa_cipher_update() zero, one or more times, passing a fragment
 *    of the message each time.
 * -# Call psa_cipher_finish().
 *
 * The application may call psa_cipher_abort() at any time after the operation
 * has been initialized.
 *
 * After a successful call to psa_cipher_encrypt_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_cipher_generate_iv(), psa_cipher_set_iv()
 *   or psa_cipher_update().
 * - A call to psa_cipher_finish() or psa_cipher_abort().
 *
 * \param[in,out] operation     The operation object to set up. It must have
 *                              been initialized as per the documentation for
 *                              #psa_cipher_operation_t and not yet in use.
 * \param handle                Handle to the key to use for the operation.
 * \param alg                   The cipher algorithm to compute
 *                              (\c PSA_ALG_XXX value such that
 *                              #PSA_ALG_IS_CIPHER(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 * \retval #PSA_ERROR_NOT_PERMITTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p key is not compatible with \p alg.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported or is not a cipher algorithm.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (already set up and not
 *         subsequently completed).
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t *operation,
                                      psa_key_handle_t handle,
                                      psa_algorithm_t alg);

/** Set the key for a multipart symmetric decryption operation.
 *
 * The sequence of operations to decrypt a message with a symmetric cipher
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Initialize the operation object with one of the methods described in the
 *    documentation for #psa_cipher_operation_t, e.g.
 *    PSA_CIPHER_OPERATION_INIT.
 * -# Call psa_cipher_decrypt_setup() to specify the algorithm and key.
 *    The key remains associated with the operation even if the content
 *    of the key slot changes.
 * -# Call psa_cipher_update() with the IV (initialization vector) for the
 *    decryption. If the IV is prepended to the ciphertext, you can call
 *    psa_cipher_update() on a buffer containing the IV followed by the
 *    beginning of the message.
 * -# Call psa_cipher_update() zero, one or more times, passing a fragment
 *    of the message each time.
 * -# Call psa_cipher_finish().
 *
 * The application may call psa_cipher_abort() at any time after the operation
 * has been initialized.
 *
 * After a successful call to psa_cipher_decrypt_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_cipher_update().
 * - A call to psa_cipher_finish() or psa_cipher_abort().
 *
 * \param[in,out] operation     The operation object to set up. It must have
 *                              been initialized as per the documentation for
 *                              #psa_cipher_operation_t and not yet in use.
 * \param handle                Handle to the key to use for the operation.
 * \param alg                   The cipher algorithm to compute
 *                              (\c PSA_ALG_XXX value such that
 *                              #PSA_ALG_IS_CIPHER(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 * \retval #PSA_ERROR_NOT_PERMITTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p key is not compatible with \p alg.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported or is not a cipher algorithm.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (already set up and not
 *         subsequently completed).
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t *operation,
                                      psa_key_handle_t handle,
                                      psa_algorithm_t alg);

/** Generate an IV for a symmetric encryption operation.
 *
 * This function generates a random IV (initialization vector), nonce
 * or initial counter value for the encryption operation as appropriate
 * for the chosen algorithm, key type and key size.
 *
 * The application must call psa_cipher_encrypt_setup() before
 * calling this function.
 *
 * If this function returns an error status, the operation becomes inactive.
 *
 * \param[in,out] operation     Active cipher operation.
 * \param[out] iv               Buffer where the generated IV is to be written.
 * \param iv_size               Size of the \p iv buffer in bytes.
 * \param[out] iv_length        On success, the number of bytes of the
 *                              generated IV.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (not set up, or IV already set).
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p iv buffer is too small.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t *operation,
                                    unsigned char *iv,
                                    size_t iv_size,
                                    size_t *iv_length);

/** Set the IV for a symmetric encryption or decryption operation.
 *
 * This function sets the random IV (initialization vector), nonce
 * or initial counter value for the encryption or decryption operation.
 *
 * The application must call psa_cipher_encrypt_setup() before
 * calling this function.
 *
 * If this function returns an error status, the operation becomes inactive.
 *
 * \note When encrypting, applications should use psa_cipher_generate_iv()
 * instead of this function, unless implementing a protocol that requires
 * a non-random IV.
 *
 * \param[in,out] operation     Active cipher operation.
 * \param[in] iv                Buffer containing the IV to use.
 * \param iv_length             Size of the IV in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (not set up, or IV already set).
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The size of \p iv is not acceptable for the chosen algorithm,
 *         or the chosen algorithm does not use an IV.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_cipher_set_iv(psa_cipher_operation_t *operation,
                               const unsigned char *iv,
                               size_t iv_length);

/** Encrypt or decrypt a message fragment in an active cipher operation.
 *
 * Before calling this function, you must:
 * 1. Call either psa_cipher_encrypt_setup() or psa_cipher_decrypt_setup().
 *    The choice of setup function determines whether this function
 *    encrypts or decrypts its input.
 * 2. If the algorithm requires an IV, call psa_cipher_generate_iv()
 *    (recommended when encrypting) or psa_cipher_set_iv().
 *
 * If this function returns an error status, the operation becomes inactive.
 *
 * \param[in,out] operation     Active cipher operation.
 * \param[in] input             Buffer containing the message fragment to
 *                              encrypt or decrypt.
 * \param input_length          Size of the \p input buffer in bytes.
 * \param[out] output           Buffer where the output is to be written.
 * \param output_size           Size of the \p output buffer in bytes.
 * \param[out] output_length    On success, the number of bytes
 *                              that make up the returned output.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (not set up, IV required but
 *         not set, or already completed).
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p output buffer is too small.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_cipher_update(psa_cipher_operation_t *operation,
                               const uint8_t *input,
                               size_t input_length,
                               unsigned char *output,
                               size_t output_size,
                               size_t *output_length);

/** Finish encrypting or decrypting a message in a cipher operation.
 *
 * The application must call psa_cipher_encrypt_setup() or
 * psa_cipher_decrypt_setup() before calling this function. The choice
 * of setup function determines whether this function encrypts or
 * decrypts its input.
 *
 * This function finishes the encryption or decryption of the message
 * formed by concatenating the inputs passed to preceding calls to
 * psa_cipher_update().
 *
 * When this function returns, the operation becomes inactive.
 *
 * \param[in,out] operation     Active cipher operation.
 * \param[out] output           Buffer where the output is to be written.
 * \param output_size           Size of the \p output buffer in bytes.
 * \param[out] output_length    On success, the number of bytes
 *                              that make up the returned output.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (not set up, IV required but
 *         not set, or already completed).
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p output buffer is too small.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_cipher_finish(psa_cipher_operation_t *operation,
                               uint8_t *output,
                               size_t output_size,
                               size_t *output_length);

/** Abort a cipher operation.
 *
 * Aborting an operation frees all associated resources except for the
 * \p operation structure itself. Once aborted, the operation object
 * can be reused for another operation by calling
 * psa_cipher_encrypt_setup() or psa_cipher_decrypt_setup() again.
 *
 * You may call this function any time after the operation object has
 * been initialized by any of the following methods:
 * - A call to psa_cipher_encrypt_setup() or psa_cipher_decrypt_setup(),
 *   whether it succeeds or not.
 * - Initializing the \c struct to all-bits-zero.
 * - Initializing the \c struct to logical zeros, e.g.
 *   `psa_cipher_operation_t operation = {0}`.
 *
 * In particular, calling psa_cipher_abort() after the operation has been
 * terminated by a call to psa_cipher_abort() or psa_cipher_finish()
 * is safe and has no effect.
 *
 * \param[in,out] operation     Initialized cipher operation.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_BAD_STATE
 *         \p operation is not an active cipher operation.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_cipher_abort(psa_cipher_operation_t *operation);

/**@}*/

/** \defgroup aead Authenticated encryption with associated data (AEAD)
 * @{
 */

/** Process an authenticated encryption operation.
 *
 * \param handle                  Handle to the key to use for the operation.
 * \param alg                     The AEAD algorithm to compute
 *                                (\c PSA_ALG_XXX value such that
 *                                #PSA_ALG_IS_AEAD(\p alg) is true).
 * \param[in] nonce               Nonce or IV to use.
 * \param nonce_length            Size of the \p nonce buffer in bytes.
 * \param[in] additional_data     Additional data that will be authenticated
 *                                but not encrypted.
 * \param additional_data_length  Size of \p additional_data in bytes.
 * \param[in] plaintext           Data that will be authenticated and
 *                                encrypted.
 * \param plaintext_length        Size of \p plaintext in bytes.
 * \param[out] ciphertext         Output buffer for the authenticated and
 *                                encrypted data. The additional data is not
 *                                part of this output. For algorithms where the
 *                                encrypted data and the authentication tag
 *                                are defined as separate outputs, the
 *                                authentication tag is appended to the
 *                                encrypted data.
 * \param ciphertext_size         Size of the \p ciphertext buffer in bytes.
 *                                This must be at least
 *                                #PSA_AEAD_ENCRYPT_OUTPUT_SIZE(\p alg,
 *                                \p plaintext_length).
 * \param[out] ciphertext_length  On success, the size of the output
 *                                in the \b ciphertext buffer.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 * \retval #PSA_ERROR_NOT_PERMITTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p key is not compatible with \p alg.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported or is not an AEAD algorithm.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_aead_encrypt(psa_key_handle_t handle,
                              psa_algorithm_t alg,
                              const uint8_t *nonce,
                              size_t nonce_length,
                              const uint8_t *additional_data,
                              size_t additional_data_length,
                              const uint8_t *plaintext,
                              size_t plaintext_length,
                              uint8_t *ciphertext,
                              size_t ciphertext_size,
                              size_t *ciphertext_length);

/** Process an authenticated decryption operation.
 *
 * \param handle                  Handle to the key to use for the operation.
 * \param alg                     The AEAD algorithm to compute
 *                                (\c PSA_ALG_XXX value such that
 *                                #PSA_ALG_IS_AEAD(\p alg) is true).
 * \param[in] nonce               Nonce or IV to use.
 * \param nonce_length            Size of the \p nonce buffer in bytes.
 * \param[in] additional_data     Additional data that has been authenticated
 *                                but not encrypted.
 * \param additional_data_length  Size of \p additional_data in bytes.
 * \param[in] ciphertext          Data that has been authenticated and
 *                                encrypted. For algorithms where the
 *                                encrypted data and the authentication tag
 *                                are defined as separate inputs, the buffer
 *                                must contain the encrypted data followed
 *                                by the authentication tag.
 * \param ciphertext_length       Size of \p ciphertext in bytes.
 * \param[out] plaintext          Output buffer for the decrypted data.
 * \param plaintext_size          Size of the \p plaintext buffer in bytes.
 *                                This must be at least
 *                                #PSA_AEAD_DECRYPT_OUTPUT_SIZE(\p alg,
 *                                \p ciphertext_length).
 * \param[out] plaintext_length   On success, the size of the output
 *                                in the \b plaintext buffer.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The ciphertext is not authentic.
 * \retval #PSA_ERROR_NOT_PERMITTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p key is not compatible with \p alg.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported or is not an AEAD algorithm.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_aead_decrypt(psa_key_handle_t handle,
                              psa_algorithm_t alg,
                              const uint8_t *nonce,
                              size_t nonce_length,
                              const uint8_t *additional_data,
                              size_t additional_data_length,
                              const uint8_t *ciphertext,
                              size_t ciphertext_length,
                              uint8_t *plaintext,
                              size_t plaintext_size,
                              size_t *plaintext_length);

/**@}*/

/** \defgroup asymmetric Asymmetric cryptography
 * @{
 */

/**
 * \brief Sign a hash or short message with a private key.
 *
 * Note that to perform a hash-and-sign signature algorithm, you must
 * first calculate the hash by calling psa_hash_setup(), psa_hash_update()
 * and psa_hash_finish(). Then pass the resulting hash as the \p hash
 * parameter to this function. You can use #PSA_ALG_SIGN_GET_HASH(\p alg)
 * to determine the hash algorithm to use.
 *
 * \param handle                Handle to the key to use for the operation.
 *                              It must be an asymmetric key pair.
 * \param alg                   A signature algorithm that is compatible with
 *                              the type of \p key.
 * \param[in] hash              The hash or message to sign.
 * \param hash_length           Size of the \p hash buffer in bytes.
 * \param[out] signature        Buffer where the signature is to be written.
 * \param signature_size        Size of the \p signature buffer in bytes.
 * \param[out] signature_length On success, the number of bytes
 *                              that make up the returned signature value.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p signature buffer is too small. You can
 *         determine a sufficient buffer size by calling
 *         #PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE(\c key_type, \c key_bits, \p alg)
 *         where \c key_type and \c key_bits are the type and bit-size
 *         respectively of \p key.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_INSUFFICIENT_ENTROPY
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_asymmetric_sign(psa_key_handle_t handle,
                                 psa_algorithm_t alg,
                                 const uint8_t *hash,
                                 size_t hash_length,
                                 uint8_t *signature,
                                 size_t signature_size,
                                 size_t *signature_length);

/**
 * \brief Verify the signature a hash or short message using a public key.
 *
 * Note that to perform a hash-and-sign signature algorithm, you must
 * first calculate the hash by calling psa_hash_setup(), psa_hash_update()
 * and psa_hash_finish(). Then pass the resulting hash as the \p hash
 * parameter to this function. You can use #PSA_ALG_SIGN_GET_HASH(\p alg)
 * to determine the hash algorithm to use.
 *
 * \param handle            Handle to the key to use for the operation.
 *                          It must be a public key or an asymmetric key pair.
 * \param alg               A signature algorithm that is compatible with
 *                          the type of \p key.
 * \param[in] hash          The hash or message whose signature is to be
 *                          verified.
 * \param hash_length       Size of the \p hash buffer in bytes.
 * \param[in] signature     Buffer containing the signature to verify.
 * \param signature_length  Size of the \p signature buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         The signature is valid.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The calculation was perfomed successfully, but the passed
 *         signature is not a valid signature.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_asymmetric_verify(psa_key_handle_t handle,
                                   psa_algorithm_t alg,
                                   const uint8_t *hash,
                                   size_t hash_length,
                                   const uint8_t *signature,
                                   size_t signature_length);

/**
 * \brief Encrypt a short message with a public key.
 *
 * \param handle                Handle to the key to use for the operation.
 *                              It must be a public key or an asymmetric
 *                              key pair.
 * \param alg                   An asymmetric encryption algorithm that is
 *                              compatible with the type of \p key.
 * \param[in] input             The message to encrypt.
 * \param input_length          Size of the \p input buffer in bytes.
 * \param[in] salt              A salt or label, if supported by the
 *                              encryption algorithm.
 *                              If the algorithm does not support a
 *                              salt, pass \c NULL.
 *                              If the algorithm supports an optional
 *                              salt and you do not want to pass a salt,
 *                              pass \c NULL.
 *
 *                              - For #PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is
 *                                supported.
 * \param salt_length           Size of the \p salt buffer in bytes.
 *                              If \p salt is \c NULL, pass 0.
 * \param[out] output           Buffer where the encrypted message is to
 *                              be written.
 * \param output_size           Size of the \p output buffer in bytes.
 * \param[out] output_length    On success, the number of bytes
 *                              that make up the returned output.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p output buffer is too small. You can
 *         determine a sufficient buffer size by calling
 *         #PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(\c key_type, \c key_bits, \p alg)
 *         where \c key_type and \c key_bits are the type and bit-size
 *         respectively of \p key.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_INSUFFICIENT_ENTROPY
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_asymmetric_encrypt(psa_key_handle_t handle,
                                    psa_algorithm_t alg,
                                    const uint8_t *input,
                                    size_t input_length,
                                    const uint8_t *salt,
                                    size_t salt_length,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *output_length);

/**
 * \brief Decrypt a short message with a private key.
 *
 * \param handle                Handle to the key to use for the operation.
 *                              It must be an asymmetric key pair.
 * \param alg                   An asymmetric encryption algorithm that is
 *                              compatible with the type of \p key.
 * \param[in] input             The message to decrypt.
 * \param input_length          Size of the \p input buffer in bytes.
 * \param[in] salt              A salt or label, if supported by the
 *                              encryption algorithm.
 *                              If the algorithm does not support a
 *                              salt, pass \c NULL.
 *                              If the algorithm supports an optional
 *                              salt and you do not want to pass a salt,
 *                              pass \c NULL.
 *
 *                              - For #PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is
 *                                supported.
 * \param salt_length           Size of the \p salt buffer in bytes.
 *                              If \p salt is \c NULL, pass 0.
 * \param[out] output           Buffer where the decrypted message is to
 *                              be written.
 * \param output_size           Size of the \c output buffer in bytes.
 * \param[out] output_length    On success, the number of bytes
 *                              that make up the returned output.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p output buffer is too small. You can
 *         determine a sufficient buffer size by calling
 *         #PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(\c key_type, \c key_bits, \p alg)
 *         where \c key_type and \c key_bits are the type and bit-size
 *         respectively of \p key.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_INSUFFICIENT_ENTROPY
 * \retval #PSA_ERROR_INVALID_PADDING
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_asymmetric_decrypt(psa_key_handle_t handle,
                                    psa_algorithm_t alg,
                                    const uint8_t *input,
                                    size_t input_length,
                                    const uint8_t *salt,
                                    size_t salt_length,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *output_length);

/**@}*/

/** \defgroup generators Generators
 * @{
 */

/** The type of the state data structure for generators.
 *
 * Before calling any function on a generator, the application must
 * initialize it by any of the following means:
 * - Set the structure to all-bits-zero, for example:
 *   \code
 *   psa_crypto_generator_t generator;
 *   memset(&generator, 0, sizeof(generator));
 *   \endcode
 * - Initialize the structure to logical zero values, for example:
 *   \code
 *   psa_crypto_generator_t generator = {0};
 *   \endcode
 * - Initialize the structure to the initializer #PSA_CRYPTO_GENERATOR_INIT,
 *   for example:
 *   \code
 *   psa_crypto_generator_t generator = PSA_CRYPTO_GENERATOR_INIT;
 *   \endcode
 * - Assign the result of the function psa_crypto_generator_init()
 *   to the structure, for example:
 *   \code
 *   psa_crypto_generator_t generator;
 *   generator = psa_crypto_generator_init();
 *   \endcode
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation.
 */
typedef struct psa_crypto_generator_s psa_crypto_generator_t;

/** \def PSA_CRYPTO_GENERATOR_INIT
 *
 * This macro returns a suitable initializer for a generator object
 * of type #psa_crypto_generator_t.
 */
#ifdef __DOXYGEN_ONLY__
/* This is an example definition for documentation purposes.
 * Implementations should define a suitable value in `crypto_struct.h`.
 */
#define PSA_CRYPTO_GENERATOR_INIT {0}
#endif

/** Return an initial value for a generator object.
 */
static psa_crypto_generator_t psa_crypto_generator_init(void);

/** Retrieve the current capacity of a generator.
 *
 * The capacity of a generator is the maximum number of bytes that it can
 * return. Reading *N* bytes from a generator reduces its capacity by *N*.
 *
 * \param[in] generator     The generator to query.
 * \param[out] capacity     On success, the capacity of the generator.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_BAD_STATE
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 */
psa_status_t psa_get_generator_capacity(const psa_crypto_generator_t *generator,
                                        size_t *capacity);

/** Read some data from a generator.
 *
 * This function reads and returns a sequence of bytes from a generator.
 * The data that is read is discarded from the generator. The generator's
 * capacity is decreased by the number of bytes read.
 *
 * \param[in,out] generator The generator object to read from.
 * \param[out] output       Buffer where the generator output will be
 *                          written.
 * \param output_length     Number of bytes to output.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INSUFFICIENT_DATA
 *                          There were fewer than \p output_length bytes
 *                          in the generator. Note that in this case, no
 *                          output is written to the output buffer.
 *                          The generator's capacity is set to 0, thus
 *                          subsequent calls to this function will not
 *                          succeed, even with a smaller output buffer.
 * \retval #PSA_ERROR_BAD_STATE
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_generator_read(psa_crypto_generator_t *generator,
                                uint8_t *output,
                                size_t output_length);

/** Create a symmetric key from data read from a generator.
 *
 * This function reads a sequence of bytes from a generator and imports
 * these bytes as a key.
 * The data that is read is discarded from the generator. The generator's
 * capacity is decreased by the number of bytes read.
 *
 * This function is equivalent to calling #psa_generator_read and
 * passing the resulting output to #psa_import_key, but
 * if the implementation provides an isolation boundary then
 * the key material is not exposed outside the isolation boundary.
 *
 * \param handle            Handle to the slot where the key will be stored.
 *                          It must have been obtained by calling
 *                          psa_allocate_key() or psa_create_key() and must
 *                          not contain key material yet.
 * \param type              Key type (a \c PSA_KEY_TYPE_XXX value).
 *                          This must be a symmetric key type.
 * \param bits              Key size in bits.
 * \param[in,out] generator The generator object to read from.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 *         If the key is persistent, the key material and the key's metadata
 *         have been saved to persistent storage.
 * \retval #PSA_ERROR_INSUFFICIENT_DATA
 *                          There were fewer than \p output_length bytes
 *                          in the generator. Note that in this case, no
 *                          output is written to the output buffer.
 *                          The generator's capacity is set to 0, thus
 *                          subsequent calls to this function will not
 *                          succeed, even with a smaller output buffer.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The key type or key size is not supported, either by the
 *         implementation in general or in this particular slot.
 * \retval #PSA_ERROR_BAD_STATE
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_ALREADY_EXISTS
 *         There is already a key in the specified slot.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_INSUFFICIENT_STORAGE
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_generator_import_key(psa_key_handle_t handle,
                                      psa_key_type_t type,
                                      size_t bits,
                                      psa_crypto_generator_t *generator);

/** Abort a generator.
 *
 * Once a generator has been aborted, its capacity is zero.
 * Aborting a generator frees all associated resources except for the
 * \c generator structure itself.
 *
 * This function may be called at any time as long as the generator
 * object has been initialized to #PSA_CRYPTO_GENERATOR_INIT, to
 * psa_crypto_generator_init() or a zero value. In particular, it is valid
 * to call psa_generator_abort() twice, or to call psa_generator_abort()
 * on a generator that has not been set up.
 *
 * Once aborted, the generator object may be called.
 *
 * \param[in,out] generator    The generator to abort.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_BAD_STATE
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_generator_abort(psa_crypto_generator_t *generator);

/** Use the maximum possible capacity for a generator.
 *
 * Use this value as the capacity argument when setting up a generator
 * to indicate that the generator should have the maximum possible capacity.
 * The value of the maximum possible capacity depends on the generator
 * algorithm.
 */
#define PSA_GENERATOR_UNBRIDLED_CAPACITY ((size_t)(-1))

/**@}*/

/** \defgroup derivation Key derivation
 * @{
 */

/** Set up a key derivation operation.
 *
 * A key derivation algorithm takes three inputs: a secret input \p key and
 * two non-secret inputs \p label and p salt.
 * The result of this function is a byte generator which can
 * be used to produce keys and other cryptographic material.
 *
 * The role of \p label and \p salt is as follows:
 * - For HKDF (#PSA_ALG_HKDF), \p salt is the salt used in the "extract" step
 *   and \p label is the info string used in the "expand" step.
 *
 * \param[in,out] generator       The generator object to set up. It must have
 *                                been initialized as per the documentation for
 *                                #psa_crypto_generator_t and not yet in use.
 * \param handle                  Handle to the secret key.
 * \param alg                     The key derivation algorithm to compute
 *                                (\c PSA_ALG_XXX value such that
 *                                #PSA_ALG_IS_KEY_DERIVATION(\p alg) is true).
 * \param[in] salt                Salt to use.
 * \param salt_length             Size of the \p salt buffer in bytes.
 * \param[in] label               Label to use.
 * \param label_length            Size of the \p label buffer in bytes.
 * \param capacity                The maximum number of bytes that the
 *                                generator will be able to provide.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 * \retval #PSA_ERROR_NOT_PERMITTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \c key is not compatible with \c alg,
 *         or \p capacity is too large for the specified algorithm and key.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not a key derivation algorithm.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_key_derivation(psa_crypto_generator_t *generator,
                                psa_key_handle_t handle,
                                psa_algorithm_t alg,
                                const uint8_t *salt,
                                size_t salt_length,
                                const uint8_t *label,
                                size_t label_length,
                                size_t capacity);

/** Set up a key agreement operation.
 *
 * A key agreement algorithm takes two inputs: a private key \p private_key
 * a public key \p peer_key.
 * The result of this function is a byte generator which can
 * be used to produce keys and other cryptographic material.
 *
 * The resulting generator always has the maximum capacity permitted by
 * the algorithm.
 *
 * \param[in,out] generator The generator object to set up. It must have been
 *                          initialized as per the documentation for
 *                          #psa_crypto_generator_t and not yet in use.
 * \param private_key       Handle to the private key to use.
 * \param[in] peer_key      Public key of the peer. The peer key must be in the
 *                          same format that psa_import_key() accepts for the
 *                          public key type corresponding to the type of
 *                          \p private_key. That is, this function performs the
 *                          equivalent of
 *                          `psa_import_key(internal_public_key_handle,
 *                          PSA_KEY_TYPE_PUBLIC_KEY_OF_KEYPAIR(private_key_type),
 *                          peer_key, peer_key_length)` where
 *                          `private_key_type` is the type of \p private_key.
 *                          For example, for EC keys, this means that \p
 *                          peer_key is interpreted as a point on the curve
 *                          that the private key is associated with. The
 *                          standard formats for public keys are documented in
 *                          the documentation of psa_export_public_key().
 * \param peer_key_length   Size of \p peer_key in bytes.
 * \param alg               The key agreement algorithm to compute
 *                          (\c PSA_ALG_XXX value such that
 *                          #PSA_ALG_IS_KEY_AGREEMENT(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 * \retval #PSA_ERROR_NOT_PERMITTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \c private_key is not compatible with \c alg,
 *         or \p peer_key is not valid for \c alg or not compatible with
 *         \c private_key.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not a key derivation algorithm.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_key_agreement(psa_crypto_generator_t *generator,
                               psa_key_handle_t private_key,
                               const uint8_t *peer_key,
                               size_t peer_key_length,
                               psa_algorithm_t alg);

/**@}*/

/** \defgroup random Random generation
 * @{
 */

/**
 * \brief Generate random bytes.
 *
 * \warning This function **can** fail! Callers MUST check the return status
 *          and MUST NOT use the content of the output buffer if the return
 *          status is not #PSA_SUCCESS.
 *
 * \note    To generate a key, use psa_generate_key() instead.
 *
 * \param[out] output       Output buffer for the generated data.
 * \param output_size       Number of bytes to generate and output.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_INSUFFICIENT_ENTROPY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_generate_random(uint8_t *output,
                                 size_t output_size);

/** Extra parameters for RSA key generation.
 *
 * You may pass a pointer to a structure of this type as the \c extra
 * parameter to psa_generate_key().
 */
typedef struct {
    uint32_t e; /**< Public exponent value. Default: 65537. */
} psa_generate_key_extra_rsa;

/**
 * \brief Generate a key or key pair.
 *
 * \param handle            Handle to the slot where the key will be stored.
 *                          It must have been obtained by calling
 *                          psa_allocate_key() or psa_create_key() and must
 *                          not contain key material yet.
 * \param type              Key type (a \c PSA_KEY_TYPE_XXX value).
 * \param bits              Key size in bits.
 * \param[in] extra         Extra parameters for key generation. The
 *                          interpretation of this parameter depends on
 *                          \p type. All types support \c NULL to use
 *                          default parameters. Implementation that support
 *                          the generation of vendor-specific key types
 *                          that allow extra parameters shall document
 *                          the format of these extra parameters and
 *                          the default values. For standard parameters,
 *                          the meaning of \p extra is as follows:
 *                          - For a symmetric key type (a type such
 *                            that #PSA_KEY_TYPE_IS_ASYMMETRIC(\p type) is
 *                            false), \p extra must be \c NULL.
 *                          - For an elliptic curve key type (a type
 *                            such that #PSA_KEY_TYPE_IS_ECC(\p type) is
 *                            false), \p extra must be \c NULL.
 *                          - For an RSA key (\p type is
 *                            #PSA_KEY_TYPE_RSA_KEYPAIR), \p extra is an
 *                            optional #psa_generate_key_extra_rsa structure
 *                            specifying the public exponent. The
 *                            default public exponent used when \p extra
 *                            is \c NULL is 65537.
 * \param extra_size        Size of the buffer that \p extra
 *                          points to, in bytes. Note that if \p extra is
 *                          \c NULL then \p extra_size must be zero.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 *         If the key is persistent, the key material and the key's metadata
 *         have been saved to persistent storage.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_ALREADY_EXISTS
 *         There is already a key in the specified slot.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_INSUFFICIENT_ENTROPY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_generate_key(psa_key_handle_t handle,
                              psa_key_type_t type,
                              size_t bits,
                              const void *extra,
                              size_t extra_size);

/**@}*/

#ifdef __cplusplus
}
#endif

/* The file "crypto_sizes.h" contains definitions for size calculation
 * macros whose definitions are implementation-specific. */
#include "crypto_sizes.h"

/* The file "crypto_struct.h" contains definitions for
 * implementation-specific structs that are declared above. */
#include "crypto_struct.h"

/* The file "crypto_extra.h" contains vendor-specific definitions. This
 * can include vendor-defined algorithms, extra functions, etc. */
#include "crypto_extra.h"

#endif /* PSA_CRYPTO_H */
