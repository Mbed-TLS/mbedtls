/**
 * \file psa/crypto_extra.h
 *
 * \brief PSA cryptography module: Mbed TLS vendor extensions
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file is reserved for vendor-specific definitions.
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef PSA_CRYPTO_EXTRA_H
#define PSA_CRYPTO_EXTRA_H

#include "mbedtls/platform_util.h"

#ifdef __cplusplus
extern "C" {
#endif

/* UID for secure storage seed */
#define PSA_CRYPTO_ITS_RANDOM_SEED_UID 0xFFFFFF52

/*
 * Deprecated PSA Crypto error code definitions
 */
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#define PSA_ERROR_UNKNOWN_ERROR \
    MBEDTLS_DEPRECATED_NUMERIC_CONSTANT( PSA_ERROR_GENERIC_ERROR )
#endif

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#define PSA_ERROR_OCCUPIED_SLOT \
    MBEDTLS_DEPRECATED_NUMERIC_CONSTANT( PSA_ERROR_ALREADY_EXISTS )
#endif

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#define PSA_ERROR_EMPTY_SLOT \
    MBEDTLS_DEPRECATED_NUMERIC_CONSTANT( PSA_ERROR_DOES_NOT_EXIST )
#endif

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#define PSA_ERROR_INSUFFICIENT_CAPACITY \
    MBEDTLS_DEPRECATED_NUMERIC_CONSTANT( PSA_ERROR_INSUFFICIENT_DATA )
#endif

/**
 * \brief Library deinitialization.
 *
 * This function clears all data associated with the PSA layer,
 * including the whole key store.
 *
 * This is an Mbed TLS extension.
 */
void mbedtls_psa_crypto_free( void );


/**
 * \brief Inject an initial entropy seed for the random generator into
 *        secure storage.
 *
 * This function injects data to be used as a seed for the random generator
 * used by the PSA Crypto implementation. On devices that lack a trusted
 * entropy source (preferably a hardware random number generator),
 * the Mbed PSA Crypto implementation uses this value to seed its
 * random generator.
 *
 * On devices without a trusted entropy source, this function must be
 * called exactly once in the lifetime of the device. On devices with
 * a trusted entropy source, calling this function is optional.
 * In all cases, this function may only be called before calling any
 * other function in the PSA Crypto API, including psa_crypto_init().
 *
 * When this function returns successfully, it populates a file in
 * persistent storage. Once the file has been created, this function
 * can no longer succeed.
 *
 * If any error occurs, this function does not change the system state.
 * You can call this function again after correcting the reason for the
 * error if possible.
 *
 * \warning This function **can** fail! Callers MUST check the return status.
 *
 * \warning If you use this function, you should use it as part of a
 *          factory provisioning process. The value of the injected seed
 *          is critical to the security of the device. It must be
 *          *secret*, *unpredictable* and (statistically) *unique per device*.
 *          You should be generate it randomly using a cryptographically
 *          secure random generator seeded from trusted entropy sources.
 *          You should transmit it securely to the device and ensure
 *          that its value is not leaked or stored anywhere beyond the
 *          needs of transmitting it from the point of generation to
 *          the call of this function, and erase all copies of the value
 *          once this function returns.
 *
 * This is an Mbed TLS extension.
 *
 * \note This function is only available on the following platforms:
 * * If the compile-time option MBEDTLS_PSA_INJECT_ENTROPY is enabled.
 *   Note that you must provide compatible implementations of
 *   mbedtls_nv_seed_read and mbedtls_nv_seed_write.
 * * In a client-server integration of PSA Cryptography, on the client side,
 *   if the server supports this feature.
 * \param[in] seed          Buffer containing the seed value to inject.
 * \param[in] seed_size     Size of the \p seed buffer.
 *                          The size of the seed in bytes must be greater
 *                          or equal to both #MBEDTLS_ENTROPY_MIN_PLATFORM
 *                          and #MBEDTLS_ENTROPY_BLOCK_SIZE.
 *                          It must be less or equal to
 *                          #MBEDTLS_ENTROPY_MAX_SEED_SIZE.
 *
 * \retval #PSA_SUCCESS
 *         The seed value was injected successfully. The random generator
 *         of the PSA Crypto implementation is now ready for use.
 *         You may now call psa_crypto_init() and use the PSA Crypto
 *         implementation.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p seed_size is out of range.
 * \retval #PSA_ERROR_STORAGE_FAILURE
 *         There was a failure reading or writing from storage.
 * \retval #PSA_ERROR_NOT_PERMITTED
 *         The library has already been initialized. It is no longer
 *         possible to call this function.
 */
psa_status_t mbedtls_psa_inject_entropy(const unsigned char *seed,
                                        size_t seed_size);

/** Set up a key derivation operation.
 *
 * FIMXE This function is no longer part of the official API. Its prototype
 * is only kept around for the sake of tests that haven't been updated yet.
 *
 * A key derivation algorithm takes three inputs: a secret input \p handle and
 * two non-secret inputs \p label and p salt.
 * The result of this function is a byte generator which can
 * be used to produce keys and other cryptographic material.
 *
 * The role of \p label and \p salt is as follows:
 * - For HKDF (#PSA_ALG_HKDF), \p salt is the salt used in the "extract" step
 *   and \p label is the info string used in the "expand" step.
 *
 * \param[in,out] operation       The key derivation object to set up. It must
 *                                have been initialized as per the documentation
 *                                for #psa_key_derivation_operation_t and not
 *                                yet be in use.
 * \param handle                  Handle to the secret key.
 * \param alg                     The key derivation algorithm to compute
 *                                (\c PSA_ALG_XXX value such that
 *                                #PSA_ALG_IS_KEY_DERIVATION(\p alg) is true).
 * \param[in] salt                Salt to use.
 * \param salt_length             Size of the \p salt buffer in bytes.
 * \param[in] label               Label to use.
 * \param label_length            Size of the \p label buffer in bytes.
 * \param capacity                The maximum number of bytes that the
 *                                operation will be able to provide.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_HANDLE
 * \retval #PSA_ERROR_EMPTY_SLOT
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
psa_status_t psa_key_derivation(psa_key_derivation_operation_t *operation,
                                psa_key_handle_t handle,
                                psa_algorithm_t alg,
                                const uint8_t *salt,
                                size_t salt_length,
                                const uint8_t *label,
                                size_t label_length,
                                size_t capacity);

/* FIXME Deprecated. Remove this as soon as all the tests are updated. */
#define PSA_ALG_SELECT_RAW                      ((psa_algorithm_t)0x31000001)

/** \defgroup policy Key policies
 * @{
 *
 * The functions in this section are legacy interfaces where the properties
 * of a key object are set after allocating a handle, in constrast with the
 * preferred interface where key objects are created atomically from
 * a structure that represents the properties.
 */

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

/** \defgroup to_handle Key creation to allocated handle
 * @{
 *
 * The functions in this section are legacy interfaces where the properties
 * of a key object are set after allocating a handle, in constrast with the
 * preferred interface where key objects are created atomically from
 * a structure that represents the properties.
 */

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
psa_status_t psa_get_key_lifetime_from_handle(psa_key_handle_t handle,
                                  psa_key_lifetime_t *lifetime);

psa_status_t psa_import_key_to_handle(psa_key_handle_t handle,
                            psa_key_type_t type,
                            const uint8_t *data,
                            size_t data_length);

psa_status_t psa_copy_key_to_handle(psa_key_handle_t source_handle,
                          psa_key_handle_t target_handle,
                          const psa_key_policy_t *constraint);

psa_status_t psa_generate_derived_key_to_handle(psa_key_handle_t handle,
                                      psa_key_type_t type,
                                      size_t bits,
                                      psa_key_derivation_operation_t *operation);

psa_status_t psa_generate_key_to_handle(psa_key_handle_t handle,
                              psa_key_type_t type,
                              size_t bits,
                              const void *extra,
                              size_t extra_size);

/**@}*/


/** \addtogroup crypto_types
 * @{
 */

/** DSA public key.
 *
 * The import and export format is the
 * representation of the public key `y = g^x mod p` as a big-endian byte
 * string. The length of the byte string is the length of the base prime `p`
 * in bytes.
 */
#define PSA_KEY_TYPE_DSA_PUBLIC_KEY             ((psa_key_type_t)0x60020000)

/** DSA key pair (private and public key).
 *
 * The import and export format is the
 * representation of the private key `x` as a big-endian byte string. The
 * length of the byte string is the private key size in bytes (leading zeroes
 * are not stripped).
 *
 * Determinstic DSA key derivation with psa_generate_derived_key follows
 * FIPS 186-4 &sect;B.1.2: interpret the byte string as integer
 * in big-endian order. Discard it if it is not in the range
 * [0, *N* - 2] where *N* is the boundary of the private key domain
 * (the prime *p* for Diffie-Hellman, the subprime *q* for DSA,
 * or the order of the curve's base point for ECC).
 * Add 1 to the resulting integer and use this as the private key *x*.
 *
 */
#define PSA_KEY_TYPE_DSA_KEY_PAIR                ((psa_key_type_t)0x70020000)

/** Whether a key type is an DSA key (pair or public-only). */
#define PSA_KEY_TYPE_IS_DSA(type)                                       \
    (PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) == PSA_KEY_TYPE_DSA_PUBLIC_KEY)

#define PSA_ALG_DSA_BASE                        ((psa_algorithm_t)0x10040000)
/** DSA signature with hashing.
 *
 * This is the signature scheme defined by FIPS 186-4,
 * with a random per-message secret number (*k*).
 *
 * \param hash_alg      A hash algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_HASH(\p hash_alg) is true).
 *                      This includes #PSA_ALG_ANY_HASH
 *                      when specifying the algorithm in a usage policy.
 *
 * \return              The corresponding DSA signature algorithm.
 * \return              Unspecified if \p hash_alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_DSA(hash_alg)                             \
    (PSA_ALG_DSA_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))
#define PSA_ALG_DETERMINISTIC_DSA_BASE          ((psa_algorithm_t)0x10050000)
#define PSA_ALG_DSA_DETERMINISTIC_FLAG          ((psa_algorithm_t)0x00010000)
/** Deterministic DSA signature with hashing.
 *
 * This is the deterministic variant defined by RFC 6979 of
 * the signature scheme defined by FIPS 186-4.
 *
 * \param hash_alg      A hash algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_HASH(\p hash_alg) is true).
 *                      This includes #PSA_ALG_ANY_HASH
 *                      when specifying the algorithm in a usage policy.
 *
 * \return              The corresponding DSA signature algorithm.
 * \return              Unspecified if \p hash_alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_DETERMINISTIC_DSA(hash_alg)                             \
    (PSA_ALG_DETERMINISTIC_DSA_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))
#define PSA_ALG_IS_DSA(alg)                                             \
    (((alg) & ~PSA_ALG_HASH_MASK & ~PSA_ALG_DSA_DETERMINISTIC_FLAG) ==  \
     PSA_ALG_DSA_BASE)
#define PSA_ALG_DSA_IS_DETERMINISTIC(alg)               \
    (((alg) & PSA_ALG_DSA_DETERMINISTIC_FLAG) != 0)
#define PSA_ALG_IS_DETERMINISTIC_DSA(alg)                       \
    (PSA_ALG_IS_DSA(alg) && PSA_ALG_DSA_IS_DETERMINISTIC(alg))
#define PSA_ALG_IS_RANDOMIZED_DSA(alg)                          \
    (PSA_ALG_IS_DSA(alg) && !PSA_ALG_DSA_IS_DETERMINISTIC(alg))


/* We need to expand the sample definition of this macro from
 * the API definition. */
#undef PSA_ALG_IS_HASH_AND_SIGN
#define PSA_ALG_IS_HASH_AND_SIGN(alg)                                   \
    (PSA_ALG_IS_RSA_PSS(alg) || PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) ||    \
     PSA_ALG_IS_DSA(alg) || PSA_ALG_IS_ECDSA(alg))

/**@}*/

/** \addtogroup attributes
 * @{
 */

/** Custom Diffie-Hellman group.
 *
 * For keys of type #PSA_KEY_TYPE_DH_PUBLIC_KEY(#PSA_DH_GROUP_CUSTOM) or
 * #PSA_KEY_TYPE_DH_KEY_PAIR(#PSA_DH_GROUP_CUSTOM), the group data comes
 * from domain parameters set by psa_set_key_domain_parameters().
 */
/* This value is reserved for private use in the TLS named group registry. */
#define PSA_DH_GROUP_CUSTOM             ((psa_dh_group_t) 0x01fc)


/**
 * \brief Set domain parameters for a key.
 *
 * Some key types require additional domain parameters in addition to
 * the key type identifier and the key size. Use this function instead
 * of psa_set_key_type() when you need to specify domain parameters.
 *
 * The format for the required domain parameters varies based on the key type.
 *
 * - For RSA keys (#PSA_KEY_TYPE_RSA_PUBLIC_KEY or #PSA_KEY_TYPE_RSA_KEY_PAIR),
 *   the domain parameter data consists of the public exponent,
 *   represented as a big-endian integer with no leading zeros.
 *   This information is used when generating an RSA key pair.
 *   When importing a key, the public exponent is read from the imported
 *   key data and the exponent recorded in the attribute structure is ignored.
 *   As an exception, the public exponent 65537 is represented by an empty
 *   byte string.
 * - For DSA keys (#PSA_KEY_TYPE_DSA_PUBLIC_KEY or #PSA_KEY_TYPE_DSA_KEY_PAIR),
 *   the `Dss-Parms` format as defined by RFC 3279 &sect;2.3.2.
 *   ```
 *   Dss-Parms ::= SEQUENCE  {
 *      p       INTEGER,
 *      q       INTEGER,
 *      g       INTEGER
 *   }
 *   ```
 * - For Diffie-Hellman key exchange keys
 *   (#PSA_KEY_TYPE_DH_PUBLIC_KEY(#PSA_DH_GROUP_CUSTOM) or
 *   #PSA_KEY_TYPE_DH_KEY_PAIR(#PSA_DH_GROUP_CUSTOM)), the
 *   `DomainParameters` format as defined by RFC 3279 &sect;2.3.3.
 *   ```
 *   DomainParameters ::= SEQUENCE {
 *      p               INTEGER,                    -- odd prime, p=jq +1
 *      g               INTEGER,                    -- generator, g
 *      q               INTEGER,                    -- factor of p-1
 *      j               INTEGER OPTIONAL,           -- subgroup factor
 *      validationParms ValidationParms OPTIONAL
 *   }
 *   ValidationParms ::= SEQUENCE {
 *      seed            BIT STRING,
 *      pgenCounter     INTEGER
 *   }
 *   ```
 *
 * \note This function may allocate memory or other resources.
 *       Once you have called this function on an attribute structure,
 *       you must call psa_reset_key_attributes() to free these resources.
 *
 * \note This is an experimental extension to the interface. It may change
 *       in future versions of the library.
 *
 * \param[in,out] attributes    Attribute structure where the specified domain
 *                              parameters will be stored.
 *                              If this function fails, the content of
 *                              \p attributes is not modified.
 * \param type                  Key type (a \c PSA_KEY_TYPE_XXX value).
 * \param[in] data              Buffer containing the key domain parameters.
 *                              The content of this buffer is interpreted
 *                              according to \p type as described above.
 * \param data_length           Size of the \p data buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 */
psa_status_t psa_set_key_domain_parameters(psa_key_attributes_t *attributes,
                                           psa_key_type_t type,
                                           const uint8_t *data,
                                           size_t data_length);

/**
 * \brief Get domain parameters for a key.
 *
 * Get the domain parameters for a key with this function, if any. The format
 * of the domain parameters written to \p data is specified in the
 * documentation for psa_set_key_domain_parameters().
 *
 * \note This is an experimental extension to the interface. It may change
 *       in future versions of the library.
 *
 * \param[in] attributes        The key attribute structure to query.
 * \param[out] data             On success, the key domain parameters.
 * \param data_size             Size of the \p data buffer in bytes.
 *                              The buffer is guaranteed to be large
 *                              enough if its size in bytes is at least
 *                              the value given by
 *                              PSA_KEY_DOMAIN_PARAMETERS_SIZE().
 * \param[out] data_length      On success, the number of bytes
 *                              that make up the key domain parameters data.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 */
psa_status_t psa_get_key_domain_parameters(
    const psa_key_attributes_t *attributes,
    uint8_t *data,
    size_t data_size,
    size_t *data_length);

/** Safe output buffer size for psa_get_key_domain_parameters().
 *
 * This macro returns a compile-time constant if its arguments are
 * compile-time constants.
 *
 * \warning This function may call its arguments multiple times or
 *          zero times, so you should not pass arguments that contain
 *          side effects.
 *
 * \note This is an experimental extension to the interface. It may change
 *       in future versions of the library.
 *
 * \param key_type  A supported key type.
 * \param key_bits  The size of the key in bits.
 *
 * \return If the parameters are valid and supported, return
 *         a buffer size in bytes that guarantees that
 *         psa_get_key_domain_parameters() will not fail with
 *         #PSA_ERROR_BUFFER_TOO_SMALL.
 *         If the parameters are a valid combination that is not supported
 *         by the implementation, this macro shall return either a
 *         sensible size or 0.
 *         If the parameters are not valid, the
 *         return value is unspecified.
 */
#define PSA_KEY_DOMAIN_PARAMETERS_SIZE(key_type, key_bits)              \
    (PSA_KEY_TYPE_IS_RSA(key_type) ? sizeof(int) :                      \
     PSA_KEY_TYPE_IS_DH(key_type) ? PSA_DH_KEY_DOMAIN_PARAMETERS_SIZE(key_bits) : \
     PSA_KEY_TYPE_IS_DSA(key_type) ? PSA_DSA_KEY_DOMAIN_PARAMETERS_SIZE(key_bits) : \
     0)
#define PSA_DH_KEY_DOMAIN_PARAMETERS_SIZE(key_bits)     \
    (4 + (PSA_BITS_TO_BYTES(key_bits) + 5) * 3 /*without optional parts*/)
#define PSA_DSA_KEY_DOMAIN_PARAMETERS_SIZE(key_bits)    \
    (4 + (PSA_BITS_TO_BYTES(key_bits) + 5) * 2 /*p, g*/ + 34 /*q*/)

/**@}*/

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_EXTRA_H */
