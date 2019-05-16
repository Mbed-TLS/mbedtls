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
 * \param[in,out] operation       The key derivation object to set up. It must have
 *                                been initialized as per the documentation for
 *                                #psa_key_derivation_operation_t and not yet in use.
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

psa_status_t psa_generate_random_key_to_handle(psa_key_handle_t handle,
                              psa_key_type_t type,
                              size_t bits,
                              const void *extra,
                              size_t extra_size);

/**@}*/

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_EXTRA_H */
