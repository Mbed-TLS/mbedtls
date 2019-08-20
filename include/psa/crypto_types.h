/**
 * \file psa/crypto_types.h
 *
 * \brief PSA cryptography module: type aliases.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h. Drivers must include the appropriate driver
 * header file.
 *
 * This file contains portable definitions of integral types for properties
 * of cryptographic keys, designations of cryptographic algorithms, and
 * error codes returned by the library.
 *
 * This header file does not declare any function.
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

#ifndef PSA_CRYPTO_TYPES_H
#define PSA_CRYPTO_TYPES_H

#include <stdint.h>

/** \defgroup error Error codes
 * @{
 */

/**
 * \brief Function return status.
 *
 * This is either #PSA_SUCCESS (which is zero), indicating success,
 * or a small negative value indicating that an error occurred. Errors are
 * encoded as one of the \c PSA_ERROR_xxx values defined here. */
/* If #PSA_SUCCESS is already defined, it means that #psa_status_t
 * is also defined in an external header, so prevent its multiple
 * definition.
 */
#ifndef PSA_SUCCESS
typedef int32_t psa_status_t;
#endif

/**@}*/

/** \defgroup crypto_types Key and algorithm types
 * @{
 */

/** \brief Encoding of a key type.
 */
typedef uint32_t psa_key_type_t;

/** The type of PSA elliptic curve identifiers. */
typedef uint16_t psa_ecc_curve_t;

/** The type of PSA Diffie-Hellman group identifiers. */
typedef uint16_t psa_dh_group_t;

/** \brief Encoding of a cryptographic algorithm.
 *
 * For algorithms that can be applied to multiple key types, this type
 * does not encode the key type. For example, for symmetric ciphers
 * based on a block cipher, #psa_algorithm_t encodes the block cipher
 * mode and the padding mode while the block cipher itself is encoded
 * via #psa_key_type_t.
 */
typedef uint32_t psa_algorithm_t;

/**@}*/

/** \defgroup key_lifetimes Key lifetimes
 * @{
 */

/** Encoding of key lifetimes.
 *
 * The lifetime of a key indicates where it is stored and what system actions
 * may create and destroy it.
 *
 * Keys with the lifetime #PSA_KEY_LIFETIME_VOLATILE are automatically
 * destroyed when the application terminates or on a power reset.
 *
 * Keys with a lifetime other than #PSA_KEY_LIFETIME_VOLATILE are said
 * to be _persistent_.
 * Persistent keys are preserved if the application or the system restarts.
 * Persistent keys have a key identifier of type #psa_key_id_t.
 * The application can call psa_open_key() to open a persistent key that
 * it created previously.
 */
typedef uint32_t psa_key_lifetime_t;

/** Encoding of identifiers of persistent keys.
 *
 * - Applications may freely choose key identifiers in the range
 *   #PSA_KEY_ID_USER_MIN to #PSA_KEY_ID_USER_MAX.
 * - Implementations may define additional key identifiers in the range
 *   #PSA_KEY_ID_VENDOR_MIN to #PSA_KEY_ID_VENDOR_MAX.
 * - 0 is reserved as an invalid key identifier.
 * - Key identifiers outside these ranges are reserved for future use.
 */
/* Implementation-specific quirk: The Mbed Crypto library can be built as
 * part of a multi-client service that exposes the PSA Crypto API in each
 * client and encodes the client identity in the key id argument of functions
 * such as psa_open_key(). In this build configuration, we define
 * psa_key_id_t in crypto_platform.h instead of here. */
#if !defined(MBEDTLS_PSA_CRYPTO_KEY_FILE_ID_ENCODES_OWNER)
typedef uint32_t psa_key_id_t;
#define PSA_KEY_ID_INIT 0
#endif

/**@}*/

/** \defgroup policy Key policies
 * @{
 */

/** \brief Encoding of permitted usage on a key. */
typedef uint32_t psa_key_usage_t;

/**@}*/

/** \defgroup attributes Key attributes
 * @{
 */

/** The type of a structure containing key attributes.
 *
 * This is an opaque structure that can represent the metadata of a key
 * object. Metadata that can be stored in attributes includes:
 * - The location of the key in storage, indicated by its key identifier
 *   and its lifetime.
 * - The key's policy, comprising usage flags and a specification of
 *   the permitted algorithm(s).
 * - Information about the key itself: the key type and its size.
 * - Implementations may define additional attributes.
 *
 * The actual key material is not considered an attribute of a key.
 * Key attributes do not contain information that is generally considered
 * highly confidential.
 *
 * An attribute structure can be a simple data structure where each function
 * `psa_set_key_xxx` sets a field and the corresponding function
 * `psa_get_key_xxx` retrieves the value of the corresponding field.
 * However, implementations may report values that are equivalent to the
 * original one, but have a different encoding. For example, an
 * implementation may use a more compact representation for types where
 * many bit-patterns are invalid or not supported, and store all values
 * that it does not support as a special marker value. In such an
 * implementation, after setting an invalid value, the corresponding
 * get function returns an invalid value which may not be the one that
 * was originally stored.
 *
 * An attribute structure may contain references to auxiliary resources,
 * for example pointers to allocated memory or indirect references to
 * pre-calculated values. In order to free such resources, the application
 * must call psa_reset_key_attributes(). As an exception, calling
 * psa_reset_key_attributes() on an attribute structure is optional if
 * the structure has only been modified by the following functions
 * since it was initialized or last reset with psa_reset_key_attributes():
 * - psa_set_key_id()
 * - psa_set_key_lifetime()
 * - psa_set_key_type()
 * - psa_set_key_bits()
 * - psa_set_key_usage_flags()
 * - psa_set_key_algorithm()
 *
 * Before calling any function on a key attribute structure, the application
 * must initialize it by any of the following means:
 * - Set the structure to all-bits-zero, for example:
 *   \code
 *   psa_key_attributes_t attributes;
 *   memset(&attributes, 0, sizeof(attributes));
 *   \endcode
 * - Initialize the structure to logical zero values, for example:
 *   \code
 *   psa_key_attributes_t attributes = {0};
 *   \endcode
 * - Initialize the structure to the initializer #PSA_KEY_ATTRIBUTES_INIT,
 *   for example:
 *   \code
 *   psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
 *   \endcode
 * - Assign the result of the function psa_key_attributes_init()
 *   to the structure, for example:
 *   \code
 *   psa_key_attributes_t attributes;
 *   attributes = psa_key_attributes_init();
 *   \endcode
 *
 * A freshly initialized attribute structure contains the following
 * values:
 *
 * - lifetime: #PSA_KEY_LIFETIME_VOLATILE.
 * - key identifier: unspecified.
 * - type: \c 0.
 * - key size: \c 0.
 * - usage flags: \c 0.
 * - algorithm: \c 0.
 *
 * A typical sequence to create a key is as follows:
 * -# Create and initialize an attribute structure.
 * -# If the key is persistent, call psa_set_key_id().
 *    Also call psa_set_key_lifetime() to place the key in a non-default
 *    location.
 * -# Set the key policy with psa_set_key_usage_flags() and
 *    psa_set_key_algorithm().
 * -# Set the key type with psa_set_key_type().
 *    Skip this step if copying an existing key with psa_copy_key().
 * -# When generating a random key with psa_generate_key() or deriving a key
 *    with psa_key_derivation_output_key(), set the desired key size with
 *    psa_set_key_bits().
 * -# Call a key creation function: psa_import_key(), psa_generate_key(),
 *    psa_key_derivation_output_key() or psa_copy_key(). This function reads
 *    the attribute structure, creates a key with these attributes, and
 *    outputs a handle to the newly created key.
 * -# The attribute structure is now no longer necessary.
 *    You may call psa_reset_key_attributes(), although this is optional
 *    with the workflow presented here because the attributes currently
 *    defined in this specification do not require any additional resources
 *    beyond the structure itself.
 *
 * A typical sequence to query a key's attributes is as follows:
 * -# Call psa_get_key_attributes().
 * -# Call `psa_get_key_xxx` functions to retrieve the attribute(s) that
 *    you are interested in.
 * -# Call psa_reset_key_attributes() to free any resources that may be
 *    used by the attribute structure.
 *
 * Once a key has been created, it is impossible to change its attributes.
 */
typedef struct psa_key_attributes_s psa_key_attributes_t;


#ifndef __DOXYGEN_ONLY__
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
/* Mbed Crypto defines this type in crypto_types.h because it is also
 * visible to applications through an implementation-specific extension.
 * For the PSA Cryptography specification, this type is only visible
 * via crypto_se_driver.h. */
typedef uint64_t psa_key_slot_number_t;
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
#endif /* !__DOXYGEN_ONLY__ */

/**@}*/

/** \defgroup derivation Key derivation
 * @{
 */

/** \brief Encoding of the step of a key derivation. */
typedef uint16_t psa_key_derivation_step_t;

/**@}*/

#endif /* PSA_CRYPTO_TYPES_H */
