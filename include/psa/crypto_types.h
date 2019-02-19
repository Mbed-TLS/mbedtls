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
 * or a nonzero value indicating that an error occurred. Errors are
 * encoded as one of the \c PSA_ERROR_xxx values defined here.
 * If #PSA_SUCCESS is already defined, it means that #psa_status_t
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
 */
typedef uint32_t psa_key_lifetime_t;

/** Encoding of identifiers of persistent keys.
 */
/* Implementation-specific quirk: The Mbed Crypto library can be built as
 * part of a multi-client service that exposes the PSA Crypto API in each
 * client and encodes the client identity in the key id argument of functions
 * such as psa_open_key(). In this build configuration, we define
 * psa_key_id_t in crypto_platform.h instead of here. */
#if !defined(MBEDTLS_PSA_CRYPTO_KEY_FILE_ID_ENCODES_OWNER)
typedef uint32_t psa_key_id_t;
#endif

/**@}*/

/** \defgroup policy Key policies
 * @{
 */

/** \brief Encoding of permitted usage on a key. */
typedef uint32_t psa_key_usage_t;

/**@}*/

#endif /* PSA_CRYPTO_TYPES_H */
