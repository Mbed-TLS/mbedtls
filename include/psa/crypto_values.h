/**
 * \file psa/crypto_values.h
 *
 * \brief PSA cryptography module: macros to build and analyze integer values.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h. Drivers must include the appropriate driver
 * header file.
 *
 * This file contains portable definitions of macros to build and analyze
 * values of integral types that encode properties of cryptographic keys,
 * designations of cryptographic algorithms, and error codes returned by
 * the library.
 *
 * This header file only defines preprocessor macros.
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

#ifndef PSA_CRYPTO_VALUES_H
#define PSA_CRYPTO_VALUES_H

/** \defgroup error Error codes
 * @{
 */

/* PSA error codes */

/** The action was completed successfully. */
#define PSA_SUCCESS ((psa_status_t)0)

/** An error occurred that does not correspond to any defined
 * failure cause.
 *
 * Implementations may use this error code if none of the other standard
 * error codes are applicable. */
#define PSA_ERROR_GENERIC_ERROR         ((psa_status_t)-132)

/** The requested operation or a parameter is not supported
 * by this implementation.
 *
 * Implementations should return this error code when an enumeration
 * parameter such as a key type, algorithm, etc. is not recognized.
 * If a combination of parameters is recognized and identified as
 * not valid, return #PSA_ERROR_INVALID_ARGUMENT instead. */
#define PSA_ERROR_NOT_SUPPORTED         ((psa_status_t)-134)

/** The requested action is denied by a policy.
 *
 * Implementations should return this error code when the parameters
 * are recognized as valid and supported, and a policy explicitly
 * denies the requested operation.
 *
 * If a subset of the parameters of a function call identify a
 * forbidden operation, and another subset of the parameters are
 * not valid or not supported, it is unspecified whether the function
 * returns #PSA_ERROR_NOT_PERMITTED, #PSA_ERROR_NOT_SUPPORTED or
 * #PSA_ERROR_INVALID_ARGUMENT. */
#define PSA_ERROR_NOT_PERMITTED         ((psa_status_t)-133)

/** An output buffer is too small.
 *
 * Applications can call the \c PSA_xxx_SIZE macro listed in the function
 * description to determine a sufficient buffer size.
 *
 * Implementations should preferably return this error code only
 * in cases when performing the operation with a larger output
 * buffer would succeed. However implementations may return this
 * error if a function has invalid or unsupported parameters in addition
 * to the parameters that determine the necessary output buffer size. */
#define PSA_ERROR_BUFFER_TOO_SMALL      ((psa_status_t)-138)

/** Asking for an item that already exists
 *
 * Implementations should return this error, when attempting
 * to write an item (like a key) that already exists. */
#define PSA_ERROR_ALREADY_EXISTS        ((psa_status_t)-139)

/** Asking for an item that doesn't exist
 *
 * Implementations should return this error, if a requested item (like
 * a key) does not exist. */
#define PSA_ERROR_DOES_NOT_EXIST        ((psa_status_t)-140)

/** The requested action cannot be performed in the current state.
 *
 * Multipart operations return this error when one of the
 * functions is called out of sequence. Refer to the function
 * descriptions for permitted sequencing of functions.
 *
 * Implementations shall not return this error code to indicate
 * that a key slot is occupied when it needs to be free or vice versa,
 * but shall return #PSA_ERROR_ALREADY_EXISTS or #PSA_ERROR_DOES_NOT_EXIST
 * as applicable. */
#define PSA_ERROR_BAD_STATE             ((psa_status_t)-137)

/** The parameters passed to the function are invalid.
 *
 * Implementations may return this error any time a parameter or
 * combination of parameters are recognized as invalid.
 *
 * Implementations shall not return this error code to indicate
 * that a key slot is occupied when it needs to be free or vice versa,
 * but shall return #PSA_ERROR_ALREADY_EXISTS or #PSA_ERROR_DOES_NOT_EXIST
 * as applicable.
 *
 * Implementation shall not return this error code to indicate that a
 * key handle is invalid, but shall return #PSA_ERROR_INVALID_HANDLE
 * instead.
 */
#define PSA_ERROR_INVALID_ARGUMENT      ((psa_status_t)-135)

/** There is not enough runtime memory.
 *
 * If the action is carried out across multiple security realms, this
 * error can refer to available memory in any of the security realms. */
#define PSA_ERROR_INSUFFICIENT_MEMORY   ((psa_status_t)-141)

/** There is not enough persistent storage.
 *
 * Functions that modify the key storage return this error code if
 * there is insufficient storage space on the host media. In addition,
 * many functions that do not otherwise access storage may return this
 * error code if the implementation requires a mandatory log entry for
 * the requested action and the log storage space is full. */
#define PSA_ERROR_INSUFFICIENT_STORAGE  ((psa_status_t)-142)

/** There was a communication failure inside the implementation.
 *
 * This can indicate a communication failure between the application
 * and an external cryptoprocessor or between the cryptoprocessor and
 * an external volatile or persistent memory. A communication failure
 * may be transient or permanent depending on the cause.
 *
 * \warning If a function returns this error, it is undetermined
 * whether the requested action has completed or not. Implementations
 * should return #PSA_SUCCESS on successful completion whenver
 * possible, however functions may return #PSA_ERROR_COMMUNICATION_FAILURE
 * if the requested action was completed successfully in an external
 * cryptoprocessor but there was a breakdown of communication before
 * the cryptoprocessor could report the status to the application.
 */
#define PSA_ERROR_COMMUNICATION_FAILURE ((psa_status_t)-145)

/** There was a storage failure that may have led to data loss.
 *
 * This error indicates that some persistent storage is corrupted.
 * It should not be used for a corruption of volatile memory
 * (use #PSA_ERROR_TAMPERING_DETECTED), for a communication error
 * between the cryptoprocessor and its external storage (use
 * #PSA_ERROR_COMMUNICATION_FAILURE), or when the storage is
 * in a valid state but is full (use #PSA_ERROR_INSUFFICIENT_STORAGE).
 *
 * Note that a storage failure does not indicate that any data that was
 * previously read is invalid. However this previously read data may no
 * longer be readable from storage.
 *
 * When a storage failure occurs, it is no longer possible to ensure
 * the global integrity of the keystore. Depending on the global
 * integrity guarantees offered by the implementation, access to other
 * data may or may not fail even if the data is still readable but
 * its integrity canont be guaranteed.
 *
 * Implementations should only use this error code to report a
 * permanent storage corruption. However application writers should
 * keep in mind that transient errors while reading the storage may be
 * reported using this error code. */
#define PSA_ERROR_STORAGE_FAILURE       ((psa_status_t)-146)

/** A hardware failure was detected.
 *
 * A hardware failure may be transient or permanent depending on the
 * cause. */
#define PSA_ERROR_HARDWARE_FAILURE      ((psa_status_t)-147)

/** A tampering attempt was detected.
 *
 * If an application receives this error code, there is no guarantee
 * that previously accessed or computed data was correct and remains
 * confidential. Applications should not perform any security function
 * and should enter a safe failure state.
 *
 * Implementations may return this error code if they detect an invalid
 * state that cannot happen during normal operation and that indicates
 * that the implementation's security guarantees no longer hold. Depending
 * on the implementation architecture and on its security and safety goals,
 * the implementation may forcibly terminate the application.
 *
 * This error code is intended as a last resort when a security breach
 * is detected and it is unsure whether the keystore data is still
 * protected. Implementations shall only return this error code
 * to report an alarm from a tampering detector, to indicate that
 * the confidentiality of stored data can no longer be guaranteed,
 * or to indicate that the integrity of previously returned data is now
 * considered compromised. Implementations shall not use this error code
 * to indicate a hardware failure that merely makes it impossible to
 * perform the requested operation (use #PSA_ERROR_COMMUNICATION_FAILURE,
 * #PSA_ERROR_STORAGE_FAILURE, #PSA_ERROR_HARDWARE_FAILURE,
 * #PSA_ERROR_INSUFFICIENT_ENTROPY or other applicable error code
 * instead).
 *
 * This error indicates an attack against the application. Implementations
 * shall not return this error code as a consequence of the behavior of
 * the application itself. */
#define PSA_ERROR_TAMPERING_DETECTED    ((psa_status_t)-151)

/** There is not enough entropy to generate random data needed
 * for the requested action.
 *
 * This error indicates a failure of a hardware random generator.
 * Application writers should note that this error can be returned not
 * only by functions whose purpose is to generate random data, such
 * as key, IV or nonce generation, but also by functions that execute
 * an algorithm with a randomized result, as well as functions that
 * use randomization of intermediate computations as a countermeasure
 * to certain attacks.
 *
 * Implementations should avoid returning this error after psa_crypto_init()
 * has succeeded. Implementations should generate sufficient
 * entropy during initialization and subsequently use a cryptographically
 * secure pseudorandom generator (PRNG). However implementations may return
 * this error at any time if a policy requires the PRNG to be reseeded
 * during normal operation. */
#define PSA_ERROR_INSUFFICIENT_ENTROPY  ((psa_status_t)-148)

/** The signature, MAC or hash is incorrect.
 *
 * Verification functions return this error if the verification
 * calculations completed successfully, and the value to be verified
 * was determined to be incorrect.
 *
 * If the value to verify has an invalid size, implementations may return
 * either #PSA_ERROR_INVALID_ARGUMENT or #PSA_ERROR_INVALID_SIGNATURE. */
#define PSA_ERROR_INVALID_SIGNATURE     ((psa_status_t)-149)

/** The decrypted padding is incorrect.
 *
 * \warning In some protocols, when decrypting data, it is essential that
 * the behavior of the application does not depend on whether the padding
 * is correct, down to precise timing. Applications should prefer
 * protocols that use authenticated encryption rather than plain
 * encryption. If the application must perform a decryption of
 * unauthenticated data, the application writer should take care not
 * to reveal whether the padding is invalid.
 *
 * Implementations should strive to make valid and invalid padding
 * as close as possible to indistinguishable to an external observer.
 * In particular, the timing of a decryption operation should not
 * depend on the validity of the padding. */
#define PSA_ERROR_INVALID_PADDING       ((psa_status_t)-150)

/** Return this error when there's insufficient data when attempting
 * to read from a resource. */
#define PSA_ERROR_INSUFFICIENT_DATA     ((psa_status_t)-143)

/** The key handle is not valid.
 */
#define PSA_ERROR_INVALID_HANDLE        ((psa_status_t)-136)

/**@}*/

/** \defgroup crypto_types Key and algorithm types
 * @{
 */

/** An invalid key type value.
 *
 * Zero is not the encoding of any key type.
 */
#define PSA_KEY_TYPE_NONE                       ((psa_key_type_t)0x00000000)

/** Vendor-defined flag
 *
 * Key types defined by this standard will never have the
 * #PSA_KEY_TYPE_VENDOR_FLAG bit set. Vendors who define additional key types
 * must use an encoding with the #PSA_KEY_TYPE_VENDOR_FLAG bit set and should
 * respect the bitwise structure used by standard encodings whenever practical.
 */
#define PSA_KEY_TYPE_VENDOR_FLAG                ((psa_key_type_t)0x80000000)

#define PSA_KEY_TYPE_CATEGORY_MASK              ((psa_key_type_t)0x70000000)
#define PSA_KEY_TYPE_CATEGORY_SYMMETRIC         ((psa_key_type_t)0x40000000)
#define PSA_KEY_TYPE_CATEGORY_RAW               ((psa_key_type_t)0x50000000)
#define PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY        ((psa_key_type_t)0x60000000)
#define PSA_KEY_TYPE_CATEGORY_KEY_PAIR          ((psa_key_type_t)0x70000000)

#define PSA_KEY_TYPE_CATEGORY_FLAG_PAIR         ((psa_key_type_t)0x10000000)

/** Whether a key type is vendor-defined. */
#define PSA_KEY_TYPE_IS_VENDOR_DEFINED(type) \
    (((type) & PSA_KEY_TYPE_VENDOR_FLAG) != 0)

/** Whether a key type is an unstructured array of bytes.
 *
 * This encompasses both symmetric keys and non-key data.
 */
#define PSA_KEY_TYPE_IS_UNSTRUCTURED(type) \
    (((type) & PSA_KEY_TYPE_CATEGORY_MASK & ~(psa_key_type_t)0x10000000) == \
     PSA_KEY_TYPE_CATEGORY_SYMMETRIC)

/** Whether a key type is asymmetric: either a key pair or a public key. */
#define PSA_KEY_TYPE_IS_ASYMMETRIC(type)                                \
    (((type) & PSA_KEY_TYPE_CATEGORY_MASK                               \
      & ~PSA_KEY_TYPE_CATEGORY_FLAG_PAIR) ==                            \
     PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY)
/** Whether a key type is the public part of a key pair. */
#define PSA_KEY_TYPE_IS_PUBLIC_KEY(type)                                \
    (((type) & PSA_KEY_TYPE_CATEGORY_MASK) == PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY)
/** Whether a key type is a key pair containing a private part and a public
 * part. */
#define PSA_KEY_TYPE_IS_KEYPAIR(type)                                   \
    (((type) & PSA_KEY_TYPE_CATEGORY_MASK) == PSA_KEY_TYPE_CATEGORY_KEY_PAIR)
/** The key pair type corresponding to a public key type.
 *
 * You may also pass a key pair type as \p type, it will be left unchanged.
 *
 * \param type      A public key type or key pair type.
 *
 * \return          The corresponding key pair type.
 *                  If \p type is not a public key or a key pair,
 *                  the return value is undefined.
 */
#define PSA_KEY_TYPE_KEYPAIR_OF_PUBLIC_KEY(type)        \
    ((type) | PSA_KEY_TYPE_CATEGORY_FLAG_PAIR)
/** The public key type corresponding to a key pair type.
 *
 * You may also pass a key pair type as \p type, it will be left unchanged.
 *
 * \param type      A public key type or key pair type.
 *
 * \return          The corresponding public key type.
 *                  If \p type is not a public key or a key pair,
 *                  the return value is undefined.
 */
#define PSA_KEY_TYPE_PUBLIC_KEY_OF_KEYPAIR(type)        \
    ((type) & ~PSA_KEY_TYPE_CATEGORY_FLAG_PAIR)

/** Raw data.
 *
 * A "key" of this type cannot be used for any cryptographic operation.
 * Applications may use this type to store arbitrary data in the keystore. */
#define PSA_KEY_TYPE_RAW_DATA                   ((psa_key_type_t)0x50000001)

/** HMAC key.
 *
 * The key policy determines which underlying hash algorithm the key can be
 * used for.
 *
 * HMAC keys should generally have the same size as the underlying hash.
 * This size can be calculated with #PSA_HASH_SIZE(\c alg) where
 * \c alg is the HMAC algorithm or the underlying hash algorithm. */
#define PSA_KEY_TYPE_HMAC                       ((psa_key_type_t)0x51000000)

/** A secret for key derivation.
 *
 * The key policy determines which key derivation algorithm the key
 * can be used for.
 */
#define PSA_KEY_TYPE_DERIVE                     ((psa_key_type_t)0x52000000)

/** Key for an cipher, AEAD or MAC algorithm based on the AES block cipher.
 *
 * The size of the key can be 16 bytes (AES-128), 24 bytes (AES-192) or
 * 32 bytes (AES-256).
 */
#define PSA_KEY_TYPE_AES                        ((psa_key_type_t)0x40000001)

/** Key for a cipher or MAC algorithm based on DES or 3DES (Triple-DES).
 *
 * The size of the key can be 8 bytes (single DES), 16 bytes (2-key 3DES) or
 * 24 bytes (3-key 3DES).
 *
 * Note that single DES and 2-key 3DES are weak and strongly
 * deprecated and should only be used to decrypt legacy data. 3-key 3DES
 * is weak and deprecated and should only be used in legacy protocols.
 */
#define PSA_KEY_TYPE_DES                        ((psa_key_type_t)0x40000002)

/** Key for an cipher, AEAD or MAC algorithm based on the
 * Camellia block cipher. */
#define PSA_KEY_TYPE_CAMELLIA                   ((psa_key_type_t)0x40000003)

/** Key for the RC4 stream cipher.
 *
 * Note that RC4 is weak and deprecated and should only be used in
 * legacy protocols. */
#define PSA_KEY_TYPE_ARC4                       ((psa_key_type_t)0x40000004)

/** RSA public key. */
#define PSA_KEY_TYPE_RSA_PUBLIC_KEY             ((psa_key_type_t)0x60010000)
/** RSA key pair (private and public key). */
#define PSA_KEY_TYPE_RSA_KEYPAIR                ((psa_key_type_t)0x70010000)
/** Whether a key type is an RSA key (pair or public-only). */
#define PSA_KEY_TYPE_IS_RSA(type)                                       \
    (PSA_KEY_TYPE_PUBLIC_KEY_OF_KEYPAIR(type) == PSA_KEY_TYPE_RSA_PUBLIC_KEY)

/** DSA public key. */
#define PSA_KEY_TYPE_DSA_PUBLIC_KEY             ((psa_key_type_t)0x60020000)
/** DSA key pair (private and public key). */
#define PSA_KEY_TYPE_DSA_KEYPAIR                ((psa_key_type_t)0x70020000)
/** Whether a key type is an DSA key (pair or public-only). */
#define PSA_KEY_TYPE_IS_DSA(type)                                       \
    (PSA_KEY_TYPE_PUBLIC_KEY_OF_KEYPAIR(type) == PSA_KEY_TYPE_DSA_PUBLIC_KEY)

#define PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE        ((psa_key_type_t)0x60030000)
#define PSA_KEY_TYPE_ECC_KEYPAIR_BASE           ((psa_key_type_t)0x70030000)
#define PSA_KEY_TYPE_ECC_CURVE_MASK             ((psa_key_type_t)0x0000ffff)
/** Elliptic curve key pair. */
#define PSA_KEY_TYPE_ECC_KEYPAIR(curve)         \
    (PSA_KEY_TYPE_ECC_KEYPAIR_BASE | (curve))
/** Elliptic curve public key. */
#define PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve)              \
    (PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE | (curve))

/** Whether a key type is an elliptic curve key (pair or public-only). */
#define PSA_KEY_TYPE_IS_ECC(type)                                       \
    ((PSA_KEY_TYPE_PUBLIC_KEY_OF_KEYPAIR(type) &                        \
      ~PSA_KEY_TYPE_ECC_CURVE_MASK) == PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE)
/** Whether a key type is an elliptic curve key pair. */
#define PSA_KEY_TYPE_IS_ECC_KEYPAIR(type)                               \
    (((type) & ~PSA_KEY_TYPE_ECC_CURVE_MASK) ==                         \
     PSA_KEY_TYPE_ECC_KEYPAIR_BASE)
/** Whether a key type is an elliptic curve public key. */
#define PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(type)                            \
    (((type) & ~PSA_KEY_TYPE_ECC_CURVE_MASK) ==                         \
     PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE)

/** Extract the curve from an elliptic curve key type. */
#define PSA_KEY_TYPE_GET_CURVE(type)                             \
    ((psa_ecc_curve_t) (PSA_KEY_TYPE_IS_ECC(type) ?              \
                        ((type) & PSA_KEY_TYPE_ECC_CURVE_MASK) : \
                        0))

/* The encoding of curve identifiers is currently aligned with the
 * TLS Supported Groups Registry (formerly known as the
 * TLS EC Named Curve Registry)
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8
 * The values are defined by RFC 8422 and RFC 7027. */
#define PSA_ECC_CURVE_SECT163K1         ((psa_ecc_curve_t) 0x0001)
#define PSA_ECC_CURVE_SECT163R1         ((psa_ecc_curve_t) 0x0002)
#define PSA_ECC_CURVE_SECT163R2         ((psa_ecc_curve_t) 0x0003)
#define PSA_ECC_CURVE_SECT193R1         ((psa_ecc_curve_t) 0x0004)
#define PSA_ECC_CURVE_SECT193R2         ((psa_ecc_curve_t) 0x0005)
#define PSA_ECC_CURVE_SECT233K1         ((psa_ecc_curve_t) 0x0006)
#define PSA_ECC_CURVE_SECT233R1         ((psa_ecc_curve_t) 0x0007)
#define PSA_ECC_CURVE_SECT239K1         ((psa_ecc_curve_t) 0x0008)
#define PSA_ECC_CURVE_SECT283K1         ((psa_ecc_curve_t) 0x0009)
#define PSA_ECC_CURVE_SECT283R1         ((psa_ecc_curve_t) 0x000a)
#define PSA_ECC_CURVE_SECT409K1         ((psa_ecc_curve_t) 0x000b)
#define PSA_ECC_CURVE_SECT409R1         ((psa_ecc_curve_t) 0x000c)
#define PSA_ECC_CURVE_SECT571K1         ((psa_ecc_curve_t) 0x000d)
#define PSA_ECC_CURVE_SECT571R1         ((psa_ecc_curve_t) 0x000e)
#define PSA_ECC_CURVE_SECP160K1         ((psa_ecc_curve_t) 0x000f)
#define PSA_ECC_CURVE_SECP160R1         ((psa_ecc_curve_t) 0x0010)
#define PSA_ECC_CURVE_SECP160R2         ((psa_ecc_curve_t) 0x0011)
#define PSA_ECC_CURVE_SECP192K1         ((psa_ecc_curve_t) 0x0012)
#define PSA_ECC_CURVE_SECP192R1         ((psa_ecc_curve_t) 0x0013)
#define PSA_ECC_CURVE_SECP224K1         ((psa_ecc_curve_t) 0x0014)
#define PSA_ECC_CURVE_SECP224R1         ((psa_ecc_curve_t) 0x0015)
#define PSA_ECC_CURVE_SECP256K1         ((psa_ecc_curve_t) 0x0016)
#define PSA_ECC_CURVE_SECP256R1         ((psa_ecc_curve_t) 0x0017)
#define PSA_ECC_CURVE_SECP384R1         ((psa_ecc_curve_t) 0x0018)
#define PSA_ECC_CURVE_SECP521R1         ((psa_ecc_curve_t) 0x0019)
#define PSA_ECC_CURVE_BRAINPOOL_P256R1  ((psa_ecc_curve_t) 0x001a)
#define PSA_ECC_CURVE_BRAINPOOL_P384R1  ((psa_ecc_curve_t) 0x001b)
#define PSA_ECC_CURVE_BRAINPOOL_P512R1  ((psa_ecc_curve_t) 0x001c)
#define PSA_ECC_CURVE_CURVE25519        ((psa_ecc_curve_t) 0x001d)
#define PSA_ECC_CURVE_CURVE448          ((psa_ecc_curve_t) 0x001e)

/** The block size of a block cipher.
 *
 * \param type  A cipher key type (value of type #psa_key_type_t).
 *
 * \return      The block size for a block cipher, or 1 for a stream cipher.
 *              The return value is undefined if \p type is not a supported
 *              cipher key type.
 *
 * \note It is possible to build stream cipher algorithms on top of a block
 *       cipher, for example CTR mode (#PSA_ALG_CTR).
 *       This macro only takes the key type into account, so it cannot be
 *       used to determine the size of the data that #psa_cipher_update()
 *       might buffer for future processing in general.
 *
 * \note This macro returns a compile-time constant if its argument is one.
 *
 * \warning This macro may evaluate its argument multiple times.
 */
#define PSA_BLOCK_CIPHER_BLOCK_SIZE(type)            \
    (                                                \
        (type) == PSA_KEY_TYPE_AES ? 16 :            \
        (type) == PSA_KEY_TYPE_DES ? 8 :             \
        (type) == PSA_KEY_TYPE_CAMELLIA ? 16 :       \
        (type) == PSA_KEY_TYPE_ARC4 ? 1 :            \
        0)

#define PSA_ALG_VENDOR_FLAG                     ((psa_algorithm_t)0x80000000)
#define PSA_ALG_CATEGORY_MASK                   ((psa_algorithm_t)0x7f000000)
#define PSA_ALG_CATEGORY_HASH                   ((psa_algorithm_t)0x01000000)
#define PSA_ALG_CATEGORY_MAC                    ((psa_algorithm_t)0x02000000)
#define PSA_ALG_CATEGORY_CIPHER                 ((psa_algorithm_t)0x04000000)
#define PSA_ALG_CATEGORY_AEAD                   ((psa_algorithm_t)0x06000000)
#define PSA_ALG_CATEGORY_SIGN                   ((psa_algorithm_t)0x10000000)
#define PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION  ((psa_algorithm_t)0x12000000)
#define PSA_ALG_CATEGORY_KEY_AGREEMENT          ((psa_algorithm_t)0x22000000)
#define PSA_ALG_CATEGORY_KEY_DERIVATION         ((psa_algorithm_t)0x30000000)
#define PSA_ALG_CATEGORY_KEY_SELECTION          ((psa_algorithm_t)0x31000000)

#define PSA_ALG_IS_VENDOR_DEFINED(alg)                                  \
    (((alg) & PSA_ALG_VENDOR_FLAG) != 0)

/** Whether the specified algorithm is a hash algorithm.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is a hash algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_HASH(alg)                                            \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_HASH)

/** Whether the specified algorithm is a MAC algorithm.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is a MAC algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_MAC(alg)                                             \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_MAC)

/** Whether the specified algorithm is a symmetric cipher algorithm.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is a symmetric cipher algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_CIPHER(alg)                                          \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_CIPHER)

/** Whether the specified algorithm is an authenticated encryption
 * with associated data (AEAD) algorithm.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is an AEAD algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_AEAD(alg)                                            \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_AEAD)

/** Whether the specified algorithm is a public-key signature algorithm.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is a public-key signature algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_SIGN(alg)                                            \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_SIGN)

/** Whether the specified algorithm is a public-key encryption algorithm.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is a public-key encryption algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(alg)                           \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION)

#define PSA_ALG_KEY_SELECTION_FLAG              ((psa_algorithm_t)0x01000000)
/** Whether the specified algorithm is a key agreement algorithm.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is a key agreement algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_KEY_AGREEMENT(alg)                                   \
    (((alg) & PSA_ALG_CATEGORY_MASK & ~PSA_ALG_KEY_SELECTION_FLAG) ==   \
     PSA_ALG_CATEGORY_KEY_AGREEMENT)

/** Whether the specified algorithm is a key derivation algorithm.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is a key derivation algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_KEY_DERIVATION(alg)                                  \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_KEY_DERIVATION)

/** Whether the specified algorithm is a key selection algorithm.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is a key selection algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_KEY_SELECTION(alg)                                   \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_KEY_SELECTION)

#define PSA_ALG_HASH_MASK                       ((psa_algorithm_t)0x000000ff)

#define PSA_ALG_MD2                             ((psa_algorithm_t)0x01000001)
#define PSA_ALG_MD4                             ((psa_algorithm_t)0x01000002)
#define PSA_ALG_MD5                             ((psa_algorithm_t)0x01000003)
#define PSA_ALG_RIPEMD160                       ((psa_algorithm_t)0x01000004)
#define PSA_ALG_SHA_1                           ((psa_algorithm_t)0x01000005)
/** SHA2-224 */
#define PSA_ALG_SHA_224                         ((psa_algorithm_t)0x01000008)
/** SHA2-256 */
#define PSA_ALG_SHA_256                         ((psa_algorithm_t)0x01000009)
/** SHA2-384 */
#define PSA_ALG_SHA_384                         ((psa_algorithm_t)0x0100000a)
/** SHA2-512 */
#define PSA_ALG_SHA_512                         ((psa_algorithm_t)0x0100000b)
/** SHA2-512/224 */
#define PSA_ALG_SHA_512_224                     ((psa_algorithm_t)0x0100000c)
/** SHA2-512/256 */
#define PSA_ALG_SHA_512_256                     ((psa_algorithm_t)0x0100000d)
/** SHA3-224 */
#define PSA_ALG_SHA3_224                        ((psa_algorithm_t)0x01000010)
/** SHA3-256 */
#define PSA_ALG_SHA3_256                        ((psa_algorithm_t)0x01000011)
/** SHA3-384 */
#define PSA_ALG_SHA3_384                        ((psa_algorithm_t)0x01000012)
/** SHA3-512 */
#define PSA_ALG_SHA3_512                        ((psa_algorithm_t)0x01000013)

/** In a hash-and-sign algorithm policy, allow any hash algorithm.
 *
 * This value may be used to form the algorithm usage field of a policy
 * for a signature algorithm that is parametrized by a hash. The key
 * may then be used to perform operations using the same signature
 * algorithm parametrized with any supported hash.
 *
 * That is, suppose that `PSA_xxx_SIGNATURE` is one of the following macros:
 * - #PSA_ALG_RSA_PKCS1V15_SIGN, #PSA_ALG_RSA_PSS,
 * - #PSA_ALG_DSA, #PSA_ALG_DETERMINISTIC_DSA,
 * - #PSA_ALG_ECDSA, #PSA_ALG_DETERMINISTIC_ECDSA.
 * Then you may create and use a key as follows:
 * - Set the key usage field using #PSA_ALG_ANY_HASH, for example:
 *   ```
 *   psa_key_policy_set_usage(&policy,
 *                            PSA_KEY_USAGE_SIGN, //or PSA_KEY_USAGE_VERIFY
 *                            PSA_xxx_SIGNATURE(PSA_ALG_ANY_HASH));
 *   psa_set_key_policy(handle, &policy);
 *   ```
 * - Import or generate key material.
 * - Call psa_asymmetric_sign() or psa_asymmetric_verify(), passing
 *   an algorithm built from `PSA_xxx_SIGNATURE` and a specific hash. Each
 *   call to sign or verify a message may use a different hash.
 *   ```
 *   psa_asymmetric_sign(handle, PSA_xxx_SIGNATURE(PSA_ALG_SHA_256), ...);
 *   psa_asymmetric_sign(handle, PSA_xxx_SIGNATURE(PSA_ALG_SHA_512), ...);
 *   psa_asymmetric_sign(handle, PSA_xxx_SIGNATURE(PSA_ALG_SHA3_256), ...);
 *   ```
 *
 * This value may not be used to build other algorithms that are
 * parametrized over a hash. For any valid use of this macro to build
 * an algorithm `\p alg`, #PSA_ALG_IS_HASH_AND_SIGN(\p alg) is true.
 *
 * This value may not be used to build an algorithm specification to
 * perform an operation. It is only valid to build policies.
 */
#define PSA_ALG_ANY_HASH                        ((psa_algorithm_t)0x010000ff)

#define PSA_ALG_MAC_SUBCATEGORY_MASK            ((psa_algorithm_t)0x00c00000)
#define PSA_ALG_HMAC_BASE                       ((psa_algorithm_t)0x02800000)
/** Macro to build an HMAC algorithm.
 *
 * For example, #PSA_ALG_HMAC(#PSA_ALG_SHA_256) is HMAC-SHA-256.
 *
 * \param hash_alg      A hash algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_HASH(\p hash_alg) is true).
 *
 * \return              The corresponding HMAC algorithm.
 * \return              Unspecified if \p alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_HMAC(hash_alg)                                  \
    (PSA_ALG_HMAC_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))

#define PSA_ALG_HMAC_GET_HASH(hmac_alg)                             \
    (PSA_ALG_CATEGORY_HASH | ((hmac_alg) & PSA_ALG_HASH_MASK))

/** Whether the specified algorithm is an HMAC algorithm.
 *
 * HMAC is a family of MAC algorithms that are based on a hash function.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is an HMAC algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_HMAC(alg)                                            \
    (((alg) & (PSA_ALG_CATEGORY_MASK | PSA_ALG_MAC_SUBCATEGORY_MASK)) == \
     PSA_ALG_HMAC_BASE)

/* In the encoding of a MAC algorithm, the bits corresponding to
 * PSA_ALG_MAC_TRUNCATION_MASK encode the length to which the MAC is
 * truncated. As an exception, the value 0 means the untruncated algorithm,
 * whatever its length is. The length is encoded in 6 bits, so it can
 * reach up to 63; the largest MAC is 64 bytes so its trivial truncation
 * to full length is correctly encoded as 0 and any non-trivial truncation
 * is correctly encoded as a value between 1 and 63. */
#define PSA_ALG_MAC_TRUNCATION_MASK             ((psa_algorithm_t)0x00003f00)
#define PSA_MAC_TRUNCATION_OFFSET 8

/** Macro to build a truncated MAC algorithm.
 *
 * A truncated MAC algorithm is identical to the corresponding MAC
 * algorithm except that the MAC value for the truncated algorithm
 * consists of only the first \p mac_length bytes of the MAC value
 * for the untruncated algorithm.
 *
 * \note    This macro may allow constructing algorithm identifiers that
 *          are not valid, either because the specified length is larger
 *          than the untruncated MAC or because the specified length is
 *          smaller than permitted by the implementation.
 *
 * \note    It is implementation-defined whether a truncated MAC that
 *          is truncated to the same length as the MAC of the untruncated
 *          algorithm is considered identical to the untruncated algorithm
 *          for policy comparison purposes.
 *
 * \param mac_alg       A MAC algorithm identifier (value of type
 *                      #psa_algorithm_t such that #PSA_ALG_IS_MAC(\p alg)
 *                      is true). This may be a truncated or untruncated
 *                      MAC algorithm.
 * \param mac_length    Desired length of the truncated MAC in bytes.
 *                      This must be at most the full length of the MAC
 *                      and must be at least an implementation-specified
 *                      minimum. The implementation-specified minimum
 *                      shall not be zero.
 *
 * \return              The corresponding MAC algorithm with the specified
 *                      length.
 * \return              Unspecified if \p alg is not a supported
 *                      MAC algorithm or if \p mac_length is too small or
 *                      too large for the specified MAC algorithm.
 */
#define PSA_ALG_TRUNCATED_MAC(mac_alg, mac_length)                      \
    (((mac_alg) & ~PSA_ALG_MAC_TRUNCATION_MASK) |                       \
     ((mac_length) << PSA_MAC_TRUNCATION_OFFSET & PSA_ALG_MAC_TRUNCATION_MASK))

/** Macro to build the base MAC algorithm corresponding to a truncated
 * MAC algorithm.
 *
 * \param mac_alg       A MAC algorithm identifier (value of type
 *                      #psa_algorithm_t such that #PSA_ALG_IS_MAC(\p alg)
 *                      is true). This may be a truncated or untruncated
 *                      MAC algorithm.
 *
 * \return              The corresponding base MAC algorithm.
 * \return              Unspecified if \p alg is not a supported
 *                      MAC algorithm.
 */
#define PSA_ALG_FULL_LENGTH_MAC(mac_alg)        \
    ((mac_alg) & ~PSA_ALG_MAC_TRUNCATION_MASK)

/** Length to which a MAC algorithm is truncated.
 *
 * \param mac_alg       A MAC algorithm identifier (value of type
 *                      #psa_algorithm_t such that #PSA_ALG_IS_MAC(\p alg)
 *                      is true).
 *
 * \return              Length of the truncated MAC in bytes.
 * \return              0 if \p alg is a non-truncated MAC algorithm.
 * \return              Unspecified if \p alg is not a supported
 *                      MAC algorithm.
 */
#define PSA_MAC_TRUNCATED_LENGTH(mac_alg)                               \
    (((mac_alg) & PSA_ALG_MAC_TRUNCATION_MASK) >> PSA_MAC_TRUNCATION_OFFSET)

#define PSA_ALG_CIPHER_MAC_BASE                 ((psa_algorithm_t)0x02c00000)
#define PSA_ALG_CBC_MAC                         ((psa_algorithm_t)0x02c00001)
#define PSA_ALG_CMAC                            ((psa_algorithm_t)0x02c00002)
#define PSA_ALG_GMAC                            ((psa_algorithm_t)0x02c00003)

/** Whether the specified algorithm is a MAC algorithm based on a block cipher.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is a MAC algorithm based on a block cipher, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_BLOCK_CIPHER_MAC(alg)                                \
    (((alg) & (PSA_ALG_CATEGORY_MASK | PSA_ALG_MAC_SUBCATEGORY_MASK)) == \
     PSA_ALG_CIPHER_MAC_BASE)

#define PSA_ALG_CIPHER_STREAM_FLAG              ((psa_algorithm_t)0x00800000)
#define PSA_ALG_CIPHER_FROM_BLOCK_FLAG          ((psa_algorithm_t)0x00400000)

/** Whether the specified algorithm is a stream cipher.
 *
 * A stream cipher is a symmetric cipher that encrypts or decrypts messages
 * by applying a bitwise-xor with a stream of bytes that is generated
 * from a key.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is a stream cipher algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier or if it is not a symmetric cipher algorithm.
 */
#define PSA_ALG_IS_STREAM_CIPHER(alg)            \
    (((alg) & (PSA_ALG_CATEGORY_MASK | PSA_ALG_CIPHER_STREAM_FLAG)) == \
        (PSA_ALG_CATEGORY_CIPHER | PSA_ALG_CIPHER_STREAM_FLAG))

/** The ARC4 stream cipher algorithm.
 */
#define PSA_ALG_ARC4                            ((psa_algorithm_t)0x04800001)

/** The CTR stream cipher mode.
 *
 * CTR is a stream cipher which is built from a block cipher.
 * The underlying block cipher is determined by the key type.
 * For example, to use AES-128-CTR, use this algorithm with
 * a key of type #PSA_KEY_TYPE_AES and a length of 128 bits (16 bytes).
 */
#define PSA_ALG_CTR                             ((psa_algorithm_t)0x04c00001)

#define PSA_ALG_CFB                             ((psa_algorithm_t)0x04c00002)

#define PSA_ALG_OFB                             ((psa_algorithm_t)0x04c00003)

/** The XTS cipher mode.
 *
 * XTS is a cipher mode which is built from a block cipher. It requires at
 * least one full block of input, but beyond this minimum the input
 * does not need to be a whole number of blocks.
 */
#define PSA_ALG_XTS                             ((psa_algorithm_t)0x044000ff)

/** The CBC block cipher chaining mode, with no padding.
 *
 * The underlying block cipher is determined by the key type.
 *
 * This symmetric cipher mode can only be used with messages whose lengths
 * are whole number of blocks for the chosen block cipher.
 */
#define PSA_ALG_CBC_NO_PADDING                  ((psa_algorithm_t)0x04600100)

/** The CBC block cipher chaining mode with PKCS#7 padding.
 *
 * The underlying block cipher is determined by the key type.
 *
 * This is the padding method defined by PKCS#7 (RFC 2315) &sect;10.3.
 */
#define PSA_ALG_CBC_PKCS7                       ((psa_algorithm_t)0x04600101)

#define PSA_ALG_CCM                             ((psa_algorithm_t)0x06001001)
#define PSA_ALG_GCM                             ((psa_algorithm_t)0x06001002)

/* In the encoding of a AEAD algorithm, the bits corresponding to
 * PSA_ALG_AEAD_TAG_LENGTH_MASK encode the length of the AEAD tag.
 * The constants for default lengths follow this encoding.
 */
#define PSA_ALG_AEAD_TAG_LENGTH_MASK            ((psa_algorithm_t)0x00003f00)
#define PSA_AEAD_TAG_LENGTH_OFFSET 8

/** Macro to build a shortened AEAD algorithm.
 *
 * A shortened AEAD algorithm is similar to the corresponding AEAD
 * algorithm, but has an authentication tag that consists of fewer bytes.
 * Depending on the algorithm, the tag length may affect the calculation
 * of the ciphertext.
 *
 * \param aead_alg      An AEAD algorithm identifier (value of type
 *                      #psa_algorithm_t such that #PSA_ALG_IS_AEAD(\p alg)
 *                      is true).
 * \param tag_length    Desired length of the authentication tag in bytes.
 *
 * \return              The corresponding AEAD algorithm with the specified
 *                      length.
 * \return              Unspecified if \p alg is not a supported
 *                      AEAD algorithm or if \p tag_length is not valid
 *                      for the specified AEAD algorithm.
 */
#define PSA_ALG_AEAD_WITH_TAG_LENGTH(aead_alg, tag_length)              \
    (((aead_alg) & ~PSA_ALG_AEAD_TAG_LENGTH_MASK) |                     \
     ((tag_length) << PSA_AEAD_TAG_LENGTH_OFFSET &                      \
      PSA_ALG_AEAD_TAG_LENGTH_MASK))

/** Calculate the corresponding AEAD algorithm with the default tag length.
 *
 * \param aead_alg      An AEAD algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_AEAD(\p alg) is true).
 *
 * \return              The corresponding AEAD algorithm with the default
 *                      tag length for that algorithm.
 */
#define PSA_ALG_AEAD_WITH_DEFAULT_TAG_LENGTH(aead_alg)                  \
    (                                                                   \
        PSA__ALG_AEAD_WITH_DEFAULT_TAG_LENGTH__CASE(aead_alg, PSA_ALG_CCM) \
        PSA__ALG_AEAD_WITH_DEFAULT_TAG_LENGTH__CASE(aead_alg, PSA_ALG_GCM) \
        0)
#define PSA__ALG_AEAD_WITH_DEFAULT_TAG_LENGTH__CASE(aead_alg, ref)      \
    PSA_ALG_AEAD_WITH_TAG_LENGTH(aead_alg, 0) ==                        \
    PSA_ALG_AEAD_WITH_TAG_LENGTH(ref, 0) ?  \
    ref :

#define PSA_ALG_RSA_PKCS1V15_SIGN_BASE          ((psa_algorithm_t)0x10020000)
/** RSA PKCS#1 v1.5 signature with hashing.
 *
 * This is the signature scheme defined by RFC 8017
 * (PKCS#1: RSA Cryptography Specifications) under the name
 * RSASSA-PKCS1-v1_5.
 *
 * \param hash_alg      A hash algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_HASH(\p hash_alg) is true).
 *                      This includes #PSA_ALG_ANY_HASH
 *                      when specifying the algorithm in a usage policy.
 *
 * \return              The corresponding RSA PKCS#1 v1.5 signature algorithm.
 * \return              Unspecified if \p alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg)                             \
    (PSA_ALG_RSA_PKCS1V15_SIGN_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))
/** Raw PKCS#1 v1.5 signature.
 *
 * The input to this algorithm is the DigestInfo structure used by
 * RFC 8017 (PKCS#1: RSA Cryptography Specifications), &sect;9.2
 * steps 3&ndash;6.
 */
#define PSA_ALG_RSA_PKCS1V15_SIGN_RAW PSA_ALG_RSA_PKCS1V15_SIGN_BASE
#define PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)                               \
    (((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_RSA_PKCS1V15_SIGN_BASE)

#define PSA_ALG_RSA_PSS_BASE               ((psa_algorithm_t)0x10030000)
/** RSA PSS signature with hashing.
 *
 * This is the signature scheme defined by RFC 8017
 * (PKCS#1: RSA Cryptography Specifications) under the name
 * RSASSA-PSS, with the message generation function MGF1, and with
 * a salt length equal to the length of the hash. The specified
 * hash algorithm is used to hash the input message, to create the
 * salted hash, and for the mask generation.
 *
 * \param hash_alg      A hash algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_HASH(\p hash_alg) is true).
 *                      This includes #PSA_ALG_ANY_HASH
 *                      when specifying the algorithm in a usage policy.
 *
 * \return              The corresponding RSA PSS signature algorithm.
 * \return              Unspecified if \p alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_RSA_PSS(hash_alg)                               \
    (PSA_ALG_RSA_PSS_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))
#define PSA_ALG_IS_RSA_PSS(alg)                                 \
    (((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_RSA_PSS_BASE)

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
 * \return              Unspecified if \p alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_DSA(hash_alg)                             \
    (PSA_ALG_DSA_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))
#define PSA_ALG_DETERMINISTIC_DSA_BASE          ((psa_algorithm_t)0x10050000)
#define PSA_ALG_DSA_DETERMINISTIC_FLAG          ((psa_algorithm_t)0x00010000)
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

#define PSA_ALG_ECDSA_BASE                      ((psa_algorithm_t)0x10060000)
/** ECDSA signature with hashing.
 *
 * This is the ECDSA signature scheme defined by ANSI X9.62,
 * with a random per-message secret number (*k*).
 *
 * The representation of the signature as a byte string consists of
 * the concatentation of the signature values *r* and *s*. Each of
 * *r* and *s* is encoded as an *N*-octet string, where *N* is the length
 * of the base point of the curve in octets. Each value is represented
 * in big-endian order (most significant octet first).
 *
 * \param hash_alg      A hash algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_HASH(\p hash_alg) is true).
 *                      This includes #PSA_ALG_ANY_HASH
 *                      when specifying the algorithm in a usage policy.
 *
 * \return              The corresponding ECDSA signature algorithm.
 * \return              Unspecified if \p alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_ECDSA(hash_alg)                                 \
    (PSA_ALG_ECDSA_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))
/** ECDSA signature without hashing.
 *
 * This is the same signature scheme as #PSA_ALG_ECDSA(), but
 * without specifying a hash algorithm. This algorithm may only be
 * used to sign or verify a sequence of bytes that should be an
 * already-calculated hash. Note that the input is padded with
 * zeros on the left or truncated on the left as required to fit
 * the curve size.
 */
#define PSA_ALG_ECDSA_ANY PSA_ALG_ECDSA_BASE
#define PSA_ALG_DETERMINISTIC_ECDSA_BASE        ((psa_algorithm_t)0x10070000)
/** Deterministic ECDSA signature with hashing.
 *
 * This is the deterministic ECDSA signature scheme defined by RFC 6979.
 *
 * The representation of a signature is the same as with #PSA_ALG_ECDSA().
 *
 * Note that when this algorithm is used for verification, signatures
 * made with randomized ECDSA (#PSA_ALG_ECDSA(\p hash_alg)) with the
 * same private key are accepted. In other words,
 * #PSA_ALG_DETERMINISTIC_ECDSA(\p hash_alg) differs from
 * #PSA_ALG_ECDSA(\p hash_alg) only for signature, not for verification.
 *
 * \param hash_alg      A hash algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_HASH(\p hash_alg) is true).
 *                      This includes #PSA_ALG_ANY_HASH
 *                      when specifying the algorithm in a usage policy.
 *
 * \return              The corresponding deterministic ECDSA signature
 *                      algorithm.
 * \return              Unspecified if \p alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_DETERMINISTIC_ECDSA(hash_alg)                           \
    (PSA_ALG_DETERMINISTIC_ECDSA_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))
#define PSA_ALG_IS_ECDSA(alg)                                           \
    (((alg) & ~PSA_ALG_HASH_MASK & ~PSA_ALG_DSA_DETERMINISTIC_FLAG) ==  \
     PSA_ALG_ECDSA_BASE)
#define PSA_ALG_ECDSA_IS_DETERMINISTIC(alg)             \
    (((alg) & PSA_ALG_DSA_DETERMINISTIC_FLAG) != 0)
#define PSA_ALG_IS_DETERMINISTIC_ECDSA(alg)                             \
    (PSA_ALG_IS_ECDSA(alg) && PSA_ALG_ECDSA_IS_DETERMINISTIC(alg))
#define PSA_ALG_IS_RANDOMIZED_ECDSA(alg)                                \
    (PSA_ALG_IS_ECDSA(alg) && !PSA_ALG_ECDSA_IS_DETERMINISTIC(alg))

/** Whether the specified algorithm is a hash-and-sign algorithm.
 *
 * Hash-and-sign algorithms are public-key signature algorithms structured
 * in two parts: first the calculation of a hash in a way that does not
 * depend on the key, then the calculation of a signature from the
 * hash value and the key.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is a hash-and-sign algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_HASH_AND_SIGN(alg)                                   \
    (PSA_ALG_IS_RSA_PSS(alg) || PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) ||    \
     PSA_ALG_IS_DSA(alg) || PSA_ALG_IS_ECDSA(alg))

/** Get the hash used by a hash-and-sign signature algorithm.
 *
 * A hash-and-sign algorithm is a signature algorithm which is
 * composed of two phases: first a hashing phase which does not use
 * the key and produces a hash of the input message, then a signing
 * phase which only uses the hash and the key and not the message
 * itself.
 *
 * \param alg   A signature algorithm (\c PSA_ALG_XXX value such that
 *              #PSA_ALG_IS_SIGN(\p alg) is true).
 *
 * \return      The underlying hash algorithm if \p alg is a hash-and-sign
 *              algorithm.
 * \return      0 if \p alg is a signature algorithm that does not
 *              follow the hash-and-sign structure.
 * \return      Unspecified if \p alg is not a signature algorithm or
 *              if it is not supported by the implementation.
 */
#define PSA_ALG_SIGN_GET_HASH(alg)                                     \
    (PSA_ALG_IS_HASH_AND_SIGN(alg) ?                                   \
     ((alg) & PSA_ALG_HASH_MASK) == 0 ? /*"raw" algorithm*/ 0 :        \
     ((alg) & PSA_ALG_HASH_MASK) | PSA_ALG_CATEGORY_HASH :             \
     0)

/** RSA PKCS#1 v1.5 encryption.
 */
#define PSA_ALG_RSA_PKCS1V15_CRYPT              ((psa_algorithm_t)0x12020000)

#define PSA_ALG_RSA_OAEP_BASE                   ((psa_algorithm_t)0x12030000)
/** RSA OAEP encryption.
 *
 * This is the encryption scheme defined by RFC 8017
 * (PKCS#1: RSA Cryptography Specifications) under the name
 * RSAES-OAEP, with the message generation function MGF1.
 *
 * \param hash_alg      The hash algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_HASH(\p hash_alg) is true) to use
 *                      for MGF1.
 *
 * \return              The corresponding RSA OAEP signature algorithm.
 * \return              Unspecified if \p alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_RSA_OAEP(hash_alg)                              \
    (PSA_ALG_RSA_OAEP_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))
#define PSA_ALG_IS_RSA_OAEP(alg)                                \
    (((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_RSA_OAEP_BASE)
#define PSA_ALG_RSA_OAEP_GET_HASH(alg)                          \
    (PSA_ALG_IS_RSA_OAEP(alg) ?                                 \
     ((alg) & PSA_ALG_HASH_MASK) | PSA_ALG_CATEGORY_HASH :      \
     0)

#define PSA_ALG_HKDF_BASE                       ((psa_algorithm_t)0x30000100)
/** Macro to build an HKDF algorithm.
 *
 * For example, `PSA_ALG_HKDF(PSA_ALG_SHA256)` is HKDF using HMAC-SHA-256.
 *
 * \param hash_alg      A hash algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_HASH(\p hash_alg) is true).
 *
 * \return              The corresponding HKDF algorithm.
 * \return              Unspecified if \p alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_HKDF(hash_alg)                                  \
    (PSA_ALG_HKDF_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))
/** Whether the specified algorithm is an HKDF algorithm.
 *
 * HKDF is a family of key derivation algorithms that are based on a hash
 * function and the HMAC construction.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \c alg is an HKDF algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \c alg is not a supported
 *         key derivation algorithm identifier.
 */
#define PSA_ALG_IS_HKDF(alg)                            \
    (((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_HKDF_BASE)
#define PSA_ALG_HKDF_GET_HASH(hkdf_alg)                         \
    (PSA_ALG_CATEGORY_HASH | ((hkdf_alg) & PSA_ALG_HASH_MASK))

#define PSA_ALG_TLS12_PRF_BASE                     ((psa_algorithm_t)0x30000200)
/** Macro to build a TLS-1.2 PRF algorithm.
 *
 * TLS 1.2 uses a custom pseudorandom function (PRF) for key schedule,
 * specified in Section 5 of RFC 5246. It is based on HMAC and can be
 * used with either SHA-256 or SHA-384.
 *
 * For the application to TLS-1.2, the salt and label arguments passed
 * to psa_key_derivation() are what's called 'seed' and 'label' in RFC 5246,
 * respectively. For example, for TLS key expansion, the salt is the
 * concatenation of ServerHello.Random + ClientHello.Random,
 * while the label is "key expansion".
 *
 * For example, `PSA_ALG_TLS12_PRF(PSA_ALG_SHA256)` represents the
 * TLS 1.2 PRF using HMAC-SHA-256.
 *
 * \param hash_alg      A hash algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_HASH(\p hash_alg) is true).
 *
 * \return              The corresponding TLS-1.2 PRF algorithm.
 * \return              Unspecified if \p alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_TLS12_PRF(hash_alg)                                  \
    (PSA_ALG_TLS12_PRF_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))

/** Whether the specified algorithm is a TLS-1.2 PRF algorithm.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \c alg is a TLS-1.2 PRF algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \c alg is not a supported
 *         key derivation algorithm identifier.
 */
#define PSA_ALG_IS_TLS12_PRF(alg)                                    \
    (((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_TLS12_PRF_BASE)
#define PSA_ALG_TLS12_PRF_GET_HASH(hkdf_alg)                         \
    (PSA_ALG_CATEGORY_HASH | ((hkdf_alg) & PSA_ALG_HASH_MASK))

#define PSA_ALG_TLS12_PSK_TO_MS_BASE ((psa_algorithm_t)0x30000300)
/** Macro to build a TLS-1.2 PSK-to-MasterSecret algorithm.
 *
 * In a pure-PSK handshake in TLS 1.2, the master secret is derived
 * from the PreSharedKey (PSK) through the application of padding
 * (RFC 4279, Section 2) and the TLS-1.2 PRF (RFC 5246, Section 5).
 * The latter is based on HMAC and can be used with either SHA-256
 * or SHA-384.
 *
 * For the application to TLS-1.2, the salt passed to psa_key_derivation()
 * (and forwarded to the TLS-1.2 PRF) is the concatenation of the
 * ClientHello.Random + ServerHello.Random, while the label is "master secret"
 * or "extended master secret".
 *
 * For example, `PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA256)` represents the
 * TLS-1.2 PSK to MasterSecret derivation PRF using HMAC-SHA-256.
 *
 * \param hash_alg      A hash algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_HASH(\p hash_alg) is true).
 *
 * \return              The corresponding TLS-1.2 PSK to MS algorithm.
 * \return              Unspecified if \p alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_TLS12_PSK_TO_MS(hash_alg)                                  \
    (PSA_ALG_TLS12_PSK_TO_MS_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))

/** Whether the specified algorithm is a TLS-1.2 PSK to MS algorithm.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \c alg is a TLS-1.2 PSK to MS algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \c alg is not a supported
 *         key derivation algorithm identifier.
 */
#define PSA_ALG_IS_TLS12_PSK_TO_MS(alg)                                    \
    (((alg) & ~PSA_ALG_HASH_MASK) == PSA_ALG_TLS12_PSK_TO_MS_BASE)
#define PSA_ALG_TLS12_PSK_TO_MS_GET_HASH(hkdf_alg)                         \
    (PSA_ALG_CATEGORY_HASH | ((hkdf_alg) & PSA_ALG_HASH_MASK))

#define PSA_ALG_KEY_DERIVATION_MASK             ((psa_algorithm_t)0x010fffff)

/** Use a shared secret as is.
 *
 * Specify this algorithm as the selection component of a key agreement
 * to use the raw result of the key agreement as key material.
 *
 * \warning The raw result of a key agreement algorithm such as finite-field
 * Diffie-Hellman or elliptic curve Diffie-Hellman has biases and should
 * not be used directly as key material. It can however be used as the secret
 * input in a key derivation algorithm.
 */
#define PSA_ALG_SELECT_RAW                      ((psa_algorithm_t)0x31000001)

#define PSA_ALG_KEY_AGREEMENT_GET_KDF(alg)                              \
    (((alg) & PSA_ALG_KEY_DERIVATION_MASK) | PSA_ALG_CATEGORY_KEY_DERIVATION)

#define PSA_ALG_KEY_AGREEMENT_GET_BASE(alg)                              \
    ((alg) & ~PSA_ALG_KEY_DERIVATION_MASK)

#define PSA_ALG_FFDH_BASE                       ((psa_algorithm_t)0x22100000)
/** The Diffie-Hellman key agreement algorithm.
 *
 * This algorithm combines the finite-field Diffie-Hellman (DH) key
 * agreement, also known as Diffie-Hellman-Merkle (DHM) key agreement,
 * to produce a shared secret from a private key and the peer's
 * public key, with a key selection or key derivation algorithm to produce
 * one or more shared keys and other shared cryptographic material.
 *
 * The shared secret produced by key agreement and passed as input to the
 * derivation or selection algorithm \p kdf_alg is the shared secret
 * `g^{ab}` in big-endian format.
 * It is `ceiling(m / 8)` bytes long where `m` is the size of the prime `p`
 * in bits.
 *
 * \param kdf_alg       A key derivation algorithm (\c PSA_ALG_XXX value such
 *                      that #PSA_ALG_IS_KEY_DERIVATION(\p hash_alg) is true)
 *                      or a key selection algorithm (\c PSA_ALG_XXX value such
 *                      that #PSA_ALG_IS_KEY_SELECTION(\p hash_alg) is true).
 *
 * \return              The Diffie-Hellman algorithm with the specified
 *                      selection or derivation algorithm.
 */
#define PSA_ALG_FFDH(kdf_alg) \
    (PSA_ALG_FFDH_BASE | ((kdf_alg) & PSA_ALG_KEY_DERIVATION_MASK))
/** Whether the specified algorithm is a finite field Diffie-Hellman algorithm.
 *
 * This includes every supported key selection or key agreement algorithm
 * for the output of the Diffie-Hellman calculation.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \c alg is a finite field Diffie-Hellman algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \c alg is not a supported
 *         key agreement algorithm identifier.
 */
#define PSA_ALG_IS_FFDH(alg) \
    (PSA_ALG_KEY_AGREEMENT_GET_BASE(alg) == PSA_ALG_FFDH_BASE)

#define PSA_ALG_ECDH_BASE                       ((psa_algorithm_t)0x22200000)
/** The elliptic curve Diffie-Hellman (ECDH) key agreement algorithm.
 *
 * This algorithm combines the elliptic curve Diffie-Hellman key
 * agreement to produce a shared secret from a private key and the peer's
 * public key, with a key selection or key derivation algorithm to produce
 * one or more shared keys and other shared cryptographic material.
 *
 * The shared secret produced by key agreement and passed as input to the
 * derivation or selection algorithm \p kdf_alg is the x-coordinate of
 * the shared secret point. It is always `ceiling(m / 8)` bytes long where
 * `m` is the bit size associated with the curve, i.e. the bit size of the
 * order of the curve's coordinate field. When `m` is not a multiple of 8,
 * the byte containing the most significant bit of the shared secret
 * is padded with zero bits. The byte order is either little-endian
 * or big-endian depending on the curve type.
 *
 * - For Montgomery curves (curve types `PSA_ECC_CURVE_CURVEXXX`),
 *   the shared secret is the x-coordinate of `d_A Q_B = d_B Q_A`
 *   in little-endian byte order.
 *   The bit size is 448 for Curve448 and 255 for Curve25519.
 * - For Weierstrass curves over prime fields (curve types
 *   `PSA_ECC_CURVE_SECPXXX` and `PSA_ECC_CURVE_BRAINPOOL_PXXX`),
 *   the shared secret is the x-coordinate of `d_A Q_B = d_B Q_A`
 *   in big-endian byte order.
 *   The bit size is `m = ceiling(log_2(p))` for the field `F_p`.
 * - For Weierstrass curves over binary fields (curve types
 *   `PSA_ECC_CURVE_SECTXXX`),
 *   the shared secret is the x-coordinate of `d_A Q_B = d_B Q_A`
 *   in big-endian byte order.
 *   The bit size is `m` for the field `F_{2^m}`.
 *
 * \param kdf_alg       A key derivation algorithm (\c PSA_ALG_XXX value such
 *                      that #PSA_ALG_IS_KEY_DERIVATION(\p hash_alg) is true)
 *                      or a selection algorithm (\c PSA_ALG_XXX value such
 *                      that #PSA_ALG_IS_KEY_SELECTION(\p hash_alg) is true).
 *
 * \return              The Diffie-Hellman algorithm with the specified
 *                      selection or derivation algorithm.
 */
#define PSA_ALG_ECDH(kdf_alg) \
    (PSA_ALG_ECDH_BASE | ((kdf_alg) & PSA_ALG_KEY_DERIVATION_MASK))
/** Whether the specified algorithm is an elliptic curve Diffie-Hellman
 * algorithm.
 *
 * This includes every supported key selection or key agreement algorithm
 * for the output of the Diffie-Hellman calculation.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \c alg is an elliptic curve Diffie-Hellman algorithm,
 *         0 otherwise.
 *         This macro may return either 0 or 1 if \c alg is not a supported
 *         key agreement algorithm identifier.
 */
#define PSA_ALG_IS_ECDH(alg) \
    (PSA_ALG_KEY_AGREEMENT_GET_BASE(alg) == PSA_ALG_ECDH_BASE)

/** Whether the specified algorithm encoding is a wildcard.
 *
 * Wildcard values may only be used to set the usage algorithm field in
 * a policy, not to perform an operation.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \c alg is a wildcard algorithm encoding.
 * \return 0 if \c alg is a non-wildcard algorithm encoding (suitable for
 *         an operation).
 * \return This macro may return either 0 or 1 if \c alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_WILDCARD(alg)                        \
    (PSA_ALG_IS_HASH_AND_SIGN(alg) ?                    \
     PSA_ALG_SIGN_GET_HASH(alg) == PSA_ALG_ANY_HASH :   \
     (alg) == PSA_ALG_ANY_HASH)

/**@}*/

/** \defgroup key_lifetimes Key lifetimes
 * @{
 */

/** A volatile key only exists as long as the handle to it is not closed.
 * The key material is guaranteed to be erased on a power reset.
 */
#define PSA_KEY_LIFETIME_VOLATILE               ((psa_key_lifetime_t)0x00000000)

/** The default storage area for persistent keys.
 *
 * A persistent key remains in storage until it is explicitly destroyed or
 * until the corresponding storage area is wiped. This specification does
 * not define any mechanism to wipe a storage area, but implementations may
 * provide their own mechanism (for example to perform a factory reset,
 * to prepare for device refurbishment, or to uninstall an application).
 *
 * This lifetime value is the default storage area for the calling
 * application. Implementations may offer other storage areas designated
 * by other lifetime values as implementation-specific extensions.
 */
#define PSA_KEY_LIFETIME_PERSISTENT             ((psa_key_lifetime_t)0x00000001)

/**@}*/

/** \defgroup policy Key policies
 * @{
 */

/** Whether the key may be exported.
 *
 * A public key or the public part of a key pair may always be exported
 * regardless of the value of this permission flag.
 *
 * If a key does not have export permission, implementations shall not
 * allow the key to be exported in plain form from the cryptoprocessor,
 * whether through psa_export_key() or through a proprietary interface.
 * The key may however be exportable in a wrapped form, i.e. in a form
 * where it is encrypted by another key.
 */
#define PSA_KEY_USAGE_EXPORT                    ((psa_key_usage_t)0x00000001)

/** Whether the key may be used to encrypt a message.
 *
 * This flag allows the key to be used for a symmetric encryption operation,
 * for an AEAD encryption-and-authentication operation,
 * or for an asymmetric encryption operation,
 * if otherwise permitted by the key's type and policy.
 *
 * For a key pair, this concerns the public key.
 */
#define PSA_KEY_USAGE_ENCRYPT                   ((psa_key_usage_t)0x00000100)

/** Whether the key may be used to decrypt a message.
 *
 * This flag allows the key to be used for a symmetric decryption operation,
 * for an AEAD decryption-and-verification operation,
 * or for an asymmetric decryption operation,
 * if otherwise permitted by the key's type and policy.
 *
 * For a key pair, this concerns the private key.
 */
#define PSA_KEY_USAGE_DECRYPT                   ((psa_key_usage_t)0x00000200)

/** Whether the key may be used to sign a message.
 *
 * This flag allows the key to be used for a MAC calculation operation
 * or for an asymmetric signature operation,
 * if otherwise permitted by the key's type and policy.
 *
 * For a key pair, this concerns the private key.
 */
#define PSA_KEY_USAGE_SIGN                      ((psa_key_usage_t)0x00000400)

/** Whether the key may be used to verify a message signature.
 *
 * This flag allows the key to be used for a MAC verification operation
 * or for an asymmetric signature verification operation,
 * if otherwise permitted by by the key's type and policy.
 *
 * For a key pair, this concerns the public key.
 */
#define PSA_KEY_USAGE_VERIFY                    ((psa_key_usage_t)0x00000800)

/** Whether the key may be used to derive other keys.
 */
#define PSA_KEY_USAGE_DERIVE                    ((psa_key_usage_t)0x00001000)

/**@}*/

#endif /* PSA_CRYPTO_VALUES_H */
