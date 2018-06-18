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

/** \brief Key slot number.
 *
 * This type represents key slots. It must be an unsigned integral
 * type. The choice of type is implementation-dependent.
 * 0 is not a valid key slot number. The meaning of other values is
 * implementation dependent.
 *
 * At any given point in time, each key slot either contains a
 * cryptographic object, or is empty. Key slots are persistent:
 * once set, the cryptographic object remains in the key slot until
 * explicitly destroyed.
 */
typedef _unsigned_integral_type_ psa_key_slot_t;

/**@}*/
#endif /* __DOXYGEN_ONLY__ */

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup basic Basic definitions
 * @{
 */

#if defined(PSA_SUCCESS)
/* If PSA_SUCCESS is defined, assume that PSA crypto is being used
 * together with PSA IPC, which also defines the identifier
 * PSA_SUCCESS. We must not define PSA_SUCCESS ourselves in that case;
 * the other error code names don't clash. Also define psa_status_t as
 * an alias for the type used by PSA IPC. This is a temporary hack
 * until we unify error reporting in PSA IPC and PSA crypto.
 *
 * Note that psa_defs.h must be included before this header!
 */
typedef psa_error_t psa_status_t;

#else /* defined(PSA_SUCCESS) */

/**
 * \brief Function return status.
 *
 * This is either #PSA_SUCCESS (which is zero), indicating success,
 * or a nonzero value indicating that an error occurred. Errors are
 * encoded as one of the \c PSA_ERROR_xxx values defined here.
 */
typedef int32_t psa_status_t;

/** The action was completed successfully. */
#define PSA_SUCCESS ((psa_status_t)0)

#endif /* !defined(PSA_SUCCESS) */

/** An error occurred that does not correspond to any defined
 * failure cause.
 *
 * Implementations may use this error code if none of the other standard
 * error codes are applicable. */
#define PSA_ERROR_UNKNOWN_ERROR         ((psa_status_t)1)

/** The requested operation or a parameter is not supported
 * by this implementation.
 *
 * Implementations should return this error code when an enumeration
 * parameter such as a key type, algorithm, etc. is not recognized.
 * If a combination of parameters is recognized and identified as
 * not valid, return #PSA_ERROR_INVALID_ARGUMENT instead. */
#define PSA_ERROR_NOT_SUPPORTED         ((psa_status_t)2)

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
#define PSA_ERROR_NOT_PERMITTED         ((psa_status_t)3)

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
#define PSA_ERROR_BUFFER_TOO_SMALL      ((psa_status_t)4)

/** A slot is occupied, but must be empty to carry out the
 * requested action.
 *
 * If the slot number is invalid (i.e. the requested action could
 * not be performed even after erasing the slot's content),
 * implementations shall return #PSA_ERROR_INVALID_ARGUMENT instead. */
#define PSA_ERROR_OCCUPIED_SLOT         ((psa_status_t)5)

/** A slot is empty, but must be occupied to carry out the
 * requested action.
 *
 * If the slot number is invalid (i.e. the requested action could
 * not be performed even after creating appropriate content in the slot),
 * implementations shall return #PSA_ERROR_INVALID_ARGUMENT instead. */
#define PSA_ERROR_EMPTY_SLOT            ((psa_status_t)6)

/** The requested action cannot be performed in the current state.
 *
 * Multipart operations return this error when one of the
 * functions is called out of sequence. Refer to the function
 * descriptions for permitted sequencing of functions.
 *
 * Implementations shall not return this error code to indicate
 * that a key slot is occupied when it needs to be free or vice versa,
 * but shall return #PSA_ERROR_OCCUPIED_SLOT or #PSA_ERROR_EMPTY_SLOT
 * as applicable. */
#define PSA_ERROR_BAD_STATE             ((psa_status_t)7)

/** The parameters passed to the function are invalid.
 *
 * Implementations may return this error any time a parameter or
 * combination of parameters are recognized as invalid.
 *
 * Implementations shall not return this error code to indicate
 * that a key slot is occupied when it needs to be free or vice versa,
 * but shall return #PSA_ERROR_OCCUPIED_SLOT or #PSA_ERROR_EMPTY_SLOT
 * as applicable. */
#define PSA_ERROR_INVALID_ARGUMENT      ((psa_status_t)8)

/** There is not enough runtime memory.
 *
 * If the action is carried out across multiple security realms, this
 * error can refer to available memory in any of the security realms. */
#define PSA_ERROR_INSUFFICIENT_MEMORY   ((psa_status_t)9)

/** There is not enough persistent storage.
 *
 * Functions that modify the key storage return this error code if
 * there is insufficient storage space on the host media. In addition,
 * many functions that do not otherwise access storage may return this
 * error code if the implementation requires a mandatory log entry for
 * the requested action and the log storage space is full. */
#define PSA_ERROR_INSUFFICIENT_STORAGE  ((psa_status_t)10)

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
#define PSA_ERROR_COMMUNICATION_FAILURE ((psa_status_t)11)

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
#define PSA_ERROR_STORAGE_FAILURE       ((psa_status_t)12)

/** A hardware failure was detected.
 *
 * A hardware failure may be transient or permanent depending on the
 * cause. */
#define PSA_ERROR_HARDWARE_FAILURE      ((psa_status_t)13)

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
#define PSA_ERROR_TAMPERING_DETECTED    ((psa_status_t)14)

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
#define PSA_ERROR_INSUFFICIENT_ENTROPY  ((psa_status_t)15)

/** The signature, MAC or hash is incorrect.
 *
 * Verification functions return this error if the verification
 * calculations completed successfully, and the value to be verified
 * was determined to be incorrect.
 *
 * If the value to verify has an invalid size, implementations may return
 * either #PSA_ERROR_INVALID_ARGUMENT or #PSA_ERROR_INVALID_SIGNATURE. */
#define PSA_ERROR_INVALID_SIGNATURE     ((psa_status_t)16)

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
#define PSA_ERROR_INVALID_PADDING       ((psa_status_t)17)

/** The generator has insufficient capacity left.
 *
 * Once a function returns this error, attempts to read from the
 * generator will always return this error. */
#define PSA_ERROR_INSUFFICIENT_CAPACITY ((psa_status_t)18)

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

#define PSA_BITS_TO_BYTES(bits) (((bits) + 7) / 8)
#define PSA_BYTES_TO_BITS(bytes) ((bytes) * 8)

/**@}*/

/** \defgroup crypto_types Key and algorithm types
 * @{
 */

/** \brief Encoding of a key type.
 */
typedef uint32_t psa_key_type_t;

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
#define PSA_KEY_TYPE_IS_ECC_KEYPAIR(type)                               \
    (((type) & ~PSA_KEY_TYPE_ECC_CURVE_MASK) ==                         \
     PSA_KEY_TYPE_ECC_KEYPAIR_BASE)
#define PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(type)                            \
    (((type) & ~PSA_KEY_TYPE_ECC_CURVE_MASK) ==                         \
     PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE)

/** The type of PSA elliptic curve identifiers. */
typedef uint16_t psa_ecc_curve_t;
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

/** \brief Encoding of a cryptographic algorithm.
 *
 * For algorithms that can be applied to multiple key types, this type
 * does not encode the key type. For example, for symmetric ciphers
 * based on a block cipher, #psa_algorithm_t encodes the block cipher
 * mode and the padding mode while the block cipher itself is encoded
 * via #psa_key_type_t.
 */
typedef uint32_t psa_algorithm_t;

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
 * \param alg           A MAC algorithm identifier (value of type
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
#define PSA_ALG_TRUNCATED_MAC(alg, mac_length)                          \
    (((alg) & ~PSA_ALG_MAC_TRUNCATION_MASK) |                           \
     ((mac_length) << PSA_MAC_TRUNCATION_OFFSET & PSA_ALG_MAC_TRUNCATION_MASK))

/** Macro to build the base MAC algorithm corresponding to a truncated
 * MAC algorithm.
 *
 * \param alg           A MAC algorithm identifier (value of type
 *                      #psa_algorithm_t such that #PSA_ALG_IS_MAC(\p alg)
 *                      is true). This may be a truncated or untruncated
 *                      MAC algorithm.
 *
 * \return              The corresponding base MAC algorithm.
 * \return              Unspecified if \p alg is not a supported
 *                      MAC algorithm.
 */
#define PSA_ALG_FULL_LENGTH_MAC(alg)            \
    ((alg) & ~PSA_ALG_MAC_TRUNCATION_MASK)

/** Length to which a MAC algorithm is truncated.
 *
 * \param alg           A MAC algorithm identifier (value of type
 *                      #psa_algorithm_t such that #PSA_ALG_IS_MAC(\p alg)
 *                      is true).
 *
 * \return              Length of the truncated MAC in bytes.
 * \return              0 if \p alg is a non-truncated MAC algorithm.
 * \return              Unspecified if \p alg is not a supported
 *                      MAC algorithm.
 */
#define PSA_MAC_TRUNCATED_LENGTH(alg)           \
    (((alg) & PSA_ALG_MAC_TRUNCATION_MASK) >> PSA_MAC_TRUNCATION_OFFSET)

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
 * \param alg           A AEAD algorithm identifier (value of type
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
#define PSA_ALG_AEAD_WITH_TAG_LENGTH(alg, tag_length)                   \
    (((alg) & ~PSA_ALG_AEAD_TAG_LENGTH_MASK) |                          \
     ((tag_length) << PSA_AEAD_TAG_LENGTH_OFFSET &                      \
      PSA_ALG_AEAD_TAG_LENGTH_MASK))

/** Calculate the corresponding AEAD algorithm with the default tag length.
 *
 * \param alg   An AEAD algorithm (\c PSA_ALG_XXX value such that
 *              #PSA_ALG_IS_AEAD(\p alg) is true).
 *
 * \return      The corresponding AEAD algorithm with the default tag length
 *              for that algorithm.
 */
#define PSA_ALG_AEAD_WITH_DEFAULT_TAG_LENGTH(alg)                       \
    (                                                                   \
        PSA__ALG_AEAD_WITH_DEFAULT_TAG_LENGTH__CASE(alg, PSA_ALG_CCM)   \
        PSA__ALG_AEAD_WITH_DEFAULT_TAG_LENGTH__CASE(alg, PSA_ALG_GCM)   \
        0)
#define PSA__ALG_AEAD_WITH_DEFAULT_TAG_LENGTH__CASE(alg, ref) \
    PSA_ALG_AEAD_WITH_TAG_LENGTH(alg, 0) == \
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
    (PSA_ALG_IS_RSA_PSS(alg) || PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) ||   \
     PSA_ALG_IS_DSA(alg) || PSA_ALG_IS_ECDSA(alg) ?                    \
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

/**@}*/

/** \defgroup key_management Key management
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
 * \param key         Slot where the key will be stored. This must be a
 *                    valid slot for a key of the chosen type. It must
 *                    be unoccupied.
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
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The key type or key size is not supported, either by the
 *         implementation in general or in this particular slot.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key slot is invalid,
 *         or the key data is not correctly formatted.
 * \retval #PSA_ERROR_OCCUPIED_SLOT
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
psa_status_t psa_import_key(psa_key_slot_t key,
                            psa_key_type_t type,
                            const uint8_t *data,
                            size_t data_length);

/**
 * \brief Destroy a key and restore the slot to its default state.
 *
 * This function destroys the content of the key slot from both volatile
 * memory and, if applicable, non-volatile storage. Implementations shall
 * make a best effort to ensure that any previous content of the slot is
 * unrecoverable.
 *
 * This function also erases any metadata such as policies. It returns the
 * specified slot to its default state.
 *
 * \param key           The key slot to erase.
 *
 * \retval #PSA_SUCCESS
 *         The slot's content, if any, has been erased.
 * \retval #PSA_ERROR_NOT_PERMITTED
 *         The slot holds content and cannot be erased because it is
 *         read-only, either due to a policy or due to physical restrictions.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The specified slot number does not designate a valid slot.
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
psa_status_t psa_destroy_key(psa_key_slot_t key);

/**
 * \brief Get basic metadata about a key.
 *
 * \param key           Slot whose content is queried. This must
 *                      be an occupied key slot.
 * \param[out] type     On success, the key type (a \c PSA_KEY_TYPE_XXX value).
 *                      This may be a null pointer, in which case the key type
 *                      is not written.
 * \param[out] bits     On success, the key size in bits.
 *                      This may be a null pointer, in which case the key size
 *                      is not written.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_EMPTY_SLOT
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_get_key_information(psa_key_slot_t key,
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
 * \param key               Slot whose content is to be exported. This must
 *                          be an occupied key slot.
 * \param[out] data         Buffer where the key data is to be written.
 * \param data_size         Size of the \p data buffer in bytes.
 * \param[out] data_length  On success, the number of bytes
 *                          that make up the key data.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_EMPTY_SLOT
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
psa_status_t psa_export_key(psa_key_slot_t key,
                            uint8_t *data,
                            size_t data_size,
                            size_t *data_length);

/**
 * \brief Export a public key or the public part of a key pair in binary format.
 *
 * The output of this function can be passed to psa_import_key() to
 * create an object that is equivalent to the public key.
 *
 * The format is the DER representation defined by RFC 5280 as
 * `SubjectPublicKeyInfo`, with the `subjectPublicKey` format
 * specified below.
 * ```
 * SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm          AlgorithmIdentifier,
 *      subjectPublicKey   BIT STRING  }
 * AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm          OBJECT IDENTIFIER,
 *      parameters         ANY DEFINED BY algorithm OPTIONAL  }
 * ```
 *
 * - For RSA public keys (#PSA_KEY_TYPE_RSA_PUBLIC_KEY),
 *   the `subjectPublicKey` format is defined by RFC 3279 &sect;2.3.1 as
 *   `RSAPublicKey`,
 *   with the OID `rsaEncryption`,
 *   and with the parameters `NULL`.
 *   ```
 *   pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
 *                                  rsadsi(113549) pkcs(1) 1 }
 *   rsaEncryption OBJECT IDENTIFIER ::=  { pkcs-1 1 }
 *
 *   RSAPublicKey ::= SEQUENCE {
 *      modulus            INTEGER,    -- n
 *      publicExponent     INTEGER  }  -- e
 *   ```
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
 * - For elliptic curve public keys (key types for which
 *   #PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY is true),
 *   the `subjectPublicKey` format is defined by RFC 3279 &sect;2.3.5 as
 *   `ECPoint`, which contains the uncompressed
 *   representation defined by SEC1 &sect;2.3.3.
 *   The OID is `id-ecPublicKey`,
 *   and the parameters must be given as a `namedCurve` OID as specified in
 *   RFC 5480 &sect;2.1.1.1 or other applicable standards.
 *   ```
 *   ansi-X9-62 OBJECT IDENTIFIER ::=
 *                           { iso(1) member-body(2) us(840) 10045 }
 *   id-public-key-type OBJECT IDENTIFIER  ::= { ansi-X9.62 2 }
 *   id-ecPublicKey OBJECT IDENTIFIER ::= { id-publicKeyType 1 }
 *
 *   ECPoint ::= ...
 *      -- first 8 bits: 0x04;
 *      -- then x_P as a `ceiling(m/8)`-byte string, big endian;
 *      -- then y_P as a `ceiling(m/8)`-byte string, big endian;
 *      -- where `m` is the bit size associated with the curve,
 *      --       i.e. the bit size of `q` for a curve over `F_q`.
 *
 *   EcpkParameters ::= CHOICE { -- other choices are not allowed
 *      namedCurve    OBJECT IDENTIFIER }
 *   ```
 *
 * \param key               Slot whose content is to be exported. This must
 *                          be an occupied key slot.
 * \param[out] data         Buffer where the key data is to be written.
 * \param data_size         Size of the \p data buffer in bytes.
 * \param[out] data_length  On success, the number of bytes
 *                          that make up the key data.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_EMPTY_SLOT
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
psa_status_t psa_export_public_key(psa_key_slot_t key,
                                   uint8_t *data,
                                   size_t data_size,
                                   size_t *data_length);

/**@}*/

/** \defgroup policy Key policies
 * @{
 */

/** \brief Encoding of permitted usage on a key. */
typedef uint32_t psa_key_usage_t;

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

/** The type of the key policy data structure.
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_key_policy_s psa_key_policy_t;

/** \brief Initialize a key policy structure to a default that forbids all
 * usage of the key.
 *
 * \param[out] policy   The policy object to initialize.
 */
void psa_key_policy_init(psa_key_policy_t *policy);

/** \brief Set the standard fields of a policy structure.
 *
 * Note that this function does not make any consistency check of the
 * parameters. The values are only checked when applying the policy to
 * a key slot with psa_set_key_policy().
 *
 * \param[out] policy   The policy object to modify.
 * \param usage         The permitted uses for the key.
 * \param alg           The algorithm that the key may be used for.
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
 * \param key           The key slot whose policy is to be changed.
 * \param[in] policy    The policy object to query.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_OCCUPIED_SLOT
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
psa_status_t psa_set_key_policy(psa_key_slot_t key,
                                const psa_key_policy_t *policy);

/** \brief Get the usage policy for a key slot.
 *
 * \param key           The key slot whose policy is being queried.
 * \param[out] policy   On success, the key's policy.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_get_key_policy(psa_key_slot_t key,
                                psa_key_policy_t *policy);

/**@}*/

/** \defgroup persistence Key lifetime
 * @{
 */

/** Encoding of key lifetimes.
 */
typedef uint32_t psa_key_lifetime_t;

/** A volatile key slot retains its content as long as the application is
 * running. It is guaranteed to be erased on a power reset.
 */
#define PSA_KEY_LIFETIME_VOLATILE               ((psa_key_lifetime_t)0x00000000)

/** A persistent key slot retains its content as long as it is not explicitly
 * destroyed.
 */
#define PSA_KEY_LIFETIME_PERSISTENT             ((psa_key_lifetime_t)0x00000001)

/** A write-once key slot may not be modified once a key has been set.
 * It will retain its content as long as the device remains operational.
 */
#define PSA_KEY_LIFETIME_WRITE_ONCE             ((psa_key_lifetime_t)0x7fffffff)

/** \brief Retrieve the lifetime of a key slot.
 *
 * The assignment of lifetimes to slots is implementation-dependent.
 *
 * \param key           Slot to query.
 * \param[out] lifetime On success, the lifetime value.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key slot is invalid.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_get_key_lifetime(psa_key_slot_t key,
                                  psa_key_lifetime_t *lifetime);

/** \brief Change the lifetime of a key slot.
 *
 * Whether the lifetime of a key slot can be changed at all, and if so
 * whether the lifetime of an occupied key slot can be changed, is
 * implementation-dependent.
 *
 * When creating a persistent key, you must call this function before creating
 * the key material with psa_import_key(), psa_generate_key() or
 * psa_generator_import_key(). To open an existing persistent key, you must
 * call this function with the correct lifetime value before using the slot
 * for a cryptographic operation. Once a slot's lifetime has been set,
 * the lifetime remains associated with the slot until a subsequent call to
 * psa_set_key_lifetime(), until the key is wiped with psa_destroy_key or
 * until the application terminates (or disconnects from the cryptography
 * service, if the implementation offers such a possibility).
 *
 * \param key           Slot whose lifetime is to be changed.
 * \param lifetime      The lifetime value to set for the given key slot.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key slot is invalid,
 *         or the lifetime value is invalid.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The implementation does not support the specified lifetime value,
 *         at least for the specified key slot.
 * \retval #PSA_ERROR_OCCUPIED_SLOT
 *         The slot contains a key, and the implementation does not support
 *         changing the lifetime of an occupied slot.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_set_key_lifetime(psa_key_slot_t key,
                                  psa_key_lifetime_t lifetime);

/**@}*/

/** \defgroup hash Message digests
 * @{
 */

/** The type of the state data structure for multipart hash operations.
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_hash_operation_s psa_hash_operation_t;

/** The size of the output of psa_hash_finish(), in bytes.
 *
 * This is also the hash size that psa_hash_verify() expects.
 *
 * \param alg   A hash algorithm (\c PSA_ALG_XXX value such that
 *              #PSA_ALG_IS_HASH(\p alg) is true), or an HMAC algorithm
 *              (#PSA_ALG_HMAC(\c hash_alg) where \c hash_alg is a
 *              hash algorithm).
 *
 * \return The hash size for the specified hash algorithm.
 *         If the hash algorithm is not recognized, return 0.
 *         An implementation may return either 0 or the correct size
 *         for a hash algorithm that it recognizes, but does not support.
 */
#define PSA_HASH_SIZE(alg)                                      \
    (                                                           \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_MD2 ? 16 :            \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_MD4 ? 16 :            \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_MD5 ? 16 :            \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_RIPEMD160 ? 20 :      \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_1 ? 20 :          \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_224 ? 28 :        \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_256 ? 32 :        \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_384 ? 48 :        \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512 ? 64 :        \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512_224 ? 28 :    \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512_256 ? 32 :    \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_224 ? 28 :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_256 ? 32 :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_384 ? 48 :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_512 ? 64 :       \
        0)

/** Start a multipart hash operation.
 *
 * The sequence of operations to calculate a hash (message digest)
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Call psa_hash_setup() to specify the algorithm.
 * -# Call psa_hash_update() zero, one or more times, passing a fragment
 *    of the message each time. The hash that is calculated is the hash
 *    of the concatenation of these messages in order.
 * -# To calculate the hash, call psa_hash_finish().
 *    To compare the hash with an expected value, call psa_hash_verify().
 *
 * The application may call psa_hash_abort() at any time after the operation
 * has been initialized with psa_hash_setup().
 *
 * After a successful call to psa_hash_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_hash_update().
 * - A call to psa_hash_finish(), psa_hash_verify() or psa_hash_abort().
 *
 * \param[out] operation    The operation object to use.
 * \param alg               The hash algorithm to compute (\c PSA_ALG_XXX value
 *                          such that #PSA_ALG_IS_HASH(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported or is not a hash algorithm.
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
 *         The operation state is not valid (not started, or already completed).
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
 *         The operation state is not valid (not started, or already completed).
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
 *         The operation state is not valid (not started, or already completed).
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

/**@}*/

/** \defgroup MAC Message authentication codes
 * @{
 */

/** The type of the state data structure for multipart MAC operations.
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_mac_operation_s psa_mac_operation_t;

/** Start a multipart MAC calculation operation.
 *
 * This function sets up the calculation of the MAC
 * (message authentication code) of a byte string.
 * To verify the MAC of a message against an
 * expected value, use psa_mac_verify_setup() instead.
 *
 * The sequence of operations to calculate a MAC is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
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
 * has been initialized with psa_mac_sign_setup().
 *
 * After a successful call to psa_mac_sign_setup(), the application must
 * eventually terminate the operation through one of the following methods:
 * - A failed call to psa_mac_update().
 * - A call to psa_mac_sign_finish() or psa_mac_abort().
 *
 * \param[out] operation    The operation object to use.
 * \param key               Slot containing the key to use for the operation.
 * \param alg               The MAC algorithm to compute (\c PSA_ALG_XXX value
 *                          such that #PSA_ALG_IS_MAC(alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_EMPTY_SLOT
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
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_mac_sign_setup(psa_mac_operation_t *operation,
                                psa_key_slot_t key,
                                psa_algorithm_t alg);

/** Start a multipart MAC verification operation.
 *
 * This function sets up the verification of the MAC
 * (message authentication code) of a byte string against an expected value.
 *
 * The sequence of operations to verify a MAC is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
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
 * has been initialized with psa_mac_verify_setup().
 *
 * After a successful call to psa_mac_verify_setup(), the application must
 * eventually terminate the operation through one of the following methods:
 * - A failed call to psa_mac_update().
 * - A call to psa_mac_verify_finish() or psa_mac_abort().
 *
 * \param[out] operation    The operation object to use.
 * \param key               Slot containing the key to use for the operation.
 * \param alg               The MAC algorithm to compute (\c PSA_ALG_XXX value
 *                          such that #PSA_ALG_IS_MAC(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_EMPTY_SLOT
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
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_mac_verify_setup(psa_mac_operation_t *operation,
                                  psa_key_slot_t key,
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
 *         The operation state is not valid (not started, or already completed).
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
 *         The operation state is not valid (not started, or already completed).
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
 *         The operation state is not valid (not started, or already completed).
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
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_cipher_operation_s psa_cipher_operation_t;

/** Set the key for a multipart symmetric encryption operation.
 *
 * The sequence of operations to encrypt a message with a symmetric cipher
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
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
 * has been initialized with psa_cipher_encrypt_setup().
 *
 * After a successful call to psa_cipher_encrypt_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_cipher_generate_iv(), psa_cipher_set_iv()
 *   or psa_cipher_update().
 * - A call to psa_cipher_finish() or psa_cipher_abort().
 *
 * \param[out] operation        The operation object to use.
 * \param key                   Slot containing the key to use for the operation.
 * \param alg                   The cipher algorithm to compute
 *                              (\c PSA_ALG_XXX value such that
 *                              #PSA_ALG_IS_CIPHER(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_EMPTY_SLOT
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
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t *operation,
                                      psa_key_slot_t key,
                                      psa_algorithm_t alg);

/** Set the key for a multipart symmetric decryption operation.
 *
 * The sequence of operations to decrypt a message with a symmetric cipher
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
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
 * has been initialized with psa_cipher_decrypt_setup().
 *
 * After a successful call to psa_cipher_decrypt_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_cipher_update().
 * - A call to psa_cipher_finish() or psa_cipher_abort().
 *
 * \param[out] operation        The operation object to use.
 * \param key                   Slot containing the key to use for the operation.
 * \param alg                   The cipher algorithm to compute
 *                              (\c PSA_ALG_XXX value such that
 *                              #PSA_ALG_IS_CIPHER(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_EMPTY_SLOT
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
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t *operation,
                                      psa_key_slot_t key,
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
 *         The operation state is not valid (not started, or IV already set).
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
 *         The operation state is not valid (not started, or IV already set).
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
 *         The operation state is not valid (not started, IV required but
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
 *         The operation state is not valid (not started, IV required but
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

/** The tag size for an AEAD algorithm, in bytes.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(\p alg) is true).
 *
 * \return                    The tag size for the specified algorithm.
 *                            If the AEAD algorithm does not have an identified
 *                            tag that can be distinguished from the rest of
 *                            the ciphertext, return 0.
 *                            If the AEAD algorithm is not recognized, return 0.
 *                            An implementation may return either 0 or a
 *                            correct size for an AEAD algorithm that it
 *                            recognizes, but does not support.
 */
#define PSA_AEAD_TAG_LENGTH(alg)                                        \
    (PSA_ALG_IS_AEAD(alg) ?                                             \
     (((alg) & PSA_ALG_AEAD_TAG_LENGTH_MASK) >> PSA_AEAD_TAG_LENGTH_OFFSET) : \
     0)

/** Process an authenticated encryption operation.
 *
 * \param key                     Slot containing the key to use.
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
 * \retval #PSA_ERROR_EMPTY_SLOT
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
psa_status_t psa_aead_encrypt(psa_key_slot_t key,
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
 * \param key                     Slot containing the key to use.
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
 * \retval #PSA_ERROR_EMPTY_SLOT
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
psa_status_t psa_aead_decrypt(psa_key_slot_t key,
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
 * \brief ECDSA signature size for a given curve bit size
 *
 * \param curve_bits    Curve size in bits.
 * \return              Signature size in bytes.
 *
 * \note This macro returns a compile-time constant if its argument is one.
 */
#define PSA_ECDSA_SIGNATURE_SIZE(curve_bits)    \
    (PSA_BITS_TO_BYTES(curve_bits) * 2)

/**
 * \brief Sign a hash or short message with a private key.
 *
 * Note that to perform a hash-and-sign signature algorithm, you must
 * first calculate the hash by calling psa_hash_setup(), psa_hash_update()
 * and psa_hash_finish(). Then pass the resulting hash as the \p hash
 * parameter to this function. You can use #PSA_ALG_SIGN_GET_HASH(\p alg)
 * to determine the hash algorithm to use.
 *
 * \param key                   Key slot containing an asymmetric key pair.
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
psa_status_t psa_asymmetric_sign(psa_key_slot_t key,
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
 * \param key               Key slot containing a public key or an
 *                          asymmetric key pair.
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
psa_status_t psa_asymmetric_verify(psa_key_slot_t key,
                                   psa_algorithm_t alg,
                                   const uint8_t *hash,
                                   size_t hash_length,
                                   const uint8_t *signature,
                                   size_t signature_length);

#define PSA_RSA_MINIMUM_PADDING_SIZE(alg)                               \
    (PSA_ALG_IS_RSA_OAEP(alg) ?                                         \
     2 * PSA_HASH_FINAL_SIZE(PSA_ALG_RSA_OAEP_GET_HASH(alg)) + 1 :      \
     11 /*PKCS#1v1.5*/)

/**
 * \brief Encrypt a short message with a public key.
 *
 * \param key                   Key slot containing a public key or an
 *                              asymmetric key pair.
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
psa_status_t psa_asymmetric_encrypt(psa_key_slot_t key,
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
 * \param key                   Key slot containing an asymmetric key pair.
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
psa_status_t psa_asymmetric_decrypt(psa_key_slot_t key,
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
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_BAD_STATE
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
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
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_INSUFFICIENT_CAPACITY
 *                          There were fewer than \p output_length bytes
 *                          in the generator. Note that in this case, no
 *                          output is written to the output buffer.
 *                          The generator's capacity is set to 0, thus
 *                          subsequent calls to this function will not
 *                          succeed, even with a smaller output buffer.
 * \retval PSA_ERROR_BAD_STATE
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
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
 * \param key               Slot where the key will be stored. This must be a
 *                          valid slot for a key of the chosen type. It must
 *                          be unoccupied.
 * \param type              Key type (a \c PSA_KEY_TYPE_XXX value).
 *                          This must be a symmetric key type.
 * \param bits              Key size in bits.
 * \param[in,out] generator The generator object to read from.
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_ERROR_INSUFFICIENT_CAPACITY
 *                          There were fewer than \p output_length bytes
 *                          in the generator. Note that in this case, no
 *                          output is written to the output buffer.
 *                          The generator's capacity is set to 0, thus
 *                          subsequent calls to this function will not
 *                          succeed, even with a smaller output buffer.
 * \retval PSA_ERROR_NOT_SUPPORTED
 *         The key type or key size is not supported, either by the
 *         implementation in general or in this particular slot.
 * \retval PSA_ERROR_BAD_STATE
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         The key slot is invalid.
 * \retval PSA_ERROR_OCCUPIED_SLOT
 *         There is already a key in the specified slot.
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_INSUFFICIENT_STORAGE
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_generator_import_key(psa_key_slot_t key,
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
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_BAD_STATE
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
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
 * \param[in,out] generator       The generator object to set up. It must
 *                                have been initialized to all-bits-zero,
 *                                a logical zero (`{0}`),
 *                                \c PSA_CRYPTO_GENERATOR_INIT or
 *                                psa_crypto_generator_init().
 * \param key                     Slot containing the secret key to use.
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
psa_status_t psa_key_derivation(psa_crypto_generator_t *generator,
                                psa_key_slot_t key,
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
 * \param[in,out] generator       The generator object to set up. It must
 *                                have been initialized to all-bits-zero,
 *                                a logical zero (`{0}`),
 *                                \c PSA_CRYPTO_GENERATOR_INIT or
 *                                psa_crypto_generator_init().
 * \param private_key             Slot containing the private key to use.
 * \param[in] peer_key            Public key of the peer. It must be
 *                                in the same format that psa_import_key()
 *                                accepts. The standard formats for public
 *                                keys are documented in the documentation
 *                                of psa_export_public_key().
 * \param peer_key_length         Size of \p peer_key in bytes.
 * \param alg                     The key agreement algorithm to compute
 *                                (\c PSA_ALG_XXX value such that
 *                                #PSA_ALG_IS_KEY_AGREEMENT(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_EMPTY_SLOT
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
                               psa_key_slot_t private_key,
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
 * \param key               Slot where the key will be stored. This must be a
 *                          valid slot for a key of the chosen type. It must
 *                          be unoccupied.
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
psa_status_t psa_generate_key(psa_key_slot_t key,
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
