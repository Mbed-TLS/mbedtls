/**
 * \file psa/crypto.h
 * \brief Platform Security Architecture cryptography module
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

/**
 * \brief Function return status.
 *
 * Zero indicates success, anything else indicates an error.
 */
typedef enum {
    /** The action was completed successfully. */
    PSA_SUCCESS = 0,
    /** The requested operation or a parameter is not supported
     * by this implementation.
     *
     * Implementations should return this error code when an enumeration
     * parameter such as a key type, algorithm, etc. is not recognized.
     * If a combination of parameters is recognized and identified as
     * not valid, return #PSA_ERROR_INVALID_ARGUMENT instead. */
    PSA_ERROR_NOT_SUPPORTED,
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
    PSA_ERROR_NOT_PERMITTED,
    /** An output buffer is too small.
     *
     * Applications can call the `PSA_xxx_SIZE` macro listed in the function
     * description to determine a sufficient buffer size.
     *
     * Implementations should preferably return this error code only
     * in cases when performing the operation with a larger output
     * buffer would succeed. However implementations may return this
     * error if a function has invalid or unsupported parameters in addition
     * to the parameters that determine the necessary output buffer size. */
    PSA_ERROR_BUFFER_TOO_SMALL,
    /** A slot is occupied, but must be empty to carry out the
     * requested action.
     *
     * If the slot number is invalid (i.e. the requested action could
     * not be performed even after erasing the slot's content),
     * implementations shall return #PSA_ERROR_INVALID_ARGUMENT instead. */
    PSA_ERROR_OCCUPIED_SLOT,
    /** A slot is empty, but must be occupied to carry out the
     * requested action.
     *
     * If the slot number is invalid (i.e. the requested action could
     * not be performed even after creating appropriate content in the slot),
     * implementations shall return #PSA_ERROR_INVALID_ARGUMENT instead. */
    PSA_ERROR_EMPTY_SLOT,
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
    PSA_ERROR_BAD_STATE,
    /** The parameters passed to the function are invalid.
     *
     * Implementations may return this error any time a parameter or
     * combination of parameters are recognized as invalid.
     *
     * Implementations shall not return this error code to indicate
     * that a key slot is occupied when it needs to be free or vice versa,
     * but shall return #PSA_ERROR_OCCUPIED_SLOT or #PSA_ERROR_EMPTY_SLOT
     * as applicable. */
    PSA_ERROR_INVALID_ARGUMENT,
    /** There is not enough runtime memory.
     *
     * If the action is carried out across multiple security realms, this
     * error can refer to available memory in any of the security realms. */
    PSA_ERROR_INSUFFICIENT_MEMORY,
    /** There is not enough persistent storage.
     *
     * Functions that modify the key storage return this error code if
     * there is insufficient storage space on the host media. In addition,
     * many functions that do not otherwise access storage may return this
     * error code if the implementation requires a mandatory log entry for
     * the requested action and the log storage space is full. */
    PSA_ERROR_INSUFFICIENT_STORAGE,
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
    PSA_ERROR_COMMUNICATION_FAILURE,
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
    PSA_ERROR_STORAGE_FAILURE,
    /** A hardware failure was detected.
     *
     * A hardware failure may be transient or permanent depending on the
     * cause. */
    PSA_ERROR_HARDWARE_FAILURE,
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
    PSA_ERROR_TAMPERING_DETECTED,
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
    PSA_ERROR_INSUFFICIENT_ENTROPY,
    /** The signature, MAC or hash is incorrect.
     *
     * Verification functions return this error if the verification
     * calculations completed successfully, and the value to be verified
     * was determined to be incorrect.
     *
     * If the value to verify has an invalid size, implementations may return
     * either #PSA_ERROR_INVALID_ARGUMENT or #PSA_ERROR_INVALID_SIGNATURE. */
    PSA_ERROR_INVALID_SIGNATURE,
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
    PSA_ERROR_INVALID_PADDING,
    /** An error occurred that does not correspond to any defined
     * failure cause.
     *
     * Implementations may use this error code if none of the other standard
     * error codes are applicable. */
    PSA_ERROR_UNKNOWN_ERROR,
} psa_status_t;

/**
 * \brief Library initialization.
 *
 * Applications must call this function before calling any other
 * function in this module.
 *
 * Applications may call this function more than once. Once a call
 * succeeds, subsequent calls are guaranteed to succeed.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 * \retval PSA_ERROR_INSUFFICIENT_ENTROPY
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

#define PSA_KEY_TYPE_CATEGORY_MASK              ((psa_key_type_t)0x7e000000)
#define PSA_KEY_TYPE_RAW_DATA                   ((psa_key_type_t)0x02000000)
#define PSA_KEY_TYPE_CATEGORY_SYMMETRIC         ((psa_key_type_t)0x04000000)
#define PSA_KEY_TYPE_CATEGORY_ASYMMETRIC        ((psa_key_type_t)0x06000000)
#define PSA_KEY_TYPE_PAIR_FLAG                  ((psa_key_type_t)0x01000000)

#define PSA_KEY_TYPE_HMAC                       ((psa_key_type_t)0x02000001)
#define PSA_KEY_TYPE_AES                        ((psa_key_type_t)0x04000001)
#define PSA_KEY_TYPE_DES                        ((psa_key_type_t)0x04000002)
#define PSA_KEY_TYPE_CAMELLIA                   ((psa_key_type_t)0x04000003)
#define PSA_KEY_TYPE_ARC4                       ((psa_key_type_t)0x04000004)

/** RSA public key. */
#define PSA_KEY_TYPE_RSA_PUBLIC_KEY             ((psa_key_type_t)0x06010000)
/** RSA key pair (private and public key). */
#define PSA_KEY_TYPE_RSA_KEYPAIR                ((psa_key_type_t)0x07010000)
/** DSA public key. */
#define PSA_KEY_TYPE_DSA_PUBLIC_KEY             ((psa_key_type_t)0x06020000)
/** DSA key pair (private and public key). */
#define PSA_KEY_TYPE_DSA_KEYPAIR                ((psa_key_type_t)0x07020000)
#define PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE        ((psa_key_type_t)0x06030000)
#define PSA_KEY_TYPE_ECC_KEYPAIR_BASE           ((psa_key_type_t)0x07030000)
#define PSA_KEY_TYPE_ECC_CURVE_MASK             ((psa_key_type_t)0x0000ffff)
#define PSA_KEY_TYPE_ECC_KEYPAIR(curve)         \
    (PSA_KEY_TYPE_ECC_KEYPAIR_BASE | (curve))
#define PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve)              \
    (PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE | (curve))

/** Whether a key type is vendor-defined. */
#define PSA_KEY_TYPE_IS_VENDOR_DEFINED(type) \
    (((type) & PSA_KEY_TYPE_VENDOR_FLAG) != 0)
#define PSA_KEY_TYPE_IS_RAW_BYTES(type)                                 \
    (((type) & PSA_KEY_TYPE_CATEGORY_MASK) == PSA_KEY_TYPE_RAW_DATA ||  \
     ((type) & PSA_KEY_TYPE_CATEGORY_MASK) == PSA_KEY_TYPE_CATEGORY_SYMMETRIC)

/** Whether a key type is asymmetric: either a key pair or a public key. */
#define PSA_KEY_TYPE_IS_ASYMMETRIC(type)                                \
    (((type) & PSA_KEY_TYPE_CATEGORY_MASK) == PSA_KEY_TYPE_CATEGORY_ASYMMETRIC)
/** Whether a key type is the public part of a key pair. */
#define PSA_KEY_TYPE_IS_PUBLIC_KEY(type)                                \
    (((type) & (PSA_KEY_TYPE_CATEGORY_MASK | PSA_KEY_TYPE_PAIR_FLAG) == \
      PSA_KEY_TYPE_CATEGORY_ASYMMETRIC))
/** Whether a key type is a key pair containing a private part and a public
 * part. */
#define PSA_KEY_TYPE_IS_KEYPAIR(type)                                   \
    (((type) & (PSA_KEY_TYPE_CATEGORY_MASK | PSA_KEY_TYPE_PAIR_FLAG)) == \
     (PSA_KEY_TYPE_CATEGORY_ASYMMETRIC | PSA_KEY_TYPE_PAIR_FLAG))
/** Whether a key type is an RSA key pair or public key. */
/** The key pair type corresponding to a public key type. */
#define PSA_KEY_TYPE_KEYPAIR_OF_PUBLIC_KEY(type)        \
    ((type) | PSA_KEY_TYPE_PAIR_FLAG)
/** The public key type corresponding to a key pair type. */
#define PSA_KEY_TYPE_PUBLIC_KEY_OF_KEYPAIR(type)        \
    ((type) & ~PSA_KEY_TYPE_PAIR_FLAG)
#define PSA_KEY_TYPE_IS_RSA(type)                                       \
    (PSA_KEY_TYPE_PUBLIC_KEY_OF_KEYPAIR(type) == PSA_KEY_TYPE_RSA_PUBLIC_KEY)
/** Whether a key type is an elliptic curve key pair or public key. */
#define PSA_KEY_TYPE_IS_ECC(type)                                       \
    ((PSA_KEY_TYPE_PUBLIC_KEY_OF_KEYPAIR(type) &                        \
      ~PSA_KEY_TYPE_ECC_CURVE_MASK) == PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE)

/** The block size of a block cipher.
 *
 * \param type  A cipher key type (value of type #psa_key_type_t).
 *
 * \return      The block size for a block cipher, or 1 for a stream cipher.
 *              The return value is undefined if \c type does not identify
 *              a cipher algorithm.
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

#define PSA_ALG_IS_VENDOR_DEFINED(alg)                                  \
    (((alg) & PSA_ALG_VENDOR_FLAG) != 0)
/** Whether the specified algorithm is a hash algorithm.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \c alg is a hash algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \c alg is not a valid
 *         algorithm identifier.
 */
#define PSA_ALG_IS_HASH(alg)                                            \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_HASH)
#define PSA_ALG_IS_MAC(alg)                                             \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_MAC)
#define PSA_ALG_IS_CIPHER(alg)                                          \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_CIPHER)
#define PSA_ALG_IS_AEAD(alg)                                            \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_AEAD)
#define PSA_ALG_IS_SIGN(alg)                                            \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_SIGN)
#define PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(alg)                           \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION)
#define PSA_ALG_IS_KEY_AGREEMENT(alg)                                   \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_KEY_AGREEMENT)
#define PSA_ALG_IS_KEY_DERIVATION(alg)                                  \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_KEY_DERIVATION)

#define PSA_ALG_HASH_MASK                       ((psa_algorithm_t)0x000000ff)
#define PSA_ALG_MD2                             ((psa_algorithm_t)0x01000001)
#define PSA_ALG_MD4                             ((psa_algorithm_t)0x01000002)
#define PSA_ALG_MD5                             ((psa_algorithm_t)0x01000003)
#define PSA_ALG_RIPEMD160                       ((psa_algorithm_t)0x01000004)
#define PSA_ALG_SHA_1                           ((psa_algorithm_t)0x01000005)
#define PSA_ALG_SHA_224                         ((psa_algorithm_t)0x01000008)
#define PSA_ALG_SHA_256                         ((psa_algorithm_t)0x01000009)
#define PSA_ALG_SHA_384                         ((psa_algorithm_t)0x0100000a)
#define PSA_ALG_SHA_512                         ((psa_algorithm_t)0x0100000b)
#define PSA_ALG_SHA_512_224                     ((psa_algorithm_t)0x0100000c)
#define PSA_ALG_SHA_512_256                     ((psa_algorithm_t)0x0100000d)
#define PSA_ALG_SHA3_224                        ((psa_algorithm_t)0x01000010)
#define PSA_ALG_SHA3_256                        ((psa_algorithm_t)0x01000011)
#define PSA_ALG_SHA3_384                        ((psa_algorithm_t)0x01000012)
#define PSA_ALG_SHA3_512                        ((psa_algorithm_t)0x01000013)

#define PSA_ALG_MAC_SUBCATEGORY_MASK            ((psa_algorithm_t)0x00c00000)
#define PSA_ALG_HMAC_BASE                       ((psa_algorithm_t)0x02800000)
#define PSA_ALG_HMAC(hash_alg)                  \
    (PSA_ALG_HMAC_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))
#define PSA_ALG_HMAC_HASH(hmac_alg)                             \
    (PSA_ALG_CATEGORY_HASH | ((hmac_alg) & PSA_ALG_HASH_MASK))
#define PSA_ALG_IS_HMAC(alg)                                            \
    (((alg) & (PSA_ALG_CATEGORY_MASK | PSA_ALG_MAC_SUBCATEGORY_MASK)) == \
     PSA_ALG_HMAC_BASE)
#define PSA_ALG_CIPHER_MAC_BASE                 ((psa_algorithm_t)0x02c00000)
#define PSA_ALG_CBC_MAC                         ((psa_algorithm_t)0x02c00001)
#define PSA_ALG_CMAC                            ((psa_algorithm_t)0x02c00002)
#define PSA_ALG_GMAC                            ((psa_algorithm_t)0x02c00003)
#define PSA_ALG_IS_CIPHER_MAC(alg)                                      \
    (((alg) & (PSA_ALG_CATEGORY_MASK | PSA_ALG_MAC_SUBCATEGORY_MASK)) == \
     PSA_ALG_CIPHER_MAC_BASE)

#define PSA_ALG_CIPHER_SUBCATEGORY_MASK         ((psa_algorithm_t)0x00c00000)
#define PSA_ALG_BLOCK_CIPHER_BASE               ((psa_algorithm_t)0x04000000)
#define PSA_ALG_BLOCK_CIPHER_MODE_MASK          ((psa_algorithm_t)0x000000ff)
#define PSA_ALG_BLOCK_CIPHER_PADDING_MASK       ((psa_algorithm_t)0x003f0000)
#define PSA_ALG_BLOCK_CIPHER_PAD_NONE           ((psa_algorithm_t)0x00000000)
#define PSA_ALG_BLOCK_CIPHER_PAD_PKCS7          ((psa_algorithm_t)0x00010000)
#define PSA_ALG_IS_BLOCK_CIPHER(alg)            \
    (((alg) & (PSA_ALG_CATEGORY_MASK | PSA_ALG_CIPHER_SUBCATEGORY_MASK)) == \
        PSA_ALG_BLOCK_CIPHER_BASE)

#define PSA_ALG_CBC_BASE                        ((psa_algorithm_t)0x04000001)
#define PSA_ALG_CFB_BASE                        ((psa_algorithm_t)0x04000002)
#define PSA_ALG_OFB_BASE                        ((psa_algorithm_t)0x04000003)
#define PSA_ALG_XTS_BASE                        ((psa_algorithm_t)0x04000004)
#define PSA_ALG_STREAM_CIPHER                   ((psa_algorithm_t)0x04800000)
#define PSA_ALG_CTR                             ((psa_algorithm_t)0x04800001)
#define PSA_ALG_ARC4                            ((psa_algorithm_t)0x04800002)

#define PSA_ALG_CCM                             ((psa_algorithm_t)0x06000001)
#define PSA_ALG_GCM                             ((psa_algorithm_t)0x06000002)

#define PSA_ALG_RSA_PKCS1V15_SIGN_RAW           ((psa_algorithm_t)0x10010000)
#define PSA_ALG_RSA_PSS_MGF1                    ((psa_algorithm_t)0x10020000)
#define PSA_ALG_RSA_PKCS1V15_CRYPT              ((psa_algorithm_t)0x12010000)
#define PSA_ALG_RSA_OAEP_MGF1_BASE              ((psa_algorithm_t)0x12020000)
#define PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg)                             \
    (PSA_ALG_RSA_PKCS1V15_SIGN_RAW | ((hash_alg) & PSA_ALG_HASH_MASK))
#define PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)                               \
    (((alg) & 0x7fffff00) == PSA_ALG_RSA_PKCS1V15_SIGN_RAW)
#define PSA_ALG_RSA_GET_HASH(alg)                                       \
    (((alg) & PSA_ALG_HASH_MASK) | PSA_ALG_CATEGORY_HASH)

/**@}*/

/** \defgroup key_management Key management
 * @{
 */

/**
 * \brief Import a key in binary format.
 *
 * This function supports any output from psa_export_key(). Refer to the
 * documentation of psa_export_key() for the format for each key type.
 *
 * \param key         Slot where the key will be stored. This must be a
 *                    valid slot for a key of the chosen type. It must
 *                    be unoccupied.
 * \param type        Key type (a \c PSA_KEY_TYPE_XXX value).
 * \param data        Buffer containing the key data.
 * \param data_length Size of the \c data buffer in bytes.
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_ERROR_NOT_SUPPORTED
 *         The key type or key size is not supported, either by the
 *         implementation in general or in this particular slot.
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         The key slot is invalid,
 *         or the key data is not correctly formatted.
 * \retval PSA_ERROR_OCCUPIED_SLOT
 *         There is already a key in the specified slot.
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_INSUFFICIENT_STORAGE
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_import_key(psa_key_slot_t key,
                            psa_key_type_t type,
                            const uint8_t *data,
                            size_t data_length);

/**
 * \brief Destroy a key.
 *
 * \retval PSA_SUCCESS
 *         The slot's content, if any, has been erased.
 * \retval PSA_ERROR_NOT_PERMITTED
 *         The slot holds content and cannot be erased because it is
 *         read-only, either due to a policy or due to physical restrictions.
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         The specified slot number does not designate a valid slot.
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 *         There was an failure in communication with the cryptoprocessor.
 *         The key material may still be present in the cryptoprocessor.
 * \retval PSA_ERROR_STORAGE_FAILURE
 *         The storage is corrupted. Implementations shall make a best effort
 *         to erase key material even in this stage, however applications
 *         should be aware that it may be impossible to guarantee that the
 *         key material is not recoverable in such cases.
 * \retval PSA_ERROR_TAMPERING_DETECTED
 *         An unexpected condition which is not a storage corruption or
 *         a communication failure occurred. The cryptoprocessor may have
 *         been compromised.
 */
psa_status_t psa_destroy_key(psa_key_slot_t key);

/**
 * \brief Get basic metadata about a key.
 *
 * \param key           Slot whose content is queried. This must
 *                      be an occupied key slot.
 * \param type          On success, the key type (a \c PSA_KEY_TYPE_XXX value).
 *                      This may be a null pointer, in which case the key type
 *                      is not written.
 * \param bits          On success, the key size in bits.
 *                      This may be a null pointer, in which case the key size
 *                      is not written.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_EMPTY_SLOT
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
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
 * If a key is created with psa_import_key() and then exported with
 * this function, it is not guaranteed that the resulting data is
 * identical: the implementation may choose a different representation
 * of the same key if the format permits it.
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
 *   is the non-encrypted DER representation defined by PKCS\#8 (RFC 5208)
 *   as PrivateKeyInfo.
 * - For RSA public keys (#PSA_KEY_TYPE_RSA_PUBLIC_KEY), the format
 *   is the DER representation defined by RFC 5280 as SubjectPublicKeyInfo.
 *
 * \param key           Slot whose content is to be exported. This must
 *                      be an occupied key slot.
 * \param data          Buffer where the key data is to be written.
 * \param data_size     Size of the \c data buffer in bytes.
 * \param data_length   On success, the number of bytes
 *                      that make up the key data.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_EMPTY_SLOT
 * \retval PSA_ERROR_NOT_PERMITTED
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
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
 * For standard key types, the output format is as follows:
 *
 * - For RSA keys (#PSA_KEY_TYPE_RSA_KEYPAIR or #PSA_KEY_TYPE_RSA_PUBLIC_KEY),
 *   is the DER representation of the public key defined by RFC 5280
 *   as SubjectPublicKeyInfo.
 *
 * \param key           Slot whose content is to be exported. This must
 *                      be an occupied key slot.
 * \param data          Buffer where the key data is to be written.
 * \param data_size     Size of the \c data buffer in bytes.
 * \param data_length   On success, the number of bytes
 *                      that make up the key data.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_EMPTY_SLOT
 * \retval PSA_ERROR_INVALID_ARGUMENT
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
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
 * For a key pair, this concerns the public key.
 */
#define PSA_KEY_USAGE_ENCRYPT                   ((psa_key_usage_t)0x00000100)

/** Whether the key may be used to decrypt a message.
 *
 * For a key pair, this concerns the private key.
 */
#define PSA_KEY_USAGE_DECRYPT                   ((psa_key_usage_t)0x00000200)

/** Whether the key may be used to sign a message.
 *
 * For a key pair, this concerns the private key.
 */
#define PSA_KEY_USAGE_SIGN                      ((psa_key_usage_t)0x00000400)

/** Whether the key may be used to verify a message signature.
 *
 * For a key pair, this concerns the public key.
 */
#define PSA_KEY_USAGE_VERIFY                    ((psa_key_usage_t)0x00000800)

/** The type of the key policy data structure.
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_key_policy_s psa_key_policy_t;

/** \brief Initialize a key policy structure to a default that forbids all
 * usage of the key. */
void psa_key_policy_init(psa_key_policy_t *policy);

/** \brief Set the standard fields of a policy structure.
 *
 * Note that this function does not make any consistency check of the
 * parameters. The values are only checked when applying the policy to
 * a key slot with psa_set_key_policy().
 */
void psa_key_policy_set_usage(psa_key_policy_t *policy,
                              psa_key_usage_t usage,
                              psa_algorithm_t alg);

psa_key_usage_t psa_key_policy_get_usage(psa_key_policy_t *policy);

psa_algorithm_t psa_key_policy_get_algorithm(psa_key_policy_t *policy);

/** \brief Set the usage policy on a key slot.
 *
 * This function must be called on an empty key slot, before importing,
 * generating or creating a key in the slot. Changing the policy of an
 * existing key is not permitted.
 *
 * Implementations may set restrictions on supported key policies
 * depending on the key type and the key slot.
 */
psa_status_t psa_set_key_policy(psa_key_slot_t key,
                                const psa_key_policy_t *policy);

/** \brief Get the usage policy for a key slot.
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
 */
psa_status_t psa_get_key_lifetime(psa_key_slot_t key,
                                  psa_key_lifetime_t *lifetime);

/** \brief Change the lifetime of a key slot.
 *
 * Whether the lifetime of a key slot can be changed at all, and if so
 * whether the lifetime of an occupied key slot can be changed, is
 * implementation-dependent.
 */
psa_status_t psa_set_key_lifetime(psa_key_slot_t key,
                                  const psa_key_lifetime_t *lifetime);

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
 *              #PSA_ALG_IS_HASH(alg) is true).
 *
 * \return The hash size for the specified hash algorithm.
 *         If the hash algorithm is not recognized, return 0.
 *         An implementation may return either 0 or the correct size
 *         for a hash algorithm that it recognizes, but does not support.
 */
#define PSA_HASH_SIZE(alg)                                            \
    (                                                                 \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_MD2 ? 16 :               \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_MD4 ? 16 :               \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_MD5 ? 16 :               \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_RIPEMD160 ? 20 :         \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_SHA_1 ? 20 :             \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_SHA_224 ? 28 :           \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_SHA_256 ? 32 :           \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_SHA_384 ? 48 :           \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_SHA_512 ? 64 :           \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_SHA_512_224 ? 28 :       \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_SHA_512_256 ? 32 :       \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_SHA3_224 ? 28 :          \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_SHA3_256 ? 32 :          \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_SHA3_384 ? 48 :          \
        PSA_ALG_RSA_GET_HASH(alg) == PSA_ALG_SHA3_512 ? 64 :          \
        0)

/** Start a multipart hash operation.
 *
 * The sequence of operations to calculate a hash (message digest)
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Call psa_hash_start() to specify the algorithm.
 * -# Call psa_hash_update() zero, one or more times, passing a fragment
 *    of the message each time. The hash that is calculated is the hash
 *    of the concatenation of these messages in order.
 * -# To calculate the hash, call psa_hash_finish().
 *    To compare the hash with an expected value, call psa_hash_verify().
 *
 * The application may call psa_hash_abort() at any time after the operation
 * has been initialized with psa_hash_start().
 *
 * After a successful call to psa_hash_start(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_hash_update().
 * - A call to psa_hash_finish(), psa_hash_verify() or psa_hash_abort().
 *
 * \param operation
 * \param alg       The hash algorithm to compute (\c PSA_ALG_XXX value
 *                  such that #PSA_ALG_IS_HASH(alg) is true).
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not a hash algorithm.
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_hash_start(psa_hash_operation_t *operation,
                            psa_algorithm_t alg);

/** Add a message fragment to a multipart hash operation.
 *
 * The application must call psa_hash_start() before calling this function.
 *
 * If this function returns an error status, the operation becomes inactive.
 *
 * \param operation     Active hash operation.
 * \param input         Buffer containing the message fragment to hash.
 * \param input_length  Size of the \c input buffer in bytes.
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_ERROR_BAD_STATE
 *         The operation state is not valid (not started, or already completed).
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_hash_update(psa_hash_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length);

/** Finish the calculation of the hash of a message.
 *
 * The application must call psa_hash_start() before calling this function.
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
 * \param operation     Active hash operation.
 * \param hash          Buffer where the hash is to be written.
 * \param hash_size     Size of the \c hash buffer in bytes.
 * \param hash_length   On success, the number of bytes
 *                      that make up the hash value. This is always
 *                      #PSA_HASH_SIZE(alg) where \c alg is the
 *                      hash algorithm that is calculated.
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_ERROR_BAD_STATE
 *         The operation state is not valid (not started, or already completed).
 * \retval PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \c hash buffer is too small. You can determine a
 *         sufficient buffer size by calling #PSA_HASH_SIZE(alg)
 *         where \c alg is the hash algorithm that is calculated.
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_hash_finish(psa_hash_operation_t *operation,
                             uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length);

/** Finish the calculation of the hash of a message and compare it with
 * an expected value.
 *
 * The application must call psa_hash_start() before calling this function.
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
 * \param operation     Active hash operation.
 * \param hash          Buffer containing the expected hash value.
 * \param hash_length   Size of the \c hash buffer in bytes.
 *
 * \retval PSA_SUCCESS
 *         The expected hash is identical to the actual hash of the message.
 * \retval PSA_ERROR_INVALID_SIGNATURE
 *         The hash of the message was calculated successfully, but it
 *         differs from the expected hash.
 * \retval PSA_ERROR_BAD_STATE
 *         The operation state is not valid (not started, or already completed).
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_hash_verify(psa_hash_operation_t *operation,
                             const uint8_t *hash,
                             size_t hash_length);

/** Abort a hash operation.
 *
 * This function may be called at any time after psa_hash_start().
 * Aborting an operation frees all associated resources except for the
 * \c operation structure itself.
 *
 * Implementation should strive to be robust and handle inactive hash
 * operations safely (do nothing and return #PSA_ERROR_BAD_STATE). However,
 * application writers should beware that uninitialized memory may happen
 * to be indistinguishable from an active hash operation, and the behavior
 * of psa_hash_abort() is undefined in this case.
 *
 * \param operation     Active hash operation.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_BAD_STATE
 *         \c operation is not an active hash operation.
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
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

/** The size of the output of psa_mac_finish(), in bytes.
 *
 * This is also the MAC size that psa_mac_verify() expects.
 *
 * \param alg   A MAC algorithm (\c PSA_ALG_XXX value such that
 *              #PSA_ALG_IS_MAC(alg) is true).
 *
 * \return The MAC size for the specified algorithm.
 *         If the MAC algorithm is not recognized, return 0.
 *         An implementation may return either 0 or the correct size
 *         for a MAC algorithm that it recognizes, but does not support.
 */
#define PSA_MAC_FINAL_SIZE(key_type, key_bits, alg)                     \
    (PSA_ALG_IS_HMAC(alg) ? PSA_HASH_SIZE(PSA_ALG_HMAC_HASH(alg)) : \
     PSA_ALG_IS_BLOCK_CIPHER_MAC(alg) ? PSA_BLOCK_CIPHER_BLOCK_SIZE(key_type) : \
     0)

/** Start a multipart MAC operation.
 *
 * The sequence of operations to calculate a MAC (message authentication code)
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Call psa_mac_start() to specify the algorithm and key.
 *    The key remains associated with the operation even if the content
 *    of the key slot changes.
 * -# Call psa_mac_update() zero, one or more times, passing a fragment
 *    of the message each time. The MAC that is calculated is the MAC
 *    of the concatenation of these messages in order.
 * -# To calculate the MAC, call psa_mac_finish().
 *    To compare the MAC with an expected value, call psa_mac_verify().
 *
 * The application may call psa_mac_abort() at any time after the operation
 * has been initialized with psa_mac_start().
 *
 * After a successful call to psa_mac_start(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_mac_update().
 * - A call to psa_mac_finish(), psa_mac_verify() or psa_mac_abort().
 *
 * \param operation
 * \param alg       The MAC algorithm to compute (\c PSA_ALG_XXX value
 *                  such that #PSA_ALG_IS_MAC(alg) is true).
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_ERROR_EMPTY_SLOT
 * \retval PSA_ERROR_NOT_PERMITTED
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         \c key is not compatible with \c alg.
 * \retval PSA_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not a MAC algorithm.
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_mac_start(psa_mac_operation_t *operation,
                           psa_key_slot_t key,
                           psa_algorithm_t alg);

psa_status_t psa_mac_update(psa_mac_operation_t *operation,
                            const uint8_t *input,
                            size_t input_length);

psa_status_t psa_mac_finish(psa_mac_operation_t *operation,
                            uint8_t *mac,
                            size_t mac_size,
                            size_t *mac_length);

psa_status_t psa_mac_verify(psa_mac_operation_t *operation,
                            const uint8_t *mac,
                            size_t mac_length);

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
 * -# Call psa_encrypt_setup() to specify the algorithm and key.
 *    The key remains associated with the operation even if the content
 *    of the key slot changes.
 * -# Call either psa_encrypt_generate_iv() or psa_encrypt_set_iv() to
 *    generate or set the IV (initialization vector). You should use
 *    psa_encrypt_generate_iv() unless the protocol you are implementing
 *    requires a specific IV value.
 * -# Call psa_cipher_update() zero, one or more times, passing a fragment
 *    of the message each time.
 * -# Call psa_cipher_finish().
 *
 * The application may call psa_cipher_abort() at any time after the operation
 * has been initialized with psa_encrypt_setup().
 *
 * After a successful call to psa_encrypt_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_encrypt_generate_iv(), psa_encrypt_set_iv()
 *   or psa_cipher_update().
 * - A call to psa_cipher_finish() or psa_cipher_abort().
 *
 * \param operation
 * \param alg       The cipher algorithm to compute (\c PSA_ALG_XXX value
 *                  such that #PSA_ALG_IS_CIPHER(alg) is true).
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_ERROR_EMPTY_SLOT
 * \retval PSA_ERROR_NOT_PERMITTED
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         \c key is not compatible with \c alg.
 * \retval PSA_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not a cipher algorithm.
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_encrypt_setup(psa_cipher_operation_t *operation,
                               psa_key_slot_t key,
                               psa_algorithm_t alg);

/** Set the key for a multipart symmetric decryption operation.
 *
 * The sequence of operations to decrypt a message with a symmetric cipher
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Call psa_decrypt_setup() to specify the algorithm and key.
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
 * has been initialized with psa_encrypt_setup().
 *
 * After a successful call to psa_decrypt_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_cipher_update().
 * - A call to psa_cipher_finish() or psa_cipher_abort().
 *
 * \param operation
 * \param alg       The cipher algorithm to compute (\c PSA_ALG_XXX value
 *                  such that #PSA_ALG_IS_CIPHER(alg) is true).
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_ERROR_EMPTY_SLOT
 * \retval PSA_ERROR_NOT_PERMITTED
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         \c key is not compatible with \c alg.
 * \retval PSA_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not a cipher algorithm.
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_decrypt_setup(psa_cipher_operation_t *operation,
                               psa_key_slot_t key,
                               psa_algorithm_t alg);

psa_status_t psa_encrypt_generate_iv(psa_cipher_operation_t *operation,
                                     unsigned char *iv,
                                     size_t iv_size,
                                     size_t *iv_length);

psa_status_t psa_encrypt_set_iv(psa_cipher_operation_t *operation,
                                const unsigned char *iv,
                                size_t iv_length);

psa_status_t psa_cipher_update(psa_cipher_operation_t *operation,
                               const uint8_t *input,
                               size_t input_length);

psa_status_t psa_cipher_finish(psa_cipher_operation_t *operation,
                               uint8_t *mac,
                               size_t mac_size,
                               size_t *mac_length);

psa_status_t psa_cipher_abort(psa_cipher_operation_t *operation);

/**@}*/

/** \defgroup aead Authenticated encryption with associated data (AEAD)
 * @{
 */

/** The type of the state data structure for multipart AEAD operations.
 *
 * This is an implementation-defined \c struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_aead_operation_s psa_aead_operation_t;

/** Set the key for a multipart authenticated encryption operation.
 *
 * The sequence of operations to authenticate-and-encrypt a message
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Call psa_aead_encrypt_setup() to specify the algorithm and key.
 *    The key remains associated with the operation even if the content
 *    of the key slot changes.
 * -# Call either psa_aead_generate_iv() or psa_aead_set_iv() to
 *    generate or set the IV (initialization vector). You should use
 *    psa_encrypt_generate_iv() unless the protocol you are implementing
 *    requires a specific IV value.
 * -# Call psa_aead_update_ad() to pass the associated data that is
 *    to be authenticated but not encrypted. You may omit this step if
 *    there is no associated data.
 * -# Call psa_aead_update() zero, one or more times, passing a fragment
 *    of the data to encrypt each time.
 * -# Call psa_aead_finish().
 *
 * The application may call psa_aead_abort() at any time after the operation
 * has been initialized with psa_aead_encrypt_setup().
 *
 * After a successful call to psa_aead_encrypt_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_aead_generate_iv(), psa_aead_set_iv(),
 *   psa_aead_update_ad() or psa_aead_update().
 * - A call to psa_aead_finish() or psa_aead_abort().
 *
 * \param operation
 * \param alg       The AEAD algorithm to compute (\c PSA_ALG_XXX value
 *                  such that #PSA_ALG_IS_AEAD(alg) is true).
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_ERROR_EMPTY_SLOT
 * \retval PSA_ERROR_NOT_PERMITTED
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         \c key is not compatible with \c alg.
 * \retval PSA_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not an AEAD algorithm.
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t *operation,
                                    psa_key_slot_t key,
                                    psa_algorithm_t alg);

/** Set the key for a multipart authenticated decryption operation.
 *
 * The sequence of operations to authenticated and decrypt a message
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Call psa_aead_decrypt_setup() to specify the algorithm and key.
 *    The key remains associated with the operation even if the content
 *    of the key slot changes.
 * -# Call psa_aead_set_iv() to pass the initialization vector (IV)
 *    for the authenticated decryption.
 * -# Call psa_aead_update_ad() to pass the associated data that is
 *    to be authenticated but not encrypted. You may omit this step if
 *    there is no associated data.
 * -# Call psa_aead_update() zero, one or more times, passing a fragment
 *    of the data to decrypt each time.
 * -# Call psa_aead_finish().
 *
 * The application may call psa_aead_abort() at any time after the operation
 * has been initialized with psa_aead_decrypt_setup().
 *
 * After a successful call to psa_aead_decrypt_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A failed call to psa_aead_update().
 * - A call to psa_aead_finish() or psa_aead_abort().
 *
 * \param operation
 * \param alg       The AEAD algorithm to compute (\c PSA_ALG_XXX value
 *                  such that #PSA_ALG_IS_AEAD(alg) is true).
 *
 * \retval PSA_SUCCESS
 *         Success.
 * \retval PSA_ERROR_EMPTY_SLOT
 * \retval PSA_ERROR_NOT_PERMITTED
 * \retval PSA_ERROR_INVALID_ARGUMENT
 *         \c key is not compatible with \c alg.
 * \retval PSA_ERROR_NOT_SUPPORTED
 *         \c alg is not supported or is not an AEAD algorithm.
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t *operation,
                                    psa_key_slot_t key,
                                    psa_algorithm_t alg);

psa_status_t psa_aead_generate_iv(psa_aead_operation_t *operation,
                                  unsigned char *iv,
                                  size_t iv_size,
                                  size_t *iv_length);

psa_status_t psa_aead_set_iv(psa_aead_operation_t *operation,
                             const unsigned char *iv,
                             size_t iv_length);

psa_status_t psa_aead_update_ad(psa_aead_operation_t *operation,
                                const uint8_t *input,
                                size_t input_length);

psa_status_t psa_aead_update(psa_aead_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length);

psa_status_t psa_aead_finish(psa_aead_operation_t *operation,
                             uint8_t *tag,
                             size_t tag_size,
                             size_t *tag_length);

psa_status_t psa_aead_verify(psa_aead_operation_t *operation,
                             uint8_t *tag,
                             size_t tag_length);

psa_status_t psa_aead_abort(psa_aead_operation_t *operation);

/**@}*/

/** \defgroup asymmetric Asymmetric cryptography
 * @{
 */

/**
 * \brief Maximum ECDSA signature size for a given curve bit size
 *
 * \param curve_bits    Curve size in bits
 * \return              Maximum signature size in bytes
 *
 * \note This macro returns a compile-time constant if its argument is one.
 *
 * \warning This macro may evaluate its argument multiple times.
 */
/*
 * RFC 4492 page 20:
 *
 *     Ecdsa-Sig-Value ::= SEQUENCE {
 *         r       INTEGER,
 *         s       INTEGER
 *     }
 *
 * Size is at most
 *    1 (tag) + 1 (len) + 1 (initial 0) + curve_bytes for each of r and s,
 *    twice that + 1 (tag) + 2 (len) for the sequence
 * (assuming curve_bytes is less than 126 for r and s,
 * and less than 124 (total len <= 255) for the sequence)
 */
#define PSA_ECDSA_SIGNATURE_SIZE(curve_bits)                          \
    ( /*T,L of SEQUENCE*/ ((curve_bits) >= 61 * 8 ? 3 : 2) +          \
      /*T,L of r,s*/       2 * (((curve_bits) >= 127 * 8 ? 3 : 2) +   \
      /*V of r,s*/               ((curve_bits) + 8) / 8))


/** Safe signature buffer size for psa_asymmetric_sign().
 *
 * This macro returns a safe buffer size for a signature using a key
 * of the specified type and size, with the specified algorithm.
 * Note that the actual size of the signature may be smaller
 * (some algorithms produce a variable-size signature).
 *
 * \warning This function may call its arguments multiple times or
 *          zero times, so you should not pass arguments that contain
 *          side effects.
 *
 * \param key_type  An asymmetric key type (this may indifferently be a
 *                  key pair type or a public key type).
 * \param key_bits  The size of the key in bits.
 * \param alg       The signature algorithm.
 *
 * \return If the parameters are valid and supported, return
 *         a buffer size in bytes that guarantees that
 *         psa_asymmetric_sign() will not fail with
 *         #PSA_ERROR_BUFFER_TOO_SMALL.
 *         If the parameters are a valid combination that is not supported
 *         by the implementation, this macro either shall return either a
 *         sensible size or 0.
 *         If the parameters are not valid, the
 *         return value is unspecified.
 *
 */
#define PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE(key_type, key_bits, alg)        \
    (PSA_KEY_TYPE_IS_RSA(key_type) ? ((void)alg, PSA_BITS_TO_BYTES(key_bits)) : \
     PSA_KEY_TYPE_IS_ECC(key_type) ? PSA_ECDSA_SIGNATURE_SIZE(key_bits) : \
     ((void)alg, 0))

/**
 * \brief Sign a hash or short message with a private key.
 *
 * \param key               Key slot containing an asymmetric key pair.
 * \param alg               A signature algorithm that is compatible with
 *                          the type of \c key.
 * \param hash              The message to sign.
 * \param hash_length       Size of the \c hash buffer in bytes.
 * \param salt              A salt or label, if supported by the signature
 *                          algorithm.
 *                          If the signature algorithm does not support a
 *                          salt, pass \c NULL.
 *                          If the signature algorithm supports an optional
 *                          salt and you do not want to pass a salt,
 *                          pass \c NULL.
 * \param salt_length       Size of the \c salt buffer in bytes.
 *                          If \c salt is \c NULL, pass 0.
 * \param signature         Buffer where the signature is to be written.
 * \param signature_size    Size of the \c signature buffer in bytes.
 * \param signature_length  On success, the number of bytes
 *                          that make up the returned signature value.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \c signature buffer is too small. You can
 *         determine a sufficient buffer size by calling
 *         #PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE(key_type, key_bits, alg)
 *         where \c key_type and \c key_bits are the type and bit-size
 *         respectively of \c key.
 * \retval PSA_ERROR_NOT_SUPPORTED
 * \retval PSA_ERROR_INVALID_ARGUMENT
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 * \retval PSA_ERROR_INSUFFICIENT_ENTROPY
 */
psa_status_t psa_asymmetric_sign(psa_key_slot_t key,
                                 psa_algorithm_t alg,
                                 const uint8_t *hash,
                                 size_t hash_length,
                                 const uint8_t *salt,
                                 size_t salt_length,
                                 uint8_t *signature,
                                 size_t signature_size,
                                 size_t *signature_length);

/**
 * \brief Verify the signature a hash or short message using a public key.
 *
 * \param key               Key slot containing a public key or an
 *                          asymmetric key pair.
 * \param alg               A signature algorithm that is compatible with
 *                          the type of \c key.
 * \param hash              The message whose signature is to be verified.
 * \param hash_length       Size of the \c hash buffer in bytes.
 * \param salt              A salt or label, if supported by the signature
 *                          algorithm.
 *                          If the signature algorithm does not support a
 *                          salt, pass \c NULL.
 *                          If the signature algorithm supports an optional
 *                          salt and you do not want to pass a salt,
 *                          pass \c NULL.
 * \param salt_length       Size of the \c salt buffer in bytes.
 *                          If \c salt is \c NULL, pass 0.
 * \param signature         Buffer containing the signature to verify.
 * \param signature_size    Size of the \c signature buffer in bytes.
 *
 * \retval PSA_SUCCESS
 *         The signature is valid.
 * \retval PSA_ERROR_INVALID_SIGNATURE
 *         The calculation was perfomed successfully, but the passed
 *         signature is not a valid signature.
 * \retval PSA_ERROR_NOT_SUPPORTED
 * \retval PSA_ERROR_INVALID_ARGUMENT
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_asymmetric_verify(psa_key_slot_t key,
                                   psa_algorithm_t alg,
                                   const uint8_t *hash,
                                   size_t hash_length,
                                   const uint8_t *salt,
                                   size_t salt_length,
                                   uint8_t *signature,
                                   size_t signature_size);

#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg)     \
    (PSA_KEY_TYPE_IS_RSA(key_type) ? ((void)alg, PSA_BITS_TO_BYTES(key_bits)) : \
     ((void)alg, 0))
#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg) \
    PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg)

/**
 * \brief Encrypt a short message with a public key.
 *
 * \param key               Key slot containing a public key or an asymmetric
 *                          key pair.
 * \param alg               An asymmetric encryption algorithm that is
 *                          compatible with the type of \c key.
 * \param input             The message to encrypt.
 * \param input_length      Size of the \c input buffer in bytes.
 * \param salt              A salt or label, if supported by the encryption
 *                          algorithm.
 *                          If the algorithm does not support a
 *                          salt, pass \c NULL.
 *                          If the algorithm supports an optional
 *                          salt and you do not want to pass a salt,
 *                          pass \c NULL.
 *
 *                          - For #PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is
 *                            supported.
 * \param salt_length       Size of the \c salt buffer in bytes.
 *                          If \c salt is \c NULL, pass 0.
 * \param output            Buffer where the encrypted message is to be written.
 * \param output_size       Size of the \c output buffer in bytes.
 * \param output_length     On success, the number of bytes
 *                          that make up the returned output.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \c output buffer is too small. You can
 *         determine a sufficient buffer size by calling
 *         #PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg)
 *         where \c key_type and \c key_bits are the type and bit-size
 *         respectively of \c key.
 * \retval PSA_ERROR_NOT_SUPPORTED
 * \retval PSA_ERROR_INVALID_ARGUMENT
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 * \retval PSA_ERROR_INSUFFICIENT_ENTROPY
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
 * \param key               Key slot containing an asymmetric key pair.
 * \param alg               An asymmetric encryption algorithm that is
 *                          compatible with the type of \c key.
 * \param input             The message to decrypt.
 * \param input_length      Size of the \c input buffer in bytes.
 * \param salt              A salt or label, if supported by the encryption
 *                          algorithm.
 *                          If the algorithm does not support a
 *                          salt, pass \c NULL.
 *                          If the algorithm supports an optional
 *                          salt and you do not want to pass a salt,
 *                          pass \c NULL.
 *
 *                          - For #PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is
 *                            supported.
 * \param salt_length       Size of the \c salt buffer in bytes.
 *                          If \c salt is \c NULL, pass 0.
 * \param output            Buffer where the decrypted message is to be written.
 * \param output_size       Size of the \c output buffer in bytes.
 * \param output_length     On success, the number of bytes
 *                          that make up the returned output.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \c output buffer is too small. You can
 *         determine a sufficient buffer size by calling
 *         #PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg)
 *         where \c key_type and \c key_bits are the type and bit-size
 *         respectively of \c key.
 * \retval PSA_ERROR_NOT_SUPPORTED
 * \retval PSA_ERROR_INVALID_ARGUMENT
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 * \retval PSA_ERROR_INSUFFICIENT_ENTROPY
 * \retval PSA_ERROR_INVALID_PADDING
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

/** \defgroup generation Key generation
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
 * \param output            Output buffer for the generated data.
 * \param output_size       Number of bytes to generate and output.
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_NOT_SUPPORTED
 * \retval PSA_ERROR_INSUFFICIENT_ENTROPY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_generate_random(uint8_t *output,
                                 size_t output_size);

/**
 * \brief Generate a key or key pair.
 *
 * \param key         Slot where the key will be stored. This must be a
 *                    valid slot for a key of the chosen type. It must
 *                    be unoccupied.
 * \param type        Key type (a \c PSA_KEY_TYPE_XXX value).
 * \param bits        Key size in bits.
 * \param parameters  Extra parameters for key generation. The interpretation
 *                    of this parameter depends on \c type. All types support
 *                    \c NULL to use default parameters specified below.
 *
 * For any symmetric key type (type such that
 * `PSA_KEY_TYPE_IS_ASYMMETRIC(type)` is false), \c parameters must be
 * \c NULL. For asymmetric key types defined by this specification,
 * the parameter type and the default parameters are defined by the
 * table below. For vendor-defined key types, the vendor documentation
 * shall define the parameter type and the default parameters.
 *
 * Type | Parameter type | Meaning | Parameters used if `parameters == NULL`
 * ---- | -------------- | ------- | ---------------------------------------
 * `PSA_KEY_TYPE_RSA_KEYPAIR` | `unsigned int` | Public exponent | 65537
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_NOT_SUPPORTED
 * \retval PSA_ERROR_INVALID_ARGUMENT
 * \retval PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval PSA_ERROR_INSUFFICIENT_ENTROPY
 * \retval PSA_ERROR_COMMUNICATION_FAILURE
 * \retval PSA_ERROR_HARDWARE_FAILURE
 * \retval PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_generate_key(psa_key_slot_t key,
                              psa_key_type_t type,
                              size_t bits,
                              const void *parameters);

/**@}*/

#ifdef __cplusplus
}
#endif

/* The file "crypto_struct.h" contains definitions for
 * implementation-specific structs that are declared above. */
#include "crypto_struct.h"

/* The file "crypto_extra.h" contains vendor-specific definitions. This
 * can include vendor-defined algorithms, extra functions, etc. */
#include "crypto_extra.h"

#endif /* PSA_CRYPTO_H */
