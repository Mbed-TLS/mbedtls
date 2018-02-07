/**
 * \file psa/crypto.h
 * \brief Platform Security Architecture cryptography module
 */

#ifndef PSA_CRYPTO_H
#define PSA_CRYPTO_H

#include "crypto_platform.h"

#include <stddef.h>

#ifdef __DOXYGEN_ONLY__
/** \defgroup platform Implementation-specific definitions
 * @{
 */

/** \brief Key slot number.
 *
 * This type represents key slots. It must be an unsigned integral
 * type.* The choice of type is implementation-dependent.
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
#endif

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
        by this implementation. */
    PSA_ERROR_NOT_SUPPORTED,
    /** The requested action is denied by a policy. */
    PSA_ERROR_NOT_PERMITTED,
    /** An output buffer is too small. */
    PSA_ERROR_BUFFER_TOO_SMALL,
    /** A slot is occupied, but must be empty to carry out the
        requested action. */
    PSA_ERROR_OCCUPIED_SLOT,
    /** A slot is empty, but must be occupied to carry out the
        requested action. */
    PSA_ERROR_EMPTY_SLOT,
    /** The requested action cannot be performed in the current state. */
    PSA_ERROR_BAD_STATE,
    /** The parameters passed to the function are invalid. */
    PSA_ERROR_INVALID_ARGUMENT,
    /** There is not enough runtime memory. */
    PSA_ERROR_INSUFFICIENT_MEMORY,
    /** There is not enough persistent storage. */
    PSA_ERROR_INSUFFICIENT_STORAGE,
    /** There was a communication failure inside the implementation. */
    PSA_ERROR_COMMUNICATION_FAILURE,
    /** There was a storage failure that may have led to data loss. */
    PSA_ERROR_STORAGE_FAILURE,
    /** A hardware failure was detected. */
    PSA_ERROR_HARDWARE_FAILURE,
    /** A tampering attempt was detected. */
    PSA_ERROR_TAMPERING_DETECTED,
    /** There is not enough entropy to generate random data needed
        for the requested action. */
    PSA_ERROR_INSUFFICIENT_ENTROPY,
    /** The signature, MAC or hash is incorrect. */
    PSA_ERROR_INVALID_SIGNATURE,
    /** The decrypted padding is incorrect. */
    PSA_ERROR_INVALID_PADDING,
    /** An error occurred that does not correspond to any defined
        failure cause. */
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
 * \return * \c PSA_SUCCESS: success.
 *         * \c PSA_ERROR_INSUFFICIENT_MEMORY
 *         * \c PSA_ERROR_COMMUNICATION_FAILURE
 *         * \c PSA_ERROR_HARDWARE_FAILURE
 *         * \c PSA_ERROR_TAMPERING_DETECTED
 *         * \c PSA_ERROR_INSUFFICIENT_ENTROPY
 */
psa_status_t psa_crypto_init(void);

#define BITS_TO_BYTES(bits) (((bits) + 7) / 8)
#define BYTES_TO_BITS(bytes) ((bytes) * 8)

/**@}*/

/** \defgroup crypto_types Key and algorithm types
 * @{
 */

typedef uint32_t psa_key_type_t;

#define PSA_KEY_TYPE_NONE                       ((psa_key_type_t)0x00000000)
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

#define PSA_KEY_TYPE_RSA_PUBLIC_KEY             ((psa_key_type_t)0x06010000)
#define PSA_KEY_TYPE_RSA_KEYPAIR                ((psa_key_type_t)0x07010000)
#define PSA_KEY_TYPE_ECC_BASE                   ((psa_key_type_t)0x06030000)
#define PSA_KEY_TYPE_ECC_CURVE_MASK             ((psa_key_type_t)0x0000ffff)

#define PSA_KEY_TYPE_IS_VENDOR_DEFINED(type) \
    (((type) & PSA_KEY_TYPE_VENDOR_FLAG) != 0)
#define PSA_KEY_TYPE_IS_ASYMMETRIC(type)                                \
    (((type) & PSA_KEY_TYPE_CATEGORY_MASK) == PSA_KEY_TYPE_CATEGORY_ASYMMETRIC)
#define PSA_KEY_TYPE_IS_PUBLIC_KEY(type)                                \
    (((type) & (PSA_KEY_TYPE_CATEGORY_MASK | PSA_KEY_TYPE_PAIR_FLAG) == \
      PSA_KEY_TYPE_CATEGORY_ASYMMETRIC))
#define PSA_KEY_TYPE_IS_KEYPAIR(type)                                   \
    (((type) & (PSA_KEY_TYPE_CATEGORY_MASK | PSA_KEY_TYPE_PAIR_FLAG)) == \
     (PSA_KEY_TYPE_CATEGORY_ASYMMETRIC | PSA_KEY_TYPE_PAIR_FLAG))
#define PSA_KEY_TYPE_IS_RSA(type)                                       \
    (((type) & ~PSA_KEY_TYPE_PAIR_FLAG) == PSA_KEY_TYPE_RSA_PUBLIC_KEY)
#define PSA_KEY_TYPE_IS_ECC(type)                                       \
    (((type) & ~PSA_KEY_TYPE_ECC_CURVE_MASK) == PSA_KEY_TYPE_ECC_BASE)

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
#define PSA_ALG_SHA_256_128                     ((psa_algorithm_t)0x01000004)
#define PSA_ALG_RIPEMD160                       ((psa_algorithm_t)0x01000005)
#define PSA_ALG_SHA_1                           ((psa_algorithm_t)0x01000006)
#define PSA_ALG_SHA_256_160                     ((psa_algorithm_t)0x01000007)
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

#define PSA_ALG_HMAC_BASE                       ((psa_algorithm_t)0x02800000)
#define PSA_ALG_HMAC(hash_alg)                  \
    (PSA_ALG_HMAC_BASE | (hash_alg))
#define PSA_ALG_CBC_MAC                         ((psa_algorithm_t)0x02000001)
#define PSA_ALG_CMAC                            ((psa_algorithm_t)0x02000002)
#define PSA_ALG_GMAC                            ((psa_algorithm_t)0x02000003)

#define PSA_ALG_BLOCK_CIPHER_BASE_MASK          ((psa_algorithm_t)0x000000ff)
#define PSA_ALG_BLOCK_CIPHER_PADDING_MASK       ((psa_algorithm_t)0x007f0000)
#define PSA_ALG_BLOCK_CIPHER_PAD_PKCS7          ((psa_algorithm_t)0x00010000)
#define PSA_ALG_CBC_BASE                        ((psa_algorithm_t)0x04000001)
#define PSA_ALG_CFB_BASE                        ((psa_algorithm_t)0x04000003)
#define PSA_ALG_OFB_BASE                        ((psa_algorithm_t)0x04000004)
#define PSA_ALG_XTS_BASE                        ((psa_algorithm_t)0x04000005)
#define PSA_ALG_STREAM_CIPHER                   ((psa_algorithm_t)0x04800000)
#define PSA_ALG_CTR                             ((psa_algorithm_t)0x04800001)

#define PSA_ALG_CCM                             ((psa_algorithm_t)0x06000002)
#define PSA_ALG_GCM                             ((psa_algorithm_t)0x06000003)

#define PSA_ALG_RSA_PKCS1V15_RAW                ((psa_algorithm_t)0x10010000)
#define PSA_ALG_RSA_PSS_MGF1                    ((psa_algorithm_t)0x10020000)
#define PSA_ALG_RSA_OAEP                        ((psa_algorithm_t)0x12020000)
#define PSA_ALG_RSA_PKCS1V15(hash_alg)                                  \
    (PSA_ALG_RSA_PKCS1V15_RAW | ((hash_alg) & PSA_ALG_HASH_MASK))
#define PSA_ALG_IS_RSA_PKCS1V15(alg)                                    \
    (((alg) & 0x7fffff00) == PSA_ALG_RSA_PKCS1V15_RAW)
#define PSA_ALG_RSA_GET_HASH(alg)                                       \
    (((alg) & PSA_ALG_HASH_MASK) | PSA_ALG_CATEGORY_HASH)

/**@}*/

/** \defgroup key_management Key management
 * @{
 */

/**
 * \brief Import a key in binary format.
 *
 * This function supports any output from psa_export_key().
 *
 * \return * \c PSA_SUCCESS: success.
 *         * \c PSA_ERROR_NOT_SUPPORTED
 *         * \c PSA_ERROR_INVALID_ARGUMENT
 *         * \c PSA_ERROR_INSUFFICIENT_MEMORY
 *         * \c PSA_ERROR_COMMUNICATION_FAILURE
 *         * \c PSA_ERROR_HARDWARE_FAILURE
 *         * \c PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_import_key(psa_key_slot_t key,
                            psa_key_type_t type,
                            const uint8_t *data,
                            size_t data_length);

/**
 * \brief Destroy a key.
 *
 * \return * \c PSA_SUCCESS: success.
 *         * \c PSA_ERROR_EMPTY_SLOT
 *         * \c PSA_ERROR_COMMUNICATION_FAILURE
 *         * \c PSA_ERROR_HARDWARE_FAILURE
 *         * \c PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_destroy_key(psa_key_slot_t key);

/**
 * \brief Get basic metadata about a key.
 *
 * \return * \c PSA_SUCCESS: success.
 *         * \c PSA_ERROR_EMPTY_SLOT
 *         * \c PSA_ERROR_COMMUNICATION_FAILURE
 *         * \c PSA_ERROR_HARDWARE_FAILURE
 *         * \c PSA_ERROR_TAMPERING_DETECTED
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
 * of the same key.
 *
 * \return * \c PSA_SUCCESS: success.
 *         * \c PSA_ERROR_EMPTY_SLOT
 *         * \c PSA_ERROR_COMMUNICATION_FAILURE
 *         * \c PSA_ERROR_HARDWARE_FAILURE
 *         * \c PSA_ERROR_TAMPERING_DETECTED
 */
psa_status_t psa_export_key(psa_key_slot_t key,
                            uint8_t *data,
                            size_t data_size,
                            size_t *data_length);


/**@}*/

/** \defgroup hash Message digests
 * @{
 */

typedef struct psa_hash_operation_s psa_hash_operation_t;

#define PSA_HASH_FINAL_SIZE(alg)                \
    (                                           \
        (alg) == PSA_ALG_MD2 ? 16 :             \
        (alg) == PSA_ALG_MD4 ? 16 :             \
        (alg) == PSA_ALG_MD5 ? 16 :             \
        (alg) == PSA_ALG_SHA_256_128 ? 16 :     \
        (alg) == PSA_ALG_RIPEMD160 ? 20 :       \
        (alg) == PSA_ALG_SHA_1 ? 20 :           \
        (alg) == PSA_ALG_SHA_256_160 ? 20 :     \
        (alg) == PSA_ALG_SHA_224 ? 28 :         \
        (alg) == PSA_ALG_SHA_256 ? 32 :         \
        (alg) == PSA_ALG_SHA_384 ? 48 :         \
        (alg) == PSA_ALG_SHA_512 ? 64 :         \
        (alg) == PSA_ALG_SHA_512_224 ? 28 :     \
        (alg) == PSA_ALG_SHA_512_256 ? 32 :     \
        (alg) == PSA_ALG_SHA3_224 ? 28 :        \
        (alg) == PSA_ALG_SHA3_256 ? 32 :        \
        (alg) == PSA_ALG_SHA3_384 ? 48 :        \
        (alg) == PSA_ALG_SHA3_512 ? 64 :        \
        0)

psa_status_t psa_hash_start(psa_hash_operation_t *operation,
                            psa_algorithm_t alg);

psa_status_t psa_hash_update(psa_hash_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length);

psa_status_t psa_hash_finish(psa_hash_operation_t *operation,
                             uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length);

psa_status_t psa_hash_verify(psa_hash_operation_t *operation,
                             const uint8_t *hash,
                             size_t hash_length);

psa_status_t ps_hash_abort(psa_hash_operation_t *operation);

/**@}*/

/** \defgroup MAC Message authentication codes
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


#define PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE(key_type, key_bits, alg)        \
    (PSA_KEY_TYPE_IS_RSA(key_type) ? ((void)alg, BITS_TO_BYTES(key_bits)) : \
     PSA_KEY_TYPE_IS_ECC(key_type) ? PSA_ECDSA_SIGNATURE_SIZE(key_bits) : \
     0)

/**
 * \brief Sign a hash or short message with a private key.
 *
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
 */
psa_status_t psa_asymmetric_verify(psa_key_slot_t key,
                                   psa_algorithm_t alg,
                                   const uint8_t *hash,
                                   size_t hash_length,
                                   const uint8_t *salt,
                                   size_t salt_length,
                                   uint8_t *signature,
                                   size_t signature_size);

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
