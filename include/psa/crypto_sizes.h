/**
 * \file psa/crypto_sizes.h
 *
 * \brief PSA cryptography module: Mbed TLS buffer size macros
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * This file contains the definitions of macros that are useful to
 * compute buffer sizes. The signatures and semantics of these macros
 * are standardized, but the definitions are not, because they depend on
 * the available algorithms and, in some cases, on permitted tolerances
 * on buffer sizes.
 *
 * In implementations with isolation between the application and the
 * cryptography module, implementers should take care to ensure that
 * the definitions that are exposed to applications match what the
 * module implements.
 *
 * Macros that compute sizes whose values do not depend on the
 * implementation are in crypto.h.
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

#ifndef PSA_CRYPTO_SIZES_H
#define PSA_CRYPTO_SIZES_H

/* Include the Mbed TLS configuration file, the way Mbed TLS does it
 * in each of its header files. */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "../mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

/** \def PSA_HASH_MAX_SIZE
 *
 * Maximum size of a hash.
 *
 * This macro must expand to a compile-time constant integer. This value
 * should be the maximum size of a hash supported by the implementation,
 * in bytes, and must be no smaller than this maximum.
 */
#if defined(MBEDTLS_SHA512_C)
#define PSA_HASH_MAX_SIZE 64
#define PSA_HMAC_MAX_HASH_BLOCK_SIZE 128
#else
#define PSA_HASH_MAX_SIZE 32
#define PSA_HMAC_MAX_HASH_BLOCK_SIZE 64
#endif

/** \def PSA_MAC_MAX_SIZE
 *
 * Maximum size of a MAC.
 *
 * This macro must expand to a compile-time constant integer. This value
 * should be the maximum size of a MAC supported by the implementation,
 * in bytes, and must be no smaller than this maximum.
 */
/* All non-HMAC MACs have a maximum size that's smaller than the
 * minimum possible value of PSA_HASH_MAX_SIZE in this implementation. */
#define PSA_MAC_MAX_SIZE PSA_HASH_MAX_SIZE

/* The maximum size of an RSA key on this implementation, in bits.
 * This is a vendor-specific macro.
 *
 * Mbed TLS does not set a hard limit on the size of RSA keys: any key
 * whose parameters fit in a bignum is accepted. However large keys can
 * induce a large memory usage and long computation times. Unlike other
 * auxiliary macros in this file and in crypto.h, which reflect how the
 * library is configured, this macro defines how the library is
 * configured. This implementation refuses to import or generate an
 * RSA key whose size is larger than the value defined here.
 *
 * Note that an implementation may set different size limits for different
 * operations, and does not need to accept all key sizes up to the limit. */
#define PSA_VENDOR_RSA_MAX_KEY_BITS 4096

/* The maximum size of an ECC key on this implementation, in bits.
 * This is a vendor-specific macro. */
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 521
#elif defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 512
#elif defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 448
#elif defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 384
#elif defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 384
#elif defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 256
#elif defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 256
#elif defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 256
#elif defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 255
#elif defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 224
#elif defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 224
#elif defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 192
#elif defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 192
#else
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 0
#endif

/** \def PSA_ASYMMETRIC_SIGNATURE_MAX_SIZE
 *
 * Maximum size of an asymmetric signature.
 *
 * This macro must expand to a compile-time constant integer. This value
 * should be the maximum size of a MAC supported by the implementation,
 * in bytes, and must be no smaller than this maximum.
 */
#define PSA_ASYMMETRIC_SIGNATURE_MAX_SIZE                               \
    PSA_BITS_TO_BYTES(                                                  \
        PSA_VENDOR_RSA_MAX_KEY_BITS > PSA_VENDOR_ECC_MAX_CURVE_BITS ?   \
        PSA_VENDOR_RSA_MAX_KEY_BITS :                                   \
        PSA_VENDOR_ECC_MAX_CURVE_BITS                                   \
        )



/** The size of the output of psa_mac_sign_finish(), in bytes.
 *
 * This is also the MAC size that psa_mac_verify_finish() expects.
 *
 * \param key_type      The type of the MAC key.
 * \param key_bits      The size of the MAC key in bits.
 * \param alg           A MAC algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_MAC(alg) is true).
 *
 * \return              The MAC size for the specified algorithm with
 *                      the specified key parameters.
 * \return              0 if the MAC algorithm is not recognized.
 * \return              Either 0 or the correct size for a MAC algorithm that
 *                      the implementation recognizes, but does not support.
 * \return              Unspecified if the key parameters are not consistent
 *                      with the algorithm.
 */
#define PSA_MAC_FINAL_SIZE(key_type, key_bits, alg)                     \
    (PSA_ALG_IS_HMAC(alg) ? PSA_HASH_SIZE(PSA_ALG_HMAC_HASH(alg)) : \
     PSA_ALG_IS_BLOCK_CIPHER_MAC(alg) ? PSA_BLOCK_CIPHER_BLOCK_SIZE(key_type) : \
     0)

/** The maximum size of the output of psa_aead_encrypt(), in bytes.
 *
 * If the size of the ciphertext buffer is at least this large, it is
 * guaranteed that psa_aead_encrypt() will not fail due to an
 * insufficient buffer size. Depending on the algorithm, the actual size of
 * the ciphertext may be smaller.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(alg) is true).
 * \param plaintext_length    Size of the plaintext in bytes.
 *
 * \return                    The AEAD ciphertext size for the specified
 *                            algorithm.
 *                            If the AEAD algorithm is not recognized, return 0.
 *                            An implementation may return either 0 or a
 *                            correct size for an AEAD algorithm that it
 *                            recognizes, but does not support.
 */
#define PSA_AEAD_ENCRYPT_OUTPUT_SIZE(alg, plaintext_length)     \
    (PSA_AEAD_TAG_SIZE(alg) != 0 ?                              \
     (plaintext_length) + PSA_AEAD_TAG_SIZE(alg) :              \
     0)

/** The maximum size of the output of psa_aead_decrypt(), in bytes.
 *
 * If the size of the plaintext buffer is at least this large, it is
 * guaranteed that psa_aead_decrypt() will not fail due to an
 * insufficient buffer size. Depending on the algorithm, the actual size of
 * the plaintext may be smaller.
 *
 * \param alg                 An AEAD algorithm
 *                            (\c PSA_ALG_XXX value such that
 *                            #PSA_ALG_IS_AEAD(alg) is true).
 * \param ciphertext_length   Size of the plaintext in bytes.
 *
 * \return                    The AEAD ciphertext size for the specified
 *                            algorithm.
 *                            If the AEAD algorithm is not recognized, return 0.
 *                            An implementation may return either 0 or a
 *                            correct size for an AEAD algorithm that it
 *                            recognizes, but does not support.
 */
#define PSA_AEAD_DECRYPT_OUTPUT_SIZE(alg, ciphertext_length)    \
    (PSA_AEAD_TAG_SIZE(alg) != 0 ?                              \
     (plaintext_length) - PSA_AEAD_TAG_SIZE(alg) :              \
     0)

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

#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg)     \
    (PSA_KEY_TYPE_IS_RSA(key_type) ?                                    \
     ((void)alg, PSA_BITS_TO_BYTES(key_bits)) :                         \
     0)
#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg)     \
    (PSA_KEY_TYPE_IS_RSA(key_type) ?                                    \
     PSA_BITS_TO_BYTES(key_bits) - PSA_RSA_MINIMUM_PADDING_SIZE(alg) :  \
     0)

#endif /* PSA_CRYPTO_SIZES_H */
