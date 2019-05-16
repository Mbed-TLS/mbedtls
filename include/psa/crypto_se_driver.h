/**
 * \file psa/crypto_se_driver.h
 * \brief PSA external cryptoprocessor driver module
 *
 * This header declares types and function signatures for cryptography
 * drivers that access key material via opaque references.
 * This is meant for cryptoprocessors that have a separate key storage from the
 * space in which the PSA Crypto implementation runs, typically secure
 * elements (SEs).
 *
 * This file is part of the PSA Crypto Driver Model, containing functions for
 * driver developers to implement to enable hardware to be called in a
 * standardized way by a PSA Cryptographic API implementation. The functions
 * comprising the driver model, which driver authors implement, are not
 * intended to be called by application developers.
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
#ifndef PSA_CRYPTO_SE_DRIVER_H
#define PSA_CRYPTO_SE_DRIVER_H

#include "crypto_driver_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** An internal designation of a key slot between the core part of the
 * PSA Crypto implementation and the driver. The meaning of this value
 * is driver-dependent. */
typedef uint32_t psa_key_slot_number_t; // Change this to psa_key_slot_t after psa_key_slot_t is removed from Mbed crypto

/** \defgroup se_mac Secure Element Message Authentication Codes
 * Generation and authentication of Message Authentication Codes (MACs) using
 * a secure element can be done either as a single function call (via the
 * `psa_drv_se_mac_generate_t` or `psa_drv_se_mac_verify_t` functions), or in
 * parts using the following sequence:
 * - `psa_drv_se_mac_setup_t`
 * - `psa_drv_se_mac_update_t`
 * - `psa_drv_se_mac_update_t`
 * - ...
 * - `psa_drv_se_mac_finish_t` or `psa_drv_se_mac_finish_verify_t`
 *
 * If a previously started secure element MAC operation needs to be terminated,
 * it should be done so by the `psa_drv_se_mac_abort_t`. Failure to do so may
 * result in allocated resources not being freed or in other undefined
 * behavior.
 */
/**@{*/
/** \brief A function that starts a secure element  MAC operation for a PSA
 * Crypto Driver implementation
 *
 * \param[in,out] p_context     A structure that will contain the
 *                              hardware-specific MAC context
 * \param[in] key_slot          The slot of the key to be used for the
 *                              operation
 * \param[in] algorithm         The algorithm to be used to underly the MAC
 *                              operation
 *
 * \retval  PSA_SUCCESS
 *          Success.
 */
typedef psa_status_t (*psa_drv_se_mac_setup_t)(void *p_context,
                                               psa_key_slot_number_t key_slot,
                                               psa_algorithm_t algorithm);

/** \brief A function that continues a previously started secure element MAC
 * operation
 *
 * \param[in,out] p_context     A hardware-specific structure for the
 *                              previously-established MAC operation to be
 *                              updated
 * \param[in] p_input           A buffer containing the message to be appended
 *                              to the MAC operation
 * \param[in] input_length  The size in bytes of the input message buffer
 */
typedef psa_status_t (*psa_drv_se_mac_update_t)(void *p_context,
                                                const uint8_t *p_input,
                                                size_t input_length);

/** \brief a function that completes a previously started secure element MAC
 * operation by returning the resulting MAC.
 *
 * \param[in,out] p_context     A hardware-specific structure for the
 *                              previously started MAC operation to be
 *                              finished
 * \param[out] p_mac            A buffer where the generated MAC will be
 *                              placed
 * \param[in] mac_size          The size in bytes of the buffer that has been
 *                              allocated for the `output` buffer
 * \param[out] p_mac_length     After completion, will contain the number of
 *                              bytes placed in the `p_mac` buffer
 *
 * \retval PSA_SUCCESS
 *          Success.
 */
typedef psa_status_t (*psa_drv_se_mac_finish_t)(void *p_context,
                                                uint8_t *p_mac,
                                                size_t mac_size,
                                                size_t *p_mac_length);

/** \brief A function that completes a previously started secure element MAC
 * operation by comparing the resulting MAC against a provided value
 *
 * \param[in,out] p_context A hardware-specific structure for the previously
 *                          started MAC operation to be fiinished
 * \param[in] p_mac         The MAC value against which the resulting MAC will
 *                          be compared against
 * \param[in] mac_length    The size in bytes of the value stored in `p_mac`
 *
 * \retval PSA_SUCCESS
 *         The operation completed successfully and the MACs matched each
 *         other
 * \retval PSA_ERROR_INVALID_SIGNATURE
 *         The operation completed successfully, but the calculated MAC did
 *         not match the provided MAC
 */
typedef psa_status_t (*psa_drv_se_mac_finish_verify_t)(void *p_context,
                                                       const uint8_t *p_mac,
                                                       size_t mac_length);

/** \brief A function that aborts a previous started secure element MAC
 * operation
 *
 * \param[in,out] p_context A hardware-specific structure for the previously
 *                          started MAC operation to be aborted
 */
typedef psa_status_t (*psa_drv_se_mac_abort_t)(void *p_context);

/** \brief A function that performs a secure element MAC operation in one
 * command and returns the calculated MAC
 *
 * \param[in] p_input           A buffer containing the message to be MACed
 * \param[in] input_length      The size in bytes of `p_input`
 * \param[in] key_slot          The slot of the key to be used
 * \param[in] alg               The algorithm to be used to underlie the MAC
 *                              operation
 * \param[out] p_mac            A buffer where the generated MAC will be
 *                              placed
 * \param[in] mac_size          The size in bytes of the `p_mac` buffer
 * \param[out] p_mac_length     After completion, will contain the number of
 *                              bytes placed in the `output` buffer
 *
 * \retval PSA_SUCCESS
 *         Success.
 */
typedef psa_status_t (*psa_drv_se_mac_generate_t)(const uint8_t *p_input,
                                                  size_t input_length,
                                                  psa_key_slot_number_t key_slot,
                                                  psa_algorithm_t alg,
                                                  uint8_t *p_mac,
                                                  size_t mac_size,
                                                  size_t *p_mac_length);

/** \brief A function that performs a secure element MAC operation in one
 * command and compares the resulting MAC against a provided value
 *
 * \param[in] p_input       A buffer containing the message to be MACed
 * \param[in] input_length  The size in bytes of `input`
 * \param[in] key_slot      The slot of the key to be used
 * \param[in] alg           The algorithm to be used to underlie the MAC
 *                          operation
 * \param[in] p_mac         The MAC value against which the resulting MAC will
 *                          be compared against
 * \param[in] mac_length   The size in bytes of `mac`
 *
 * \retval PSA_SUCCESS
 *         The operation completed successfully and the MACs matched each
 *         other
 * \retval PSA_ERROR_INVALID_SIGNATURE
 *         The operation completed successfully, but the calculated MAC did
 *         not match the provided MAC
 */
typedef psa_status_t (*psa_drv_se_mac_verify_t)(const uint8_t *p_input,
                                                size_t input_length,
                                                psa_key_slot_number_t key_slot,
                                                psa_algorithm_t alg,
                                                const uint8_t *p_mac,
                                                size_t mac_length);

/** \brief A struct containing all of the function pointers needed to
 * perform secure element MAC operations
 *
 * PSA Crypto API implementations should populate the table as appropriate
 * upon startup.
 *
 * If one of the functions is not implemented (such as
 * `psa_drv_se_mac_generate_t`), it should be set to NULL.
 *
 * Driver implementers should ensure that they implement all of the functions
 * that make sense for their hardware, and that they provide a full solution
 * (for example, if they support `p_setup`, they should also support
 * `p_update` and at least one of `p_finish` or `p_finish_verify`).
 *
 */
typedef struct {
    /**The size in bytes of the hardware-specific secure element MAC context
     * structure
    */
    size_t                    context_size;
    /** Function that performs a MAC setup operation
     */
    psa_drv_se_mac_setup_t          p_setup;
    /** Function that performs a MAC update operation
     */
    psa_drv_se_mac_update_t         p_update;
    /** Function that completes a MAC operation
     */
    psa_drv_se_mac_finish_t         p_finish;
    /** Function that completes a MAC operation with a verify check
     */
    psa_drv_se_mac_finish_verify_t  p_finish_verify;
    /** Function that aborts a previoustly started MAC operation
     */
    psa_drv_se_mac_abort_t          p_abort;
    /** Function that performs a MAC operation in one call
     */
    psa_drv_se_mac_generate_t       p_mac;
    /** Function that performs a MAC and verify operation in one call
     */
    psa_drv_se_mac_verify_t         p_mac_verify;
} psa_drv_se_mac_t;
/**@}*/

/** \defgroup se_cipher Secure Element Symmetric Ciphers
 *
 * Encryption and Decryption using secure element keys in block modes other
 * than ECB must be done in multiple parts, using the following flow:
 * - `psa_drv_se_cipher_setup_t`
 * - `psa_drv_se_cipher_set_iv_t` (optional depending upon block mode)
 * - `psa_drv_se_cipher_update_t`
 * - `psa_drv_se_cipher_update_t`
 * - ...
 * - `psa_drv_se_cipher_finish_t`
 *
 * If a previously started secure element Cipher operation needs to be
 * terminated, it should be done so by the `psa_drv_se_cipher_abort_t`. Failure
 * to do so may result in allocated resources not being freed or in other
 * undefined behavior.
 *
 * In situations where a PSA Cryptographic API implementation is using a block
 * mode not-supported by the underlying hardware or driver, it can construct
 * the block mode itself, while calling the `psa_drv_se_cipher_ecb_t` function
 * for the cipher operations.
 */
/**@{*/

/** \brief A function that provides the cipher setup function for a
 * secure element driver
 *
 * \param[in,out] p_context     A structure that will contain the
 *                              hardware-specific cipher context.
 * \param[in] key_slot          The slot of the key to be used for the
 *                              operation
 * \param[in] algorithm         The algorithm to be used in the cipher
 *                              operation
 * \param[in] direction         Indicates whether the operation is an encrypt
 *                              or decrypt
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_NOT_SUPPORTED
 */
typedef psa_status_t (*psa_drv_se_cipher_setup_t)(void *p_context,
                                                  psa_key_slot_number_t key_slot,
                                                  psa_algorithm_t algorithm,
                                                  psa_encrypt_or_decrypt_t direction);

/** \brief A function that sets the initialization vector (if
 * necessary) for an secure element cipher operation
 *
 * Rationale: The `psa_se_cipher_*` operation in the PSA Cryptographic API has
 * two IV functions: one to set the IV, and one to generate it internally. The
 * generate function is not necessary for the drivers to implement as the PSA
 * Crypto implementation can do the generation using its RNG features.
 *
 * \param[in,out] p_context     A structure that contains the previously set up
 *                              hardware-specific cipher context
 * \param[in] p_iv              A buffer containing the initialization vector
 * \param[in] iv_length         The size (in bytes) of the `p_iv` buffer
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_se_cipher_set_iv_t)(void *p_context,
                                                   const uint8_t *p_iv,
                                                   size_t iv_length);

/** \brief A function that continues a previously started secure element cipher
 * operation
 *
 * \param[in,out] p_context         A hardware-specific structure for the
 *                                  previously started cipher operation
 * \param[in] p_input               A buffer containing the data to be
 *                                  encrypted/decrypted
 * \param[in] input_size            The size in bytes of the buffer pointed to
 *                                  by `p_input`
 * \param[out] p_output             The caller-allocated buffer where the
 *                                  output will be placed
 * \param[in] output_size           The allocated size in bytes of the
 *                                  `p_output` buffer
 * \param[out] p_output_length      After completion, will contain the number
 *                                  of bytes placed in the `p_output` buffer
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_se_cipher_update_t)(void *p_context,
                                                   const uint8_t *p_input,
                                                   size_t input_size,
                                                   uint8_t *p_output,
                                                   size_t output_size,
                                                   size_t *p_output_length);

/** \brief A function that completes a previously started secure element cipher
 * operation
 *
 * \param[in,out] p_context     A hardware-specific structure for the
 *                              previously started cipher operation
 * \param[out] p_output         The caller-allocated buffer where the output
 *                              will be placed
 * \param[in] output_size       The allocated size in bytes of the `p_output`
 *                              buffer
 * \param[out] p_output_length  After completion, will contain the number of
 *                              bytes placed in the `p_output` buffer
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_se_cipher_finish_t)(void *p_context,
                                                   uint8_t *p_output,
                                                   size_t output_size,
                                                   size_t *p_output_length);

/** \brief A function that aborts a previously started secure element cipher
 * operation
 *
 * \param[in,out] p_context     A hardware-specific structure for the
 *                              previously started cipher operation
 */
typedef psa_status_t (*psa_drv_se_cipher_abort_t)(void *p_context);

/** \brief A function that performs the ECB block mode for secure element
 * cipher operations
 *
 * Note: this function should only be used with implementations that do not
 * provide a needed higher-level operation.
 *
 * \param[in] key_slot      The slot of the key to be used for the operation
 * \param[in] algorithm     The algorithm to be used in the cipher operation
 * \param[in] direction     Indicates whether the operation is an encrypt or
 *                          decrypt
 * \param[in] p_input       A buffer containing the data to be
 *                          encrypted/decrypted
 * \param[in] input_size    The size in bytes of the buffer pointed to by
 *                          `p_input`
 * \param[out] p_output     The caller-allocated buffer where the output will
 *                          be placed
 * \param[in] output_size   The allocated size in bytes of the `p_output`
 *                          buffer
 *
 * \retval PSA_SUCCESS
 * \retval PSA_ERROR_NOT_SUPPORTED
 */
typedef psa_status_t (*psa_drv_se_cipher_ecb_t)(psa_key_slot_number_t key_slot,
                                                psa_algorithm_t algorithm,
                                                psa_encrypt_or_decrypt_t direction,
                                                const uint8_t *p_input,
                                                size_t input_size,
                                                uint8_t *p_output,
                                                size_t output_size);

/**
 * \brief A struct containing all of the function pointers needed to implement
 * cipher operations using secure elements.
 *
 * PSA Crypto API implementations should populate instances of the table as
 * appropriate upon startup or at build time.
 *
 * If one of the functions is not implemented (such as
 * `psa_drv_se_cipher_ecb_t`), it should be set to NULL.
 */
typedef struct {
    /** The size in bytes of the hardware-specific secure element cipher
     * context structure
     */
    size_t               context_size;
    /** Function that performs a cipher setup operation */
    psa_drv_se_cipher_setup_t  p_setup;
    /** Function that sets a cipher IV (if necessary) */
    psa_drv_se_cipher_set_iv_t p_set_iv;
    /** Function that performs a cipher update operation */
    psa_drv_se_cipher_update_t p_update;
    /** Function that completes a cipher operation */
    psa_drv_se_cipher_finish_t p_finish;
    /** Function that aborts a cipher operation */
    psa_drv_se_cipher_abort_t  p_abort;
    /** Function that performs ECB mode for a cipher operation
     * (Danger: ECB mode should not be used directly by clients of the PSA
     * Crypto Client API)
     */
    psa_drv_se_cipher_ecb_t    p_ecb;
} psa_drv_se_cipher_t;

/**@}*/

/** \defgroup se_asymmetric Secure Element Asymmetric Cryptography
 *
 * Since the amount of data that can (or should) be encrypted or signed using
 * asymmetric keys is limited by the key size, asymmetric key operations using
 * keys in a secure element must be done in single function calls.
 */
/**@{*/

/**
 * \brief A function that signs a hash or short message with a private key in
 * a secure element
 *
 * \param[in] key_slot              Key slot of an asymmetric key pair
 * \param[in] alg                   A signature algorithm that is compatible
 *                                  with the type of `key`
 * \param[in] p_hash                The hash to sign
 * \param[in] hash_length           Size of the `p_hash` buffer in bytes
 * \param[out] p_signature          Buffer where the signature is to be written
 * \param[in] signature_size        Size of the `p_signature` buffer in bytes
 * \param[out] p_signature_length   On success, the number of bytes
 *                                  that make up the returned signature value
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_se_asymmetric_sign_t)(psa_key_slot_number_t key_slot,
                                                     psa_algorithm_t alg,
                                                     const uint8_t *p_hash,
                                                     size_t hash_length,
                                                     uint8_t *p_signature,
                                                     size_t signature_size,
                                                     size_t *p_signature_length);

/**
 * \brief A function that verifies the signature a hash or short message using
 * an asymmetric public key in a secure element
 *
 * \param[in] key_slot          Key slot of a public key or an asymmetric key
 *                              pair
 * \param[in] alg               A signature algorithm that is compatible with
 *                              the type of `key`
 * \param[in] p_hash            The hash whose signature is to be verified
 * \param[in] hash_length       Size of the `p_hash` buffer in bytes
 * \param[in] p_signature       Buffer containing the signature to verify
 * \param[in] signature_length  Size of the `p_signature` buffer in bytes
 *
 * \retval PSA_SUCCESS
 *         The signature is valid.
 */
typedef psa_status_t (*psa_drv_se_asymmetric_verify_t)(psa_key_slot_number_t key_slot,
                                                       psa_algorithm_t alg,
                                                       const uint8_t *p_hash,
                                                       size_t hash_length,
                                                       const uint8_t *p_signature,
                                                       size_t signature_length);

/**
 * \brief A function that encrypts a short message with an asymmetric public
 * key in a secure element
 *
 * \param[in] key_slot          Key slot of a public key or an asymmetric key
 *                              pair
 * \param[in] alg               An asymmetric encryption algorithm that is
 *                              compatible with the type of `key`
 * \param[in] p_input           The message to encrypt
 * \param[in] input_length      Size of the `p_input` buffer in bytes
 * \param[in] p_salt            A salt or label, if supported by the
 *                              encryption algorithm
 *                              If the algorithm does not support a
 *                              salt, pass `NULL`.
 *                              If the algorithm supports an optional
 *                              salt and you do not want to pass a salt,
 *                              pass `NULL`.
 *                              For #PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is
 *                              supported.
 * \param[in] salt_length       Size of the `p_salt` buffer in bytes
 *                              If `p_salt` is `NULL`, pass 0.
 * \param[out] p_output         Buffer where the encrypted message is to
 *                              be written
 * \param[in] output_size       Size of the `p_output` buffer in bytes
 * \param[out] p_output_length  On success, the number of bytes that make up
 *                              the returned output
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_se_asymmetric_encrypt_t)(psa_key_slot_number_t key_slot,
                                                        psa_algorithm_t alg,
                                                        const uint8_t *p_input,
                                                        size_t input_length,
                                                        const uint8_t *p_salt,
                                                        size_t salt_length,
                                                        uint8_t *p_output,
                                                        size_t output_size,
                                                        size_t *p_output_length);

/**
 * \brief A function that decrypts a short message with an asymmetric private
 * key in a secure element.
 *
 * \param[in] key_slot          Key slot of an asymmetric key pair
 * \param[in] alg               An asymmetric encryption algorithm that is
 *                              compatible with the type of `key`
 * \param[in] p_input           The message to decrypt
 * \param[in] input_length      Size of the `p_input` buffer in bytes
 * \param[in] p_salt            A salt or label, if supported by the
 *                              encryption algorithm
 *                              If the algorithm does not support a
 *                              salt, pass `NULL`.
 *                              If the algorithm supports an optional
 *                              salt and you do not want to pass a salt,
 *                              pass `NULL`.
 *                              For #PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is
 *                              supported.
 * \param[in] salt_length       Size of the `p_salt` buffer in bytes
 *                              If `p_salt` is `NULL`, pass 0.
 * \param[out] p_output         Buffer where the decrypted message is to
 *                              be written
 * \param[in] output_size       Size of the `p_output` buffer in bytes
 * \param[out] p_output_length  On success, the number of bytes
 *                              that make up the returned output
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_se_asymmetric_decrypt_t)(psa_key_slot_number_t key_slot,
                                                        psa_algorithm_t alg,
                                                        const uint8_t *p_input,
                                                        size_t input_length,
                                                        const uint8_t *p_salt,
                                                        size_t salt_length,
                                                        uint8_t *p_output,
                                                        size_t output_size,
                                                        size_t *p_output_length);

/**
 * \brief A struct containing all of the function pointers needed to implement
 * asymmetric cryptographic operations using secure elements.
 *
 * PSA Crypto API implementations should populate instances of the table as
 * appropriate upon startup or at build time.
 *
 * If one of the functions is not implemented, it should be set to NULL.
 */
typedef struct {
    /** Function that performs an asymmetric sign operation */
    psa_drv_se_asymmetric_sign_t    p_sign;
    /** Function that performs an asymmetric verify operation */
    psa_drv_se_asymmetric_verify_t  p_verify;
    /** Function that performs an asymmetric encrypt operation */
    psa_drv_se_asymmetric_encrypt_t p_encrypt;
    /** Function that performs an asymmetric decrypt operation */
    psa_drv_se_asymmetric_decrypt_t p_decrypt;
} psa_drv_se_asymmetric_t;

/**@}*/

/** \defgroup se_aead Secure Element Authenticated Encryption with Additional Data
 * Authenticated Encryption with Additional Data (AEAD) operations with secure
 * elements must be done in one function call. While this creates a burden for
 * implementers as there must be sufficient space in memory for the entire
 * message, it prevents decrypted data from being made available before the
 * authentication operation is complete and the data is known to be authentic.
 */
/**@{*/

/** \brief A function that performs a secure element authenticated encryption
 * operation
 *
 * \param[in] key_slot                  Slot containing the key to use.
 * \param[in] algorithm                 The AEAD algorithm to compute
 *                                      (\c PSA_ALG_XXX value such that
 *                                      #PSA_ALG_IS_AEAD(`alg`) is true)
 * \param[in] p_nonce                   Nonce or IV to use
 * \param[in] nonce_length              Size of the `p_nonce` buffer in bytes
 * \param[in] p_additional_data         Additional data that will be
 *                                      authenticated but not encrypted
 * \param[in] additional_data_length    Size of `p_additional_data` in bytes
 * \param[in] p_plaintext               Data that will be authenticated and
 *                                      encrypted
 * \param[in] plaintext_length          Size of `p_plaintext` in bytes
 * \param[out] p_ciphertext             Output buffer for the authenticated and
 *                                      encrypted data. The additional data is
 *                                      not part of this output. For algorithms
 *                                      where the encrypted data and the
 *                                      authentication tag are defined as
 *                                      separate outputs, the authentication
 *                                      tag is appended to the encrypted data.
 * \param[in] ciphertext_size           Size of the `p_ciphertext` buffer in
 *                                      bytes
 * \param[out] p_ciphertext_length      On success, the size of the output in
 *                                      the `p_ciphertext` buffer
 *
 * \retval #PSA_SUCCESS
 *         Success.
 */
typedef psa_status_t (*psa_drv_se_aead_encrypt_t)(psa_key_slot_number_t key_slot,
                                                  psa_algorithm_t algorithm,
                                                  const uint8_t *p_nonce,
                                                  size_t nonce_length,
                                                  const uint8_t *p_additional_data,
                                                  size_t additional_data_length,
                                                  const uint8_t *p_plaintext,
                                                  size_t plaintext_length,
                                                  uint8_t *p_ciphertext,
                                                  size_t ciphertext_size,
                                                  size_t *p_ciphertext_length);

/** A function that peforms a secure element authenticated decryption operation
 *
 * \param[in] key_slot                  Slot containing the key to use
 * \param[in] algorithm                 The AEAD algorithm to compute
 *                                      (\c PSA_ALG_XXX value such that
 *                                      #PSA_ALG_IS_AEAD(`alg`) is true)
 * \param[in] p_nonce                   Nonce or IV to use
 * \param[in] nonce_length              Size of the `p_nonce` buffer in bytes
 * \param[in] p_additional_data         Additional data that has been
 *                                      authenticated but not encrypted
 * \param[in] additional_data_length    Size of `p_additional_data` in bytes
 * \param[in] p_ciphertext              Data that has been authenticated and
 *                                      encrypted.
 *                                      For algorithms where the encrypted data
 *                                      and the authentication tag are defined
 *                                      as separate inputs, the buffer must
 *                                      contain the encrypted data followed by
 *                                      the authentication tag.
 * \param[in] ciphertext_length         Size of `p_ciphertext` in bytes
 * \param[out] p_plaintext              Output buffer for the decrypted data
 * \param[in] plaintext_size            Size of the `p_plaintext` buffer in
 *                                      bytes
 * \param[out] p_plaintext_length       On success, the size of the output in
 *                                      the `p_plaintext` buffer
 *
 * \retval #PSA_SUCCESS
 *         Success.
 */
typedef psa_status_t (*psa_drv_se_aead_decrypt_t)(psa_key_slot_number_t key_slot,
                                                  psa_algorithm_t algorithm,
                                                  const uint8_t *p_nonce,
                                                  size_t nonce_length,
                                                  const uint8_t *p_additional_data,
                                                  size_t additional_data_length,
                                                  const uint8_t *p_ciphertext,
                                                  size_t ciphertext_length,
                                                  uint8_t *p_plaintext,
                                                  size_t plaintext_size,
                                                  size_t *p_plaintext_length);

/**
 * \brief A struct containing all of the function pointers needed to implement
 * secure element Authenticated Encryption with Additional Data operations
 *
 * PSA Crypto API implementations should populate instances of the table as
 * appropriate upon startup.
 *
 * If one of the functions is not implemented, it should be set to NULL.
 */
typedef struct {
    /** Function that performs the AEAD encrypt operation */
    psa_drv_se_aead_encrypt_t p_encrypt;
    /** Function that performs the AEAD decrypt operation */
    psa_drv_se_aead_decrypt_t p_decrypt;
} psa_drv_se_aead_t;
/**@}*/

/** \defgroup se_key_management Secure Element Key Management
 * Currently, key management is limited to importing keys in the clear,
 * destroying keys, and exporting keys in the clear.
 * Whether a key may be exported is determined by the key policies in place
 * on the key slot.
 */
/**@{*/

/** \brief A function that imports a key into a secure element in binary format
 *
 * This function can support any output from psa_export_key(). Refer to the
 * documentation of psa_export_key() for the format for each key type.
 *
 * \param[in] key_slot      Slot where the key will be stored
 *                          This must be a valid slot for a key of the chosen
 *                          type. It must be unoccupied.
 * \param[in] lifetime      The required lifetime of the key storage
 * \param[in] type          Key type (a \c PSA_KEY_TYPE_XXX value)
 * \param[in] algorithm     Key algorithm (a \c PSA_ALG_XXX value)
 * \param[in] usage         The allowed uses of the key
 * \param[in] p_data        Buffer containing the key data
 * \param[in] data_length   Size of the `data` buffer in bytes
 *
 * \retval #PSA_SUCCESS
 *         Success.
 */
typedef psa_status_t (*psa_drv_se_import_key_t)(psa_key_slot_number_t key_slot,
                                                psa_key_lifetime_t lifetime,
                                                psa_key_type_t type,
                                                psa_algorithm_t algorithm,
                                                psa_key_usage_t usage,
                                                const uint8_t *p_data,
                                                size_t data_length);

/**
 * \brief A function that destroys a secure element key and restore the slot to
 * its default state
 *
 * This function destroys the content of the key from a secure element.
 * Implementations shall make a best effort to ensure that any previous content
 * of the slot is unrecoverable.
 *
 * This function returns the specified slot to its default state.
 *
 * \param[in] key_slot        The key slot to erase.
 *
 * \retval #PSA_SUCCESS
 *         The slot's content, if any, has been erased.
 */
typedef psa_status_t (*psa_drv_se_destroy_key_t)(psa_key_slot_number_t key);

/**
 * \brief A function that exports a secure element key in binary format
 *
 * The output of this function can be passed to psa_import_key() to
 * create an equivalent object.
 *
 * If a key is created with `psa_import_key()` and then exported with
 * this function, it is not guaranteed that the resulting data is
 * identical: the implementation may choose a different representation
 * of the same key if the format permits it.
 *
 * This function should generate output in the same format that
 * `psa_export_key()` does. Refer to the
 * documentation of `psa_export_key()` for the format for each key type.
 *
 * \param[in] key               Slot whose content is to be exported. This must
 *                              be an occupied key slot.
 * \param[out] p_data           Buffer where the key data is to be written.
 * \param[in] data_size         Size of the `p_data` buffer in bytes.
 * \param[out] p_data_length    On success, the number of bytes
 *                              that make up the key data.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 * \retval #PSA_ERROR_NOT_PERMITTED
 * \retval #PSA_ERROR_NOT_SUPPORTED
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_HARDWARE_FAILURE
 * \retval #PSA_ERROR_TAMPERING_DETECTED
 */
typedef psa_status_t (*psa_drv_se_export_key_t)(psa_key_slot_number_t key,
                                                uint8_t *p_data,
                                                size_t data_size,
                                                size_t *p_data_length);

/**
 * \brief A function that generates a symmetric or asymmetric key on a secure
 * element
 *
 * If \p type is asymmetric (`#PSA_KEY_TYPE_IS_ASYMMETRIC(\p type) == 1`),
 * the public component of the generated key will be placed in `p_pubkey_out`.
 * The format of the public key information will match the format specified for
 * the psa_export_key() function for the key type.
 *
 * \param[in] key_slot      Slot where the generated key will be placed
 * \param[in] type          The type of the key to be generated
 * \param[in] usage         The prescribed usage of the generated key
 *                          Note: Not all Secure Elements support the same
 *                          restrictions that PSA Crypto does (and vice versa).
 *                          Driver developers should endeavor to match the
 *                          usages as close as possible.
 * \param[in] bits          The size in bits of the key to be generated.
 * \param[in] extra         Extra parameters for key generation. The
 *                          interpretation of this parameter should match the
 *                          interpretation in the `extra` parameter is the
 *                          `psa_generate_key` function
 * \param[in] extra_size    The size in bytes of the \p extra buffer
 * \param[out] p_pubkey_out The buffer where the public key information will
 *                          be placed
 * \param[in] pubkey_out_size   The size in bytes of the `p_pubkey_out` buffer
 * \param[out] p_pubkey_length  Upon successful completion, will contain the
 *                              size of the data placed in `p_pubkey_out`.
 */
typedef psa_status_t (*psa_drv_se_generate_key_t)(psa_key_slot_number_t key_slot,
                                                  psa_key_type_t type,
                                                  psa_key_usage_t usage,
                                                  size_t bits,
                                                  const void *extra,
                                                  size_t extra_size,
                                                  uint8_t *p_pubkey_out,
                                                  size_t pubkey_out_size,
                                                  size_t *p_pubkey_length);

/**
 * \brief A struct containing all of the function pointers needed to for secure
 * element key management
 *
 * PSA Crypto API implementations should populate instances of the table as
 * appropriate upon startup or at build time.
 *
 * If one of the functions is not implemented, it should be set to NULL.
 */
typedef struct {
    /** Function that performs a key import operation */
    psa_drv_se_import_key_t     p_import;
    /** Function that performs a generation */
    psa_drv_se_generate_key_t   p_generate;
    /** Function that performs a key destroy operation */
    psa_drv_se_destroy_key_t    p_destroy;
    /** Function that performs a key export operation */
    psa_drv_se_export_key_t     p_export;
} psa_drv_se_key_management_t;

/**@}*/

/** \defgroup driver_derivation Secure Element Key Derivation and Agreement
 * Key derivation is the process of generating new key material using an
 * existing key and additional parameters, iterating through a basic
 * cryptographic function, such as a hash.
 * Key agreement is a part of cryptographic protocols that allows two parties
 * to agree on the same key value, but starting from different original key
 * material.
 * The flows are similar, and the PSA Crypto Driver Model uses the same functions
 * for both of the flows.
 *
 * There are two different final functions for the flows,
 * `psa_drv_se_key_derivation_derive` and `psa_drv_se_key_derivation_export`.
 * `psa_drv_se_key_derivation_derive` is used when the key material should be
 * placed in a slot on the hardware and not exposed to the caller.
 * `psa_drv_se_key_derivation_export` is used when the key material should be
 * returned to the PSA Cryptographic API implementation.
 *
 * Different key derivation algorithms require a different number of inputs.
 * Instead of having an API that takes as input variable length arrays, which
 * can be problemmatic to manage on embedded platforms, the inputs are passed
 * to the driver via a function, `psa_drv_se_key_derivation_collateral`, that
 * is called multiple times with different `collateral_id`s. Thus, for a key
 * derivation algorithm that required 3 paramter inputs, the flow would look
 * something like:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_se_key_derivation_setup(kdf_algorithm, source_key, dest_key_size_bytes);
 * psa_drv_se_key_derivation_collateral(kdf_algorithm_collateral_id_0,
 *                                      p_collateral_0,
 *                                      collateral_0_size);
 * psa_drv_se_key_derivation_collateral(kdf_algorithm_collateral_id_1,
 *                                      p_collateral_1,
 *                                      collateral_1_size);
 * psa_drv_se_key_derivation_collateral(kdf_algorithm_collateral_id_2,
 *                                      p_collateral_2,
 *                                      collateral_2_size);
 * psa_drv_se_key_derivation_derive();
 * ~~~~~~~~~~~~~
 *
 * key agreement example:
 * ~~~~~~~~~~~~~{.c}
 * psa_drv_se_key_derivation_setup(alg, source_key. dest_key_size_bytes);
 * psa_drv_se_key_derivation_collateral(DHE_PUBKEY, p_pubkey, pubkey_size);
 * psa_drv_se_key_derivation_export(p_session_key,
 *                                  session_key_size,
 *                                  &session_key_length);
 * ~~~~~~~~~~~~~
 */
/**@{*/

/** \brief A function that Sets up a secure element key derivation operation by
 * specifying the algorithm and the source key sot
 *
 * \param[in,out] p_context A hardware-specific structure containing any
 *                          context information for the implementation
 * \param[in] kdf_alg       The algorithm to be used for the key derivation
 * \param[in] souce_key     The key to be used as the source material for the
 *                          key derivation
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_se_key_derivation_setup_t)(void *p_context,
                                                          psa_algorithm_t kdf_alg,
                                                          psa_key_slot_number_t source_key);

/** \brief A function that provides collateral (parameters) needed for a secure
 * element key derivation or key agreement operation
 *
 * Since many key derivation algorithms require multiple parameters, it is
 * expeced that this function may be called multiple times for the same
 * operation, each with a different algorithm-specific `collateral_id`
 *
 * \param[in,out] p_context     A hardware-specific structure containing any
 *                              context information for the implementation
 * \param[in] collateral_id     An ID for the collateral being provided
 * \param[in] p_collateral      A buffer containing the collateral data
 * \param[in] collateral_size   The size in bytes of the collateral
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_se_key_derivation_collateral_t)(void *p_context,
                                                               uint32_t collateral_id,
                                                               const uint8_t *p_collateral,
                                                               size_t collateral_size);

/** \brief A function that performs the final secure element key derivation
 * step and place the generated key material in a slot
 *
 * \param[in,out] p_context     A hardware-specific structure containing any
 *                              context information for the implementation
 * \param[in] dest_key          The slot where the generated key material
 *                              should be placed
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_se_key_derivation_derive_t)(void *p_context,
                                                          psa_key_slot_number_t dest_key);

/** \brief A function that performs the final step of a secure element key
 * agreement and place the generated key material in a buffer
 *
 * \param[out] p_output         Buffer in which to place the generated key
 *                              material
 * \param[in] output_size       The size in bytes of `p_output`
 * \param[out] p_output_length  Upon success, contains the number of bytes of
 *                              key material placed in `p_output`
 *
 * \retval PSA_SUCCESS
 */
typedef psa_status_t (*psa_drv_se_key_derivation_export_t)(void *p_context,
                                                           uint8_t *p_output,
                                                           size_t output_size,
                                                           size_t *p_output_length);

/**
 * \brief A struct containing all of the function pointers needed to for secure
 * element key derivation and agreement
 *
 * PSA Crypto API implementations should populate instances of the table as
 * appropriate upon startup.
 *
 * If one of the functions is not implemented, it should be set to NULL.
 */
typedef struct {
    /** The driver-specific size of the key derivation context */
    size_t                           context_size;
    /** Function that performs a key derivation setup */
    psa_drv_se_key_derivation_setup_t      p_setup;
    /** Function that sets key derivation collateral */
    psa_drv_se_key_derivation_collateral_t p_collateral;
    /** Function that performs a final key derivation step */
    psa_drv_se_key_derivation_derive_t     p_derive;
    /** Function that perforsm a final key derivation or agreement and
     * exports the key */
    psa_drv_se_key_derivation_export_t     p_export;
} psa_drv_se_key_derivation_t;

/**@}*/

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_SE_DRIVER_H */
