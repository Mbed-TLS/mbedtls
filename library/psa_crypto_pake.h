/*
 *  PSA PAKE layer on top of Mbed TLS software crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
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

#ifndef PSA_CRYPTO_PAKE_H
#define PSA_CRYPTO_PAKE_H

#include <psa/crypto.h>

/** Set the session information for a password-authenticated key exchange.
 *
 * The sequence of operations to set up a password-authenticated key exchange
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Initialize the operation object with one of the methods described in the
 *    documentation for #psa_pake_operation_t, e.g.
 *    #PSA_PAKE_OPERATION_INIT.
 * -# Call psa_pake_setup() to specify the cipher suite.
 * -# Call \c psa_pake_set_xxx() functions on the operation to complete the
 *    setup. The exact sequence of \c psa_pake_set_xxx() functions that needs
 *    to be called depends on the algorithm in use.
 *
 * Refer to the documentation of individual PAKE algorithm types (`PSA_ALG_XXX`
 * values of type ::psa_algorithm_t such that #PSA_ALG_IS_PAKE(\c alg) is true)
 * for more information.
 *
 * A typical sequence of calls to perform a password-authenticated key
 * exchange:
 * -# Call psa_pake_output(operation, #PSA_PAKE_STEP_KEY_SHARE, ...) to get the
 *    key share that needs to be sent to the peer.
 * -# Call psa_pake_input(operation, #PSA_PAKE_STEP_KEY_SHARE, ...) to provide
 *    the key share that was received from the peer.
 * -# Depending on the algorithm additional calls to psa_pake_output() and
 *    psa_pake_input() might be necessary.
 * -# Call psa_pake_get_implicit_key() for accessing the shared secret.
 *
 * Refer to the documentation of individual PAKE algorithm types (`PSA_ALG_XXX`
 * values of type ::psa_algorithm_t such that #PSA_ALG_IS_PAKE(\c alg) is true)
 * for more information.
 *
 * If an error occurs at any step after a call to psa_pake_setup(),
 * the operation will need to be reset by a call to psa_pake_abort(). The
 * application may call psa_pake_abort() at any time after the operation
 * has been initialized.
 *
 * After a successful call to psa_pake_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A call to psa_pake_abort().
 * - A successful call to psa_pake_get_implicit_key().
 *
 * \param[in,out] operation     The operation object to set up. It must have
 *                              been initialized but not set up yet.
 * \param[in] cipher_suite      The cipher suite to use. (A cipher suite fully
 *                              characterizes a PAKE algorithm and determines
 *                              the algorithm as well.)
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The algorithm in \p cipher_suite is not a PAKE algorithm, or the
 *         PAKE primitive in \p cipher_suite is not compatible with the
 *         PAKE algorithm, or the hash algorithm in \p cipher_suite is invalid
 *         or not compatible with the PAKE algorithm and primitive.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The algorithm in \p cipher_suite is not a supported PAKE algorithm,
 *         or the PAKE primitive in \p cipher_suite is not supported or not
 *         compatible with the PAKE algorithm, or the hash algorithm in
 *         \p cipher_suite is not supported or not compatible with the PAKE
 *         algorithm and primitive.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid, or
 *         the library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t mbedtls_psa_pake_setup(mbedtls_psa_pake_operation_t *operation,
                                    const psa_pake_cipher_suite_t *cipher_suite);

/** Set the password for a password-authenticated key exchange from key ID.
 *
 * Call this function when the password, or a value derived from the password,
 * is already present in the key store.
 * \param[in] attributes        The attributes of the key to use for the
 *                              operation.
 * \param[in,out] operation     The operation object to set the password for. It
 *                              must have been set up by psa_pake_setup() and
 *                              not yet in use (neither psa_pake_output() nor
 *                              psa_pake_input() has been called yet). It must
 *                              be on operation for which the password hasn't
 *                              been set yet (psa_pake_set_password_key()
 *                              hasn't been called yet).
 * \param password              Buffer holding the password
 * \param password_len          Password buffer size
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_HANDLE
 *         \p password is not a valid key identifier.
 * \retval #PSA_ERROR_NOT_PERMITTED
 *         The key does not have the #PSA_KEY_USAGE_DERIVE flag, or it does not
 *         permit the \p operation's algorithm.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key type for \p password is not #PSA_KEY_TYPE_PASSWORD or
 *         #PSA_KEY_TYPE_PASSWORD_HASH, or \p password is not compatible with
 *         the \p operation's cipher suite.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The key type or key size of \p password is not supported with the
 *         \p operation's cipher suite.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 * \retval #PSA_ERROR_STORAGE_FAILURE
 * \retval #PSA_ERROR_DATA_CORRUPT
 * \retval #PSA_ERROR_DATA_INVALID
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must have been set up.), or
 *         the library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t mbedtls_psa_pake_set_password_key(
    const psa_key_attributes_t *attributes,
    mbedtls_psa_pake_operation_t *operation,
    uint8_t *password,
    size_t password_len);

/** Set the user ID for a password-authenticated key exchange.
 *
 * Call this function to set the user ID. For PAKE algorithms that associate a
 * user identifier with each side of the session you need to call
 * psa_pake_set_peer() as well. For PAKE algorithms that associate a single
 * user identifier with the session, call psa_pake_set_user() only.
 *
 * Refer to the documentation of individual PAKE algorithm types (`PSA_ALG_XXX`
 * values of type ::psa_algorithm_t such that #PSA_ALG_IS_PAKE(\c alg) is true)
 * for more information.
 *
 * \param[in,out] operation     The operation object to set the user ID for. It
 *                              must have been set up by psa_pake_setup() and
 *                              not yet in use (neither psa_pake_output() nor
 *                              psa_pake_input() has been called yet). It must
 *                              be on operation for which the user ID hasn't
 *                              been set (psa_pake_set_user() hasn't been
 *                              called yet).
 * \param[in] user_id           The user ID to authenticate with.
 * \param user_id_len           Size of the \p user_id buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p user_id is not valid for the \p operation's algorithm and cipher
 *         suite.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The value of \p user_id is not supported by the implementation.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid, or
 *         the library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t mbedtls_psa_pake_set_user(mbedtls_psa_pake_operation_t *operation,
                                       const uint8_t *user_id,
                                       size_t user_id_len);

/** Set the peer ID for a password-authenticated key exchange.
 *
 * Call this function in addition to psa_pake_set_user() for PAKE algorithms
 * that associate a user identifier with each side of the session. For PAKE
 * algorithms that associate a single user identifier with the session, call
 * psa_pake_set_user() only.
 *
 * Refer to the documentation of individual PAKE algorithm types (`PSA_ALG_XXX`
 * values of type ::psa_algorithm_t such that #PSA_ALG_IS_PAKE(\c alg) is true)
 * for more information.
 *
 * \param[in,out] operation     The operation object to set the peer ID for. It
 *                              must have been set up by psa_pake_setup() and
 *                              not yet in use (neither psa_pake_output() nor
 *                              psa_pake_input() has been called yet). It must
 *                              be on operation for which the peer ID hasn't
 *                              been set (psa_pake_set_peer() hasn't been
 *                              called yet).
 * \param[in] peer_id           The peer's ID to authenticate.
 * \param peer_id_len           Size of the \p peer_id buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p user_id is not valid for the \p operation's algorithm and cipher
 *         suite.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The algorithm doesn't associate a second identity with the session.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         Calling psa_pake_set_peer() is invalid with the \p operation's
 *         algorithm, the operation state is not valid, or the library has not
 *         been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t mbedtls_psa_pake_set_peer(mbedtls_psa_pake_operation_t *operation,
                                       const uint8_t *peer_id,
                                       size_t peer_id_len);

/** Set the application role for a password-authenticated key exchange.
 *
 * Not all PAKE algorithms need to differentiate the communicating entities.
 * It is optional to call this function for PAKEs that don't require a role
 * to be specified. For such PAKEs the application role parameter is ignored,
 * or #PSA_PAKE_ROLE_NONE can be passed as \c role.
 *
 * Refer to the documentation of individual PAKE algorithm types (`PSA_ALG_XXX`
 * values of type ::psa_algorithm_t such that #PSA_ALG_IS_PAKE(\c alg) is true)
 * for more information.
 *
 * \param[in,out] operation     The operation object to specify the
 *                              application's role for. It must have been set up
 *                              by psa_pake_setup() and not yet in use (neither
 *                              psa_pake_output() nor psa_pake_input() has been
 *                              called yet). It must be on operation for which
 *                              the application's role hasn't been specified
 *                              (psa_pake_set_role() hasn't been called yet).
 * \param role                  A value of type ::psa_pake_role_t indicating the
 *                              application's role in the PAKE the algorithm
 *                              that is being set up. For more information see
 *                              the documentation of \c PSA_PAKE_ROLE_XXX
 *                              constants.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The \p role is not a valid PAKE role in the \p operation’s algorithm.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The \p role for this algorithm is not supported or is not valid.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid, or
 *         the library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t mbedtls_psa_pake_set_role(mbedtls_psa_pake_operation_t *operation,
                                       psa_pake_role_t role);

/** Get output for a step of a password-authenticated key exchange.
 *
 * Depending on the algorithm being executed, you might need to call this
 * function several times or you might not need to call this at all.
 *
 * The exact sequence of calls to perform a password-authenticated key
 * exchange depends on the algorithm in use.  Refer to the documentation of
 * individual PAKE algorithm types (`PSA_ALG_XXX` values of type
 * ::psa_algorithm_t such that #PSA_ALG_IS_PAKE(\c alg) is true) for more
 * information.
 *
 * If this function returns an error status, the operation enters an error
 * state and must be aborted by calling psa_pake_abort().
 *
 * \param[in,out] operation    Active PAKE operation.
 * \param step                 The step of the algorithm for which the output is
 *                             requested.
 * \param[out] output          Buffer where the output is to be written in the
 *                             format appropriate for this \p step. Refer to
 *                             the documentation of the individual
 *                             \c PSA_PAKE_STEP_XXX constants for more
 *                             information.
 * \param output_size          Size of the \p output buffer in bytes. This must
 *                             be at least #PSA_PAKE_OUTPUT_SIZE(\p alg, \p
 *                             primitive, \p step) where \p alg and
 *                             \p primitive are the PAKE algorithm and primitive
 *                             in the operation's cipher suite, and \p step is
 *                             the output step.
 *
 * \param[out] output_length   On success, the number of bytes of the returned
 *                             output.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p output buffer is too small.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p step is not compatible with the operation's algorithm.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p step is not supported with the operation's algorithm.
 * \retval #PSA_ERROR_INSUFFICIENT_ENTROPY
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 * \retval #PSA_ERROR_STORAGE_FAILURE
 * \retval #PSA_ERROR_DATA_CORRUPT
 * \retval #PSA_ERROR_DATA_INVALID
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be active, and fully set
 *         up, and this call must conform to the algorithm's requirements
 *         for ordering of input and output steps), or
 *         the library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t mbedtls_psa_pake_output(mbedtls_psa_pake_operation_t *operation,
                                     psa_pake_step_t step,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_length);

/** Provide input for a step of a password-authenticated key exchange.
 *
 * Depending on the algorithm being executed, you might need to call this
 * function several times or you might not need to call this at all.
 *
 * The exact sequence of calls to perform a password-authenticated key
 * exchange depends on the algorithm in use.  Refer to the documentation of
 * individual PAKE algorithm types (`PSA_ALG_XXX` values of type
 * ::psa_algorithm_t such that #PSA_ALG_IS_PAKE(\c alg) is true) for more
 * information.
 *
 * If this function returns an error status, the operation enters an error
 * state and must be aborted by calling psa_pake_abort().
 *
 * \param[in,out] operation    Active PAKE operation.
 * \param step                 The step for which the input is provided.
 * \param[in] input            Buffer containing the input in the format
 *                             appropriate for this \p step. Refer to the
 *                             documentation of the individual
 *                             \c PSA_PAKE_STEP_XXX constants for more
 *                             information.
 * \param input_length         Size of the \p input buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The verification fails for a #PSA_PAKE_STEP_ZK_PROOF input step.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p is not compatible with the \p operation’s algorithm, or the
 *         \p input is not valid for the \p operation's algorithm, cipher suite
 *         or \p step.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p step p is not supported with the \p operation's algorithm, or the
 *         \p input is not supported for the \p operation's algorithm, cipher
 *         suite or \p step.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 * \retval #PSA_ERROR_STORAGE_FAILURE
 * \retval #PSA_ERROR_DATA_CORRUPT
 * \retval #PSA_ERROR_DATA_INVALID
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be active, and fully set
 *         up, and this call must conform to the algorithm's requirements
 *         for ordering of input and output steps), or
 *         the library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t mbedtls_psa_pake_input(mbedtls_psa_pake_operation_t *operation,
                                    psa_pake_step_t step,
                                    const uint8_t *input,
                                    size_t input_length);

/** Get implicitly confirmed shared secret from a PAKE.
 *
 * At this point there is a cryptographic guarantee that only the authenticated
 * party who used the same password is able to compute the key. But there is no
 * guarantee that the peer is the party it claims to be and was able to do so.
 *
 * That is, the authentication is only implicit. Since the peer is not
 * authenticated yet, no action should be taken yet that assumes that the peer
 * is who it claims to be. For example, do not access restricted files on the
 * peer's behalf until an explicit authentication has succeeded.
 *
 * This function can be called after the key exchange phase of the operation
 * has completed. It imports the shared secret output of the PAKE into the
 * provided derivation operation. The input step
 * #PSA_KEY_DERIVATION_INPUT_SECRET is used when placing the shared key
 * material in the key derivation operation.
 *
 * The exact sequence of calls to perform a password-authenticated key
 * exchange depends on the algorithm in use.  Refer to the documentation of
 * individual PAKE algorithm types (`PSA_ALG_XXX` values of type
 * ::psa_algorithm_t such that #PSA_ALG_IS_PAKE(\c alg) is true) for more
 * information.
 *
 * When this function returns successfully, \p operation becomes inactive.
 * If this function returns an error status, both \p operation
 * and \p key_derivation operations enter an error state and must be aborted by
 * calling psa_pake_abort() and psa_key_derivation_abort() respectively.
 *
 * \param[in,out] operation    Active PAKE operation.
 * \param[out] output          A key derivation operation that is ready
 *                             for an input step of type
 *                             #PSA_KEY_DERIVATION_INPUT_SECRET.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         #PSA_KEY_DERIVATION_INPUT_SECRET is not compatible with the
 *         algorithm in the \p output key derivation operation.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         Input from a PAKE is not supported by the algorithm in the \p output
 *         key derivation operation.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 * \retval #PSA_ERROR_STORAGE_FAILURE
 * \retval #PSA_ERROR_DATA_CORRUPT
 * \retval #PSA_ERROR_DATA_INVALID
 * \retval #PSA_ERROR_BAD_STATE
 *         The PAKE operation state is not valid (it must be active, but beyond
 *         that validity is specific to the algorithm), or
 *         the library has not been previously initialized by psa_crypto_init(),
 *         or the state of \p output is not valid for
 *         the #PSA_KEY_DERIVATION_INPUT_SECRET step. This can happen if the
 *         step is out of order or the application has done this step already
 *         and it may not be repeated.
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t mbedtls_psa_pake_get_implicit_key(
    mbedtls_psa_pake_operation_t *operation,
    psa_key_derivation_operation_t *output);

/** Abort a PAKE operation.
 *
 * Aborting an operation frees all associated resources except for the \c
 * operation structure itself. Once aborted, the operation object can be reused
 * for another operation by calling psa_pake_setup() again.
 *
 * This function may be called at any time after the operation
 * object has been initialized as described in #psa_pake_operation_t.
 *
 * In particular, calling psa_pake_abort() after the operation has been
 * terminated by a call to psa_pake_abort() or psa_pake_get_implicit_key()
 * is safe and has no effect.
 *
 * \param[in,out] operation    The operation to abort.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_COMMUNICATION_FAILURE
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 * \retval #PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t mbedtls_psa_pake_abort(mbedtls_psa_pake_operation_t *operation);

#endif /* PSA_CRYPTO_PAKE_H */
