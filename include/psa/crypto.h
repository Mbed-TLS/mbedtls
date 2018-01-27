/**
 * \file psa/crypto.h
 * \brief Platform Security Architecture cryptography module
 */

#ifndef PSA_CRYPTO_H
#define PSA_CRYPTO_H

#include "crypto_platform.h"

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
    /** A hardware failure was detected. */
    PSA_ERROR_HARDWARE_FAILURE,
    /** A tampering attempt was detected. */
    PSA_ERROR_TAMPERING_DETECTED,
    /** There is not enough entropy to generate random data needed
        for the requested action. */
    PSA_ERROR_INSUFFICIENT_ENTROPY,
    /** The signature or MAC is incorrect. */
    PSA_ERROR_INVALID_SIGNATURE,
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

/**@}*/

#ifdef __cplusplus
}
#endif

#include "crypto_extra.h"

#endif /* PSA_CRYPTO_H */
