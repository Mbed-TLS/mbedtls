/** Memory poisoning wrappers for PSA functions.
 *
 *  These wrappers poison the input and output buffers of each function
 *  before calling it, to ensure that it does not access the buffers
 *  except by calling the approved buffer-copying functions.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_MEMORY_POISONING_WRAPPERS_H
#define PSA_MEMORY_POISONING_WRAPPERS_H

#include "psa/crypto.h"

#include "test/memory.h"

#if defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_TEST_MEMORY_CAN_POISON)

/**
 * \brief         Setup the memory poisoning test hooks used by
 *                psa_crypto_copy_input() and psa_crypto_copy_output() for
 *                memory poisoning.
 */
void mbedtls_poison_test_hooks_setup(void);

/**
 * \brief         Teardown the memory poisoning test hooks used by
 *                psa_crypto_copy_input() and psa_crypto_copy_output() for
 *                memory poisoning.
 */
void mbedtls_poison_test_hooks_teardown(void);

psa_status_t wrap_psa_cipher_encrypt(mbedtls_svc_key_id_t key,
                                     psa_algorithm_t alg,
                                     const uint8_t *input,
                                     size_t input_length,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_length);

#define psa_cipher_encrypt(...) wrap_psa_cipher_encrypt(__VA_ARGS__)

#endif /* MBEDTLS_TEST_HOOKS && MBEDTLS_TEST_MEMORY_CAN_POISON */

#endif /* PSA_MEMORY_POISONING_WRAPPERS_H */