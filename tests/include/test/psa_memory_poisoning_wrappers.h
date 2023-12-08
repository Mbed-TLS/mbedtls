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

#include "psa/crypto.h"

#include "test/memory.h"

#include "psa_crypto_invasive.h"

#if defined(MBEDTLS_TEST_MEMORY_CAN_POISON)

static void setup_test_hooks(void)
{
    psa_input_pre_copy_hook = mbedtls_test_memory_unpoison;
    psa_input_post_copy_hook = mbedtls_test_memory_poison;
    psa_output_pre_copy_hook = mbedtls_test_memory_unpoison;
    psa_output_post_copy_hook = mbedtls_test_memory_poison;
}

static void teardown_test_hooks(void)
{
    psa_input_pre_copy_hook = NULL;
    psa_input_post_copy_hook = NULL;
    psa_output_pre_copy_hook = NULL;
    psa_output_post_copy_hook = NULL;
}

psa_status_t wrap_psa_cipher_encrypt(mbedtls_svc_key_id_t key,
                                     psa_algorithm_t alg,
                                     const uint8_t *input,
                                     size_t input_length,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_length)
{
    setup_test_hooks();
    MBEDTLS_TEST_MEMORY_POISON(input, input_length);
    MBEDTLS_TEST_MEMORY_POISON(output, output_size);
    psa_status_t status = psa_cipher_encrypt(key,
                                             alg,
                                             input,
                                             input_length,
                                             output,
                                             output_size,
                                             output_length);
    MBEDTLS_TEST_MEMORY_UNPOISON(input, input_length);
    MBEDTLS_TEST_MEMORY_UNPOISON(output, output_size);
    teardown_test_hooks();
    return status;
}

#define psa_cipher_encrypt(...) wrap_psa_cipher_encrypt(__VA_ARGS__)

#endif /* MBEDTLS_TEST_MEMORY_CAN_POISON */
