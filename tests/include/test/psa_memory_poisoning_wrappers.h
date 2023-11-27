#include "psa/crypto.h"

#include "test/memory.h"

psa_status_t wrap_psa_cipher_encrypt(mbedtls_svc_key_id_t key,
                                     psa_algorithm_t alg,
                                     const uint8_t *input,
                                     size_t input_length,
                                     uint8_t *output,
                                     size_t output_size,
                                     size_t *output_length)
{
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
    return status;
}

#define psa_cipher_encrypt(...) wrap_psa_cipher_encrypt(__VA_ARGS__)
