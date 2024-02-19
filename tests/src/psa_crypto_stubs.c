/** \file psa_crypto_stubs.c
 *
 * \brief Stub functions when MBEDTLS_PSA_CRYPTO_CLIENT is enabled but
 *        MBEDTLS_PSA_CRYPTO_C is disabled.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <psa/crypto.h>

#if defined(MBEDTLS_PSA_CRYPTO_CLIENT) && !defined(MBEDTLS_PSA_CRYPTO_C)

psa_status_t psa_asymmetric_decrypt(mbedtls_svc_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *input,
                                    size_t input_length,
                                    const uint8_t *salt,
                                    size_t salt_length,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *output_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) salt;
    (void) salt_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_COMMUNICATION_FAILURE;
}

psa_status_t psa_asymmetric_encrypt(mbedtls_svc_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *input,
                                    size_t input_length,
                                    const uint8_t *salt,
                                    size_t salt_length,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *output_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) salt;
    (void) salt_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_COMMUNICATION_FAILURE;
}

psa_status_t psa_destroy_key(mbedtls_svc_key_id_t key)
{
    (void) key;
    return PSA_ERROR_COMMUNICATION_FAILURE;
}

psa_status_t psa_export_public_key(mbedtls_svc_key_id_t key,
                                   uint8_t *data,
                                   size_t data_size,
                                   size_t *data_length)
{
    (void) key;
    (void) data;
    (void) data_size;
    (void) data_length;
    return PSA_ERROR_COMMUNICATION_FAILURE;
}

psa_status_t psa_get_key_attributes(mbedtls_svc_key_id_t key,
                                    psa_key_attributes_t *attributes)
{
    (void) key;
    (void) attributes;
    return PSA_ERROR_COMMUNICATION_FAILURE;
}

psa_status_t psa_hash_abort(psa_hash_operation_t *operation)
{
    (void) operation;
    return PSA_ERROR_COMMUNICATION_FAILURE;
}

psa_status_t psa_hash_finish(psa_hash_operation_t *operation,
                             uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length)
{
    (void) operation;
    (void) hash;
    (void) hash_size;
    (void) hash_length;
    return PSA_ERROR_COMMUNICATION_FAILURE;
}

psa_status_t psa_hash_setup(psa_hash_operation_t *operation,
                            psa_algorithm_t alg)
{
    (void) operation;
    (void) alg;
    return PSA_ERROR_COMMUNICATION_FAILURE;
}

psa_status_t psa_hash_update(psa_hash_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length)
{
    (void) operation;
    (void) input;
    (void) input_length;
    return PSA_ERROR_COMMUNICATION_FAILURE;
}

psa_status_t psa_import_key(const psa_key_attributes_t *attributes,
                            const uint8_t *data,
                            size_t data_length,
                            mbedtls_svc_key_id_t *key)
{
    (void) attributes;
    (void) data;
    (void) data_length;
    (void) key;
    return PSA_ERROR_COMMUNICATION_FAILURE;
}

psa_status_t psa_sign_hash(mbedtls_svc_key_id_t key,
                           psa_algorithm_t alg,
                           const uint8_t *hash,
                           size_t hash_length,
                           uint8_t *signature,
                           size_t signature_size,
                           size_t *signature_length)
{
    (void) key;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;
    return PSA_ERROR_COMMUNICATION_FAILURE;
}

psa_status_t psa_verify_hash(mbedtls_svc_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t *hash,
                             size_t hash_length,
                             const uint8_t *signature,
                             size_t signature_length)
{
    (void) key;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_length;
    return PSA_ERROR_COMMUNICATION_FAILURE;
}

#endif /* MBEDTLS_PSA_CRYPTO_CLIENT !MBEDTLS_PSA_CRYPTO_C */
