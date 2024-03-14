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

psa_status_t psa_generate_random(uint8_t *output,
                                 size_t output_size)
{
    (void) output;
    (void) output_size;

    return PSA_ERROR_COMMUNICATION_FAILURE;
}

#endif /* MBEDTLS_PSA_CRYPTO_CLIENT && !MBEDTLS_PSA_CRYPTO_C */
