/*
 *  PSA crypto random generator.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C) && !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

#include "psa_crypto_core.h"
#include "psa_crypto_random.h"
#include "psa_crypto_random_impl.h"

#if defined(MBEDTLS_PSA_INJECT_ENTROPY)
#include "entropy_poll.h"
#endif

void psa_random_internal_init(mbedtls_psa_random_context_t *rng)
{
    /* Set default configuration if
     * mbedtls_psa_crypto_configure_entropy_sources() hasn't been called. */
    if (rng->entropy_init == NULL) {
        rng->entropy_init = mbedtls_entropy_init;
    }
    if (rng->entropy_free == NULL) {
        rng->entropy_free = mbedtls_entropy_free;
    }

    rng->entropy_init(&rng->entropy);
#if defined(MBEDTLS_PSA_INJECT_ENTROPY) && \
    defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES)
    /* The PSA entropy injection feature depends on using NV seed as an entropy
     * source. Add NV seed as an entropy source for PSA entropy injection. */
    mbedtls_entropy_add_source(&rng->entropy,
                               mbedtls_nv_seed_poll, NULL,
                               MBEDTLS_ENTROPY_BLOCK_SIZE,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);
#endif

    mbedtls_psa_drbg_init(&rng->drbg);
}

void psa_random_internal_free(mbedtls_psa_random_context_t *rng)
{
    mbedtls_psa_drbg_free(&rng->drbg);
    rng->entropy_free(&rng->entropy);
}
psa_status_t psa_random_internal_seed(mbedtls_psa_random_context_t *rng)
{
    const unsigned char drbg_seed[] = "PSA";
    int ret = mbedtls_psa_drbg_seed(&rng->drbg, &rng->entropy,
                                    drbg_seed, sizeof(drbg_seed) - 1);
    return mbedtls_to_psa_error(ret);
}

psa_status_t psa_random_internal_generate(
    mbedtls_psa_random_context_t *rng,
    uint8_t *output, size_t output_size)
{
    while (output_size > 0) {
        size_t request_size =
            (output_size > MBEDTLS_PSA_RANDOM_MAX_REQUEST ?
             MBEDTLS_PSA_RANDOM_MAX_REQUEST :
             output_size);
#if defined(MBEDTLS_CTR_DRBG_C)
        int ret = mbedtls_ctr_drbg_random(&rng->drbg, output, request_size);
#elif defined(MBEDTLS_HMAC_DRBG_C)
        int ret = mbedtls_hmac_drbg_random(&rng->drbg, output, request_size);
#endif /* !MBEDTLS_CTR_DRBG_C && !MBEDTLS_HMAC_DRBG_C */
        if (ret != 0) {
            return mbedtls_to_psa_error(ret);
        }
        output_size -= request_size;
        output += request_size;
    }
    return PSA_SUCCESS;
}

#endif /* MBEDTLS_PSA_CRYPTO_C && !MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */
