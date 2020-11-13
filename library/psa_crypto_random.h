/** \file psa_crypto_random.h
 *
 * \brief PSA crypto random generator abstraction.
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

#ifndef PSA_CRYPTO_RANDOM_H
#define PSA_CRYPTO_RANDOM_H

#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

#include <string.h>
#include <mbedtls/entropy.h> // only for error codes
#include <psa/crypto.h>

typedef mbedtls_psa_external_random_context_t mbedtls_psa_random_context_t;

static inline int mbedtls_psa_get_random( void *p_rng,
                                          unsigned char *output,
                                          size_t output_size )
{
    (void) p_rng;
    psa_status_t status = psa_generate_random( output, output_size );
    if( status == PSA_SUCCESS )
        return( 0 );
    else
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
}

static inline void *mbedtls_psa_random_state( mbedtls_psa_random_context_t *rng )
{
    (void) rng;
    return( NULL );
}

#else /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

/* Currently, the only supported RNG is Mbed TLS's CTR_DRBG seeded with
 * mbedtls_entropy_func(). */

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

/** The type of the PSA DRBG context.
 */
typedef mbedtls_ctr_drbg_context mbedtls_psa_drbg_context_t;

/** Initialize the PSA DRBG.
 *
 * \param p_rng        Pointer to the Mbed TLS DRBG state.
 */
static inline void mbedtls_psa_drbg_init( mbedtls_psa_drbg_context_t *p_rng )
{
    mbedtls_ctr_drbg_init( p_rng );
}

/** Deinitialize the PSA DRBG.
 *
 * \param p_rng        Pointer to the Mbed TLS DRBG state.
 */
static inline void mbedtls_psa_drbg_free( mbedtls_psa_drbg_context_t *p_rng )
{
    mbedtls_ctr_drbg_free( p_rng );
}

/** The type of the PSA random generator context.
 *
 * The random generator context is composed of an entropy context and
 * a DRBG context.
 */
typedef struct
{
    void (* entropy_init )( mbedtls_entropy_context *ctx );
    void (* entropy_free )( mbedtls_entropy_context *ctx );
    mbedtls_entropy_context entropy;
    mbedtls_psa_drbg_context_t drbg;
} mbedtls_psa_random_context_t;

/** Return random data.
 *
 * This function is suitable as the \p f_rng parameter to Mbed TLS functions
 * that require a random generator. Use mbedtls_psa_random_state() to
 * obtain the \p p_rng parameter.
 *
 * \param p_rng         The CTR_DRBG context. This must be
 *                      mbedtls_psa_random_state( \c rng )
 *                      where \c rng is a pointer to a
 *                      ::mbedtls_psa_random_context_t structure.
 * \param output        The buffer to fill.
 * \param output_len    The length of the buffer in bytes.
 *                      It must be at most #MBEDTLS_PSA_RANDOM_MAX_REQUEST.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED or
 *                      #MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG on failure.
 */
static inline int mbedtls_psa_get_random( void *p_rng,
                                          unsigned char *output,
                                          size_t output_len )
{
    return( mbedtls_ctr_drbg_random( p_rng, output, output_len ) );
}

/** The maximum number of bytes that mbedtls_psa_get_random() is expected to
 * return.
 */
#define MBEDTLS_PSA_RANDOM_MAX_REQUEST MBEDTLS_CTR_DRBG_MAX_REQUEST

/** Retrieve the DRBG state from the PSA RNG state.
 *
 * \param rng           Pointer to the PSA random generator state.
 *
 * \return              The DRBG state (\c p_rng argument ).
 */
static inline mbedtls_psa_drbg_context_t *mbedtls_psa_random_state(
    mbedtls_psa_random_context_t *rng )
{
    return( &rng->drbg );
}


/** Seed the PSA DRBG.
 *
 * \param rng           DRBG context to be seeded.
 * \param custom        The personalization string.
 *                      This can be \c NULL, in which case the personalization
 *                      string is empty regardless of the value of \p len.
 * \param len           The length of the personalization string.
 *
 * \return              \c 0 on success.
 * \return              An Mbed TLS error code (\c MBEDTLS_ERR_xxx) on failure.
 */
static inline int mbedtls_psa_drbg_seed(
    mbedtls_psa_random_context_t *rng,
    const unsigned char *custom, size_t len )
{
    return( mbedtls_ctr_drbg_seed( mbedtls_psa_random_state( rng ),
                                   mbedtls_entropy_func,
                                   &rng->entropy,
                                   custom, len ) );
}

#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

#endif /* PSA_CRYPTO_RANDOM_H */
