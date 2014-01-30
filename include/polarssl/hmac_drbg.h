/**
 * \file hmac_drbg.h
 *
 * \brief HMAC_DRBG (NIST SP 800-90A)
 *
 *  Copyright (C) 2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_HMAC_DRBG_H
#define POLARSSL_HMAC_DRBG_H

#include "md.h"

/*
 * ! Same values as ctr_drbg.h !
 */
#define POLARSSL_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED        -0x0034  /**< The entropy source failed. */
#define POLARSSL_ERR_HMAC_DRBG_REQUEST_TOO_BIG              -0x0036  /**< Too many random requested in single call. */
#define POLARSSL_ERR_HMAC_DRBG_INPUT_TOO_BIG                -0x0038  /**< Input too large (Entropy + additional). */
#define POLARSSL_ERR_HMAC_DRBG_FILE_IO_ERROR                -0x003A  /**< Read/write error in file. */

#define HMAC_DRBG_RESEED_INTERVAL   10000   /**< Interval before reseed is performed by default */
#define HMAC_DRBG_MAX_INPUT         256     /**< Maximum number of additional input bytes */
#define HMAC_DRBG_MAX_REQUEST       1024    /**< Maximum number of requested bytes per call */
#define HMAC_DRBG_MAX_SEED_INPUT    384     /**< Maximum size of (re)seed buffer */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HMAC_DRBG context.
 * TODO: reseed counter, prediction resistance flag.
 */
typedef struct
{
    md_context_t md_ctx;
    unsigned char V[POLARSSL_MD_MAX_SIZE];
    unsigned char K[POLARSSL_MD_MAX_SIZE];

    size_t entropy_len;         /*!< entropy bytes grabbed on each (re)seed */

    /*
     * Callbacks (Entropy)
     */
    int (*f_entropy)(void *, unsigned char *, size_t);
    void *p_entropy;            /*!< context for the entropy function */
} hmac_drbg_context;

/**
 * \brief               HMAC_DRBG initialisation
 *
 * \param ctx           HMAC_DRBG context to be initialised
 * \param md_info       MD algorithm to use for HMAC_DRBG
 * \param f_entropy     Entropy callback (p_entropy, buffer to fill, buffer
 *                      length)
 * \param p_entropy     Entropy context
 * \param custom        Personalization data (Device specific identifiers)
 *                      (Can be NULL)
 * \param len           Length of personalization data
 *
 * \note                The "security strength" as defined by NIST is set to:
 *                      128 bits if md_alg is SHA-1,
 *                      192 bits if md_alg is SHA-224,
 *                      256 bits if md_alg is SHA-256 or higher.
 *                      Note that SHA-256 is just as efficient as SHA-224.
 *
 * \return              0 if successful, or
 *                      POLARSSL_ERR_MD_BAD_INPUT_DATA, or
 *                      POLARSSL_ERR_MD_ALLOC_FAILED, or
 *                      POLARSSL_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED.
 */
int hmac_drbg_init( hmac_drbg_context *ctx,
                    const md_info_t * md_info,
                    int (*f_entropy)(void *, unsigned char *, size_t),
                    void *p_entropy,
                    const unsigned char *custom,
                    size_t len );

/**
 * \brief               Simplified HMAC_DRBG initialisation.
 *                      (For use with deterministic ECDSA.)
 *
 * \param ctx           HMAC_DRBG context to be initialised
 * \param md_info       MD algorithm to use for HMAC_DRBG
 * \param data          Concatenation of entropy string and additional data
 * \param data_len      Length of data in bytes
 *
 * \return              0 if successful, or
 *                      POLARSSL_ERR_MD_BAD_INPUT_DATA, or
 *                      POLARSSL_ERR_MD_ALLOC_FAILED.
 */
int hmac_drbg_init_buf( hmac_drbg_context *ctx,
                        const md_info_t * md_info,
                        const unsigned char *data, size_t data_len );

/**
 * \brief               HMAC_DRBG update state
 *
 * \param ctx           HMAC_DRBG context
 * \param additional    Additional data to update state with, or NULL
 * \param add_len       Length of additional data, or 0
 *
 * \note                Additional data is optional, pass NULL and 0 as second
 *                      third argument if no additional data is being used.
 */
void hmac_drbg_update( hmac_drbg_context *ctx,
                       const unsigned char *additional, size_t add_len );

/**
 * \brief               HMAC_DRBG generate random with additional update input
 *
 * Note: Automatically reseeds if reseed_counter is reached.
 *
 * \param p_rng         HMAC_DRBG context
 * \param output        Buffer to fill
 * \param output_len    Length of the buffer
 * \param additional    Additional data to update with (can be NULL)
 * \param add_len       Length of additional data (can be 0)
 *
 * \return              0 if successful, or
 *                      TODO: POLARSSL_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED, or
 *                      TODO: POLARSSL_ERR_HMAC_DRBG_REQUEST_TOO_BIG
 */
int hmac_drbg_random_with_add( void *p_rng,
                               unsigned char *output, size_t output_len,
                               const unsigned char *additional,
                               size_t add_len );

/**
 * \brief               HMAC_DRBG generate random
 *
 * Note: Automatically reseeds if reseed_counter is reached.
 *
 * \param p_rng         HMAC_DRBG context
 * \param output        Buffer to fill
 * \param output_len    Length of the buffer
 *
 * \return              0 if successful, or
 *                      TODO: POLARSSL_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED, or
 *                      TODO: POLARSSL_ERR_HMAC_DRBG_REQUEST_TOO_BIG
 */
int hmac_drbg_random( void *p_rng, unsigned char *output, size_t out_len );

/**
 * \brief               Free an HMAC_DRBG context
 *
 * \param ctx           HMAC_DRBG context to free.
 */
void hmac_drbg_free( hmac_drbg_context *ctx );


#if defined(POLARSSL_SELF_TEST)
/**
 * \brief               Checkup routine
 *
 * \return              0 if successful, or 1 if the test failed
 */
int hmac_drbg_self_test( int verbose );
#endif

#ifdef __cplusplus
}
#endif

#endif /* hmac_drbg.h */
