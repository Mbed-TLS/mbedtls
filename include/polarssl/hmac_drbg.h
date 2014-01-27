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

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Simplified HMAC_DRBG context.
 * No reseed counter, no prediction resistance flag.
 */
typedef struct
{
    md_context_t md_ctx;
    unsigned char V[POLARSSL_MD_MAX_SIZE];
    unsigned char K[POLARSSL_MD_MAX_SIZE];
} hmac_drbg_context;

/**
 * \brief               HMAC_DRBG initialisation
 *
 * \param ctx           HMAC_DRBG context to be initialised
 * \param md_info       MD algorithm to use for HMAC_DRBG
 * \param data          Concatenation of entropy string and additional data
 * \param data_len      Length of data in bytes
 *
 * \todo                Use entropy callback rather than buffer.
 *
 * \return              0 if successful, or
 *                      POLARSSL_ERR_MD_BAD_INPUT_DATA, or
 *                      POLARSSL_ERR_MD_ALLOC_FAILED
 */
int hmac_drbg_init( hmac_drbg_context *ctx,
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
 * \brief               HMAC_DRBG generate random
 *
 * Note: Automatically reseeds if reseed_counter is reached. (TODO)
 *
 * \param p_rng         HMAC_DRBG context
 * \param output        Buffer to fill
 * \param output_len    Length of the buffer
 *
 * \return              0 if successful.
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
