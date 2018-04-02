/**
 * \file keccak_sponge.h
 *
 * \brief The sponge cryptographic construction built on the Keccak-f[1600]
 *        permutation.
 *
 * Reference: National Institute of Standards and Technology (NIST).
 * _SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions._
 * FIPS PUB 202. August 2015.
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 *
 * \author Daniel King <damaki.gh@gmail.com>
 */
/*  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_KECCAK_SPONGE_H
#define MBEDTLS_KECCAK_SPONGE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "keccakf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA -0x001B /**< Bad input parameters to function. */
#define MBEDTLS_ERR_KECCAK_SPONGE_NOT_SETUP      -0x001D /**< mbedtls_keccak_sponge_starts has not been called. */
#define MBEDTLS_ERR_KECCAK_SPONGE_BAD_STATE      -0x001F /**< The requested operation cannot be performed with the current context state. */

#if !defined(MBEDTLS_KECCAK_SPONGE_ALT)

typedef struct
{
    mbedtls_keccakf_context keccakf_ctx;
    unsigned char queue[1600 / 8]; /* store partial block data (absorbing) or pending output data (squeezing) */
    size_t queue_len;              /* queue length (in bits) */
    size_t rate;                   /* sponge rate (in bits) */
    size_t suffix_len;             /* length of the suffix (in bits) (range 0..8) */
    int state;                     /* Current state (absorbing/ready to squeeze/squeezing) */
    unsigned char suffix;          /* suffix bits appended to message, before padding */
}
mbedtls_keccak_sponge_context;

#else /* MBEDTLS_KECCAK_SPONGE_ALT */
#include "keccak_sponge_alt.h"
#endif /* MBEDTLS_KECCAK_SPONGE_ALT */

/**
 * \brief               Initialize a Keccak sponge context.
 *
 * \param ctx           The context to initialize.
 */
void mbedtls_keccak_sponge_init( mbedtls_keccak_sponge_context *ctx );

/**
 * \brief               Clean a Keccak sponge context.
 *
 * \param ctx           The context to clean.
 */
void mbedtls_keccak_sponge_free( mbedtls_keccak_sponge_context *ctx );

/**
 * \brief               Clone (the state of) a Keccak Sponge context.
 *
 * \param dst           The destination context.
 * \param src           The context to clone.
 */
void mbedtls_keccak_sponge_clone( mbedtls_keccak_sponge_context *dst,
                                  const mbedtls_keccak_sponge_context *src );

/**
 * \brief               Comfigure the sponge context to start streaming.
 *
 * \note                You must call mbedtls_keccak_sponge_init() before
 *                      calling this function, and you may no longer call
 *                      it after calling mbedtls_keccak_sponge_absorb() or
 *                      mbedtls_keccak_sponge_squeeze().
 *
 * \note                This function \b MUST be called after calling
 *                      mbedtls_keccak_sponge_init() and before calling the
 *                      absorb or squeeze functions. If this function has not
 *                      been called then the absorb/squeeze functions will
 *                      return #MBEDTLS_ERR_KECCAK_SPONGE_NOT_SETUP.
 *
 * \param ctx           The sponge context to set up.
 * \param capacity      The sponge's capacity parameter. This determines the
 *                      security of the sponge. The capacity should be double
 *                      the required security (in bits). For example, if 128 bits
 *                      of security are required then \p capacity should be set
 *                      to 256. This must be a multiple of 8. Must be less than
 *                      1600.
 * \param suffix        A byte containing the suffix bits that are absorbed
 *                      before the padding rule is applied.
 * \param suffix_len    The length (in bits) of the suffix.
 *                      8 is the maximum value.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA
 *                      \p ctx is \c NULL,
 *                      or \p capacity is out of range or not a multiple of 8,
 *                      or \p suffix_len is greater than 8.
 * \retval #MBEDTLS_ERR_KECCAK_SPONGE_BAD_STATE
 *                      This function was called without a prior call to
 *                      mbedtls_keccak_sponge_init() or after calling
 *                      mbedtls_keccak_sponge_absorb() or
 *                      mbedtls_keccak_sponge_squeeze(),
 */
int mbedtls_keccak_sponge_starts( mbedtls_keccak_sponge_context *ctx,
                                  size_t capacity,
                                  unsigned char suffix,
                                  size_t suffix_len );

/**
 * \brief               Process input bits into the sponge.
 *
 * \note                This function can be called multiple times to stream
 *                      a large amount of data.
 *
 * \param ctx           The sponge context.
 * \param data          The buffer containing the bits to input into the sponge.
 * \param size          The number of bytes to input.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA
 *                      \p ctx or \p data is \c NULL.
 * \retval #MBEDTLS_ERR_KECCAK_SPONGE_NOT_SETUP
 *                      mbedtls_keccak_sponge_starts() has not been called
 *                      on \p ctx.
 * \retval #MBEDTLS_ERR_KECCAK_SPONGE_BAD_STATE
 *                      The sponge can no longer accept data for absorption.
 *                      This occurs when mbedtls_keccak_sponge_squeeze() has
 *                      been previously called.
 *                      Alternatively, mbedtls_keccak_sponge_starts() has
 *                      not yet been called to set up the context.
 */
int mbedtls_keccak_sponge_absorb( mbedtls_keccak_sponge_context *ctx,
        const unsigned char* data,
        size_t size );

/**
 * \brief               Get output bytes from the sponge.
 *
 * \note                This function can be called multiple times to generate
 *                      arbitrary-length output.
 *
 *                      After calling this function it is no longer possible
 *                      to absorb bits into the sponge state.
 *
 * \param ctx           The sponge context.
 * \param data          The buffer to where output bytes are stored.
 * \param size          The number of output bytes to produce.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA
 *                      \p ctx or \p data is \c NULL.
 * \retval #MBEDTLS_ERR_KECCAK_SPONGE_NOT_SETUP
 *                      mbedtls_keccak_sponge_starts() has not been called
 *                      on \p ctx.
 * \retval #MBEDTLS_ERR_KECCAK_SPONGE_BAD_STATE
 *                      mbedtls_keccak_sponge_starts() has not yet been called
 *                      to set up the context.
 */
int mbedtls_keccak_sponge_squeeze( mbedtls_keccak_sponge_context *ctx,
        unsigned char* data,
        size_t size );

/**
 * \brief               Absorb data through the sponge to capacity.
 *                      For internal use only.
 *
 * \note                You must call mbedtls_keccak_sponge_starts() before
 *                      calling this function. You must not call this function
 *                      after calling mbedtls_keccak_sponge_squeeze().
 *
 * \warning             This function does not protect against being called
 *                      in an invalid state. If in doubt, call
 *                      mbedtls_keccak_sponge_absorb() instead.
 *
 * \param ctx           The sponge context.
 * \param input         The buffer containing bytes to absorb. This function
 *                      reads 1600 - c bits (200 - ceiling(c/8) bytes) where
 *                      where c is the capacity set by
 *                      mbedtls_keccak_sponge_starts().
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA
 *                      \p ctx or \p input is \c NULL.
 */
int mbedtls_keccak_sponge_process( mbedtls_keccak_sponge_context *ctx,
                                   const unsigned char *input );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_KECCAK_SPONGE_H */
