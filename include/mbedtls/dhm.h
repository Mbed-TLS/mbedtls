/**
 * \file dhm.h
 *
 * \brief Diffie-Hellman-Merkle key exchange
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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
#ifndef MBEDTLS_DHM_H
#define MBEDTLS_DHM_H

#include "bignum.h"

/*
 * DHM Error codes
 */
#define MBEDTLS_ERR_DHM_BAD_INPUT_DATA                    -0x3080  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_DHM_READ_PARAMS_FAILED                -0x3100  /**< Reading of the DHM parameters failed. */
#define MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED                -0x3180  /**< Making of the DHM parameters failed. */
#define MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED                -0x3200  /**< Reading of the public values failed. */
#define MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED                -0x3280  /**< Making of the public value failed. */
#define MBEDTLS_ERR_DHM_CALC_SECRET_FAILED                -0x3300  /**< Calculation of the DHM secret failed. */
#define MBEDTLS_ERR_DHM_INVALID_FORMAT                    -0x3380  /**< The ASN.1 data is not formatted correctly. */
#define MBEDTLS_ERR_DHM_ALLOC_FAILED                      -0x3400  /**< Allocation of memory failed. */
#define MBEDTLS_ERR_DHM_FILE_IO_ERROR                     -0x3480  /**< Read/write of file failed. */

#if ! defined(MBEDTLS_DEPRECATED_REMOVED)
#if defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_DEPRECATED    __attribute__((deprecated))
#else
#define MBEDTLS_DEPRECATED
#endif
#endif

/**
 * RFC 3526, RFC 5114 and RFC 7919 standardize a number of
 * Diffie-Hellman groups, some of which are included here
 * for use within the SSL/TLS module and the user's convenience
 * when configuring the Diffie-Hellman parameters by hand
 * through \c mbedtls_ssl_conf_dh_param.
 *
 * Included are:
 *  RFC 5114 2.2.  2048-bit MODP Group with 224-bit Prime Order Subgroup
 *  RFC 3526 3.    2048-bit MODP Group
 *  RFC 3526 4.    3072-bit MODP Group
 *  RFC 3526 5.    4096-bit MODP Group
 *  RFC 7919 A.1   ffdhe2048
 *  RFC 7919 A.2   ffdhe3072
 *  RFC 7919 A.3   ffdhe4096
 *  RFC 7919 A.4   ffdhe6144
 *  RFC 7919 A.5   ffdhe8192
 *
 * The constants with suffix "_p" denote the chosen prime moduli, while
 * the constants with suffix "_g" denote the chosen generator
 * of the associated prime field.
 *
 * All constants are represented as null-terminated strings containing the
 * hexadecimal presentation of the respective numbers.
 *
 * \warning The origin of the primes in RFC 5114 is not documented and
 *          their use therefore constitutes a security risk!
 *
 * \deprecated The primes from RFC 5114 are superseded by the primes
 *             from RFC 3526 and RFC 7919 and should no longer be used.
 *             They will be removed in the next major revision.
 *
 * The primes from RFC 3526 and RFC 7919 have been generating by the following
 * trust-worthy procedure:
 * - Fix N in { 2048, 3072, 4096, 6144, 8192 } and consider the N-bit number
 *   the first and last 64 bits are all 1, and the remaining N - 128 bits of
 *   which are 0x7ff...ff.
 * - Add the smallest multiple of the first N - 129 bits of the binary expansion
 *   of pi (for RFC 5236) or e (for RFC 7919) to this intermediate bit-string
 *   such that the resulting integer is a safe-prime.
 * - The result is the respective RFC 3526 / 7919 prime, and the corresponding
 *   generator is always chosen to be 2 (which is a square for these prime,
 *   hence the corresponding subgroup has order (p-1)/2 and avoids leaking a
 *   bit in the private exponent).
 *
 * The above description can be validated using the
 * the program programs/util/rfc_3526_7919_verify.
 */

const char * const mbedtls_dhm_rfc3526_modp_2048_p;
const char * const mbedtls_dhm_rfc3526_modp_2048_g;
const char * const mbedtls_dhm_rfc3526_modp_3072_p;
const char * const mbedtls_dhm_rfc3526_modp_3072_g;
const char * const mbedtls_dhm_rfc3526_modp_4096_p;
const char * const mbedtls_dhm_rfc3526_modp_4096_g;

const char * const mbedtls_dhm_rfc7919_ffdhe2048_p;
const char * const mbedtls_dhm_rfc7919_ffdhe2048_g;
const char * const mbedtls_dhm_rfc7919_ffdhe3072_p;
const char * const mbedtls_dhm_rfc7919_ffdhe3072_g;
const char * const mbedtls_dhm_rfc7919_ffdhe4096_p;
const char * const mbedtls_dhm_rfc7919_ffdhe4096_g;
const char * const mbedtls_dhm_rfc7919_ffdhe6144_p;
const char * const mbedtls_dhm_rfc7919_ffdhe6144_g;
const char * const mbedtls_dhm_rfc7919_ffdhe8192_p;
const char * const mbedtls_dhm_rfc7919_ffdhe8192_g;

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
MBEDTLS_DEPRECATED const char * const mbedtls_dhm_rfc5114_modp_2048_p;
MBEDTLS_DEPRECATED const char * const mbedtls_dhm_rfc5114_modp_2048_g;
#endif

/**
 * \deprecated These macros are superseded by direct access to the corresponding
 *             global variables and will be removed in the next major revision.
 */
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#define MBEDTLS_DHM_RFC5114_MODP_2048_P mbedtls_dhm_rfc5114_modp_2048_p
#define MBEDTLS_DHM_RFC5114_MODP_2048_G mbedtls_dhm_rfc5114_modp_2048_g
#define MBEDTLS_DHM_RFC3526_MODP_2048_P mbedtls_dhm_rfc3526_modp_2048_p
#define MBEDTLS_DHM_RFC3526_MODP_2048_G mbedtls_dhm_rfc3526_modp_2048_g
#define MBEDTLS_DHM_RFC3526_MODP_3072_P mbedtls_dhm_rfc3526_modp_3072_p
#define MBEDTLS_DHM_RFC3526_MODP_3072_G mbedtls_dhm_rfc3526_modp_3072_g
#define MBEDTLS_DHM_RFC3526_MODP_4096_P mbedtls_dhm_rfc3526_modp_4096_p
#define MBEDTLS_DHM_RFC3526_MODP_4096_G mbedtls_dhm_rfc3526_modp_4096_g
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          DHM context structure
 */
typedef struct
{
    size_t len; /*!<  size(P) in chars  */
    mbedtls_mpi P;      /*!<  prime modulus     */
    mbedtls_mpi G;      /*!<  generator         */
    mbedtls_mpi X;      /*!<  secret value      */
    mbedtls_mpi GX;     /*!<  self = G^X mod P  */
    mbedtls_mpi GY;     /*!<  peer = G^Y mod P  */
    mbedtls_mpi K;      /*!<  key = GY^X mod P  */
    mbedtls_mpi RP;     /*!<  cached R^2 mod P  */
    mbedtls_mpi Vi;     /*!<  blinding value    */
    mbedtls_mpi Vf;     /*!<  un-blinding value */
    mbedtls_mpi pX;     /*!<  previous X        */
}
mbedtls_dhm_context;

/**
 * \brief          Initialize DHM context
 *
 * \param ctx      DHM context to be initialized
 */
void mbedtls_dhm_init( mbedtls_dhm_context *ctx );

/**
 * \brief          Parse the ServerKeyExchange parameters
 *
 * \param ctx      DHM context
 * \param p        &(start of input buffer), will be increased
 *                 by the amount of data read.
 * \param end      end of buffer
 *
 * \return         0 if successful, or an MBEDTLS_ERR_DHM_XXX error code
 */
int mbedtls_dhm_read_params( mbedtls_dhm_context *ctx,
                     unsigned char **p,
                     const unsigned char *end );

/**
 * \brief          Setup and write the ServerKeyExchange parameters
 *
 * \param ctx      DHM context
 * \param x_size   private value size in bytes
 * \param output   destination buffer
 * \param olen     number of chars written
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \note           The destination buffer must be large enough to hold
 *                 the modulus, the generator, and the public key, each
 *                 wrapped with a 2-byte length field. It is the responsibility
 *                 of the caller to ensure that enough space is available.
 *
 * \note           This function assumes that ctx->P and ctx->G
 *                 have already been properly set (for example
 *                 using mbedtls_mpi_read_string or mbedtls_mpi_read_binary).
 *
 * \return         0 if successful, or an MBEDTLS_ERR_DHM_XXX error code
 */
int mbedtls_dhm_make_params( mbedtls_dhm_context *ctx, int x_size,
                     unsigned char *output, size_t *olen,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief          Import the peer's public value G^Y
 *
 * \param ctx      DHM context
 * \param input    input buffer
 * \param ilen     size of buffer
 *
 * \return         0 if successful, or an MBEDTLS_ERR_DHM_XXX error code
 */
int mbedtls_dhm_read_public( mbedtls_dhm_context *ctx,
                     const unsigned char *input, size_t ilen );

/**
 * \brief          Create own private value X and export G^X
 *
 * \param ctx      DHM context
 * \param x_size   private value size in bytes
 * \param output   destination buffer
 * \param olen     size of the destination buffer;
 *                 must be at least equal to the size of P, ctx->len
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \note           The destination buffer will always be fully written
 *                 so as to contain a big-endian presentation of G^X mod P.
 *                 If it is larger than ctx->len, it will accordingly be
 *                 padded with zero-bytes in the beginning.
 *
 * \return         0 if successful, or an MBEDTLS_ERR_DHM_XXX error code
 */
int mbedtls_dhm_make_public( mbedtls_dhm_context *ctx, int x_size,
                     unsigned char *output, size_t olen,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief          Derive and export the shared secret (G^Y)^X mod P
 *
 * \param ctx      DHM context
 * \param output   destination buffer
 * \param output_size   size of the destination buffer, must be at
 *                      at least the size of ctx->len
 * \param olen     on exit, holds the actual number of bytes written
 * \param f_rng    RNG function, for blinding purposes
 * \param p_rng    RNG parameter
 *
 * \return         0 if successful, or an MBEDTLS_ERR_DHM_XXX error code
 *
 * \note           If non-NULL, f_rng is used to blind the input as
 *                 countermeasure against timing attacks. Blinding is
 *                 automatically used if and only if our secret value X is
 *                 re-used and costs nothing otherwise, so it is recommended
 *                 to always pass a non-NULL f_rng argument.
 */
int mbedtls_dhm_calc_secret( mbedtls_dhm_context *ctx,
                     unsigned char *output, size_t output_size, size_t *olen,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng );

/**
 * \brief          Free and clear the components of a DHM key
 *
 * \param ctx      DHM context to free and clear
 */
void mbedtls_dhm_free( mbedtls_dhm_context *ctx );

#if defined(MBEDTLS_ASN1_PARSE_C)
/** \ingroup x509_module */
/**
 * \brief          Parse DHM parameters in PEM or DER format
 *
 * \param dhm      DHM context to be initialized
 * \param dhmin    input buffer
 * \param dhminlen size of the buffer
 *                 (including the terminating null byte for PEM data)
 *
 * \return         0 if successful, or a specific DHM or PEM error code
 */
int mbedtls_dhm_parse_dhm( mbedtls_dhm_context *dhm, const unsigned char *dhmin,
                   size_t dhminlen );

#if defined(MBEDTLS_FS_IO)
/** \ingroup x509_module */
/**
 * \brief          Load and parse DHM parameters
 *
 * \param dhm      DHM context to be initialized
 * \param path     filename to read the DHM Parameters from
 *
 * \return         0 if successful, or a specific DHM or PEM error code
 */
int mbedtls_dhm_parse_dhmfile( mbedtls_dhm_context *dhm, const char *path );
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_ASN1_PARSE_C */

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_dhm_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* dhm.h */
