/**
 * \file ecdsa.h
 *
 * \brief Elliptic curve DSA
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
#ifndef MBEDTLS_ECDSA_H
#define MBEDTLS_ECDSA_H

#include "ecp.h"
#include "md.h"

/*
 * RFC 4492 page 20:
 *
 *     Ecdsa-Sig-Value ::= SEQUENCE {
 *         r       INTEGER,
 *         s       INTEGER
 *     }
 *
 * Size is at most
 *    1 (tag) + 1 (len) + 1 (initial 0) + ECP_MAX_BYTES for each of r and s,
 *    twice that + 1 (tag) + 2 (len) for the sequence
 * (assuming ECP_MAX_BYTES is less than 126 for r and s,
 * and less than 124 (total len <= 255) for the sequence)
 */

/**
 * \brief           Maximum ECDSA signature size for a given curve bit size
 *
 * \param bits      Curve size in bits
 * \return          Maximum signature size in bytes
 *
 * \note            This macro returns a compile-time constant if its argument
 *                  is one. It may evaluate its argument multiple times; if
 *                  this is a problem, call the function
 *                  mbedtls_ecdsa_max_sig_len instead.
 */
#define MBEDTLS_ECDSA_MAX_SIG_LEN( bits )                               \
    ( /*T,L of SEQUENCE*/ ( ( bits ) >= 61 * 8 ? 3 : 2 ) +              \
      /*T,L of r,s*/        2 * ( ( ( bits ) >= 127 * 8 ? 3 : 2 ) +     \
      /*V of r,s*/                ( ( bits ) + 8 ) / 8 ) )

/**
 * \brief           Maximum ECDSA signature size for a given curve bit size
 *
 * \param bits      Curve size in bits
 * \return          Maximum signature size in bytes
 *
 * \note            If you need a compile-time constant, call the macro
 *                  MBEDTLS_ECDSA_MAX_SIG_LEN instead.
 */
static inline size_t mbedtls_ecdsa_max_sig_len( size_t bits )
{
    return( MBEDTLS_ECDSA_MAX_SIG_LEN( bits ) );
}

#if MBEDTLS_ECP_MAX_BYTES > 124
#error "MBEDTLS_ECP_MAX_BYTES bigger than expected, please fix MBEDTLS_ECDSA_MAX_LEN"
#endif
/** Maximum size of an ECDSA signature in bytes */
#define MBEDTLS_ECDSA_MAX_LEN  ( 3 + 2 * ( 3 + MBEDTLS_ECP_MAX_BYTES ) )

/**
 * \brief           ECDSA context structure
 */
typedef mbedtls_ecp_keypair mbedtls_ecdsa_context;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief           Compute ECDSA signature of a previously hashed message
 *
 * \note            The deterministic version is usually prefered.
 *
 * \param grp       ECP group
 * \param r         First output integer
 * \param s         Second output integer
 * \param d         Private signing key
 * \param buf       Message hash
 * \param blen      Length of buf
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  prescribed by SEC1 4.1.3 step 5.
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_ECP_XXX or MBEDTLS_MPI_XXX error code
 */
int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
/**
 * \brief           Compute ECDSA signature of a previously hashed message,
 *                  deterministic version (RFC 6979).
 *
 * \param grp       ECP group
 * \param r         First output integer
 * \param s         Second output integer
 * \param d         Private signing key
 * \param buf       Message hash
 * \param blen      Length of buf
 * \param md_alg    MD algorithm used to hash the message
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  prescribed by SEC1 4.1.3 step 5.
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_ECP_XXX or MBEDTLS_MPI_XXX error code
 */
int mbedtls_ecdsa_sign_det( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                    const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                    mbedtls_md_type_t md_alg );
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

/**
 * \brief           Verify ECDSA signature of a previously hashed message
 *
 * \param grp       ECP group
 * \param buf       Message hash
 * \param blen      Length of buf
 * \param Q         Public key to use for verification
 * \param r         First integer of the signature
 * \param s         Second integer of the signature
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  prescribed by SEC1 4.1.4 step 3.
 *
 * \return          0 if successful,
 *                  MBEDTLS_ERR_ECP_BAD_INPUT_DATA if signature is invalid
 *                  or a MBEDTLS_ERR_ECP_XXX or MBEDTLS_MPI_XXX error code
 */
int mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,
                  const unsigned char *buf, size_t blen,
                  const mbedtls_ecp_point *Q, const mbedtls_mpi *r, const mbedtls_mpi *s);

/**
 * \brief           Compute ECDSA signature and write it to buffer,
 *                  serialized as defined in RFC 4492 page 20.
 *                  (Not thread-safe to use same context in multiple threads)
 *
 * \note            The deterministic version (RFC 6979) is used if
 *                  MBEDTLS_ECDSA_DETERMINISTIC is defined.
 *
 * \param ctx       ECDSA context
 * \param md_alg    Algorithm that was used to hash the message
 * \param hash      Message hash
 * \param hlen      Length of hash
 * \param sig       Buffer that will hold the signature
 * \param slen      Length of the signature written
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \note            The \c sig buffer must be at least
 *                  `MBEDTLS_ECDSA_MAX_SIG_LEN(ctx->grp.pbits)` bytes long.
 *                  MBEDTLS_ECDSA_MAX_LEN is always safe.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  prescribed by SEC1 4.1.3 step 5.
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_ECP_XXX, MBEDTLS_ERR_MPI_XXX or
 *                  MBEDTLS_ERR_ASN1_XXX error code
 */
int mbedtls_ecdsa_write_signature( mbedtls_ecdsa_context *ctx, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hlen,
                           unsigned char *sig, size_t *slen,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng );

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
#if ! defined(MBEDTLS_DEPRECATED_REMOVED)
#if defined(MBEDTLS_DEPRECATED_WARNING)
#define MBEDTLS_DEPRECATED    __attribute__((deprecated))
#else
#define MBEDTLS_DEPRECATED
#endif
/**
 * \brief           Compute ECDSA signature and write it to buffer,
 *                  serialized as defined in RFC 4492 page 20.
 *                  Deterministic version, RFC 6979.
 *                  (Not thread-safe to use same context in multiple threads)
 *
 * \deprecated      Superseded by mbedtls_ecdsa_write_signature() in 2.0.0
 *
 * \param ctx       ECDSA context
 * \param hash      Message hash
 * \param hlen      Length of hash
 * \param sig       Buffer that will hold the signature
 * \param slen      Length of the signature written
 * \param md_alg    MD algorithm used to hash the message
 *
 * \note            The \c sig buffer must be at least
 *                  `MBEDTLS_ECDSA_MAX_SIG_LEN(ctx->grp.pbits)` bytes long.
 *                  MBEDTLS_ECDSA_MAX_LEN is always safe.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  prescribed by SEC1 4.1.3 step 5.
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_ECP_XXX, MBEDTLS_ERR_MPI_XXX or
 *                  MBEDTLS_ERR_ASN1_XXX error code
 */
int mbedtls_ecdsa_write_signature_det( mbedtls_ecdsa_context *ctx,
                               const unsigned char *hash, size_t hlen,
                               unsigned char *sig, size_t *slen,
                               mbedtls_md_type_t md_alg ) MBEDTLS_DEPRECATED;
#undef MBEDTLS_DEPRECATED
#endif /* MBEDTLS_DEPRECATED_REMOVED */
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

/**
 * \brief           Convert a signature from ASN.1 to a raw concatenation
 *                  of {r,s}
 *
 * \param sig       Signature to be converted
 * \param ssize     Size of the signature
 * \param byte_len  Length of a single number of the signature
 * \param buf       Buffer pointer for the converted signature
 * \param bufsize   Size of the passed buffer
 * \param buflen    Size of the signature written to the buffer
 *
 * \note            The size of the buffer \c bufsize should be at least
 *                  2*byte_len bytes long, otherwise this function will
 *                  return an error.
 *
 * \return          0 if successful, or a MBEDTLS_ERR_ECP_BAD_INPUT_DATA or
 *                  MBEDTLS_ERR_ASN1_LENGTH_MISMATCH error code
 *
 */
int mbedtls_ecdsa_signature_to_raw( const unsigned char *sig,
                            size_t ssize, uint16_t byte_len,
                            unsigned char *buf, size_t bufsize,
                            size_t* buflen );
/**
 * \brief           Convert a signature from numbers to ASN.1
 *
 * \param r         First number of the signature
 * \param s         Second number of the signature
 * \param sig       Buffer that will hold the signature
 * \param slen      Length of the signature written
 * \param ssize     Size of the sig buffer
 *
 * \note            The size of the buffer \c ssize should be at least
 *                  `MBEDTLS_ECDSA_MAX_SIG_LEN(grp->pbits)` bytes long if
 *                  the signature was produced from curve \c grp,
 *                  otherwise this function will return an error.
 *
 * \return          0 if successful,
 *                  or a MBEDTLS_ERR_MPI_XXX or MBEDTLS_ERR_ASN1_XXX error code
 *
 */
int mbedtls_ecdsa_signature_to_asn1( const mbedtls_mpi *r,
                             const mbedtls_mpi *s, unsigned char *sig,
                             size_t *slen, size_t ssize );

/**
 * \brief           Read and verify an ECDSA signature
 *
 * \param ctx       ECDSA context
 * \param hash      Message hash
 * \param hlen      Size of hash
 * \param sig       Signature to read and verify
 * \param slen      Size of sig
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  prescribed by SEC1 4.1.4 step 3.
 *
 * \return          0 if successful,
 *                  MBEDTLS_ERR_ECP_BAD_INPUT_DATA if signature is invalid,
 *                  MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH if the signature is
 *                  valid but its actual length is less than siglen,
 *                  or a MBEDTLS_ERR_ECP_XXX or MBEDTLS_ERR_MPI_XXX error code
 */
int mbedtls_ecdsa_read_signature( mbedtls_ecdsa_context *ctx,
                          const unsigned char *hash, size_t hlen,
                          const unsigned char *sig, size_t slen );

/**
 * \brief           Generate an ECDSA keypair on the given curve
 *
 * \param ctx       ECDSA context in which the keypair should be stored
 * \param gid       Group (elliptic curve) to use. One of the various
 *                  MBEDTLS_ECP_DP_XXX macros depending on configuration.
 * \param f_rng     RNG function
 * \param p_rng     RNG parameter
 *
 * \return          0 on success, or a MBEDTLS_ERR_ECP_XXX code.
 */
int mbedtls_ecdsa_genkey( mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id gid,
                  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

/**
 * \brief           Set an ECDSA context from an EC key pair
 *
 * \param ctx       ECDSA context to set
 * \param key       EC key to use
 *
 * \return          0 on success, or a MBEDTLS_ERR_ECP_XXX code.
 */
int mbedtls_ecdsa_from_keypair( mbedtls_ecdsa_context *ctx, const mbedtls_ecp_keypair *key );

/**
 * \brief           Initialize context
 *
 * \param ctx       Context to initialize
 */
void mbedtls_ecdsa_init( mbedtls_ecdsa_context *ctx );

/**
 * \brief           Free context
 *
 * \param ctx       Context to free
 */
void mbedtls_ecdsa_free( mbedtls_ecdsa_context *ctx );

#ifdef __cplusplus
}
#endif

#endif /* ecdsa.h */
