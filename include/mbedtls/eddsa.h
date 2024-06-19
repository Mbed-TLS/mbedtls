/**
 * \file eddsa.h
 *
 * \brief This file contains EDDSA definitions and functions.
 *
 * The Edwards-curve Digital Signature Algorithm (EdDSA) is defined in
 * <em>Standards for Efficient Cryptography Group (SECG):
 * SEC1 Elliptic Curve Cryptography</em>.
 * The use of EdDSA for TLS is defined in <em>RFC-8422: Elliptic Curve
 * Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)
 * Versions 1.2 and Earlier</em>.
 *
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

#ifndef MBEDTLS_EDDSA_H
#define MBEDTLS_EDDSA_H

#include "mbedtls/build_info.h"

#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

/**
 * \brief           Maximum EdDSA signature size for a given curve bit size
 *
 * \param bits      Curve size in bits
 * \return          Maximum signature size in bytes
 *
 * \note            This macro returns a compile-time constant if its argument
 *                  is one. It may evaluate its argument multiple times.
 */
/*
 *     Eddsa-Sig-Value ::= SEQUENCE {
 *         r       INTEGER,
 *         s       INTEGER
 *     }
 *
 * For each of r and s, the value (V) may include an extra initial "0" bit.
 */
#define MBEDTLS_EDDSA_MAX_SIG_LEN(bits)                               \
    (/*T,L of SEQUENCE*/ ((bits) >= 61 * 8 ? 3 : 2) +              \
     /*T,L of r,s*/ 2 * (((bits) >= 127 * 8 ? 3 : 2) +     \
                         /*V of r,s*/ ((bits) + 8) / 8))

/** The maximal size of an EdDSA signature in Bytes. */
/* EdDSA is defined for two curves: Ed25519 (256 bits) and Ed448 (456 bits) */

#if defined(MBEDTLS_ECP_DP_ED448_ENABLED)
#define MBEDTLS_EDDSA_MAX_LEN  MBEDTLS_EDDSA_MAX_SIG_LEN(456)
#elif defined(MBEDTLS_ECP_DP_ED25519_ENABLED)
#define MBEDTLS_EDDSA_MAX_LEN  MBEDTLS_EDDSA_MAX_SIG_LEN(256)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * EdDSA signature operation type.
 *
 * It identifies the signature operation type (pure, ctx or prehash).
 */

typedef enum {
    MBEDTLS_EDDSA_NONE = 0, /*!< Operation not defined. */
    MBEDTLS_EDDSA_PURE,     /*!< Pure operation (the usual). It uses the entire message, without hashing it previously. */
    MBEDTLS_EDDSA_CTX,      /*!< Operation with a deterministic context. It uses the entire message, without hashing it previously. */
    MBEDTLS_EDDSA_PREHASH,  /*!< Operation with a pre-hashed message. It uses the hashed message instead of full message like pure or ctx. */
} mbedtls_eddsa_id;

/**
 * \brief          This function checks whether a given group can be used
 *                 for EdDSA.
 *
 * \param gid      The ECP group ID to check.
 *
 * \return         \c 1 if the group can be used, \c 0 otherwise
 */
int mbedtls_eddsa_can_do(mbedtls_ecp_group_id gid);

/**
 * \brief           This function computes the EdDSA signature of a
 *                  previously-hashed message.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated
 *                  as defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.3, step 5.
 *
 * \see             ecp.h
 *
 * \param grp       The context for the elliptic curve to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through mbedtls_ecp_group_load().
 * \param r         The MPI context in which to store the first part
 *                  the signature. This must be initialized.
 * \param s         The MPI context in which to store the second part
 *                  the signature. This must be initialized.
 * \param d         The private signing key. This must be initialized.
 * \param buf       The content to be signed. This is usually the hash of
 *                  the original data to be signed. This must be a readable
 *                  buffer of length \p blen Bytes. It may be \c NULL if
 *                  \p blen is zero.
 * \param blen      The length of \p buf in Bytes.
 * \param eddsa_id  The signature operation id that identifies PureEdDSA,
 *                  EdDSActx or EdDSAph
 * \param ed_ctx    The context for EdDSActx and EdDSAph operations.
                    it can be \c NULL if \c MBEDTLS_EDDSA_PURE is used or
                    if no context is provided.
 * \param ed_ctx_len The length of the context for EdDSActx and EdDSAph
 *                  operations. It can be \c 0.
 * \param f_rng     The RNG function. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL if \p f_rng doesn't need a context parameter.
 *
 * \return          \c 0 on success.
 * \return          An \c MBEDTLS_ERR_ECP_XXX
 *                  or \c MBEDTLS_MPI_XXX error code on failure.
 */
int mbedtls_eddsa_sign(mbedtls_ecp_group *grp,
                       mbedtls_mpi *r, mbedtls_mpi *s,
                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       mbedtls_eddsa_id eddsa_id,
                       const unsigned char *ed_ctx, size_t ed_ctx_len,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

/**
 * \brief           This function verifies the EdDSA signature of a
 *                  previously-hashed message.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.4, step 3.
 *
 * \see             ecp.h
 *
 * \param grp       The ECP group to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through mbedtls_ecp_group_load().
 * \param buf       The hashed content that was signed. This must be a readable
 *                  buffer of length \p blen Bytes. It may be \c NULL if
 *                  \p blen is zero.
 * \param blen      The length of \p buf in Bytes.
 * \param Q         The public key to use for verification. This must be
 *                  initialized and setup.
 * \param r         The first integer of the signature.
 *                  This must be initialized.
 * \param s         The second integer of the signature.
 *                  This must be initialized.
 * \param eddsa_id  The signature operation id that identifies PureEdDSA,
 *                  EdDSActx or EdDSAph
 * \param ed_ctx    The context for EdDSActx and EdDSAph operations.
                    it can be \c NULL if \c MBEDTLS_EDDSA_PURE is used or
                    if no context is provided.
 * \param ed_ctx_len The length of the context for EdDSActx and EdDSAph
 *                  operations. It can be \c 0.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA if the signature
 *                  is invalid.
 * \return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_MPI_XXX
 *                  error code on failure for any other reason.
 */
int mbedtls_eddsa_verify(mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *Q, const mbedtls_mpi *r,
                         const mbedtls_mpi *s,
                         mbedtls_eddsa_id eddsa_id,
                         const unsigned char *ed_ctx, size_t ed_ctx_len);

/**
 * \brief           This function computes the EdDSA signature and writes it
 *                  to a buffer, serialized as defined in <em>RFC-4492:
 *                  Elliptic Curve Cryptography (ECC) Cipher Suites for
 *                  Transport Layer Security (TLS)</em>.
 *
 * \warning         It is not thread-safe to use the same context in
 *                  multiple threads.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.3, step 5.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECP keypair context to use. This must be initialized
 *                  and have a group and private key bound to it, for example
 *                  via mbedtls_eddsa_genkey().
 * \param hash      The message hash to be signed. This must be a readable
 *                  buffer of length \p blen Bytes.
 * \param hlen      The length of the hash \p hash in Bytes.
 * \param sig       The buffer to which to write the signature.
 *                  A buffer size of #MBEDTLS_EDDSA_MAX_LEN is always safe.
 * \param sig_size  The size of the \p sig buffer in bytes.
 * \param slen      The address at which to store the actual length of
 *                  the signature written. Must not be \c NULL.
 * \param eddsa_id  The signature operation id that identifies PureEdDSA,
 *                  EdDSActx or EdDSAph
 * \param ed_ctx    The context for EdDSActx and EdDSAph operations.
                    it can be \c NULL if \c MBEDTLS_EDDSA_PURE is used or
                    if no context is provided.
 * \param ed_ctx_len The length of the context for EdDSActx and EdDSAph
 *                  operations. It can be \c 0.
 * \param f_rng     The RNG function. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL if \p f_rng is \c NULL or doesn't use a context.
 *
 * \return          \c 0 on success.
 * \return          An \c MBEDTLS_ERR_ECP_XXX, \c MBEDTLS_ERR_MPI_XXX or
 *                  \c MBEDTLS_ERR_ASN1_XXX error code on failure.
 */
int mbedtls_eddsa_write_signature(mbedtls_ecp_keypair *ctx,
                                  const unsigned char *hash, size_t hlen,
                                  unsigned char *sig, size_t sig_size, size_t *slen,
                                  mbedtls_eddsa_id eddsa_id,
                                  const unsigned char *ed_ctx, size_t ed_ctx_len,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng);

/**
 * \brief           This function reads and verifies an EdDSA signature.
 *
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated as
 *                  defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.4, step 3.
 *
 * \see             ecp.h
 *
 * \param ctx       The ECP keypair context to use. This must be initialized
 *                  and have a group and public key bound to it.
 * \param hash      The message hash that was signed. This must be a readable
 *                  buffer of length \p size Bytes.
 * \param hlen      The size of the hash \p hash.
 * \param sig       The signature to read and verify. This must be a readable
 *                  buffer of length \p slen Bytes.
 * \param slen      The size of \p sig in Bytes.
 * \param eddsa_id  The signature operation id that identifies PureEdDSA,
 *                  EdDSActx or EdDSAph
 * \param ed_ctx    The context for EdDSActx and EdDSAph operations.
                    it can be \c NULL if \c MBEDTLS_EDDSA_PURE is used or
                    if no context is provided.
 * \param ed_ctx_len The length of the context for EdDSActx and EdDSAph
 *                  operations. It can be \c 0.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA if signature is invalid.
 * \return          #MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH if there is a valid
 *                  signature in \p sig, but its length is less than \p siglen.
 * \return          An \c MBEDTLS_ERR_ECP_XXX or \c MBEDTLS_ERR_MPI_XXX
 *                  error code on failure for any other reason.
 */
int mbedtls_eddsa_read_signature(mbedtls_ecp_keypair *ctx,
                                 const unsigned char *hash, size_t hlen,
                                 const unsigned char *sig, size_t slen,
                                 mbedtls_eddsa_id eddsa_id,
                                 const unsigned char *ed_ctx, size_t ed_ctx_len);

#ifdef __cplusplus
}
#endif

#endif /* eddsa.h */
