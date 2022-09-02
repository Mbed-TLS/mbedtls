/**
 * \file lmots.h
 *
 * \brief This file provides an API for the LM-OTS post-quantum-safe one-time
 *        public-key signature scheme as defined in RFC8554 and NIST.SP.200-208.
 *        This implementation currently only supports a single parameter set
 *        MBEDTLS_LMOTS_SHA256_N32_W8 in order to reduce complexity.
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

#ifndef MBEDTLS_LMOTS_H
#define MBEDTLS_LMOTS_H

#include "mbedtls/build_info.h"

#include "psa/crypto.h"

#include <stdint.h>
#include <stddef.h>

/* Currently only defined for SHA256, 32 is the max hash output size */
#define MBEDTLS_LMOTS_N_HASH_LEN_MAX           (32u)
#define MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT_MAX    (34u)
#define MBEDTLS_LMOTS_N_HASH_LEN(type)         (type == MBEDTLS_LMOTS_SHA256_N32_W8 ? 32u : 0)
#define MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT(type)  (type == MBEDTLS_LMOTS_SHA256_N32_W8 ? 34u : 0)
#define MBEDTLS_LMOTS_C_RANDOM_VALUE_LEN(type) (MBEDTLS_LMOTS_N_HASH_LEN(type))
#define MBEDTLS_LMOTS_TYPE_LEN                 (4u)
#define MBEDTLS_LMOTS_I_KEY_ID_LEN             (16u)
#define MBEDTLS_LMOTS_Q_LEAF_ID_LEN            (4u)

#define MBEDTLS_LMOTS_SIG_LEN(type) (MBEDTLS_LMOTS_TYPE_LEN + \
                                     MBEDTLS_LMOTS_C_RANDOM_VALUE_LEN(type) + \
                                     (MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT(type) * \
                                      MBEDTLS_LMOTS_N_HASH_LEN(type)))

#define MBEDTLS_LMOTS_PUBLIC_KEY_LEN(type) (MBEDTLS_LMOTS_TYPE_LEN + \
                                            MBEDTLS_LMOTS_I_KEY_ID_LEN + \
                                            MBEDTLS_LMOTS_Q_LEAF_ID_LEN + \
                                            MBEDTLS_LMOTS_N_HASH_LEN(type))

#define MBEDTLS_LMOTS_SIG_TYPE_OFFSET       (0)
#define MBEDTLS_LMOTS_SIG_C_RANDOM_OFFSET (MBEDTLS_LMOTS_SIG_TYPE_OFFSET + \
                                           MBEDTLS_LMOTS_TYPE_LEN)
#define MBEDTLS_LMOTS_SIG_SIGNATURE_OFFSET(type) (MBEDTLS_LMOTS_SIG_C_RANDOM_OFFSET + \
                                                  MBEDTLS_LMOTS_C_RANDOM_VALUE_LEN(type))

#ifdef __cplusplus
extern "C" {
#endif

/** The Identifier of the LMS parameter set, as per
 *  https://www.iana.org/assignments/leighton-micali-signatures/leighton-micali-signatures.xhtml.
 *  We are only implementing a subset of the types, particularly N32_W8, for the sake of simplicty.
 */
typedef enum {
    MBEDTLS_LMOTS_SHA256_N32_W8 = 4
} mbedtls_lmots_algorithm_type_t;


/** LMOTS parameters structure.
 *
 * This contains the metadata associated with an LMOTS key, detailing the
 * algorithm type, the key ID, and the leaf identifier should be key be part of
 * a LMS key.
 */
typedef struct {
    unsigned char MBEDTLS_PRIVATE(I_key_identifier[MBEDTLS_LMOTS_I_KEY_ID_LEN]); /*!< The key
                                                     identifier. */
    unsigned char MBEDTLS_PRIVATE(q_leaf_identifier[MBEDTLS_LMOTS_Q_LEAF_ID_LEN]); /*!< Which
                                                      leaf of the LMS key this is.
                                                      0 if the key is not part of an LMS key. */
    mbedtls_lmots_algorithm_type_t MBEDTLS_PRIVATE(type); /*!< The LM-OTS key type identifier as
                                                               per IANA. Only SHA256_N32_W8 is
                                                               currently supported. */
} mbedtls_lmots_parameters_t;

/** LMOTS public context structure.
 *
 * A LMOTS public key is a hash output, and the applicable parameter set.
 *
 * The context must be initialized before it is used. A public key must either
 * be imported or generated from a private context.
 *
 * \dot
 * digraph lmots_public_t {
 *   UNINITIALIZED -> INIT [label="init"];
 *   HAVE_PUBLIC_KEY -> INIT [label="free"];
 *   INIT -> HAVE_PUBLIC_KEY [label="import_public_key"];
 *   INIT -> HAVE_PUBLIC_KEY [label="calculate_public_key from private key"];
 *   HAVE_PUBLIC_KEY -> HAVE_PUBLIC_KEY [label="export_public_key"];
 * }
 * \enddot
 */
typedef struct {
    mbedtls_lmots_parameters_t MBEDTLS_PRIVATE(params);
    unsigned char MBEDTLS_PRIVATE(public_key)[MBEDTLS_LMOTS_N_HASH_LEN_MAX];
    unsigned char MBEDTLS_PRIVATE(have_public_key); /*!< Whether the context contains a public key.
                                                     Boolean values only. */
} mbedtls_lmots_public_t;

#ifdef MBEDTLS_LMS_PRIVATE
/** LMOTS private context structure.
 *
 * A LMOTS private key is one hash output for each of digit of the digest +
 * checksum, and the applicable parameter set.
 *
 * The context must be initialized before it is used. A public key must either
 * be imported or generated from a private context.
 *
 * \dot
 * digraph lmots_public_t {
 *   UNINITIALIZED -> INIT [label="init"];
 *   HAVE_PRIVATE_KEY -> INIT [label="free"];
 *   INIT -> HAVE_PRIVATE_KEY [label="generate_private_key"];
 *   HAVE_PRIVATE_KEY -> INIT [label="sign"];
 * }
 * \enddot
 */
typedef struct {
    mbedtls_lmots_parameters_t MBEDTLS_PRIVATE(params);
    unsigned char MBEDTLS_PRIVATE(private_key)[MBEDTLS_LMOTS_P_SIG_DIGIT_COUNT_MAX][MBEDTLS_LMOTS_N_HASH_LEN_MAX];
    unsigned char MBEDTLS_PRIVATE(have_private_key); /*!< Whether the context contains a private key.
                                                     Boolean values only. */
} mbedtls_lmots_private_t;
#endif /* MBEDTLS_LMS_PRIVATE */

/**
 * \brief                    This function converts an unsigned int into a
 *                           network-byte-order (big endian) string.
 *
 * \param val                The unsigned integer value
 * \param len                The length of the string.
 * \param bytes              The string to output into.
 *
 * \return                   The corresponding LMS error code.
 */
void unsigned_int_to_network_bytes( unsigned int val, size_t len,
                                    unsigned char *bytes );

/**
 * \brief                    This function converts a network-byte-order
 *                           (big endian) string into an unsigned integer.
 *
 * \param len                The length of the string.
 * \param bytes              The string.
 *
 * \return                   The corresponding LMS error code.
 */
unsigned int network_bytes_to_unsigned_int( size_t len,
                                            const unsigned char *bytes );

/**
 * \brief                    This function converts a \ref psa_status_t to a
 *                           low-level LMS error code.
 *
 * \param status             The psa_status_t to convert
 *
 * \return                   The corresponding LMS error code.
 */
int mbedtls_lms_error_from_psa( psa_status_t status );


/**
 * \brief                    This function initializes a public LMOTS context
 *
 * \param ctx                The uninitialized LMOTS context that will then be
 *                           initialized.
 */
void mbedtls_lmots_init_public( mbedtls_lmots_public_t *ctx );

/**
 * \brief                    This function uninitializes a public LMOTS context
 *
 * \param ctx                The initialized LMOTS context that will then be
 *                           uninitialized.
 */
void mbedtls_lmots_free_public( mbedtls_lmots_public_t *ctx );

/**
 * \brief                    This function imports an LMOTS public key into a
 *                           LMOTS context.
 *
 * \note                     Before this function is called, the context must
 *                           have been initialized.
 *
 * \note                     See IETF RFC8554 for details of the encoding of
 *                           this public key.
 *
 * \param ctx                The initialized LMOTS context store the key in.
 * \param key                The buffer from which the key will be read.
 *                           #MBEDTLS_LMOTS_PUBLIC_KEY_LEN bytes will be read
 *                           from this.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lmots_import_public_key( mbedtls_lmots_public_t *ctx,
                                     const unsigned char *key, size_t key_size );

/**
 * \brief                    This function creates a candidate public key from
 *                           an LMOTS signature. This can then be compared to
 *                           the real public key to determine the validity of
 *                           the signature.
 *
 * \note                     This function is exposed publicly to be used in LMS
 *                           signature verification, it is expected that
 *                           mbedtls_lmots_verify will be used for LMOTS
 *                           signature verification.
 *
 * \param params             The LMOTS parameter set, q and I values as an
 *                           mbedtls_lmots_parameters_t struct.
 * \param msg                The buffer from which the message will be read.
 * \param msg_size           The size of the message that will be read.
 * \param sig                The buffer from which the signature will be read.
 *                           #MBEDTLS_LMOTS_SIG_LEN bytes will be read from
 *                           this.
 * \param out                The buffer where the candidate public key will be
 *                           stored. Must be at least #MBEDTLS_LMOTS_N_HASH_LEN
 *                           bytes in size.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lmots_calculate_public_key_candidate( const mbedtls_lmots_parameters_t *params,
                                                  const unsigned char *msg,
                                                  size_t msg_size,
                                                  const unsigned char *sig,
                                                  size_t sig_size,
                                                  unsigned char *out,
                                                  size_t out_size,
                                                  size_t *out_len );

/**
 * \brief                    This function verifies a LMOTS signature, using a
 *                           LMOTS context that contains a public key.
 *
 * \warning                  This function is **not intended for use in
 *                           production**, due to as-yet unsolved problems with
 *                           handling stateful keys.
 *
 * \note                     Before this function is called, the context must
 *                           have been initialized and must contain a public key
 *                           (either by import or calculation from a private
 *                           key).
 *
 * \param ctx                The initialized LMOTS context from which the public
 *                           key will be read.
 * \param msg                The buffer from which the message will be read.
 * \param msg_size           The size of the message that will be read.
 * \param sig                The buf from which the signature will be read.
 *                           #MBEDTLS_LMOTS_SIG_LEN bytes will be read from
 *                           this.
 *
 * \return         \c 0 on successful verification.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lmots_verify( mbedtls_lmots_public_t *ctx, const unsigned char *msg,
                          size_t msg_size, const unsigned char *sig,
                          size_t sig_size );

#ifdef MBEDTLS_LMS_PRIVATE

/**
 * \brief                    This function initializes a private LMOTS context
 *
 * \param ctx                The uninitialized LMOTS context that will then be
 *                           initialized.
 */
void mbedtls_lmots_init_private( mbedtls_lmots_private_t *ctx );

/**
 * \brief                    This function uninitializes a private LMOTS context
 *
 * \param ctx                The initialized LMOTS context that will then be
 *                           uninitialized.
 */
void mbedtls_lmots_free_private( mbedtls_lmots_private_t *ctx );

/**
 * \brief                    This function generates an LMOTS private key, and
 *                           stores in into an LMOTS context.
 *
 * \warning                  This function is **not intended for use in
 *                           production**, due to as-yet unsolved problems with
 *                           handling stateful keys.
 *
 * \note                     The seed must have at least 256 bits of entropy.
 *
 * \param ctx                The initialized LMOTS context to generate the key
 *                           into.
 * \param I_key_identifier   The key identifier of the key, as a 16-byte string.
 * \param q_leaf_identifier  The leaf identifier of key. If this LMOTS key is
 *                           not being used as part of an LMS key, this should
 *                           be set to 0.
 * \param seed               The seed used to deterministically generate the
 *                           key.
 * \param seed_size          The length of the seed.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lmots_generate_private_key( mbedtls_lmots_private_t *ctx,
                                        mbedtls_lmots_algorithm_type_t type,
                                        const unsigned char I_key_identifier[MBEDTLS_LMOTS_I_KEY_ID_LEN],
                                        uint32_t q_leaf_identifier,
                                        const unsigned char *seed,
                                        size_t seed_size );

/**
 * \brief                    This function generates an LMOTS public key from a
 *                           LMOTS context that already contains a private key.
 *
 * \note                     Before this function is called, the context must
 *                           have been initialized and the context must contain
 *                           a private key.
 *
 * \param ctx                The initialized LMOTS context to generate the key
 *                           from and store it into.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lmots_calculate_public_key( mbedtls_lmots_public_t *ctx,
                                        mbedtls_lmots_private_t *priv_ctx );


/**
 * \brief                    This function exports an LMOTS public key from a
 *                           LMOTS context that already contains a public key.
 *
 * \note                     Before this function is called, the context must
 *                           have been initialized and the context must contain
 *                           a public key.
 *
 * \note                     See IETF RFC8554 for details of the encoding of
 *                           this public key.
 *
 * \param ctx                The initialized LMOTS context that contains the
 *                           publc key.
 * \param key                The buffer into which the key will be output. Must
 *                           be at least #MBEDTLS_LMOTS_PUBLIC_KEY_LEN in size.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lmots_export_public_key( mbedtls_lmots_public_t *ctx,
                                     unsigned char *key, size_t key_size,
                                     size_t *key_len );
/**
 * \brief                    This function creates a LMOTS signature, using a
 *                           LMOTS context that contains a private key.
 *
 * \note                     Before this function is called, the context must
 *                           have been initialized and must contain a private
 *                           key.
 *
 * \note                     LMOTS private keys can only be used once, otherwise
 *                           attackers may be able to create forged signatures.
 *                           If the signing operation is successful, the private
 *                           key in the context will be erased, and no further
 *                           signing will be possible until another private key
 *                           is loaded
 *
 * \param ctx                The initialized LMOTS context from which the
 *                           private key will be read.
 * \param f_rng              The RNG function to be used for signature
 *                           generation.
 * \param p_rng              The RNG context to be passed to f_rng
 * \param msg                The buffer from which the message will be read.
 * \param msg_size           The size of the message that will be read.
 * \param sig                The buf into which the signature will be stored.
 *                           Must be at least #MBEDTLS_LMOTS_SIG_LEN in size.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lmots_sign( mbedtls_lmots_private_t *ctx,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng, const unsigned char *msg, size_t msg_size,
                        unsigned char *sig, size_t sig_size, size_t* sig_len );

#endif /* MBEDTLS_LMS_PRIVATE */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_LMOTS_H */
