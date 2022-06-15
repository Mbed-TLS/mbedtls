/**
 * \file lmots.h
 *
 * \brief This file provides an API for the LM-OTS post-quantum-safe one-time
 *        public-key signature scheme.
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

#include "mbedtls/private_access.h"

#include <stdint.h>
#include <stddef.h>

#define MBEDTLS_ERR_LMOTS_BAD_INPUT_DATA -0x0076 /**< Bad data has been input to an LMOTS function */
#define MBEDTLS_ERR_LMOTS_VERIFY_FAILED  -0x0078 /**< LMOTS signature verification failed */

#define MBEDTLS_LMOTS_N_HASH_LEN            (32)
#define MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN      (34)
#define MBEDTLS_LMOTS_TYPE_LEN              (4)
#define MBEDTLS_LMOTS_C_RANDOM_VALUE_LEN    (MBEDTLS_LMOTS_N_HASH_LEN)
#define MBEDTLS_LMOTS_I_KEY_ID_LEN          (16)
#define MBEDTLS_LMOTS_Q_LEAF_ID_LEN         (4)

#define MBEDTLS_LMOTS_SIG_LEN (MBEDTLS_LMOTS_TYPE_LEN + MBEDTLS_LMOTS_C_RANDOM_VALUE_LEN + \
                               (MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN * MBEDTLS_LMOTS_N_HASH_LEN))

#define MBEDTLS_LMOTS_PUBKEY_LEN (MBEDTLS_LMOTS_TYPE_LEN + MBEDTLS_LMOTS_I_KEY_ID_LEN + \
                                  MBEDTLS_LMOTS_Q_LEAF_ID_LEN + MBEDTLS_LMOTS_N_HASH_LEN)

#define MBEDTLS_LMOTS_SIG_TYPE_OFFSET      (0)
#define MBEDTLS_LMOTS_SIG_C_RANDOM_OFFSET  (MBEDTLS_LMOTS_SIG_TYPE_OFFSET     + MBEDTLS_LMOTS_TYPE_LEN)
#define MBEDTLS_LMOTS_SIG_SIGNATURE_OFFSET (MBEDTLS_LMOTS_SIG_C_RANDOM_OFFSET + MBEDTLS_LMOTS_C_RANDOM_VALUE_LEN)

#define MBEDTLS_LMOTS_PUBKEY_TYPE_OFFSET      (0)
#define MBEDTLS_LMOTS_PUBKEY_I_KEY_ID_OFFSET  (MBEDTLS_LMOTS_PUBKEY_TYPE_OFFSET      + MBEDTLS_LMOTS_TYPE_LEN)
#define MBEDTLS_LMOTS_PUBKEY_Q_LEAF_ID_OFFSET (MBEDTLS_LMOTS_PUBKEY_I_KEY_ID_OFFSET  + MBEDTLS_LMOTS_I_KEY_ID_LEN)
#define MBEDTLS_LMOTS_PUBKEY_KEY_HASH_OFFSET  (MBEDTLS_LMOTS_PUBKEY_Q_LEAF_ID_OFFSET + MBEDTLS_LMOTS_Q_LEAF_ID_LEN)


#ifdef __cplusplus
extern "C" {
#endif

/* https://www.iana.org/assignments/leighton-micali-signatures/leighton-micali-signatures.xhtml
 * We are only implementing a subset of the types, particularly n32_w8, for the sake of simplicty.
 */
typedef enum {
    MBEDTLS_LMOTS_SHA256_N32_W8 = 4
} mbedtls_lmots_algorithm_type_t;


typedef struct {
    unsigned char MBEDTLS_PRIVATE(have_privkey); /*!< Whether the context contains a private key.
                                                     Boolean values only. */
    unsigned char MBEDTLS_PRIVATE(have_pubkey); /*!< Whether the context contains a public key.
                                                     Boolean values only. */
    unsigned char MBEDTLS_PRIVATE(I_key_identifier[MBEDTLS_LMOTS_I_KEY_ID_LEN]); /*!< The key
                                                     identifier. */
    unsigned int MBEDTLS_PRIVATE(q_leaf_identifier); /*!< Which leaf of the LMS key this is.
                                                     0 if the key is not part of an LMS key. */
    unsigned char MBEDTLS_PRIVATE(q_leaf_identifier_bytes)[MBEDTLS_LMOTS_Q_LEAF_ID_LEN];/*!< The
                                                     leaf identifier in network bytes form. */
    mbedtls_lmots_algorithm_type_t MBEDTLS_PRIVATE(type); /*!< The LM-OTS key type identifier as
                                                     per IANA. Only SHA256_N32_W8 is currently
                                                     supported. */
    unsigned char MBEDTLS_PRIVATE(priv_key[MBEDTLS_LMOTS_P_SIG_SYMBOL_LEN][32]); /*!< The private
                                                     key, one hash output per byte of the encoded
                                                     symbol string P (32 bytes of hash output +
                                                     2 bytes of checksum). */
    unsigned char MBEDTLS_PRIVATE(pub_key[32]); /*!< The public key, in the form of a SHA256
                                                     output. */
} mbedtls_lmots_context;


/**
 * \brief                    This function initializes an LMOTS context
 *
 * \param ctx                The uninitialized LMOTS context that will then be
 *                           initialized.
 */
void mbedtls_lmots_init( mbedtls_lmots_context *ctx );

/**
 * \brief                    This function uninitializes an LMOTS context
 *
 * \param ctx                The initialized LMOTS context that will then be
 *                           uninitialized.
 */
void mbedtls_lmots_free( mbedtls_lmots_context *ctx );

/**
 * \brief                    This function sets the type of an LMOTS context
 *
 * \note                     The parameter set in the context will then be used
 *                           for keygen operations etc.
 *
 * \param ctx                The initialized LMOTS context.
 * \param type               The type that will be set in the context.
 */
int mbedtls_lmots_set_algorithm_type( mbedtls_lmots_context *ctx,
                                      mbedtls_lmots_algorithm_type_t type );

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
 * \param I_key_identifier   The key identifier of the key, as a 16 byte
 *                           bytestring.
 * \param q_leaf_identifier  The leaf identifier of key. If this LMOTS key is
 *                           not being used as part of an LMS key, this should
 *                           be set to 0.
 * \param msg                The buffer from which the message will be read.
 * \param msg_len            The size of the message that will be read.
 * \param sig                The buff from which the signature will be read.
 *                           MBEDTLS_LMOTS_SIG_LEN bytes will be read from this.
 * \param out                The buffer where the candidate public key will be
 *                           stored. Must be at least #MBEDTLS_LMOTS_N_HASH_LEN
 *                           bytes in size.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lmots_generate_pub_key_candidate( const unsigned char I_key_identifier[MBEDTLS_LMOTS_I_KEY_ID_LEN],
                                              const unsigned char q_leaf_identifier[MBEDTLS_LMOTS_Q_LEAF_ID_LEN],
                                              const unsigned char  *msg,
                                              size_t msg_len,
                                              const unsigned char *sig,
                                              unsigned char *out );

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
 * \param msg_len            The size of the message that will be read.
 * \param sig                The buf into which the signature will be stored.
 *                           Must be at least #MBEDTLS_LMOTS_SIG_LEN in size.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lmots_sign( mbedtls_lmots_context *ctx,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng, const unsigned char *msg, size_t msg_len,
                        unsigned char *sig );

/**
 * \brief                    This function verifies a LMOTS signature, using a
 *                           LMOTS context that contains a public key.
 *
 * \note                     Before this function is called, the context must
 *                           have been initialized and must contain a public key
 *                           (either by import or generation).
 *
 * \param ctx                The initialized LMOTS context from which the public
 *                           key will be read.
 * \param msg                The buffer from which the message will be read.
 * \param msg_len            The size of the message that will be read.
 * \param sig                The buf from which the signature will be read.
 *                           #MBEDTLS_LMOTS_SIG_LEN bytes will be read from
 *                           this.
 *
 * \return         \c 0 on successful verification.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lmots_verify( mbedtls_lmots_context *ctx, const unsigned char *msg,
                          size_t msg_len, const unsigned char *sig );

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
 *                           #MBEDTLS_LMOTS_PUBKEY_LEN bytes will be read from
 *                           this.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lmots_import_pubkey( mbedtls_lmots_context *ctx,
                                 const unsigned char *key );

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
 *                           be at least #MBEDTLS_LMOTS_PUBKEY_LEN in size.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lmots_export_pubkey( mbedtls_lmots_context *ctx,
                                 unsigned char *key );

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
int mbedtls_lmots_gen_pubkey( mbedtls_lmots_context *ctx );

/**
 * \brief                    This function generates an LMOTS private key, and
 *                           stores in into an LMOTS context.
 *
 * \note                     Before this function is called, the context must
 *                           have been initialized and the type of the LMOTS
 *                           context set using mbedtls_lmots_set_algorithm_type
 *
 * \note                     The seed must have at least 256 bits of entropy.
 *
 * \param ctx                The initialized LMOTS context to generate the key
 *                           into.
 * \param I_key_identifier   The key identifier of the key, as a 16 byte
 *                           bytestring.
 * \param q_leaf_identifier  The leaf identifier of key. If this LMOTS key is
 *                           not being used as part of an LMS key, this should
 *                           be set to 0.
 * \param seed               The seed used to deterministically generate the
 *                           key.
 * \param seed_len           The length of the seed.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lmots_gen_privkey( mbedtls_lmots_context *ctx,
                               const unsigned char I_key_identifier[MBEDTLS_LMOTS_I_KEY_ID_LEN],
                               unsigned int q_leaf_identifier,
                               const unsigned char *seed,
                               size_t seed_len );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_LMOTS_H */
