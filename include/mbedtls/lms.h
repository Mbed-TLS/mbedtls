/**
 * \file lms.h
 *
 * \brief This file provides an API for the LMS post-quantum-safe stateful-hash
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
#ifndef MBEDTLS_LMS_H
#define MBEDTLS_LMS_H

#include <stdint.h>
#include <stddef.h>

#include "mbedtls/private_access.h"
#include "mbedtls/lmots.h"

#define MBEDTLS_ERR_LMS_BAD_INPUT_DATA   -0x0011 /**< Bad data has been input to an LMS function */
#define MBEDTLS_ERR_LMS_OUT_OF_PRIV_KEYS -0x0013 /**< Specified LMS key has utilised all of its private keys */
#define MBEDTLS_ERR_LMS_VERIFY_FAILED    -0x0015 /**< LMS signature verification failed */
#define MBEDTLS_ERR_LMS_ALLOC_FAILED     -0x0017 /**< LMS failed to allocate space for a private key */

#define MBEDTLS_LMS_TYPE_LEN            (4)
#define MBEDTLS_LMS_H_TREE_HEIGHT       (10)
#define MBEDTLS_LMS_M_NODE_BYTES        (32)

#define MBEDTLS_LMS_SIG_LEN (MBEDTLS_LMOTS_Q_LEAF_ID_LEN + MBEDTLS_LMOTS_SIG_LEN + \
                             MBEDTLS_LMS_TYPE_LEN + MBEDTLS_LMS_H_TREE_HEIGHT * MBEDTLS_LMS_M_NODE_BYTES)

#define MBEDTLS_LMS_PUBKEY_LEN (MBEDTLS_LMS_TYPE_LEN + MBEDTLS_LMOTS_TYPE_LEN + \
                                MBEDTLS_LMOTS_I_KEY_ID_LEN + MBEDTLS_LMS_M_NODE_BYTES)

#define MBEDTLS_LMS_SIG_Q_LEAF_ID_OFFSET    (0)
#define MBEDTLS_LMS_SIG_OTS_SIG_OFFSET      (MBEDTLS_LMS_SIG_Q_LEAF_ID_OFFSET + MBEDTLS_LMOTS_Q_LEAF_ID_LEN)
#define MBEDTLS_LMS_SIG_TYPE_OFFSET         (MBEDTLS_LMS_SIG_OTS_SIG_OFFSET   + MBEDTLS_LMOTS_SIG_LEN)
#define MBEDTLS_LMS_SIG_PATH_OFFSET         (MBEDTLS_LMS_SIG_TYPE_OFFSET      + MBEDTLS_LMS_TYPE_LEN)

#define MBEDTLS_LMS_PUBKEY_TYPE_OFFSET      (0)
#define MBEDTLS_LMS_PUBKEY_OTSTYPE_OFFSET   (MBEDTLS_LMS_PUBKEY_TYPE_OFFSET     + MBEDTLS_LMS_TYPE_LEN)
#define MBEDTLS_LMS_PUBKEY_I_KEY_ID_OFFSET  (MBEDTLS_LMS_PUBKEY_OTSTYPE_OFFSET  + MBEDTLS_LMOTS_TYPE_LEN)
#define MBEDTLS_LMS_PUBKEY_ROOT_NODE_OFFSET (MBEDTLS_LMS_PUBKEY_I_KEY_ID_OFFSET + MBEDTLS_LMOTS_I_KEY_ID_LEN)

#ifdef __cplusplus
extern "C" {
#endif

/* https://www.iana.org/assignments/leighton-micali-signatures/leighton-micali-signatures.xhtml
 * We are only implementing a subset of the types, particularly H10, for the sake of simplicty.
 */
typedef enum {
    MBEDTLS_LMS_SHA256_M32_H10 = 0x6,
} mbedtls_lms_algorithm_type_t;


typedef struct {
    unsigned char MBEDTLS_PRIVATE(have_privkey); /*!< Whether the context contains a private key.
                                                     Boolean values only. */
    unsigned char MBEDTLS_PRIVATE(have_pubkey); /*!< Whether the context contains a public key.
                                                     Boolean values only. */
    unsigned char MBEDTLS_PRIVATE(I_key_identifier)[MBEDTLS_LMOTS_I_KEY_ID_LEN]; /*!< The key
                                                     identifier. */
    mbedtls_lms_algorithm_type_t MBEDTLS_PRIVATE(type); /*!< The LMS key type identifier as per
                                                     IANA. Only SHA256_M32_H10 is currently
                                                     supported. */
    mbedtls_lmots_algorithm_type_t MBEDTLS_PRIVATE(otstype); /*!< The LM-OTS key type identifier as
                                                     per IANA. Only SHA256_N32_W8 is currently
                                                     supported. */
    unsigned int MBEDTLS_PRIVATE(q_next_usable_key); /*!< The index of the next OTS key that has not
                                                     been used. */
    mbedtls_lmots_context *MBEDTLS_PRIVATE(priv_keys); /*!< The private key material. One OTS key
                                                     for each leaf node in the merkle tree. */
    unsigned char MBEDTLS_PRIVATE(T_1_pub_key)[MBEDTLS_LMS_M_NODE_BYTES]; /*!< The public key, in
                                                     the form of the merkle tree root node. */
} mbedtls_lms_context;


/**
 * \brief                    This function initializes an LMS context
 *
 * \param ctx                The uninitialized LMS context that will then be
 *                           initialized.
 */
void mbedtls_lms_init( mbedtls_lms_context *ctx );

/**
 * \brief                    This function uninitializes an LMS context
 *
 * \param ctx                The initialized LMS context that will then be
 *                           uninitialized.
 */
void mbedtls_lms_free( mbedtls_lms_context *ctx );

/**
 * \brief                    This function sets the type of an LMS context
 *
 * \note                     The parameter set in the context will then be used
 *                           for keygen operations etc.
 *
 * \param ctx                The initialized LMS context.
 * \param type               The type that will be set in the context.
 * \param otstype            The type of the LMOTS implementation used by this
 *                           context.
 */
int mbedtls_lms_set_algorithm_type( mbedtls_lms_context *ctx,
                                    mbedtls_lms_algorithm_type_t type,
                                    mbedtls_lmots_algorithm_type_t otstype);

/**
 * \brief                    This function creates a LMS signature, using a
 *                           LMOTS context that contains a private key.
 *
 * \note                     This function is intended for _testing purposes
 *                           only_, due to complexities around updating stateful
 *                           keys.
 *
 * \note                     Before this function is called, the context must
 *                           have been initialized and must contain a private
 *                           key.
 *
 * \note                     Each of the LMOTS private keys inside a LMS private
 *                           key can only be used once. If they are reused, then
 *                           attackers may be able to forge signatures with that
 *                           key. This is all handled transparently, but it is
 *                           important to not perform copy operations on LMS
 *                           contexts that contain private key material.
 *
 * \param ctx                The initialized LMS context from which the
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
int mbedtls_lms_sign( mbedtls_lms_context *ctx,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void* p_rng, unsigned char *msg, unsigned int msg_len,
                      unsigned char *sig);

/**
 * \brief                    This function verifies a LMS signature, using a
 *                           LMS context that contains a public key.
 *
 * \note                     Before this function is called, the context must
 *                           have been initialized and must contain a public key
 *                           (either by import or generation).
 *
 * \param ctx                The initialized LMS context from which the public
 *                           key will be read.
 * \param msg                The buffer from which the message will be read.
 * \param msg_len            The size of the message that will be read.
 * \param sig                The buf from which the signature will be read.
 *                           #MBEDTLS_LMS_SIG_LEN bytes will be read from
 *                           this.
 *
 * \return         \c 0 on successful verification.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lms_verify( const mbedtls_lms_context *ctx,
                        const unsigned char *msg, unsigned int msg_len,
                        const unsigned char *sig );

/**
 * \brief                    This function imports an LMOTS public key into a
 *                           LMS context.
 *
 * \note                     Before this function is called, the context must
 *                           have been initialized.
 *
 * \note                     See IETF RFC8554 for details of the encoding of
 *                           this public key.
 *
 * \param ctx                The initialized LMS context store the key in.
 * \param key                The buffer from which the key will be read.
 *                           #MBEDTLS_LMS_PUBKEY_LEN bytes will be read from
 *                           this.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lms_import_pubkey( mbedtls_lms_context *ctx,
                               const unsigned char *key );

/**
 * \brief                    This function exports an LMOTS public key from a
 *                           LMS context that already contains a public key.
 *
 * \note                     Before this function is called, the context must
 *                           have been initialized and the context must contain
 *                           a public key.
 *
 * \note                     See IETF RFC8554 for details of the encoding of
 *                           this public key.
 *
 * \param ctx                The initialized LMS context that contains the
 *                           publc key.
 * \param key                The buffer into which the key will be output. Must
 *                           be at least #MBEDTLS_LMS_PUBKEY_LEN in size.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lms_export_pubkey( mbedtls_lms_context *ctx,
                               unsigned char *key );

/**
 * \brief                    This function generates an LMS public key from a
 *                           LMS context that already contains a private key.
 *
 * \note                     Before this function is called, the context must
 *                           have been initialized and the context must contain
 *                           a private key.
 *
 * \param ctx                The initialized LMS context to generate the key
 *                           from and store it into.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lms_gen_pubkey( mbedtls_lms_context *ctx );

/**
 * \brief                    This function generates an LMS private key, and
 *                           stores in into an LMS context.
 *
 * \note                     Before this function is called, the context must
 *                           have been initialized and the type of the LMS
 *                           context set using mbedtls_lmots_set_algorithm_type
 *
 * \note                     The seed must have at least 256 bits of entropy.
 *
 * \param ctx                The initialized LMOTS context to generate the key
 *                           into.
 * \param f_rng              The RNG function to be used to generate the key ID.
 * \param p_rng              The RNG context to be passed to f_rng
 * \param seed               The seed used to deterministically generate the
 *                           key.
 * \param seed_len           The length of the seed.
 *
 * \return         \c 0 on success.
 * \return         A non-zero error code on failure.
 */
int mbedtls_lms_gen_privkey( mbedtls_lms_context *ctx,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void* p_rng, unsigned char *seed,
                             size_t seed_len );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_LMS_H */
