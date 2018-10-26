/**
 * \file transform.h
 *
 * \brief Abstraction layer for record protection.
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

#ifndef MBEDTLS_MPS_TRANSFORM_H
#define MBEDTLS_MPS_TRANSFORM_H

#include <stdlib.h>
#include <stdint.h>

/*
 * \brief   Opaque representation of record protection mechanisms.
 */
struct mbedtls_mps_transform_t;
typedef struct mbedtls_mps_transform_t mbedtls_mps_transform_t;

/*
 * \brief         Structure representing an inclusion of two buffers.
 */
typedef struct
{
    unsigned char *buf; /*!< The parent buffer containing the
                         *   record payload as a sub buffer.          */
    size_t buf_len;     /*!< The length of the parent buffer.         */
    size_t data_offset; /*!< The offset of the payload sub buffer
                         *   from the beginning of the parent buffer. */
    size_t data_len;    /*!< The length of the payload sub buffer.
                         *   For more information on its use in the
                         *   Layer 2 context structure, see the
                         *   documentation of ::mps_l2.               */
} mps_l2_bufpair;

/*
 * \brief Structure representing protected and unprotected (D)TLS records.
 */
typedef struct
{
    uint64_t ctr;       /*!< The record sequence number.            */
    uint16_t epoch;     /*!< The epoch to which the record belongs. */
    uint8_t type;       /*!< The record content type.               */
    uint8_t major_ver;  /*!< The major TLS version of the record.   */
    uint8_t minor_ver;  /*!< The minor TLS version of the record.   */

    mps_l2_bufpair buf; /*!< The record's plaintext or ciphertext,
                         *   surrounded by a parent buffer. */
} mps_rec;

extern int transform_free( mbedtls_mps_transform_t *transform );

/*
 * \brief Encrypt a record using a particular protection mechanism.
 *
 * \param transform   The protection mechanism to use to encrypt the record.
 * \param rec         The plaintext record to protect. The margin around the
 *                    plaintext buffer must be large enough to hold the
 *                    record expansion, or otherwise the encryption will fail.
 * \param f_rng       A secure PRNG if needed by the protection mechanism.
 * \param p_rng       A context to be passed to \p f_rng.
 *
 * \return            \c 0 on success.
 * \return            A negative error code on failure.
 */
extern int transform_encrypt( mbedtls_mps_transform_t *transform, mps_rec *rec,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng );

/*
 * \brief Decrypt a record using a particular protection mechanism.
 *
 * \param transform   The protection mechanism to use to decrypt the record.
 * \param rec         The ciphertext record to protect.
 * \param f_rng       A secure PRNG if needed by the protection mechanism.
 * \param p_rng       A context to be passed to \p f_rng.
 *
 * \return            \c 0 on success.
 * \return            A negative error code on failure.
 */
extern int transform_decrypt( mbedtls_mps_transform_t *transform,
                              mps_rec *rec );

/*
 * \brief Obtain the encryption expansion for a record protection mechanism.
 *
 * \param transform   The protection mechanism to use.
 * \param pre_exp     The address at which to store the pre-expansion during
 *                    encryption. The pre-expansion must be known in advance
 *                    and be independent of the record that's encrypted.
 * \param post_exp    The address at which to store the maximum post-expansion
 *                    during encryption. The post-expansion may vary from record
 *                    to record, and the value returned by this function must
 *                    be such that encryption always succeeds if at least the
 *                    returned amount of space is available.
 *
 * \return            \c 0 on success.
 * \return            A negative error code on failure.
 */
extern int transform_get_expansion( mbedtls_mps_transform_t *transform,
                                    size_t *pre_exp, size_t *post_exp );

#endif /* MBEDTLS_MPS_TRANSFORM_H */
