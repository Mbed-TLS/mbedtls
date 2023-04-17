/**
 * \file pk_internal.h
 *
 * \brief Public Key abstraction layer: internal (i.e. library only) functions
 *        and definitions.
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
#ifndef MBEDTLS_PK_INTERNAL_H
#define MBEDTLS_PK_INTERNAL_H

#include "mbedtls/pk.h"

#if defined(MBEDTLS_ECP_LIGHT)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif

#if defined(MBEDTLS_ECP_LIGHT) && defined(MBEDTLS_USE_PSA_CRYPTO)
/**
 * Return the raw public key content on the provided buffer.
 *
 * \param pk        The PK context that will be used to extract the public key.
 * \param buf       The output buffer into which the key will be copied
 * \param buf_size  The size of the output buffer
 * \param key_len   The effective length of the key copied into the output
 *                  buffer.
 *
 * \return          0, on success;
 *                  MBEDTLS_ERR_PK_BAD_INPUT_DATA if the provided PK context
 *                      is not valid or if there is no public key stored in it;
 *                  MBEDTLS_ERR_PK_BUFFER_TOO_SMALL if the provided output
 *                      buffer is too small to contain the public key.
 */
int mbedtls_pk_get_public_key(mbedtls_pk_context *pk, unsigned char *buf,
                              size_t buf_size, size_t *key_len);

/**
 * Return EC parameter used in the given PK context.
 *
 * \param pk        The PK context that from which the EC's key properties will
 *                  be get.
 * \param ec_curve  Output variable that will get the EC family.
 * \param bits      Output variable that will get the number of bits used for
 *                  the EC curve.
 *
 * \return          0, on success;
 *                  MBEDTLS_ERR_PK_BAD_INPUT_DATA if the provided pointers are
 *                      not valid or if the provided PK context has no valid
 *                      EC properties set.
 */
int mbedtls_pk_get_ec_public_key_props(mbedtls_pk_context *pk,
                                       psa_ecc_family_t *ec_curve,
                                       size_t *bits);

/**
 * \brief   Copy the public key content in raw format from "ctx->pk_ctx"
 *          (which is an ecp_keypair) into the internal "ctx->pk_raw" buffer.
 *
 * \note    This is a temporary function that can be removed as soon as the pk
 *          module is free from ECP_C
 *
 * \param pk   It is the pk_context which is going to be updated. It acts both
 *             as input and output.
 */
int mbedtls_pk_update_public_key_from_keypair(mbedtls_pk_context *pk);

/**
 * \brief   Copy the public key content from the internal raw buffer, "ctx->pk_raw",
 *          to the ecp_keypair structure, "ctx->pk_ctx".
 *
 * \note    This is a temporary function that can be removed as soon as the pk
 *          module is free from ECP_C
 *
 * \param pk   It is the pk_context which is going to be updated. It acts both
 *             as input and output.
 */
int mbedtls_pk_update_keypair_from_public_key(mbedtls_pk_context *pk);
#endif /* MBEDTLS_ECP_LIGHT && MBEDTLS_USE_PSA_CRYPTO */

#endif /* MBEDTLS_PK_INTERNAL_H */
