/**
 * \file pkcs7_write.h
 *
 * \brief PKCS7 generic defines and structures
 *  https://tools.ietf.org/html/rfc2315
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_PKCS7_WRITE_H
#define MBEDTLS_PKCS7_WRITE_H

#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "md.h"


#ifdef __cplusplus
extern "C" {
#endif

/* limited support for specific RFC syntax versions */
#define MBEDTLS_PKCS7_SIGNED_DATA_VERSION   1
#define MBEDTLS_PKCS7_SIGNER_INFO_VERSION   1

/**
 * \brief                   This function generates a PKCS7 containing SignedData (sect 9.1)
 *                          as described by RFC 2315 (https://tools.ietf.org/html/rfc2315).
 *                          It uses the given \p crts and \p keys to sign the \p data and
 *                          return a valid PKCS7 buffer, \p pkcs7.
 *
 * \param pkcs7             The resulting PKCS7, this is the output data. Allocated
 *                          internally on success.
 * \param pkcs7_size        The length of \p pkcs7.
 * \param data              The data that is to be the contents of the PKCS7.
 *                          This is what gets signed.
 *                          Pass \c NULL if data length is 0.
 * \param data_size         Length of \p data.
 *                          Pass 0 if \p data is \c NULL.
 * \param crts              Array of x509 certificates (DER).
 *                          These should have a corresponding private key
 *                          with same index in \p keys.
 *                          Support is currently limited to RSA keys only
 * \param keys              Array of private keys (DER).
 *                          Support is currently limited to RSA keys only
 * \param crt_sizes         Array of sizes for \p crts. Indexes should match
 * \param key_sizes         Array of sizes for \p keys.
 * \param key_pairs         Number of key pairs. Array length of key/crts.
 * \param hash_func         Hash function to use in digest, see mbedtls_md_type_t for
 *                          values in mbedtls/md.h
 * \param f_rng             RNG function. This must not be \c NULL.
 * \param p_rng             RNG parameter, can be \c NULL.
 * \param keys_are_sigs     Flag that is set to 0 if \p keys contains private keys
 *                          If not 0, then \p keys are considered to contain raw
 *                          signatures that were generated externally.
 *                          Useful if user does not have access to private keys.
 *
 * \note                    The caller is responisble for freeing \p pkcs7 on successful return.
 *
 * \return                  0 on success.
 * \return                  #MBEDTLS_ERR_PKCS7_INVALID_ALG if \p hash_func does not correlate to
 *                          valid \c mbedtls_md_type_t.
 * \return                  #MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA if there are any issues reading or
 *                          writing user provided input.
 * \return                  #MBEDTLS_ERR_PKCS7_ALLOC_FAILED if memory allocations fail.
 * \return                  #MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE if support is not yet
 *                          implemented (eg: signing keys are not RSA).
 * \return                  error code from mbedtls_x509_crt_parse().
 * \return                  error code from mbedtls_md().
 */
int mbedtls_pkcs7_create( unsigned char **pkcs7, size_t *pkcs7_size,
                          const unsigned char *data, size_t data_size, const unsigned char **crts,
                          const unsigned char **keys, size_t *crt_sizes, size_t *key_sizes, size_t key_pairs,
                          mbedtls_md_type_t hash_func, int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng, int keys_are_sigs );

#ifdef __cplusplus
}
#endif

#endif
