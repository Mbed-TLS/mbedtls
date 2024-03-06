/**
 * \file rsa_internal.h
 *
 * \brief Internal-only RSA public-key cryptosystem API.
 *
 * This file declares RSA-related functions that are to be used
 * only from within the Mbed TLS library itself.
 *
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_RSA_INTERNAL_H
#define MBEDTLS_RSA_INTERNAL_H

#include "mbedtls/rsa.h"

#if defined(MBEDTLS_PKCS1_V21)
/**
 * \brief This function is analogue to \c mbedtls_rsa_rsassa_pss_sign().
 *        The only difference between them is that this function is more flexible
 *        on the parameters of \p ctx that are set with \c mbedtls_rsa_set_padding().
 *
 * \note  Compared to its counterpart, this function:
 *        - does not check the padding setting of \p ctx.
 *        - allows the hash_id of \p ctx to be MBEDTLS_MD_NONE,
 *          in which case it uses \p md_alg as the hash_id.
 *
 * \note  Refer to \c mbedtls_rsa_rsassa_pss_sign() for a description
 *        of the functioning and parameters of this function.
 */
int mbedtls_rsa_rsassa_pss_sign_no_mode_check(mbedtls_rsa_context *ctx,
                                              int (*f_rng)(void *, unsigned char *, size_t),
                                              void *p_rng,
                                              mbedtls_md_type_t md_alg,
                                              unsigned int hashlen,
                                              const unsigned char *hash,
                                              unsigned char *sig);
#endif /* MBEDTLS_PKCS1_V21 */

#endif /* rsa_internal.h */
