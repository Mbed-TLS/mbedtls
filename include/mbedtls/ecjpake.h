/**
 * \file ecjpake.h
 *
 * \brief Elliptic curve J-PAKE
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
#ifndef MBEDTLS_ECJPAKE_H
#define MBEDTLS_ECJPAKE_H

#include "ecp.h"
#include "md.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    const mbedtls_md_info_t *md_info;   /**< Hash to use                    */
    mbedtls_ecp_group grp;              /**< Elliptic curve                 */

    mbedtls_ecp_point X1;               /**< Public key one                 */
    mbedtls_ecp_point X2;               /**< Public key two                 */
    mbedtls_ecp_point X3;               /**< Public key three               */
    mbedtls_ecp_point X4;               /**< Public key four                */

    mbedtls_mpi xa;                     /**< Our first secret (x1 or x3)    */
    mbedtls_mpi xb;                     /**< Our second secret (x2 or x4)   */
} mbedtls_ecjpake_context;

/*
 * \brief           Initialize a context
 *                  (just makes it ready for setup() or free()).
 *
 * \param ctx       context to initialize
 */
void mbedtls_ecjpake_init( mbedtls_ecjpake_context *ctx );

/*
 * \brief           Free a context's content
 *
 * \param ctx       context to free
 */
void mbedtls_ecjpake_free( mbedtls_ecjpake_context *ctx );

/*
 * \brief           Set up a context for use
 *
 * \note            Currently the only values for hash/curve allowed by the
 *                  standard are MBEDTLS_MD_SHA256/MBEDTLS_ECP_DP_SECP256R1.
 *
 * \param ctx       context to set up
 * \param hash      hash function to use (MBEDTLS_MD_XXX)
 * \param curve     elliptic curve identifier (MBEDTLS_ECP_DP_XXX)
 *
 * \return          0 if successfull,
 *                  a negative error code otherwise
 */
int mbedtls_ecjpake_setup( mbedtls_ecjpake_context *ctx,
                           mbedtls_md_type_t hash,
                           mbedtls_ecp_group_id curve );

#if defined(MBEDTLS_SELF_TEST)
/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if a test failed
 */
int mbedtls_ecjpake_self_test( int verbose );
#endif

#ifdef __cplusplus
}
#endif

#endif /* ecjpake.h */
