/**
 * \file ecp_internal.h
 *
 * \brief Function declarations for alternative implementation of elliptic curve
 * point arithmetic.
 *
 *  Copyright (C) 2016, ARM Limited, All Rights Reserved
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
#ifndef MBEDTLS_ECP_FUNCTION_ALT_H
#define MBEDTLS_ECP_FUNCTION_ALT_H


#if defined(MBEDTLS_ECP_FUNCTION_ALT)

unsigned char ecp_alt_grp_capable( const mbedtls_ecp_group *grp );

#if defined(MBEDTLS_ECP_ALT_INIT)
int  ecp_alt_init( const mbedtls_ecp_group *grp );
#endif

#if defined(MBEDTLS_ECP_ALT_DEINIT)
void ecp_alt_deinit( const mbedtls_ecp_group *grp );

#if defined(MBEDTLS_ECP_RANDOMIZE_JAC_ALT)
int ecp_randomize_jac_alt( const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng );
#endif

#if defined(MBEDTLS_ECP_ADD_MIXED_ALT)
int ecp_add_mixed_alt( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                       const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q );
#endif

#if defined(MBEDTLS_ECP_DOUBLE_JAC_ALT)
int ecp_double_jac_alt( const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_ecp_point *P );
#endif

#if defined(MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT)
int ecp_normalize_jac_many_alt( const mbedtls_ecp_group *grp,
                                mbedtls_ecp_point *T[], size_t t_len );
#endif

#if defined(MBEDTLS_ECP_NORMALIZE_JAC_ALT)
int ecp_normalize_jac_alt( const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt );
#endif

#if defined(MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT)
int ecp_double_add_mxz_alt( const mbedtls_ecp_group *grp,
                            mbedtls_ecp_point *R, mbedtls_ecp_point *S,
                            const mbedtls_ecp_point *P,
                            const mbedtls_ecp_point *Q, const mbedtls_mpi *d );
#endif

#if defined(MBEDTLS_ECP_RANDOMIZE_MXZ_ALT)
int ecp_randomize_mxz_alt( const mbedtls_ecp_group *grp, mbedtls_ecp_point *P,
                           int (*f_rng)(void *, unsigned char *, size_t), 
                           void *p_rng );
#endif

#if defined(MBEDTLS_ECP_NORMALIZE_MXZ_ALT)
int ecp_normalize_mxz_alt( const mbedtls_ecp_group *grp, mbedtls_ecp_point *P );
#endif

#endif /* MBEDTLS_ECP_FUNCTION_ALT */

#endif /* ecp_function_alt.h */

