/**
 * \file ecdh_misc.h
 *
 * \brief Internal functions shared by the ECDH module
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 ( the "License" ); you may
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
#if !defined(MBEDTLS_ECDH_MISC_H)
#define MBEDTLS_ECDH_MISC_H

#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"

#if defined(MBEDTLS_ECDH_C)

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

/*
 * Setup context without Everest
 */
int mbedtls_ecdh_setup_no_everest( mbedtls_ecdh_context *ctx,
                                   mbedtls_ecp_group_id grp_id );

/*
 * TLS 1.3 version of mbedtls_ecdh_make_params
 */
int mbedtls_ecdh_tls13_make_params( mbedtls_ecdh_context *ctx, size_t *olen,
                                    unsigned char *buf, size_t buf_len,
                                    int ( *f_rng )( void *, unsigned char *, size_t ),
                                    void *p_rng );

/*
 * TLS 1.3 version of mbedtls_ecdh_read_public
 */
int mbedtls_ecdh_tls13_read_public( mbedtls_ecdh_context *ctx,
                                    const unsigned char *buf,
                                    size_t buf_len );

#endif /* MBEDTLS_SSL_PROTO_TLS1_3 */

#endif /* MBEDTLS_ECDH_C */

#endif /* !MBEDTLS_ECDH_MISC_H */
