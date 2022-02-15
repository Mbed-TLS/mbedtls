
/**
 * \file ecp_internal.h
 *
 * \brief ECC-related functions with external linkage but which are
 *        not part of the public API.
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
#ifndef MBEDTLS_ECP_INTERNAL_H
#define MBEDTLS_ECP_INTERNAL_H

#include "common.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"

static inline mbedtls_ecp_group_id mbedtls_ecp_named_group_to_id(
    uint16_t named_curve )
{
    const mbedtls_ecp_curve_info *curve_info;
    curve_info = mbedtls_ecp_curve_info_from_tls_id( named_curve );
    if( curve_info == NULL )
        return( MBEDTLS_ECP_DP_NONE );
    return( curve_info->grp_id );
}

int mbedtls_ecdh_import_public_raw( mbedtls_ecdh_context *ctx,
                                    const unsigned char *buf,
                                    const unsigned char *end );

#endif /* MBEDTLS_ECP_INTERNAL_H */
