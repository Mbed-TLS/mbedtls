/**
 *  Internal MD/hash functions - no crypto, just data.
 *  This is used to avoid depending on MD_C just to query a length.
 *
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

#ifndef MBEDTLS_MD_INTERNAL_H
#define MBEDTLS_MD_INTERNAL_H

#include "common.h"

#include "mbedtls/md.h"
#include "or_psa_helpers.h"

/** Get the output length of the given hash type
 *
 * \param md_type   The hash type.
 *
 * \return          The output length in bytes, or 0 if not known
 */
static inline unsigned char mbedtls_md_internal_get_size( mbedtls_md_type_t md_type )
{
    switch( md_type )
    {
#if defined(MBEDTLS_OR_PSA_WANT_ALG_MD5)
        case MBEDTLS_MD_MD5:
            return( 16 );
#endif
#if defined(MBEDTLS_OR_PSA_WANT_ALG_RIPEMD160) || \
    defined(MBEDTLS_OR_PSA_WANT_ALG_SHA_1)
        case MBEDTLS_MD_RIPEMD160:
        case MBEDTLS_MD_SHA1:
            return( 20 );
#endif
#if defined(MBEDTLS_OR_PSA_WANT_ALG_SHA_224)
        case MBEDTLS_MD_SHA224:
            return( 28 );
#endif
#if defined(MBEDTLS_OR_PSA_WANT_ALG_SHA_256)
        case MBEDTLS_MD_SHA256:
            return( 32 );
#endif
#if defined(MBEDTLS_OR_PSA_WANT_ALG_SHA_384)
        case MBEDTLS_MD_SHA384:
            return( 48 );
#endif
#if defined(MBEDTLS_OR_PSA_WANT_ALG_SHA_512)
        case MBEDTLS_MD_SHA512:
            return( 64 );
#endif
        default:
            return( 0 );
    }
}

#endif /* MBEDTLS_MD_INTERNAL_H */
