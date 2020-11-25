/*
 *  PSA RSA layer on top of Mbed TLS crypto
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

#include "common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include <psa/crypto.h>
#include "psa_crypto_core.h"
#include "psa_crypto_rsa.h"

#include <stdlib.h>
#include <string.h>
#include "mbedtls/platform.h"
#if !defined(MBEDTLS_PLATFORM_C)
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif

#include <mbedtls/rsa.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/pk_internal.h>

#if defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY)

/* Mbed TLS doesn't support non-byte-aligned key sizes (i.e. key sizes
 * that are not a multiple of 8) well. For example, there is only
 * mbedtls_rsa_get_len(), which returns a number of bytes, and no
 * way to return the exact bit size of a key.
 * To keep things simple, reject non-byte-aligned key sizes. */
static psa_status_t psa_check_rsa_key_byte_aligned(
    const mbedtls_rsa_context *rsa )
{
    mbedtls_mpi n;
    psa_status_t status;
    mbedtls_mpi_init( &n );
    status = mbedtls_to_psa_error(
        mbedtls_rsa_export( rsa, &n, NULL, NULL, NULL, NULL ) );
    if( status == PSA_SUCCESS )
    {
        if( mbedtls_mpi_bitlen( &n ) % 8 != 0 )
            status = PSA_ERROR_NOT_SUPPORTED;
    }
    mbedtls_mpi_free( &n );
    return( status );
}

psa_status_t mbedtls_psa_rsa_load_representation(
    psa_key_type_t type, const uint8_t *data, size_t data_length,
    mbedtls_rsa_context **p_rsa )
{
    psa_status_t status;
    mbedtls_pk_context ctx;
    size_t bits;
    mbedtls_pk_init( &ctx );

    /* Parse the data. */
    if( PSA_KEY_TYPE_IS_KEY_PAIR( type ) )
        status = mbedtls_to_psa_error(
            mbedtls_pk_parse_key( &ctx, data, data_length, NULL, 0 ) );
    else
        status = mbedtls_to_psa_error(
            mbedtls_pk_parse_public_key( &ctx, data, data_length ) );
    if( status != PSA_SUCCESS )
        goto exit;

    /* We have something that the pkparse module recognizes. If it is a
     * valid RSA key, store it. */
    if( mbedtls_pk_get_type( &ctx ) != MBEDTLS_PK_RSA )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    /* The size of an RSA key doesn't have to be a multiple of 8. Mbed TLS
     * supports non-byte-aligned key sizes, but not well. For example,
     * mbedtls_rsa_get_len() returns the key size in bytes, not in bits. */
    bits = PSA_BYTES_TO_BITS( mbedtls_rsa_get_len( mbedtls_pk_rsa( ctx ) ) );
    if( bits > PSA_VENDOR_RSA_MAX_KEY_BITS )
    {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
    status = psa_check_rsa_key_byte_aligned( mbedtls_pk_rsa( ctx ) );
    if( status != PSA_SUCCESS )
        goto exit;

    /* Copy out the pointer to the RSA context, and reset the PK context
     * such that pk_free doesn't free the RSA context we just grabbed. */
    *p_rsa = mbedtls_pk_rsa( ctx );
    ctx.pk_info = NULL;

exit:
    mbedtls_pk_free( &ctx );
    return( status );
}

#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_CRYPT) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_OAEP) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_KEY_PAIR) ||
        * defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_RSA_PUBLIC_KEY) */

#endif /* MBEDTLS_PSA_CRYPTO_C */
