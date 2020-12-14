/*
 *  PSA cipher driver entry points
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

#include <psa_crypto_cipher.h>
#include "psa_crypto_core.h"
#include "mbedtls/cipher.h"

#include <string.h>

static psa_status_t cipher_setup(
    psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    mbedtls_operation_t cipher_operation )
{
    int ret = 0;
    size_t key_bits;
    const mbedtls_cipher_info_t *cipher_info = NULL;
    psa_key_type_t key_type = attributes->core.type;

    (void)key_buffer_size;

    /* Proceed with initializing an mbed TLS cipher context if no driver is
     * available for the given algorithm & key. */
    mbedtls_cipher_init( &operation->ctx.cipher );

    /* Once the cipher context is initialised, it needs to be freed using
     * psa_cipher_abort. Indicate there is something to be freed through setting
     * alg, and indicate the operation is being done using mbedtls crypto through
     * setting mbedtls_in_use. */
    operation->alg = alg;
    operation->mbedtls_in_use = 1;

    key_bits = attributes->core.bits;
    cipher_info = mbedtls_cipher_info_from_psa( alg, key_type,
                                                key_bits, NULL );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    ret = mbedtls_cipher_setup( &operation->ctx.cipher, cipher_info );
    if( ret != 0 )
        goto exit;

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES)
    if( key_type == PSA_KEY_TYPE_DES && key_bits == 128 )
    {
        /* Two-key Triple-DES is 3-key Triple-DES with K1=K3 */
        uint8_t keys[24];
        memcpy( keys, key_buffer, 16 );
        memcpy( keys + 16, key_buffer, 8 );
        ret = mbedtls_cipher_setkey( &operation->ctx.cipher,
                                     keys,
                                     192, cipher_operation );
    }
    else
#endif
    {
        ret = mbedtls_cipher_setkey( &operation->ctx.cipher, key_buffer,
                                     (int) key_bits, cipher_operation );
    }
    if( ret != 0 )
        goto exit;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_CBC_NO_PADDING) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_CBC_PKCS7)
    switch( alg )
    {
        case PSA_ALG_CBC_NO_PADDING:
            ret = mbedtls_cipher_set_padding_mode( &operation->ctx.cipher,
                                                   MBEDTLS_PADDING_NONE );
            break;
        case PSA_ALG_CBC_PKCS7:
            ret = mbedtls_cipher_set_padding_mode( &operation->ctx.cipher,
                                                   MBEDTLS_PADDING_PKCS7 );
            break;
        default:
            /* The algorithm doesn't involve padding. */
            ret = 0;
            break;
    }
    if( ret != 0 )
        goto exit;
#endif /* MBEDTLS_PSA_BUILTIN_ALG_CBC_NO_PADDING || MBEDTLS_PSA_BUILTIN_ALG_CBC_PKCS7 */

    operation->block_size = ( PSA_ALG_IS_STREAM_CIPHER( alg ) ? 1 :
                              PSA_BLOCK_CIPHER_BLOCK_LENGTH( key_type ) );
    if( ( alg & PSA_ALG_CIPHER_FROM_BLOCK_FLAG ) != 0 &&
        alg != PSA_ALG_ECB_NO_PADDING )
    {
        operation->iv_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH( key_type );
    }
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_CHACHA20)
    else
    if( ( alg == PSA_ALG_STREAM_CIPHER ) &&
        ( key_type == PSA_KEY_TYPE_CHACHA20 ) )
        operation->iv_size = 12;
#endif

exit:
    return( mbedtls_to_psa_error( ret ) );
}

psa_status_t mbedtls_psa_cipher_encrypt_setup(
    psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg )
{
    return( cipher_setup( operation, attributes,
                          key_buffer, key_buffer_size,
                          alg, MBEDTLS_ENCRYPT ) );
}

psa_status_t mbedtls_psa_cipher_decrypt_setup(
    psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg )
{
    return( cipher_setup( operation, attributes,
                          key_buffer, key_buffer_size,
                          alg, MBEDTLS_DECRYPT ) );
}
#endif /* MBEDTLS_PSA_CRYPTO_C */
