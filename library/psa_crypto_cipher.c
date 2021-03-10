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
#include "psa_crypto_random_impl.h"

#include "mbedtls/cipher.h"
#include "mbedtls/error.h"

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
    mbedtls_psa_cipher_operation_t *mbedtls_ctx = &operation->ctx.mbedtls_ctx;

    (void)key_buffer_size;

    /* Proceed with initializing an mbed TLS cipher context if no driver is
     * available for the given algorithm & key. */
    mbedtls_cipher_init( &mbedtls_ctx->cipher );

    mbedtls_ctx->alg = alg;
    key_bits = attributes->core.bits;
    cipher_info = mbedtls_cipher_info_from_psa( alg, key_type,
                                                key_bits, NULL );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    ret = mbedtls_cipher_setup( &mbedtls_ctx->cipher, cipher_info );
    if( ret != 0 )
        goto exit;

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DES)
    if( key_type == PSA_KEY_TYPE_DES && key_bits == 128 )
    {
        /* Two-key Triple-DES is 3-key Triple-DES with K1=K3 */
        uint8_t keys[24];
        memcpy( keys, key_buffer, 16 );
        memcpy( keys + 16, key_buffer, 8 );
        ret = mbedtls_cipher_setkey( &mbedtls_ctx->cipher,
                                     keys,
                                     192, cipher_operation );
    }
    else
#endif
    {
        ret = mbedtls_cipher_setkey( &mbedtls_ctx->cipher, key_buffer,
                                     (int) key_bits, cipher_operation );
    }
    if( ret != 0 )
        goto exit;

#if defined(MBEDTLS_PSA_BUILTIN_ALG_CBC_NO_PADDING) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_CBC_PKCS7)
    switch( alg )
    {
        case PSA_ALG_CBC_NO_PADDING:
            ret = mbedtls_cipher_set_padding_mode( &mbedtls_ctx->cipher,
                                                   MBEDTLS_PADDING_NONE );
            break;
        case PSA_ALG_CBC_PKCS7:
            ret = mbedtls_cipher_set_padding_mode( &mbedtls_ctx->cipher,
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

    mbedtls_ctx->block_size = ( PSA_ALG_IS_STREAM_CIPHER( alg ) ? 1 :
                              PSA_BLOCK_CIPHER_BLOCK_LENGTH( key_type ) );
    if( ( alg & PSA_ALG_CIPHER_FROM_BLOCK_FLAG ) != 0 &&
        alg != PSA_ALG_ECB_NO_PADDING )
    {
        mbedtls_ctx->iv_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH( key_type );
    }
#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_CHACHA20)
    else
    if( ( alg == PSA_ALG_STREAM_CIPHER ) &&
        ( key_type == PSA_KEY_TYPE_CHACHA20 ) )
        mbedtls_ctx->iv_size = 12;
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

psa_status_t mbedtls_psa_cipher_generate_iv(
    psa_cipher_operation_t *operation,
    uint8_t *iv, size_t iv_size, size_t *iv_length )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_psa_cipher_operation_t *mbedtls_ctx = &operation->ctx.mbedtls_ctx;

    if( iv_size < mbedtls_ctx->iv_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    ret = mbedtls_psa_get_random( MBEDTLS_PSA_RANDOM_STATE,
                                  iv, mbedtls_ctx->iv_size );
    if( ret != 0 )
        return( mbedtls_to_psa_error( ret ) );

    *iv_length = mbedtls_ctx->iv_size;

    return( mbedtls_psa_cipher_set_iv( operation, iv, *iv_length ) );
}

psa_status_t mbedtls_psa_cipher_set_iv( psa_cipher_operation_t *operation,
                                        const uint8_t *iv,
                                        size_t iv_length )
{
    mbedtls_psa_cipher_operation_t *mbedtls_ctx = &operation->ctx.mbedtls_ctx;

    if( iv_length != mbedtls_ctx->iv_size )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return( mbedtls_to_psa_error(
                mbedtls_cipher_set_iv( &mbedtls_ctx->cipher,
                                       iv, iv_length ) ) );
}

/* Process input for which the algorithm is set to ECB mode. This requires
 * manual processing, since the PSA API is defined as being able to process
 * arbitrary-length calls to psa_cipher_update() with ECB mode, but the
 * underlying mbedtls_cipher_update only takes full blocks. */
static psa_status_t psa_cipher_update_ecb(
    mbedtls_cipher_context_t *ctx,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t block_size = ctx->cipher_info->block_size;
    size_t internal_output_length = 0;
    *output_length = 0;

    if( input_length == 0 )
    {
        status = PSA_SUCCESS;
        goto exit;
    }

    if( ctx->unprocessed_len > 0 )
    {
        /* Fill up to block size, and run the block if there's a full one. */
        size_t bytes_to_copy = block_size - ctx->unprocessed_len;

        if( input_length < bytes_to_copy )
            bytes_to_copy = input_length;

        memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ),
                input, bytes_to_copy );
        input_length -= bytes_to_copy;
        input += bytes_to_copy;
        ctx->unprocessed_len += bytes_to_copy;

        if( ctx->unprocessed_len == block_size )
        {
            status = mbedtls_to_psa_error(
                mbedtls_cipher_update( ctx,
                                       ctx->unprocessed_data,
                                       block_size,
                                       output, &internal_output_length ) );

            if( status != PSA_SUCCESS )
                goto exit;

            output += internal_output_length;
            output_size -= internal_output_length;
            *output_length += internal_output_length;
            ctx->unprocessed_len = 0;
        }
    }

    while( input_length >= block_size )
    {
        /* Run all full blocks we have, one by one */
        status = mbedtls_to_psa_error(
            mbedtls_cipher_update( ctx, input,
                                   block_size,
                                   output, &internal_output_length ) );

        if( status != PSA_SUCCESS )
            goto exit;

        input_length -= block_size;
        input += block_size;

        output += internal_output_length;
        output_size -= internal_output_length;
        *output_length += internal_output_length;
    }

    if( input_length > 0 )
    {
        /* Save unprocessed bytes for later processing */
        memcpy( &( ctx->unprocessed_data[ctx->unprocessed_len] ),
                input, input_length );
        ctx->unprocessed_len += input_length;
    }

    status = PSA_SUCCESS;

exit:
    return( status );
}

psa_status_t mbedtls_psa_cipher_update( psa_cipher_operation_t *operation,
                                        const uint8_t *input,
                                        size_t input_length,
                                        uint8_t *output,
                                        size_t output_size,
                                        size_t *output_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_psa_cipher_operation_t *mbedtls_ctx = &operation->ctx.mbedtls_ctx;
    size_t expected_output_size;

    if( ! PSA_ALG_IS_STREAM_CIPHER( mbedtls_ctx->alg ) )
    {
        /* Take the unprocessed partial block left over from previous
         * update calls, if any, plus the input to this call. Remove
         * the last partial block, if any. You get the data that will be
         * output in this call. */
        expected_output_size =
            ( mbedtls_ctx->cipher.unprocessed_len + input_length )
            / mbedtls_ctx->block_size * mbedtls_ctx->block_size;
    }
    else
    {
        expected_output_size = input_length;
    }

    if( output_size < expected_output_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    if( mbedtls_ctx->alg == PSA_ALG_ECB_NO_PADDING )
    {
        /* mbedtls_cipher_update has an API inconsistency: it will only
        * process a single block at a time in ECB mode. Abstract away that
        * inconsistency here to match the PSA API behaviour. */
        status = psa_cipher_update_ecb( &mbedtls_ctx->cipher,
                                        input,
                                        input_length,
                                        output,
                                        output_size,
                                        output_length );
    }
    else
    {
        status = mbedtls_to_psa_error(
            mbedtls_cipher_update( &mbedtls_ctx->cipher, input,
                                   input_length, output, output_length ) );
    }

    return( status );
}

psa_status_t mbedtls_psa_cipher_finish( psa_cipher_operation_t *operation,
                                        uint8_t *output,
                                        size_t output_size,
                                        size_t *output_length )
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    mbedtls_psa_cipher_operation_t *mbedtls_ctx = &operation->ctx.mbedtls_ctx;
    uint8_t temp_output_buffer[MBEDTLS_MAX_BLOCK_LENGTH];

    if( mbedtls_ctx->cipher.unprocessed_len != 0 )
    {
        if( mbedtls_ctx->alg == PSA_ALG_ECB_NO_PADDING ||
            mbedtls_ctx->alg == PSA_ALG_CBC_NO_PADDING )
        {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    }

    status = mbedtls_to_psa_error(
        mbedtls_cipher_finish( &mbedtls_ctx->cipher,
                               temp_output_buffer,
                               output_length ) );
    if( status != PSA_SUCCESS )
        goto exit;

    if( *output_length == 0 )
        ; /* Nothing to copy. Note that output may be NULL in this case. */
    else if( output_size >= *output_length )
        memcpy( output, temp_output_buffer, *output_length );
    else
        status = PSA_ERROR_BUFFER_TOO_SMALL;

exit:
    mbedtls_platform_zeroize( temp_output_buffer,
                              sizeof( temp_output_buffer ) );

    return( status );
}

psa_status_t mbedtls_psa_cipher_abort( psa_cipher_operation_t *operation )
{
    mbedtls_psa_cipher_operation_t *mbedtls_ctx = &operation->ctx.mbedtls_ctx;

    /* Sanity check (shouldn't happen: operation->alg should
     * always have been initialized to a valid value). */
    if( ! PSA_ALG_IS_CIPHER( mbedtls_ctx->alg ) )
        return( PSA_ERROR_BAD_STATE );

    mbedtls_cipher_free( &mbedtls_ctx->cipher );

    return( PSA_SUCCESS );
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
