/*
 *  PSA AEAD layer on top of Mbed TLS software crypto
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
#include "psa_crypto_aead.h"

#include "mbedtls/ccm.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/cipher.h"
#include "mbedtls/gcm.h"

#include <string.h>

/* Use builtin defines specific to this compilation unit, since the test driver
 * relies on the software driver. */
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_CCM) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_CCM) ) )
#define BUILTIN_ALG_CCM                 1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_GCM) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_GCM) ) )
#define BUILTIN_ALG_GCM                 1
#endif
#if( defined(MBEDTLS_PSA_BUILTIN_ALG_CHACHA20_POLY1305) || \
    ( defined(PSA_CRYPTO_DRIVER_TEST) && defined(MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305) ) )
#define BUILTIN_ALG_CHACHA20_POLY1305   1
#endif

/* Implement the PSA driver hash interface on top of mbed TLS if either the
 * software driver or the test driver requires it. */
#if defined(MBEDTLS_PSA_BUILTIN_AEAD) || defined(PSA_CRYPTO_DRIVER_TEST)

static const mbedtls_cipher_info_t *mbedtls_aead_cipher_info_from_psa(
    psa_algorithm_t alg,
    psa_key_type_t key_type,
    size_t key_bits,
    mbedtls_cipher_id_t* cipher_id )
{
    mbedtls_cipher_mode_t mode;
    mbedtls_cipher_id_t cipher_id_tmp;

    switch( PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg, 0 ) )
    {
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 ):
            mode = MBEDTLS_MODE_CCM;
            break;
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 ):
            mode = MBEDTLS_MODE_GCM;
            break;
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CHACHA20_POLY1305, 0 ):
            mode = MBEDTLS_MODE_CHACHAPOLY;
            break;
        default:
            return( NULL );
    }

    switch( key_type )
    {
        case PSA_KEY_TYPE_AES:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_AES;
            break;
        case PSA_KEY_TYPE_DES:
            /* key_bits is 64 for Single-DES, 128 for two-key Triple-DES,
             * and 192 for three-key Triple-DES. */
            if( key_bits == 64 )
                cipher_id_tmp = MBEDTLS_CIPHER_ID_DES;
            else
                cipher_id_tmp = MBEDTLS_CIPHER_ID_3DES;
            /* mbedtls doesn't recognize two-key Triple-DES as an algorithm,
             * but two-key Triple-DES is functionally three-key Triple-DES
             * with K1=K3, so that's how we present it to mbedtls. */
            if( key_bits == 128 )
                key_bits = 192;
            break;
        case PSA_KEY_TYPE_CAMELLIA:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_CAMELLIA;
            break;
        case PSA_KEY_TYPE_ARC4:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_ARC4;
            break;
        case PSA_KEY_TYPE_CHACHA20:
            cipher_id_tmp = MBEDTLS_CIPHER_ID_CHACHA20;
            break;
        default:
            return( NULL );
    }
    if( cipher_id != NULL )
        *cipher_id = cipher_id_tmp;

    return( mbedtls_cipher_info_from_values( cipher_id_tmp,
                                             (int) key_bits, mode ) );
}

typedef union {
    unsigned dummy;
#if defined(MBEDTLS_CCM_C)
    mbedtls_ccm_context ccm;
#endif /* MBEDTLS_CCM_C */
#if defined(MBEDTLS_GCM_C)
    mbedtls_gcm_context gcm;
#endif /* MBEDTLS_GCM_C */
#if defined(MBEDTLS_CHACHAPOLY_C)
    mbedtls_chachapoly_context chachapoly;
#endif /* MBEDTLS_CHACHAPOLY_C */
} mbedtls_aead_context_t;

static psa_status_t aead_validate_and_get_tag_length( psa_status_t alg,
                                                      size_t *tag_length )
{
    switch( PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg, 0 ) )
    {
#if defined(BUILTIN_ALG_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 ):
            if( PSA_AEAD_TAG_LENGTH( alg ) > 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            *tag_length = PSA_AEAD_TAG_LENGTH( alg );
            return( PSA_SUCCESS );
#endif /* BUILTIN_ALG_CCM */
#if defined(BUILTIN_ALG_GCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 ):
            if( PSA_AEAD_TAG_LENGTH( alg ) > 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            *tag_length = PSA_AEAD_TAG_LENGTH( alg );
            return( PSA_SUCCESS );
#endif /* BUILTIN_ALG_CCM */
#if defined(BUILTIN_ALG_CHACHA20_POLY1305)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CHACHA20_POLY1305, 0 ):
            if( PSA_AEAD_TAG_LENGTH( alg ) > 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            *tag_length = PSA_AEAD_TAG_LENGTH( alg );
            return( PSA_SUCCESS );
#endif /* BUILTIN_ALG_CHACHA20_POLY1305 */
    }

    return( PSA_ERROR_NOT_SUPPORTED );
}

static void aead_context_setup( mbedtls_aead_context_t *ctx )
{
    memset( ctx, 0, sizeof(mbedtls_aead_context_t) );
}

static void aead_context_teardown( psa_algorithm_t alg,
                                   mbedtls_aead_context_t *ctx )
{
    switch( PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg, 0 ) )
    {
#if defined(BUILTIN_ALG_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 ):
            mbedtls_ccm_free( &ctx->ccm );
            break;
#endif /* BUILTIN_ALG_CCM */
#if defined(BUILTIN_ALG_GCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 ):
            mbedtls_gcm_free( &ctx->gcm );
            break;
#endif /* BUILTIN_ALG_CCM */
#if defined(BUILTIN_ALG_CHACHA20_POLY1305)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CHACHA20_POLY1305, 0 ):
            mbedtls_chachapoly_free( &ctx->chachapoly );
            break;
#endif /* BUILTIN_ALG_CHACHA20_POLY1305 */
    }
}

static psa_status_t aead_set_key( mbedtls_aead_context_t *ctx,
                                  psa_algorithm_t alg,
                                  const psa_key_attributes_t *attributes,
                                  const uint8_t *key_buffer,
                                  size_t key_buffer_size )
{
    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_id_t cipher_id;

    /* Check the underlying cipher is available in this library */
    cipher_info = mbedtls_aead_cipher_info_from_psa(
                    alg,
                    psa_get_key_type( attributes ),
                    psa_get_key_bits( attributes ),
                    &cipher_id );
    if( cipher_info == NULL )
        return( PSA_ERROR_NOT_SUPPORTED );

    if( PSA_BITS_TO_BYTES( cipher_info->key_bitlen ) != key_buffer_size )
        return( PSA_ERROR_INVALID_ARGUMENT );

    /* Set the key on the Mbed TLS context structure */
    switch( PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg, 0 ) )
    {
#if defined(BUILTIN_ALG_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 ):
            /* CCM allows the following tag lengths: 4, 6, 8, 10, 12, 14, 16.
             * The call to mbedtls_ccm_encrypt_and_tag or
             * mbedtls_ccm_auth_decrypt will validate the tag length. */
            if( PSA_BLOCK_CIPHER_BLOCK_LENGTH( psa_get_key_type( attributes ) ) != 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );

            mbedtls_ccm_init( &ctx->ccm );
            return(
                mbedtls_to_psa_error(
                    mbedtls_ccm_setkey( &ctx->ccm, cipher_id,
                                        key_buffer,
                                        PSA_BYTES_TO_BITS( key_buffer_size ) ) ) );
#endif /* BUILTIN_ALG_CCM */

#if defined(BUILTIN_ALG_GCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 ):
            /* GCM allows the following tag lengths: 4, 8, 12, 13, 14, 15, 16.
             * The call to mbedtls_gcm_crypt_and_tag or
             * mbedtls_gcm_auth_decrypt will validate the tag length. */
            if( PSA_BLOCK_CIPHER_BLOCK_LENGTH( psa_get_key_type( attributes ) ) != 16 )
                return( PSA_ERROR_INVALID_ARGUMENT );

            mbedtls_gcm_init( &ctx->gcm );
            return(
                mbedtls_to_psa_error(
                    mbedtls_gcm_setkey( &ctx->gcm, cipher_id,
                                        key_buffer,
                                        PSA_BYTES_TO_BITS( key_buffer_size ) ) ) );
#endif /* BUILTIN_ALG_GCM */

#if defined(BUILTIN_ALG_CHACHA20_POLY1305)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CHACHA20_POLY1305, 0 ):
            /* We only support the default tag length. */
            if( alg != PSA_ALG_CHACHA20_POLY1305 )
                return( PSA_ERROR_NOT_SUPPORTED );

            mbedtls_chachapoly_init( &ctx->chachapoly );
            return(
                mbedtls_to_psa_error(
                    mbedtls_chachapoly_setkey( &ctx->chachapoly,
                                               key_buffer ) ) );
#endif /* BUILTIN_ALG_CHACHA20_POLY1305 */

        default:
            (void) ctx;
            (void) key_buffer;
            return( PSA_ERROR_NOT_SUPPORTED );
    }
}

static psa_status_t aead_encrypt( const psa_key_attributes_t *attributes,
                                  const uint8_t *key_buffer,
                                  size_t key_buffer_size,
                                  psa_algorithm_t alg,
                                  const uint8_t *nonce,
                                  size_t nonce_length,
                                  const uint8_t *additional_data,
                                  size_t additional_data_length,
                                  const uint8_t *plaintext,
                                  size_t plaintext_length,
                                  uint8_t *ciphertext,
                                  size_t ciphertext_size,
                                  size_t *ciphertext_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_aead_context_t ctx;
    size_t tag_length = PSA_AEAD_TAG_LENGTH( alg );
    uint8_t *tag;

    /* Validate that the requested algorithm is capable of the requested tag
     * length, and simultaneously validate that this library is capable of
     * executing the requested algorithm. */
    status = aead_validate_and_get_tag_length( alg, &tag_length );
    if( status != PSA_SUCCESS )
        return( status );

    /* Now that we know we should be able to execute this algorithm, set up a
     * Mbed TLS context structure. */
    aead_context_setup( &ctx );

    /* Set the key on this context */
    status = aead_set_key( &ctx, alg, attributes, key_buffer, key_buffer_size );
    if( status != PSA_SUCCESS )
        goto exit;

    /* For all currently supported modes, the tag is at the end of the
     * ciphertext. */
    if( ciphertext_size < ( plaintext_length + tag_length ) )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }
    tag = ciphertext + plaintext_length;

    /* Execute the actual AEAD operation. */
    switch( PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg, 0 ) )
    {
#if defined(BUILTIN_ALG_GCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 ):
            status = mbedtls_to_psa_error(
                mbedtls_gcm_crypt_and_tag( &ctx.gcm,
                                           MBEDTLS_GCM_ENCRYPT,
                                           plaintext_length,
                                           nonce, nonce_length,
                                           additional_data,
                                           additional_data_length,
                                           plaintext, ciphertext,
                                           tag_length, tag ) );
            break;
#endif /* BUILTIN_ALG_GCM */
#if defined(BUILTIN_ALG_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 ):
            status = mbedtls_to_psa_error(
                mbedtls_ccm_encrypt_and_tag( &ctx.ccm,
                                             plaintext_length,
                                             nonce, nonce_length,
                                             additional_data,
                                             additional_data_length,
                                             plaintext, ciphertext,
                                             tag, tag_length ) );
            break;
#endif /* BUILTIN_ALG_CCM */
#if defined(BUILTIN_ALG_CHACHA20_POLY1305)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CHACHA20_POLY1305, 0 ):
            if( nonce_length != 12 || tag_length != 16 )
            {
                status = PSA_ERROR_NOT_SUPPORTED;
                goto exit;
            }
            status = mbedtls_to_psa_error(
                mbedtls_chachapoly_encrypt_and_tag( &ctx.chachapoly,
                                                    plaintext_length,
                                                    nonce,
                                                    additional_data,
                                                    additional_data_length,
                                                    plaintext,
                                                    ciphertext,
                                                    tag ) );
            break;
#endif /* BUILTIN_ALG_CHACHA20_POLY1305 */
        default:
            (void) nonce;
            (void) nonce_length;
            (void) additional_data;
            (void) additional_data_length;
            (void) plaintext;
            (void) tag;
            status = PSA_ERROR_CORRUPTION_DETECTED;
            break;
    }

    if( status != PSA_SUCCESS && ciphertext_size != 0 )
        memset( ciphertext, 0, ciphertext_size );

exit:
    aead_context_teardown( alg, &ctx );
    if( status == PSA_SUCCESS )
        *ciphertext_length = plaintext_length + tag_length;
    return( status );
}

/* Locate the tag in a ciphertext buffer containing the encrypted data
 * followed by the tag. Return the length of the part preceding the tag in
 * *plaintext_length. This is the size of the plaintext in modes where
 * the encrypted data has the same size as the plaintext, such as
 * CCM and GCM. */
static psa_status_t psa_aead_unpadded_locate_tag( size_t tag_length,
                                                  const uint8_t *ciphertext,
                                                  size_t ciphertext_length,
                                                  size_t plaintext_size,
                                                  const uint8_t **p_tag )
{
    size_t payload_length;
    if( tag_length > ciphertext_length )
        return( PSA_ERROR_INVALID_ARGUMENT );
    payload_length = ciphertext_length - tag_length;
    if( payload_length > plaintext_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );
    *p_tag = ciphertext + payload_length;
    return( PSA_SUCCESS );
}

static psa_status_t aead_decrypt( const psa_key_attributes_t *attributes,
                                  const uint8_t *key_buffer,
                                  size_t key_buffer_size,
                                  psa_algorithm_t alg,
                                  const uint8_t *nonce,
                                  size_t nonce_length,
                                  const uint8_t *additional_data,
                                  size_t additional_data_length,
                                  const uint8_t *ciphertext,
                                  size_t ciphertext_length,
                                  uint8_t *plaintext,
                                  size_t plaintext_size,
                                  size_t *plaintext_length )
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_aead_context_t ctx;
    size_t tag_length = 0;
    const uint8_t *tag;

    /* Validate that the requested algorithm is capable of the requested tag
     * length, and simultaneously validate that this library is capable of
     * executing the requested algorithm. */
    status = aead_validate_and_get_tag_length( alg, &tag_length );
    if( status != PSA_SUCCESS )
        return( status );

    /* Now that we know we should be able to execute this algorithm, set up a
     * Mbed TLS context structure. */
    aead_context_setup( &ctx );

     /* Set the key on this context */
    status = aead_set_key( &ctx, alg, attributes, key_buffer, key_buffer_size );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_aead_unpadded_locate_tag( tag_length,
                                           ciphertext, ciphertext_length,
                                           plaintext_size, &tag );
    if( status != PSA_SUCCESS )
        goto exit;

    /* Execute the actual AEAD operation. */
    switch( PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg, 0 ) )
    {
#if defined(BUILTIN_ALG_GCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 ):
            status = mbedtls_to_psa_error(
                mbedtls_gcm_auth_decrypt( &ctx.gcm,
                                          ciphertext_length - tag_length,
                                          nonce, nonce_length,
                                          additional_data,
                                          additional_data_length,
                                          tag, tag_length,
                                          ciphertext, plaintext ) );
            break;
#endif /* BUILTIN_ALG_GCM */
#if defined(BUILTIN_ALG_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 ):
            status = mbedtls_to_psa_error(
                mbedtls_ccm_auth_decrypt( &ctx.ccm,
                                          ciphertext_length - tag_length,
                                          nonce, nonce_length,
                                          additional_data,
                                          additional_data_length,
                                          ciphertext, plaintext,
                                          tag, tag_length ) );
            break;
#endif /* BUILTIN_ALG_CCM */
#if defined(BUILTIN_ALG_CHACHA20_POLY1305)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CHACHA20_POLY1305, 0 ):
            if( nonce_length != 12 || tag_length != 16 )
            {
                status = PSA_ERROR_NOT_SUPPORTED;
                goto exit;
            }
            status = mbedtls_to_psa_error(
                mbedtls_chachapoly_auth_decrypt( &ctx.chachapoly,
                                                 ciphertext_length - tag_length,
                                                 nonce,
                                                 additional_data,
                                                 additional_data_length,
                                                 tag,
                                                 ciphertext,
                                                 plaintext ) );
            break;
#endif /* BUILTIN_ALG_CHACHA20_POLY1305 */
        default:
            (void) nonce;
            (void) nonce_length;
            (void) additional_data;
            (void) additional_data_length;
            (void) plaintext;
            (void) tag;
            status = PSA_ERROR_CORRUPTION_DETECTED;
            break;
    }

    if( status != PSA_SUCCESS && plaintext_size != 0 )
        memset( plaintext, 0, plaintext_size );

exit:
    aead_context_teardown( alg, &ctx );
    if( status == PSA_SUCCESS )
        *plaintext_length = ciphertext_length - tag_length;
    return( status );
}
#endif /* MBEDTLS_PSA_BUILTIN_AEAD || PSA_CRYPTO_DRIVER_TEST */

#if defined(MBEDTLS_PSA_BUILTIN_AEAD)
psa_status_t mbedtls_psa_aead_encrypt( const psa_key_attributes_t *attributes,
                                       const uint8_t *key_buffer,
                                       size_t key_buffer_size,
                                       psa_algorithm_t alg,
                                       const uint8_t *nonce,
                                       size_t nonce_length,
                                       const uint8_t *additional_data,
                                       size_t additional_data_length,
                                       const uint8_t *plaintext,
                                       size_t plaintext_length,
                                       uint8_t *ciphertext,
                                       size_t ciphertext_size,
                                       size_t *ciphertext_length )
{
    return ( aead_encrypt( attributes, key_buffer, key_buffer_size, alg,
                           nonce, nonce_length,
                           additional_data, additional_data_length,
                           plaintext, plaintext_length,
                           ciphertext, ciphertext_size, ciphertext_length ) );
}

psa_status_t mbedtls_psa_aead_decrypt( const psa_key_attributes_t *attributes,
                                       const uint8_t *key_buffer,
                                       size_t key_buffer_size,
                                       psa_algorithm_t alg,
                                       const uint8_t *nonce,
                                       size_t nonce_length,
                                       const uint8_t *additional_data,
                                       size_t additional_data_length,
                                       const uint8_t *ciphertext,
                                       size_t ciphertext_length,
                                       uint8_t *plaintext,
                                       size_t plaintext_size,
                                       size_t *plaintext_length )
{
    return ( aead_decrypt( attributes, key_buffer, key_buffer_size, alg,
                           nonce, nonce_length,
                           additional_data, additional_data_length,
                           ciphertext, ciphertext_length,
                           plaintext, plaintext_size, plaintext_length ) );
}
#endif /* MBEDTLS_PSA_BUILTIN_AEAD */

 /*
  * BEYOND THIS POINT, TEST DRIVER ENTRY POINTS ONLY.
  */
#if defined(PSA_CRYPTO_DRIVER_TEST)

static psa_status_t is_aead_accelerated( psa_algorithm_t alg )
{
    switch( PSA_ALG_AEAD_WITH_SHORTENED_TAG( alg, 0 ) )
    {
#if defined(MBEDTLS_PSA_ACCEL_ALG_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CCM, 0 ):
            return( PSA_SUCCESS );
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_GCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_GCM, 0 ):
            return( PSA_SUCCESS );
#endif
#if defined(MBEDTLS_PSA_ACCEL_ALG_CHACHA20_POLY1305)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG( PSA_ALG_CHACHA20_POLY1305, 0 ):
            return( PSA_SUCCESS );
#endif
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }
}

psa_status_t mbedtls_transparent_test_driver_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length )
{
    if( is_aead_accelerated( alg ) == PSA_SUCCESS )
    {
        return( aead_encrypt( attributes, key_buffer, key_buffer_size, alg,
                              nonce, nonce_length,
                              additional_data, additional_data_length,
                              plaintext, plaintext_length,
                              ciphertext, ciphertext_size, ciphertext_length ) );
    }
    else
        return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_transparent_test_driver_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length )
{
    if( is_aead_accelerated( alg ) == PSA_SUCCESS )
    {
        return( aead_decrypt( attributes, key_buffer, key_buffer_size, alg,
                              nonce, nonce_length,
                              additional_data, additional_data_length,
                              ciphertext, ciphertext_length,
                              plaintext, plaintext_size, plaintext_length ) );
    }
    else
        return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) nonce;
    (void) nonce_length;
    (void) additional_data;
    (void) additional_data_length;
    (void) plaintext;
    (void) plaintext_length,
    (void) ciphertext;
    (void) ciphertext_size;
    (void) ciphertext_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_opaque_test_driver_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce,
    size_t nonce_length,
    const uint8_t *additional_data,
    size_t additional_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length )
{
    /* Opaque driver testing is not implemented yet through this mechanism. */
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) nonce;
    (void) nonce_length;
    (void) additional_data;
    (void) additional_data_length;
    (void) ciphertext;
    (void) ciphertext_length,
    (void) plaintext;
    (void) plaintext_size;
    (void) plaintext_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

#endif /* PSA_CRYPTO_DRIVER_TEST */

#endif /* MBEDTLS_PSA_CRYPTO_C */
