/**
 * \file cipher_light.c
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

#include "common.h"

#include "cipher_light_internal.h"

#if defined(MBEDTLS_CIPHER_LIGHT)

void mbedtls_cipher_light_free(mbedtls_cipher_light_context_t *ctx)
{
    switch (ctx->id) {
#if defined(MBEDTLS_AES_C)
        case MBEDTLS_CIPHER_LIGHT_ID_AES:
            mbedtls_aes_free(&ctx->ctx.aes);
            break;
#endif
#if defined(MBEDTLS_ARIA_C)
        case MBEDTLS_CIPHER_LIGHT_ID_ARIA:
            mbedtls_aria_free(&ctx->ctx.aria);
            break;
#endif
#if defined(MBEDTLS_CAMELLIA_C)
        case MBEDTLS_CIPHER_LIGHT_ID_CAMELLIA:
            mbedtls_camellia_free(&ctx->ctx.camellia);
            break;
#endif
        default:
            break;
    }
    ctx->id = MBEDTLS_CIPHER_LIGHT_ID_NONE;
}

int mbedtls_cipher_light_setkey(mbedtls_cipher_light_context_t *ctx,
                                mbedtls_cipher_id_t cipher_id,
                                const unsigned char *key,
                                unsigned key_bitlen)
{
    switch (cipher_id) {
#if defined(MBEDTLS_AES_C)
        case MBEDTLS_CIPHER_ID_AES:
            ctx->id = MBEDTLS_CIPHER_LIGHT_ID_AES;
            return mbedtls_aes_setkey_enc(&ctx->ctx.aes, key, key_bitlen);
#endif
#if defined(MBEDTLS_ARIA_C)
        case MBEDTLS_CIPHER_ID_ARIA:
            ctx->id = MBEDTLS_CIPHER_LIGHT_ID_ARIA;
            return mbedtls_aria_setkey_enc(&ctx->ctx.aria, key, key_bitlen);
#endif
#if defined(MBEDTLS_CAMELLIA_C)
        case MBEDTLS_CIPHER_ID_CAMELLIA:
            ctx->id = MBEDTLS_CIPHER_LIGHT_ID_CAMELLIA;
            return mbedtls_camellia_setkey_enc(&ctx->ctx.camellia, key, key_bitlen);
#endif
        default:
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
}

int mbedtls_cipher_light_encrypt(mbedtls_cipher_light_context_t *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16])
{
    switch (ctx->id) {
#if defined(MBEDTLS_AES_C)
        case MBEDTLS_CIPHER_LIGHT_ID_AES:
            return mbedtls_aes_crypt_ecb(&ctx->ctx.aes, MBEDTLS_AES_ENCRYPT,
                                         input, output);
#endif
#if defined(MBEDTLS_ARIA_C)
        case MBEDTLS_CIPHER_LIGHT_ID_ARIA:
            return mbedtls_aria_crypt_ecb(&ctx->ctx.aria, input, output);
#endif
#if defined(MBEDTLS_CAMELLIA_C)
        case MBEDTLS_CIPHER_LIGHT_ID_CAMELLIA:
            return mbedtls_camellia_crypt_ecb(&ctx->ctx.camellia,
                                              MBEDTLS_CAMELLIA_ENCRYPT,
                                              input, output);
#endif
        default:
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
}

#endif /* MBEDTLS_CIPHER_LIGHT */
