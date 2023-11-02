/**
 * \file cipher_light.h
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
#ifndef MBEDTLS_CIPHER_LIGHT_H
#define MBEDTLS_CIPHER_LIGHT_H

#include "mbedtls/build_info.h"

#include "mbedtls/cipher.h"

#if defined(MBEDTLS_AES_C)
#include "mbedtls/aes.h"
#endif
#if defined(MBEDTLS_ARIA_C)
#include "mbedtls/aria.h"
#endif
#if defined(MBEDTLS_CAMELLIA_C)
#include "mbedtls/camellia.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MBEDTLS_CIPHER_LIGHT_ID_NONE = 0,  /**< Placeholder to mark the end of cipher ID lists. */
    MBEDTLS_CIPHER_LIGHT_ID_AES,       /**< The AES cipher. */
    MBEDTLS_CIPHER_LIGHT_ID_CAMELLIA,  /**< The Camellia cipher. */
    MBEDTLS_CIPHER_LIGHT_ID_ARIA,      /**< The Aria cipher. */
} mbedtls_cipher_light_id_t;

typedef struct {
    mbedtls_cipher_light_id_t id;
    union {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if defined(MBEDTLS_AES_C)
        mbedtls_aes_context aes;
#endif
#if defined(MBEDTLS_ARIA_C)
        mbedtls_aria_context aria;
#endif
#if defined(MBEDTLS_CAMELLIA_C)
        mbedtls_camellia_context camellia;
#endif
    } ctx;
} mbedtls_cipher_light_context_t;

static inline void mbedtls_cipher_light_init(mbedtls_cipher_light_context_t *ctx)
{
    ctx->id = MBEDTLS_CIPHER_LIGHT_ID_NONE;
    ctx->ctx.dummy = 0;
}

void mbedtls_cipher_light_free(mbedtls_cipher_light_context_t *ctx);

int mbedtls_cipher_light_setkey(mbedtls_cipher_light_context_t *ctx,
                                mbedtls_cipher_id_t cipher_id,
                                const unsigned char *key,
                                unsigned key_bitlen);

int mbedtls_cipher_light_encrypt(mbedtls_cipher_light_context_t *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16]);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CIPHER_LIGHT_H */
