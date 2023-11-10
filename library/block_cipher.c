/**
 * \file block_cipher.c
 *
 * \brief Lightweight abstraction layer for block ciphers with 128 bit blocks,
 * for use by the GCM and CCM modules.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#include "block_cipher_internal.h"

#if defined(MBEDTLS_BLOCK_CIPHER_C)

void mbedtls_block_cipher_free(mbedtls_block_cipher_context_t *ctx)
{
    switch (ctx->id) {
#if defined(MBEDTLS_AES_C)
        case MBEDTLS_BLOCK_CIPHER_ID_AES:
            mbedtls_aes_free(&ctx->ctx.aes);
            break;
#endif
#if defined(MBEDTLS_ARIA_C)
        case MBEDTLS_BLOCK_CIPHER_ID_ARIA:
            mbedtls_aria_free(&ctx->ctx.aria);
            break;
#endif
#if defined(MBEDTLS_CAMELLIA_C)
        case MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA:
            mbedtls_camellia_free(&ctx->ctx.camellia);
            break;
#endif
        default:
            break;
    }
    ctx->id = MBEDTLS_BLOCK_CIPHER_ID_NONE;
}

int mbedtls_block_cipher_setup(mbedtls_block_cipher_context_t *ctx,
                               mbedtls_cipher_id_t cipher_id)
{
    switch (cipher_id) {
#if defined(MBEDTLS_AES_C)
        case MBEDTLS_CIPHER_ID_AES:
            ctx->id = MBEDTLS_BLOCK_CIPHER_ID_AES;
            mbedtls_aes_init(&ctx->ctx.aes);
            return 0;
#endif
#if defined(MBEDTLS_ARIA_C)
        case MBEDTLS_CIPHER_ID_ARIA:
            ctx->id = MBEDTLS_BLOCK_CIPHER_ID_ARIA;
            mbedtls_aria_init(&ctx->ctx.aria);
            return 0;
#endif
#if defined(MBEDTLS_CAMELLIA_C)
        case MBEDTLS_CIPHER_ID_CAMELLIA:
            ctx->id = MBEDTLS_BLOCK_CIPHER_ID_CAMELLIA;
            mbedtls_camellia_init(&ctx->ctx.camellia);
            return 0;
#endif
        default:
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
}

#endif /* MBEDTLS_BLOCK_CIPHER_C */
