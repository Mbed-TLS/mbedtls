/**
 * Copyright (C) 2014 Virgil Security Inc.
 *
 * This file is part of extension to mbed TLS (http://www.polarssl.org)
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_KDF1_C)

#include <string.h>

#include "polarssl/kdf1.h"
#include "polarssl/md.h"

#define KDF1_TRY(invocation) \
do { \
    result = invocation; \
    if((result) < 0) { \
        goto exit; \
    } \
} while (0)

#define KDF1_CEIL(x,y) (1 + ((x - 1) / y))

int kdf1(const md_info_t *md_info, const unsigned char *input, size_t ilen,
        unsigned char * output, size_t olen)
{
    int result = 0;
    size_t counter = 0;
    size_t counter_len = 0;
    unsigned char counter_string[4] = {0x0};

    unsigned char hash[POLARSSL_MD_MAX_SIZE] = {0x0};
    unsigned char hash_len = 0;

    size_t olen_actual = 0;

    md_context_t md_ctx;

    if (md_info == NULL)
        return( POLARSSL_ERR_KDF1_BAD_INPUT_DATA );

    // Initialize digest context
    KDF1_TRY(md_init_ctx(&md_ctx, md_info));

    // Get hash parameters
    hash_len = md_get_size(md_info);

    // Get KDF parameters
    counter_len = KDF1_CEIL(olen, hash_len);

    // Start hashing
    for(; counter < counter_len; ++counter) {
        counter_string[0] = (unsigned char)((counter >> 24) & 255);
        counter_string[1] = (unsigned char)((counter >> 16) & 255);
        counter_string[2] = (unsigned char)((counter >> 8)) & 255;
        counter_string[3] = (unsigned char)(counter & 255);
        KDF1_TRY(md_starts(&md_ctx));
        KDF1_TRY(md_update(&md_ctx, input, ilen));
        KDF1_TRY(md_update(&md_ctx, counter_string, 4));
        if (olen_actual + hash_len <= olen) {
            KDF1_TRY(md_finish(&md_ctx, output + olen_actual));
            olen_actual += hash_len;
        } else {
            KDF1_TRY(md_finish(&md_ctx, hash));
            memcpy(output + olen_actual, hash, olen - olen_actual);
            olen_actual = olen;
        }
    }
exit:
    md_free(&md_ctx);
    return result;
}

#endif /* POLARSSL_KDF1_C */
