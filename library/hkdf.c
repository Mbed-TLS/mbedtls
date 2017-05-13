/*
 * HKDF implementation -- RFC 5869
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include <string.h>
#include "mbedtls/hkdf.h"

/* HKDF-Extract + HKDF-Expand */
int mbedtls_hkdf(const mbedtls_md_info_t *md, const unsigned char *salt,
                 int salt_len, const unsigned char *ikm, int ikm_len,
                 const unsigned char *info, int info_len, unsigned char *okm,
                 int okm_len)
{
    unsigned char prk[MBEDTLS_MD_MAX_SIZE];

    return mbedtls_hkdf_extract(md, salt, salt_len, ikm, ikm_len, prk) ||
           mbedtls_hkdf_expand(md, prk, mbedtls_md_get_size(md), info, info_len,
                               okm, okm_len);
}

/* HKDF-Extract(salt, IKM) -> PRK */
int mbedtls_hkdf_extract(const mbedtls_md_info_t *md, const unsigned char *salt,
                         int salt_len, const unsigned char *ikm, int ikm_len,
                         unsigned char *prk)
{
    int hash_len;
    unsigned char null_salt[MBEDTLS_MD_MAX_SIZE] = { '\0' };

    if (salt_len < 0) {
        return MBEDTLS_ERR_HKDF_BAD_PARAM;
    }

    hash_len = mbedtls_md_get_size(md);

    if (salt == NULL) {
        salt = null_salt;
        salt_len = hash_len;
    }

    return mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk);
}

/* HKDF-Expand(PRK, info, L) -> OKM */
int mbedtls_hkdf_expand(const mbedtls_md_info_t *md, const unsigned char *prk,
                        int prk_len, const unsigned char *info, int info_len,
                        unsigned char *okm, int okm_len)
{
    int hash_len;
    int N;
    int T_len = 0, where = 0, i, ret;
    mbedtls_md_context_t ctx;
    unsigned char T[MBEDTLS_MD_MAX_SIZE];

    if (info_len < 0 || okm_len < 0 || okm == NULL) {
        return MBEDTLS_ERR_HKDF_BAD_PARAM;
    }

    hash_len = mbedtls_md_get_size(md);

    if (prk_len < hash_len) {
        return MBEDTLS_ERR_HKDF_BAD_PARAM;
    }

    if (info == NULL) {
        info = (const unsigned char *)"";
    }

    N = okm_len / hash_len;

    if ((okm_len % hash_len) != 0) {
        N++;
    }

    if (N > 255) {
        return MBEDTLS_ERR_HKDF_BAD_PARAM;
    }

    mbedtls_md_init(&ctx);

    if ((ret = mbedtls_md_setup(&ctx, md, 1)) != 0) {
        mbedtls_md_free(&ctx);
        return ret;
    }

    /* Section 2.3. */
    for (i = 1; i <= N; i++) {
        unsigned char c = i;

        ret = mbedtls_md_hmac_starts(&ctx, prk, prk_len) ||
              mbedtls_md_hmac_update(&ctx, T, T_len) ||
              mbedtls_md_hmac_update(&ctx, info, info_len) ||
              /* The constant concatenated to the end of each T(n) is a single
                 octet. */
              mbedtls_md_hmac_update(&ctx, &c, 1) ||
              mbedtls_md_hmac_finish(&ctx, T);

        if (ret != 0) {
            mbedtls_md_free(&ctx);
            return ret;
        }

        memcpy(okm + where, T, (i != N) ? hash_len : (okm_len - where));
        where += hash_len;
        T_len = hash_len;
    }

    mbedtls_md_free(&ctx);

    return 0;
}
