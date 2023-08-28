/*
 *  Privacy Enhanced Mail (PEM) decoding
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

#if defined(MBEDTLS_PEM_PARSE_C) || defined(MBEDTLS_PEM_WRITE_C)

#include "mbedtls/pem.h"
#include "mbedtls/base64.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/cipher.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#include "mbedtls/platform.h"

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif

#if defined(MBEDTLS_MD_CAN_MD5) &&  \
    defined(MBEDTLS_CIPHER_MODE_CBC) &&                             \
    (defined(MBEDTLS_DES_C) || defined(MBEDTLS_AES_C))
#define PEM_RFC1421
#endif /* MBEDTLS_MD_CAN_MD5 &&
          MBEDTLS_CIPHER_MODE_CBC &&
          ( MBEDTLS_AES_C || MBEDTLS_DES_C ) */

#if defined(MBEDTLS_PEM_PARSE_C)
void mbedtls_pem_init(mbedtls_pem_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_pem_context));
}

#if defined(PEM_RFC1421)
/*
 * Read a 16-byte hex string and convert it to binary
 */
static int pem_get_iv(const unsigned char *s, unsigned char *iv,
                      size_t iv_len)
{
    size_t i, j, k;

    memset(iv, 0, iv_len);

    for (i = 0; i < iv_len * 2; i++, s++) {
        if (*s >= '0' && *s <= '9') {
            j = *s - '0';
        } else
        if (*s >= 'A' && *s <= 'F') {
            j = *s - '7';
        } else
        if (*s >= 'a' && *s <= 'f') {
            j = *s - 'W';
        } else {
            return MBEDTLS_ERR_PEM_INVALID_ENC_IV;
        }

        k = ((i & 1) != 0) ? j : j << 4;

        iv[i >> 1] = (unsigned char) (iv[i >> 1] | k);
    }

    return 0;
}

static int pem_pbkdf1(unsigned char *key, size_t keylen,
                      unsigned char *iv,
                      const unsigned char *pwd, size_t pwdlen)
{
    mbedtls_md_context_t md5_ctx;
    const mbedtls_md_info_t *md5_info;
    unsigned char md5sum[16];
    size_t use_len;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_md_init(&md5_ctx);

    /* Prepare the context. (setup() errors gracefully on NULL info.) */
    md5_info = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
    if ((ret = mbedtls_md_setup(&md5_ctx, md5_info, 0)) != 0) {
        goto exit;
    }

    /*
     * key[ 0..15] = MD5(pwd || IV)
     */
    if ((ret = mbedtls_md_starts(&md5_ctx)) != 0) {
        goto exit;
    }
    if ((ret = mbedtls_md_update(&md5_ctx, pwd, pwdlen)) != 0) {
        goto exit;
    }
    if ((ret = mbedtls_md_update(&md5_ctx, iv,  8)) != 0) {
        goto exit;
    }
    if ((ret = mbedtls_md_finish(&md5_ctx, md5sum)) != 0) {
        goto exit;
    }

    if (keylen <= 16) {
        memcpy(key, md5sum, keylen);
        goto exit;
    }

    memcpy(key, md5sum, 16);

    /*
     * key[16..23] = MD5(key[ 0..15] || pwd || IV])
     */
    if ((ret = mbedtls_md_starts(&md5_ctx)) != 0) {
        goto exit;
    }
    if ((ret = mbedtls_md_update(&md5_ctx, md5sum, 16)) != 0) {
        goto exit;
    }
    if ((ret = mbedtls_md_update(&md5_ctx, pwd, pwdlen)) != 0) {
        goto exit;
    }
    if ((ret = mbedtls_md_update(&md5_ctx, iv, 8)) != 0) {
        goto exit;
    }
    if ((ret = mbedtls_md_finish(&md5_ctx, md5sum)) != 0) {
        goto exit;
    }

    use_len = 16;
    if (keylen < 32) {
        use_len = keylen - 16;
    }

    memcpy(key + 16, md5sum, use_len);

exit:
    mbedtls_md_free(&md5_ctx);
    mbedtls_platform_zeroize(md5sum, 16);

    return ret;
}

#if defined(MBEDTLS_CIPHER_C)
static int pem_cipher_decrypt(mbedtls_cipher_type_t enc_alg,
                              unsigned char *iv, size_t iv_len,
                              const unsigned char *pwd, size_t pwdlen,
                              unsigned char *input, size_t input_len)
{
    mbedtls_cipher_context_t ctx;
    // Pick the largest key size between DES and AES, i.e. AES-256
    unsigned char key[32];
    const mbedtls_cipher_info_t *cipher_info;
    size_t key_bitlen, block_size;
    unsigned char *output;
    size_t output_len;
    int ret;

    cipher_info = mbedtls_cipher_info_from_type(enc_alg);
    if (cipher_info == NULL) {
        return MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE;
    }

    key_bitlen = mbedtls_cipher_info_get_key_bitlen(cipher_info);
    block_size = mbedtls_cipher_info_get_block_size(cipher_info);

    mbedtls_cipher_init(&ctx);

    ret = mbedtls_cipher_setup(&ctx, cipher_info);
    if (ret != 0) {
        return ret;
    }

    ret = pem_pbkdf1(key, key_bitlen/8, iv, pwd, pwdlen);
    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_cipher_setkey(&ctx, key, key_bitlen, MBEDTLS_DECRYPT);
    if (ret != 0) {
        return ret;
    }

    output_len = input_len + block_size;
    output = mbedtls_calloc(1, output_len);

    ret = mbedtls_cipher_crypt(&ctx, iv, iv_len, input, input_len,
                               output, &output_len);
    if (ret != 0) {
        goto exit;
    }

    memcpy(input, output, input_len);

exit:
    mbedtls_free(output);
    return ret;
}
#endif /* MBEDTLS_CIPHER_C */

#endif /* PEM_RFC1421 */

int mbedtls_pem_read_buffer(mbedtls_pem_context *ctx, const char *header, const char *footer,
                            const unsigned char *data, const unsigned char *pwd,
                            size_t pwdlen, size_t *use_len)
{
    int ret, enc;
    size_t len;
    unsigned char *buf;
    const unsigned char *s1, *s2, *end;
#if defined(PEM_RFC1421)
    unsigned char pem_iv[16];
    mbedtls_cipher_type_t enc_alg = MBEDTLS_CIPHER_NONE;
#else
    ((void) pwd);
    ((void) pwdlen);
#endif /* PEM_RFC1421 */

    if (ctx == NULL) {
        return MBEDTLS_ERR_PEM_BAD_INPUT_DATA;
    }

    s1 = (unsigned char *) strstr((const char *) data, header);

    if (s1 == NULL) {
        return MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    }

    s2 = (unsigned char *) strstr((const char *) data, footer);

    if (s2 == NULL || s2 <= s1) {
        return MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    }

    s1 += strlen(header);
    if (*s1 == ' ') {
        s1++;
    }
    if (*s1 == '\r') {
        s1++;
    }
    if (*s1 == '\n') {
        s1++;
    } else {
        return MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    }

    end = s2;
    end += strlen(footer);
    if (*end == ' ') {
        end++;
    }
    if (*end == '\r') {
        end++;
    }
    if (*end == '\n') {
        end++;
    }
    *use_len = end - data;

    enc = 0;

    if (s2 - s1 >= 22 && memcmp(s1, "Proc-Type: 4,ENCRYPTED", 22) == 0) {
#if defined(PEM_RFC1421)
        enc++;

        s1 += 22;
        if (*s1 == '\r') {
            s1++;
        }
        if (*s1 == '\n') {
            s1++;
        } else {
            return MBEDTLS_ERR_PEM_INVALID_DATA;
        }


#if defined(MBEDTLS_DES_C)
        if (s2 - s1 >= 23 && memcmp(s1, "DEK-Info: DES-EDE3-CBC,", 23) == 0) {
            enc_alg = MBEDTLS_CIPHER_DES_EDE3_CBC;

            s1 += 23;
            if (s2 - s1 < 16 || pem_get_iv(s1, pem_iv, 8) != 0) {
                return MBEDTLS_ERR_PEM_INVALID_ENC_IV;
            }

            s1 += 16;
        } else if (s2 - s1 >= 18 && memcmp(s1, "DEK-Info: DES-CBC,", 18) == 0) {
            enc_alg = MBEDTLS_CIPHER_DES_CBC;

            s1 += 18;
            if (s2 - s1 < 16 || pem_get_iv(s1, pem_iv, 8) != 0) {
                return MBEDTLS_ERR_PEM_INVALID_ENC_IV;
            }

            s1 += 16;
        }
#endif /* MBEDTLS_DES_C */

#if defined(MBEDTLS_AES_C)
        if (s2 - s1 >= 14 && memcmp(s1, "DEK-Info: AES-", 14) == 0) {
            if (s2 - s1 < 22) {
                return MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG;
            } else if (memcmp(s1, "DEK-Info: AES-128-CBC,", 22) == 0) {
                enc_alg = MBEDTLS_CIPHER_AES_128_CBC;
            } else if (memcmp(s1, "DEK-Info: AES-192-CBC,", 22) == 0) {
                enc_alg = MBEDTLS_CIPHER_AES_192_CBC;
            } else if (memcmp(s1, "DEK-Info: AES-256-CBC,", 22) == 0) {
                enc_alg = MBEDTLS_CIPHER_AES_256_CBC;
            } else {
                return MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG;
            }

            s1 += 22;
            if (s2 - s1 < 32 || pem_get_iv(s1, pem_iv, 16) != 0) {
                return MBEDTLS_ERR_PEM_INVALID_ENC_IV;
            }

            s1 += 32;
        }
#endif /* MBEDTLS_AES_C */

        if (enc_alg == MBEDTLS_CIPHER_NONE) {
            return MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG;
        }

        if (*s1 == '\r') {
            s1++;
        }
        if (*s1 == '\n') {
            s1++;
        } else {
            return MBEDTLS_ERR_PEM_INVALID_DATA;
        }
#else
        return MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE;
#endif /* PEM_RFC1421 */
    }

    if (s1 >= s2) {
        return MBEDTLS_ERR_PEM_INVALID_DATA;
    }

    ret = mbedtls_base64_decode(NULL, 0, &len, s1, s2 - s1);

    if (ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PEM_INVALID_DATA, ret);
    }

    if ((buf = mbedtls_calloc(1, len)) == NULL) {
        return MBEDTLS_ERR_PEM_ALLOC_FAILED;
    }

    if ((ret = mbedtls_base64_decode(buf, len, &len, s1, s2 - s1)) != 0) {
        mbedtls_zeroize_and_free(buf, len);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PEM_INVALID_DATA, ret);
    }

    if (enc != 0) {
#if defined(PEM_RFC1421)
        if (pwd == NULL) {
            mbedtls_zeroize_and_free(buf, len);
            return MBEDTLS_ERR_PEM_PASSWORD_REQUIRED;
        }

        ret = MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE;

#if defined(MBEDTLS_CIPHER_C)
        ret = pem_cipher_decrypt(enc_alg, pem_iv, sizeof(pem_iv),
                                 pwd, pwdlen, buf, len);
#endif

        if (ret != 0) {
            mbedtls_free(buf);
            return ret;
        }

        /*
         * The result will be ASN.1 starting with a SEQUENCE tag, with 1 to 3
         * length bytes (allow 4 to be sure) in all known use cases.
         *
         * Use that as a heuristic to try to detect password mismatches.
         */
        if (len <= 2 || buf[0] != 0x30 || buf[1] > 0x83) {
            mbedtls_zeroize_and_free(buf, len);
            return MBEDTLS_ERR_PEM_PASSWORD_MISMATCH;
        }
#else
        mbedtls_zeroize_and_free(buf, len);
        return MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE;
#endif /* PEM_RFC1421 */
    }

    ctx->buf = buf;
    ctx->buflen = len;

    return 0;
}

void mbedtls_pem_free(mbedtls_pem_context *ctx)
{
    if (ctx->buf != NULL) {
        mbedtls_zeroize_and_free(ctx->buf, ctx->buflen);
    }
    mbedtls_free(ctx->info);

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_pem_context));
}
#endif /* MBEDTLS_PEM_PARSE_C */

#if defined(MBEDTLS_PEM_WRITE_C)
int mbedtls_pem_write_buffer(const char *header, const char *footer,
                             const unsigned char *der_data, size_t der_len,
                             unsigned char *buf, size_t buf_len, size_t *olen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *encode_buf = NULL, *c, *p = buf;
    size_t len = 0, use_len, add_len = 0;

    mbedtls_base64_encode(NULL, 0, &use_len, der_data, der_len);
    add_len = strlen(header) + strlen(footer) + (((use_len > 2) ? (use_len - 2) : 0) / 64) + 1;

    if (use_len + add_len > buf_len) {
        *olen = use_len + add_len;
        return MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL;
    }

    if (use_len != 0 &&
        ((encode_buf = mbedtls_calloc(1, use_len)) == NULL)) {
        return MBEDTLS_ERR_PEM_ALLOC_FAILED;
    }

    if ((ret = mbedtls_base64_encode(encode_buf, use_len, &use_len, der_data,
                                     der_len)) != 0) {
        mbedtls_free(encode_buf);
        return ret;
    }

    memcpy(p, header, strlen(header));
    p += strlen(header);
    c = encode_buf;

    while (use_len) {
        len = (use_len > 64) ? 64 : use_len;
        memcpy(p, c, len);
        use_len -= len;
        p += len;
        c += len;
        *p++ = '\n';
    }

    memcpy(p, footer, strlen(footer));
    p += strlen(footer);

    *p++ = '\0';
    *olen = p - buf;

    /* Clean any remaining data previously written to the buffer */
    memset(buf + *olen, 0, buf_len - *olen);

    mbedtls_free(encode_buf);
    return 0;
}
#endif /* MBEDTLS_PEM_WRITE_C */
#endif /* MBEDTLS_PEM_PARSE_C || MBEDTLS_PEM_WRITE_C */
