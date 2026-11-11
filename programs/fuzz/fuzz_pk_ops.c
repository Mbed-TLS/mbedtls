#include <stdint.h>
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "common.h"

#define MAX_BLOB 4096

static size_t get_len16(const uint8_t *d, size_t n, size_t pos, size_t cap,
                        size_t *out_pos)
{
    size_t len;

    if (pos + 2 > n) {
        *out_pos = n;
        return 0;
    }
    len = (size_t) d[pos] | ((size_t) d[pos + 1] << 8);
    pos += 2;
    if (len > cap) {
        len = cap;
    }
    if (len > n - pos) {
        len = n - pos;
    }
    *out_pos = pos;
    return len;
}

static mbedtls_md_type_t md_from_byte(uint8_t b)
{
    switch (b % 8) {
        case 0: return MBEDTLS_MD_SHA256;
        case 1: return MBEDTLS_MD_SHA384;
        case 2: return MBEDTLS_MD_SHA512;
        case 3: return MBEDTLS_MD_SHA224;
        case 4: return MBEDTLS_MD_SHA1;
        case 5: return MBEDTLS_MD_MD5;
        case 6: return MBEDTLS_MD_SHA3_256;
        default: return MBEDTLS_MD_NONE;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    int ret;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    uint8_t op, opts, hash_sel;
    size_t pos = 0, key_len, payload_len;
    const uint8_t *payload;
    int parse_public;

    mbedtls_pk_init(&pk);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if (Size < 6) {
        goto exit;
    }

    op = Data[pos++];
    opts = Data[pos++];
    hash_sel = Data[pos++];
    parse_public = (op & 0x10) != 0;
    op &= 0x0f;

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, dummy_entropy, &entropy,
                              (const unsigned char *) "fuzz_pk_ops", 11)
        != 0) {
        goto exit;
    }

    key_len = get_len16(Data, Size, pos, MAX_BLOB, &pos);
    if (key_len == 0 || key_len > Size - pos) {
        goto exit;
    }
    {
        const uint8_t *key = Data + pos;
        int want_pwd = (opts & 0x80) != 0;
        size_t pwd_len = 0;
        const uint8_t *pwd = NULL;

        pos += key_len;
        /* password byte-string for encrypted PEM/PKCS12/PKCS5 parsing */
        if (want_pwd) {
            pwd_len = Data[pos % Size];
            pos = (pos + 1) % (Size + 1);
            if (pos + pwd_len > Size) {
                pwd_len = Size - pos;
            }
            pwd = Data + pos;
        }

        if (parse_public) {
            ret = mbedtls_pk_parse_public_key(&pk, key, key_len);
        } else {
            ret = mbedtls_pk_parse_key(&pk, key, key_len, pwd, pwd_len,
                                       dummy_random, &ctr_drbg);
        }
        pos += pwd_len;
        if (ret != 0) {
            goto exit;
        }
    }

    payload_len = get_len16(Data, Size, pos, MAX_BLOB, &pos);
    if (payload_len > Size - pos) {
        payload_len = Size - pos;
    }
    payload = Data + pos;
    pos += payload_len;
    if (payload_len == 0) {
        goto exit;
    }

    {
        mbedtls_rsa_context *rsa = (mbedtls_pk_get_type(&pk) ==
                                    MBEDTLS_PK_RSA)
                                     ? mbedtls_pk_rsa(pk) : NULL;
        mbedtls_md_type_t md = md_from_byte(hash_sel);
        int rsa_padding = (opts & 0x01) ? MBEDTLS_RSA_PKCS_V21
                                        : MBEDTLS_RSA_PKCS_V15;
        uint8_t out[512];
        size_t out_len = 0;
        int is_private;

        if (rsa != NULL && (opts & 0x02)) {
            (void) mbedtls_rsa_set_padding(rsa, rsa_padding,
                                           mbedtls_md_info_from_type(md));
        }

        is_private = (mbedtls_pk_get_type(&pk) == MBEDTLS_PK_RSA ||
                      mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY ||
                      mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY_DH);

        switch (op % 8) {
            case 0: /* sign */
                if (is_private) {
                    (void) mbedtls_pk_sign(&pk, md, payload, payload_len,
                                           out, sizeof(out), &out_len,
                                           dummy_random, &ctr_drbg);
                }
                break;
            case 1: /* verify against attacker bytes */
                (void) mbedtls_pk_verify(&pk, md, payload, payload_len,
                                         payload, payload_len);
                break;
            case 2: /* verify_ext (PSS path for RSA keys) */
                (void) mbedtls_pk_verify_ext(mbedtls_pk_get_type(&pk) ==
                                             MBEDTLS_PK_RSA
                                               ? MBEDTLS_PK_RSASSA_PSS
                                               : MBEDTLS_PK_NONE,
                                             NULL, &pk, md,
                                             payload, payload_len,
                                             payload, payload_len);
                break;
            case 3: /* decrypt */
                if (is_private) {
                    (void) mbedtls_pk_decrypt(&pk, payload, payload_len,
                                              out, &out_len, sizeof(out),
                                              dummy_random, &ctr_drbg);
                }
                break;
            case 4: /* encrypt */
                (void) mbedtls_pk_encrypt(&pk, payload, payload_len,
                                          out, &out_len, sizeof(out),
                                          dummy_random, &ctr_drbg);
                break;
            case 5: /* DER write round trip + bitlen */
            {
                unsigned char expbuf[MAX_BLOB];

                if (!is_private) {
                    (void) mbedtls_pk_write_pubkey_der(&pk, expbuf,
                                                       sizeof(expbuf));
                } else {
                    (void) mbedtls_pk_write_key_der(&pk, expbuf,
                                                    sizeof(expbuf));
                }
                (void) mbedtls_pk_get_bitlen(&pk);
            }
                break;
            case 6: /* RSA-specific: legacy sign/verify + padding flip */
                if (rsa != NULL) {
                    uint8_t sigbuf[512];

                    (void) mbedtls_rsa_pkcs1_sign(rsa, dummy_random,
                                                  &ctr_drbg,
                                                  md, payload_len,
                                                  payload, out);
                    /* legacy verify reads a full modulus-size sig buffer */
                    if (mbedtls_rsa_get_len(rsa) <= sizeof(sigbuf)) {
                        memset(sigbuf, 0x41, sizeof(sigbuf));
                        if (payload_len <= sizeof(sigbuf)) {
                            memcpy(sigbuf, payload, payload_len);
                        }
                        (void) mbedtls_rsa_pkcs1_verify(rsa, md,
                                                        payload_len,
                                                        payload, sigbuf);
                    }
                    (void) mbedtls_rsa_set_padding(rsa,
                                                   (opts & 0x04)
                                                     ? MBEDTLS_RSA_PKCS_V15
                                                     : MBEDTLS_RSA_PKCS_V21,
                                                   mbedtls_md_info_from_type(
                                                       md));
                }
                break;
            default: /* rng==NULL sign path + verify */
                (void) mbedtls_pk_verify(&pk, md, payload, payload_len,
                                         payload, payload_len);
                if (is_private) {
                    (void) mbedtls_pk_sign(&pk, md, payload, payload_len,
                                           out, sizeof(out), &out_len,
                                           NULL, NULL);
                }
                break;
        }
    }

exit:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&pk);
    return 0;
}
