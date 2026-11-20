/*
 * OSS-Fuzz: PKCS#12 / PKCS#5 PBE/PBKDF2 harness.
 *
 * Shape: [op][md][mode][iter][len16 pwd][pwd][len16 salt][salt]
 *        [len16 params][params][len16 data][data]
 * The params blob is SEQUENCE *contents* presented as an mbedtls_asn1_buf
 * (tag = SEQUENCE) to the _ext APIs, matching the library test vectors.
 *
 * Bounds: blobs <= 4096; outputs <= 512; iterations <= 4096 (byte<<4).
 */
#include <stdint.h>
#include <string.h>

#include "mbedtls/pkcs12.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/asn1.h"
#include "mbedtls/cipher.h"
#include "mbedtls/md.h"
#include "common.h"

#define MAX_BLOB 4096

#if defined(MBEDTLS_ASN1_PARSE_C) && defined(MBEDTLS_CIPHER_C) && \
    defined(MBEDTLS_MD_C)

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
    switch (b % 6) {
        case 0: return MBEDTLS_MD_SHA256;
        case 1: return MBEDTLS_MD_SHA512;
        case 2: return MBEDTLS_MD_SHA384;
        case 3: return MBEDTLS_MD_SHA224;
        case 4: return MBEDTLS_MD_SHA1;
        default: return MBEDTLS_MD_MD5;
    }
}

static mbedtls_cipher_type_t cipher_from_byte(uint8_t b)
{
    switch (b % 5) {
        case 0: return MBEDTLS_CIPHER_AES_128_CBC;
        case 1: return MBEDTLS_CIPHER_AES_256_CBC;
        case 2: return MBEDTLS_CIPHER_DES_EDE3_CBC;
        case 3: return MBEDTLS_CIPHER_AES_192_CBC;
        default: return MBEDTLS_CIPHER_DES_CBC;
    }
}
#endif /* MBEDTLS_ASN1_PARSE_C && MBEDTLS_CIPHER_C && MBEDTLS_MD_C */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#if defined(MBEDTLS_ASN1_PARSE_C) && defined(MBEDTLS_CIPHER_C) && \
    defined(MBEDTLS_MD_C)
    uint8_t op, md_byte, mode, iter_byte;
    mbedtls_md_type_t md;
    int iterations;
    size_t pos = 0, pwd_len, salt_len, params_len, data_len;
    const uint8_t *pwd, *salt, *params, *data;
    uint8_t out[512];
    size_t out_len = 0;

    if (Size < 12) {
        return 0;
    }
    op = Data[pos++];
    md_byte = Data[pos++];
    mode = Data[pos++];
    iter_byte = Data[pos++];
    md = md_from_byte(md_byte);
    iterations = 1 + ((int) iter_byte << 4);

    pwd_len = get_len16(Data, Size, pos, MAX_BLOB, &pos);
    if (pwd_len > Size - pos) {
        return 0;
    }
    pwd = Data + pos;
    pos += pwd_len;

    salt_len = get_len16(Data, Size, pos, 256, &pos);
    if (salt_len > Size - pos) {
        return 0;
    }
    salt = Data + pos;
    pos += salt_len;

    params_len = get_len16(Data, Size, pos, MAX_BLOB, &pos);
    if (params_len > Size - pos) {
        return 0;
    }
    params = Data + pos;
    pos += params_len;

    data_len = get_len16(Data, Size, pos, MAX_BLOB, &pos);
    if (data_len > Size - pos) {
        data_len = Size - pos;
    }
    data = Data + pos;
    if (data_len == 0) {
        return 0;
    }

    {
        mbedtls_asn1_buf pbe_params;
        int pbe_mode = (mode & 1) ? MBEDTLS_PKCS12_PBE_ENCRYPT
                                  : MBEDTLS_PKCS12_PBE_DECRYPT;

        /* SEQUENCE contents (no outer TLV); tag set on the asn1_buf */
        pbe_params.tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
        pbe_params.len = params_len;
        pbe_params.p = (unsigned char *) params;

        switch (op % 6) {
            case 0: /* PKCS#12 KDF: key, IV, and optionally MAC key */
                (void) mbedtls_pkcs12_derivation(out, 128,
                                                 pwd, pwd_len,
                                                 salt, salt_len,
                                                 md, MBEDTLS_PKCS12_DERIVE_KEY,
                                                 iterations);
                (void) mbedtls_pkcs12_derivation(out, 128,
                                                 pwd, pwd_len,
                                                 salt, salt_len,
                                                 md, MBEDTLS_PKCS12_DERIVE_IV,
                                                 iterations);
                if (mode & 1) {
                    (void) mbedtls_pkcs12_derivation(
                        out, 128, pwd, pwd_len, salt, salt_len, md,
                        MBEDTLS_PKCS12_DERIVE_MAC_KEY, iterations);
                }
                break;
#if defined(MBEDTLS_CIPHER_PADDING_PKCS7)
            case 1: /* PKCS#12 PBE (mode selects encrypt/decrypt) */
                (void) mbedtls_pkcs12_pbe_ext(&pbe_params, pbe_mode,
                                              cipher_from_byte(md_byte),
                                              md, pwd, pwd_len,
                                              data, data_len,
                                              out, sizeof(out), &out_len);
                break;
            case 2: /* PKCS#12 PBE opposite polarity of mode */
                (void) mbedtls_pkcs12_pbe_ext(
                    &pbe_params,
                    (mode & 1) ? MBEDTLS_PKCS12_PBE_DECRYPT
                               : MBEDTLS_PKCS12_PBE_ENCRYPT,
                    cipher_from_byte(md_byte),
                    md, pwd, pwd_len,
                    data, data_len,
                    out, sizeof(out), &out_len);
                break;
            case 3: /* PBES2 encrypt/decrypt via mode */
                (void) mbedtls_pkcs5_pbes2_ext(&pbe_params, pbe_mode,
                                               pwd, pwd_len,
                                               data, data_len,
                                               out, sizeof(out), &out_len);
                break;
            case 4: /* PBES2 opposite polarity */
                (void) mbedtls_pkcs5_pbes2_ext(
                    &pbe_params,
                    (mode & 1) ? MBEDTLS_PKCS5_DECRYPT
                               : MBEDTLS_PKCS5_ENCRYPT,
                    pwd, pwd_len,
                    data, data_len,
                    out, sizeof(out), &out_len);
                break;
#endif /* MBEDTLS_CIPHER_PADDING_PKCS7 */
            default: /* PBKDF2 (iterations + key-length matrix) */
                (void) mbedtls_pkcs5_pbkdf2_hmac_ext(
                    md, pwd, pwd_len, salt, salt_len,
                    (unsigned int) iterations,
                    (uint32_t) (128 + 128 * (iter_byte & 1)), out);
                break;
        }
    }
#else
    (void) Data;
    (void) Size;
#endif /* MBEDTLS_ASN1_PARSE_C && MBEDTLS_CIPHER_C && MBEDTLS_MD_C */

    return 0;
}
