/*
 * OSS-Fuzz coverage pipeline pair 8 (mbedtls-pkcs12): PBE/PBKDF2 harness.
 *
 * Rationale (coverage report 20261110):
 *   pkcs12.c 255 dark lines @0%, pkcs5.c 237 @0%, des.c PBE paths. These are
 *   the password-based-encryption primitives behind every encrypted key or
 *   PKCS#12 blob an application loads; no harness touches them. They are
 *   provably seed-limited: DER param structures (salt OCTET STRING,
 *   iteration counts, PRF/cipher OIDs) and the PBES1/PBES2 layouts cannot
 *   come from blind mutation — hence handcrafted valid DER param seeds.
 *
 * Shape: bytes-in = [op][md][mode][iter][len16 pwd][pwd][len16 salt][salt]
 *                   [len16 params][params][len16 data][data]
 * The params blob is presented as an mbedtls_asn1_buf (SEQUENCE tag) to the
 * _ext APIs, so the ASN.1 param-parse paths (OID lookup, iteration/prf
 * extraction) run on attacker bytes.
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

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    uint8_t op, md_byte, mode, iter_byte;
    mbedtls_md_type_t md;
    int iterations, id;
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
    (void) mode;
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

        /* attacker bytes presented as the DER SEQUENCE the _ext APIs parse */
        pbe_params.tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
        pbe_params.len = params_len;
        pbe_params.p = (unsigned char *) params;

        switch (op % 6) {
            case 0: /* PKCS#12 KDF (id 1 = key material, 2 = IV) */
                id = (iter_byte & 1) ? 2 : 1;
                (void) mbedtls_pkcs12_derivation(out, 128,
                                                 pwd, pwd_len,
                                                 salt, salt_len,
                                                 md, id, iterations);
                (void) mbedtls_pkcs12_derivation(out, 128,
                                                 pwd, pwd_len,
                                                 salt, salt_len,
                                                 md, id, iterations);
                break;
            case 1: /* PKCS#12 PBE encrypt */
                (void) mbedtls_pkcs12_pbe_ext(&pbe_params,
                                              MBEDTLS_PKCS12_PBE_ENCRYPT,
                                              cipher_from_byte(md_byte),
                                              md, pwd, pwd_len,
                                              data, data_len,
                                              out, sizeof(out), &out_len);
                break;
            case 2: /* PKCS#12 PBE decrypt (padding-removal paths) */
                (void) mbedtls_pkcs12_pbe_ext(&pbe_params,
                                              MBEDTLS_PKCS12_PBE_DECRYPT,
                                              cipher_from_byte(md_byte),
                                              md, pwd, pwd_len,
                                              data, data_len,
                                              out, sizeof(out), &out_len);
                break;
            case 3: /* PBES2 encrypt */
                (void) mbedtls_pkcs5_pbes2_ext(&pbe_params,
                                               MBEDTLS_PKCS12_PBE_ENCRYPT,
                                               pwd, pwd_len,
                                               data, data_len,
                                               out, sizeof(out), &out_len);
                break;
            case 4: /* PBES2 decrypt */
                (void) mbedtls_pkcs5_pbes2_ext(&pbe_params,
                                               MBEDTLS_PKCS12_PBE_DECRYPT,
                                               pwd, pwd_len,
                                               data, data_len,
                                               out, sizeof(out), &out_len);
                break;
            default: /* PBKDF2 (iterations + key-length matrix) */
                (void) mbedtls_pkcs5_pbkdf2_hmac_ext(
                    md, pwd, pwd_len, salt, salt_len,
                    (unsigned int) iterations,
                    (uint32_t) (128 + 128 * (iter_byte & 1)), out);
                break;
        }
    }
    return 0;
}
