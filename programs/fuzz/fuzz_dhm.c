/*
 * OSS-Fuzz: DHM key-exchange harness.
 *
 * Shape: [opts][len16 params][params][len16 peer_pub][peer_pub]
 * Flow: parse DHM parameters (PEM/DER — seeds use real framework ffdhe/
 * dh_*.pem files), make our public value (RNG-driven private exponent),
 * read the ATTACKER's public value, calculate the shared secret (attacker
 * range-validation paths run: value < 2, >= P, etc.).
 * All statuses ignored; error paths are dark validation code.
 *
 * Bounds: blobs <= 4096 bytes; single exchange per input.
 */
#include <stdint.h>
#include <string.h>

#include "mbedtls/dhm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "common.h"

#define MAX_BLOB 4096

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_ASN1_PARSE_C) && \
    defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_ENTROPY_C)

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
#endif /* MBEDTLS_DHM_C && MBEDTLS_ASN1_PARSE_C &&
          MBEDTLS_CTR_DRBG_C && MBEDTLS_ENTROPY_C */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_ASN1_PARSE_C) && \
    defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_ENTROPY_C)
    int ret;
    mbedtls_dhm_context dhm;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    uint8_t opts;
    size_t pos = 0, params_len, peer_len;
    uint8_t out[MAX_BLOB];
    size_t out_len = 0;

    mbedtls_dhm_init(&dhm);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if (Size < 5) {
        goto exit;
    }
    opts = Data[pos++];

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, dummy_entropy, &entropy,
                              (const unsigned char *) "fuzz_dhm", 7) != 0) {
        goto exit;
    }

    /* 1. DHM parameters (PEM "-----BEGIN DH PARAMETERS-----" or DER) */
    params_len = get_len16(Data, Size, pos, MAX_BLOB, &pos);
    if (params_len == 0 || params_len > Size - pos) {
        goto exit;
    }
    ret = mbedtls_dhm_parse_dhm(&dhm, Data + pos, params_len);
    pos += params_len;
    if (ret != 0) {
        goto exit;
    }

    /* 2. make our public value (RNG-driven private exponent; 3.6 has no
     * public read_private API) */
    (void) mbedtls_dhm_make_public(&dhm, 32, out, MAX_BLOB,
                                   dummy_random, &ctr_drbg);

    /* 3. attacker public value (range validation paths) */
    peer_len = get_len16(Data, Size, pos, MAX_BLOB, &pos);
    if (peer_len > Size - pos) {
        peer_len = Size - pos;
    }
    if (peer_len > 0) {
        (void) mbedtls_dhm_read_public(&dhm, Data + pos, peer_len);
    }

    /* 4. shared secret against attacker peer (P-range checks) */
    (void) mbedtls_dhm_calc_secret(&dhm, out, sizeof(out), &out_len,
                                   dummy_random, &ctr_drbg);

    (void) opts;

exit:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_dhm_free(&dhm);
#else
    (void) Data;
    (void) Size;
#endif /* MBEDTLS_DHM_C && MBEDTLS_ASN1_PARSE_C &&
          MBEDTLS_CTR_DRBG_C && MBEDTLS_ENTROPY_C */

    return 0;
}
