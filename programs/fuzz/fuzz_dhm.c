/*
 * OSS-Fuzz coverage pipeline pair 10 (mbedtls-dhm): DHM key-exchange harness.
 *
 * Rationale (coverage report 20261110):
 *   dhm.c 250 dark lines @32.1% — read_public/make_public/calc_secret and
 *   the range-validation paths for attacker-supplied public values. DHM is
 *   the TLS 1.2 DHE server-side exchange surface; no existing harness
 *   drives it. bignum range checks on peer values are classic memory/logic
 *   bug territory.
 *
 * Shape: bytes-in = [opts][len16 params][params][len16 own_priv][own_priv]
 *                   [len16 peer_pub][peer_pub]
 * Flow: parse DHM parameters (PEM/DER — seeds use real framework ffdhe/
 * dh_*.pem files), read our private exponent from input (or generate), make
 * our public value, read the ATTACKER's public value, calculate the shared
 * secret (attacker range-validation paths run: value < 2, >= P, etc.).
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

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
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

    if (Size < 7) {
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

    /* 2. our private exponent: generated internally by make_public below
     * (3.6 has no public read_private API; X is a private member) */

    /* 3. make our public value (RNG-driven path, 32-byte exponent) */
    (void) mbedtls_dhm_make_public(&dhm, 32, out, MAX_BLOB,
                                   dummy_random, &ctr_drbg);

    /* 4. attacker public value (range validation paths) */
    peer_len = get_len16(Data, Size, pos, MAX_BLOB, &pos);
    if (peer_len > Size - pos) {
        peer_len = Size - pos;
    }
    if (peer_len > 0) {
        (void) mbedtls_dhm_read_public(&dhm, Data + pos, peer_len);
    }

    /* 5. shared secret against attacker peer (P-range checks) */
    (void) mbedtls_dhm_calc_secret(&dhm, out, sizeof(out), &out_len,
                                   dummy_random, &ctr_drbg);

    (void) opts;

exit:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_dhm_free(&dhm);
    return 0;
}
