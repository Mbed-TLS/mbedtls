/*
 * OSS-Fuzz coverage pipeline pair 1 (mbedtls-psa-crypto): stateful PSA Crypto
 * API harness.
 *
 * Rationale (worth model, coverage report 20261110):
 *   psa_crypto.c 5,627 dark lines @2.73% and the whole psa_crypto_{hash,
 *   cipher,aead,mac,rsa,ecp,ffdh}.c layer at 0%: no existing harness calls
 *   the PSA API. These files are the attacker-facing crypto service used by
 *   embedded stacks (and, in the usepsa build, by X.509/TLS via pk_wrap).
 *   Exercising them also drives the primitives through their PSA entry paths
 *   (aes.c, cmac.c, des.c, sha3.c, ripemd160.c, chacha20/chachapoly.c,
 *   everest x25519 in the usepsa build, psa_crypto_driver_wrappers*) and the
 *   key storage path (psa_crypto_storage.c, psa_its_file.c, slot management).
 *
 * Shape: stateful component-API harness. The input is a bounded op script:
 *   [op byte][selector byte(s)][payload bytes]*
 * Key slots (volatile, up to 12) and a small persistent key id range (1..16)
 * are threaded through the ops so successive ops in one input can combine
 * (import -> sign -> verify -> export -> copy -> destroy). Verification is
 * fed attacker-controlled tags/signatures so comparison paths run; PSA
 * statuses are ignored (error paths are themselves dark validation code).
 *
 * Bounds (do-not-get-stuck rule): at most 48 ops, payload chunks <= 4096
 * bytes, RSA key *generation* fixed at 1024 bits (keygen dominates runtime;
 * larger RSA keys stay reachable via import, which is where attacker input
 * actually enters). Every loop is bounded.
 *
 * Persistent keys use ids 1..16 and are destroyed at the end of every run;
 * storage files therefore do not accumulate across runs (a file left by an
 * aborted run is reloaded and destroyed by a later run, itself a storage-
 * path exercise).
 */

#include <stdint.h>
#include <string.h>

#include "psa/crypto.h"
#include "mbedtls/psa_util.h" /* mbedtls_psa_crypto_free */
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h" /* MBEDTLS_ENTROPY_BLOCK_SIZE */
#include "common.h"          /* LLVMFuzzerTestOneInput prototype */

#define MAX_OPS 48
#define MAX_KEYS 12
#define MAX_CHUNK 4096
#define MAX_SMALL 1024
#define PERSISTENT_ID_COUNT 16
#define PSA_ID_BASE (PSA_KEY_ID_USER_MIN) /* 1 */

/*
 * The full config enables MBEDTLS_ENTROPY_NV_SEED (+ PLATFORM_NV_SEED_ALT).
 * Its default callbacks read/write a "seed" file in the cwd, which does not
 * exist in the fuzzing environment, so psa_crypto_init() fails with
 * PSA_ERROR_INSUFFICIENT_ENTROPY and the whole PSA layer stays dark (this is
 * also why the production usepsa-* targets never get past init). Register
 * deterministic in-memory NV-seed callbacks so PSA init succeeds.
 */
#if defined(MBEDTLS_ENTROPY_NV_SEED) && defined(MBEDTLS_PLATFORM_NV_SEED_ALT)
static unsigned char fuzz_nv_seed[MBEDTLS_ENTROPY_BLOCK_SIZE];

static int fuzz_nv_seed_read(unsigned char *buf, size_t buf_len)
{
    if (buf_len > sizeof(fuzz_nv_seed)) {
        return -1;
    }
    memcpy(buf, fuzz_nv_seed, buf_len);
    return 0;
}

static int fuzz_nv_seed_write(unsigned char *buf, size_t buf_len)
{
    if (buf_len > sizeof(fuzz_nv_seed)) {
        return -1;
    }
    memcpy(fuzz_nv_seed, buf, buf_len);
    return 0;
}

static void fuzz_platform_init(void)
{
    mbedtls_platform_set_nv_seed(fuzz_nv_seed_read, fuzz_nv_seed_write);
}
#else
static void fuzz_platform_init(void)
{
}
#endif /* MBEDTLS_ENTROPY_NV_SEED && MBEDTLS_PLATFORM_NV_SEED_ALT */

typedef struct {
    const uint8_t *d;
    size_t n;
    size_t pos;
} cursor_t;

static uint32_t cur_bits(cursor_t *c, int want_bits)
{
    uint32_t v = 0;
    int i;

    for (i = 0; i < want_bits; i += 8) {
        if (c->pos >= c->n) {
            return 0;
        }
        v |= (uint32_t) c->d[c->pos++] << i;
    }
    return v;
}

static uint8_t get8(cursor_t *c)
{
    if (c->pos >= c->n) {
        return 0;
    }
    return c->d[c->pos++];
}

static uint16_t get16(cursor_t *c)
{
    return (uint16_t) cur_bits(c, 16);
}

static size_t get_len8(cursor_t *c, size_t cap)
{
    size_t len = get8(c);

    if (len == 0 || len > cap) {
        len = (len == 0) ? 0 : cap;
    }
    return len;
}

/* Two-byte little-endian length (key material can exceed 255 bytes,
 * e.g. a 2048-bit RSA PKCS#1 DER is ~1190 bytes). */
static size_t get_len16(cursor_t *c, size_t cap)
{
    size_t len = cur_bits(c, 16);

    if (len == 0 || len > cap) {
        len = (len == 0) ? 0 : cap;
    }
    return len;
}

/* Pointer into the remaining input, consuming `len` bytes; NULL (and
 * nothing consumed) if fewer than `len` bytes remain. */
static const uint8_t *get_bytes(cursor_t *c, size_t len)
{
    const uint8_t *p;

    if (len == 0 || len > c->n - c->pos) {
        return NULL;
    }
    p = c->d + c->pos;
    c->pos += len;
    return p;
}

/* ---- algorithm / key-type selectors ------------------------------------ */

static psa_algorithm_t hash_from_sel(uint8_t s)
{
    static const psa_algorithm_t t[] = {
        PSA_ALG_MD5, PSA_ALG_SHA_1, PSA_ALG_SHA_224, PSA_ALG_SHA_256,
        PSA_ALG_SHA_384, PSA_ALG_SHA_512, PSA_ALG_RIPEMD160,
        PSA_ALG_SHA3_224, PSA_ALG_SHA3_256, PSA_ALG_SHA3_512
    };

    return t[s % (sizeof(t) / sizeof(t[0]))];
}

static psa_algorithm_t mac_from_sel(uint8_t s, uint8_t hsel)
{
    if (s & 1) {
        return PSA_ALG_HMAC(hash_from_sel(hsel));
    }
    return PSA_ALG_CMAC;
}

static psa_algorithm_t sig_from_sel(uint8_t s, uint8_t hsel)
{
    switch (s % 6) {
        case 0: return PSA_ALG_RSA_PKCS1V15_SIGN(hash_from_sel(hsel));
        case 1: return PSA_ALG_RSA_PKCS1V15_SIGN_BASE; /* RAW */
        case 2: return PSA_ALG_RSA_PSS(hash_from_sel(hsel));
        case 3: return PSA_ALG_RSA_PSS_ANY_SALT(hash_from_sel(hsel));
        case 4: return PSA_ALG_ECDSA(hash_from_sel(hsel));
        default: return PSA_ALG_DETERMINISTIC_ECDSA(hash_from_sel(hsel));
    }
}

static psa_algorithm_t asym_enc_from_sel(uint8_t s, uint8_t hsel)
{
    if (s & 1) {
        return PSA_ALG_RSA_OAEP(hash_from_sel(hsel));
    }
    return PSA_ALG_RSA_PKCS1V15_CRYPT;
}

static psa_algorithm_t aead_from_sel(uint8_t s, uint8_t tag_sel)
{
    psa_algorithm_t base;

    switch (s % 3) {
        case 0: base = PSA_ALG_GCM; break;
        case 1: base = PSA_ALG_CCM; break;
        default: base = PSA_ALG_CHACHA20_POLY1305; break;
    }
    if (tag_sel & 1) {
        size_t tag_len = 4 + (tag_sel >> 2); /* 4..19, many invalid on purpose */

        return PSA_ALG_AEAD_WITH_SHORTENED_TAG(base, tag_len);
    }
    return base;
}

static psa_algorithm_t cipher_from_sel(uint8_t s)
{
    static const psa_algorithm_t t[] = {
        PSA_ALG_STREAM_CIPHER, PSA_ALG_CTR, PSA_ALG_CFB,
        PSA_ALG_ECB_NO_PADDING, PSA_ALG_CBC_NO_PADDING, PSA_ALG_CBC_PKCS7
    };

    return t[s % (sizeof(t) / sizeof(t[0]))];
}

static psa_algorithm_t kdf_from_sel(uint8_t s, uint8_t hsel)
{
    switch (s % 6) {
        case 0: return PSA_ALG_HKDF(hash_from_sel(hsel));
        case 1: return PSA_ALG_HKDF_EXTRACT(hash_from_sel(hsel));
        case 2: return PSA_ALG_HKDF_EXPAND(hash_from_sel(hsel));
        case 3: return PSA_ALG_TLS12_PRF(hash_from_sel(hsel));
        case 4: return PSA_ALG_TLS12_PSK_TO_MS(hash_from_sel(hsel));
        default: return PSA_ALG_PBKDF2_HMAC(hash_from_sel(hsel));
    }
}

static psa_key_type_t key_type_from_sel(uint8_t s)
{
    switch (s % 14) {
        case 0: return PSA_KEY_TYPE_RAW_DATA;
        case 1: return PSA_KEY_TYPE_HMAC;
        case 2: return PSA_KEY_TYPE_AES;
        case 3: return PSA_KEY_TYPE_ARIA;
        case 4: return PSA_KEY_TYPE_CAMELLIA;
        case 5: return PSA_KEY_TYPE_CHACHA20;
        case 6: return PSA_KEY_TYPE_DES;
        case 7: return PSA_KEY_TYPE_RSA_PUBLIC_KEY;
        case 8: return PSA_KEY_TYPE_RSA_KEY_PAIR;
        case 9: return PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        case 10: return PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1);
        case 11: return PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY);
        case 12: return PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919);
        default: return PSA_KEY_TYPE_PASSWORD;
    }
}

static size_t key_bits_from_sel(uint8_t s, psa_key_type_t type)
{
    switch (type) {
        case PSA_KEY_TYPE_AES:
        case PSA_KEY_TYPE_ARIA:
        case PSA_KEY_TYPE_CAMELLIA:
            return (s & 1) ? ((s & 2) ? 256 : 192) : 128;
        case PSA_KEY_TYPE_CHACHA20:
            return 256;
        case PSA_KEY_TYPE_DES:
            return 64 * (1 + (s % 3)); /* 64/128/192 */
        case PSA_KEY_TYPE_HMAC:
        case PSA_KEY_TYPE_PASSWORD:
            return 64 + 8 * (s % 56);
        case PSA_KEY_TYPE_RSA_KEY_PAIR:
            return 1024; /* keep generation fast; larger keys via import */
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1):
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1):
            return (s & 1) ? ((s & 2) ? 521 : 384) : ((s & 2) ? 256 : 224);
        case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY):
            return (s & 1) ? 448 : 255;
        case PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919):
            return (s & 1) ? 3072 : 2048;
        default:
            return 128 + 8 * (s % 16);
    }
}

static psa_key_usage_t usage_for_alg(psa_algorithm_t alg)
{
    /* Usage must be compatible with the algorithm or PSA rejects the
     * import/generation outright (NOT_PERMITTED) before any op runs. */
    if (PSA_ALG_IS_CIPHER(alg) || PSA_ALG_IS_AEAD(alg) ||
        PSA_ALG_IS_RSA_OAEP(alg) || alg == PSA_ALG_RSA_PKCS1V15_CRYPT) {
        return PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT |
               PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY;
    }
    if (PSA_ALG_IS_MAC(alg)) {
        return PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH |
               PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
               PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY;
    }
    if (PSA_ALG_IS_SIGN_HASH(alg) || PSA_ALG_IS_SIGN_MESSAGE(alg)) {
        return PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH |
               PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
               PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY;
    }
    if (PSA_ALG_IS_KEY_AGREEMENT(alg) || PSA_ALG_IS_KEY_DERIVATION(alg)) {
        return PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT |
               PSA_KEY_USAGE_COPY;
    }
    return PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_COPY;
}

/* ---- key table ---------------------------------------------------------- */

static mbedtls_svc_key_id_t g_keys[MAX_KEYS];
static unsigned g_nkeys; /* valid entries: min(g_wr, MAX_KEYS) */
static unsigned g_wr;    /* total keys ever added (ring write cursor) */

static void add_key(mbedtls_svc_key_id_t k)
{
    g_keys[g_wr % MAX_KEYS] = k;
    g_wr++;
    if (g_nkeys < MAX_KEYS) {
        g_nkeys = g_wr;
    }
}

/* ---- ops ---------------------------------------------------------------- */

static void op_hash(cursor_t *c)
{
    uint8_t hsel = get8(c);
    uint8_t sub = get8(c);
    psa_algorithm_t alg = hash_from_sel(hsel);
    uint8_t buf[MAX_CHUNK];
    psa_hash_operation_t op = psa_hash_operation_init();
    size_t len = get_len8(c, MAX_CHUNK);
    const uint8_t *p = get_bytes(c, len);

    if (p != NULL) {
        memcpy(buf, p, len);
    }

    (void) psa_hash_setup(&op, alg);
    if (len > 0 && p != NULL) {
        size_t half = len / 2;
        (void) psa_hash_update(&op, buf, half);
        (void) psa_hash_update(&op, buf + half, len - half);
    }
    if (sub & 1) {
        psa_hash_operation_t clone = psa_hash_operation_init();
        uint8_t hash[PSA_HASH_MAX_SIZE];
        size_t outlen = sizeof(hash);

        if (psa_hash_clone(&op, &clone) == PSA_SUCCESS) {
            (void) psa_hash_finish(&clone, hash, sizeof(hash), &outlen);
        }
        (void) psa_hash_abort(&clone);
    }
    if (sub & 2) {
        /* verify against attacker bytes: comparison path incl. mismatch */
        size_t vlen = PSA_HASH_LENGTH(alg);
        const uint8_t *v = get_bytes(c, vlen);

        if (v != NULL) {
            (void) psa_hash_verify(&op, v, vlen);
        }
    }
    {
        size_t outlen = sizeof(buf);
        (void) psa_hash_finish(&op, buf, sizeof(buf), &outlen);
    }
    (void) psa_hash_abort(&op);
}

static void op_import(cursor_t *c, int persistent)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_type_t type = key_type_from_sel(get8(c));
    size_t len = get_len16(c, MAX_CHUNK);
    const uint8_t *p = get_bytes(c, len);
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    uint8_t algsel;
    psa_algorithm_t alg;
    psa_status_t st;

    if (p == NULL) {
        return;
    }

    algsel = get8(c);
    if (algsel & 1) {
        alg = cipher_from_sel(get8(c));
    } else {
        switch (algsel % 6) {
            case 0: alg = hash_from_sel(get8(c)); break;
            case 1: alg = mac_from_sel(get8(c), get8(c)); break;
            case 2: alg = sig_from_sel(get8(c), get8(c)); break;
            case 3: alg = kdf_from_sel(get8(c), get8(c)); break;
            case 4: alg = aead_from_sel(get8(c), get8(c)); break;
            default: alg = asym_enc_from_sel(get8(c), get8(c)); break;
        }
    }

    psa_set_key_type(&attrs, type);
    psa_set_key_bits(&attrs, 0); /* infer from data */
    psa_set_key_usage_flags(&attrs, usage_for_alg(alg));
    psa_set_key_algorithm(&attrs, alg);
    if (persistent) {
        uint8_t idb = get8(c);

        psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_id(&attrs, PSA_ID_BASE + (idb % PERSISTENT_ID_COUNT));
    }

    st = psa_import_key(&attrs, p, len, &key);
    if (st == PSA_SUCCESS && !persistent) {
        add_key(key);
    }
}

static void op_generate(cursor_t *c, int persistent)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_type_t type = key_type_from_sel(get8(c));
    size_t bits = key_bits_from_sel(get8(c), type);
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    uint8_t algsel = get8(c);
    psa_algorithm_t alg = 0;
    psa_status_t st;

    if (algsel & 1) {
        alg = cipher_from_sel(get8(c));
    } else {
        switch (algsel % 5) {
            case 0: alg = mac_from_sel(get8(c), get8(c)); break;
            case 1: alg = sig_from_sel(get8(c), get8(c)); break;
            case 2: alg = aead_from_sel(get8(c), get8(c)); break;
            case 3: alg = asym_enc_from_sel(get8(c), get8(c)); break;
            default:
                /* raw key-agreement policy (ECDH/FFDH) */
                alg = (get8(c) & 1) ? PSA_ALG_FFDH : PSA_ALG_ECDH;
                break;
        }
    }

    psa_set_key_type(&attrs, type);
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs, usage_for_alg(alg));
    psa_set_key_algorithm(&attrs, alg);
    if (persistent) {
        psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_id(&attrs, PSA_ID_BASE + (get8(c) % PERSISTENT_ID_COUNT));
    }

    st = psa_generate_key(&attrs, &key);
    if (st == PSA_SUCCESS && !persistent) {
        add_key(key);
    }
}

static mbedtls_svc_key_id_t pick_key(cursor_t *c)
{
    if (g_nkeys == 0) {
        return MBEDTLS_SVC_KEY_ID_INIT;
    }
    return g_keys[get8(c) % g_nkeys];
}

static void op_mac(cursor_t *c)
{
    mbedtls_svc_key_id_t key = pick_key(c);
    uint8_t hsel = get8(c);
    uint8_t msel = get8(c);
    psa_algorithm_t alg = mac_from_sel(msel, hsel);
    size_t len = get_len8(c, MAX_SMALL);
    const uint8_t *p = get_bytes(c, len);
    uint8_t mac[PSA_MAC_MAX_SIZE];
    size_t maclen = 0;
    size_t vlen = get_len8(c, sizeof(mac));
    const uint8_t *v = get_bytes(c, vlen);

    if (p == NULL) {
        return;
    }
    (void) psa_mac_compute(key, alg, p, len, mac, sizeof(mac), &maclen);
    if (v != NULL) {
        (void) psa_mac_verify(key, alg, p, len, v, vlen);
    }
    /* multipart path */
    if (msel & 2) {
        psa_mac_operation_t op = psa_mac_operation_init();
        uint8_t out[PSA_MAC_MAX_SIZE];
        size_t outlen = 0;

        if (msel & 4) {
            (void) psa_mac_verify_setup(&op, key, alg);
        } else {
            (void) psa_mac_sign_setup(&op, key, alg);
        }
        (void) psa_mac_update(&op, p, len);
        if (msel & 4) {
            if (v != NULL) {
                (void) psa_mac_verify_finish(&op, v, vlen);
            }
        } else {
            (void) psa_mac_sign_finish(&op, out, sizeof(out), &outlen);
        }
        (void) psa_mac_abort(&op);
    }
}

static void op_cipher(cursor_t *c)
{
    mbedtls_svc_key_id_t key = pick_key(c);
    psa_algorithm_t alg = cipher_from_sel(get8(c));
    uint8_t mode = get8(c);
    size_t ptlen = get_len8(c, MAX_SMALL);
    const uint8_t *pt = get_bytes(c, ptlen);
    uint8_t iv[33];
    size_t ivlen;
    const uint8_t *ivp;
    uint8_t out[MAX_SMALL + 32];
    size_t outlen = 0;
    uint8_t dec[MAX_SMALL + 64];
    size_t declen = 0;

    if (pt == NULL || ptlen == 0) {
        return;
    }
    ivlen = get_len8(c, sizeof(iv));
    ivp = get_bytes(c, ivlen);
    if (ivp != NULL) {
        memcpy(iv, ivp, ivlen);
    } else {
        memset(iv, 0x5a, sizeof(iv));
        ivlen = 16;
    }

    /* 3.6 one-shot API: encrypt emits IV||ciphertext; decrypt expects IV||ct */
    if (mode & 1) {
        (void) psa_cipher_encrypt(key, alg, pt, ptlen,
                                  out, sizeof(out), &outlen);
        if (outlen > 0) {
            (void) psa_cipher_decrypt(key, alg, out, outlen,
                                      dec, sizeof(dec), &declen);
        }
    } else {
        /* attacker bytes as IV||ciphertext: parse/decrypt dark paths */
        (void) psa_cipher_decrypt(key, alg, pt, ptlen,
                                  dec, sizeof(dec), &declen);
    }
    /* multipart path */
    if (mode & 2) {
        psa_cipher_operation_t op = psa_cipher_operation_init();
        uint8_t miv[33];
        size_t mivlen = sizeof(miv);
        uint8_t mout[MAX_SMALL + 32];
        size_t moutlen = 0;
        size_t off;

        if (mode & 4) {
            (void) psa_cipher_decrypt_setup(&op, key, alg);
            if (ivlen > sizeof(miv)) {
                ivlen = sizeof(miv);
            }
            (void) psa_cipher_set_iv(&op, iv, ivlen);
        } else {
            (void) psa_cipher_encrypt_setup(&op, key, alg);
            (void) psa_cipher_generate_iv(&op, miv, sizeof(miv), &mivlen);
        }
        for (off = 0; off < ptlen; off += 97) {
            size_t chunk = (ptlen - off < 97) ? ptlen - off : 97;
            size_t written = 0;

            (void) psa_cipher_update(&op, pt + off, chunk,
                                     mout + moutlen, sizeof(mout) - moutlen,
                                     &written);
            moutlen += written;
            if (moutlen > sizeof(mout)) {
                moutlen = sizeof(mout);
            }
        }
        (void) psa_cipher_finish(&op, mout + moutlen, sizeof(mout) - moutlen,
                                 &moutlen);
        (void) psa_cipher_abort(&op);
    }
}

static void op_aead(cursor_t *c)
{
    mbedtls_svc_key_id_t key = pick_key(c);
    uint8_t tsel = get8(c);
    uint8_t nsel = get8(c);
    psa_algorithm_t alg = aead_from_sel(tsel, nsel);
    uint8_t nonce[33];
    size_t noncelen = get_len8(c, sizeof(nonce));
    const uint8_t *np = get_bytes(c, noncelen);
    size_t adlen = get_len8(c, MAX_SMALL);
    const uint8_t *ad = get_bytes(c, adlen);
    size_t ptlen = get_len8(c, MAX_SMALL);
    const uint8_t *pt = get_bytes(c, ptlen);
    uint8_t out[MAX_SMALL + 64];
    size_t outlen = 0;
    uint8_t dec[MAX_SMALL];
    size_t declen = 0;

    if (pt == NULL || (adlen > 0 && ad == NULL)) {
        return;
    }
    if (np != NULL) {
        memcpy(nonce, np, noncelen);
    } else {
        memset(nonce, 0xa5, sizeof(nonce));
        noncelen = 12;
    }

    if (nsel & 1) {
        (void) psa_aead_encrypt(key, alg, nonce, noncelen,
                                ad, adlen, pt, ptlen,
                                out, sizeof(out), &outlen);
        if (outlen > 0) {
            (void) psa_aead_decrypt(key, alg, nonce, noncelen,
                                    ad, adlen, out, outlen,
                                    dec, sizeof(dec), &declen);
        }
    } else {
        (void) psa_aead_decrypt(key, alg, nonce, noncelen,
                                ad, adlen, pt, ptlen,
                                dec, sizeof(dec), &declen);
    }
    /* multipart path with generated vs set nonce */
    {
        psa_aead_operation_t op = psa_aead_operation_init();
        uint8_t mtag[PSA_AEAD_TAG_MAX_SIZE];
        size_t taglen = sizeof(mtag);

        if (psa_aead_encrypt_setup(&op, key, alg) == PSA_SUCCESS) {
            if (nsel & 2) {
                (void) psa_aead_set_nonce(&op, nonce, noncelen);
            } else {
                (void) psa_aead_generate_nonce(&op, nonce, sizeof(nonce),
                                               &noncelen);
            }
            (void) psa_aead_update_ad(&op, ad, adlen);
            {
                size_t off;
                size_t total = 0;

                for (off = 0; off < ptlen; off += 64) {
                    size_t chunk = (ptlen - off < 64) ? ptlen - off : 64;
                    size_t written = 0;

                    (void) psa_aead_update(&op, pt + off, chunk,
                                           out + total, sizeof(out) - total,
                                           &written);
                    total += written;
                    if (total > sizeof(out)) {
                        total = sizeof(out);
                    }
                }
            }
            (void) psa_aead_finish(&op, out, 0, &outlen,
                                   mtag, sizeof(mtag), &taglen);
        }
        (void) psa_aead_abort(&op);
    }
}

static void op_sign_verify_hash(cursor_t *c, int verify)
{
    mbedtls_svc_key_id_t key = pick_key(c);
    psa_algorithm_t alg = sig_from_sel(get8(c), get8(c));
    size_t hlen = get_len8(c, 128);
    const uint8_t *h = get_bytes(c, hlen);
    uint8_t sig[PSA_SIGNATURE_MAX_SIZE];
    size_t siglen = 0;
    size_t vlen = get_len8(c, sizeof(sig));
    const uint8_t *v = get_bytes(c, vlen);

    if (h == NULL) {
        return;
    }
    if (verify) {
        if (v != NULL) {
            (void) psa_verify_hash(key, alg, h, hlen, v, vlen);
        }
    } else {
        (void) psa_sign_hash(key, alg, h, hlen, sig, sizeof(sig), &siglen);
        if (v != NULL) {
            (void) psa_verify_hash(key, alg, h, hlen, v, vlen);
        } else if (siglen > 0) {
            (void) psa_verify_hash(key, alg, h, hlen, sig, siglen);
        }
    }
}

static void op_sign_verify_message(cursor_t *c, int verify)
{
    mbedtls_svc_key_id_t key = pick_key(c);
    psa_algorithm_t alg = sig_from_sel(get8(c), get8(c));
    size_t mlen = get_len8(c, MAX_SMALL);
    const uint8_t *m = get_bytes(c, mlen);
    uint8_t sig[PSA_SIGNATURE_MAX_SIZE];
    size_t siglen = 0;
    size_t vlen = get_len8(c, sizeof(sig));
    const uint8_t *v = get_bytes(c, vlen);

    if (m == NULL) {
        return;
    }
    if (verify) {
        if (v != NULL) {
            (void) psa_verify_message(key, alg, m, mlen, v, vlen);
        }
    } else {
        (void) psa_sign_message(key, alg, m, mlen, sig, sizeof(sig), &siglen);
        if (siglen > 0) {
            (void) psa_verify_message(key, alg, m, mlen, sig, siglen);
        }
    }
}

static void op_asymmetric(cursor_t *c, int decrypt)
{
    mbedtls_svc_key_id_t key = pick_key(c);
    psa_algorithm_t alg = asym_enc_from_sel(get8(c), get8(c));
    size_t inlen = get_len8(c, MAX_SMALL);
    const uint8_t *in = get_bytes(c, inlen);
    size_t saltlen = get_len8(c, 64);
    const uint8_t *salt = get_bytes(c, saltlen);
    uint8_t out[PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE];
    size_t outlen = 0;

    /* PSA requires a valid buffer whenever the length is non-zero */
    if (in == NULL || (saltlen > 0 && salt == NULL)) {
        return;
    }
    if (decrypt) {
        (void) psa_asymmetric_decrypt(key, alg, in, inlen,
                                      salt, saltlen,
                                      out, sizeof(out), &outlen);
    } else {
        (void) psa_asymmetric_encrypt(key, alg, in, inlen,
                                      salt, saltlen,
                                      out, sizeof(out), &outlen);
    }
}

static void op_key_agreement(cursor_t *c)
{
    mbedtls_svc_key_id_t key = pick_key(c);
    uint8_t asel = get8(c);
    psa_algorithm_t alg = (asel & 1) ? PSA_ALG_FFDH : PSA_ALG_ECDH;
    size_t peerlen = get_len8(c, MAX_SMALL);
    const uint8_t *peer = get_bytes(c, peerlen);
    uint8_t shared[1024]; /* >= raw agreement output for any supported group */
    size_t sharedlen = 0;

    if (peer == NULL) {
        return;
    }
    (void) psa_raw_key_agreement(alg, key, peer, peerlen,
                                 shared, sizeof(shared), &sharedlen);
}

static void op_kdf(cursor_t *c)
{
    psa_algorithm_t alg = kdf_from_sel(get8(c), get8(c));
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    uint8_t steps = get8(c);
    uint8_t i;
    uint32_t capacity = (uint32_t) (get16(&c[0]) & 0xFFFu) * 8u + 1u;

    if (psa_key_derivation_setup(&op, alg) != PSA_SUCCESS) {
        (void) psa_key_derivation_abort(&op);
        return;
    }
    (void) psa_key_derivation_set_capacity(&op, capacity);

    for (i = 0; i < steps && i < 12; i++) {
        uint8_t s = get8(c);
        psa_key_derivation_step_t step;
        size_t len;
        const uint8_t *p;

        switch (s % 7) {
            case 0: step = PSA_KEY_DERIVATION_INPUT_SECRET; break;
            case 1: step = PSA_KEY_DERIVATION_INPUT_PASSWORD; break;
            case 2: step = PSA_KEY_DERIVATION_INPUT_SALT; break;
            case 3: step = PSA_KEY_DERIVATION_INPUT_LABEL; break;
            case 4: step = PSA_KEY_DERIVATION_INPUT_INFO; break;
            case 5: step = PSA_KEY_DERIVATION_INPUT_SEED; break;
            default: step = PSA_KEY_DERIVATION_INPUT_OTHER_SECRET; break;
        }
        if (s & 0x40) {
            /* key-input path (SECRET/OTHER_SECRET/PASSWORD as stored key) */
            (void) psa_key_derivation_input_key(&op, step, pick_key(c));
        } else {
            len = get_len8(c, MAX_SMALL);
            p = get_bytes(c, len);
            if (p == NULL) {
                break;
            }
            (void) psa_key_derivation_input_bytes(&op, step, p, len);
        }
    }

    {
        uint8_t outs = get8(c);
        uint8_t j;
        uint8_t out[MAX_SMALL];
        size_t outlen;

        for (j = 0; j < outs && j < 8; j++) {
            if (j & 1) {
                psa_key_attributes_t attrs = psa_key_attributes_init();
                psa_key_type_t t = key_type_from_sel(get8(c));
                mbedtls_svc_key_id_t k = MBEDTLS_SVC_KEY_ID_INIT;

                psa_set_key_type(&attrs, t);
                psa_set_key_bits(&attrs, key_bits_from_sel(get8(c), t));
                {
                    psa_algorithm_t dalg = kdf_from_sel(get8(c), get8(c));

                    psa_set_key_usage_flags(&attrs, usage_for_alg(dalg));
                    psa_set_key_algorithm(&attrs, dalg);
                }
                if (psa_key_derivation_output_key(&attrs, &op, &k) ==
                    PSA_SUCCESS) {
                    add_key(k);
                }
                (void) psa_reset_key_attributes(&attrs);
            } else {
                outlen = get_len8(c, sizeof(out));
                (void) psa_key_derivation_output_bytes(&op, out, outlen);
            }
        }
    }
    (void) psa_key_derivation_abort(&op);
}

static void op_export(cursor_t *c, int public_only)
{
    mbedtls_svc_key_id_t key = pick_key(c);
    uint8_t buf[MAX_CHUNK];
    size_t len = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();

    if (public_only) {
        (void) psa_export_public_key(key, buf, sizeof(buf), &len);
    } else {
        (void) psa_export_key(key, buf, sizeof(buf), &len);
    }
    (void) psa_get_key_attributes(key, &attrs);
    (void) psa_reset_key_attributes(&attrs);
}

static void op_copy_purge_destroy(cursor_t *c, int mode)
{
    mbedtls_svc_key_id_t src = pick_key(c);

    if (mode == 0) {
        psa_key_attributes_t attrs = psa_key_attributes_init();
        mbedtls_svc_key_id_t dst = MBEDTLS_SVC_KEY_ID_INIT;

        (void) psa_get_key_attributes(src, &attrs);
        psa_set_key_usage_flags(&attrs,
                                usage_for_alg(psa_get_key_algorithm(&attrs)));
        (void) psa_copy_key(src, &attrs, &dst);
        /* destroying an invalid handle is a harmless INVALID_HANDLE */
        (void) psa_destroy_key(dst);
        (void) psa_reset_key_attributes(&attrs);
    } else if (mode == 1) {
        (void) psa_purge_key(src);
    } else {
        (void) psa_destroy_key(src);
    }
}

static void op_open(cursor_t *c)
{
    uint8_t idb = get8(c);
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;

    (void) psa_open_key(PSA_ID_BASE + (idb % PERSISTENT_ID_COUNT), &key);
}

static void op_generate_random(cursor_t *c)
{
    uint8_t buf[MAX_SMALL];
    size_t len = get_len8(c, sizeof(buf));

    (void) psa_generate_random(buf, len);
}

/* ---- driver ------------------------------------------------------------- */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    cursor_t c = { Data, Size, 0 };
    uint8_t nops;
    uint8_t i;

    if (Size < 2) {
        return 0;
    }

    fuzz_platform_init();
    if (psa_crypto_init() != PSA_SUCCESS) {
        return 0;
    }

    memset(g_keys, 0, sizeof(g_keys));
    g_nkeys = 0;
    g_wr = 0;

    nops = get8(&c);
    if (nops > MAX_OPS) {
        nops = MAX_OPS;
    }

    for (i = 0; i < nops; i++) {
        uint8_t op = get8(&c);

        switch (op % 22) {
            case 0: op_import(&c, 0); break;
            case 1: op_generate(&c, 0); break;
            case 2: op_hash(&c); break;
            case 3: op_mac(&c); break;
            case 4: op_cipher(&c); break;
            case 5: op_aead(&c); break;
            case 6: op_sign_verify_hash(&c, 0); break;
            case 7: op_sign_verify_hash(&c, 1); break;
            case 8: op_sign_verify_message(&c, 0); break;
            case 9: op_sign_verify_message(&c, 1); break;
            case 10: op_asymmetric(&c, 0); break;
            case 11: op_asymmetric(&c, 1); break;
            case 12: op_key_agreement(&c); break;
            case 13: op_kdf(&c); break;
            case 14: op_export(&c, 0); break;
            case 15: op_export(&c, 1); break;
            case 16: op_copy_purge_destroy(&c, 0); break;
            case 17: op_copy_purge_destroy(&c, 1); break;
            case 18: op_import(&c, 1); break;
            case 19: op_generate(&c, 1); break;
            case 20: op_generate_random(&c); break;
            default: op_open(&c); break;
        }
        if (c.pos >= c.n) {
            break;
        }
    }

    /* destroy every created key: volatile slots + the persistent id range */
    for (i = 0; i < g_nkeys; i++) {
        (void) psa_destroy_key(g_keys[i]);
    }
    for (i = 0; i < PERSISTENT_ID_COUNT; i++) {
        mbedtls_svc_key_id_t k = MBEDTLS_SVC_KEY_ID_INIT;

        if (psa_open_key(PSA_ID_BASE + i, &k) == PSA_SUCCESS) {
            (void) psa_destroy_key(k);
        }
    }

    mbedtls_psa_crypto_free();
    return 0;
}
