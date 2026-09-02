/* Multipart PSA AEAD under allocation failure.
 *
 * The record layer only ever calls the one-shot psa_aead_encrypt/decrypt, so
 * the multipart state machine - setup, set_nonce, set_lengths, update_ad,
 * update, finish, verify, abort - has no other harness. Its cleanup paths are
 * the interesting part: every public psa_* entry point taking a buffer copies
 * it locally (unless MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS is set, and it is
 * not), so failing one allocation drives the error arms that no input can.
 *
 *   byte 0        algorithm selector
 *   byte 1        key type / size selector
 *   byte 2        operation order selector
 *   bytes 3-4     allocation countdown, little-endian; 0xffff means no failure
 *   byte 5        nonce length selector
 *   rest          key material, additional data and plaintext
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "psa/crypto.h"
#include "fuzz_common.h"

#define FUZZ_AEAD_HDR 6

#if defined(PSA_WANT_KEY_TYPE_AES) || defined(PSA_WANT_KEY_TYPE_CHACHA20)
static const psa_algorithm_t aead_algs[] = {
    PSA_ALG_GCM,
    PSA_ALG_CCM,
    PSA_ALG_CHACHA20_POLY1305,
    PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 8),
    PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 4),
    PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(PSA_ALG_GCM, 12),
};
#define N_AEAD_ALGS (sizeof(aead_algs) / sizeof(aead_algs[0]))

struct key_shape {
    psa_key_type_t type;
    size_t bits;
};

static const struct key_shape key_shapes[] = {
    { PSA_KEY_TYPE_AES, 128 },
    { PSA_KEY_TYPE_AES, 192 },
    { PSA_KEY_TYPE_AES, 256 },
    { PSA_KEY_TYPE_CHACHA20, 256 },
};
#define N_KEY_SHAPES (sizeof(key_shapes) / sizeof(key_shapes[0]))

/* Drive one multipart encryption to its end. The tag buffer is a heap block of
 * exactly the size the caller declares, so a write past what the contract
 * permits lands outside it. */
static void aead_encrypt_pass(mbedtls_svc_key_id_t key, psa_algorithm_t alg,
                              unsigned order, size_t nonce_len,
                              const uint8_t *ad, size_t ad_len,
                              const uint8_t *pt, size_t pt_len)
{
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    unsigned char nonce[16];
    unsigned char *ct = NULL, *tag = NULL;
    size_t ct_size, ct_len = 0, fin_len = 0, tag_size, tag_len = 0;

    if (psa_aead_encrypt_setup(&op, key, alg) != PSA_SUCCESS) {
        goto done;
    }
    memset(nonce, 0x5a, sizeof(nonce));
    if (nonce_len > sizeof(nonce)) {
        nonce_len = sizeof(nonce);
    }
    if (psa_aead_set_nonce(&op, nonce, nonce_len) != PSA_SUCCESS) {
        goto done;
    }
    if (order & 1) {
        /* CCM requires the lengths up front; other algorithms accept them. */
        (void) psa_aead_set_lengths(&op, ad_len, pt_len);
    }
    (void) psa_aead_update_ad(&op, ad, ad_len);

    ct_size = PSA_AEAD_UPDATE_OUTPUT_SIZE(PSA_KEY_TYPE_AES, alg, pt_len) + 64;
    ct = malloc(ct_size != 0 ? ct_size : 1);
    if (ct == NULL) {
        goto done;
    }
    (void) psa_aead_update(&op, pt, pt_len, ct, ct_size, &ct_len);

    if (order & 2) {
        /* A zero-size ciphertext buffer makes the tag the only allocation
         * psa_aead_finish() attempts, so an injected failure is necessarily the
         * tag's. That separates the tag-is-NULL-with-a-non-zero-length case
         * from the harmless NULL-plus-zero one, which the same helper also
         * reaches and which proves nothing. */
        tag_size = PSA_AEAD_TAG_LENGTH(PSA_KEY_TYPE_AES, 128, alg);
        if (tag_size == 0 || tag_size > 64) {
            goto done;
        }
        tag = malloc(tag_size);
        if (tag == NULL) {
            goto done;
        }
        (void) psa_aead_finish(&op, NULL, 0, &fin_len, tag, tag_size, &tag_len);
        goto done;
    }

    /* Exactly the declared size: psa_aead_finish() may write tag_size bytes and
     * no more, so an over-write is an over-write of this allocation. */
    tag_size = PSA_AEAD_TAG_LENGTH(PSA_KEY_TYPE_AES, 128, alg);
    if (tag_size == 0 || tag_size > 64) {
        goto done;
    }
    tag = malloc(tag_size);
    if (tag == NULL) {
        goto done;
    }
    (void) psa_aead_finish(&op, ct, ct_size, &fin_len,
                           tag, tag_size, &tag_len);
done:
    psa_aead_abort(&op);
    free(ct);
    free(tag);
}
#endif /* PSA_WANT_KEY_TYPE_AES || PSA_WANT_KEY_TYPE_CHACHA20 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    srand(1);
    fuzz_watchdog_arm();
#if defined(PSA_WANT_KEY_TYPE_AES) || defined(PSA_WANT_KEY_TYPE_CHACHA20)
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
    const struct key_shape *shape;
    psa_algorithm_t alg;
    unsigned char key_bytes[32];
    unsigned long countdown;
    size_t nonce_len, ad_len, body;
    const uint8_t *payload;

    if (Size < FUZZ_AEAD_HDR + 1) {
        goto exit;
    }
    if (psa_crypto_init() != PSA_SUCCESS) {
        goto exit;
    }
    dummy_init();

    alg = aead_algs[Data[0] % N_AEAD_ALGS];
    shape = &key_shapes[Data[1] % N_KEY_SHAPES];
    countdown = (unsigned long) Data[3] | ((unsigned long) Data[4] << 8);
    nonce_len = Data[5] % 17;

    payload = Data + FUZZ_AEAD_HDR;
    body = Size - FUZZ_AEAD_HDR;
    ad_len = body / 2;

    memset(key_bytes, 0, sizeof(key_bytes));
    memcpy(key_bytes, payload, body < sizeof(key_bytes) ? body : sizeof(key_bytes));

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, alg);
    psa_set_key_type(&attr, shape->type);
    if (psa_import_key(&attr, key_bytes, shape->bits / 8, &key) != PSA_SUCCESS) {
        goto exit;
    }

    /* 0xffff is the "run clean" encoding, so the same corpus entry can be
     * compared with and without a failure injected. */
    if (countdown != 0xffff) {
        fuzz_fail_alloc_after(countdown);
    }
    aead_encrypt_pass(key, alg, Data[2], nonce_len,
                      payload, ad_len, payload + ad_len, body - ad_len);
    fuzz_fail_alloc_off();

    psa_destroy_key(key);
exit:
    mbedtls_psa_crypto_free();
#else
    (void) Data;
    (void) Size;
#endif
    fuzz_watchdog_disarm();
    return 0;
}
