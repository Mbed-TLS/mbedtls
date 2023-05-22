/*
 *  Public Key abstraction layer: wrapper functions
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

#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PK_C)
#include "pk_wrap.h"
#include "pk_internal.h"
#include "mbedtls/error.h"

/* Even if RSA not activated, for the sake of RSA-alt */
#include "mbedtls/rsa.h"

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_PSA_CRYPTO_C)
#include "pkwrite.h"
#endif

#if defined(MBEDTLS_PSA_CRYPTO_C)
#include "mbedtls/psa_util.h"
#define PSA_PK_TO_MBEDTLS_ERR(status) psa_pk_status_to_mbedtls(status)
#define PSA_PK_RSA_TO_MBEDTLS_ERR(status) PSA_TO_MBEDTLS_ERR_LIST(status,     \
                                                                  psa_to_pk_rsa_errors,            \
                                                                  psa_pk_status_to_mbedtls)
#define PSA_PK_ECDSA_TO_MBEDTLS_ERR(status) PSA_TO_MBEDTLS_ERR_LIST(status,   \
                                                                    psa_to_pk_ecdsa_errors,        \
                                                                    psa_pk_status_to_mbedtls)
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#include "hash_info.h"

#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
#include "mbedtls/asn1write.h"
#include "mbedtls/asn1.h"
#endif
#endif  /* MBEDTLS_USE_PSA_CRYPTO */

#include "mbedtls/platform.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#if defined(MBEDTLS_PSA_CRYPTO_C)
int mbedtls_pk_error_from_psa(psa_status_t status)
{
    switch (status) {
        case PSA_SUCCESS:
            return 0;
        case PSA_ERROR_INVALID_HANDLE:
            return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
        case PSA_ERROR_NOT_PERMITTED:
            return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
        case PSA_ERROR_BUFFER_TOO_SMALL:
            return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
        case PSA_ERROR_NOT_SUPPORTED:
            return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
        case PSA_ERROR_INVALID_ARGUMENT:
            return MBEDTLS_ERR_PK_INVALID_ALG;
        case PSA_ERROR_INSUFFICIENT_MEMORY:
            return MBEDTLS_ERR_PK_ALLOC_FAILED;
        case PSA_ERROR_BAD_STATE:
            return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        case PSA_ERROR_COMMUNICATION_FAILURE:
        case PSA_ERROR_HARDWARE_FAILURE:
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        case PSA_ERROR_DATA_CORRUPT:
        case PSA_ERROR_DATA_INVALID:
        case PSA_ERROR_STORAGE_FAILURE:
            return MBEDTLS_ERR_PK_FILE_IO_ERROR;
        case PSA_ERROR_CORRUPTION_DETECTED:
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        default:
            return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }
}

#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY) ||    \
    defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR)
int mbedtls_pk_error_from_psa_rsa(psa_status_t status)
{
    switch (status) {
        case PSA_ERROR_NOT_PERMITTED:
        case PSA_ERROR_INVALID_ARGUMENT:
        case PSA_ERROR_INVALID_HANDLE:
            return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        case PSA_ERROR_BUFFER_TOO_SMALL:
            return MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
        case PSA_ERROR_INSUFFICIENT_ENTROPY:
            return MBEDTLS_ERR_RSA_RNG_FAILED;
        case PSA_ERROR_INVALID_SIGNATURE:
            return MBEDTLS_ERR_RSA_VERIFY_FAILED;
        case PSA_ERROR_INVALID_PADDING:
            return MBEDTLS_ERR_RSA_INVALID_PADDING;
        case PSA_SUCCESS:
            return 0;
        case PSA_ERROR_NOT_SUPPORTED:
            return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
        case PSA_ERROR_INSUFFICIENT_MEMORY:
            return MBEDTLS_ERR_PK_ALLOC_FAILED;
        case PSA_ERROR_BAD_STATE:
            return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        case PSA_ERROR_COMMUNICATION_FAILURE:
        case PSA_ERROR_HARDWARE_FAILURE:
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        case PSA_ERROR_DATA_CORRUPT:
        case PSA_ERROR_DATA_INVALID:
        case PSA_ERROR_STORAGE_FAILURE:
            return MBEDTLS_ERR_PK_FILE_IO_ERROR;
        case PSA_ERROR_CORRUPTION_DETECTED:
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        default:
            return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }
}
#endif /* PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY || PSA_WANT_KEY_TYPE_RSA_KEY_PAIR */
#endif /* MBEDTLS_PSA_CRYPTO_C */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
int mbedtls_pk_error_from_psa_ecdsa(psa_status_t status)
{
    switch (status) {
        case PSA_ERROR_NOT_PERMITTED:
        case PSA_ERROR_INVALID_ARGUMENT:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        case PSA_ERROR_INVALID_HANDLE:
            return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
        case PSA_ERROR_BUFFER_TOO_SMALL:
            return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        case PSA_ERROR_INSUFFICIENT_ENTROPY:
            return MBEDTLS_ERR_ECP_RANDOM_FAILED;
        case PSA_ERROR_INVALID_SIGNATURE:
            return MBEDTLS_ERR_ECP_VERIFY_FAILED;
        case PSA_SUCCESS:
            return 0;
        case PSA_ERROR_NOT_SUPPORTED:
            return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
        case PSA_ERROR_INSUFFICIENT_MEMORY:
            return MBEDTLS_ERR_PK_ALLOC_FAILED;
        case PSA_ERROR_BAD_STATE:
            return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        case PSA_ERROR_COMMUNICATION_FAILURE:
        case PSA_ERROR_HARDWARE_FAILURE:
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        case PSA_ERROR_DATA_CORRUPT:
        case PSA_ERROR_DATA_INVALID:
        case PSA_ERROR_STORAGE_FAILURE:
            return MBEDTLS_ERR_PK_FILE_IO_ERROR;
        case PSA_ERROR_CORRUPTION_DETECTED:
            return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        default:
            return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    }
}
#endif /* PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY */
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* !MBEDTLS_DEPRECATED_REMOVED */

#if defined(MBEDTLS_RSA_C)
static int rsa_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_RSA ||
           type == MBEDTLS_PK_RSASSA_PSS;
}

static size_t rsa_get_bitlen(mbedtls_pk_context *pk)
{
    const mbedtls_rsa_context *rsa = (const mbedtls_rsa_context *) pk->pk_ctx;
    return 8 * mbedtls_rsa_get_len(rsa);
}

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int rsa_verify_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;
    mbedtls_pk_context key;
    int key_len;
    unsigned char buf[MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES];
    psa_algorithm_t psa_alg_md =
        PSA_ALG_RSA_PKCS1V15_SIGN(mbedtls_hash_info_psa_from_md(md_alg));
    size_t rsa_len = mbedtls_rsa_get_len(rsa);

    if (md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (sig_len < rsa_len) {
        return MBEDTLS_ERR_RSA_VERIFY_FAILED;
    }

    /* mbedtls_pk_write_pubkey_der() expects a full PK context;
     * re-construct one to make it happy */
    key.pk_info = &mbedtls_rsa_info;
    key.pk_ctx = rsa;
    key_len = mbedtls_pk_write_pubkey_der(&key, buf, sizeof(buf));
    if (key_len <= 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, psa_alg_md);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);

    status = psa_import_key(&attributes,
                            buf + sizeof(buf) - key_len, key_len,
                            &key_id);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = psa_verify_hash(key_id, psa_alg_md, hash, hash_len,
                             sig, sig_len);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }
    ret = 0;

cleanup:
    status = psa_destroy_key(key_id);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#else
static int rsa_verify_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;
    size_t rsa_len = mbedtls_rsa_get_len(rsa);

    if (md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (sig_len < rsa_len) {
        return MBEDTLS_ERR_RSA_VERIFY_FAILED;
    }

    if ((ret = mbedtls_rsa_pkcs1_verify(rsa, md_alg,
                                        (unsigned int) hash_len,
                                        hash, sig)) != 0) {
        return ret;
    }

    /* The buffer contains a valid signature followed by extra data.
     * We have a special error code for that so that so that callers can
     * use mbedtls_pk_verify() to check "Does the buffer start with a
     * valid signature?" and not just "Does the buffer contain a valid
     * signature?". */
    if (sig_len > rsa_len) {
        return MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return 0;
}
#endif

#if defined(MBEDTLS_PSA_CRYPTO_C)
int  mbedtls_pk_psa_rsa_sign_ext(psa_algorithm_t alg,
                                 mbedtls_rsa_context *rsa_ctx,
                                 const unsigned char *hash, size_t hash_len,
                                 unsigned char *sig, size_t sig_size,
                                 size_t *sig_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;
    mbedtls_pk_context key;
    int key_len;
    unsigned char buf[MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES];
    mbedtls_pk_info_t pk_info = mbedtls_rsa_info;

    *sig_len = mbedtls_rsa_get_len(rsa_ctx);
    if (sig_size < *sig_len) {
        return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    /* mbedtls_pk_write_key_der() expects a full PK context;
     * re-construct one to make it happy */
    key.pk_info = &pk_info;
    key.pk_ctx = rsa_ctx;
    key_len = mbedtls_pk_write_key_der(&key, buf, sizeof(buf));
    if (key_len <= 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);

    status = psa_import_key(&attributes,
                            buf + sizeof(buf) - key_len, key_len,
                            &key_id);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }
    status = psa_sign_hash(key_id, alg, hash, hash_len,
                           sig, sig_size, sig_len);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    status = psa_destroy_key(key_id);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
    }
    return ret;
}
#endif /* MBEDTLS_PSA_CRYPTO_C */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int rsa_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t sig_size, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    ((void) f_rng);
    ((void) p_rng);

    psa_algorithm_t psa_md_alg;
    psa_md_alg = mbedtls_hash_info_psa_from_md(md_alg);
    if (psa_md_alg == 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    return mbedtls_pk_psa_rsa_sign_ext(PSA_ALG_RSA_PKCS1V15_SIGN(
                                           psa_md_alg),
                                       pk->pk_ctx, hash, hash_len,
                                       sig, sig_size, sig_len);
}
#else
static int rsa_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t sig_size, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;

    if (md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    *sig_len = mbedtls_rsa_get_len(rsa);
    if (sig_size < *sig_len) {
        return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    return mbedtls_rsa_pkcs1_sign(rsa, f_rng, p_rng,
                                  md_alg, (unsigned int) hash_len,
                                  hash, sig);
}
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int rsa_decrypt_wrap(mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;
    mbedtls_pk_context key;
    int key_len;
    unsigned char buf[MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES];

    ((void) f_rng);
    ((void) p_rng);

#if !defined(MBEDTLS_RSA_ALT)
    if (rsa->padding != MBEDTLS_RSA_PKCS_V15) {
        return MBEDTLS_ERR_RSA_INVALID_PADDING;
    }
#endif /* !MBEDTLS_RSA_ALT */

    if (ilen != mbedtls_rsa_get_len(rsa)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    /* mbedtls_pk_write_key_der() expects a full PK context;
     * re-construct one to make it happy */
    key.pk_info = &mbedtls_rsa_info;
    key.pk_ctx = rsa;
    key_len = mbedtls_pk_write_key_der(&key, buf, sizeof(buf));
    if (key_len <= 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_CRYPT);

    status = psa_import_key(&attributes,
                            buf + sizeof(buf) - key_len, key_len,
                            &key_id);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = psa_asymmetric_decrypt(key_id, PSA_ALG_RSA_PKCS1V15_CRYPT,
                                    input, ilen,
                                    NULL, 0,
                                    output, osize, olen);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    mbedtls_platform_zeroize(buf, sizeof(buf));
    status = psa_destroy_key(key_id);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#else
static int rsa_decrypt_wrap(mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;

    if (ilen != mbedtls_rsa_get_len(rsa)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    return mbedtls_rsa_pkcs1_decrypt(rsa, f_rng, p_rng,
                                     olen, input, output, osize);
}
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int rsa_encrypt_wrap(mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;
    mbedtls_pk_context key;
    int key_len;
    unsigned char buf[MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES];

    ((void) f_rng);
    ((void) p_rng);

#if !defined(MBEDTLS_RSA_ALT)
    if (rsa->padding != MBEDTLS_RSA_PKCS_V15) {
        return MBEDTLS_ERR_RSA_INVALID_PADDING;
    }
#endif

    if (mbedtls_rsa_get_len(rsa) > osize) {
        return MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
    }

    /* mbedtls_pk_write_pubkey_der() expects a full PK context;
     * re-construct one to make it happy */
    key.pk_info = &mbedtls_rsa_info;
    key.pk_ctx = rsa;
    key_len = mbedtls_pk_write_pubkey_der(&key, buf, sizeof(buf));
    if (key_len <= 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_CRYPT);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);

    status = psa_import_key(&attributes,
                            buf + sizeof(buf) - key_len, key_len,
                            &key_id);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = psa_asymmetric_encrypt(key_id, PSA_ALG_RSA_PKCS1V15_CRYPT,
                                    input, ilen,
                                    NULL, 0,
                                    output, osize, olen);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    status = psa_destroy_key(key_id);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#else
static int rsa_encrypt_wrap(mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;
    *olen = mbedtls_rsa_get_len(rsa);

    if (*olen > osize) {
        return MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
    }

    return mbedtls_rsa_pkcs1_encrypt(rsa, f_rng, p_rng,
                                     ilen, input, output);
}
#endif

static int rsa_check_pair_wrap(mbedtls_pk_context *pub, mbedtls_pk_context *prv,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng)
{
    (void) f_rng;
    (void) p_rng;
    return mbedtls_rsa_check_pub_priv((const mbedtls_rsa_context *) pub->pk_ctx,
                                      (const mbedtls_rsa_context *) prv->pk_ctx);
}

static void *rsa_alloc_wrap(void)
{
    void *ctx = mbedtls_calloc(1, sizeof(mbedtls_rsa_context));

    if (ctx != NULL) {
        mbedtls_rsa_init((mbedtls_rsa_context *) ctx);
    }

    return ctx;
}

static void rsa_free_wrap(void *ctx)
{
    mbedtls_rsa_free((mbedtls_rsa_context *) ctx);
    mbedtls_free(ctx);
}

static void rsa_debug(mbedtls_pk_context *pk, mbedtls_pk_debug_item *items)
{
#if defined(MBEDTLS_RSA_ALT)
    /* Not supported */
    (void) pk;
    (void) items;
#else
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;

    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.N";
    items->value = &(rsa->N);

    items++;

    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.E";
    items->value = &(rsa->E);
#endif
}

const mbedtls_pk_info_t mbedtls_rsa_info = {
    MBEDTLS_PK_RSA,
    "RSA",
    rsa_get_bitlen,
    rsa_can_do,
    rsa_verify_wrap,
    rsa_sign_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    rsa_decrypt_wrap,
    rsa_encrypt_wrap,
    rsa_check_pair_wrap,
    rsa_alloc_wrap,
    rsa_free_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    rsa_debug,
};
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_ECP_LIGHT)
/*
 * Generic EC key
 */
static int eckey_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_ECKEY ||
           type == MBEDTLS_PK_ECKEY_DH ||
           type == MBEDTLS_PK_ECDSA;
}

static size_t eckey_get_bitlen(mbedtls_pk_context *pk)
{
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    return pk->ec_bits;
#else
    mbedtls_ecp_keypair *ecp = (mbedtls_ecp_keypair *) pk->pk_ctx;
    return ecp->grp.pbits;
#endif
}

#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
/*
 * An ASN.1 encoded signature is a sequence of two ASN.1 integers. Parse one of
 * those integers and convert it to the fixed-length encoding expected by PSA.
 */
static int extract_ecdsa_sig_int(unsigned char **from, const unsigned char *end,
                                 unsigned char *to, size_t to_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t unpadded_len, padding_len;

    if ((ret = mbedtls_asn1_get_tag(from, end, &unpadded_len,
                                    MBEDTLS_ASN1_INTEGER)) != 0) {
        return ret;
    }

    while (unpadded_len > 0 && **from == 0x00) {
        (*from)++;
        unpadded_len--;
    }

    if (unpadded_len > to_len || unpadded_len == 0) {
        return MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

    padding_len = to_len - unpadded_len;
    memset(to, 0x00, padding_len);
    memcpy(to + padding_len, *from, unpadded_len);
    (*from) += unpadded_len;

    return 0;
}

/*
 * Convert a signature from an ASN.1 sequence of two integers
 * to a raw {r,s} buffer. Note: the provided sig buffer must be at least
 * twice as big as int_size.
 */
static int extract_ecdsa_sig(unsigned char **p, const unsigned char *end,
                             unsigned char *sig, size_t int_size)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t tmp_size;

    if ((ret = mbedtls_asn1_get_tag(p, end, &tmp_size,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return ret;
    }

    /* Extract r */
    if ((ret = extract_ecdsa_sig_int(p, end, sig, int_size)) != 0) {
        return ret;
    }
    /* Extract s */
    if ((ret = extract_ecdsa_sig_int(p, end, sig + int_size, int_size)) != 0) {
        return ret;
    }

    return 0;
}

static int ecdsa_verify_wrap(mbedtls_pk_context *pk,
                             mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;
    unsigned char *p;
    psa_algorithm_t psa_sig_md = PSA_ALG_ECDSA_ANY;
    size_t signature_len;
    ((void) md_alg);
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    unsigned char buf[PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE];
    psa_ecc_family_t curve = pk->ec_family;
    size_t curve_bits = pk->ec_bits;
#else
    mbedtls_ecp_keypair *ctx = pk->pk_ctx;
    size_t key_len;
    /* This buffer will initially contain the public key and then the signature
     * but at different points in time. For all curves except secp224k1, which
     * is not currently supported in PSA, the public key is one byte longer
     * (header byte + 2 numbers, while the signature is only 2 numbers),
     * so use that as the buffer size. */
    unsigned char buf[MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t curve_bits;
    psa_ecc_family_t curve =
        mbedtls_ecc_group_to_psa(ctx->grp.id, &curve_bits);
#endif

    if (curve == 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, psa_sig_md);

#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    status = psa_import_key(&attributes,
                            pk->pub_raw, pk->pub_raw_len,
                            &key_id);
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
    ret = mbedtls_ecp_point_write_binary(&ctx->grp, &ctx->Q,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &key_len, buf, sizeof(buf));
    if (ret != 0) {
        goto cleanup;
    }

    status = psa_import_key(&attributes,
                            buf, key_len,
                            &key_id);
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    signature_len = PSA_ECDSA_SIGNATURE_SIZE(curve_bits);
    if (signature_len > sizeof(buf)) {
        ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        goto cleanup;
    }

    p = (unsigned char *) sig;
    /* extract_ecdsa_sig's last parameter is the size
     * of each integer to be parsed, so it's actually half
     * the size of the signature. */
    if ((ret = extract_ecdsa_sig(&p, sig + sig_len, buf,
                                 signature_len/2)) != 0) {
        goto cleanup;
    }

    status = psa_verify_hash(key_id, psa_sig_md,
                             hash, hash_len,
                             buf, signature_len);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    if (p != sig + sig_len) {
        ret = MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
        goto cleanup;
    }
    ret = 0;

cleanup:
    status = psa_destroy_key(key_id);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int ecdsa_verify_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) md_alg);

    ret = mbedtls_ecdsa_read_signature((mbedtls_ecdsa_context *) pk->pk_ctx,
                                       hash, hash_len, sig, sig_len);

    if (ret == MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH) {
        return MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return ret;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */

#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
/*
 * Simultaneously convert and move raw MPI from the beginning of a buffer
 * to an ASN.1 MPI at the end of the buffer.
 * See also mbedtls_asn1_write_mpi().
 *
 * p: pointer to the end of the output buffer
 * start: start of the output buffer, and also of the mpi to write at the end
 * n_len: length of the mpi to read from start
 */
static int asn1_write_mpibuf(unsigned char **p, unsigned char *start,
                             size_t n_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    if ((size_t) (*p - start) < n_len) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    len = n_len;
    *p -= len;
    memmove(*p, start, len);

    /* ASN.1 DER encoding requires minimal length, so skip leading 0s.
     * Neither r nor s should be 0, but as a failsafe measure, still detect
     * that rather than overflowing the buffer in case of a PSA error. */
    while (len > 0 && **p == 0x00) {
        ++(*p);
        --len;
    }

    /* this is only reached if the signature was invalid */
    if (len == 0) {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }

    /* if the msb is 1, ASN.1 requires that we prepend a 0.
     * Neither r nor s can be 0, so we can assume len > 0 at all times. */
    if (**p & 0x80) {
        if (*p - start < 1) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = 0x00;
        len += 1;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_INTEGER));

    return (int) len;
}

/* Transcode signature from PSA format to ASN.1 sequence.
 * See ecdsa_signature_to_asn1 in ecdsa.c, but with byte buffers instead of
 * MPIs, and in-place.
 *
 * [in/out] sig: the signature pre- and post-transcoding
 * [in/out] sig_len: signature length pre- and post-transcoding
 * [int] buf_len: the available size the in/out buffer
 */
static int pk_ecdsa_sig_asn1_from_psa(unsigned char *sig, size_t *sig_len,
                                      size_t buf_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    const size_t rs_len = *sig_len / 2;
    unsigned char *p = sig + buf_len;

    MBEDTLS_ASN1_CHK_ADD(len, asn1_write_mpibuf(&p, sig + rs_len, rs_len));
    MBEDTLS_ASN1_CHK_ADD(len, asn1_write_mpibuf(&p, sig, rs_len));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, sig, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, sig,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    memmove(sig, p, len);
    *sig_len = len;

    return 0;
}

static int ecdsa_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           unsigned char *sig, size_t sig_size, size_t *sig_len,
                           int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_ecp_keypair *ctx = pk->pk_ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;
    unsigned char buf[MBEDTLS_PSA_MAX_EC_KEY_PAIR_LENGTH];
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    psa_algorithm_t psa_sig_md =
        PSA_ALG_DETERMINISTIC_ECDSA(mbedtls_hash_info_psa_from_md(md_alg));
#else
    psa_algorithm_t psa_sig_md =
        PSA_ALG_ECDSA(mbedtls_hash_info_psa_from_md(md_alg));
#endif
    size_t curve_bits;
    psa_ecc_family_t curve =
        mbedtls_ecc_group_to_psa(ctx->grp.id, &curve_bits);
    size_t key_len = PSA_BITS_TO_BYTES(curve_bits);

    /* PSA has its own RNG */
    ((void) f_rng);
    ((void) p_rng);

    if (curve == 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (key_len > sizeof(buf)) {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    ret = mbedtls_mpi_write_binary(&ctx->d, buf, key_len);
    if (ret != 0) {
        goto cleanup;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(curve));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, psa_sig_md);

    status = psa_import_key(&attributes,
                            buf, key_len,
                            &key_id);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = psa_sign_hash(key_id, psa_sig_md, hash, hash_len,
                           sig, sig_size, sig_len);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = pk_ecdsa_sig_asn1_from_psa(sig, sig_len, sig_size);

cleanup:
    mbedtls_platform_zeroize(buf, sizeof(buf));
    status = psa_destroy_key(key_id);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int ecdsa_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           unsigned char *sig, size_t sig_size, size_t *sig_len,
                           int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return mbedtls_ecdsa_write_signature((mbedtls_ecdsa_context *) pk->pk_ctx,
                                         md_alg, hash, hash_len,
                                         sig, sig_size, sig_len,
                                         f_rng, p_rng);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
/* Forward declarations */
static int ecdsa_verify_rs_wrap(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx);

static int ecdsa_sign_rs_wrap(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx);

/*
 * Restart context for ECDSA operations with ECKEY context
 *
 * We need to store an actual ECDSA context, as we need to pass the same to
 * the underlying ecdsa function, so we can't create it on the fly every time.
 */
typedef struct {
    mbedtls_ecdsa_restart_ctx ecdsa_rs;
    mbedtls_ecdsa_context ecdsa_ctx;
} eckey_restart_ctx;

static void *eckey_rs_alloc(void)
{
    eckey_restart_ctx *rs_ctx;

    void *ctx = mbedtls_calloc(1, sizeof(eckey_restart_ctx));

    if (ctx != NULL) {
        rs_ctx = ctx;
        mbedtls_ecdsa_restart_init(&rs_ctx->ecdsa_rs);
        mbedtls_ecdsa_init(&rs_ctx->ecdsa_ctx);
    }

    return ctx;
}

static void eckey_rs_free(void *ctx)
{
    eckey_restart_ctx *rs_ctx;

    if (ctx == NULL) {
        return;
    }

    rs_ctx = ctx;
    mbedtls_ecdsa_restart_free(&rs_ctx->ecdsa_rs);
    mbedtls_ecdsa_free(&rs_ctx->ecdsa_ctx);

    mbedtls_free(ctx);
}

static int eckey_verify_rs_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    eckey_restart_ctx *rs = rs_ctx;

    /* Should never happen */
    if (rs == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /* set up our own sub-context if needed (that is, on first run) */
    if (rs->ecdsa_ctx.grp.pbits == 0) {
        MBEDTLS_MPI_CHK(mbedtls_ecdsa_from_keypair(&rs->ecdsa_ctx, pk->pk_ctx));
    }

    MBEDTLS_MPI_CHK(ecdsa_verify_rs_wrap(pk,
                                         md_alg, hash, hash_len,
                                         sig, sig_len, &rs->ecdsa_rs));

cleanup:
    return ret;
}

static int eckey_sign_rs_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    eckey_restart_ctx *rs = rs_ctx;

    /* Should never happen */
    if (rs == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /* set up our own sub-context if needed (that is, on first run) */
    if (rs->ecdsa_ctx.grp.pbits == 0) {
        MBEDTLS_MPI_CHK(mbedtls_ecdsa_from_keypair(&rs->ecdsa_ctx, pk->pk_ctx));
    }

    MBEDTLS_MPI_CHK(ecdsa_sign_rs_wrap(pk, md_alg,
                                       hash, hash_len, sig, sig_size, sig_len,
                                       f_rng, p_rng, &rs->ecdsa_rs));

cleanup:
    return ret;
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
/*
 * Alternative function used to verify that the EC private/public key pair
 * is valid using PSA functions instead of ECP ones.
 * The flow is:
 * - import the private key "prv" to PSA and export its public part
 * - write the raw content of public key "pub" to a local buffer
 * - compare the two buffers
 */
static int eckey_check_pair_psa(mbedtls_pk_context *pub, mbedtls_pk_context *prv)
{
    psa_status_t status, destruction_status;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    /* We are using MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH for the size of this
     * buffer because it will be used to hold the private key at first and
     * then its public part (but not at the same time). */
    uint8_t prv_key_buf[MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t prv_key_len;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    const psa_ecc_family_t curve = prv->ec_family;
    const size_t curve_bits = prv->ec_bits;
#else /* !MBEDTLS_PK_USE_PSA_EC_DATA */
    uint8_t pub_key_buf[MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t pub_key_len;
    size_t curve_bits;
    const psa_ecc_family_t curve =
        mbedtls_ecc_group_to_psa(mbedtls_pk_ec_ro(*prv)->grp.id, &curve_bits);
#endif /* !MBEDTLS_PK_USE_PSA_EC_DATA */
    const size_t curve_bytes = PSA_BITS_TO_BYTES(curve_bits);

    if (curve == 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(curve));
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT);

    ret = mbedtls_mpi_write_binary(&mbedtls_pk_ec_ro(*prv)->d,
                                   prv_key_buf, curve_bytes);
    if (ret != 0) {
        return ret;
    }

    status = psa_import_key(&key_attr, prv_key_buf, curve_bytes, &key_id);
    ret = PSA_PK_TO_MBEDTLS_ERR(status);
    if (ret != 0) {
        return ret;
    }

    mbedtls_platform_zeroize(prv_key_buf, sizeof(prv_key_buf));

    status = psa_export_public_key(key_id, prv_key_buf, sizeof(prv_key_buf),
                                   &prv_key_len);
    ret = PSA_PK_TO_MBEDTLS_ERR(status);
    destruction_status = psa_destroy_key(key_id);
    if (ret != 0) {
        return ret;
    } else if (destruction_status != PSA_SUCCESS) {
        return PSA_PK_TO_MBEDTLS_ERR(destruction_status);
    }

#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    if (memcmp(prv_key_buf, pub->pub_raw, pub->pub_raw_len) != 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#else
    ret = mbedtls_ecp_point_write_binary(&mbedtls_pk_ec_rw(*pub)->grp,
                                         &mbedtls_pk_ec_rw(*pub)->Q,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &pub_key_len, pub_key_buf,
                                         sizeof(pub_key_buf));
    if (ret != 0) {
        return ret;
    }

    if (memcmp(prv_key_buf, pub_key_buf, curve_bytes) != 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif /* !MBEDTLS_PK_USE_PSA_EC_DATA */

    return 0;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

static int eckey_check_pair(mbedtls_pk_context *pub, mbedtls_pk_context *prv,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    (void) f_rng;
    (void) p_rng;
    return eckey_check_pair_psa(pub, prv);
#elif defined(MBEDTLS_ECP_C)
    return mbedtls_ecp_check_pub_priv((const mbedtls_ecp_keypair *) pub->pk_ctx,
                                      (const mbedtls_ecp_keypair *) prv->pk_ctx,
                                      f_rng, p_rng);
#else
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#endif
}

static void *eckey_alloc_wrap(void)
{
    void *ctx = mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair));

    if (ctx != NULL) {
        mbedtls_ecp_keypair_init(ctx);
    }

    return ctx;
}

static void eckey_free_wrap(void *ctx)
{
    mbedtls_ecp_keypair_free((mbedtls_ecp_keypair *) ctx);
    mbedtls_free(ctx);
}

static void eckey_debug(mbedtls_pk_context *pk, mbedtls_pk_debug_item *items)
{
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    items->type = MBEDTLS_PK_DEBUG_PSA_EC;
    items->name = "eckey.Q";
    items->value = pk;
#else
    mbedtls_ecp_keypair *ecp = (mbedtls_ecp_keypair *) pk->pk_ctx;
    items->type = MBEDTLS_PK_DEBUG_ECP;
    items->name = "eckey.Q";
    items->value = &(ecp->Q);
#endif
}

const mbedtls_pk_info_t mbedtls_eckey_info = {
    MBEDTLS_PK_ECKEY,
    "EC",
    eckey_get_bitlen,
    eckey_can_do,
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
    ecdsa_verify_wrap,   /* Compatible key structures */
#else
    NULL,
#endif
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
    ecdsa_sign_wrap,   /* Compatible key structures */
#else
    NULL,
#endif
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    eckey_verify_rs_wrap,
    eckey_sign_rs_wrap,
#endif
    NULL,
    NULL,
    eckey_check_pair,
    eckey_alloc_wrap,
    eckey_free_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    eckey_rs_alloc,
    eckey_rs_free,
#endif
    eckey_debug,
};

/*
 * EC key restricted to ECDH
 */
static int eckeydh_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_ECKEY ||
           type == MBEDTLS_PK_ECKEY_DH;
}

const mbedtls_pk_info_t mbedtls_eckeydh_info = {
    MBEDTLS_PK_ECKEY_DH,
    "EC_DH",
    eckey_get_bitlen,         /* Same underlying key structure */
    eckeydh_can_do,
    NULL,
    NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    NULL,
    NULL,
    eckey_check_pair,
    eckey_alloc_wrap,       /* Same underlying key structure */
    eckey_free_wrap,        /* Same underlying key structure */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    eckey_debug,            /* Same underlying key structure */
};
#endif /* MBEDTLS_ECP_LIGHT */

#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
static int ecdsa_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_ECDSA;
}

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
static int ecdsa_verify_rs_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) md_alg);

    ret = mbedtls_ecdsa_read_signature_restartable(
        (mbedtls_ecdsa_context *) pk->pk_ctx,
        hash, hash_len, sig, sig_len,
        (mbedtls_ecdsa_restart_ctx *) rs_ctx);

    if (ret == MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH) {
        return MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return ret;
}

static int ecdsa_sign_rs_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx)
{
    return mbedtls_ecdsa_write_signature_restartable(
        (mbedtls_ecdsa_context *) pk->pk_ctx,
        md_alg, hash, hash_len, sig, sig_size, sig_len, f_rng, p_rng,
        (mbedtls_ecdsa_restart_ctx *) rs_ctx);

}

static void *ecdsa_rs_alloc(void)
{
    void *ctx = mbedtls_calloc(1, sizeof(mbedtls_ecdsa_restart_ctx));

    if (ctx != NULL) {
        mbedtls_ecdsa_restart_init(ctx);
    }

    return ctx;
}

static void ecdsa_rs_free(void *ctx)
{
    mbedtls_ecdsa_restart_free(ctx);
    mbedtls_free(ctx);
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

const mbedtls_pk_info_t mbedtls_ecdsa_info = {
    MBEDTLS_PK_ECDSA,
    "ECDSA",
    eckey_get_bitlen,     /* Compatible key structures */
    ecdsa_can_do,
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
    ecdsa_verify_wrap,   /* Compatible key structures */
#else
    NULL,
#endif
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
    ecdsa_sign_wrap,   /* Compatible key structures */
#else
    NULL,
#endif
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    ecdsa_verify_rs_wrap,
    ecdsa_sign_rs_wrap,
#endif
    NULL,
    NULL,
    eckey_check_pair,   /* Compatible key structures */
    eckey_alloc_wrap,   /* Compatible key structures */
    eckey_free_wrap,   /* Compatible key structures */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    ecdsa_rs_alloc,
    ecdsa_rs_free,
#endif
    eckey_debug,        /* Compatible key structures */
};
#endif /* MBEDTLS_PK_CAN_ECDSA_SOME */

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
/*
 * Support for alternative RSA-private implementations
 */

static int rsa_alt_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_RSA;
}

static size_t rsa_alt_get_bitlen(mbedtls_pk_context *pk)
{
    const mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

    return 8 * rsa_alt->key_len_func(rsa_alt->key);
}

static int rsa_alt_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             unsigned char *sig, size_t sig_size, size_t *sig_len,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

    if (UINT_MAX < hash_len) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    *sig_len = rsa_alt->key_len_func(rsa_alt->key);
    if (*sig_len > MBEDTLS_PK_SIGNATURE_MAX_SIZE) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    if (*sig_len > sig_size) {
        return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    return rsa_alt->sign_func(rsa_alt->key, f_rng, p_rng,
                              md_alg, (unsigned int) hash_len, hash, sig);
}

static int rsa_alt_decrypt_wrap(mbedtls_pk_context *pk,
                                const unsigned char *input, size_t ilen,
                                unsigned char *output, size_t *olen, size_t osize,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

    ((void) f_rng);
    ((void) p_rng);

    if (ilen != rsa_alt->key_len_func(rsa_alt->key)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    return rsa_alt->decrypt_func(rsa_alt->key,
                                 olen, input, output, osize);
}

#if defined(MBEDTLS_RSA_C)
static int rsa_alt_check_pair(mbedtls_pk_context *pub, mbedtls_pk_context *prv,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
    unsigned char hash[32];
    size_t sig_len = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (rsa_alt_get_bitlen(prv) != rsa_get_bitlen(pub)) {
        return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

    memset(hash, 0x2a, sizeof(hash));

    if ((ret = rsa_alt_sign_wrap(prv, MBEDTLS_MD_NONE,
                                 hash, sizeof(hash),
                                 sig, sizeof(sig), &sig_len,
                                 f_rng, p_rng)) != 0) {
        return ret;
    }

    if (rsa_verify_wrap(pub, MBEDTLS_MD_NONE,
                        hash, sizeof(hash), sig, sig_len) != 0) {
        return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

    return 0;
}
#endif /* MBEDTLS_RSA_C */

static void *rsa_alt_alloc_wrap(void)
{
    void *ctx = mbedtls_calloc(1, sizeof(mbedtls_rsa_alt_context));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(mbedtls_rsa_alt_context));
    }

    return ctx;
}

static void rsa_alt_free_wrap(void *ctx)
{
    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_rsa_alt_context));
    mbedtls_free(ctx);
}

const mbedtls_pk_info_t mbedtls_rsa_alt_info = {
    MBEDTLS_PK_RSA_ALT,
    "RSA-alt",
    rsa_alt_get_bitlen,
    rsa_alt_can_do,
    NULL,
    rsa_alt_sign_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    rsa_alt_decrypt_wrap,
    NULL,
#if defined(MBEDTLS_RSA_C)
    rsa_alt_check_pair,
#else
    NULL,
#endif
    rsa_alt_alloc_wrap,
    rsa_alt_free_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL,
    NULL,
#endif
    NULL,
};

#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static size_t pk_opaque_get_bitlen(mbedtls_pk_context *pk)
{
    size_t bits;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    if (PSA_SUCCESS != psa_get_key_attributes(pk->priv_id, &attributes)) {
        return 0;
    }

    bits = psa_get_key_bits(&attributes);
    psa_reset_key_attributes(&attributes);
    return bits;
}

static int pk_opaque_ecdsa_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_ECKEY ||
           type == MBEDTLS_PK_ECDSA;
}

static int pk_opaque_rsa_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_RSA ||
           type == MBEDTLS_PK_RSASSA_PSS;
}

static int pk_opaque_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                               const unsigned char *hash, size_t hash_len,
                               unsigned char *sig, size_t sig_size, size_t *sig_len,
                               int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
#if !defined(MBEDTLS_PK_CAN_ECDSA_SIGN) && !defined(MBEDTLS_RSA_C)
    ((void) pk);
    ((void) md_alg);
    ((void) hash);
    ((void) hash_len);
    ((void) sig);
    ((void) sig_size);
    ((void) sig_len);
    ((void) f_rng);
    ((void) p_rng);
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#else /* !MBEDTLS_PK_CAN_ECDSA_SIGN && !MBEDTLS_RSA_C */
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg;
    psa_key_type_t type;
    psa_status_t status;

    /* PSA has its own RNG */
    (void) f_rng;
    (void) p_rng;

    status = psa_get_key_attributes(pk->priv_id, &attributes);
    if (status != PSA_SUCCESS) {
        return PSA_PK_TO_MBEDTLS_ERR(status);
    }

    type = psa_get_key_type(&attributes);
    psa_reset_key_attributes(&attributes);

#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
    if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(type)) {
        alg = PSA_ALG_ECDSA(mbedtls_hash_info_psa_from_md(md_alg));
    } else
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */
#if defined(MBEDTLS_RSA_C)
    if (PSA_KEY_TYPE_IS_RSA(type)) {
        alg = PSA_ALG_RSA_PKCS1V15_SIGN(mbedtls_hash_info_psa_from_md(md_alg));
    } else
#endif /* MBEDTLS_RSA_C */
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;

    /* make the signature */
    status = psa_sign_hash(pk->priv_id, alg, hash, hash_len,
                           sig, sig_size, sig_len);
    if (status != PSA_SUCCESS) {
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
        if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(type)) {
            return PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
        } else
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */
#if defined(MBEDTLS_RSA_C)
        if (PSA_KEY_TYPE_IS_RSA(type)) {
            return PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        } else
#endif /* MBEDTLS_RSA_C */
        return PSA_PK_TO_MBEDTLS_ERR(status);
    }

#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
    if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(type)) {
        /* transcode it to ASN.1 sequence */
        return pk_ecdsa_sig_asn1_from_psa(sig, sig_len, sig_size);
    }
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */

    return 0;
#endif /* !MBEDTLS_PK_CAN_ECDSA_SIGN && !MBEDTLS_RSA_C */
}

const mbedtls_pk_info_t mbedtls_pk_ecdsa_opaque_info = {
    MBEDTLS_PK_OPAQUE,
    "Opaque",
    pk_opaque_get_bitlen,
    pk_opaque_ecdsa_can_do,
    NULL, /* verify - will be done later */
    pk_opaque_sign_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL, /* restartable verify - not relevant */
    NULL, /* restartable sign - not relevant */
#endif
    NULL, /* decrypt - not relevant */
    NULL, /* encrypt - not relevant */
    NULL, /* check_pair - could be done later or left NULL */
    NULL, /* alloc - no need to allocate new data dynamically */
    NULL, /* free - as for the alloc, there is no data to free */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL, /* restart alloc - not relevant */
    NULL, /* restart free - not relevant */
#endif
    NULL, /* debug - could be done later, or even left NULL */
};

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR)
static int pk_opaque_rsa_decrypt(mbedtls_pk_context *pk,
                                 const unsigned char *input, size_t ilen,
                                 unsigned char *output, size_t *olen, size_t osize,
                                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    psa_status_t status;

    /* PSA has its own RNG */
    (void) f_rng;
    (void) p_rng;

    status = psa_asymmetric_decrypt(pk->priv_id, PSA_ALG_RSA_PKCS1V15_CRYPT,
                                    input, ilen,
                                    NULL, 0,
                                    output, osize, olen);
    if (status != PSA_SUCCESS) {
        return PSA_PK_RSA_TO_MBEDTLS_ERR(status);
    }

    return 0;
}
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR */

const mbedtls_pk_info_t mbedtls_pk_rsa_opaque_info = {
    MBEDTLS_PK_OPAQUE,
    "Opaque",
    pk_opaque_get_bitlen,
    pk_opaque_rsa_can_do,
    NULL, /* verify - will be done later */
    pk_opaque_sign_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL, /* restartable verify - not relevant */
    NULL, /* restartable sign - not relevant */
#endif
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR)
    pk_opaque_rsa_decrypt,
#else
    NULL, /* decrypt - not available */
#endif /* PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY */
    NULL, /* encrypt - will be done later */
    NULL, /* check_pair - could be done later or left NULL */
    NULL, /* alloc - no need to allocate new data dynamically */
    NULL, /* free - as for the alloc, there is no data to free */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    NULL, /* restart alloc - not relevant */
    NULL, /* restart free - not relevant */
#endif
    NULL, /* debug - could be done later, or even left NULL */
};

#endif /* MBEDTLS_USE_PSA_CRYPTO */

#endif /* MBEDTLS_PK_C */
