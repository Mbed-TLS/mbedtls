/*
 *  Example ECDSA program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if defined(MBEDTLS_ECDSA_C) && \
    defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"

#include <string.h>
#endif

/*
 * Uncomment to show key and signature details
 */
#define VERBOSE

/*
 * Uncomment to force use of a specific curve
 */
#define ECPARAMS    MBEDTLS_ECP_DP_SECP192R1

#if !defined(ECPARAMS)
#define ECPARAMS    mbedtls_ecp_curve_list()->grp_id
#endif

#if !defined(MBEDTLS_ECDSA_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main(void)
{
    mbedtls_printf("MBEDTLS_ECDSA_C and/or MBEDTLS_SHA256_C and/or "
                   "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C not defined\n");
    mbedtls_exit(0);
}
#else
#if defined(VERBOSE)
static void dump_buf(const char *title, unsigned char *buf, size_t len)
{
    size_t i;

    mbedtls_printf("%s", title);
    for (i = 0; i < len; i++) {
        mbedtls_printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16]);
    }
    mbedtls_printf("\n");
}

static void dump_pubkey(const char *title, mbedtls_ecdsa_context *key)
{
    unsigned char buf[300];
    size_t len;

    if (mbedtls_ecp_write_public_key(key, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                     &len, buf, sizeof(buf)) != 0) {
        mbedtls_printf("internal error\n");
        return;
    }

    dump_buf(title, buf, len);
}
#else
#define dump_buf(a, b, c)
#define dump_pubkey(a, b)
#endif


int main(int argc, char *argv[])
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char message[100];
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len;
    const char *pers = "ecdsa";
    ((void) argv);

    mbedtls_ecdsa_init(&ctx_sign);
    mbedtls_ecdsa_init(&ctx_verify);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    memset(sig, 0, sizeof(sig));
    memset(message, 0x25, sizeof(message));

    if (argc != 1) {
        mbedtls_printf("usage: ecdsa\n");

#if defined(_WIN32)
        mbedtls_printf("\n");
#endif

        goto exit;
    }

    /*
     * Generate a key pair for signing
     */
    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n  . Generating key pair...");
    fflush(stdout);

    if ((ret = mbedtls_ecdsa_genkey(&ctx_sign, ECPARAMS,
                                    mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ecdsa_genkey returned %d\n", ret);
        goto exit;
    }

    mbedtls_ecp_group_id grp_id = mbedtls_ecp_keypair_get_group_id(&ctx_sign);
    const mbedtls_ecp_curve_info *curve_info =
        mbedtls_ecp_curve_info_from_grp_id(grp_id);
    mbedtls_printf(" ok (key size: %d bits)\n", (int) curve_info->bit_size);

    dump_pubkey("  + Public key: ", &ctx_sign);

    /*
     * Compute message hash
     */
    mbedtls_printf("  . Computing message hash...");
    fflush(stdout);

    if ((ret = mbedtls_sha256(message, sizeof(message), hash, 0)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_sha256 returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    dump_buf("  + Hash: ", hash, sizeof(hash));

    /*
     * Sign message hash
     */
    mbedtls_printf("  . Signing message hash...");
    fflush(stdout);

    if ((ret = mbedtls_ecdsa_write_signature(&ctx_sign, MBEDTLS_MD_SHA256,
                                             hash, sizeof(hash),
                                             sig, sizeof(sig), &sig_len,
                                             mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ecdsa_write_signature returned %d\n", ret);
        goto exit;
    }
    mbedtls_printf(" ok (signature length = %u)\n", (unsigned int) sig_len);

    dump_buf("  + Signature: ", sig, sig_len);

    /*
     * Transfer public information to verifying context
     *
     * We could use the same context for verification and signatures, but we
     * chose to use a new one in order to make it clear that the verifying
     * context only needs the public key (Q), and not the private key (d).
     */
    mbedtls_printf("  . Preparing verification context...");
    fflush(stdout);

    if ((ret = mbedtls_ecp_export(&ctx_sign, NULL, NULL, &Q)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ecp_export returned %d\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ecp_set_public_key(grp_id, &ctx_verify, &Q)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ecp_set_public_key returned %d\n", ret);
        goto exit;
    }

    /*
     * Verify signature
     */
    mbedtls_printf(" ok\n  . Verifying signature...");
    fflush(stdout);

    if ((ret = mbedtls_ecdsa_read_signature(&ctx_verify,
                                            hash, sizeof(hash),
                                            sig, sig_len)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ecdsa_read_signature returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    mbedtls_ecdsa_free(&ctx_verify);
    mbedtls_ecdsa_free(&ctx_sign);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C &&
          ECPARAMS */
