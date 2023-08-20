/*
 *  Edwards-curve Digital Signature Algorithm
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

/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 */

#include "common.h"

#if defined(MBEDTLS_EDDSA_C)

#include "mbedtls/eddsa.h"
#include <string.h>

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#if defined(MBEDTLS_ECP_DP_ED25519_ENABLED)
#include "mbedtls/sha512.h"
#endif

int mbedtls_eddsa_can_do(mbedtls_ecp_group_id gid)
{
    switch (gid) {
#ifdef MBEDTLS_ECP_DP_ED25519_ENABLED
        case MBEDTLS_ECP_DP_ED25519: return 1;
#endif
        default: return 0;
    }
}

#ifdef MBEDTLS_ECP_DP_ED25519_ENABLED
static int mbedtls_eddsa_put_dom2_ctx(int flag, const unsigned char *ctx,
                                      size_t ctx_len, mbedtls_sha512_context *sha_ctx)
{
    unsigned char ct_init_string[] = "SigEd25519 no Ed25519 collisions";
    unsigned char ct_flag = flag;
    unsigned char ct_ctx_len = ctx_len & 0xff;

    mbedtls_sha512_update(sha_ctx, ct_init_string, 32);
    mbedtls_sha512_update(sha_ctx, &ct_flag, 1);
    mbedtls_sha512_update(sha_ctx, &ct_ctx_len, 1);

    if (ctx && ctx_len > 0) {
        mbedtls_sha512_update(sha_ctx, ctx, ctx_len);
    }

    return 0;
}
#endif

/*
 * Compute EdDSA signature of a message.
 * For PREHASH operation, the message is already previously hashed.
 * Obviously, for PREHASH, we skip hash message step.
 */
int mbedtls_eddsa_sign(mbedtls_ecp_group *grp,
                       mbedtls_mpi *r, mbedtls_mpi *s,
                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       mbedtls_eddsa_id eddsa_id,
                       const unsigned char *ed_ctx, size_t ed_ctx_len,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret;
    mbedtls_ecp_point Q, R;
    mbedtls_mpi q, prefix, rq, h;

    /* EdDSA only should be used with Ed25519 curve  */
    if (!mbedtls_eddsa_can_do(grp->id) || grp->N.p == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#ifdef MBEDTLS_ECP_DP_ED25519_ENABLED
    if (grp->id == MBEDTLS_ECP_DP_ED25519 && eddsa_id != MBEDTLS_EDDSA_PURE &&
        eddsa_id != MBEDTLS_EDDSA_CTX && eddsa_id != MBEDTLS_EDDSA_PREHASH) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }
#endif

    if (eddsa_id == MBEDTLS_EDDSA_PREHASH && blen != 64) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    mbedtls_ecp_point_init(&Q); mbedtls_ecp_point_init(&R);

    mbedtls_mpi_init(&q); mbedtls_mpi_init(&prefix); mbedtls_mpi_init(&rq); mbedtls_mpi_init(&h);

    /* Step 1 */
    MBEDTLS_MPI_CHK(mbedtls_ecp_expand_edwards(grp, d, &q, &prefix));

    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, &Q, &q, &grp->G, f_rng, p_rng));

    switch (grp->id) {
#ifdef MBEDTLS_ECP_DP_ED25519_ENABLED
        case MBEDTLS_ECP_DP_ED25519:
        {
            mbedtls_sha512_context sha_ctx;
            unsigned char sha_buf[64], tmp_buf[32];
            size_t olen = 0;

            /* r computation */
            mbedtls_sha512_init(&sha_ctx);
            mbedtls_sha512_starts(&sha_ctx, 0);

            /* Step 2 */
            if (eddsa_id == MBEDTLS_EDDSA_CTX) {
                MBEDTLS_MPI_CHK(mbedtls_eddsa_put_dom2_ctx(0, ed_ctx, ed_ctx_len, &sha_ctx));
            } else if (eddsa_id == MBEDTLS_EDDSA_PREHASH) {
                MBEDTLS_MPI_CHK(mbedtls_eddsa_put_dom2_ctx(1, ed_ctx, ed_ctx_len, &sha_ctx));
            }

            /* Update SHA with prefix */
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary_le(&prefix, tmp_buf, sizeof(tmp_buf)));

            mbedtls_sha512_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

            mbedtls_platform_zeroize(tmp_buf, sizeof(tmp_buf));

            /* In EDDSA_PREHASH, buf should contain the SHA512 hash. It contains the whole message otherwise */
            mbedtls_sha512_update(&sha_ctx, buf, blen);

            mbedtls_sha512_finish(&sha_ctx, sha_buf);
            mbedtls_sha512_free(&sha_ctx);

            MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&rq, sha_buf, sizeof(sha_buf)));

            mbedtls_platform_zeroize(sha_buf, sizeof(sha_buf));

            MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&rq, &rq, &grp->N));

            /* Step 3 */
            MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, &R, &rq, &grp->G, f_rng, p_rng));

            /* We encode the R point to r */
            MBEDTLS_MPI_CHK(mbedtls_ecp_point_encode(grp, r, &R));

            /* s computation */
            mbedtls_sha512_init(&sha_ctx);
            mbedtls_sha512_starts(&sha_ctx, 0);

            /* Step 4 */
            if (eddsa_id == MBEDTLS_EDDSA_CTX) {
                MBEDTLS_MPI_CHK(mbedtls_eddsa_put_dom2_ctx(0, ed_ctx, ed_ctx_len, &sha_ctx));
            } else if (eddsa_id == MBEDTLS_EDDSA_PREHASH) {
                MBEDTLS_MPI_CHK(mbedtls_eddsa_put_dom2_ctx(1, ed_ctx, ed_ctx_len, &sha_ctx));
            }

            MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(grp, &R, MBEDTLS_ECP_PF_COMPRESSED,
                                                           &olen, tmp_buf, sizeof(tmp_buf)));
            mbedtls_sha512_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

            MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(grp, &Q, MBEDTLS_ECP_PF_COMPRESSED,
                                                           &olen, tmp_buf, sizeof(tmp_buf)));
            mbedtls_sha512_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

            mbedtls_platform_zeroize(tmp_buf, sizeof(tmp_buf));

            /* In EDDSA_PREHASH, buf should contain the SHA512 hash. It contains the whole message otherwise */
            mbedtls_sha512_update(&sha_ctx, buf, blen);

            mbedtls_sha512_finish(&sha_ctx, sha_buf);
            mbedtls_sha512_free(&sha_ctx);

            /* Step 5 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&h, sha_buf, sizeof(sha_buf)));
            mbedtls_platform_zeroize(sha_buf, sizeof(sha_buf));

            MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&h, &h, &grp->N));

            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&h, &h, &q));

            MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(s, &h, &rq));

            MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(s, s, &grp->N));
            break;
        }
#endif
        default:
            break;
    }

cleanup:
    mbedtls_mpi_free(&q);
    mbedtls_mpi_free(&prefix);
    mbedtls_mpi_free(&rq);
    mbedtls_mpi_free(&h);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_point_free(&R);

    return ret;

}

int mbedtls_eddsa_verify(mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *Q, const mbedtls_mpi *r,
                         const mbedtls_mpi *s,
                         mbedtls_eddsa_id eddsa_id,
                         const unsigned char *ed_ctx, size_t ed_ctx_len)
{
    int ret = 0;
    mbedtls_mpi h;
    mbedtls_ecp_point R;

    mbedtls_mpi_init(&h);
    mbedtls_ecp_point_init(&R);

    /* Step 1 */
    if (mbedtls_mpi_cmp_mpi(s, &grp->N) >= 0 || mbedtls_mpi_cmp_int(s, 0) < 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    switch (grp->id) {
#ifdef MBEDTLS_ECP_DP_ED25519_ENABLED
        case MBEDTLS_ECP_DP_ED25519:
        {
            mbedtls_sha512_context sha_ctx;
            unsigned char sha_buf[64], tmp_buf[32];
            size_t olen = 0;

            mbedtls_sha512_init(&sha_ctx);
            mbedtls_sha512_starts(&sha_ctx, 0);

            /* Step 2 */
            if (eddsa_id == MBEDTLS_EDDSA_CTX) {
                MBEDTLS_MPI_CHK(mbedtls_eddsa_put_dom2_ctx(0, ed_ctx, ed_ctx_len, &sha_ctx));
            } else if (eddsa_id == MBEDTLS_EDDSA_PREHASH) {
                MBEDTLS_MPI_CHK(mbedtls_eddsa_put_dom2_ctx(1, ed_ctx, ed_ctx_len, &sha_ctx));
            }

            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary_le(r, tmp_buf, sizeof(tmp_buf)));
            mbedtls_sha512_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));

            MBEDTLS_MPI_CHK(mbedtls_ecp_point_write_binary(grp, Q, MBEDTLS_ECP_PF_COMPRESSED, &olen,
                                                           tmp_buf, sizeof(tmp_buf)));
            mbedtls_sha512_update(&sha_ctx, tmp_buf, sizeof(tmp_buf));
            mbedtls_platform_zeroize(tmp_buf, sizeof(tmp_buf));

            /* In EDDSA_PREHASH, buf should contain the SHA512 hash. It contains the whole message otherwise */
            mbedtls_sha512_update(&sha_ctx, buf, blen);

            mbedtls_sha512_finish(&sha_ctx, sha_buf);
            mbedtls_sha512_free(&sha_ctx);

            MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&h, sha_buf, sizeof(sha_buf)));
            mbedtls_platform_zeroize(sha_buf, sizeof(sha_buf));

            MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&h, &h, &grp->N));

            /* Step 3 */
            /* We perform fast single-signature verification by compressing sB-hA and comparing with r without decompressing it (expensive) */
            MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&h, &grp->N, &h));
            MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(grp, &R, s, &grp->G, &h, Q));
            MBEDTLS_MPI_CHK(mbedtls_ecp_point_encode(grp, &h, &R));     /* We reuse h */

            /* Since h is a compressed point, we are free to compare with r without decompressing it */
            if (mbedtls_mpi_cmp_mpi(&h, r) != 0) {
                ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
                goto cleanup;
            }
            break;
        }
#endif
        default:
            break;
    }

cleanup:
    mbedtls_mpi_free(&h);
    mbedtls_ecp_point_free(&R);
    return ret;
}

/*
 * Convert a signature (given by context) to binary
 */
static int eddsa_signature_to_binary(const mbedtls_ecp_group *grp,
                                     const mbedtls_mpi *r,
                                     const mbedtls_mpi *s,
                                     unsigned char *sig,
                                     size_t sig_size,
                                     size_t *slen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t plen = (grp->pbits + 1 + 7) >> 3;

    if (2 * plen > sig_size) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    ret = mbedtls_mpi_write_binary_le(r, sig, plen);
    if (ret != 0) {
        return ret;
    }
    ret = mbedtls_mpi_write_binary_le(s, sig + plen, plen);
    if (ret != 0) {
        return ret;
    }
    *slen = 2 * plen;

    return 0;
}

/*
 * Compute and write signature
 */
int mbedtls_eddsa_write_signature(mbedtls_ecp_keypair *ctx,
                                  const unsigned char *hash, size_t hlen,
                                  unsigned char *sig, size_t sig_size, size_t *slen,
                                  mbedtls_eddsa_id eddsa_id,
                                  const unsigned char *ed_ctx, size_t ed_ctx_len,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi r, s;

    if (ctx == NULL || hash == NULL || sig == NULL || slen == NULL || f_rng == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    MBEDTLS_MPI_CHK(mbedtls_eddsa_sign(&ctx->grp, &r, &s, &ctx->d,
                                       hash, hlen, eddsa_id, ed_ctx,
                                       ed_ctx_len, f_rng,
                                       p_rng));

    MBEDTLS_MPI_CHK(eddsa_signature_to_binary(&ctx->grp, &r, &s, sig, sig_size, slen));

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

/*
 * Restartable read and check signature
 */
int mbedtls_eddsa_read_signature(mbedtls_ecp_keypair *ctx,
                                 const unsigned char *hash, size_t hlen,
                                 const unsigned char *sig, size_t slen,
                                 mbedtls_eddsa_id eddsa_id,
                                 const unsigned char *ed_ctx, size_t ed_ctx_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t plen = (ctx->grp.pbits + 1 + 7) >> 3;
    mbedtls_mpi r, s;

    if (ctx == NULL || hash == NULL || sig == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (2 * plen > slen) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&r, sig, plen));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&s, sig + plen, plen));

    if ((ret = mbedtls_eddsa_verify(&ctx->grp, hash, hlen,
                                    &ctx->Q, &r, &s,
                                    eddsa_id, ed_ctx, ed_ctx_len)) != 0) {
        goto cleanup;
    }

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

#endif /* MBEDTLS_EDDSA_C */
