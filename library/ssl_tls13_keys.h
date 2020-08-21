/*
 *  TLS 1.3 key schedule
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 ( the "License" ); you may
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
#if !defined(MBEDTLS_SSL_TLS1_3_KEYS_H)
#define MBEDTLS_SSL_TLS1_3_KEYS_H

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)
#define MBEDTLS_SSL_TLS1_3_LABEL_LIST                                   \
    const unsigned char finished    [ sizeof("finished")     - 1 ];     \
    const unsigned char resumption  [ sizeof("resumption")   - 1 ];     \
    const unsigned char traffic_upd [ sizeof("traffic upd")  - 1 ];     \
    const unsigned char export      [ sizeof("exporter")     - 1 ];     \
    const unsigned char key         [ sizeof("key")          - 1 ];     \
    const unsigned char iv          [ sizeof("iv")           - 1 ];     \
    const unsigned char sn          [ sizeof("sn")           - 1 ];     \
    const unsigned char c_hs_traffic[ sizeof("c hs traffic") - 1 ];     \
    const unsigned char c_ap_traffic[ sizeof("c ap traffic") - 1 ];     \
    const unsigned char c_e_traffic [ sizeof("c e traffic")  - 1 ];     \
    const unsigned char s_hs_traffic[ sizeof("s hs traffic") - 1 ];     \
    const unsigned char s_ap_traffic[ sizeof("s ap traffic") - 1 ];     \
    const unsigned char s_e_traffic [ sizeof("s e traffic")  - 1 ];     \
    const unsigned char exp_master  [ sizeof("exp master")   - 1 ];     \
    const unsigned char res_master  [ sizeof("res master")   - 1 ];     \
    const unsigned char ext_binder  [ sizeof("ext binder")   - 1 ];     \
    const unsigned char res_binder  [ sizeof("res binder")   - 1 ];     \
    const unsigned char derived     [ sizeof("derived")      - 1 ];     \

union mbedtls_ssl_tls1_3_labels_union
{
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};
struct mbedtls_ssl_tls1_3_labels_struct
{
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};
extern const struct mbedtls_ssl_tls1_3_labels_struct mbedtls_ssl_tls1_3_labels;

#define MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( LABEL )  \
    mbedtls_ssl_tls1_3_labels.LABEL,              \
    sizeof(mbedtls_ssl_tls1_3_labels.LABEL)

#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN  \
    sizeof( union mbedtls_ssl_tls1_3_labels_union )

/* The maximum length of HKDF contexts used in the TLS 1.3 standad.
 * Since contexts are always hashes of message transcripts, this can
 * be approximated from above by the maximum hash size. */
#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN  \
    MBEDTLS_MD_MAX_SIZE

/* Maximum desired length for expanded key material generated
 * by HKDF-Expand-Label. */
#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN 255

/**
 * \brief           The \c HKDF-Expand-Label function from
 *                  the TLS 1.3 standard RFC 8446.
 *
 * <tt>
 *                  HKDF-Expand-Label( Secret, Label, Context, Length ) =
 *                       HKDF-Expand( Secret, HkdfLabel, Length )
 * </tt>
 *
 * \param hash_alg  The identifier for the hash algorithm to use.
 * \param secret    The \c Secret argument to \c HKDF-Expand-Label.
 *                  This must be a readable buffer of length \p slen Bytes.
 * \param slen      The length of \p secret in Bytes.
 * \param label     The \c Label argument to \c HKDF-Expand-Label.
 *                  This must be a readable buffer of length \p llen Bytes.
 * \param llen      The length of \p label in Bytes.
 * \param ctx       The \c Context argument to \c HKDF-Expand-Label.
 *                  This must be a readable buffer of length \p clen Bytes.
 * \param clen      The length of \p context in Bytes.
 * \param buf       The destination buffer to hold the expanded secret.
 *                  This must be a writable buffe of length \p blen Bytes.
 * \param blen      The desired size of the expanded secret in Bytes.
 *
 * \returns         \c 0 on success.
 * \return          A negative error code on failure.
 */

int mbedtls_ssl_tls1_3_hkdf_expand_label(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *secret, size_t slen,
                     const unsigned char *label, size_t llen,
                     const unsigned char *ctx, size_t clen,
                     unsigned char *buf, size_t blen );

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */

#endif /* MBEDTLS_SSL_TLS1_3_KEYS_H */
