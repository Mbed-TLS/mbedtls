/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * The following function was automatically generated through the script
 * ./tests/scripts/generate_ssl_hrr_reset_check.py.
 */

#include <test/ssl_helpers.h>
#include <test/ssl_helpers_internal.h>
#include "mbedtls/psa_util.h"
#include <test/macros.h>

#if defined(MBEDTLS_SSL_TLS_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(MBEDTLS_SSL_SRV_C)

int mbedtls_test_ssl_check_context_after_hrr_reset(
    const mbedtls_ssl_context *before,
    const mbedtls_ssl_context *after)
{
    mbedtls_ssl_context initial;
    mbedtls_ssl_handshake_params normalized_handshake;
    mbedtls_ssl_session normalized_session;
    int ret = -1;

    memset(&initial, 0, sizeof(initial));
    memset(&normalized_handshake, 0, sizeof(normalized_handshake));
    mbedtls_ssl_init(&initial);
    TEST_EQUAL(mbedtls_ssl_setup(&initial, after->conf), 0);

    /* This reset retains connection and record-layer state. Variable record
     * buffers may currently be reallocated by ssl_handshake_init(), so their
     * replacement is checked for validity rather than pointer identity. */
    /* *INDENT-OFF* */
    TEST_ASSERT(before->conf == after->conf);
    TEST_EQUAL(before->state, after->state);
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    TEST_EQUAL(before->renego_status, after->renego_status);
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    TEST_EQUAL(before->renego_records_seen, after->renego_records_seen);
#endif
    TEST_EQUAL(before->tls_version, after->tls_version);
#if defined(MBEDTLS_SSL_EARLY_DATA) && defined(MBEDTLS_SSL_CLI_C)
    TEST_EQUAL(before->early_data_state, after->early_data_state);
#endif
    TEST_EQUAL(before->badmac_seen_or_in_hsfraglen, after->badmac_seen_or_in_hsfraglen);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    TEST_ASSERT(before->f_vrfy == after->f_vrfy);
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    TEST_ASSERT(before->p_vrfy == after->p_vrfy);
#endif
    TEST_ASSERT(before->f_send == after->f_send);
    TEST_ASSERT(before->f_recv == after->f_recv);
    TEST_ASSERT(before->f_recv_timeout == after->f_recv_timeout);
    TEST_ASSERT(before->p_bio == after->p_bio);
    TEST_ASSERT(before->session_in == after->session_in);
    TEST_ASSERT(before->session_out == after->session_out);
    TEST_ASSERT(before->session == after->session);
    TEST_ASSERT(before->session_negotiate != NULL);
    TEST_ASSERT(after->session_negotiate != NULL);
    normalized_session = *after->session_negotiate;
#if defined(MBEDTLS_SSL_EARLY_DATA)
    TEST_EQUAL(before->session_negotiate->max_early_data_size, after->session_negotiate->max_early_data_size);
    normalized_session.max_early_data_size = initial.session_negotiate->max_early_data_size;
#endif
    TEST_MEMORY_COMPARE(&normalized_session, sizeof(normalized_session), initial.session_negotiate, sizeof(*initial.session_negotiate));
    TEST_ASSERT(before->handshake != NULL);
    TEST_ASSERT(after->handshake != NULL);
    TEST_ASSERT(before->handshake->ciphersuite_info == after->handshake->ciphersuite_info);
    TEST_EQUAL(before->handshake->hrr_selected_group, after->handshake->hrr_selected_group);
    TEST_ASSERT(before->handshake->update_checksum ==
                after->handshake->update_checksum);
    normalized_handshake = *after->handshake;
    normalized_handshake.ciphersuite_info = initial.handshake->ciphersuite_info;
    normalized_handshake.hrr_selected_group = initial.handshake->hrr_selected_group;
    normalized_handshake.update_checksum = initial.handshake->update_checksum;
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    TEST_EQUAL(before->handshake->ch1_sni_name_present, after->handshake->ch1_sni_name_present);
    TEST_EQUAL(before->handshake->ch1_sni_name_len, after->handshake->ch1_sni_name_len);
    if (before->handshake->ch1_sni_name_present) {
    TEST_MEMORY_COMPARE(before->handshake->ch1_sni_name, before->handshake->ch1_sni_name_len, after->handshake->ch1_sni_name, after->handshake->ch1_sni_name_len);
    }
    normalized_handshake.ch1_sni_name_present = initial.handshake->ch1_sni_name_present;
    normalized_handshake.ch1_sni_name = initial.handshake->ch1_sni_name;
    normalized_handshake.ch1_sni_name_len = initial.handshake->ch1_sni_name_len;
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    normalized_handshake.fin_sha256_psa = initial.handshake->fin_sha256_psa;
#else
    normalized_handshake.fin_sha256 = initial.handshake->fin_sha256;
#endif
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    normalized_handshake.fin_sha384_psa = initial.handshake->fin_sha384_psa;
#else
    normalized_handshake.fin_sha384 = initial.handshake->fin_sha384;
#endif
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    /* Ignore unspecified inactive union storage in the opaque PAKE operation. */
    memcpy(&normalized_handshake.psa_pake_ctx, &initial.handshake->psa_pake_ctx, sizeof(normalized_handshake.psa_pake_ctx));
#endif
#endif
    TEST_MEMORY_COMPARE(&normalized_handshake, sizeof(normalized_handshake), initial.handshake, sizeof(*initial.handshake));
    TEST_ASSERT(before->transform_in == after->transform_in);
    TEST_ASSERT(before->transform_out == after->transform_out);
    TEST_ASSERT(before->transform == after->transform);
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    TEST_ASSERT(before->transform_negotiate == after->transform_negotiate);
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    TEST_ASSERT(before->transform_application == after->transform_application);
#endif
    TEST_ASSERT(before->p_timer == after->p_timer);
    TEST_ASSERT(before->f_set_timer == after->f_set_timer);
    TEST_ASSERT(before->f_get_timer == after->f_get_timer);
    TEST_ASSERT(after->in_buf != NULL);
    TEST_ASSERT(after->in_ctr != NULL);
    TEST_ASSERT(after->in_hdr != NULL);
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    TEST_ASSERT(after->in_cid != NULL);
#endif
    TEST_ASSERT(after->in_len != NULL);
    TEST_ASSERT(after->in_iv != NULL);
    TEST_ASSERT(after->in_msg != NULL);
    TEST_ASSERT(before->in_offt == after->in_offt);
    TEST_EQUAL(before->in_msgtype, after->in_msgtype);
    TEST_EQUAL(before->in_msglen, after->in_msglen);
    TEST_EQUAL(before->in_left, after->in_left);
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    TEST_EQUAL(before->in_buf_len, after->in_buf_len);
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    TEST_EQUAL(before->in_epoch, after->in_epoch);
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    TEST_EQUAL(before->next_record_offset, after->next_record_offset);
#endif
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    TEST_EQUAL(before->in_window_top, after->in_window_top);
#endif
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    TEST_EQUAL(before->in_window, after->in_window);
#endif
    TEST_EQUAL(before->in_hslen, after->in_hslen);
    TEST_EQUAL(before->nb_zero, after->nb_zero);
    TEST_EQUAL(before->keep_current_message, after->keep_current_message);
    TEST_EQUAL(before->send_alert, after->send_alert);
    TEST_EQUAL(before->alert_type, after->alert_type);
    TEST_EQUAL(before->alert_reason, after->alert_reason);
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    TEST_EQUAL(before->disable_datagram_packing, after->disable_datagram_packing);
#endif
#if defined(MBEDTLS_SSL_EARLY_DATA)

#if defined(MBEDTLS_SSL_SRV_C)
    TEST_EQUAL(before->discard_early_data_record, after->discard_early_data_record);
#endif
#endif
#if defined(MBEDTLS_SSL_EARLY_DATA)
    TEST_EQUAL(before->total_early_data_size, after->total_early_data_size);
#endif
    TEST_ASSERT(after->out_buf != NULL);
    TEST_ASSERT(after->out_ctr != NULL);
    TEST_ASSERT(after->out_hdr != NULL);
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    TEST_ASSERT(after->out_cid != NULL);
#endif
    TEST_ASSERT(after->out_len != NULL);
    TEST_ASSERT(after->out_iv != NULL);
    TEST_ASSERT(after->out_msg != NULL);
    TEST_EQUAL(before->out_msgtype, after->out_msgtype);
    TEST_EQUAL(before->out_msglen, after->out_msglen);
    TEST_EQUAL(before->out_left, after->out_left);
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    TEST_EQUAL(before->out_buf_len, after->out_buf_len);
#endif
    TEST_MEMORY_COMPARE(before->cur_out_ctr, sizeof(before->cur_out_ctr), after->cur_out_ctr, sizeof(after->cur_out_ctr));
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    TEST_EQUAL(before->mtu, after->mtu);
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    TEST_ASSERT(before->hostname == after->hostname);
#endif
#if defined(MBEDTLS_SSL_ALPN)
    TEST_ASSERT(after->alpn_chosen == initial.alpn_chosen);
#endif
#if defined(MBEDTLS_SSL_DTLS_SRTP)
    TEST_MEMORY_COMPARE(&(before->dtls_srtp_info), sizeof(before->dtls_srtp_info), &(after->dtls_srtp_info), sizeof(after->dtls_srtp_info));
#endif
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    TEST_ASSERT(before->cli_id == after->cli_id);
#endif
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    TEST_EQUAL(before->cli_id_len, after->cli_id_len);
#endif
    TEST_EQUAL(before->secure_renegotiation, after->secure_renegotiation);
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    TEST_EQUAL(before->verify_data_len, after->verify_data_len);
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    TEST_MEMORY_COMPARE(before->own_verify_data, sizeof(before->own_verify_data), after->own_verify_data, sizeof(after->own_verify_data));
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    TEST_MEMORY_COMPARE(before->peer_verify_data, sizeof(before->peer_verify_data), after->peer_verify_data, sizeof(after->peer_verify_data));
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    TEST_MEMORY_COMPARE(before->own_cid, sizeof(before->own_cid), after->own_cid, sizeof(after->own_cid));
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    TEST_EQUAL(before->own_cid_len, after->own_cid_len);
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    TEST_EQUAL(before->negotiate_cid, after->negotiate_cid);
#endif
    TEST_ASSERT(before->f_export_keys == after->f_export_keys);
    TEST_ASSERT(before->p_export_keys == after->p_export_keys);
    TEST_EQUAL(before->user_data.n, after->user_data.n);
    /* *INDENT-ON* */

    ret = 0;

exit:
    mbedtls_ssl_free(&initial);
    return ret;
}

#endif /* MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_PROTO_TLS1_3 &&
          MBEDTLS_SSL_SRV_C */
