#!/usr/bin/env python3
"""Generate test code to validate mbedtls_ssl_session_reset().
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import scripts_path # pylint: disable=unused-import
from mbedtls_framework import ssl_session_reset_check

RULES = {
    # Fields that are reset
    'state': ssl_session_reset_check.ResetBehavior.RESET,
    'renego_status': ssl_session_reset_check.ResetBehavior.RESET,
    'renego_records_seen': ssl_session_reset_check.ResetBehavior.RESET,
    'early_data_state': ssl_session_reset_check.ResetBehavior.RESET,
    'badmac_seen': ssl_session_reset_check.ResetBehavior.RESET,
    'session_in': ssl_session_reset_check.ResetBehavior.RESET,
    'session_out': ssl_session_reset_check.ResetBehavior.RESET,
    'session': ssl_session_reset_check.ResetBehavior.RESET,
    'transform_in': ssl_session_reset_check.ResetBehavior.RESET,
    'transform_out': ssl_session_reset_check.ResetBehavior.RESET,
    'transform': ssl_session_reset_check.ResetBehavior.RESET,
    'transform_application': ssl_session_reset_check.ResetBehavior.RESET,
    'in_offt': ssl_session_reset_check.ResetBehavior.RESET,
    'in_msgtype': ssl_session_reset_check.ResetBehavior.RESET,
    'in_msglen': ssl_session_reset_check.ResetBehavior.RESET,
    'in_left': ssl_session_reset_check.ResetBehavior.RESET,
    'in_epoch': ssl_session_reset_check.ResetBehavior.RESET,
    'next_record_offset': ssl_session_reset_check.ResetBehavior.RESET,
    'in_window_top': ssl_session_reset_check.ResetBehavior.RESET,
    'in_window': ssl_session_reset_check.ResetBehavior.RESET,
    'in_hslen': ssl_session_reset_check.ResetBehavior.RESET,
    'in_hsfraglen': ssl_session_reset_check.ResetBehavior.RESET,
    'nb_zero': ssl_session_reset_check.ResetBehavior.RESET,
    'keep_current_message': ssl_session_reset_check.ResetBehavior.RESET,
    'in_fatal_alert_recv': ssl_session_reset_check.ResetBehavior.RESET,
    'in_fatal_alert_type': ssl_session_reset_check.ResetBehavior.RESET,
    'send_alert': ssl_session_reset_check.ResetBehavior.RESET,
    'alert_type': ssl_session_reset_check.ResetBehavior.RESET,
    'alert_reason': ssl_session_reset_check.ResetBehavior.RESET,
    'discard_early_data_record': ssl_session_reset_check.ResetBehavior.RESET,
    'total_early_data_size': ssl_session_reset_check.ResetBehavior.RESET,
    'out_msgtype': ssl_session_reset_check.ResetBehavior.RESET,
    'out_msglen': ssl_session_reset_check.ResetBehavior.RESET,
    'out_left': ssl_session_reset_check.ResetBehavior.RESET,
    'cur_out_ctr': ssl_session_reset_check.ResetBehavior.RESET,
    'alpn_chosen': ssl_session_reset_check.ResetBehavior.RESET,
    'dtls_srtp_info': ssl_session_reset_check.ResetBehavior.RESET,
    'cli_id': ssl_session_reset_check.ResetBehavior.RESET,
    'cli_id_len': ssl_session_reset_check.ResetBehavior.RESET,
    'secure_renegotiation': ssl_session_reset_check.ResetBehavior.RESET,
    'verify_data_len': ssl_session_reset_check.ResetBehavior.RESET,
    'own_verify_data': ssl_session_reset_check.ResetBehavior.RESET,
    'peer_verify_data': ssl_session_reset_check.ResetBehavior.RESET,

    # Fields that are preserved during reset
    'conf': ssl_session_reset_check.ResetBehavior.KEEP,
    'f_vrfy': ssl_session_reset_check.ResetBehavior.KEEP,
    'p_vrfy': ssl_session_reset_check.ResetBehavior.KEEP,
    'f_send': ssl_session_reset_check.ResetBehavior.KEEP,
    'f_recv': ssl_session_reset_check.ResetBehavior.KEEP,
    'f_recv_timeout': ssl_session_reset_check.ResetBehavior.KEEP,
    'p_bio': ssl_session_reset_check.ResetBehavior.KEEP,
    'p_timer': ssl_session_reset_check.ResetBehavior.KEEP,
    'f_set_timer': ssl_session_reset_check.ResetBehavior.KEEP,
    'f_get_timer': ssl_session_reset_check.ResetBehavior.KEEP,
    'disable_datagram_packing': ssl_session_reset_check.ResetBehavior.KEEP,
    'mtu': ssl_session_reset_check.ResetBehavior.KEEP,
    'hostname': ssl_session_reset_check.ResetBehavior.KEEP,
    'own_cid': ssl_session_reset_check.ResetBehavior.KEEP,
    'own_cid_len': ssl_session_reset_check.ResetBehavior.KEEP,
    'negotiate_cid': ssl_session_reset_check.ResetBehavior.KEEP,
    'f_export_keys': ssl_session_reset_check.ResetBehavior.KEEP,
    'p_export_keys': ssl_session_reset_check.ResetBehavior.KEEP,

    # Fields which are intentionally not checked.
    'unused': ssl_session_reset_check.ResetBehavior.IGNORE,

    # Pointers which might be reallocated during reset
    'in_buf': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'in_ctr': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'in_hdr': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'in_cid': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'in_len': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'in_iv': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'in_msg': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'out_buf': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'out_ctr': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'out_hdr': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'out_cid': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'out_len': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'out_iv': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'out_msg': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'session_negotiate': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'handshake': ssl_session_reset_check.ResetBehavior.REALLOCATE,
    'transform_negotiate': ssl_session_reset_check.ResetBehavior.REALLOCATE,

    # Fields with custom check rules. Rules must be defined in the
    # SPECIAL_BEHAVIORS dictionary below.
    'flags': ssl_session_reset_check.ResetBehavior.SPECIAL,
    'tls_version': ssl_session_reset_check.ResetBehavior.SPECIAL,
    'user_data': ssl_session_reset_check.ResetBehavior.SPECIAL,
    'in_buf_len': ssl_session_reset_check.ResetBehavior.SPECIAL,
    'out_buf_len': ssl_session_reset_check.ResetBehavior.SPECIAL,
}

SPECIAL_BEHAVIORS = {
    'flags': ['TEST_EQUAL((after->flags & ~(MBEDTLS_SSL_CONTEXT_FLAGS_KEEP_AT_SESSION)), '
              'initial.flags);',
              'TEST_EQUAL((before->flags & MBEDTLS_SSL_CONTEXT_FLAGS_KEEP_AT_SESSION), ' +
              '(after->flags & MBEDTLS_SSL_CONTEXT_FLAGS_KEEP_AT_SESSION));'],
    'tls_version': ['TEST_ASSERT(after->tls_version == after->conf->max_tls_version);'],
    'user_data': ['TEST_ASSERT(before->user_data.n == after->user_data.n);'],
    'in_buf_len': ['TEST_ASSERT(after->in_buf_len == MBEDTLS_SSL_IN_BUFFER_LEN);'],
    'out_buf_len': ['TEST_ASSERT(after->out_buf_len == MBEDTLS_SSL_OUT_BUFFER_LEN);'],
}

NAMED_STRUCTURES = [
    'dtls_srtp_info',
]

FIELDS_INFO = ssl_session_reset_check.FieldsInfo(RULES,
                                                 SPECIAL_BEHAVIORS,
                                                 NAMED_STRUCTURES)

if __name__ == '__main__':
    ssl_session_reset_check.main(FIELDS_INFO)
