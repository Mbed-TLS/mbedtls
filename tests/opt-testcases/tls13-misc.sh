#!/bin/sh

# tls13-misc.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

requires_gnutls_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED

run_test    "TLS 1.3: PSK: No valid ciphersuite. G->m" \
            "$P_SRV tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-CIPHER-ALL:+AES-256-GCM:+AEAD:+SHA384:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched ciphersuite"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED

run_test    "TLS 1.3: PSK: No valid ciphersuite. O->m" \
            "$P_SRV tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex -ciphersuites TLS_AES_256_GCM_SHA384\
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched ciphersuite"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Multiple PSKs: valid ticket, reconnect with ticket" \
         "$P_SRV tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70 tickets=8" \
         "$P_CLI tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 2" \
         -s "sent selected_identity: 0" \
         -s "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "key exchange mode: ephemeral$" \
         -S "ticket is not authentic"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Multiple PSKs: invalid ticket, reconnect with PSK" \
         "$P_SRV tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70 tickets=8 dummy_ticket=1" \
         "$P_CLI tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 2" \
         -s "sent selected_identity: 1" \
         -s "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "key exchange mode: ephemeral$" \
         -s "ticket is not authentic"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Session resumption failure, ticket authentication failed." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key tickets=8 dummy_ticket=1" \
         "$P_CLI debug_level=4 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -s "ticket is not authentic" \
         -S "ticket is expired" \
         -S "Invalid ticket creation time" \
         -S "Ticket age exceeds limitation" \
         -S "Ticket age outside tolerance window"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Session resumption failure, ticket expired." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key tickets=8 dummy_ticket=2" \
         "$P_CLI debug_level=4 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "ticket is not authentic" \
         -s "ticket is expired" \
         -S "Invalid ticket creation time" \
         -S "Ticket age exceeds limitation" \
         -S "Ticket age outside tolerance window"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Session resumption failure, invalid start time." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key tickets=8 dummy_ticket=3" \
         "$P_CLI debug_level=4 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "ticket is not authentic" \
         -S "ticket is expired" \
         -s "Invalid ticket creation time" \
         -S "Ticket age exceeds limitation" \
         -S "Ticket age outside tolerance window"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Session resumption failure, ticket expired. too old" \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key tickets=8 dummy_ticket=4" \
         "$P_CLI debug_level=4 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "ticket is not authentic" \
         -S "ticket is expired" \
         -S "Invalid ticket creation time" \
         -s "Ticket age exceeds limitation" \
         -S "Ticket age outside tolerance window"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Session resumption failure, age outside tolerance window, too young." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key tickets=8 dummy_ticket=5" \
         "$P_CLI debug_level=4 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "ticket is not authentic" \
         -S "ticket is expired" \
         -S "Invalid ticket creation time" \
         -S "Ticket age exceeds limitation" \
         -s "Ticket age outside tolerance window"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Session resumption failure, age outside tolerance window, too old." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key tickets=8 dummy_ticket=6" \
         "$P_CLI debug_level=4 reco_mode=1 reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -S "ticket is not authentic" \
         -S "ticket is expired" \
         -S "Invalid ticket creation time" \
         -S "Ticket age exceeds limitation" \
         -s "Ticket age outside tolerance window"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/psk, fail, no common kex mode" \
            "$P_SRV tls13_kex_modes=psk debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
requires_all_configs_disabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                              MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
run_test    "TLS 1.3: G->m: PSK: configured psk only, good." \
            "$P_SRV tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3:+GROUP-ALL \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension"         \
            -s "Found PSK_EPHEMERAL KEX MODE"           \
            -s "Found PSK KEX MODE"                     \
            -s "key exchange mode: psk$"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
requires_all_configs_disabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                              MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
run_test    "TLS 1.3: G->m: PSK: configured psk_ephemeral only, good." \
            "$P_SRV tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3:+GROUP-ALL \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension"         \
            -s "Found PSK_EPHEMERAL KEX MODE"           \
            -s "Found PSK KEX MODE"                     \
            -s "key exchange mode: psk_ephemeral$"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
requires_all_configs_disabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                              MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test    "TLS 1.3: G->m: PSK: configured ephemeral only, good." \
            "$P_SRV tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3:+GROUP-ALL \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "key exchange mode: ephemeral$"

requires_openssl_tls1_3_with_compatible_ephemeral
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_all_configs_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test    "TLS 1.3: NewSessionTicket: Basic check, m->O" \
            "$O_NEXT_SRV -msg -tls1_3 -no_resume_ephemeral -no_cache --num_tickets 4" \
            "$P_CLI debug_level=1 reco_mode=1 reconnect=1" \
            0 \
            -c "Protocol is TLSv1.3" \
            -c "got new session ticket." \
            -c "Saving session for reuse... ok" \
            -c "Reconnecting with saved session" \
            -c "HTTP/1.0 200 ok"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_CLI_C \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3 m->G: resumption" \
            "$G_NEXT_SRV -d 5 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3 --disable-client-cert" \
            "$P_CLI reco_mode=1 reconnect=1" \
            0 \
            -c "Protocol is TLSv1.3" \
            -c "Saving session for reuse... ok" \
            -c "Reconnecting with saved session... ok" \
            -c "HTTP/1.0 200 OK"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_CLI_C \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
requires_ciphersuite_enabled TLS1-3-AES-256-GCM-SHA384
run_test    "TLS 1.3 m->G: resumption with AES-256-GCM-SHA384 only" \
            "$G_NEXT_SRV -d 5 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3 --disable-client-cert" \
            "$P_CLI force_ciphersuite=TLS1-3-AES-256-GCM-SHA384 reco_mode=1 reconnect=1" \
            0 \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS1-3-AES-256-GCM-SHA384" \
            -c "Saving session for reuse... ok" \
            -c "Reconnecting with saved session... ok" \
            -c "HTTP/1.0 200 OK"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_EARLY_DATA \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3 m->G: resumption with early data" \
            "$G_NEXT_SRV -d 5 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3 --disable-client-cert \
                         --earlydata --maxearlydata 16384" \
            "$P_CLI debug_level=3 early_data=1 reco_mode=1 reconnect=1" \
            0 \
            -c "Protocol is TLSv1.3" \
            -c "Saving session for reuse... ok" \
            -c "Reconnecting with saved session" \
            -c "HTTP/1.0 200 OK" \
            -c "received max_early_data_size: 16384" \
            -c "NewSessionTicket: early_data(42) extension received." \
            -c "ClientHello: early_data(42) extension exists." \
            -c "EncryptedExtensions: early_data(42) extension received." \
            -c "bytes of early data written" \
            -s "decrypted early data with length:"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_EARLY_DATA \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
requires_ciphersuite_enabled TLS1-3-AES-256-GCM-SHA384
run_test    "TLS 1.3 m->G: resumption with early data, AES-256-GCM-SHA384 only" \
            "$G_NEXT_SRV -d 5 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3 --disable-client-cert \
                         --earlydata --maxearlydata 16384" \
            "$P_CLI debug_level=3 force_ciphersuite=TLS1-3-AES-256-GCM-SHA384 early_data=1 reco_mode=1 reconnect=1" \
            0 \
            -c "Protocol is TLSv1.3" \
            -c "Ciphersuite is TLS1-3-AES-256-GCM-SHA384" \
            -c "Saving session for reuse... ok" \
            -c "Reconnecting with saved session" \
            -c "HTTP/1.0 200 OK" \
            -c "received max_early_data_size: 16384" \
            -c "NewSessionTicket: early_data(42) extension received." \
            -c "ClientHello: early_data(42) extension exists." \
            -c "EncryptedExtensions: early_data(42) extension received." \
            -c "bytes of early data written" \
            -s "decrypted early data with length:"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_EARLY_DATA \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3 m->G: resumption, early data cli-enabled/srv-disabled" \
            "$G_NEXT_SRV -d 5 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:+ECDHE-PSK:+PSK --disable-client-cert" \
            "$P_CLI debug_level=3 early_data=1 reco_mode=1 reconnect=1" \
            0 \
            -c "Protocol is TLSv1.3" \
            -c "Saving session for reuse... ok" \
            -c "Reconnecting with saved session" \
            -c "HTTP/1.0 200 OK" \
            -C "received max_early_data_size: 16384" \
            -C "NewSessionTicket: early_data(42) extension received." \

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_EARLY_DATA \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3 m->G: resumption, early data cli-default/srv-enabled" \
            "$G_NEXT_SRV -d 5 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3 --disable-client-cert \
                         --earlydata --maxearlydata 16384" \
            "$P_CLI debug_level=3 reco_mode=1 reconnect=1" \
            0 \
            -c "Protocol is TLSv1.3" \
            -c "Saving session for reuse... ok" \
            -c "Reconnecting with saved session" \
            -c "HTTP/1.0 200 OK" \
            -c "received max_early_data_size: 16384" \
            -c "NewSessionTicket: early_data(42) extension received." \
            -C "ClientHello: early_data(42) extension exists." \

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_EARLY_DATA \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3 m->G: resumption, early data cli-disabled/srv-enabled" \
            "$G_NEXT_SRV -d 5 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3 --disable-client-cert \
                         --earlydata --maxearlydata 16384" \
            "$P_CLI debug_level=3 early_data=0 reco_mode=1 reconnect=1" \
            0 \
            -c "Protocol is TLSv1.3" \
            -c "Saving session for reuse... ok" \
            -c "Reconnecting with saved session" \
            -c "HTTP/1.0 200 OK" \
            -c "received max_early_data_size: 16384" \
            -c "NewSessionTicket: early_data(42) extension received." \
            -C "ClientHello: early_data(42) extension exists." \

requires_openssl_tls1_3_with_compatible_ephemeral
requires_config_enabled MBEDTLS_SSL_SESSION_TICKETS
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
requires_all_configs_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
# https://github.com/openssl/openssl/issues/10714
# Until now, OpenSSL client does not support reconnect.
skip_next_test
run_test    "TLS 1.3: NewSessionTicket: Basic check, O->m" \
            "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key tickets=4" \
            "$O_NEXT_CLI -msg -debug -tls1_3 -reconnect" \
            0 \
            -s "=> write NewSessionTicket msg" \
            -s "server state: MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET" \
            -s "server state: MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET_FLUSH"

requires_gnutls_tls1_3
requires_config_enabled MBEDTLS_SSL_SESSION_TICKETS
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
requires_all_configs_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test    "TLS 1.3: NewSessionTicket: Basic check, G->m" \
            "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key tickets=4" \
            "$G_NEXT_CLI localhost -d 4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3 -V -r" \
            0 \
            -c "Connecting again- trying to resume previous session" \
            -c "NEW SESSION TICKET (4) was received" \
            -s "=> write NewSessionTicket msg" \
            -s "server state: MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET" \
            -s "server state: MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET_FLUSH" \
            -s "key exchange mode: ephemeral" \
            -s "key exchange mode: psk_ephemeral" \
            -s "found pre_shared_key extension"

requires_gnutls_tls1_3
requires_config_enabled MBEDTLS_SSL_SESSION_TICKETS
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
requires_all_configs_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
# Test the session resumption when the cipher suite for the original session is
# TLS1-3-AES-256-GCM-SHA384. In that case, the PSK is 384 bits long and not
# 256 bits long as with all the other TLS 1.3 cipher suites.
requires_ciphersuite_enabled TLS1-3-AES-256-GCM-SHA384
run_test    "TLS 1.3: NewSessionTicket: Basic check with AES-256-GCM only, G->m" \
            "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=4" \
            "$G_NEXT_CLI localhost -d 4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-256-GCM -V -r" \
            0 \
            -c "Connecting again- trying to resume previous session" \
            -c "NEW SESSION TICKET (4) was received" \
            -s "Ciphersuite is TLS1-3-AES-256-GCM-SHA384" \
            -s "=> write NewSessionTicket msg" \
            -s "server state: MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET" \
            -s "server state: MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET_FLUSH" \
            -s "key exchange mode: ephemeral" \
            -s "key exchange mode: psk_ephemeral" \
            -s "found pre_shared_key extension"

requires_config_enabled MBEDTLS_SSL_SESSION_TICKETS
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_DEBUG_C
requires_all_configs_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test    "TLS 1.3: NewSessionTicket: Basic check, m->m" \
            "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key tickets=4" \
            "$P_CLI debug_level=4 reco_mode=1 reconnect=1" \
            0 \
            -c "Protocol is TLSv1.3" \
            -c "got new session ticket ( 3 )" \
            -c "Saving session for reuse... ok" \
            -c "Reconnecting with saved session" \
            -c "HTTP/1.0 200 OK"    \
            -s "=> write NewSessionTicket msg" \
            -s "server state: MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET" \
            -s "server state: MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET_FLUSH" \
            -s "key exchange mode: ephemeral" \
            -s "key exchange mode: psk_ephemeral" \
            -s "found pre_shared_key extension"

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 \
                             MBEDTLS_SSL_CLI_C MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_HAVE_TIME \
                             MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test    "TLS 1.3 m->m: NewSessionTicket: Ticket lifetime max value (7d)" \
            "$P_SRV debug_level=1 crt_file=data_files/server5.crt key_file=data_files/server5.key ticket_timeout=604800 tickets=1" \
            "$P_CLI reco_mode=1 reconnect=1" \
            0 \
            -c "Protocol is TLSv1.3" \
            -c "HTTP/1.0 200 OK" \
            -c "got new session ticket" \
            -c "Reconnecting with saved session... ok" \
            -s "Protocol is TLSv1.3" \
            -S "Ticket lifetime (604800) is greater than 7 days."

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 \
                             MBEDTLS_SSL_CLI_C MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_HAVE_TIME \
                             MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test    "TLS 1.3 m->m: NewSessionTicket: Ticket lifetime too long (7d + 1s)" \
            "$P_SRV debug_level=1 crt_file=data_files/server5.crt key_file=data_files/server5.key ticket_timeout=604801 tickets=1" \
            "$P_CLI reco_mode=1 reconnect=1" \
            1 \
            -c "Protocol is TLSv1.3" \
            -C "HTTP/1.0 200 OK" \
            -C "got new session ticket" \
            -C "Reconnecting with saved session... ok" \
            -S "Protocol is TLSv1.3" \
            -s "Ticket lifetime (604801) is greater than 7 days."

requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 \
                             MBEDTLS_SSL_CLI_C MBEDTLS_SSL_SRV_C \
                             MBEDTLS_SSL_SESSION_TICKETS MBEDTLS_HAVE_TIME \
                             MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test    "TLS 1.3 m->m: NewSessionTicket: ticket lifetime=0" \
            "$P_SRV debug_level=2 crt_file=data_files/server5.crt key_file=data_files/server5.key ticket_timeout=0 tickets=1" \
            "$P_CLI debug_level=2 reco_mode=1 reconnect=1" \
            1 \
            -c "Protocol is TLSv1.3" \
            -c "HTTP/1.0 200 OK" \
            -c "Discard new session ticket" \
            -C "got new session ticket" \
            -c "Reconnecting with saved session... failed" \
            -s "Protocol is TLSv1.3" \
            -s "<= write new session ticket"

requires_config_enabled MBEDTLS_SSL_SESSION_TICKETS
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_DEBUG_C
requires_all_configs_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test    "TLS 1.3: NewSessionTicket: servername check, m->m" \
            "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key tickets=4 \
            sni=localhost,data_files/server2.crt,data_files/server2.key,-,-,-,polarssl.example,data_files/server1-nospace.crt,data_files/server1.key,-,-,-" \
            "$P_CLI debug_level=4 server_name=localhost reco_mode=1 reconnect=1" \
            0 \
            -c "Protocol is TLSv1.3" \
            -c "got new session ticket." \
            -c "Saving session for reuse... ok" \
            -c "Reconnecting with saved session" \
            -c "HTTP/1.0 200 OK"    \
            -s "=> write NewSessionTicket msg" \
            -s "server state: MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET" \
            -s "server state: MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET_FLUSH" \
            -s "key exchange mode: ephemeral" \
            -s "key exchange mode: psk_ephemeral" \
            -s "found pre_shared_key extension"

requires_config_enabled MBEDTLS_SSL_SESSION_TICKETS
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_DEBUG_C
requires_all_configs_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test    "TLS 1.3: NewSessionTicket: servername negative check, m->m" \
            "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key tickets=4 \
            sni=localhost,data_files/server2.crt,data_files/server2.key,-,-,-,polarssl.example,data_files/server1-nospace.crt,data_files/server1.key,-,-,-" \
            "$P_CLI debug_level=4 server_name=localhost reco_server_name=remote reco_mode=1 reconnect=1" \
            1 \
            -c "Protocol is TLSv1.3" \
            -c "got new session ticket." \
            -c "Saving session for reuse... ok" \
            -c "Reconnecting with saved session" \
            -c "Hostname mismatch the session ticket, disable session resumption."    \
            -s "=> write NewSessionTicket msg" \
            -s "server state: MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET" \
            -s "server state: MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET_FLUSH"

#TODO: OpenSSL tests don't work now. It might be openssl options issue, cause GnuTLS has worked.
skip_next_test
requires_openssl_tls1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_all_configs_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_EARLY_DATA
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3, ext PSK, early data" \
            "$O_NEXT_SRV_EARLY_DATA -msg -debug -tls1_3 -psk_identity 0a0b0c -psk 010203 -allow_no_dhe_kex -nocert" \
            "$P_CLI debug_level=5 tls13_kex_modes=psk early_data=1 psk=010203 psk_identity=0a0b0c" \
             1 \
            -c "Reconnecting with saved session" \
            -c "NewSessionTicket: early_data(42) extension received." \
            -c "ClientHello: early_data(42) extension exists." \
            -c "EncryptedExtensions: early_data(42) extension received." \
            -c "EncryptedExtensions: early_data(42) extension ( ignored )."

EARLY_DATA_INPUT_LEN_BLOCKS=$(( ( $( cat $EARLY_DATA_INPUT | wc -c ) + 31 ) / 32 ))
EARLY_DATA_INPUT_LEN=$(( $EARLY_DATA_INPUT_LEN_BLOCKS * 32 ))

requires_gnutls_next
requires_all_configs_enabled MBEDTLS_SSL_EARLY_DATA MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 G->m: EarlyData: feature is enabled, good." \
         "$P_SRV force_version=tls13 debug_level=4 early_data=1 max_early_data_size=$EARLY_DATA_INPUT_LEN" \
         "$G_NEXT_CLI localhost --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+GROUP-ALL:+KX-ALL \
                      -d 10 -r --earlydata $EARLY_DATA_INPUT " \
         0 \
         -s "Sent max_early_data_size=$EARLY_DATA_INPUT_LEN"                \
         -s "NewSessionTicket: early_data(42) extension exists."            \
         -s "ClientHello: early_data(42) extension exists."                 \
         -s "EncryptedExtensions: early_data(42) extension exists."         \
         -s "$( head -1 $EARLY_DATA_INPUT )"                                \
         -s "$( tail -1 $EARLY_DATA_INPUT )"                                \
         -s "200 early data bytes read"                                     \
         -s "106 early data bytes read"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk/none." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=7" \
         "$P_CLI debug_level=4 tls13_kex_modes=psk_or_ephemeral reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -s "No suitable PSK key exchange mode" \
         -s "No usable PSK or ticket"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk/psk." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=8" \
         "$P_CLI debug_level=4 tls13_kex_modes=psk_or_ephemeral reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "No suitable PSK key exchange mode" \
         -s "found matched identity"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk/psk_ephemeral." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=9" \
         "$P_CLI debug_level=4 tls13_kex_modes=psk_or_ephemeral reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -s "No suitable PSK key exchange mode" \
         -s "No usable PSK or ticket"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk/psk_all." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=10" \
         "$P_CLI debug_level=4 tls13_kex_modes=psk_or_ephemeral reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "No suitable PSK key exchange mode" \
         -s "found matched identity"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk_ephemeral/none." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=7" \
         "$P_CLI debug_level=4 tls13_kex_modes=ephemeral_all reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -s "No suitable PSK key exchange mode" \
         -s "No usable PSK or ticket"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk_ephemeral/psk." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=8" \
         "$P_CLI debug_level=4 tls13_kex_modes=ephemeral_all reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -s "No suitable PSK key exchange mode" \
         -s "No usable PSK or ticket"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk_ephemeral/psk_ephemeral." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=9" \
         "$P_CLI debug_level=4 tls13_kex_modes=ephemeral_all reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "No suitable PSK key exchange mode" \
         -s "found matched identity" \
         -s "key exchange mode: psk_ephemeral"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk_ephemeral/psk_all." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=10" \
         "$P_CLI debug_level=4 tls13_kex_modes=ephemeral_all reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "No suitable PSK key exchange mode" \
         -s "found matched identity" \
         -s "key exchange mode: psk_ephemeral"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk_all/none." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=7" \
         "$P_CLI debug_level=4 tls13_kex_modes=all reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "sent selected_identity:" \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk_ephemeral" \
         -S "key exchange mode: psk$" \
         -s "No suitable PSK key exchange mode" \
         -s "No usable PSK or ticket"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk_all/psk." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=8" \
         "$P_CLI debug_level=4 tls13_kex_modes=all reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "No suitable PSK key exchange mode" \
         -s "found matched identity"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk_all/psk_ephemeral." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=9" \
         "$P_CLI debug_level=4 tls13_kex_modes=all reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "No suitable PSK key exchange mode" \
         -s "found matched identity" \
         -s "key exchange mode: psk_ephemeral"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk_all/psk_all." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=10" \
         "$P_CLI debug_level=4 tls13_kex_modes=all reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "No suitable PSK key exchange mode" \
         -s "found matched identity" \
         -s "key exchange mode: psk_ephemeral"

requires_all_configs_enabled MBEDTLS_SSL_EARLY_DATA MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_CLI_C MBEDTLS_SSL_SRV_C \
                             MBEDTLS_DEBUG_C MBEDTLS_HAVE_TIME \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Ephemeral over PSK kex with early data enabled" \
         "$P_SRV force_version=tls13 debug_level=4 early_data=1 max_early_data_size=1024" \
         "$P_CLI debug_level=4 early_data=1 tls13_kex_modes=psk_or_ephemeral reco_mode=1 reconnect=1" \
         0 \
         -s "key exchange mode: ephemeral" \
         -S "key exchange mode: psk" \
         -s "found matched identity" \
         -s "EarlyData: rejected, not a session resumption" \
         -C "EncryptedExtensions: early_data(42) extension exists."
