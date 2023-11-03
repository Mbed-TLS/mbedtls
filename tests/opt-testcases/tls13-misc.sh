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
         -S "Invalid ticket start time" \
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
         -S "Invalid ticket start time" \
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
         -s "Invalid ticket start time" \
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
         -S "Invalid ticket start time" \
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
         -S "Invalid ticket start time" \
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
         -S "Invalid ticket start time" \
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

requires_gnutls_tls1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_all_configs_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_EARLY_DATA
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3 m->G: EarlyData: basic check, good" \
            "$G_NEXT_SRV -d 10 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:+ECDHE-PSK:+PSK --earlydata --disable-client-cert" \
            "$P_CLI debug_level=4 early_data=1 reco_mode=1 reconnect=1 reco_delay=900" \
            0 \
            -c "Reconnecting with saved session" \
            -c "NewSessionTicket: early_data(42) extension received." \
            -c "ClientHello: early_data(42) extension exists." \
            -c "EncryptedExtensions: early_data(42) extension received." \
            -c "EncryptedExtensions: early_data(42) extension exists." \
            -c "<= write EndOfEarlyData" \
            -s "Parsing extension 'Early Data/42' (0 bytes)" \
            -s "Sending extension Early Data/42 (0 bytes)" \
            -s "END OF EARLY DATA (5) was received." \
            -s "early data accepted"

requires_gnutls_tls1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_all_configs_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_EARLY_DATA
requires_any_configs_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3 m->G: EarlyData: no early_data in NewSessionTicket, good" \
            "$G_NEXT_SRV -d 10 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:+ECDHE-PSK:+PSK --disable-client-cert" \
            "$P_CLI debug_level=4 early_data=1 reco_mode=1 reconnect=1" \
            0 \
            -c "Reconnecting with saved session" \
            -C "NewSessionTicket: early_data(42) extension received." \
            -c "ClientHello: early_data(42) extension does not exist." \
            -C "EncryptedExtensions: early_data(42) extension received." \
            -C "EncryptedExtensions: early_data(42) extension exists."

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
         -s "No suitable key exchange mode" \
         -s "No matched PSK or ticket"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk/psk." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=8" \
         "$P_CLI debug_level=4 tls13_kex_modes=psk_or_ephemeral reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "No suitable key exchange mode" \
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
         -s "No suitable key exchange mode" \
         -s "No matched PSK or ticket"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk/psk_all." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=10" \
         "$P_CLI debug_level=4 tls13_kex_modes=psk_or_ephemeral reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "No suitable key exchange mode" \
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
         -s "No suitable key exchange mode" \
         -s "No matched PSK or ticket"

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
         -s "No suitable key exchange mode" \
         -s "No matched PSK or ticket"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk_ephemeral/psk_ephemeral." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=9" \
         "$P_CLI debug_level=4 tls13_kex_modes=ephemeral_all reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "No suitable key exchange mode" \
         -s "found matched identity"

requires_all_configs_enabled MBEDTLS_SSL_SESSION_TICKETS \
                             MBEDTLS_SSL_SRV_C MBEDTLS_SSL_CLI_C MBEDTLS_DEBUG_C \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED \
                             MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
run_test "TLS 1.3 m->m: Resumption with ticket flags, psk_ephemeral/psk_all." \
         "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key dummy_ticket=10" \
         "$P_CLI debug_level=4 tls13_kex_modes=ephemeral_all reconnect=1" \
         0 \
         -c "Pre-configured PSK number = 1" \
         -S "No suitable key exchange mode" \
         -s "found matched identity"

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
         -s "No suitable key exchange mode" \
         -s "No matched PSK or ticket"

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
         -S "No suitable key exchange mode" \
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
         -S "No suitable key exchange mode" \
         -s "found matched identity"

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
         -S "No suitable key exchange mode" \
         -s "found matched identity"

