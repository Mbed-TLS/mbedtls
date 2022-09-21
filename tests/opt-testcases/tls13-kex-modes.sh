#!/bin/sh

# tls13-kex-modes.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

get_srv_psk_list ()
{
    case $(( TESTS % 3 )) in
        0) echo "psk_list=abc,dead,def,beef,Client_identity,6162636465666768696a6b6c6d6e6f70";;
        1) echo "psk_list=abc,dead,Client_identity,6162636465666768696a6b6c6d6e6f70,def,beef";;
        2) echo "psk_list=Client_identity,6162636465666768696a6b6c6d6e6f70,abc,dead,def,beef";;
    esac
}

requires_gnutls_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: No valid ciphersuite. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
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
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: No valid ciphersuite. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex -ciphersuites TLS_AES_256_GCM_SHA384\
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched ciphersuite"


requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/psk, fail, no common kex mode" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 $(get_srv_psk_list)" \
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
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/psk, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -s "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/psk, fail, key id mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/psk, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_or_ephemeral/psk, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -s "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_or_ephemeral/psk, fail, key id mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_or_ephemeral/psk, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/psk_ephemeral, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/psk_ephemeral, fail, key id mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/psk_ephemeral, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/psk_ephemeral, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/psk_ephemeral, fail, key id mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/psk_ephemeral, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_or_ephemeral/psk_ephemeral, fail, no common kex mode" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/psk_all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/psk_all, fail, key id mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/psk_all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/psk_all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/psk_all, fail, key id mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/psk_all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_or_ephemeral/psk_all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -s "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_or_ephemeral/psk_all, fail, key id mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_or_ephemeral/psk_all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/ephemeral_all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/ephemeral_all, good, key id mismatch, dhe." \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/ephemeral_all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/ephemeral_all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/ephemeral_all, good, key id mismatch, dhe." \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/ephemeral_all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_or_ephemeral/ephemeral_all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/all, good, key id mismatch, dhe." \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/all, good, key id mismatch, dhe." \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_or_ephemeral/all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_or_ephemeral/all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: ephemeral_all/psk_or_ephemeral, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/psk_or_ephemeral, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: all/psk_or_ephemeral, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_or_ephemeral/psk_or_ephemeral, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_or_ephemeral/psk_or_ephemeral, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_ephemeral group(secp256r1) check, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3:-GROUP-ALL:+GROUP-SECP256R1 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "write selected_group: secp256r1" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_ephemeral group(secp384r1) check, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3:-GROUP-ALL:+GROUP-SECP384R1 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "write selected_group: secp384r1" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_ephemeral group(secp521r1) check, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3:-GROUP-ALL:+GROUP-SECP521R1 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "write selected_group: secp521r1" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_ephemeral group(x25519) check, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3:-GROUP-ALL:+GROUP-X25519 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "write selected_group: x25519" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_gnutls_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: G->m: psk_ephemeral group(x448) check, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3:-GROUP-ALL:+GROUP-X448 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "write selected_group: x448" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/psk, fail, no common kex mode" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/psk, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -s "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/psk, fail, key id mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity wrong_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/psk, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f71" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/psk_ephemeral, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/psk_ephemeral, fail, key id mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity wrong_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/psk_ephemeral, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f71" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/psk_ephemeral, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/psk_ephemeral, fail, key id mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity wrong_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/psk_ephemeral, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f71" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/psk_all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/psk_all, fail, key id mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity wrong_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/psk_all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f71" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/psk_all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/psk_all, fail, key id mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity wrong_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/psk_all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f71" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/ephemeral_all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/ephemeral_all, good, key id mismatch, dhe." \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity wrong_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/ephemeral_all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f71" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/ephemeral_all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/ephemeral_all, good, key id mismatch, dhe." \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity wrong_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/ephemeral_all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f71" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/all, good, key id mismatch, dhe." \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity wrong_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f71" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/all, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/all, good, key id mismatch, dhe." \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity wrong_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/all, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f71" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: ephemeral_all/psk_or_ephemeral, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg   \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/psk_or_ephemeral, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: all/psk_or_ephemeral, fail, key material mismatch" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 $(get_srv_psk_list)" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f71" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Invalid binder." \
            -S "key exchange mode: psk$"  \
            -S "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: psk_ephemeral group(secp256r1) check, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex -groups P-256 \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "write selected_group: secp256r1" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: psk_ephemeral group(secp384r1) check, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex -groups secp384r1 \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "write selected_group: secp384r1" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: psk_ephemeral group(secp521r1) check, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex -groups secp521r1 \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "write selected_group: secp521r1" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: psk_ephemeral group(x25519) check, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex -groups X25519 \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "write selected_group: x25519" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_all_configs_enabled MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE MBEDTLS_SSL_SRV_C MBEDTLS_DEBUG_C
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: O->m: psk_ephemeral group(x448) check, good" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg  -allow_no_dhe_kex -groups X448 \
                         -psk_identity Client_identity  -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "write selected_group: x448" \
            -S "key exchange mode: psk$"  \
            -s "key exchange mode: psk_ephemeral"  \
            -S "key exchange mode: ephemeral"
