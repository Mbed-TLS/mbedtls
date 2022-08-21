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

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk: with matched key and identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
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
            -s "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk: with matched key and identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -s "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk: with matched key and identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
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
            -s "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk: with matched key and identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk: with matched key and identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk: with mismatched identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk: with mismatched identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk: with mismatched identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk: with mismatched identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk: with mismatched identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk: without pre_shared_key,with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+VERS-TLS1.3 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk: without pre_shared_key,with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex " \
            1 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk: without pre_shared_key,with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg " \
            1 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_ephemeral: with matched key and identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
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
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_ephemeral: with matched key and identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_ephemeral: with matched key and identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_ephemeral: with matched key and identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
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
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_ephemeral: with matched key and identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_ephemeral: with mismatched identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_ephemeral: with mismatched identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_ephemeral: with mismatched identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_ephemeral: with mismatched identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_ephemeral: with mismatched identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_ephemeral: without pre_shared_key,with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+VERS-TLS1.3 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_ephemeral: without pre_shared_key,with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex " \
            1 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_ephemeral: without pre_shared_key,with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg " \
            1 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral: with matched key and identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral: with matched key and identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral: with matched key and identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral: with matched key and identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral: with matched key and identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral: with mismatched identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral: with mismatched identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral: with mismatched identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral: with mismatched identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral: with mismatched identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral: without pre_shared_key,with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+VERS-TLS1.3 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral: without pre_shared_key,with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex " \
            0 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral: without pre_shared_key,with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg " \
            0 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_all: with matched key and identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_all: with matched key and identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_all: with matched key and identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -s "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_all: with matched key and identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_all: with matched key and identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_all: with mismatched identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_all: with mismatched identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_all: with mismatched identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_all: with mismatched identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_all: with mismatched identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_all: without pre_shared_key,with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+VERS-TLS1.3 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_all: without pre_shared_key,with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex " \
            1 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_all: without pre_shared_key,with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg " \
            1 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found"
requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral_all: with matched key and identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral_all: with matched key and identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral_all: with matched key and identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral_all: with matched key and identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral_all: with matched key and identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral_all: with mismatched identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral_all: with mismatched identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral_all: with mismatched identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral_all: with mismatched identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral_all: with mismatched identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral_all: without pre_shared_key,with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+VERS-TLS1.3 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral_all: without pre_shared_key,with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex " \
            0 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: ephemeral_all: without pre_shared_key,with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=ephemeral_all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg " \
            0 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: with matched key and identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: with matched key and identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: with matched key and identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: with matched key and identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: with matched key and identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -s "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: with mismatched identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: with mismatched identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: with mismatched identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: with mismatched identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: with mismatched identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: without pre_shared_key,with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+VERS-TLS1.3 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: without pre_shared_key,with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex " \
            0 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: without pre_shared_key,with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg " \
            0 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_or_ephemeral: with matched key and identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
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
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_or_ephemeral: with matched key and identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_or_ephemeral: with matched key and identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
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
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_or_ephemeral: with matched key and identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
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
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_or_ephemeral: with matched key and identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -s "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_or_ephemeral: with mismatched identity, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_or_ephemeral: with mismatched identity, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_or_ephemeral: with mismatched identity, with psk_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:-ECDHE-PSK:-DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -S "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_or_ephemeral: with mismatched identity, with psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:-PSK:+VERS-TLS1.3 \
                         --pskusername wrong_identity --pskkey=6162636465666768696a6b6c6d6e6f70 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_or_ephemeral: with mismatched identity, with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg \
                         -psk_identity wrong_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            0 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -s "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_or_ephemeral: without pre_shared_key,with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+VERS-TLS1.3 \
                         localhost" \
            0 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_or_ephemeral: without pre_shared_key,with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex " \
            0 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_PSK_ENABLED
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: psk_or_ephemeral: without pre_shared_key,with psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk_or_ephemeral debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg " \
            0 \
            -s "found psk key exchange modes extension" \
            -S "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -S "Found PSK KEX MODE" \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket" \
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -s "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: with mismatched key, with psk_ke and psk_dhe_ke. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$G_NEXT_CLI -d 10 --priority NORMAL:-VERS-ALL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:+VERS-TLS1.3 \
                         --pskusername Client_identity --pskkey=6162636465666768696a6b6c6d6e6f71 \
                         localhost" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Binder is not matched." \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: all: with mismatched key, with psk_ke and psk_dhe_ke. O->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex \
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f71" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "Binder is not matched." \
            -S "Pre shared key found" \
            -S "No matched PSK or ticket"\
            -S "key exchange mode: psk$" \
            -S "key exchange mode: psk_ephemeral" \
            -S "key exchange mode: ephemeral"
