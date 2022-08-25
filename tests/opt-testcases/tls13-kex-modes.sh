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

requires_gnutls_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_DEBUG_C
# SOME_ECDHE_ENABLED?
requires_any_configs_enabled MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED \
                             MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
run_test    "TLS 1.3: PSK: No valid ciphersuite. G->m" \
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
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
            "$P_SRV force_version=tls13 tls13_kex_modes=all debug_level=5 psk_identity=Client_identity psk=6162636465666768696a6b6c6d6e6f70" \
            "$O_NEXT_CLI -tls1_3 -msg -allow_no_dhe_kex -ciphersuites TLS_AES_256_GCM_SHA384\
                         -psk_identity Client_identity -psk 6162636465666768696a6b6c6d6e6f70" \
            1 \
            -s "found psk key exchange modes extension" \
            -s "found pre_shared_key extension" \
            -s "Found PSK_EPHEMERAL KEX MODE" \
            -s "Found PSK KEX MODE" \
            -s "No matched ciphersuite"