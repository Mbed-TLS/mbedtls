# Regression tests for TLS 1.3 with opaque pre-shared keys (#10956).
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

# 10956: TLS 1.3 opaque PSK regression tests.
# The sample programs import the opaque PSK with PSA_KEY_USAGE_DERIVE only
# (no PSA_KEY_USAGE_EXPORT), so these tests fail if the TLS 1.3 key
# schedule or PSK binder calculation tries to export the key instead of
# using psa_key_derivation_input_key().
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3: PSK: opaque PSK both sides" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=4 \
             force_ciphersuite=TLS1-3-AES-128-GCM-SHA256 \
             psk=00112233445566778899aabbccddeeff \
             psk_identity=Client_identity psk_opaque=1" \
            "$P_CLI force_version=tls13 tls13_kex_modes=psk debug_level=4 \
             force_ciphersuite=TLS1-3-AES-128-GCM-SHA256 \
             psk=00112233445566778899aabbccddeeff \
             psk_identity=Client_identity psk_opaque=1" \
            0 \
            -c "Protocol is TLSv1.3" \
            -s "Pre shared key found"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3: PSK: opaque client, raw server" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=4 \
             force_ciphersuite=TLS1-3-AES-128-GCM-SHA256 \
             psk=00112233445566778899aabbccddeeff \
             psk_identity=Client_identity" \
            "$P_CLI force_version=tls13 tls13_kex_modes=psk debug_level=4 \
             force_ciphersuite=TLS1-3-AES-128-GCM-SHA256 \
             psk=00112233445566778899aabbccddeeff \
             psk_identity=Client_identity psk_opaque=1" \
            0 \
            -c "Protocol is TLSv1.3" \
            -s "Pre shared key found"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
run_test    "TLS 1.3: PSK: raw client, opaque server" \
            "$P_SRV force_version=tls13 tls13_kex_modes=psk debug_level=4 \
             force_ciphersuite=TLS1-3-AES-128-GCM-SHA256 \
             psk=00112233445566778899aabbccddeeff \
             psk_identity=Client_identity psk_opaque=1" \
            "$P_CLI force_version=tls13 tls13_kex_modes=psk debug_level=4 \
             force_ciphersuite=TLS1-3-AES-128-GCM-SHA256 \
             psk=00112233445566778899aabbccddeeff \
             psk_identity=Client_identity" \
            0 \
            -c "Protocol is TLSv1.3" \
            -s "Pre shared key found"
