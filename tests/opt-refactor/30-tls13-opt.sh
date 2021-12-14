#!/bin/sh

# 30-tls13-opt.sh
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

# Dummy TLS 1.3 test
# Currently only checking that passing TLS 1.3 key exchange modes to
# ssl_client2/ssl_server2 example programs works.
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test    "TLS 1.3, key exchange mode parameter passing: PSK only" \
            "$P_SRV tls13_kex_modes=psk" \
            "$P_CLI tls13_kex_modes=psk" \
            0
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test    "TLS 1.3, key exchange mode parameter passing: PSK-ephemeral only" \
            "$P_SRV tls13_kex_modes=psk_ephemeral" \
            "$P_CLI tls13_kex_modes=psk_ephemeral" \
            0
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test    "TLS 1.3, key exchange mode parameter passing: Pure-ephemeral only" \
            "$P_SRV tls13_kex_modes=ephemeral" \
            "$P_CLI tls13_kex_modes=ephemeral" \
            0
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test    "TLS 1.3, key exchange mode parameter passing: All ephemeral" \
            "$P_SRV tls13_kex_modes=ephemeral_all" \
            "$P_CLI tls13_kex_modes=ephemeral_all" \
            0
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test    "TLS 1.3, key exchange mode parameter passing: All PSK" \
            "$P_SRV tls13_kex_modes=psk_all" \
            "$P_CLI tls13_kex_modes=psk_all" \
            0
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test    "TLS 1.3, key exchange mode parameter passing: All" \
            "$P_SRV tls13_kex_modes=all" \
            "$P_CLI tls13_kex_modes=all" \
            0


# openssl feature tests: check if tls1.3 exists.
requires_openssl_tls1_3
run_test    "TLS 1.3: Test openssl tls1_3 feature" \
            "$O_NEXT_SRV -tls1_3 -msg" \
            "$O_NEXT_CLI -tls1_3 -msg" \
            0 \
            -c "TLS 1.3" \
            -s "TLS 1.3"

# gnutls feature tests: check if TLS 1.3 is supported as well as the NO_TICKETS and DISABLE_TLS13_COMPAT_MODE options.
requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_gnutls_next_disable_tls13_compat
run_test    "TLS 1.3: Test gnutls tls1_3 feature" \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS:%DISABLE_TLS13_COMPAT_MODE --disable-client-cert " \
            "$G_NEXT_CLI localhost --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:%NO_TICKETS:%DISABLE_TLS13_COMPAT_MODE -V" \
            0 \
            -s "Version: TLS1.3" \
            -c "Version: TLS1.3"

# TLS1.3 test cases
# TODO: remove or rewrite this test case if #4832 is resolved.
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
skip_handshake_stage_check
run_test    "TLS 1.3: Not supported version check: tls12 and tls13" \
            "$P_SRV debug_level=1 min_version=tls12 max_version=tls13" \
            "$P_CLI debug_level=1 min_version=tls12 max_version=tls13" \
            1 \
            -s "SSL - The requested feature is not available" \
            -c "SSL - The requested feature is not available" \
            -s "Hybrid TLS 1.2 + TLS 1.3 configurations are not yet supported" \
            -c "Hybrid TLS 1.2 + TLS 1.3 configurations are not yet supported"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test    "TLS 1.3: handshake dispatch test: tls13 only" \
            "$P_SRV debug_level=2 min_version=tls13 max_version=tls13" \
            "$P_CLI debug_level=2 min_version=tls13 max_version=tls13" \
            1 \
            -s "tls13 server state: MBEDTLS_SSL_HELLO_REQUEST"     \
            -c "tls13 client state: MBEDTLS_SSL_HELLO_REQUEST"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_disabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: minimal feature sets - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache" \
            "$P_CLI debug_level=3 min_version=tls13 max_version=tls13" \
            0 \
            -c "tls13 client state: MBEDTLS_SSL_HELLO_REQUEST(0)"               \
            -c "tls13 client state: MBEDTLS_SSL_SERVER_HELLO(2)"                \
            -c "tls13 client state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS(19)"       \
            -c "tls13 client state: MBEDTLS_SSL_CERTIFICATE_REQUEST(5)"         \
            -c "tls13 client state: MBEDTLS_SSL_SERVER_CERTIFICATE(3)"          \
            -c "tls13 client state: MBEDTLS_SSL_CERTIFICATE_VERIFY(9)"          \
            -c "tls13 client state: MBEDTLS_SSL_SERVER_FINISHED(13)"            \
            -c "tls13 client state: MBEDTLS_SSL_CLIENT_FINISHED(11)"            \
            -c "tls13 client state: MBEDTLS_SSL_FLUSH_BUFFERS(14)"              \
            -c "tls13 client state: MBEDTLS_SSL_HANDSHAKE_WRAPUP(15)"           \
            -c "<= ssl_tls13_process_server_hello" \
            -c "server hello, chosen ciphersuite: ( 1301 ) - TLS1-3-AES-128-GCM-SHA256" \
            -c "ECDH curve: x25519"         \
            -c "=> ssl_tls13_process_server_hello" \
            -c "<= parse encrypted extensions"      \
            -c "Certificate verification flags clear" \
            -c "=> parse certificate verify"          \
            -c "<= parse certificate verify"          \
            -c "mbedtls_ssl_tls13_process_certificate_verify() returned 0" \
            -c "<= parse finished message" \
            -c "HTTP/1.0 200 ok"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_disabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: minimal feature sets - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS --disable-client-cert" \
            "$P_CLI debug_level=3 min_version=tls13 max_version=tls13" \
            0 \
            -s "SERVER HELLO was queued"    \
            -c "tls13 client state: MBEDTLS_SSL_HELLO_REQUEST(0)"               \
            -c "tls13 client state: MBEDTLS_SSL_SERVER_HELLO(2)"                \
            -c "tls13 client state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS(19)"       \
            -c "tls13 client state: MBEDTLS_SSL_CERTIFICATE_REQUEST(5)"         \
            -c "tls13 client state: MBEDTLS_SSL_SERVER_CERTIFICATE(3)"          \
            -c "tls13 client state: MBEDTLS_SSL_CERTIFICATE_VERIFY(9)"          \
            -c "tls13 client state: MBEDTLS_SSL_SERVER_FINISHED(13)"            \
            -c "tls13 client state: MBEDTLS_SSL_CLIENT_FINISHED(11)"            \
            -c "tls13 client state: MBEDTLS_SSL_FLUSH_BUFFERS(14)"              \
            -c "tls13 client state: MBEDTLS_SSL_HANDSHAKE_WRAPUP(15)"           \
            -c "<= ssl_tls13_process_server_hello" \
            -c "server hello, chosen ciphersuite: ( 1301 ) - TLS1-3-AES-128-GCM-SHA256" \
            -c "ECDH curve: x25519"         \
            -c "=> ssl_tls13_process_server_hello" \
            -c "<= parse encrypted extensions"      \
            -c "Certificate verification flags clear" \
            -c "=> parse certificate verify"          \
            -c "<= parse certificate verify"          \
            -c "mbedtls_ssl_tls13_process_certificate_verify() returned 0" \
            -c "<= parse finished message" \
            -c "HTTP/1.0 200 OK"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
skip_handshake_stage_check
requires_gnutls_tls1_3
run_test    "TLS 1.3: Not supported version check:gnutls: srv max TLS 1.0" \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.0 -d 4" \
            "$P_CLI min_version=tls13 max_version=tls13 debug_level=4" \
            1 \
            -s "Client's version: 3.3" \
            -c "is a fatal alert message (msg 40)" \
            -S "Version: TLS1.0" \
            -C "Protocol is TLSv1.0"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
skip_handshake_stage_check
requires_gnutls_tls1_3
run_test    "TLS 1.3: Not supported version check:gnutls: srv max TLS 1.1" \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.1 -d 4" \
            "$P_CLI min_version=tls13 max_version=tls13 debug_level=4" \
            1 \
            -s "Client's version: 3.3" \
            -c "is a fatal alert message (msg 40)" \
            -S "Version: TLS1.1" \
            -C "Protocol is TLSv1.1"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
skip_handshake_stage_check
requires_gnutls_tls1_3
run_test    "TLS 1.3: Not supported version check:gnutls: srv max TLS 1.2" \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2 -d 4" \
            "$P_CLI min_version=tls13 max_version=tls13 debug_level=4" \
            1 \
            -s "Client's version: 3.3" \
            -c "is a fatal alert message (msg 40)" \
            -S "Version: TLS1.2" \
            -C "Protocol is TLSv1.2"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
skip_handshake_stage_check
requires_openssl_next
run_test    "TLS 1.3: Not supported version check:openssl: srv max TLS 1.0" \
            "$O_NEXT_SRV -msg -tls1" \
            "$P_CLI min_version=tls13 max_version=tls13 debug_level=4" \
            1 \
            -s "fatal protocol_version" \
            -c "is a fatal alert message (msg 70)" \
            -S "Version: TLS1.0" \
            -C "Protocol  : TLSv1.0"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
skip_handshake_stage_check
requires_openssl_next
run_test    "TLS 1.3: Not supported version check:openssl: srv max TLS 1.1" \
            "$O_NEXT_SRV -msg -tls1_1" \
            "$P_CLI min_version=tls13 max_version=tls13 debug_level=4" \
            1 \
            -s "fatal protocol_version" \
            -c "is a fatal alert message (msg 70)" \
            -S "Version: TLS1.1" \
            -C "Protocol  : TLSv1.1"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
skip_handshake_stage_check
requires_openssl_next
run_test    "TLS 1.3: Not supported version check:openssl: srv max TLS 1.2" \
            "$O_NEXT_SRV -msg -tls1_2" \
            "$P_CLI min_version=tls13 max_version=tls13 debug_level=4" \
            1 \
            -s "fatal protocol_version" \
            -c "is a fatal alert message (msg 70)" \
            -S "Version: TLS1.2" \
            -C "Protocol  : TLSv1.2"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_disabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: CertificateRequest check - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10" \
            "$P_CLI debug_level=4 force_version=tls13 " \
            1 \
            -c "CertificateRequest not supported"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_disabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: CertificateRequest check - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS" \
            "$P_CLI debug_level=3 min_version=tls13 max_version=tls13" \
            1 \
            -c "CertificateRequest not supported"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_disabled MBEDTLS_USE_PSA_CRYPTO
requires_openssl_tls1_3
run_test    "TLS 1.3: HelloRetryRequest check, ciphersuite TLS_AES_128_GCM_SHA256 - openssl" \
            "$O_NEXT_SRV -ciphersuites TLS_AES_128_GCM_SHA256  -sigalgs ecdsa_secp256r1_sha256 -groups P-256 -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache" \
            "$P_CLI debug_level=4 force_version=tls13" \
            0 \
            -c "received HelloRetryRequest message" \
            -c "<= ssl_tls13_process_server_hello ( HelloRetryRequest )" \
            -c "tls13 client state: MBEDTLS_SSL_CLIENT_HELLO" \
            -c "HTTP/1.0 200 ok"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_disabled MBEDTLS_USE_PSA_CRYPTO
requires_openssl_tls1_3
run_test    "TLS 1.3: HelloRetryRequest check, ciphersuite TLS_AES_256_GCM_SHA384 - openssl" \
            "$O_NEXT_SRV -ciphersuites TLS_AES_256_GCM_SHA384  -sigalgs ecdsa_secp256r1_sha256 -groups P-256 -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache" \
            "$P_CLI debug_level=4 force_version=tls13" \
            0 \
            -c "received HelloRetryRequest message" \
            -c "<= ssl_tls13_process_server_hello ( HelloRetryRequest )" \
            -c "tls13 client state: MBEDTLS_SSL_CLIENT_HELLO" \
            -c "HTTP/1.0 200 ok"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_disabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: HelloRetryRequest check, ciphersuite TLS_AES_128_GCM_SHA256 - gnutls" \
            "$G_NEXT_SRV -d 4 --priority=NONE:+GROUP-SECP256R1:+AES-128-GCM:+SHA256:+AEAD:+SIGN-ECDSA-SECP256R1-SHA256:+VERS-TLS1.3:%NO_TICKETS --disable-client-cert" \
            "$P_CLI debug_level=4 force_version=tls13" \
            0 \
            -c "received HelloRetryRequest message" \
            -c "<= ssl_tls13_process_server_hello ( HelloRetryRequest )" \
            -c "tls13 client state: MBEDTLS_SSL_CLIENT_HELLO" \
            -c "HTTP/1.0 200 OK"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_disabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: HelloRetryRequest check, ciphersuite TLS_AES_256_GCM_SHA384 - gnutls" \
            "$G_NEXT_SRV -d 4 --priority=NONE:+GROUP-SECP256R1:+AES-256-GCM:+SHA384:+AEAD:+SIGN-ECDSA-SECP256R1-SHA256:+VERS-TLS1.3:%NO_TICKETS --disable-client-cert" \
            "$P_CLI debug_level=4 force_version=tls13" \
            0 \
            -c "received HelloRetryRequest message" \
            -c "<= ssl_tls13_process_server_hello ( HelloRetryRequest )" \
            -c "tls13 client state: MBEDTLS_SSL_CLIENT_HELLO" \
            -c "HTTP/1.0 200 OK"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_disabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_disabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3 m->O both peers do not support middlebox compatibility" \
            "$O_NEXT_SRV -msg -tls1_3 -no_middlebox -num_tickets 0 -no_resume_ephemeral -no_cache" \
            "$P_CLI debug_level=3 min_version=tls13 max_version=tls13" \
            0 \
            -c "HTTP/1.0 200 ok"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_disabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_disabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3 m->O server with middlebox compat support, not client" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache" \
            "$P_CLI debug_level=3 min_version=tls13 max_version=tls13" \
            1 \
            -c "ChangeCipherSpec invalid in TLS 1.3 without compatibility mode"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_gnutls_next_disable_tls13_compat
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_disabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_disabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3 m->G both peers do not support middlebox compatibility" \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS:%DISABLE_TLS13_COMPAT_MODE --disable-client-cert" \
            "$P_CLI debug_level=3 min_version=tls13 max_version=tls13" \
            0 \
            -c "HTTP/1.0 200 OK"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_disabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_disabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3 m->G server with middlebox compat support, not client" \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS --disable-client-cert" \
            "$P_CLI debug_level=3 min_version=tls13 max_version=tls13" \
            1 \
            -c "ChangeCipherSpec invalid in TLS 1.3 without compatibility mode"
