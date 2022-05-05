#!/bin/sh

# 30-tls13-generic.sh
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
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test    "TLS 1.3: key exchange mode parameter passing: PSK only" \
            "$P_SRV tls13_kex_modes=psk debug_level=4" \
            "$P_CLI tls13_kex_modes=psk debug_level=4" \
            0
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test    "TLS 1.3: key exchange mode parameter passing: PSK-ephemeral only" \
            "$P_SRV tls13_kex_modes=psk_ephemeral" \
            "$P_CLI tls13_kex_modes=psk_ephemeral" \
            0
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test    "TLS 1.3: key exchange mode parameter passing: Pure-ephemeral only" \
            "$P_SRV tls13_kex_modes=ephemeral" \
            "$P_CLI tls13_kex_modes=ephemeral" \
            0
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test    "TLS 1.3: key exchange mode parameter passing: All ephemeral" \
            "$P_SRV tls13_kex_modes=ephemeral_all" \
            "$P_CLI tls13_kex_modes=ephemeral_all" \
            0
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test    "TLS 1.3: key exchange mode parameter passing: All PSK" \
            "$P_SRV tls13_kex_modes=psk_all" \
            "$P_CLI tls13_kex_modes=psk_all" \
            0
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test    "TLS 1.3: key exchange mode parameter passing: All" \
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
requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3: minimal feature sets - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache" \
            "$P_CLI debug_level=3" \
            0 \
            -c "client state: MBEDTLS_SSL_HELLO_REQUEST" \
            -c "client state: MBEDTLS_SSL_SERVER_HELLO" \
            -c "client state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
            -c "client state: MBEDTLS_SSL_CERTIFICATE_REQUEST" \
            -c "client state: MBEDTLS_SSL_SERVER_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CERTIFICATE_VERIFY" \
            -c "client state: MBEDTLS_SSL_SERVER_FINISHED" \
            -c "client state: MBEDTLS_SSL_CLIENT_FINISHED" \
            -c "client state: MBEDTLS_SSL_FLUSH_BUFFERS" \
            -c "client state: MBEDTLS_SSL_HANDSHAKE_WRAPUP" \
            -c "<= ssl_tls13_process_server_hello" \
            -c "server hello, chosen ciphersuite: ( 1301 ) - TLS1-3-AES-128-GCM-SHA256" \
            -c "ECDH curve: x25519" \
            -c "=> ssl_tls13_process_server_hello" \
            -c "<= parse encrypted extensions" \
            -c "Certificate verification flags clear" \
            -c "=> parse certificate verify" \
            -c "<= parse certificate verify" \
            -c "mbedtls_ssl_tls13_process_certificate_verify() returned 0" \
            -c "<= parse finished message" \
            -c "Protocol is TLSv1.3" \
            -c "HTTP/1.0 200 ok"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3: minimal feature sets - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS --disable-client-cert" \
            "$P_CLI debug_level=3" \
            0 \
            -s "SERVER HELLO was queued" \
            -c "client state: MBEDTLS_SSL_HELLO_REQUEST" \
            -c "client state: MBEDTLS_SSL_SERVER_HELLO" \
            -c "client state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
            -c "client state: MBEDTLS_SSL_CERTIFICATE_REQUEST" \
            -c "client state: MBEDTLS_SSL_SERVER_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CERTIFICATE_VERIFY" \
            -c "client state: MBEDTLS_SSL_SERVER_FINISHED" \
            -c "client state: MBEDTLS_SSL_CLIENT_FINISHED" \
            -c "client state: MBEDTLS_SSL_FLUSH_BUFFERS" \
            -c "client state: MBEDTLS_SSL_HANDSHAKE_WRAPUP" \
            -c "<= ssl_tls13_process_server_hello" \
            -c "server hello, chosen ciphersuite: ( 1301 ) - TLS1-3-AES-128-GCM-SHA256" \
            -c "ECDH curve: x25519" \
            -c "=> ssl_tls13_process_server_hello" \
            -c "<= parse encrypted extensions" \
            -c "Certificate verification flags clear" \
            -c "=> parse certificate verify" \
            -c "<= parse certificate verify" \
            -c "mbedtls_ssl_tls13_process_certificate_verify() returned 0" \
            -c "<= parse finished message" \
            -c "Protocol is TLSv1.3" \
            -c "HTTP/1.0 200 OK"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_ALPN
run_test    "TLS 1.3: alpn - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -alpn h2" \
            "$P_CLI debug_level=3 alpn=h2" \
            0 \
            -c "client state: MBEDTLS_SSL_HELLO_REQUEST" \
            -c "client state: MBEDTLS_SSL_SERVER_HELLO" \
            -c "client state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
            -c "client state: MBEDTLS_SSL_CERTIFICATE_REQUEST" \
            -c "client state: MBEDTLS_SSL_SERVER_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CERTIFICATE_VERIFY" \
            -c "client state: MBEDTLS_SSL_SERVER_FINISHED" \
            -c "client state: MBEDTLS_SSL_CLIENT_FINISHED" \
            -c "client state: MBEDTLS_SSL_FLUSH_BUFFERS" \
            -c "client state: MBEDTLS_SSL_HANDSHAKE_WRAPUP" \
            -c "<= ssl_tls13_process_server_hello" \
            -c "server hello, chosen ciphersuite: ( 1301 ) - TLS1-3-AES-128-GCM-SHA256" \
            -c "ECDH curve: x25519" \
            -c "=> ssl_tls13_process_server_hello" \
            -c "<= parse encrypted extensions" \
            -c "Certificate verification flags clear" \
            -c "=> parse certificate verify" \
            -c "<= parse certificate verify" \
            -c "mbedtls_ssl_tls13_process_certificate_verify() returned 0" \
            -c "<= parse finished message" \
            -c "Protocol is TLSv1.3" \
            -c "HTTP/1.0 200 ok" \
            -c "Application Layer Protocol is h2"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_ALPN
run_test    "TLS 1.3: alpn - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS --disable-client-cert --alpn=h2" \
            "$P_CLI debug_level=3 alpn=h2" \
            0 \
            -s "SERVER HELLO was queued" \
            -c "client state: MBEDTLS_SSL_HELLO_REQUEST" \
            -c "client state: MBEDTLS_SSL_SERVER_HELLO" \
            -c "client state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
            -c "client state: MBEDTLS_SSL_CERTIFICATE_REQUEST" \
            -c "client state: MBEDTLS_SSL_SERVER_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CERTIFICATE_VERIFY" \
            -c "client state: MBEDTLS_SSL_SERVER_FINISHED" \
            -c "client state: MBEDTLS_SSL_CLIENT_FINISHED" \
            -c "client state: MBEDTLS_SSL_FLUSH_BUFFERS" \
            -c "client state: MBEDTLS_SSL_HANDSHAKE_WRAPUP" \
            -c "<= ssl_tls13_process_server_hello" \
            -c "server hello, chosen ciphersuite: ( 1301 ) - TLS1-3-AES-128-GCM-SHA256" \
            -c "ECDH curve: x25519" \
            -c "=> ssl_tls13_process_server_hello" \
            -c "<= parse encrypted extensions" \
            -c "Certificate verification flags clear" \
            -c "=> parse certificate verify" \
            -c "<= parse certificate verify" \
            -c "mbedtls_ssl_tls13_process_certificate_verify() returned 0" \
            -c "<= parse finished message" \
            -c "Protocol is TLSv1.3" \
            -c "HTTP/1.0 200 OK" \
            -c "Application Layer Protocol is h2"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
skip_handshake_stage_check
requires_gnutls_tls1_3
run_test    "TLS 1.3: Not supported version check:gnutls: srv max TLS 1.0" \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.0 -d 4" \
            "$P_CLI debug_level=4" \
            1 \
            -s "Client's version: 3.3" \
            -S "Version: TLS1.0" \
            -C "Protocol is TLSv1.0"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
skip_handshake_stage_check
requires_gnutls_tls1_3
run_test    "TLS 1.3: Not supported version check:gnutls: srv max TLS 1.1" \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.1 -d 4" \
            "$P_CLI debug_level=4" \
            1 \
            -s "Client's version: 3.3" \
            -S "Version: TLS1.1" \
            -C "Protocol is TLSv1.1"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
skip_handshake_stage_check
requires_gnutls_tls1_3
run_test    "TLS 1.3: Not supported version check:gnutls: srv max TLS 1.2" \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2 -d 4" \
            "$P_CLI force_version=tls13 debug_level=4" \
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
            "$P_CLI debug_level=4" \
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
            "$P_CLI debug_level=4" \
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
            "$P_CLI force_version=tls13 debug_level=4" \
            1 \
            -s "fatal protocol_version" \
            -c "is a fatal alert message (msg 70)" \
            -S "Version: TLS1.2" \
            -C "Protocol  : TLSv1.2"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, no client certificate - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -verify 10" \
            "$P_CLI debug_level=4 crt_file=none key_file=none" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -s "TLS 1.3" \
            -c "HTTP/1.0 200 ok" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, no client certificate - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS --verify-client-cert" \
            "$P_CLI debug_level=3 crt_file=none key_file=none" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE"\
            -s "Version: TLS1.3" \
            -c "HTTP/1.0 200 OK" \
            -c "Protocol is TLSv1.3"


requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3: Client authentication, no server middlebox compat - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10 -no_middlebox" \
            "$P_CLI debug_level=4 crt_file=data_files/cli2.crt key_file=data_files/cli2.key" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3: Client authentication, no server middlebox compat - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS:%DISABLE_TLS13_COMPAT_MODE" \
            "$P_CLI debug_level=3 crt_file=data_files/cli2.crt \
                    key_file=data_files/cli2.key" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, ecdsa_secp256r1_sha256 - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10" \
            "$P_CLI debug_level=4 crt_file=data_files/ecdsa_secp256r1.crt \
                    key_file=data_files/ecdsa_secp256r1.key" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, ecdsa_secp256r1_sha256 - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS" \
            "$P_CLI debug_level=3 crt_file=data_files/ecdsa_secp256r1.crt \
                    key_file=data_files/ecdsa_secp256r1.key" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, ecdsa_secp384r1_sha384 - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10" \
            "$P_CLI debug_level=4 crt_file=data_files/ecdsa_secp384r1.crt \
                    key_file=data_files/ecdsa_secp384r1.key" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, ecdsa_secp384r1_sha384 - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS" \
            "$P_CLI debug_level=3 crt_file=data_files/ecdsa_secp384r1.crt \
                    key_file=data_files/ecdsa_secp384r1.key" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, ecdsa_secp521r1_sha512 - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10" \
            "$P_CLI debug_level=4 crt_file=data_files/ecdsa_secp521r1.crt \
                    key_file=data_files/ecdsa_secp521r1.key" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, ecdsa_secp521r1_sha512 - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS" \
            "$P_CLI debug_level=3 crt_file=data_files/ecdsa_secp521r1.crt \
                    key_file=data_files/ecdsa_secp521r1.key" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, rsa_pss_rsae_sha256 - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10" \
            "$P_CLI debug_level=4 crt_file=data_files/cert_sha256.crt \
                    key_file=data_files/server1.key sig_algs=ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, rsa_pss_rsae_sha256 - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS" \
            "$P_CLI debug_level=3 crt_file=data_files/server2-sha256.crt \
                    key_file=data_files/server2.key sig_algs=ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, rsa_pss_rsae_sha384 - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10" \
            "$P_CLI debug_level=4 force_version=tls13 crt_file=data_files/cert_sha256.crt \
                    key_file=data_files/server1.key sig_algs=ecdsa_secp256r1_sha256,rsa_pss_rsae_sha384" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, rsa_pss_rsae_sha384 - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS" \
            "$P_CLI debug_level=3 force_version=tls13 crt_file=data_files/server2-sha256.crt \
                    key_file=data_files/server2.key sig_algs=ecdsa_secp256r1_sha256,rsa_pss_rsae_sha384" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, rsa_pss_rsae_sha512 - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10" \
            "$P_CLI debug_level=4 force_version=tls13 crt_file=data_files/cert_sha256.crt \
                    key_file=data_files/server1.key sig_algs=ecdsa_secp256r1_sha256,rsa_pss_rsae_sha512" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, rsa_pss_rsae_sha512 - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS" \
            "$P_CLI debug_level=3 force_version=tls13 crt_file=data_files/server2-sha256.crt \
                    key_file=data_files/server2.key sig_algs=ecdsa_secp256r1_sha256,rsa_pss_rsae_sha512" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, client alg not in server list - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10
                -sigalgs ecdsa_secp256r1_sha256" \
            "$P_CLI debug_level=3 crt_file=data_files/ecdsa_secp521r1.crt \
                    key_file=data_files/ecdsa_secp521r1.key sig_algs=ecdsa_secp256r1_sha256,ecdsa_secp521r1_sha512" \
            1 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "signature algorithm not in received or offered list." \
            -C "unknown pk type"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
run_test    "TLS 1.3: Client authentication, client alg not in server list - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:-SIGN-ALL:+SIGN-ECDSA-SECP256R1-SHA256:%NO_TICKETS" \
            "$P_CLI debug_level=3 crt_file=data_files/ecdsa_secp521r1.crt \
                    key_file=data_files/ecdsa_secp521r1.key sig_algs=ecdsa_secp256r1_sha256,ecdsa_secp521r1_sha512" \
            1 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "signature algorithm not in received or offered list." \
            -C "unknown pk type"

# Test using an opaque private key for client authentication
requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, no server middlebox compat - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10 -no_middlebox" \
            "$P_CLI debug_level=4 crt_file=data_files/cli2.crt key_file=data_files/cli2.key key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, no server middlebox compat - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS:%DISABLE_TLS13_COMPAT_MODE" \
            "$P_CLI debug_level=3 crt_file=data_files/cli2.crt \
                    key_file=data_files/cli2.key key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, ecdsa_secp256r1_sha256 - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10" \
            "$P_CLI debug_level=4 crt_file=data_files/ecdsa_secp256r1.crt \
                    key_file=data_files/ecdsa_secp256r1.key key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, ecdsa_secp256r1_sha256 - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS" \
            "$P_CLI debug_level=3 crt_file=data_files/ecdsa_secp256r1.crt \
                    key_file=data_files/ecdsa_secp256r1.key key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, ecdsa_secp384r1_sha384 - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10" \
            "$P_CLI debug_level=4 crt_file=data_files/ecdsa_secp384r1.crt \
                    key_file=data_files/ecdsa_secp384r1.key key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, ecdsa_secp384r1_sha384 - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS" \
            "$P_CLI debug_level=3 crt_file=data_files/ecdsa_secp384r1.crt \
                    key_file=data_files/ecdsa_secp384r1.key key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, ecdsa_secp521r1_sha512 - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10" \
            "$P_CLI debug_level=4 crt_file=data_files/ecdsa_secp521r1.crt \
                    key_file=data_files/ecdsa_secp521r1.key key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, ecdsa_secp521r1_sha512 - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS" \
            "$P_CLI debug_level=3 crt_file=data_files/ecdsa_secp521r1.crt \
                    key_file=data_files/ecdsa_secp521r1.key key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, rsa_pss_rsae_sha256 - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10" \
            "$P_CLI debug_level=4 crt_file=data_files/cert_sha256.crt \
                    key_file=data_files/server1.key sig_algs=ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256 key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, rsa_pss_rsae_sha256 - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS" \
            "$P_CLI debug_level=3 crt_file=data_files/server2-sha256.crt \
                    key_file=data_files/server2.key sig_algs=ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256 key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, rsa_pss_rsae_sha384 - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10" \
            "$P_CLI debug_level=4 force_version=tls13 crt_file=data_files/cert_sha256.crt \
                    key_file=data_files/server1.key sig_algs=ecdsa_secp256r1_sha256,rsa_pss_rsae_sha384 key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, rsa_pss_rsae_sha384 - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS" \
            "$P_CLI debug_level=3 force_version=tls13 crt_file=data_files/server2-sha256.crt \
                    key_file=data_files/server2.key sig_algs=ecdsa_secp256r1_sha256,rsa_pss_rsae_sha384 key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, rsa_pss_rsae_sha512 - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10" \
            "$P_CLI debug_level=4 force_version=tls13 crt_file=data_files/cert_sha256.crt \
                    key_file=data_files/server1.key sig_algs=ecdsa_secp256r1_sha256,rsa_pss_rsae_sha512 key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, rsa_pss_rsae_sha512 - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS" \
            "$P_CLI debug_level=3 force_version=tls13 crt_file=data_files/server2-sha256.crt \
                    key_file=data_files/server2.key sig_algs=ecdsa_secp256r1_sha256,rsa_pss_rsae_sha512 key_opaque=1" \
            0 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "Protocol is TLSv1.3"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, client alg not in server list - openssl" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache -Verify 10
                -sigalgs ecdsa_secp256r1_sha256" \
            "$P_CLI debug_level=3 crt_file=data_files/ecdsa_secp521r1.crt \
                    key_file=data_files/ecdsa_secp521r1.key sig_algs=ecdsa_secp256r1_sha256,ecdsa_secp521r1_sha512 key_opaque=1" \
            1 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "signature algorithm not in received or offered list." \
            -C "unkown pk type"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_RSA_C
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
run_test    "TLS 1.3: Client authentication - opaque key, client alg not in server list - gnutls" \
            "$G_NEXT_SRV --debug=4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:-SIGN-ALL:+SIGN-ECDSA-SECP256R1-SHA256:%NO_TICKETS" \
            "$P_CLI debug_level=3 crt_file=data_files/ecdsa_secp521r1.crt \
                    key_file=data_files/ecdsa_secp521r1.key sig_algs=ecdsa_secp256r1_sha256,ecdsa_secp521r1_sha512 key_opaque=1" \
            1 \
            -c "got a certificate request" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE" \
            -c "client state: MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY" \
            -c "signature algorithm not in received or offered list." \
            -C "unkown pk type"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_openssl_tls1_3
run_test    "TLS 1.3: HRR check, ciphersuite TLS_AES_128_GCM_SHA256 - openssl" \
            "$O_NEXT_SRV -ciphersuites TLS_AES_128_GCM_SHA256  -sigalgs ecdsa_secp256r1_sha256 -groups P-256 -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache" \
            "$P_CLI debug_level=4" \
            0 \
            -c "received HelloRetryRequest message" \
            -c "<= ssl_tls13_process_server_hello ( HelloRetryRequest )" \
            -c "client state: MBEDTLS_SSL_CLIENT_HELLO" \
            -c "Protocol is TLSv1.3" \
            -c "HTTP/1.0 200 ok"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_openssl_tls1_3
run_test    "TLS 1.3: HRR check, ciphersuite TLS_AES_256_GCM_SHA384 - openssl" \
            "$O_NEXT_SRV -ciphersuites TLS_AES_256_GCM_SHA384  -sigalgs ecdsa_secp256r1_sha256 -groups P-256 -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache" \
            "$P_CLI debug_level=4" \
            0 \
            -c "received HelloRetryRequest message" \
            -c "<= ssl_tls13_process_server_hello ( HelloRetryRequest )" \
            -c "client state: MBEDTLS_SSL_CLIENT_HELLO" \
            -c "Protocol is TLSv1.3" \
            -c "HTTP/1.0 200 ok"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3: HRR check, ciphersuite TLS_AES_128_GCM_SHA256 - gnutls" \
            "$G_NEXT_SRV -d 4 --priority=NONE:+GROUP-SECP256R1:+AES-128-GCM:+SHA256:+AEAD:+SIGN-ECDSA-SECP256R1-SHA256:+VERS-TLS1.3:%NO_TICKETS --disable-client-cert" \
            "$P_CLI debug_level=4" \
            0 \
            -c "received HelloRetryRequest message" \
            -c "<= ssl_tls13_process_server_hello ( HelloRetryRequest )" \
            -c "client state: MBEDTLS_SSL_CLIENT_HELLO" \
            -c "Protocol is TLSv1.3" \
            -c "HTTP/1.0 200 OK"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3: HRR check, ciphersuite TLS_AES_256_GCM_SHA384 - gnutls" \
            "$G_NEXT_SRV -d 4 --priority=NONE:+GROUP-SECP256R1:+AES-256-GCM:+SHA384:+AEAD:+SIGN-ECDSA-SECP256R1-SHA256:+VERS-TLS1.3:%NO_TICKETS --disable-client-cert" \
            "$P_CLI debug_level=4" \
            0 \
            -c "received HelloRetryRequest message" \
            -c "<= ssl_tls13_process_server_hello ( HelloRetryRequest )" \
            -c "client state: MBEDTLS_SSL_CLIENT_HELLO" \
            -c "Protocol is TLSv1.3" \
            -c "HTTP/1.0 200 OK"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_SRV_C
run_test    "TLS 1.3: Server side check - openssl" \
            "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=0" \
            "$O_NEXT_CLI -msg -debug -tls1_3 -no_middlebox" \
            0 \
            -s "tls13 server state: MBEDTLS_SSL_CLIENT_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_CERTIFICATE" \
            -s "tls13 server state: MBEDTLS_SSL_CERTIFICATE_VERIFY" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_FINISHED" \
            -s "tls13 server state: MBEDTLS_SSL_CLIENT_FINISHED" \
            -s "tls13 server state: MBEDTLS_SSL_HANDSHAKE_WRAPUP"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_openssl_tls1_3
run_test    "TLS 1.3: Server side check - openssl with client authentication" \
            "$P_SRV debug_level=4 auth_mode=required crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=0" \
            "$O_NEXT_CLI -msg -debug -cert data_files/server5.crt -key data_files/server5.key -tls1_3 -no_middlebox" \
            0 \
            -s "tls13 server state: MBEDTLS_SSL_CLIENT_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
            -s "tls13 server state: MBEDTLS_SSL_CERTIFICATE_REQUEST" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_CERTIFICATE" \
            -s "tls13 server state: MBEDTLS_SSL_CERTIFICATE_VERIFY" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_FINISHED" \
            -s "=> write certificate request" \
            -s "=> parse client hello" \
            -s "<= parse client hello"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_SRV_C
run_test    "TLS 1.3: Server side check - gnutls" \
            "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=0" \
            "$G_NEXT_CLI localhost -d 4 --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:%NO_TICKETS:%DISABLE_TLS13_COMPAT_MODE -V" \
            0 \
            -s "tls13 server state: MBEDTLS_SSL_CLIENT_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_CERTIFICATE" \
            -s "tls13 server state: MBEDTLS_SSL_CERTIFICATE_VERIFY" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_FINISHED" \
            -s "tls13 server state: MBEDTLS_SSL_CLIENT_FINISHED" \
            -s "tls13 server state: MBEDTLS_SSL_HANDSHAKE_WRAPUP" \
            -c "HTTP/1.0 200 OK"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_SRV_C
run_test    "TLS 1.3: Server side check - gnutls with client authentication" \
            "$P_SRV debug_level=4 auth_mode=required crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=0" \
            "$G_NEXT_CLI localhost -d 4 --x509certfile data_files/server5.crt --x509keyfile data_files/server5.key --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:%NO_TICKETS:%DISABLE_TLS13_COMPAT_MODE -V" \
            0 \
            -s "tls13 server state: MBEDTLS_SSL_CLIENT_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
            -s "tls13 server state: MBEDTLS_SSL_CERTIFICATE_REQUEST" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_CERTIFICATE" \
            -s "tls13 server state: MBEDTLS_SSL_CERTIFICATE_VERIFY" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_FINISHED" \
            -s "=> write certificate request" \
            -s "=> parse client hello" \
            -s "<= parse client hello"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3: Server side check - mbedtls" \
            "$P_SRV debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=0" \
            "$P_CLI debug_level=4 force_version=tls13" \
            0 \
            -s "tls13 server state: MBEDTLS_SSL_CLIENT_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
            -s "tls13 server state: MBEDTLS_SSL_CERTIFICATE_REQUEST" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_CERTIFICATE" \
            -s "tls13 server state: MBEDTLS_SSL_CERTIFICATE_VERIFY" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_FINISHED" \
            -s "tls13 server state: MBEDTLS_SSL_CLIENT_FINISHED" \
            -s "tls13 server state: MBEDTLS_SSL_HANDSHAKE_WRAPUP" \
            -c "HTTP/1.0 200 OK"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3: Server side check - mbedtls with client authentication" \
            "$P_SRV debug_level=4 auth_mode=required crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=0" \
            "$P_CLI debug_level=4 crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13" \
            0 \
            -s "tls13 server state: MBEDTLS_SSL_CLIENT_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_CERTIFICATE" \
            -s "=> write certificate request" \
            -c "client state: MBEDTLS_SSL_CERTIFICATE_REQUEST" \
            -s "=> parse client hello" \
            -s "<= parse client hello"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3: Server side check - mbedtls with client empty certificate" \
            "$P_SRV debug_level=4 auth_mode=required crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=0" \
            "$P_CLI debug_level=4 crt_file=none key_file=none force_version=tls13" \
            1 \
            -s "tls13 server state: MBEDTLS_SSL_CLIENT_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_CERTIFICATE" \
            -s "=> write certificate request" \
            -s "SSL - No client certification received from the client, but required by the authentication mode" \
            -c "client state: MBEDTLS_SSL_CERTIFICATE_REQUEST" \
            -s "=> parse client hello" \
            -s "<= parse client hello"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3: Server side check - mbedtls with optional client authentication" \
            "$P_SRV debug_level=4 auth_mode=optional crt_file=data_files/server5.crt key_file=data_files/server5.key force_version=tls13 tickets=0" \
            "$P_CLI debug_level=4 force_version=tls13 crt_file=none key_file=none" \
            0 \
            -s "tls13 server state: MBEDTLS_SSL_CLIENT_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_HELLO" \
            -s "tls13 server state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_CERTIFICATE" \
            -s "=> write certificate request" \
            -c "client state: MBEDTLS_SSL_CERTIFICATE_REQUEST" \
            -s "=> parse client hello" \
            -s "<= parse client hello"

requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test "TLS 1.3: server: HRR check - mbedtls" \
         "$P_SRV debug_level=4 force_version=tls13 curves=secp384r1" \
         "$P_CLI debug_level=4 force_version=tls13 curves=secp256r1,secp384r1" \
         0 \
        -s "tls13 server state: MBEDTLS_SSL_CLIENT_HELLO" \
        -s "tls13 server state: MBEDTLS_SSL_SERVER_HELLO" \
        -s "tls13 server state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
        -s "tls13 server state: MBEDTLS_SSL_HELLO_RETRY_REQUEST" \
        -c "client state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
        -s "selected_group: secp384r1" \
        -s "=> write hello retry request" \
        -s "<= write hello retry request"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3: Server side check, no server certificate available" \
            "$P_SRV debug_level=4 crt_file=none key_file=none force_version=tls13" \
            "$P_CLI debug_level=4 force_version=tls13" \
            1 \
            -s "tls13 server state: MBEDTLS_SSL_SERVER_CERTIFICATE" \
            -s "No certificate available."

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_disabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3 m->O both peers do not support middlebox compatibility" \
            "$O_NEXT_SRV -msg -tls1_3 -no_middlebox -num_tickets 0 -no_resume_ephemeral -no_cache" \
            "$P_CLI debug_level=3" \
            0 \
            -c "Protocol is TLSv1.3" \
            -c "HTTP/1.0 200 ok"

requires_openssl_tls1_3
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_disabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3 m->O server with middlebox compat support, not client" \
            "$O_NEXT_SRV -msg -tls1_3 -num_tickets 0 -no_resume_ephemeral -no_cache" \
            "$P_CLI debug_level=3" \
            1 \
            -c "ChangeCipherSpec invalid in TLS 1.3 without compatibility mode"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_gnutls_next_disable_tls13_compat
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_disabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3 m->G both peers do not support middlebox compatibility" \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS:%DISABLE_TLS13_COMPAT_MODE --disable-client-cert" \
            "$P_CLI debug_level=3" \
            0 \
            -c "Protocol is TLSv1.3" \
            -c "HTTP/1.0 200 OK"

requires_gnutls_tls1_3
requires_gnutls_next_no_ticket
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_config_disabled MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
run_test    "TLS 1.3 m->G server with middlebox compat support, not client" \
            "$G_NEXT_SRV --priority=NORMAL:-VERS-ALL:+VERS-TLS1.3:+CIPHER-ALL:%NO_TICKETS --disable-client-cert" \
            "$P_CLI debug_level=3" \
            1 \
            -c "ChangeCipherSpec invalid in TLS 1.3 without compatibility mode"
