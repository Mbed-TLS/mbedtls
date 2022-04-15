#!/bin/sh

# tls13-generic.sh
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

requires_config_enabled MBEDTLS_DEBUG_C
requires_config_enabled MBEDTLS_SSL_CLI_C
requires_config_enabled MBEDTLS_SSL_SRV_C
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
run_test "TLS 1.3 m->M: HRR secp256r1 -> secp384r1" \
         "$P_SRV debug_level=4 force_version=tls13 curves=secp384r1" \
         "$P_CLI debug_level=4 force_version=tls13 curves=secp256r1,secp384r1" \
         1 \
        -s "tls13 server state: MBEDTLS_SSL_CLIENT_HELLO" \
        -s "tls13 server state: MBEDTLS_SSL_SERVER_HELLO" \
        -s "tls13 server state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
        -s "tls13 server state: MBEDTLS_SSL_HELLO_RETRY_REQUEST" \
        -c "client state: MBEDTLS_SSL_ENCRYPTED_EXTENSIONS" \
        -s "selected_group: secp384r1" \
        -s "SSL - The requested feature is not available" \
        -s "=> write hello retry request" \
        -s "<= write hello retry request"
