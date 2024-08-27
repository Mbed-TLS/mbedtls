#!/bin/sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

program="${0%/*}"/ssl_client1
protocol='TLS 1.3'

. "${0%/*}/tls_client_demo_common.sh"

depends_on MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED

run_one_connection -tls1_3

cleanup
