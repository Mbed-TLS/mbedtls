#!/bin/sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

program="${0%/*}"/ssl_server
protocol='TLS 1.3'

. "${0%/*}/tls_server_demo_common.sh"

depends_on MBEDTLS_SSL_PROTO_TLS1_3 MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED

run_one_connection -tls1_3

if config_has MBEDTLS_THREADING_PTHREAD; then
    program="${0%/*}"/ssl_pthread_server
    run_one_connection -tls1_3
fi

cleanup
