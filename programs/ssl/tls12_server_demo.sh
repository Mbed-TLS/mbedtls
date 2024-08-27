#!/bin/sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

program="${0%/*}"/ssl_server
protocol='TLS 1.2'

. "${0%/*}/tls_server_demo_common.sh"

depends_on MBEDTLS_SSL_PROTO_TLS1_2
if ! { config_has MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED ||
       config_has MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED ||
       config_has MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED ||
       config_has MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED ||
       config_has MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED ||
       config_has MBEDTLS_KEY_EXCHANGE_RSA_ENABLED; }; then
    depends_on 'MBEDTLS_KEY_EXCHANGE_<any-non-PSK>_ENABLED'
fi

run_one_connection -tls1_2

if config_has MBEDTLS_THREADING_PTHREAD; then
    program="${0%/*}"/ssl_pthread_server
    run_one_connection -tls1_2
fi

if config_has MBEDTLS_SSL_PROTO_DTLS; then
    program="${0%/*}"/dtls_server
    protocol='DTLS 1.2'
    run_one_connection -dtls1_2
fi

cleanup
