#!/bin/sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

program="${0%/*}"/ssl_client1
protocol='TLS 1.2'

. "${0%/*}/tls_client_demo_common.sh"

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

cleanup
