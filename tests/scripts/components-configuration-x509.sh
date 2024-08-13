# components-configuration-x509.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Configuration Testing - X509
################################################################

component_test_no_x509_info () {
    msg "build: full + MBEDTLS_X509_REMOVE_INFO" # ~ 10s
    scripts/config.pl full
    scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # too slow for tests
    scripts/config.pl set MBEDTLS_X509_REMOVE_INFO
    make CFLAGS='-Werror -O2'

    msg "test: full + MBEDTLS_X509_REMOVE_INFO" # ~ 10s
    make test

    msg "test: ssl-opt.sh, full + MBEDTLS_X509_REMOVE_INFO" # ~ 1 min
    tests/ssl-opt.sh
}

component_test_sw_inet_pton () {
    msg "build: default plus MBEDTLS_TEST_SW_INET_PTON"

    # MBEDTLS_TEST_HOOKS required for x509_crt_parse_cn_inet_pton
    scripts/config.py set MBEDTLS_TEST_HOOKS
    make CFLAGS="-DMBEDTLS_TEST_SW_INET_PTON"

    msg "test: default plus MBEDTLS_TEST_SW_INET_PTON"
    make test
}
