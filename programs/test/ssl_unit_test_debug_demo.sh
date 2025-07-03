#!/bin/sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

. "${0%/*}/../../framework/scripts/demo_common.sh"

msg <<'EOF'
This script tests that SSL debugging logs are working in unit tests.
EOF

# Expected dependencies
depends_on MBEDTLS_DEBUG_C MBEDTLS_SSL_CLI_C MBEDTLS_SSL_SRV_C MBEDTLS_SSL_PROTO_TLS1_2
# Dependencies due to test helper limitations (could be partly relaxed with
# some work)
depends_on PSA_WANT_ALG_ECDSA PSA_WANT_ALG_ECDH PSA_WANT_ECC_SECP_R1_256
depends_on PSA_WANT_ALG_SHA_256 PSA_WANT_ALG_CHACHA20_POLY1305

program="${0%/*}"/ssl_unit_test_debug
tmp_out="$program.out"
files_to_clean="$tmp_out"

go () {
    "$program" "$@" >"$tmp_out"
}

check_log () {
    run "Check for a level $1 $2 log" \
        grep -q -E "^$2: [^ ]+: \\|$1\\| " "$tmp_out"
}

check_no_log () {
    run "Check the absence of a level $1 log" \
        grep -L ": \\|$1\\| " "$tmp_out"
}

run "Run with the default settings" go -1
run "Check that stdout is empty" test ! -s "$tmp_out"

run "Run with threshold=0" go 0
run "Check that stdout is empty" test ! -s "$tmp_out"

run "Run with threshold=1" go 1
check_log 1 Client
check_log 1 Server
check_no_log 2

run "Run with threshold=4" go 4
check_log 1 Client
check_log 4 Client
check_log 1 Server
check_log 4 Server

cleanup
