## Common parts for an interoperability demo between an Mbed TLS server
## and an OpenSSL client.

# Required named parameters:
# * $protocol: human-readable protocol version.
# * $program: server program to run.

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

. "${0%/*}/../demo_common.sh"

msg <<'EOF'
This script demonstrates the interoperability between a very simple
$protocol server using Mbed TLS and an OpenSSL client.

EOF

if ! openssl version >/dev/null; then
    echo >&2 "This demo script requires the 'openssl' command line program."
    exit 100
fi

depends_on MBEDTLS_SSL_TLS_C MBEDTLS_SSL_SRV_C

client_log="openssl-s_client-$$.log"
files_to_clean="$client_log"

run_one_connection () {
    echo
    echo "#### Local connection: $protocol ####"

    # Start the server in the background
    printf '+ %s &\n' "$program"
    "$program" &
    server_pid=$!

    # Give the server a reasonable amount of time to start
    sleep 1
    set openssl s_client -connect localhost:4433 "$@"
    printf '\n+ %s\n' "$*"
    echo "This is some content." | "$@" >"$client_log" 2>&1
    echo

    ret=0
    kill "$server_pid" || wait "$server_pid" || ret=$?
    if [ "$ret" -ne 0 ]; then
        echo "FAIL: $* returned $ret"
        echo "BEGIN client output"
        cat "$client_log"
        echo "END client output"
        rm "$client_log"
    fi
    return "$ret"
}
