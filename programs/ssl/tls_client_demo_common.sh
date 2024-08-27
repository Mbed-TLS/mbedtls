## Common parts for an interoperability demo between an Mbed TLS client
## and an OpenSSL server.

# Required named parameters:
# * $protocol: human-readable protocol version.
# * $program: client program to run.

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

. "${0%/*}/../demo_common.sh"

msg <<'EOF'
This script demonstrates the interoperability between a very simple
$protocol client using Mbed TLS and an OpenSSL server.

EOF

if ! openssl version >/dev/null; then
    echo >&2 "This demo script requires the 'openssl' command line program."
    exit 100
fi

depends_on MBEDTLS_SSL_TLS_C MBEDTLS_SSL_CLI_C

server_log="openssl-s_server-$$.log"
files_to_clean="$server_log"

unique_string="Response in demo $$."

response () {
    # Sleep until the client is likely to be connected.
    sleep 2
    printf '%s\r\n' \
           'HTTP/1.0 200 OK' \
           'Content-Type: text/plain' \
           '' \
           "$unique_string"
}

run_one_connection () {
    echo
    echo "#### Local connection: $protocol ####"
    # Pass a key and certificate. The ssl_client1 program doesn't actually
    # check the certificates, so it doesn't matter what we pass here.
    set -- \
        -key "$root_dir/framework/data_files/server5.key" \
        -cert "$root_dir/framework/data_files/server5.crt" \
        "$@"
    set openssl s_server -accept 4433 -trace "$@"
    printf '+ %s &\n' "$*"
    response | "$@" >"$server_log" 2>&1 &
    server_pid=$!
    # Give the server a reasonable amount of time to start
    sleep 1
    ret=0
    printf '+ %s\n' "$program"
    "$program" || ret=$?
    kill "$server_pid" 2>/dev/null || true # The server may exit first
    # Check and display the presence of a few connection parameters
    grep '^ *client_version=' "$server_log"
    grep '^ *KeyExchangeAlgorithm=' "$server_log"
    grep '^ *cipher_suite ' "$server_log"
    grep 'ApplicationData' "$server_log"
    if [ "$ret" -ne 0 ]; then
        echo "FAIL: $program returned $ret"
        echo "BEGIN server output"
        cat "$server_log"
        echo "END server output"
        rm "$server_log"
    fi
    return "$ret"
}
