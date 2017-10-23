#!/bin/sh

set -u

MBEDTLS_BASE="$(dirname -- "$0")/../.."
TPXY_BIN="$MBEDTLS_BASE/programs/test/udp_proxy"
SRV_BIN="$MBEDTLS_BASE/programs/ssl/ssl_server2"

: ${VERBOSE:=0}
FULL_PARAMS=$*
PROXY_PARAMS=${FULL_PARAMS%%" -- "*}
SERVER_PARAMS=${FULL_PARAMS#*" -- "}

stop_proxy() {
    test -n "${TPXY_PID:-}" &&
        (
            echo "\n  * Killing proxy (pid $TPXY_PID) ..."
            kill $TPXY_PID
        )
}

stop_server() {
    test -n "${SRV_PID:-}" &&
        (
            echo "\n  * Killing server (pid $SRV_PID) ..."
            kill $SRV_PID >/dev/null 2>/dev/null
        )
}

cleanup() {
    stop_server
    stop_proxy
    return 1
}

trap cleanup INT TERM HUP

DTLS_ENABLED=$(echo "$SERVER_PARAMS" | grep -v "::1" | grep "dtls=1")
if [ -z "$DTLS_ENABLED" ]; then
    echo "  * Couldn't find DTLS enabling, or IPv6 is in use - immediate fallback to server application..."
    if [ $VERBOSE -gt 0 ]; then
        echo "[ $SRV_BIN $SERVER_PARAMS ]"
    fi
    $SRV_BIN $SERVER_PARAMS >&1 2>&1 &
    SRV_PID=$!
    wait $SRV_PID
    exit 0
fi

SERVER_PORT_ORIG=$(echo "$SERVER_PARAMS" | sed -n "s/^.*server_port=\([0-9]*\).*$/\1/p")
if [ -z "$SERVER_PORT_ORIG" ]; then
    echo "  * No server port specified - exit"
    exit 1
fi

SERVER_ADDR_ORIG=$(echo "$SERVER_PARAMS" | sed -n "s/^.*server_addr=\([a-zA-Z0-9\.]*\).*$/\1/p")
if [ -z "$SERVER_ADDR_ORIG" ]; then
    echo "  * No server address specified - exit"
    exit 1
fi

echo "  * Server address:    $SERVER_ADDR_ORIG"
echo "  * Server port:       $SERVER_PORT_ORIG"

SERVER_PORT=$(( $SERVER_PORT_ORIG + 1 ))
echo "  * Intermediate port: $SERVER_PORT"

TPXY_CMD=\
"$TPXY_BIN $PROXY_PARAMS "\
"listen_port=$SERVER_PORT_ORIG "\
"server_port=$SERVER_PORT "\
"server_addr=$SERVER_ADDR_ORIG "\
"listen_addr=$SERVER_ADDR_ORIG"

echo "  * Start proxy in background ..."
if [ $VERBOSE -gt 0 ]; then
    echo "[ $TPXY_CMD ]"
fi

$TPXY_CMD >/dev/null 2>&1 &
TPXY_PID=$!

if [ $VERBOSE -gt 0 ]; then
    echo "  * Proxy ID:          $TPXY_PID"
fi

SERVER_PARAMS_NEW=$(echo "$SERVER_PARAMS" | sed -n "s/^\(.*server_port=\)[0-9]*\(.*\)$/\1$SERVER_PORT\2/p")
SRV_CMD="$SRV_BIN $SERVER_PARAMS_NEW"

echo "  * Starting server ..."
if [ $VERBOSE -gt 0 ]; then
    echo "[ $SRV_CMD ]"
fi

$SRV_CMD >&2 &
SRV_PID=$!

wait $SRV_PID

stop_proxy
return 0
