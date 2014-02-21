#!/bin/sh

# Test various options that are not covered by compat.sh
#
# Here the goal is not to cover every ciphersuite/version, but
# rather specific options (max fragment length, truncated hmac, etc)
# or procedures (session resumption from cache or ticket, renego, etc).
#
# Assumes all options are compiled in.

PROGS_DIR='../programs/ssl'
SRV_CMD="$PROGS_DIR/ssl_server2"
CLI_CMD="$PROGS_DIR/ssl_client2"

# Usage: run_test name srv_args cli_args cli_exit [option [...]]
# Options:  -s pattern  pattern that must be present in server output
#           -c pattern  pattern that must be present in client output
#           -S pattern  pattern that must be absent in server output
#           -C pattern  pattern that must be absent in client output
run_test() {
    echo -n "$1: "
    shift

    # run the commands
    $SRV_CMD $1 > srv_out &
    SRV_PID=$!
    sleep 1
    $CLI_CMD $2 > cli_out
    CLI_EXIT=$?
    echo SERVERQUIT | openssl s_client -no_ticket >/dev/null 2>&1
    wait $SRV_PID
    shift 2

    # check client exit code
    if [ \( "$1" = 0 -a "$CLI_EXIT" != 0 \) -o \
         \( "$1" != 0 -a "$CLI_EXIT" = 0 \) ]
    then
        echo "FAIL - client exit"
        return
    fi
    shift

    # check options
    while [ $# -gt 0 ]
    do
        case $1 in
            "-s")
                if grep "$2" srv_out >/dev/null; then :; else
                    echo "FAIL - -s $2"
                    return
                fi
                ;;

            "-c")
                if grep "$2" cli_out >/dev/null; then :; else
                    echo "FAIL - -c $2"
                    return
                fi
                ;;

            "-S")
                if grep "$2" srv_out >/dev/null; then
                    echo "FAIL - -S $2"
                    return
                fi
                ;;

            "-C")
                if grep "$2" cli_out >/dev/null; then
                    echo "FAIL - -C $2"
                    return
                fi
                ;;

            *)
                echo "Unkown test: $1" >&2
                exit 1
        esac
        shift 2
    done

    # if we're here, everything is ok
    echo "PASS"
    rm -r srv_out cli_out
}

killall -q openssl ssl_server ssl_server2

# Tests for Truncated HMAC extension

run_test    "Truncated HMAC #0" \
            "debug_level=5" \
            "trunc_hmac=0 force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA" \
            0 \
            -s "dumping 'computed mac' (20 bytes)"

run_test    "Truncated HMAC #1" \
            "debug_level=5" \
            "trunc_hmac=1 force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA" \
            0 \
            -s "dumping 'computed mac' (10 bytes)"

# Tests for Session Tickets

run_test    "Session resume using tickets #1" \
            "debug_level=4 tickets=1" \
            "debug_level=4 tickets=1 reconnect=1" \
            0 \
            -c "client hello, adding session ticket extension" \
            -s "found session ticket extension" \
            -s "server hello, adding session ticket extension" \
            -c "found session_ticket extension" \
            -c "parse new session ticket" \
            -S "session successfully restored from cache" \
            -s "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

run_test    "Session resume using tickets #2" \
            "debug_level=4 tickets=1 cache_max=0" \
            "debug_level=4 tickets=1 reconnect=1" \
            0 \
            -c "client hello, adding session ticket extension" \
            -s "found session ticket extension" \
            -s "server hello, adding session ticket extension" \
            -c "found session_ticket extension" \
            -c "parse new session ticket" \
            -S "session successfully restored from cache" \
            -s "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

run_test    "Session resume using tickets #3" \
            "debug_level=4 tickets=1 cache_max=0 ticket_timeout=1" \
            "debug_level=4 tickets=1 reconnect=1 reco_delay=2" \
            0 \
            -c "client hello, adding session ticket extension" \
            -s "found session ticket extension" \
            -s "server hello, adding session ticket extension" \
            -c "found session_ticket extension" \
            -c "parse new session ticket" \
            -S "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -S "a session has been resumed" \
            -C "a session has been resumed"

run_test    "Session resume using tickets #4" \
            "debug_level=4 tickets=1 cache_max=0 ticket_timeout=2" \
            "debug_level=4 tickets=1 reconnect=1 reco_delay=0" \
            0 \
            -c "client hello, adding session ticket extension" \
            -s "found session ticket extension" \
            -s "server hello, adding session ticket extension" \
            -c "found session_ticket extension" \
            -c "parse new session ticket" \
            -S "session successfully restored from cache" \
            -s "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

# Tests for Session Resume based on session-ID and cache

run_test    "Session resume using cache #1 (tickets enabled on client)" \
            "debug_level=4 tickets=0" \
            "debug_level=4 tickets=1 reconnect=1" \
            0 \
            -c "client hello, adding session ticket extension" \
            -s "found session ticket extension" \
            -S "server hello, adding session ticket extension" \
            -C "found session_ticket extension" \
            -C "parse new session ticket" \
            -s "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

run_test    "Session resume using cache #2 (tickets enabled on server)" \
            "debug_level=4 tickets=1" \
            "debug_level=4 tickets=0 reconnect=1" \
            0 \
            -C "client hello, adding session ticket extension" \
            -S "found session ticket extension" \
            -S "server hello, adding session ticket extension" \
            -C "found session_ticket extension" \
            -C "parse new session ticket" \
            -s "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

run_test    "Session resume using cache #3 (cache_max=0)" \
            "debug_level=4 tickets=0 cache_max=0" \
            "debug_level=4 tickets=0 reconnect=1" \
            0 \
            -S "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -S "a session has been resumed" \
            -C "a session has been resumed"

run_test    "Session resume using cache #4 (cache_max=1)" \
            "debug_level=4 tickets=0 cache_max=1" \
            "debug_level=4 tickets=0 reconnect=1" \
            0 \
            -s "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

run_test    "Session resume using cache #5 (timemout > delay)" \
            "debug_level=4 tickets=0 cache_timeout=1" \
            "debug_level=4 tickets=0 reconnect=1 reco_delay=0" \
            0 \
            -s "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

run_test    "Session resume using cache #6 (timeout < delay)" \
            "debug_level=4 tickets=0 cache_timeout=1" \
            "debug_level=4 tickets=0 reconnect=1 reco_delay=2" \
            0 \
            -S "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -S "a session has been resumed" \
            -C "a session has been resumed"

run_test    "Session resume using cache #7 (no timeout)" \
            "debug_level=4 tickets=0 cache_timeout=0" \
            "debug_level=4 tickets=0 reconnect=1 reco_delay=2" \
            0 \
            -s "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

# Tests for Max Fragment Length extension

run_test    "Max fragment length #1" \
            "debug_level=4" \
            "debug_level=4" \
            0 \
            -C "client hello, adding max_fragment_length extension" \
            -S "found max fragment length extension" \
            -S "server hello, max_fragment_length extension" \
            -C "found max_fragment_length extension"

run_test    "Max fragment length #2" \
            "debug_level=4" \
            "debug_level=4 max_frag_len=4096" \
            0 \
            -c "client hello, adding max_fragment_length extension" \
            -s "found max fragment length extension" \
            -s "server hello, max_fragment_length extension" \
            -c "found max_fragment_length extension"

run_test    "Max fragment length #3" \
            "debug_level=4 max_frag_len=4096" \
            "debug_level=4" \
            0 \
            -C "client hello, adding max_fragment_length extension" \
            -S "found max fragment length extension" \
            -S "server hello, max_fragment_length extension" \
            -C "found max_fragment_length extension"

# Tests for renegotiation

run_test    "Renegotiation #0 (none)" \
            "debug_level=4" \
            "debug_level=4" \
            0 \
            -C "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -S "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -C "renegotiate" \
            -S "renegotiate" \
            -S "write hello request"

run_test    "Renegotiation #1 (enabled, client-initiated)" \
            "debug_level=4" \
            "debug_level=4 renegotiate=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -s "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -c "renegotiate" \
            -s "renegotiate" \
            -S "write hello request"

run_test    "Renegotiation #2 (enabled, server-initiated)" \
            "debug_level=4 renegotiate=1" \
            "debug_level=4" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -s "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -c "renegotiate" \
            -s "renegotiate" \
            -s "write hello request"

run_test    "Renegotiation #3 (enabled, double)" \
            "debug_level=4 renegotiate=1" \
            "debug_level=4 renegotiate=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -s "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -c "renegotiate" \
            -s "renegotiate" \
            -s "write hello request"

run_test    "Renegotiation #4 (client-initiated, server-rejected)" \
            "debug_level=4 renegotiation=0" \
            "debug_level=4 renegotiate=1" \
            1 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -S "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -c "renegotiate" \
            -S "renegotiate" \
            -S "write hello request"

run_test    "Renegotiation #5 (server-initiated, client-rejected)" \
            "debug_level=4 renegotiate=1" \
            "debug_level=4 renegotiation=0" \
            0 \
            -C "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -S "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -C "renegotiate" \
            -S "renegotiate" \
            -s "write hello request" \
            -s "SSL - An unexpected message was received from our peer" \
            -s "failed"
