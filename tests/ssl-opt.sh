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
    echo SERVERQUIT | openssl s_client >/dev/null 2>&1
    wait $SRV_PID
    shift 2

    # check client exit code
    if [ "$1" = 0 -a "$CLI_EXIT" != 0 ]; then
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

run_test    "Truncated HMAC" \
            "debug_level=5" \
            "debug_level=5 trunc_hmac=1 \
                force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA" \
            0 \
            -s "dumping 'computed mac' (10 bytes)$"
