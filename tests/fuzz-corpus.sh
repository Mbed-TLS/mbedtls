#!/bin/sh

# fuzz-corpus.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2019, ARM Limited, All Rights Reserved
#
# Purpose
#
# Tests fuzz targets (compiled with sanitizers) on their corpuses.
#

set -u

# Limit the size of each log to 10 GiB, in case of failures with this script
# where it may output seemingly unlimited length error logs.
ulimit -f 20971520

if cd $( dirname $0 ); then :; else
    echo "cd $( dirname $0 ) failed" >&2
    exit 1
fi

TESTS=0
FAILS=0
SKIPS=0

SHOW_TEST_NUMBER=0

print_usage() {
    echo "Usage: $0 [options]"
    printf "  -h|--help\tPrint this help.\n"
}

get_options() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                echo "Unknown argument: '$1'"
                print_usage
                exit 1
                ;;
        esac
        shift
    done
}

# print_name <name>
print_name() {
    TESTS=$(( $TESTS + 1 ))
    LINE=""

    if [ "$SHOW_TEST_NUMBER" -gt 0 ]; then
        LINE="$TESTS "
    fi

    LINE="$LINE$1"
    printf "$LINE "
    LEN=$(( 72 - `echo "$LINE" | wc -c` ))
    for i in `seq 1 $LEN`; do printf '.'; done
    printf ' '

}

# fail <message>
fail() {
    echo "FAIL"
    echo "  ! $1"

    mv $CMD_OUT cmd-${TESTS}.log
    echo "  ! outputs saved to cmd-XXX-${TESTS}.log"

    FAILS=$(( $FAILS + 1 ))
}

# Usage: run_test name binary files
run_test() {
    NAME="$1"
    shift 1

    print_name "$NAME"

    # get commands and client output
    BINARY="$1"
    shift 1
    FILES="$@"

    for FILE in $FILES
    do
        $BINARY $FILE >> $CMD_OUT 2>&1
        # check exit code
        if [ $? != 0 ]; then
            fail "command failed"
            return
        fi
    done

    # if we're here, everything is ok
    echo "PASS"

    rm -f $CMD_OUT
}

cleanup() {
    rm -f $CMD_OUT
    exit 1
}

#
# MAIN
#

get_options "$@"

# sanity checks, avoid an avalanche of errors
if [ ! -x ../programs/fuzz/fuzz_server ]; then
    echo "Command fuzz_server is not an executable file"
    exit 1
fi

# used by watchdog
MAIN_PID="$$"
# Also pick a unique name for intermediate files
CMD_OUT="cmd_out.$$"

trap cleanup INT TERM HUP

# Basic test
run_test    "server" \
            "../programs/fuzz/fuzz_server" \
            "../programs/fuzz/corpuses/server"

run_test    "client" \
            "../programs/fuzz/fuzz_client" \
            "../programs/fuzz/corpuses/client"

run_test    "dtlsserver" \
            "../programs/fuzz/fuzz_dtlsserver" \
            "../programs/fuzz/corpuses/dtlsserver"

run_test    "dtlsclient" \
            "../programs/fuzz/fuzz_dtlsclient" \
            "../programs/fuzz/corpuses/dtlsclient"

run_test    "x509crl" \
            "../programs/fuzz/fuzz_x509crl" \
            "../tests/data_files/crl*"

run_test    "x509crt" \
            "../programs/fuzz/fuzz_x509crt" \
            "../tests/data_files/*.crt" \
            "../tests/data_files/dir*/*.crt"

run_test    "x509csr" \
            "../programs/fuzz/fuzz_x509csr" \
            "../tests/data_files/*.csr" \
            "../tests/data_files/*.req.*"

run_test    "privkey" \
            "../programs/fuzz/fuzz_privkey" \
            "../tests/data_files/*.key" \
            "../tests/data_files/*.pem"

run_test    "pubkey" \
            "../programs/fuzz/fuzz_pubkey" \
            "../tests/data_files/*.pubkey" \
            "../tests/data_files/*.pub"

# Final report

echo "------------------------------------------------------------------------"

if [ $FAILS = 0 ]; then
    printf "PASSED"
else
    printf "FAILED"
fi
PASSES=$(( $TESTS - $FAILS ))
echo " ($PASSES / $TESTS tests ($SKIPS skipped))"

exit $FAILS
