#!/bin/bash

# This is a simple bash script that tests psa_client/psa_server interaction.
# This script is automatically executed when "make run" is launched by the
# "psasim" root folder. The script can also be launched manually once
# binary files are built (i.e. after "make test" is executed from the "psasim"
# root folder).
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

set -e

function clean_run() {
    pkill psa_partition || true
    pkill psa_client || true
    ipcs | grep q | awk '{ printf " -q " $$2 }' | xargs ipcrm > /dev/null 2>&1 || true
}

# The server creates some local files when it starts up so we can wait for this
# event as signal that the server is ready so that we can start client(s).
function wait_for_server_startup() {
    while [ ! -f ./psa_notify_* ]; do
    sleep 0.1
    done
}

clean_run

./psa_partition -k &
SERV_PID=$!
wait_for_server_startup
./psa_client
wait $SERV_PID
