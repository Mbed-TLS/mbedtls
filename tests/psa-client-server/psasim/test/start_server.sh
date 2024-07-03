#!/bin/bash

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

set -e

# Wait for the server to start up and create the socket.
function wait_for_server_startup() {
    while [ ! $(ss -lta | grep "127.0.0.1:4242") ]; do
        sleep 0.1
    done
}

$(dirname "$0")/kill_server.sh

$(dirname "$0")/psa_server &
wait_for_server_startup
