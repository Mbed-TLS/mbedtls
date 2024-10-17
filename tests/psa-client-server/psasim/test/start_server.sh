#!/bin/bash

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

set -e

# Wait for the server to start up and create the socket.
# Note: the socket file being checked must be in the same folder from where
#       this script is called.
function wait_for_server_startup() {
    while [ ! -f "psasim-shm" ]; do
        sleep 0.1
    done
}

$(dirname "$0")/psa_server &
wait_for_server_startup
