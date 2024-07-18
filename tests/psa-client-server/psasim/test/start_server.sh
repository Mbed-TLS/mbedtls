#!/bin/bash

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

set -e

# The server creates some local files when it starts up so we can wait for this
# event as signal that the server is ready so that we can start client(s).
function wait_for_server_startup() {
    while [ -z $(find /tmp -maxdepth 1 -name "psa_notify_*" -printf 1 -quit) ]; do
        sleep 0.1
    done
}

$(dirname "$0")/kill_server.sh

$(dirname "$0")/psa_server &
wait_for_server_startup
