#!/bin/bash

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This is a simple bash script that tests psa_client/psa_server interaction.
# This script is automatically executed when "make run" is launched by the
# "psasim" root folder. The script can also be launched manually once
# binary files are built (i.e. after "make test" is executed from the "psasim"
# root folder).

set -e

cd "$(dirname "$0")"

CLIENT_BIN=$1
shift

ipcs | grep q | awk '{ printf " -q " $2 }' | xargs ipcrm > /dev/null 2>&1 || true

./start_server.sh
./$CLIENT_BIN "$@"

# Kill server once client exited
pkill psa_server
