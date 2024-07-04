#!/bin/bash

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

set -e

pkill psa_server || true

# Remove the socket file.
rm -f "psasim-socket"
