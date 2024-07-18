#!/bin/bash

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

set -e

pkill psa_server || true

# Remove temporary files and logs
rm -f /tmp/psa_notify_*
rm -f /tmp/psa_service_*
rm -f psa_server.log

# Remove all IPCs
ipcs -q | awk '{ printf " -q " $2 }' | xargs ipcrm > /dev/null 2>&1 || true
