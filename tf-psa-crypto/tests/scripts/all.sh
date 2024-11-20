#! /usr/bin/env bash

# all.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file is executable; it is the entry point for users and the CI.
# See "Files structure" in all-core.sh for other files used.

# This script must be invoked from the project's root.

# Prevent silly mistakes when people would invoke this from mbedtls
if [ -d tf-psa-crypto -a -d include/mbedtls ]; then
    echo "When invoking this script from an mbedtls checkout," >&2
    echo "you must change the working directory to tf-psa-crypto." >&2
    exit 255
fi

if [ -d ../include/mbedtls -a -d ../framework ]; then
    # Running inside an mbedtls checkout: get the framework from mbedtls.
    FRAMEWORK="$PWD/../framework"
else
    # Running standalone: use our own framework.
    FRAMEWORK="$PWD/framework"
fi

source $FRAMEWORK/scripts/all-core.sh

main "$@"
