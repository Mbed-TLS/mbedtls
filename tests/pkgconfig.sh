#!/bin/sh

# compat.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Purpose
#
# Test pkgconfig files.
#
# For each of the build pkg-config files, .pc files, check that
# they validate and do some basic sanity testing on the output,
# ie. that the strings are non-empty.
#
# NOTE: This requires the built pc files to be on the pkg-config
# search path, this can be controlled with env variable
# PKG_CONFIG_PATH. See man(1) pkg-config for details.
#

set -e -o pipefail

all_pcs=("mbedtls" "mbedx509" "mbedcrypto")

for pc in "${all_pcs[@]}"; do
    echo -n "testing: ${pc} ... "
    pkg-config --validate "${pc}"
    version="$(pkg-config --modversion ${pc})"
    test -n "$version"
    cflags="$(pkg-config --cflags ${pc})"
    test -n "$cflags"
    libs="$(pkg-config --libs ${pc})"
    test -n "$libs"
    echo "passed"
done

exit 0
