#! /usr/bin/env sh

# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2018, ARM Limited, All Rights Reserved
#
# Purpose
#
# Check if the list of components in all.sh is up-to-date

set -eu

DEFINED="def.$$"
LISTED="lst.$$"

sed -n 's/^component_\([^ (]*\).*/\1/p' tests/scripts/all.sh \
    | sort > "$DEFINED"
tests/scripts/all.sh --list-components | grep -v '^$' \
    | sort > "$LISTED"

diff "$DEFINED" "$LISTED"

rm "$DEFINED" "$LISTED"
