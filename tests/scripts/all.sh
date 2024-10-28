#! /usr/bin/env bash

# all.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file is executable; it is the entry point for users and the CI.
# See "Files structure" in all-core.sh for other files used.

# The path is going to change when this is moved to the framework
test_script_dir="${0%/*}"
source "$test_script_dir"/all-core.sh

main "$@"
