#!/bin/sh

# pre-commit.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# Purpose
#
# This script does quick sanity checks before commiting:
#   - check that generated files are up-to-date.
#
# It is meant to be called as a git pre-commit hook, see README.md.
#
# From the git sample pre-commit hook:
#   Called by "git commit" with no arguments.  The hook should
#   exit with non-zero status after issuing an appropriate message if
#   it wants to stop the commit.

set -eu

tests/scripts/check-generated-files.sh
