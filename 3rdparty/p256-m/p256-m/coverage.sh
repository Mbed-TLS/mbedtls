#!/bin/sh

# Measure code coverage with open/closed-box testing using gcov/lcov.
#
# Author: Manuel Pégourié-Gonnard.
# SPDX-License-Identifier: Apache-2.0

set -eu

make clean
make CC=gcc CFLAGS='-Werror -Wall -Wextra -O1 -g3 --coverage' test-closedbox test-openbox

LCOV_FLAGS="--directory . --rc lcov_branch_coverage=1 --no-external"

./test-closedbox
lcov $LCOV_FLAGS --exclude $PWD/'test-*.c' --capture --output-file closed.info
./test-openbox
lcov $LCOV_FLAGS --exclude $PWD/'test-*.c' --capture --output-file open.info

genhtml --branch-coverage closed.info -o cov-closed
genhtml --branch-coverage open.info -o cov-open

# Leaving outputs for inspection. They're removed by 'make clean'.
