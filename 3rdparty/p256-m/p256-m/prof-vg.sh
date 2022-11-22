#!/bin/sh

# On-host profiling using Valgrind
#
# Author: Manuel Pégourié-Gonnard.
# SPDX-License-Identifier: Apache-2.0

set -eu

# Anything capable of running gcc has CT 64-bit mul in practice
gcc --std=c99 -Werror -Wall -Wextra -pedantic \
    -march=native -DMUL64_IS_CONSTANT_TIME \
    -Os -g p256-m.c prof.c -o prof

OUTFILE=prof.callgrind.$$
valgrind -q --tool=callgrind --collect-atstart=no --toggle-collect=main \
    --callgrind-out-file=$OUTFILE ./prof

callgrind_annotate --show-percs=yes $OUTFILE |
    sed -n '/file:function/,$ p'

rm $OUTFILE prof
