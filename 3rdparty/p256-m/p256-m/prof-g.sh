#!/bin/sh

# On-host profiling using Gprof
#
# Author: Manuel Pégourié-Gonnard.
# SPDX-License-Identifier: Apache-2.0

set -eu

# value chosen so that the program runs for at least 5 sec on my laptop,
# resulting in at least 500 samples being collected.
: ${TIMES:=500}

# Anything capable of running gcc has CT 64-bit mul in practice
gcc --std=c99 -Werror -Wall -Wextra -pedantic \
    -march=native -DMUL64_IS_CONSTANT_TIME \
    -Os -g -pg --static -DTIMES=$TIMES p256-m.c prof.c -o prof-g

./prof-g

gprof -p -b ./prof-g

rm prof-g gmon.out
