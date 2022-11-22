#!/bin/sh

# On-host profiling using gperftools
#
# Author: Manuel Pégourié-Gonnard.
# SPDX-License-Identifier: Apache-2.0

set -eu

# value chosen so that the program runs for at least 5 sec on my laptop,
# resulting in at least 500 samples being collected.
: ${TIMES:=1000}

# adjust for your platform
: ${TRIPLET:=x86_64-linux-gnu}

# Anything capable of running gcc has CT 64-bit mul in practice
gcc --std=c99 -Werror -Wall -Wextra -pedantic \
    -march=native -DMUL64_IS_CONSTANT_TIME \
    -Os -g -DTIMES=$TIMES p256-m.c prof.c -o prof-gpt

# for some reason compiling with -lprofile doesn't seem to work for me, so
# using LD_PRELOAD instead
CPUPROFILE=gpt.out LD_PRELOAD=/usr/lib/$TRIPLET/libprofiler.so ./prof-gpt

google-pprof -text ./prof-gpt gpt.out

rm prof-gpt gpt.out
