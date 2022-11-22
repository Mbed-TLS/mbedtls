#!/bin/sh

# Check constant-time behaviour using MemSan and Valgrind.
#
# Author: Manuel Pégourié-Gonnard.
# SPDX-License-Identifier: Apache-2.0

set -eu

make clean

make CFLAGS_SAN='-DCT_MEMSAN -fsanitize=memory -g3'
make clean

# valgrind is slow, save some time by using the CPU's mul64
# (this also ensures the trivial definition of u32_mul64 is tested as well)
make CFLAGS_SAN='-D CT_VALGRIND -g3 -D MUL64_IS_CONSTANT_TIME' test-closedbox test-openbox
valgrind --track-origins=yes ./test-closedbox
valgrind --track-origins=yes ./test-openbox
make clean
