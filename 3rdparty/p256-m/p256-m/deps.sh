#!/bin/sh

# Print dependencies on libc / compiler's runtime, with sizes.
#
# Author: Manuel Pégourié-Gonnard.
# SPDX-License-Identifier: Apache-2.0

set -eu

P256_SYM_RE='(u256|u288|m256|point|scalar|ecdsa|p256)_'

for CPU in m0 m4 a7; do
    printf "\n*** %s ***\n" $CPU
    arm-none-eabi-gcc -Os -mthumb -mcpu=cortex-$CPU p256-m.c entry.c \
        --entry=p256_entry -nostartfiles -o linked.elf
    arm-none-eabi-nm --print-size --radix=d linked.elf |
        awk "/^[0-9]{8} [0-9]{8} . / && !/ . $P256_SYM_RE/ \
            "'{print $2, $4; tot += $2} END {print "total: " tot}'
done

rm linked.elf
