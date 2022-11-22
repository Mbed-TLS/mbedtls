#!/bin/sh

# Print generated assembly for 32x32->64 bit unsigned multiplication.
#
# This is a development helper to:
# 1. Check it the toolchain-provided __aeabi_lmul is contant-time (it isn't).
# 2. Check if the compiler uses the UMAAL instruction (it doesn't).
#
# Author: Manuel Pégourié-Gonnard.
# SPDX-License-Identifier: Apache-2.0

set -eu

for CPU in m0 m0plus m3 m4 m7 m23 m33 a7; do
    printf "\n***** %s *****\n" $CPU
    arm-none-eabi-gcc -Os -mthumb -mcpu=cortex-$CPU toolchain-mul64.c \
        --entry=mul64 -nostartfiles -o linked.elf
    arm-none-eabi-objdump -d linked.elf
done

rm linked.elf
