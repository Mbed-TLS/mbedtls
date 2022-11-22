#!/bin/sh

# Compute maximum stack usage on selected cores with GCC.
#
# Author: Manuel Pégourié-Gonnard.
# SPDX-License-Identifier: Apache-2.0

for CPU in m0 m4 a7; do
    echo "*** $CPU ***"
    arm-none-eabi-gcc -c -fdump-rtl-dfinish -fstack-usage \
        -Os -fomit-frame-pointer -mthumb -mcpu=cortex-$CPU \
        p256-m.c
    python3 wcs.py | sed -n 's/^..p256-m.c *p256_/p256_/p'
done
