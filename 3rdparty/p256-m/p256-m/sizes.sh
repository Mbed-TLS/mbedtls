#!/bin/sh

# Print the size of p256-m.o with GCC and Clang on selected cores.
#
# Author: Manuel Pégourié-Gonnard.
# SPDX-License-Identifier: Apache-2.0

set -eu

SRC=p256-m.c
CFLAGS_COMMON="-Werror --std=c99 -fomit-frame-pointer -mthumb $SRC"

gcc() {
    arm-none-eabi-gcc -Wall -Wextra -pedantic \
        -Os $CFLAGS_COMMON "$@"
}

clang() {
    env clang --target=arm-none-eabi -Weverything \
        -Oz $CFLAGS_COMMON "$@"
}

OBJECTS=''

for CC in gcc clang; do
    for CPU in m0 m4 a7; do
        NAME="${CC}-${CPU}"
        $CC -mcpu=cortex-$CPU -S -fverbose-asm -o ${NAME}.s
        $CC -mcpu=cortex-$CPU -c -o ${NAME}.o
        arm-none-eabi-objdump -d ${NAME}.o > ${NAME}.dump
        nm --radix=d --size-sort ${NAME}.o > ${NAME}.sizes
        OBJECTS="$OBJECTS ${NAME}.o"
    done
done

arm-none-eabi-size $OBJECTS
