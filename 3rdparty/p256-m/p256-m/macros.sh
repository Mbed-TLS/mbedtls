#!/bin/sh

# Print the values of pre-defined macros of interest on a selection of cores.
# This is a development helper to investigate how to detect cores/features.
#
# Author: Manuel Pégourié-Gonnard.
# SPDX-License-Identifier: Apache-2.0

set -eu

CPU_LIST='m0 m0plus m3 m4 m7 m23 m33'
# v7-A cores
#CPU_LIST='a5 a7 a8 a9 a12 a15 a17'
# v8-A cores
#CPU_LIST='a32 a35 a53 a55 a57 a72 a73 a75 a76'
# pre-cortex cores
#CPU_LIST='arm1176jzf-s arm10tdmi arm10e arm9tdmi arm9'

for CPU in $CPU_LIST; do
    case $CPU in
        arm*)   FULL_CPU="$CPU";;
        *)      FULL_CPU="cortex-$CPU";;
    esac
    arm-none-eabi-gcc -mcpu=$FULL_CPU -mthumb -dM -E - </dev/null |
        sort > macros-gcc-$CPU.txt
    clang --target=arm-none-eabi -mcpu=$FULL_CPU -dM -E - </dev/null |
        sort > macros-clang-$CPU.txt
done

get_macro() {
    RE=$1
    CC=$2
    CPU=$3

    sed -n "s/^#define $RE \(.*\)/\1/p" macros-$CC-$CPU.txt
}

for MACRO_RE in __GNUC__ __ARM_ARCH __ARM_ARCH_PROFILE __ARM_FEATURE_DSP; do
    printf "\n%s\n      " "$MACRO_RE"
    for CPU in $CPU_LIST; do
        printf "%7s " $CPU
    done
    printf "\n"
    for CC in gcc clang; do
        printf "%5s " $CC
        for CPU in $CPU_LIST; do
            printf "%7s " $(get_macro "$MACRO_RE" $CC $CPU)
        done
        printf "\n"
    done
done

# comment out for manual exploration
rm macros-*.txt
