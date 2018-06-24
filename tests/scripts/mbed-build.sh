#!/bin/sh

# mbed-build.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2018, ARM Limited, All Rights Reserved
#
# Purpose
#
# To run test builds of the mbed OS module for all specified targets.
# Usage: mbed-build <folder to import to> <optinally string of space seperated targets>

set -eu

OUT_OF_SOURCE_DIR=$1
MBED_APP='mbed-os-example-tls'
REMOTE_URL="git@github.com:ARMmbed"

check_tools()
{
    for TOOL in "$@"; do
        if ! `hash "$TOOL" >/dev/null 2>&1`; then
            echo "$TOOL not found!" >&2
            exit 1
        fi
    done
}

mbed_build()
{
    PLATFORM=$1
    COMPILER=$2

    echo "*** $PLATFORM (release $COMPILER) ***"
    mbed compile -t $COMPILER -m $PLATFORM -c

    echo "*** $PLATFORM (debug $COMPILER) ***"
    mbed compile -t $COMPILER -m $PLATFORM --profile mbed-os/tools/profiles/debug.json -c
}

create_module()
{
    MBED_APP_URL=$REMOTE_URL/$MBED_APP

    mbed import $MBED_APP_URL

    echo "'$MBED_APP_URL' imported to '$PWD'."
}

# Make sure the tools we need are available.
check_tools "arm-none-eabi-gcc" "armcc" "mbed"

cd $OUT_OF_SOURCE_DIR
create_module
cd $MBED_APP

TOOLCHAINS="ARM GCC_ARM"
if [ $# -eq 1 ]
then
TARGETS="K64F NUCLEO_F429ZI"
else
TARGETS=$2
fi

for f in *; do
    if [ -d $f ] && [ -d $f"/mbed-os" ]; then
        cd $f
        for TOOLCHAIN in $TOOLCHAINS; do
            for TARGET in $TARGETS; do
                mbed_build $TARGET $TOOLCHAIN
            done
        done
        cd -
    fi
done
