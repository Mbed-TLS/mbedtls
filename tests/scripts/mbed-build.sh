#!/bin/sh

# mbed-build.sh
#
# This file is part of Mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2019, Arm Limited, All Rights Reserved
#
# Purpose
#
# To run test builds of the Mbed OS module for all specified targets.
# Usage: mbed-build <folder to import to> <optinally string of space seperated targets>
# If no targets given as input, a set of default targets are tested, defined in
# TARGETS variable.
# The script uses a couple of environment variables:
#     MBED_APP - The Mbed application to import and build. Default is mbed-os-example-tls.
#     REMOTE_URL - The URL for the remote fork. Default is git@github.com:ARMmbed.

DEFAULT_MBED_APP='mbed-os-example-tls'
DEFAULT_REMOTE_URL="git@github.com:ARMmbed"
DEFAULT_TARGETS="K64F NUCLEO_F429ZI"
print_usage()
{
    echo "\nUsage: mbed-build <folder to import to> <optinally string of space seperated targets>"
    echo "If no targets given as input, The following default targets are built:"
    echo "$DEFAULT_TARGETS"
    echo "The script uses a couple of environment variables:"
    echo "    MBED_APP - The Mbed application to import and build. Default is $DEFAULT_MBED_APP."
    echo "    REMOTE_URL - The URL for the remote fork. Default is $DEFAULT_REMOTE_URL."
}

if [ -z "$1" ]
then
    echo "expected folder to import not given as parameter"
    print_usage
    exit 1
fi
OUT_OF_SOURCE_DIR=$1

if [ -z "$MBED_APP" ]
then
    MBED_APP=$DEFAULT_MBED_APP
fi
if [ -z "$REMOTE_URL" ]
then
    REMOTE_URL=$DEFAULT_REMOTE_URL
fi
if [ $# -eq 1 ]
then
    TARGETS=$DEFAULT_TARGETS
else
    TARGETS=$2
fi

FAILED=0
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
    if [ $? -ne 0 ]
    then
        FAILED=1
    fi

    echo "*** $PLATFORM (debug $COMPILER) ***"
    mbed compile -t $COMPILER -m $PLATFORM --profile mbed-os/tools/profiles/debug.json -c
    if [ $? -ne 0 ]
    then
        FAILED=1
    fi
}

create_module()
{
    MBED_APP_URL=$REMOTE_URL/$MBED_APP

    mbed import $MBED_APP_URL

    echo "'$MBED_APP_URL' imported to '$PWD'."
}

# Make sure the tools we need are available.
check_tools "arm-none-eabi-gcc" "armcc" "mbed" "armclang"

cd $OUT_OF_SOURCE_DIR
create_module
cd $MBED_APP

TOOLCHAINS="ARM GCC_ARM ARMC6"


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

exit $FAILED
