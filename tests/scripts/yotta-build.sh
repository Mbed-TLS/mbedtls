#!/bin/sh

# yotta-build.sh
#
# Copyright (c) 2015-2016, ARM Limited, All Rights Reserved
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file is part of Mbed TLS (https://tls.mbed.org)
#
# Purpose
#
# To run test builds of the yotta module for all supported targets.

set -eu

check_tools()
{
    for TOOL in "$@"; do
        if ! `hash "$TOOL" >/dev/null 2>&1`; then
            echo "$TOOL not found!" >&2
            exit 1
        fi
    done
}

yotta_build()
{
    TARGET=$1

    echo; echo "*** $TARGET (release) ***"
    yt -t $TARGET build

    echo; echo "*** $TARGET (debug) ***"
    yt -t $TARGET build -d
}

# Make sure the tools we need are available.
check_tools "arm-none-eabi-gcc" "armcc" "yotta"

yotta/create-module.sh
cd yotta/module
yt update || true # needs network

if uname -a | grep 'Linux.*x86' >/dev/null; then
    yotta_build x86-linux-native
fi
if uname -a | grep 'Darwin.*x86' >/dev/null; then
    yotta_build x86-osx-native
fi

# armcc build tests.
yotta_build frdm-k64f-armcc
#yotta_build nordic-nrf51822-16k-armcc

# arm-none-eabi-gcc build tests.
yotta_build frdm-k64f-gcc
#yotta_build st-nucleo-f401re-gcc # dirent
#yotta_build stm32f429i-disco-gcc # fails in mbed-hal-st-stm32f4
#yotta_build nordic-nrf51822-16k-gcc # fails in minar-platform
#yotta_build bbc-microbit-classic-gcc # fails in minar-platform
#yotta_build st-stm32f439zi-gcc # fails in mbed-hal-st-stm32f4
#yotta_build st-stm32f429i-disco-gcc # fails in mbed-hal-st-stm32f4
