#!/bin/sh

# yotta-build.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# This file is provided under the Apache License 2.0, or the
# GNU General Public License v2.0 or later.
#
# **********
# Apache License 2.0:
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
# **********
#
# **********
# GNU General Public License v2.0 or later:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# **********
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
