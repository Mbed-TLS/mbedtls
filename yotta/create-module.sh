#!/bin/sh
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

set -eu

# relative to the script's directory
TREE=..
DEST=module

# make sure we're running in our own directory
if [ -f create-module.sh ]; then :; else
    cd $( dirname $0 )
    if [ -f create-module.sh ]; then :; else
        echo "Please run the script from is directory." >&2
        exit 1
    fi
fi

# use a temporary directory to build the module, then rsync to DEST
# this allows touching only new files, for more efficient re-builds
TMP=$DEST-tmp
rm -rf $TMP

mkdir -p $TMP/mbedtls $TMP/source
cp $TREE/include/mbedtls/*.h $TMP/mbedtls
cp $TREE/library/*.c $TMP/source

# temporary, should depend on external module later
cp data/entropy_hardware_poll.c $TMP/source
cp data/target_config.h $TMP/mbedtls

data/adjust-config.sh $TREE/scripts/config.pl $TMP/mbedtls/config.h

mkdir -p $TMP/test
cp -r data/example-* $TMP/test
# later we should have the generated test suites here too

cp data/module.json $TMP
cp data/README.md $TMP

cp ../LICENSE $TMP
if [ -f ../apache-2.0.txt ]; then cp ../apache-2.0.txt $TMP; fi

mkdir -p $DEST
rsync -cr --delete --exclude build --exclude yotta_\* $TMP/ $DEST/
rm -rf $TMP

echo "mbed TLS yotta module created in '$PWD/$DEST'."
