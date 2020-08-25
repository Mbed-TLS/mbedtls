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

if [ -d include/mbedtls ]; then :; else
    echo "$0: must be run from root" >&2
    exit 1
fi

if grep -i cmake Makefile >/dev/null; then
    echo "$0: not compatible with cmake" >&2
    exit 1
fi

cp include/mbedtls/config.h include/mbedtls/config.h.bak
scripts/config.pl full
make clean
make_ret=
CFLAGS=-fno-asynchronous-unwind-tables make lib \
      >list-symbols.make.log 2>&1 ||
  {
    make_ret=$?
    echo "Build failure: CFLAGS=-fno-asynchronous-unwind-tables make lib"
    cat list-symbols.make.log >&2
  }
rm list-symbols.make.log
mv include/mbedtls/config.h.bak include/mbedtls/config.h
if [ -n "$make_ret" ]; then
    exit "$make_ret"
fi

if uname | grep -F Darwin >/dev/null; then
    nm -gUj library/libmbed*.a 2>/dev/null | sed -n -e 's/^_//p'
elif uname | grep -F Linux >/dev/null; then
    nm -og library/libmbed*.a | grep -v '^[^ ]*: *U \|^$\|^[^ ]*:$' | sed 's/^[^ ]* . //'
fi | sort > exported-symbols
make clean

wc -l exported-symbols
