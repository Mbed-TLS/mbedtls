#!/bin/sh
#
# Copyright The Mbed TLS Contributors
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
scripts/config.py full
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
    nm -gUj library/libmbed*.a 2>/dev/null | sed -n -e 's/^_//p' | grep -v -e ^FStar -e ^Hacl
elif uname | grep -F Linux >/dev/null; then
    nm -og library/libmbed*.a | grep -v '^[^ ]*: *U \|^$\|^[^ ]*:$' | sed 's/^[^ ]* . //' | grep -v -e ^FStar -e ^Hacl
fi | sort > exported-symbols
make clean

wc -l exported-symbols
