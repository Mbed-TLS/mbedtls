#!/bin/sh

# Run the shared library dynamic loading demo program.
# This is only expected to work when Mbed TLS is built as a shared library.

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

. "${0%/*}/../demo_common.sh"

msg "Test the dynamic loading of libmbed*"

program="$programs_dir/test/dlopen"
library_dir="$root_dir/library"

# Skip this test if we don't have a shared library build. Detect this
# through the absence of the demo program.
if [ ! -e "$program" ]; then
    msg "$0: this demo requires a shared library build."
    # Exit with a success status so that this counts as a pass for run_demos.py.
    exit
fi

# ELF-based Unix-like (Linux, *BSD, Solaris, ...)
if [ -n "${LD_LIBRARY_PATH-}" ]; then
    LD_LIBRARY_PATH="$library_dir:$LD_LIBRARY_PATH"
else
    LD_LIBRARY_PATH="$library_dir"
fi
export LD_LIBRARY_PATH

# OSX/macOS
if [ -n "${DYLD_LIBRARY_PATH-}" ]; then
    DYLD_LIBRARY_PATH="$library_dir:$DYLD_LIBRARY_PATH"
else
    DYLD_LIBRARY_PATH="$library_dir"
fi
export DYLD_LIBRARY_PATH

msg "Running dynamic loading test program: $program"
msg "Loading libraries from: $library_dir"
"$program"
