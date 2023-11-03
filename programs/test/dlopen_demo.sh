#!/bin/sh

# Run the shared library dynamic loading demo program.
# This is only expected to work when Mbed TLS is built as a shared library.

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

set -e -u

program_name="dlopen"
program_dir="${0%/*}"
program="$program_dir/$program_name"

if [ ! -e "$program" ]; then
    # Look for programs in the current directory and the directories above it
    for dir in "." ".." "../.."; do
        program_dir="$dir/programs/test"
        program="$program_dir/$program_name"
        if [ -e "$program" ]; then
            break
        fi
    done
    if [ ! -e "$program" ]; then
        echo "Could not find $program_name program"

        echo "Make sure that Mbed TLS is built as a shared library." \
             "If building out-of-tree, this script must be run" \
             "from the project build directory."
        exit 1
    fi
fi

top_dir="$program_dir/../.."
library_dir="$top_dir/library"

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

echo "Running dynamic loading test program: $program"
echo "Loading libraries from: $library_dir"
"$program"
