#!/bin/sh

help () {
    cat <<EOF
Usage: $0 [-r]
Collect coverage statistics of library code into an HTML report.

General instructions:
1. Build the library with CFLAGS="--coverage -O0 -g3" and link the test
   programs with LDFLAGS="--coverage".
   This can be an out-of-tree build.
   For example (in-tree):
        make CFLAGS="--coverage -O0 -g3" LDFLAGS="--coverage"
   Or (out-of-tree):
        mkdir build-coverage && cd build-coverage &&
        cmake -D CMAKE_BUILD_TYPE=Coverage .. && make
2. Run whatever tests you want.
3. Run this script from the parent of the directory containing the library
   object files and coverage statistics files.
4. Browse the coverage report in Coverage/index.html.
5. After rework, run "$0 -r", then re-test and run "$0" to get a fresh report.

Options
  -r    Reset traces. Run this before re-testing to get fresh measurements.
EOF
}

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

set -eu

# Collect stats and build a HTML report.
lcov_library_report () {
    rm -rf Coverage
    mkdir Coverage Coverage/tmp
    lcov --capture --initial --directory library -o Coverage/tmp/files.info
    lcov --rc lcov_branch_coverage=1 --capture --directory library -o Coverage/tmp/tests.info
    lcov --rc lcov_branch_coverage=1 --add-tracefile Coverage/tmp/files.info --add-tracefile Coverage/tmp/tests.info -o Coverage/tmp/all.info
    lcov --rc lcov_branch_coverage=1 --remove Coverage/tmp/all.info -o Coverage/tmp/final.info '*.h'
    gendesc tests/Descriptions.txt -o Coverage/tmp/descriptions
    genhtml --title "Mbed TLS" --description-file Coverage/tmp/descriptions --keep-descriptions --legend --branch-coverage -o Coverage Coverage/tmp/final.info
    rm -f Coverage/tmp/*.info Coverage/tmp/descriptions
    echo "Coverage report in: Coverage/index.html"
}

# Reset the traces to 0.
lcov_reset_traces () {
    # Location with plain make
    rm -f library/*.gcda
    # Location with CMake
    rm -f library/CMakeFiles/*.dir/*.gcda
}

if [ $# -gt 0 ] && [ "$1" = "--help" ]; then
    help
    exit
fi

main=lcov_library_report
while getopts r OPTLET; do
    case $OPTLET in
        r) main=lcov_reset_traces;;
        *) help 2>&1; exit 120;;
    esac
done
shift $((OPTIND - 1))

"$main" "$@"
