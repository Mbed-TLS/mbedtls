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

# Repository detection
in_mbedtls_build_dir () {
    test -d library
}

# Collect stats and build a HTML report.
lcov_library_report () {
    rm -rf Coverage
    mkdir Coverage Coverage/tmp
    # Pass absolute paths as lcov output files. This works around a bug
    # whereby lcov tries to create the output file in the root directory
    # if it has emitted a warning. A fix was released in lcov 1.13 in 2016.
    # Ubuntu 16.04 is affected, 18.04 and above are not.
    # https://github.com/linux-test-project/lcov/commit/632c25a0d1f5e4d2f4fd5b28ce7c8b86d388c91f
    COVTMP=$PWD/Coverage/tmp
    lcov --capture --initial --directory $library_dir -o "$COVTMP/files.info"
    lcov --rc lcov_branch_coverage=1 --capture --directory $library_dir -o "$COVTMP/tests.info"
    lcov --rc lcov_branch_coverage=1 --add-tracefile "$COVTMP/files.info" --add-tracefile "$COVTMP/tests.info" -o "$COVTMP/all.info"
    lcov --rc lcov_branch_coverage=1 --remove "$COVTMP/all.info" -o "$COVTMP/final.info" '*.h'
    gendesc tests/Descriptions.txt -o "$COVTMP/descriptions"
    genhtml --title "$title" --description-file "$COVTMP/descriptions" --keep-descriptions --legend --branch-coverage -o Coverage "$COVTMP/final.info"
    rm -f "$COVTMP/"*.info "$COVTMP/descriptions"
    echo "Coverage report in: Coverage/index.html"
}

# Reset the traces to 0.
lcov_reset_traces () {
    # Location with plain make
    rm -f $library_dir/*.gcda
    # Location with CMake
    rm -f $library_dir/CMakeFiles/*.dir/*.gcda
}

if [ $# -gt 0 ] && [ "$1" = "--help" ]; then
    help
    exit
fi

if in_mbedtls_build_dir; then
    library_dir='library'
    title='Mbed TLS'
else
    library_dir='core'
    title='TF-PSA-Crypto'
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
