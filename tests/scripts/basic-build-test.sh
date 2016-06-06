#!/bin/sh

# basic-build-tests.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2016, ARM Limited, All Rights Reserved
#
# Purpose
#
# Executes the basic test suites, captures the results, and generates a simple
# test report and code coverage report.
#
# The tests include:
#   * Self-tests                - executed using program/test/selftest
#   * Unit tests                - executed using tests/scripts/run-test-suite.pl
#   * System tests              - executed using tests/ssl-opt.sh
#   * Interoperability tests    - executed using tests/compat.sh
#
# The tests focus on functionality and do not consider performance.
#
# Note the tests self-adapt due to configurations in include/mbedtls/config.h
# which can lead to some tests being skipped, and can cause the number of
# available self-tests to fluctuate.
#
# This script has been written to be generic and should work on any shell.
#
# Usage: basic-build-tests.sh
#

# Abort on errors (and uninitiliased variables)
set -eu

if [ -d library -a -d include -a -d tests ]; then :; else
    echo "Must be run from mbed TLS root" >&2
    exit 1
fi

CONFIG_H='include/mbedtls/config.h'
CONFIG_BAK="$CONFIG_H.bak"

# Step 1 - Make and instrumented build for code coverage
export CFLAGS=' --coverage -g3 -O0 '
make clean
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE
make -j


# Step 2 - Execute the tests
TEST_OUTPUT=out_${PPID}
cd tests

# Step 2a - Self-tests
../programs/test/selftest |tee self-test-$TEST_OUTPUT
echo

# Step 2b - Unit Tests
perl scripts/run-test-suites.pl -v |tee unit-test-$TEST_OUTPUT
echo

# Step 2c - System Tests
sh ssl-opt.sh |tee sys-test-$TEST_OUTPUT
echo

# Step 2d - Compatibility tests
sh compat.sh |tee compat-test-$TEST_OUTPUT
echo

# Step 3 - Process the coverage report
cd ..
make lcov |tee tests/cov-$TEST_OUTPUT


# Step 4 - Summarise the test report
echo
echo "========================================================================="
echo "Test Report Summary"
echo

cd tests

# Step 4a - Self-tests
echo "Self tests - ./programs/test/selftest"

PASSED_TESTS=$(grep 'passed' self-test-$TEST_OUTPUT |wc -l)
FAILED_TESTS=$(grep 'failed' self-test-$TEST_OUTPUT |wc -l)
AVAIL_TESTS=$(($PASSED_TESTS + $FAILED_TESTS))
EXED_TESTS=$(($PASSED_TESTS + $FAILED_TESTS))

echo "Passed             : $PASSED_TESTS"
echo "Failed             : $FAILED_TESTS"
echo "Skipped            : n/a"
echo "Total tests        : $AVAIL_TESTS"
echo

TOTAL_PASS=$PASSED_TESTS
TOTAL_FAIL=$FAILED_TESTS
TOTAL_SKIP=0
TOTAL_AVAIL=$(($PASSED_TESTS + $FAILED_TESTS))
TOTAL_EXED=$(($PASSED_TESTS + $FAILED_TESTS))


# Step 4b - Unit tests
echo "Unit tests - tests/scripts/run-test-suites.pl"

PASSED_TESTS=$(tail -n6 unit-test-$TEST_OUTPUT|sed -n -e 's/test cases passed :[\t]*\([0-9]*\)/\1/p'| tr -d ' ')
SKIPPED_TESTS=$(tail -n6 unit-test-$TEST_OUTPUT|sed -n -e 's/skipped :[ \t]*\([0-9]*\)/\1/p'| tr -d ' ')
TOTAL_SUITES=$(tail -n6 unit-test-$TEST_OUTPUT|sed -n -e 's/.* (\([0-9]*\) .*, [0-9]* tests run)/\1/p'| tr -d ' ')
FAILED_TESTS=$(tail -n6 unit-test-$TEST_OUTPUT|sed -n -e 's/failed :[\t]*\([0-9]*\)/\1/p' |tr -d ' ')

echo "No test suites     : $TOTAL_SUITES"
echo "Passed             : $PASSED_TESTS"
echo "Failed             : $FAILED_TESTS"
echo "Skipped            : $SKIPPED_TESTS"
echo "Total exec'd tests : $(($PASSED_TESTS + $FAILED_TESTS))"
echo "Total avail tests  : $(($PASSED_TESTS + $FAILED_TESTS + $SKIPPED_TESTS))"
echo

TOTAL_PASS=$(($TOTAL_PASS+$PASSED_TESTS))
TOTAL_FAIL=$(($TOTAL_FAIL+$FAILED_TESTS))
TOTAL_SKIP=$(($TOTAL_SKIP+$SKIPPED_TESTS))
TOTAL_AVAIL=$(($TOTAL_AVAIL + $PASSED_TESTS + $FAILED_TESTS + $SKIPPED_TESTS))
TOTAL_EXED=$(($TOTAL_EXED + $PASSED_TESTS + $FAILED_TESTS))


# Step 4c - TLS Options tests
echo "TLS Options tests - tests/ssl-opt.sh"

PASSED_TESTS=$(tail -n5 sys-test-$TEST_OUTPUT|sed -n -e 's/.* (\([0-9]*\) \/ [0-9]* tests ([0-9]* skipped))$/\1/p')
SKIPPED_TESTS=$(tail -n5 sys-test-$TEST_OUTPUT|sed -n -e 's/.* ([0-9]* \/ [0-9]* tests (\([0-9]*\) skipped))$/\1/p')
TOTAL_TESTS=$(tail -n5 sys-test-$TEST_OUTPUT|sed -n -e 's/.* ([0-9]* \/ \([0-9]*\) tests ([0-9]* skipped))$/\1/p')
FAILED_TESTS=$(($TOTAL_TESTS - $PASSED_TESTS))

echo "Passed             : $PASSED_TESTS"
echo "Failed             : $FAILED_TESTS"
echo "Skipped            : $SKIPPED_TESTS"
echo "Total exec'd tests : $TOTAL_TESTS"
echo "Total avail tests  : $(($TOTAL_TESTS + $SKIPPED_TESTS))"
echo

TOTAL_PASS=$(($TOTAL_PASS+$PASSED_TESTS))
TOTAL_FAIL=$(($TOTAL_FAIL+$FAILED_TESTS))
TOTAL_SKIP=$(($TOTAL_SKIP+$SKIPPED_TESTS))
TOTAL_AVAIL=$(($TOTAL_AVAIL + $TOTAL_TESTS + $SKIPPED_TESTS))
TOTAL_EXED=$(($TOTAL_EXED + $TOTAL_TESTS))


# Step 4d - System Compatibility tests
echo "System/Compatibility tests - tests/compat.sh"

PASSED_TESTS=$(tail -n5 compat-test-$TEST_OUTPUT|sed -n -e 's/.* (\([0-9]*\) \/ [0-9]* tests ([0-9]* skipped))$/\1/p')
SKIPPED_TESTS=$(tail -n5 compat-test-$TEST_OUTPUT|sed -n -e 's/.* ([0-9]* \/ [0-9]* tests (\([0-9]*\) skipped))$/\1/p')
EXED_TESTS=$(tail -n5 compat-test-$TEST_OUTPUT|sed -n -e 's/.* ([0-9]* \/ \([0-9]*\) tests ([0-9]* skipped))$/\1/p')
FAILED_TESTS=$(($EXED_TESTS - $PASSED_TESTS))

echo "Passed             : $PASSED_TESTS"
echo "Failed             : $FAILED_TESTS"
echo "Skipped            : $SKIPPED_TESTS"
echo "Total exec'd tests : $EXED_TESTS"
echo "Total avail tests  : $(($EXED_TESTS + $SKIPPED_TESTS))"
echo

TOTAL_PASS=$(($TOTAL_PASS+$PASSED_TESTS))
TOTAL_FAIL=$(($TOTAL_FAIL+$FAILED_TESTS))
TOTAL_SKIP=$(($TOTAL_SKIP+$SKIPPED_TESTS))
TOTAL_AVAIL=$(($TOTAL_AVAIL + $EXED_TESTS + $SKIPPED_TESTS))
TOTAL_EXED=$(($TOTAL_EXED + $EXED_TESTS))


# Step 4e - Grand totals
echo "-------------------------------------------------------------------------"
echo "Total tests"

echo "Total Passed       : $TOTAL_PASS"
echo "Total Failed       : $TOTAL_FAIL"
echo "Total Skipped      : $TOTAL_SKIP"
echo "Total exec'd tests : $TOTAL_EXED"
echo "Total avail tests  : $TOTAL_AVAIL"
echo


# Step 4f - Coverage
echo "Coverage"

LINES_TESTED=$(tail -n3 cov-$TEST_OUTPUT|sed -n -e 's/  lines......: [0-9]*.[0-9]% (\([0-9]*\) of [0-9]* lines)/\1/p')
LINES_TOTAL=$(tail -n3 cov-$TEST_OUTPUT|sed -n -e 's/  lines......: [0-9]*.[0-9]% ([0-9]* of \([0-9]*\) lines)/\1/p')
FUNCS_TESTED=$(tail -n3 cov-$TEST_OUTPUT|sed -n -e 's/  functions..: [0-9]*.[0-9]% (\([0-9]*\) of [0-9]* functions)$/\1/p')
FUNCS_TOTAL=$(tail -n3 cov-$TEST_OUTPUT|sed -n -e 's/  functions..: [0-9]*.[0-9]% ([0-9]* of \([0-9]*\) functions)$/\1/p')

LINES_PERCENT=$((1000*$LINES_TESTED/$LINES_TOTAL))
LINES_PERCENT="$(($LINES_PERCENT/10)).$(($LINES_PERCENT-($LINES_PERCENT/10)*10))"

FUNCS_PERCENT=$((1000*$FUNCS_TESTED/$FUNCS_TOTAL))
FUNCS_PERCENT="$(($FUNCS_PERCENT/10)).$(($FUNCS_PERCENT-($FUNCS_PERCENT/10)*10))"

echo "Lines Tested       : $LINES_TESTED of $LINES_TOTAL $LINES_PERCENT%"
echo "Functions Tested   : $FUNCS_TESTED of $FUNCS_TOTAL $FUNCS_PERCENT%"
echo


rm self-test-$TEST_OUTPUT
rm unit-test-$TEST_OUTPUT
rm sys-test-$TEST_OUTPUT
rm compat-test-$TEST_OUTPUT
rm cov-$TEST_OUTPUT

cd ..

make clean

if [ -f "$CONFIG_BAK" ]; then
    mv "$CONFIG_BAK" "$CONFIG_H"
fi
