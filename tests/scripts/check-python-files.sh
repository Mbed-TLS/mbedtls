#! /usr/bin/env sh

# This file is part of Mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2018, Arm Limited, All Rights Reserved
#
# Purpose:
#
# Run 'pylint' on Python files for programming errors and helps enforcing
# PEP8 coding standards.

if `hash pylint3 > /dev/null 2>&1`; then
    pylint3 -j 2 tests/scripts/generate_test_code.py
    pylint3 -j 2 tests/scripts/test_generate_test_code.py
    pylint3 -j 2 tests/scripts/mbedtls_test.py
else
    echo "$0: WARNING: 'pylint3' not found! Skipping checks on Python files."
fi
