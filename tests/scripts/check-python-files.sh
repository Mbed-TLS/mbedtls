#! /usr/bin/env sh

# This file is part of Mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2018, Arm Limited, All Rights Reserved
#
# Purpose:
#
# Run 'pylint' on Python files for programming errors and helps enforcing
# PEP8 coding standards.

if type python3 >/dev/null 2>/dev/null; then
    PYTHON=python3
else
    PYTHON=python
fi

$PYTHON -m pylint -j 2 scripts/*.py tests/scripts/*.py
