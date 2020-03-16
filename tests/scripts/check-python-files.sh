#! /usr/bin/env sh

# This file is part of Mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2018, Arm Limited, All Rights Reserved
#
# Purpose:
#
# Run 'pylint' on Python files for programming errors and helps enforcing
# PEP8 coding standards.

# Find the installed version of Pylint. Installed as a distro package this can
# be pylint3 and as a PEP egg, pylint. We prefer pylint over pylint3
if type pylint >/dev/null 2>/dev/null; then
    PYLINT=pylint
elif type pylint3 >/dev/null 2>/dev/null; then
    PYLINT=pylint3
else
    echo 'Pylint was not found.'
    exit 1
fi

$PYLINT -j 2 scripts/*.py tests/scripts/*.py
