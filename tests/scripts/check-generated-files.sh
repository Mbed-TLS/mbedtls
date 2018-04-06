#!/bin/sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2012-2016, ARM Limited, All Rights Reserved
#
# Purpose
#
# Verify if project files that are geneated from the source code are different
# from what would be generated, if the script were run again.
#
# The script is non-destructive.
#
# Usage: check-generated-files.sh
#



set -eu

if [ -d library -a -d include -a -d tests ]; then :; else
    echo "Must be run from mbed TLS root" >&2
    exit 1
fi

check()
{
    TARGET=$1
    SCRIPT=$2

    cp -apr $TARGET $TARGET.bak
    $SCRIPT
    diff -r $TARGET $TARGET.bak
    rm -rf $TARGET
    mv $TARGET.bak $TARGET
}

check library/error.c scripts/generate_errors.pl
check library/version_features.c scripts/generate_features.pl
check visualc scripts/generate_visualc_files.pl

