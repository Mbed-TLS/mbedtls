#! /usr/bin/env sh

# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2018, ARM Limited, All Rights Reserved
#
# Purpose
#
# Check if generated files are up-to-date.

set -eu

if [ -d library -a -d include -a -d tests ]; then :; else
    echo "Must be run from mbed TLS root" >&2
    exit 1
fi

# usage:
# - check script file1 [file2 [...]]
# - check script directory
check()
{
    SCRIPT=$1
    TO_CHECK=$2
    shift;
    FILES="$@"

    if [ -d $TO_CHECK ]; then
        FILES=""
        for FILE in $TO_CHECK/*; do
            FILES="$FILE $FILES"
        done
    fi

    for FILE in $FILES; do
        cp $FILE $FILE.bak
    done

    $SCRIPT

    # Compare the script output to the old files and remove backups
    PATTERN=""
    for FILE in $FILES; do
        if ! diff $FILE $FILE.bak >/dev/null 2>&1; then
            echo "'$FILE' was either modified or deleted by '$SCRIPT'"
            exit 1
        fi
        mv $FILE.bak $FILE

        if [ -d $TO_CHECK ]; then
            # Create a grep regular expression that we can check against the
            # directory contents to test whether new files have been created
            if [ -z $PATTERN ]; then
                PATTERN="$(basename $FILE)"
            else
                PATTERN="$PATTERN\|$(basename $FILE)"
            fi
        fi
    done

    if [ -d $TO_CHECK ]; then
        # Check if there are any new files
        if ls -1 $TO_CHECK | grep -v "$PATTERN" >/dev/null 2>&1; then
            echo "Files were created by '$SCRIPT'"
            exit 1
        fi
    fi
}

check scripts/generate_errors.pl include/mbedtls/error_includes.h include/mbedtls/error_high.h include/mbedtls/error_low.h
check scripts/generate_features.pl include/mbedtls/version_features.h
check scripts/generate_visualc_files.pl visualc/VS2010
