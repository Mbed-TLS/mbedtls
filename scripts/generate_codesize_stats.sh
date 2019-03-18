#!/bin/sh
# generate_codesize_stats.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2019, ARM Limited, All Rights Reserved
#
# Purpose
#
# Generate static memory usage statistics for an Mbed TLS build.
#

set -eu

if [ -d include/mbedtls ]; then :; else
    echo "$0: must be run from root" >&2
    exit 1
fi

if grep -i cmake Makefile >/dev/null; then
    echo "$0: not compatible with cmake" >&2
    exit 1
fi

BUILD_DIR="./library"

LIBFILES=$( ls $BUILD_DIR/*.a )
OBJFILES=$( ls $BUILD_DIR/*.o )

SUMMARY_ONLY=0
LIMIT=9999

print_usage() {
    echo "\nExtract static memory usage statistics for an Mbed TLS build.\n"
    echo "Usage: $0 [options]"
    echo "  --files\tGenerate per-file code-size statistics."
    echo "  --syms\tGenerate per-symbol code-size statistics."
    echo "  -l|--limit num\tPrint only the largest 'num' symbols of the given type. (Default: $LIMIT) "
    echo "  -h|--help\tPrint this help."
    echo "  -d|--dir=BUILD_DIR\tThe build directory containing the 'library' folder (default: ${BUILD_DIR})"
}

get_options() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -d|--dir)
                shift; BUILD_DIR=$1
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            --files)
                FILE_STATS=1
                ;;
            --syms)
                SYM_STATS=1
                ;;
            -l|--limit)
                shift; LIMIT=$1
                ;;
            -n|--name)
                shift; name=$1
                ;;
            -i|--info)
                shift; info=$1
                ;;
            *)
                echo "Unknown argument: $1"
                print_usage
                exit 1
                ;;
        esac
        shift
    done
}

FILE_STATS=0
SYM_STATS=0
name="unnamed"
info="noinfo"
get_options "$@"

date=$( date +%Y-%m-%d-%H-%M-%S )

report_syms() {
    file=$(basename $1)
    type=$2
    stat=$(nm --line-numbers --radix=d --size-sort --reverse $1 |
                  grep " [$3] "  |
                  sort --reverse |
                  head -n $LIMIT |
                  awk -v type="$type" -v info="$info" -v name="$name" -v date="$date" -v file="$file" \
                      '{ printf( "%10s %42s %12s %20s %8s %6d %s\n", date, name, info, file, type, $1, $3 ); }')
    if [ -n "$stat" ]; then
        echo "$stat"
    fi
}

# Report static memory usage (RAM and ROM)
if [ $FILE_STATS -eq 1 ]; then
    for file_full in $LIBFILES; do
        file=$(basename $file_full)
        size --radix=10 $file_full   |
            sort -s -n -k 1,1        |
            tail -n +2               |
            sed -n '/^[ ]*0/!p'      |
            awk -v info="$info" -v name="$name" -v date="$date" '{ printf( "%10s %42s %12s %20s %6d %6d %6d\n", date, name, info, $6, $1, $2, $3 ); }' |
            awk -v info="$info" -v name="$name" -v date="$date" -v file="$file" '{print $0; sum_text += $5; sum_data += $6; sum_bss += $7}
                             END { printf( "%10s %42s %12s %20s %6d %6d %6d\n\n", date, name, info, file, sum_text, sum_data, sum_bss ); }'
    done
fi

if [ $SYM_STATS -eq 1 ]; then
    SYMTYPES="CODE-tT DATA-dD RODATA-rR BSS-bB"
    for symtype in $SYMTYPES; do
        type=${symtype%*-*}
        specifier=${symtype#*-*}
        for file_full in $OBJFILES; do
            report_syms "$file_full" $type $specifier
        done
    done
fi
