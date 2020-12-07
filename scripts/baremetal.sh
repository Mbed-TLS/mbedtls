#!/bin/sh

# baremetal.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2019, ARM Limited, All Rights Reserved
#
# Purpose
#
# * Create a baremetal library-only build (omitting the tests and
#   example programs, which have stronger configuration requirements)
#   for a Cortex-M target in a minimal configuration, and generate
#   code-size statistics.
#   By default, the script uses configs/baremetal.h and targets Cortex-M0+,
#   and outputs the code-size statistics as `rom.COMMIT_HASH`.
#
# * Create a 32-bit host-build of library, tests and example programs
#   in a 'baremetal' base configuration minimally modified to allow
#   running tests and example programs, and obtain heap usage statistics
#   of a test run of ssl_client2 and ssl_server2. This can be used as
#   an estimate for heap usage of 32-bit baremetal applications using Mbed TLS.
#
#   By default, the script uses configs/baremetal.h as the base configuration
#   modified by configs/baremetal_test.h, and emits the heap usage statistics
#   as `massif.COMMIT_HASH`.
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

# The 'baremetal' configuration to test
: ${BAREMETAL_CONFIG:=./configs/baremetal.h}
CFLAGS_CONFIG="-DMBEDTLS_CONFIG_FILE='\"../$BAREMETAL_CONFIG\"'"

# The modifications to the 'baremetal' configuration which allows
# tests and example programs to build and execute.
: ${BAREMETAL_USER_CONFIG:=./configs/baremetal_test.h}
CFLAGS_USER_CONFIG="-DMBEDTLS_USER_CONFIG_FILE='\"../$BAREMETAL_USER_CONFIG\"'"

: ${ARMC5_BIN_DIR:=""}
: ${ARMC6_BIN_DIR:=""}
if [ -n "$ARMC5_BIN_DIR" ]; then
   ARMC5_BIN_DIR="$ARMC5_BIN_DIR/"
fi

if [ -n "$ARMC6_BIN_DIR" ]; then
   ARMC6_BIN_DIR="$ARMC6_BIN_DIR/"
fi

: ${NAME:=$(git rev-parse HEAD)}
: ${GCC_CC:=arm-none-eabi-gcc}
: ${GCC_AR:=arm-none-eabi-ar}
: ${ARMC6_CC:="${ARMC6_BIN_DIR}armclang"}
: ${ARMC6_AR:="${ARMC6_BIN_DIR}armar"}
: ${ARMC5_CC:="${ARMC5_BIN_DIR}armcc"}
: ${ARMC5_AR:="${ARMC5_BIN_DIR}armar"}

date=$( date +%Y-%m-%d-%H-%M-%S )

print_rom_report()
{
    echo "ROM statistics written to:"
    echo "* $ROM_OUT_FILE"
    echo "* $ROM_OUT_SYMS"

    <$ROM_OUT_FILE awk '$4 ~ /libmbedcrypto/ {printf("%15s: %5s Bytes\n", $4, $5)}'
    <$ROM_OUT_FILE awk '$4 ~ /libmbedx509/   {printf("%15s: %5s Bytes\n", $4, $5)}'
    <$ROM_OUT_FILE awk '$4 ~ /libmbedtls/    {printf("%15s: %5s Bytes\n", $4, $5)}'
    <$ROM_OUT_FILE awk '$4 ~ /libmbed/ {sum += $5} END {printf("%15s: %5d Bytes\n", "total", sum)}'
}

baremetal_build_gcc()
{
    echo "Cleanup..."
    make clean

    echo "Create 32-bit library-only baremetal build (GCC, config: $BAREMETAL_CONFIG)"
    gcc_ver=$($GCC_CC --version | head -n 1 | sed -n 's/^.*\([0-9]\.[0-9]\.[0-9]\).*$/\1/p')

    if [ $debug -eq 0 ]; then
        OPTIM_CFLAGS_GCC="-Os"
    else
        OPTIM_CFLAGS_GCC="-g"
    fi

    CFLAGS_BAREMETAL="$OPTIM_CFLAGS_GCC -mthumb -mcpu=cortex-m0plus --std=c99"
    if [ $check -ne 0 ]; then
        CFLAGS_BAREMETAL="$CFLAGS_BAREMETAL -Werror"
    fi
    CFLAGS="$CFLAGS_BAREMETAL $CFLAGS_CONFIG -DENABLE_TESTS"

    echo "GCC version: $gcc_ver"
    echo "Flags: $CFLAGS_BAREMETAL"
    make CC=$GCC_CC AR=$GCC_AR CFLAGS="$CFLAGS" lib -j > /dev/null

    if [ $check -ne 0 ]; then
        return
    fi

    ROM_OUT_FILE="rom_files__${date}__${NAME}__gcc_${gcc_ver}"
    ROM_OUT_SYMS="rom_syms__${date}__${NAME}__gcc_${gcc_ver}"
    echo "Generate file statistics..."
    ./scripts/extract_codesize_stats.sh --info "gcc_${gcc_ver}" --name $NAME --files > $ROM_OUT_FILE
    echo "Generate symbol statistics..."
    ./scripts/extract_codesize_stats.sh --info "gcc_${gcc_ver}" --name $NAME --syms > $ROM_OUT_SYMS

    print_rom_report
}

baremetal_build_armc5()
{
    echo "Cleanup..."
    make clean

    echo "Create 32-bit library-only baremetal build (ARMC5, Config: $BAREMETAL_CONFIG)"
    armc5_ver=$($ARMC5_CC | sed -n 's/.*ARM Compiler \([^ ]*\)$/\1/p')

    if [ $debug -eq 0 ]; then
        OPTIM_CFLAGS_ARMC5="-Ospace"
    else
        OPTIM_CFLAGS_ARMC5="-g"
    fi

    CFLAGS_BAREMETAL="$OPTIM_CFLAGS_ARMC5 --thumb --cpu Cortex-m0plus"
    CFLAGS="$CFLAGS_BAREMETAL $CFLAGS_CONFIG -DENABLE_TESTS"
    WARNING_CFLAGS="--strict --c99"

    if [ $check -ne 0 ]; then
        WARNING_CFLAGS="$WARNING_CFLAGS --diag_error=warning"
    fi

    echo "ARMC5 version: $armc5_ver"
    echo "Flags: $WARNING_CFLAGS $CFLAGS_BAREMETAL"
    make WARNING_CFLAGS="$WARNING_CFLAGS" CC=$ARMC5_CC AR=$ARMC5_AR CFLAGS="$CFLAGS" lib -j > /dev/null

    if [ $check -ne 0 ]; then
        return
    fi

    ROM_OUT_FILE="rom_files__${date}__${NAME}__armc5_${armc5_ver}"
    ROM_OUT_SYMS="rom_syms__${date}__${NAME}__armc5_${armc5_ver}"
    echo "Generate file statistics..."
    ./scripts/extract_codesize_stats.sh --info "armc5_${armc5_ver}" --name $NAME --files > $ROM_OUT_FILE
    echo "Generate symbol statistics..."
    ./scripts/extract_codesize_stats.sh --info "armc5_${armc5_ver}" --name $NAME --syms > $ROM_OUT_SYMS

    print_rom_report
}

baremetal_build_armc6()
{
    echo "Cleanup..."
    make clean

    echo "Create 32-bit library-only baremetal build (ARMC6, Config: $BAREMETAL_CONFIG)"
    armc6_ver=$($ARMC6_CC --version | sed -n 's/.*ARM Compiler \([^ ]*\)$/\1/p')

    if [ $debug -eq 0 ]; then
        OPTIM_CFLAGS_ARMC6="-Oz"
    else
        OPTIM_CFLAGS_ARMC6="-g"
    fi

    CFLAGS_BAREMETAL="$OPTIM_CFLAGS_ARMC6 --target=arm-arm-none-eabi -mthumb -mcpu=cortex-m0plus -xc --std=c99"
    if [ $check -ne 0 ]; then
        CFLAGS_BAREMETAL="$CFLAGS_BAREMETAL -Werror"
    fi
    CFLAGS="$CFLAGS_BAREMETAL $CFLAGS_CONFIG -DENABLE_TESTS"

    echo "ARMC6 version: $armc6_ver"
    echo "Flags: $CFLAGS_BAREMETAL"
    make CC=$ARMC6_CC AR=$ARMC6_AR CFLAGS="$CFLAGS" lib -j > /dev/null

    if [ $check -ne 0 ]; then
        return
    fi

    ROM_OUT_FILE="rom_files__${date}__${NAME}__armc6_${armc6_ver}"
    ROM_OUT_SYMS="rom_syms__${date}__${NAME}__armc6_${armc6_ver}"
    echo "Generate file statistics..."
    ./scripts/extract_codesize_stats.sh --info "armc6_${armc6_ver}" --name $NAME --files > $ROM_OUT_FILE
    echo "Generate symbol statistics..."
    ./scripts/extract_codesize_stats.sh --info "armc6_${armc6_ver}" --name $NAME --syms > $ROM_OUT_SYMS

    print_rom_report
}

# 32-bit host-build of library, tests and example programs,
# + heap usage measurements.
baremetal_ram_build() {
    : ${BASE_CFLAGS:="-g -m32 -fstack-usage"}
    echo "Create 32-bit host-build (Config: $BAREMETAL_CONFIG + $BAREMETAL_USER_CONFIG)"

    echo "Cleanup..."
    make clean

    CFLAGS="$BASE_CFLAGS $CFLAGS_CONFIG $CFLAGS_USER_CONFIG -DENABLE_TESTS"
    if [ "$build_only" -eq 1 ]; then
        CFLAGS="$CFLAGS -Werror"
    fi

    echo "Modifications: $BAREMETAL_USER_CONFIG"
    cat $BAREMETAL_USER_CONFIG | grep "^#define" | awk '{print "* " $0 }'

    echo "Build (flags: $CFLAGS)..."
    make CFLAGS="$CFLAGS" -j > /dev/null
    echo ""
}

# usage:
# - `baremetal_ram_heap 0` for heap usage only
# - `baremetal_ram_heap 1` for heap and stack usage
baremetal_ram_heap() {

    : ${CLI:=./programs/ssl/ssl_client2}
    : ${CLI_PARAMS:="dtls=1 cid=1 cid_val=beef"}
    : ${SRV:=./programs/ssl/ssl_server2}
    : ${SRV_PARAMS:="dtls=1 cid=1 cid_val=dead"} # renegotiation=1 auth_mode=required implicit
                                                 # compile-time hardcoding of configuration
    : ${VALGRIND:=valgrind}
    : ${VALGRIND_MASSIF_PARAMS="--time-unit=B --threshold=0.01 --detailed-freq=1"}

    if [ $1 -eq 1 ]; then
        RAM_HEAP_OUT="ram_heap_stack__${date}__$NAME"
        VALGRIND_MASSIF_PARAMS="--stacks=yes $VALGRIND_MASSIF_PARAMS"
    else
        RAM_HEAP_OUT="ram_heap__${date}__$NAME"
    fi

    SRV_CMD="$SRV server_addr=127.0.0.1 server_port=4433 debug_level=4 $SRV_PARAMS"
    CLI_CMD="$CLI server_addr=127.0.0.1 server_port=4433 $CLI_PARAMS"

    # Piece together valgrind cmd line
    VALGRIND_BASE="$VALGRIND --tool=massif $VALGRIND_MASSIF_PARAMS"

    FUNC_IGNORE=""
    FUNC_IGNORE="__fopen_internal            $FUNC_IGNORE"
    FUNC_IGNORE="_IO_file_doallocate         $FUNC_IGNORE"
    FUNC_IGNORE="strdup                      $FUNC_IGNORE"
    FUNC_IGNORE="__tzstring_len              $FUNC_IGNORE"
    FUNC_IGNORE="__tzfile_read               $FUNC_IGNORE"

    VALGRIND_IGNORE=""
    for func in $FUNC_IGNORE; do
        echo "* Valgrind ignore: $func"
        VALGRIND_IGNORE="--ignore-fn=$func $VALGRIND_IGNORE"
    done

    VALGRIND_CMD="$VALGRIND_BASE $VALGRIND_IGNORE --massif-out-file=${RAM_HEAP_OUT} -- $CLI_CMD"

    $SRV_CMD  > /dev/null 2>&1 &
    SRV_PID=$!
    echo "Server started, PID $SRV_PID"

    $VALGRIND_CMD > /dev/null 2>&1 &
    VAL_PID=$!
    echo "Valgrind massif started, PID $VAL_PID"

    wait $VAL_PID
    echo "Valgrind done, killing server"
    kill $SRV_PID
    echo "Done"

    if `cat $RAM_HEAP_OUT | grep '???'` >/dev/null 2>&1; then
        echo "Warning: Unrecognized symbols in massif output file - does your version of `valgrind` support 32-bit builds?"
    fi

    printf "Max heap usage: "
    ./scripts/massif_max.pl $RAM_HEAP_OUT
    echo "SUCCESS - Heap usage statistics written to: $RAM_HEAP_OUT\n"
}

baremetal_ram_stack() {
    : ${CLI:=./programs/ssl/ssl_client2}
    : ${CLI_PARAMS:="dtls=1"}
    : ${SRV:=./programs/ssl/ssl_server2}
    : ${SRV_PARAMS:="dtls=1"} # renegotiation=1 auth_mode=required implicit
                              # compile-time hardcoding of configuration
    : ${VALGRIND:=valgrind}
    : ${VALGRIND_CALLGRIND_PARAMS:="--separate-callers=100"}

    RAM_CALLGRIND_OUT="ram_callgrind__${date}__$NAME"
    RAM_STACK_OUT="ram_stack__${date}__$NAME"

    SRV_CMD="$SRV server_addr=127.0.0.1 server_port=4433 debug_level=4 $SRV_PARAMS"
    CLI_CMD="$CLI server_addr=127.0.0.1 server_port=4433 $CLI_PARAMS"

    VALGRIND_BASE="$VALGRIND --tool=callgrind $VALGRIND_CALLGRIND_PARAMS"
    VALGRIND_CMD="$VALGRIND_BASE --callgrind-out-file=${RAM_CALLGRIND_OUT} $CLI_CMD"

    $SRV_CMD  > /dev/null 2>&1 &
    SRV_PID=$!
    echo "Server started, PID $SRV_PID"

    $VALGRIND_CMD > /dev/null 2>&1 &
    VAL_PID=$!
    echo "Valgrind callgrind started, PID $VAL_PID"

    wait $VAL_PID
    echo "Valgrind done, killing server"
    kill $SRV_PID
    echo "Done"

    # Extract callgraphs from source files directly
    RAM_CALLGRAPH_OUT=""
    if [ -x "$(command -v cflow)" ]; then
        RAM_CALLGRAPH_OUT="ram_cflow__${date}__$NAME"
        cflow library/*.c > $RAM_CALLGRAPH_OUT 2> /dev/null
    fi

    # Merge stack usage files
    cat library/*.su > ${RAM_STACK_OUT}_unsorted
    sort -r -k2 -n ${RAM_STACK_OUT}_unsorted > $RAM_STACK_OUT
    rm ${RAM_STACK_OUT}_unsorted

    echo "SUCCESS"
    echo "* Stack usage statistics written to $RAM_STACK_OUT"
    echo "* Callgrind output written to $RAM_CALLGRIND_OUT"
    if [ -n $RAM_CALLGRAPH_OUT ]; then
        echo "* Static call graph written to $RAM_CALLGRAPH_OUT"
    fi
}

show_usage() {
    echo "Usage: $0 [--rom [--check] [--gcc] [--armc5] [--armc6]|--ram [--build-only] [--stack] [--heap]]"
}

test_build=0
raw_build=0

build_gcc=0
build_armc5=0
build_armc6=0

measure_heap=0
measure_stack=0

check=0
build_only=0
debug=0

while [ $# -gt 0 ]; do
    case "$1" in
        --gcc)   build_gcc=1;;
        --armc5) build_armc5=1;;
        --armc6) build_armc6=1;;
        --ram) test_build=1;;
        --rom) raw_build=1;;
        --build-only) build_only=1;;
        --heap)  measure_heap=1;;
        --stack) measure_stack=1;;
        --check) check=1;;
        --debug) debug=1;;
        -*)
            echo >&2 "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
    shift
done

if [ "$test_build" -eq 0 ] &&
       [ "$raw_build"  -eq 0 ]; then
    echo "Need to set either --ram or --rom"
    show_usage
    exit 1
fi

if [ "$test_build" -eq 1 ]; then

    if [ "$measure_heap"   -eq 0 ] &&
       [ "$measure_stack"  -eq 0 ] &&
       [ "$build_only"     -eq 0 ]; then
        echo "Need to set either --build-only, --heap or --stack with --ram"
        show_usage
        exit 1
    fi

    baremetal_ram_build

    if [ "$measure_heap" -eq 1 ]; then
        baremetal_ram_heap 0
        baremetal_ram_heap 1
    fi

    if [ "$measure_stack" -eq 1 ]; then
        baremetal_ram_stack
    fi

fi

if [ "$raw_build" -eq 1 ]; then

    if [ "$build_gcc"   -eq 0 ] &&
       [ "$build_armc5" -eq 0 ] &&
       [ "$build_armc6" -eq 0 ]; then
        echo "Need to set either --gcc, --armc5 or --armc6 with --rom"
        show_usage
        exit 1
    fi

    if [ "$build_gcc" -eq 1 ]; then
        baremetal_build_gcc
    fi
    if [ "$build_armc5" -eq 1 ]; then
        baremetal_build_armc5
    fi
    if [ "$build_armc6" -eq 1 ]; then
        baremetal_build_armc6
    fi
fi
