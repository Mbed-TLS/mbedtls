#!/bin/sh

# Run all available tests (mostly).
#
# Warning: includes various build modes, so it will mess with the current
# CMake configuration. After this script is run, the CMake cache is lost and
# CMake is not initialised any more!
#
# Assumes gcc and clang (recent enough for using ASan) are available,
# as well as cmake and valgrind.

# Abort on errors (and uninitiliased variables)
set -eu

if [ -d library -a -d include -a -d tests ]; then :; else
    echo "Must be run from PolarSSL root" >&2
    exit 1
fi

CONFIG_H='include/polarssl/config.h'
CONFIG_BAK="$CONFIG_H.bak"

MEMORY=0

while [ $# -gt 0 ]; do
    case "$1" in
        -m1)
            MEMORY=1
            ;;
        -m2)
            MEMORY=2
            ;;
        *)
            echo "Unknown argument: '$1'" >&2
            echo "Use the source, Luke!" >&2
            exit 1
            ;;
    esac
    shift
done

# remove built files as well as the cmake cache/config
cleanup()
{
    make clean

    find -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} \+
    rm -f include/Makefile include/polarssl/Makefile programs/*/Makefile
    git update-index --no-skip-worktree Makefile library/Makefile programs/Makefile tests/Makefile
    git checkout -- Makefile library/Makefile programs/Makefile tests/Makefile

    if [ -f "$CONFIG_BAK" ]; then
        mv "$CONFIG_BAK" "$CONFIG_H"
    fi
}

trap cleanup INT TERM HUP

msg()
{
    echo ""
    echo "******************************************************************"
    echo "* $1"
    echo "******************************************************************"
}

# The test ordering tries to optimize for the following criteria:
# 1. Catch possible problems early, by running first test that run quickly
#    and/or are more likely to fail than others (eg I use Clang most of the
#    time, so start with a GCC build).
# 2. Minimize total running time, by avoiding useless rebuilds
#
# Indicative running times are given for reference.

msg "build: cmake, -Werror (gcc)" # ~ 1 min
cleanup
CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Check .
make

msg "test: main suites with valgrind" # ~ 2 min 10s
make memcheck

msg "build: with ASan (clang)" # ~ 1 min
cleanup
CC=clang cmake -D CMAKE_BUILD_TYPE:String=ASan .
make

msg "test: ssl-opt.sh (ASan build)" # ~ 1 min 10s
cd tests
./ssl-opt.sh
cd ..

msg "test: main suites and selftest (ASan build)" # ~ 10s + 30s
make test
programs/test/selftest

msg "test: ref-configs (ASan build)" # ~ 4 min 45 s
tests/scripts/test-ref-configs.pl

# Most issues are likely to be caught at this point

msg "build: with ASan (rebuild after ref-configs)" # ~ 1 min
make

msg "test: compat.sh (ASan build)" # ~ 7 min 30s
cd tests
./compat.sh
cd ..

msg "build: cmake, full config" # ~ 40s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset POLARSSL_MEMORY_BACKTRACE # too slow for tests
cmake -D CMAKE_BUILD_TYPE:String=Check .
make

msg "test: main suites (full config)"
make test

msg "test: ssl-opt.sh default (full config)"
cd tests
./ssl-opt.sh -f Default
cd ..

msg "test: compat.sh 3DES & NULL (full config)"
cd tests
./compat.sh -e '^$' -f 'NULL\|3DES-EDE-CBC\|DES-CBC3'
cd ..

msg "build: Unix make, -O2 (gcc)" # ~ 30s
cleanup
CC=gcc make

# Optional parts that take a long time to run

if [ "$MEMORY" -ge 1 ]; then
    msg "test: ssl-opt --memcheck (-02 build)" # ~ 8 min
    cd tests
    ./ssl-opt.sh --memcheck
    cd ..

    if [ "$MEMORY" -ge 2 ]; then
        msg "test: compat --memcheck (-02 build)" # ~ 42 min
        cd tests
        ./compat.sh --memcheck
        cd ..
    fi
fi

echo "Done."
cleanup

