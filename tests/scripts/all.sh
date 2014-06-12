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
}

msg()
{
    echo ""
    echo "******************************************************************"
    echo "* $1"
    echo "******************************************************************"
}

# The test ordering tries to optimize for the following criteria:
# 1. Catch possible problems early, by running first test that run quickly
#    and/or are more likely to fail than others.
# 2. Minimize total running time, by avoiding useless rebuilds
#
# Indicative running times are given for reference.

msg "build: cmake, gcc with lots of warnings" # ~ 1 min
cleanup
CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Check .
make

msg "test: main suites with valgrind" # ~ 2 min 10s
make memcheck

msg "build: with ASan" # ~ 1 min
cleanup
cmake -D CMAKE_BUILD_TYPE:String=ASan .
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

msg "build: cmake, clang with lots of warnings" # ~ 40s
cleanup
CC=clang cmake -D CMAKE_BUILD_TYPE:String=Check .
make

msg "build: Unix make, -O2" # ~ 30s
cleanup
make

# Optional parts that take a long time to run

if [ "$MEMORY" -gt 0 ]; then
    msg "test: ssl-opt --memcheck (-02 build)" # ~ 8 min
    cd tests
    ./ssl-opt.sh --memcheck
    cd ..

    if [ "$MEMORY" -gt 1 ]; then
        msg "test: compat --memcheck (-02 build)" # ~ 42 min
        cd tests
        ./compat.sh --memcheck
        cd ..
    fi
fi

echo "Done."
cleanup

