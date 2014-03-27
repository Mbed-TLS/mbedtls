#!/bin/sh

# Run all available tests (mostly).
#
# Warning: includes various build modes, so it will mess with the current
# CMake configuration. After this script is run, the CMake cache is lost and
# CMake is not initialised any more!
#
# Assumes gcc, clang (recent enough for using ASan) are available, as weel as
# cmake. Also assumes valgrind is available if --memcheck is used.

# Abort on errors (and uninitiliased variables)
set -eu

if [ -d library -a -d include -a -d tests ]; then :; else
    echo "Must be run from PolarSSL root" >&2
    exit 1
fi

MEMORY=0

while [ $# -gt 0 ]; do
    case "$1" in
        -m|--memory)
            MEMORY=1
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
    git update-index --no-skip-worktree {.,library,programs,tests}/Makefile
    git checkout -- {.,library,programs,tests}/Makefile
}

msg()
{
    echo ""
    echo "******************************************************************"
    echo "* $1"
    echo "******************************************************************"
}

# Step 1: various build types

msg "Unix make, default compiler and flags"
cleanup
make

msg "cmake, gcc with lots of warnings"
cleanup
CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Check .
make

msg "cmake, clang with lots of warnings"
cleanup
CC=clang cmake -D CMAKE_BUILD_TYPE:String=Check .
make

# Step 2: Full tests, with ASan

msg "ASan build and full tests"
cleanup
cmake -D CMAKE_BUILD_TYPE:String=ASan .
make
make test
programs/test/selftest
cd tests
./compat.sh
./ssl-opt.sh
cd ..
tests/scripts/test-ref-configs.pl

# Step 3: using valgrind's memcheck

if [ "$MEMORY" -gt 0 ] && which valgrind >/dev/null; then
    msg "Release build, full tests with valgrind's memcheck"
    cleanup
    # optimized build to compensate a bit for valgrind slowdown
    cmake -D CMAKE_BUILD_TYPE:String=Release .
    make
    make memcheck
    cd tests
    ./compat.sh --memcheck
    ./ssl-opt.sh --memcheck
    cd ..
    # no test-ref-configs: doesn't have a memcheck option (yet?)
fi

# Done

echo "Done."
cleanup

