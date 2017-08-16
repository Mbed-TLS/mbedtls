#! /usr/bin/env sh

# ciscript.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2018, ARM Limited, All Rights Reserved



################################################################
#### Documentation
################################################################

# Purpose
# -------
#
# To run a particular build step with specified environment and
# config followed by the specified tests.
#
# Notes for users
# ---------------
#
# Warning: the test is destructive. The specified build mode and
# configuration can and will arbitrarily change the current CMake
# configuration. After running this script, the CMake cache will
# be lost and CMake will no longer be initialised.
#
# Tools required
# ---------------------
# This script assumes the presence of the tools required by the
# scripts it runs. In addition it requires following tools:
#   1. perl - for running config.pl
#   2. make, cmake - build tools
#   3. gcc, clang - compilers
#   4. git
#
# Interface
# ---------------------
# This script requires environment variables to identify config,
# build type and tests. These are:
#   1. MBEDTLS_ROOT     - (mandatory) Toplevel directory.
#   2. BUILD            - (mandatory) Build type. See use below.
#   3. CONFIG           - (optional)  Argument for config.pl.
#   4. RUN_BASIC_TEST   - (optional)  Basic tests.
#   5. RUN_FULL_TEST    - (optional)  Full tests = basic + SSL + config.
#
# All the environment variables must be supplied via cienv.sh file that
# this script sources in the beginning.
#
# There are other environment variables required based on the build and
# tests selected. These are checked under each build type using function
# check_env().
#
# Notes for maintainers
# ---------------------
#
# This script dispatches tests in following order:
#   1. Change to specified configuration. (Optional)
#   2. Run specified build step. (Mandatory)
#   3. Run specified tests. (Optional)
#
# Tests are specified with following environment variables:
#   1. RUN_BASIC_TEST=1
#       * Execute CTest tests
#       * Execute ./programs/test/selftest
#   2. RUN_FULL_TEST=1
#       * Execute basic tests defined above
#       * Execute SSL tests
#       * Execute config tests
#

set -ex

if [ ! -x cienv.sh ]; then
    echo "Error: Environment file cenv.sh does not exists or it is not executable!"
    exit 1
fi

check_env(){
    for var in "$@"
    do
        eval value=\$$var
        if [ -z "${value}" ]; then
            echo "Error: Test $BUILD: Required env var $var not set!"
            exit 1
        fi
    done
}

. ./cienv.sh
check_env BUILD MBEDTLS_ROOT

cd ${MBEDTLS_ROOT}

################################################################
#### Change config if specified
################################################################
if [ -n "$CONFIG" ]; then
    scripts/config.pl ${CONFIG}
fi

################################################################
#### Perform build step
################################################################

if [ "$BUILD" = "make" ]; then
    check_env CC MAKE
    ${MAKE} clean
    ${MAKE}

elif [ "$BUILD" = "cmake" ]; then
    check_env CC MAKE
    cmake -D CMAKE_BUILD_TYPE:String=Check .
    ${MAKE} clean
    ${MAKE}

elif [ "$BUILD" = "cmake-asan" ]; then
    check_env CC MAKE

    set +e
    grep "fno-sanitize-recover=undefined,integer" CMakeLists.txt
    if [ $? -ne 0 ]
    then
        sed -i s/"fno-sanitize-recover"/"fno-sanitize-recover=undefined,integer"/ CMakeLists.txt
    fi
    set -e

    cmake -D CMAKE_BUILD_TYPE:String=ASan .
    ${MAKE}

elif [ "$BUILD" = "all.sh" ]; then

    if [ ! -d .git ]
    then
        git config --global user.email "you@example.com"
        git config --global user.name "Your Name"
        git init
        git add .
        git commit -m "CI code copy"
    fi
    ./tests/scripts/all.sh -r -k --no-yotta

else
    echo "Error: Unknown build \"$BUILD\"!"
    exit 1
fi

################################################################
#### Perform tests
################################################################

if [ "$RUN_BASIC_TEST" = "1" ]; then
    ctest -vv
    ./programs/test/selftest
fi

if [ "$RUN_FULL_TEST" = "1" ]; then
    ctest -vv
    ./programs/test/selftest
    openssl version
    gnutls-serv -v
    export SEED=1
    ./tests/compat.sh
    ./tests/ssl-opt.sh
    ./tests/scripts/test-ref-configs.pl
fi

