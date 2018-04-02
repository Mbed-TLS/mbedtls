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
# To build and test with specific tools, configuration, toolchain and
# set of tests.
#
# Interface
# ---------------------
# This script requires environment variables to identify the config,
# build type and tests. These are:
#   1. MBEDTLS_ROOT     - (mandatory) Toplevel directory.
#   2. CONFIG           - (optional) Argument for config.pl.
#   3. BUILD            - (mutually exclusive with SCRIPT) Build type.
#   4. SCRIPT           - (mutually exclusive with BUILD) Script to run.
#   5. RUN_BASIC_TEST   - (optional) Basic tests.
#   6. RUN_FULL_TEST    - (optional) Full tests = basic + SSL + config.
#
# All the environment variables must be supplied via cienv.sh file that
# this script sources at the start.
#
# There are other environment variables required based on the build and
# tests selected. These are checked under each build type using function
# check_env().
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
# Notes for users
# ---------------
#
# Warning: this script is destructive. The specified build mode and
# configuration can and will arbitrarily change the current CMake
# configuration. After running this script, the CMake cache will
# be lost and CMake will no longer be initialised.
#
# Notes for maintainers
# ---------------------
#
# This script dispatches tests in following order:
#   1. Change to specified configuration. (Optional)
#   2. Run specified build step or script. (Mandatory)
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

msg()
{
    echo ""
    echo "******************************************************************"
    echo "* $1 "
    printf "* "; date
    echo "******************************************************************"
    current_section=$1
}

# remove built files as well as the cmake cache/config
cleanup()
{
    command make clean

    find . -name yotta -prune -o -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} \+
    rm -f include/Makefile include/mbedtls/Makefile programs/*/Makefile
    git update-index --no-skip-worktree Makefile library/Makefile programs/Makefile tests/Makefile
    git checkout -- Makefile library/Makefile programs/Makefile tests/Makefile

    if [ -f "$CONFIG_BAK" ]; then
        mv "$CONFIG_BAK" "$CONFIG_H"
    fi
}


. ./cienv.sh
check_env TEST_NAME MBEDTLS_ROOT
CONFIG_H=$MBEDTLS_ROOT/include/mbedtls/config.h
CONFIG_BAK="$CONFIG_H.bak"

cd ${MBEDTLS_ROOT}

################################################################
#### Change config if specified
################################################################
if [ "X${CONFIG:-X}" != XX ]; then
    if [ "${CONFIG}" = "sslv3" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl set MBEDTLS_SSL_PROTO_SSL3
    elif [ "${CONFIG}" = "no_ssl_renegotiation" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl unset MBEDTLS_SSL_RENEGOTIATION
    elif [ "${CONFIG}" = "full-config-no-mem-backtrace" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl full
        scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE
    elif [ "${CONFIG}" = "full-config-no-std-func-nv-seed" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl full
        scripts/config.pl set MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
        scripts/config.pl unset MBEDTLS_ENTROPY_NV_SEED
    elif [ "${CONFIG}" = "full-config-no-srv" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl full
        scripts/config.pl set MBEDTLS_SSL_SRV_C
    elif [ "${CONFIG}" = "full-config-no-cli" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl full
        scripts/config.pl set MBEDTLS_SSL_CLI_C
    elif [ "${CONFIG}" = "full-config-no-net-entropy" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl full
        scripts/config.pl unset MBEDTLS_NET_C # getaddrinfo() undeclared, etc.
        scripts/config.pl set MBEDTLS_NO_PLATFORM_ENTROPY # uses syscall() on GNU/Linux
    elif [ "${CONFIG}" = "no-max-fragment-len" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl full
        scripts/config.pl unset MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
    elif [ "${CONFIG}" = "test-null-entropy" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl set MBEDTLS_TEST_NULL_ENTROPY
        scripts/config.pl set MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
        scripts/config.pl set MBEDTLS_ENTROPY_C
        scripts/config.pl unset MBEDTLS_ENTROPY_NV_SEED
        scripts/config.pl unset MBEDTLS_ENTROPY_HARDWARE_ALT
        scripts/config.pl unset MBEDTLS_HAVEGE_C

    elif [ "${CONFIG}" = "bignum-limbs" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl unset MBEDTLS_HAVE_ASM
        scripts/config.pl unset MBEDTLS_AESNI_C
        scripts/config.pl unset MBEDTLS_PADLOCK_C

    elif [ "${CONFIG}" = "baremetal" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl full
        scripts/config.pl unset MBEDTLS_NET_C
        scripts/config.pl unset MBEDTLS_TIMING_C
        scripts/config.pl unset MBEDTLS_FS_IO
        scripts/config.pl unset MBEDTLS_ENTROPY_NV_SEED
        scripts/config.pl set MBEDTLS_NO_PLATFORM_ENTROPY
        # following things are not in the default config
        scripts/config.pl unset MBEDTLS_HAVEGE_C # depends on timing.c
        scripts/config.pl unset MBEDTLS_THREADING_PTHREAD
        scripts/config.pl unset MBEDTLS_THREADING_C
        scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # execinfo.h
        scripts/config.pl unset MBEDTLS_MEMORY_BUFFER_ALLOC_C # calls exit

    elif [ "${CONFIG}" = "baremetal-no-udbl" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl full
        scripts/config.pl unset MBEDTLS_NET_C
        scripts/config.pl unset MBEDTLS_TIMING_C
        scripts/config.pl unset MBEDTLS_FS_IO
        scripts/config.pl unset MBEDTLS_ENTROPY_NV_SEED
        scripts/config.pl set MBEDTLS_NO_PLATFORM_ENTROPY
        # following things are not in the default config
        scripts/config.pl unset MBEDTLS_HAVEGE_C # depends on timing.c
        scripts/config.pl unset MBEDTLS_THREADING_PTHREAD
        scripts/config.pl unset MBEDTLS_THREADING_C
        scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # execinfo.h
        scripts/config.pl unset MBEDTLS_MEMORY_BUFFER_ALLOC_C # calls exit
        scripts/config.pl set MBEDTLS_NO_UDBL_DIVISION

    elif [ "${CONFIG}" = "baremetal-for-arm" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl full
        scripts/config.pl unset MBEDTLS_NET_C
        scripts/config.pl unset MBEDTLS_TIMING_C
        scripts/config.pl unset MBEDTLS_FS_IO
        scripts/config.pl unset MBEDTLS_ENTROPY_NV_SEED
        scripts/config.pl unset MBEDTLS_HAVE_TIME
        scripts/config.pl unset MBEDTLS_HAVE_TIME_DATE
        scripts/config.pl set MBEDTLS_NO_PLATFORM_ENTROPY
        # following things are not in the default config
        scripts/config.pl unset MBEDTLS_DEPRECATED_WARNING
        scripts/config.pl unset MBEDTLS_HAVEGE_C # depends on timing.c
        scripts/config.pl unset MBEDTLS_THREADING_PTHREAD
        scripts/config.pl unset MBEDTLS_THREADING_C
        scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # execinfo.h
        scripts/config.pl unset MBEDTLS_MEMORY_BUFFER_ALLOC_C # calls exit
        scripts/config.pl unset MBEDTLS_PLATFORM_TIME_ALT # depends on MBEDTLS_HAVE_TIME

    elif [ "${CONFIG}" = "full-config-no-platform" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl full
        scripts/config.pl unset MBEDTLS_PLATFORM_C
        scripts/config.pl unset MBEDTLS_NET_C
        scripts/config.pl unset MBEDTLS_PLATFORM_MEMORY
        scripts/config.pl unset MBEDTLS_PLATFORM_PRINTF_ALT
        scripts/config.pl unset MBEDTLS_PLATFORM_FPRINTF_ALT
        scripts/config.pl unset MBEDTLS_PLATFORM_SNPRINTF_ALT
        scripts/config.pl unset MBEDTLS_PLATFORM_TIME_ALT
        scripts/config.pl unset MBEDTLS_PLATFORM_EXIT_ALT
        scripts/config.pl unset MBEDTLS_ENTROPY_NV_SEED
        scripts/config.pl unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
        scripts/config.pl unset MBEDTLS_FS_IO
    elif [ "${CONFIG}" = "allow-sha1-in-certs" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl set MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES
    elif [ "${CONFIG}" = "rsa-no-cert" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl set MBEDTLS_RSA_NO_CRT
    elif [ "${CONFIG}" = "memsan" ]; then
        cleanup
        cp "$CONFIG_H" "$CONFIG_BAK"
        scripts/config.pl unset MBEDTLS_AESNI_C
    else
        cleanup
        scripts/config.pl ${CONFIG}
    fi
fi

################################################################
#### Perform build step
################################################################
echo "here"

if [ "X${BUILD:-X}" != XX ]; then
echo "here"
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
        cleanup

        set +e
        grep "fno-sanitize-recover=undefined,integer" CMakeLists.txt
        if [ $? -ne 0 ]
        then
            sed -i s/"fno-sanitize-recover"/"fno-sanitize-recover=undefined,integer"/ CMakeLists.txt
        fi
        set -e

        cmake -D CMAKE_BUILD_TYPE:String=ASan .
        ${MAKE}

    elif [ "$BUILD" = "cmake-memsan" ]; then
        check_env CC MAKE
        cleanup

        cmake -D CMAKE_BUILD_TYPE:String=MemSan .
        ${MAKE}

    elif [ "$BUILD" = "cmake-release" ]; then
        check_env CC MAKE
        cleanup

        cmake -D CMAKE_BUILD_TYPE:String=Release .
        ${MAKE}

    elif [ "$BUILD" = "cmake-out-of-src" ]; then
        cleanup
        MBEDTLS_ROOT_DIR="$PWD"
        mkdir build
        cd build
        cmake "$MBEDTLS_ROOT_DIR"
        make
        msg "test: cmake 'out-of-source' build"
        make test
        cd "$MBEDTLS_ROOT_DIR"
        rm -rf build

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

    elif [ "$BUILD" = "source-checks" ]; then
        cleanup
        msg "test: recursion.pl" # < 1s
        tests/scripts/recursion.pl library/*.c

        msg "test: freshness of generated source files" # < 1s
        tests/scripts/check-generated-files.sh

        msg "test: doxygen markup outside doxygen blocks" # < 1s
        tests/scripts/check-doxy-blocks.pl

        msg "test/build: declared and exported names" # < 3s
        cleanup
        tests/scripts/check-names.sh

        msg "test: doxygen warnings" # ~ 3s
        cleanup
        tests/scripts/doxygen.sh
        cleanup
    elif [ "$BUILD" = "cmake-debug" ]; then
        cleanup
        cmake -D CMAKE_BUILD_TYPE:String=Debug .

    elif [ "$BUILD" = "make-full-config" ]; then
        cleanup
        make CC=gcc CFLAGS='-Werror -Wall -Wextra -std=c99 -pedantic -O0 -D_DEFAULT_SOURCE' lib programs
        make CC=gcc CFLAGS='-Werror -Wall -Wextra -O0' test

    elif [ "$BUILD" = "make-lib" ]; then
        cleanup
        ${MAKE} lib

    elif [ "$BUILD" = "make-lib-programs" ]; then
        cleanup
        ${MAKE} lib programs

    elif [ "$BUILD" = "make-tests" ]; then
        cleanup
        ${MAKE}
        ${MAKE} tests

    elif [ "$BUILD" = "make-shared" ]; then
        check_env CC MAKE
        if uname -a | grep -F Linux >/dev/null; then
            msg "build/test: make shared" # ~ 40s
            cleanup
            ${MAKE} SHARED=1 all check
        fi

    elif [ "$BUILD" = "make-i386" ]; then
        check_env CC MAKE
        if uname -a | grep -F Linux >/dev/null; then
            msg "build/test: make shared" # ~ 40s
            cleanup
            ${MAKE} SHARED=1 all check
        fi

    elif [ "$BUILD" = "make-on-x64" ]; then
        check_env CC MAKE CFLAGS

        if uname -a | grep -F x86_64 >/dev/null; then
            msg "build: i386, make, gcc" # ~ 30s
            cleanup
            ${MAKE} CC=${CC} CFLAGS=${CFLAGS}
        fi # x86_64

    else
        echo "Error: Unknown build \"$BUILD\"!"
        exit 1
    fi
elif [ "X${SCRIPT:-X}" != XX ]; then
    $SCRIPT
else
    echo "Error: Neither BUILD nor SCRIPT defined!"
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

if [ "$RUN_SSL_OPT_TEST" = "1" ]; then
    export SEED=1
    ./tests/ssl-opt.sh
fi

if [ "$RUN_SSL_OPT_SHA1_TEST" = "1" ]; then
    ./tests/ssl-opt.sh -f SHA-1
fi

if [ "$RUN_COMPAT_TEST" = "1" ]; then
    export SEED=1
    tests/compat.sh
fi

if [ "$RUN_COMPAT_RC4_DES_NULL_TEST" = "1" ]; then
    export SEED=1
    OPENSSL_CMD="$OPENSSL_LEGACY" GNUTLS_CLI="$GNUTLS_LEGACY_CLI" GNUTLS_SERV="$GNUTLS_LEGACY_SERV" tests/compat.sh -e '3DES\|DES-CBC3' -f 'NULL\|DES\|RC4\|ARCFOUR'
fi

if [ "$RUN_SSLV3_TEST" = "1" ]; then
    export SEED=1
    msg "test: SSLv3 - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "build: SSLv3 - compat.sh (ASan build)" # ~ 6 min
    ./tests/compat.sh -m 'tls1 tls1_1 tls1_2 dtls1 dtls1_2'
    OPENSSL_CMD="$OPENSSL_LEGACY" tests/compat.sh -m 'ssl3'

    msg "build: SSLv3 - ssl-opt.sh (ASan build)" # ~ 6 min
    ./tests/ssl-opt.sh
fi

if [ "$RUN_CURVES_TEST" = "1" ]; then
    tests/scripts/curves.pl
fi

if [ "$RUN_KEYEXCHANGES_TEST" = "1" ]; then
    tests/scripts/key-exchanges.pl
fi

if [ "$RUN_NO_64BIT_DIV_TEST" = "1" ]; then
    ! grep __aeabi_uldiv library/*.o
fi

if [ "$RUN_MEMCHECK_TEST" = "1" ]; then
    make memcheck
fi

if [ "$RUN_ARMC6_BUILD_TESTS_TEST" = "1" ]; then
    # ARM Compiler 6 - Target ARMv7-A
    armc6_build_test "--target=arm-arm-none-eabi -march=armv7-a"

    # ARM Compiler 6 - Target ARMv7-M
    armc6_build_test "--target=arm-arm-none-eabi -march=armv7-m"

    # ARM Compiler 6 - Target ARMv8-A - AArch32
    armc6_build_test "--target=arm-arm-none-eabi -march=armv8.2-a"

    # ARM Compiler 6 - Target ARMv8-M
    armc6_build_test "--target=arm-arm-none-eabi -march=armv8-m.main"

    # ARM Compiler 6 - Target ARMv8-A - AArch64
    armc6_build_test "--target=aarch64-arm-none-eabi -march=armv8.2-a"
fi

