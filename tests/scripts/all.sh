#! /usr/bin/env sh

# all.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2014-2017, ARM Limited, All Rights Reserved



################################################################
#### Documentation
################################################################

# Purpose
# -------
#
# To run all tests possible or available on the platform.
#
# Notes for users
# ---------------
#
# Warning: the test is destructive. It includes various build modes and
# configurations, and can and will arbitrarily change the current CMake
# configuration. The following files must be committed into git:
#    * include/mbedtls/config.h
#    * Makefile, library/Makefile, programs/Makefile, tests/Makefile
# After running this script, the CMake cache will be lost and CMake
# will no longer be initialised.
#
# The script assumes the presence of a number of tools:
#   * Basic Unix tools (Windows users note: a Unix-style find must be before
#     the Windows find in the PATH)
#   * Perl
#   * GNU Make
#   * CMake
#   * GCC and Clang (recent enough for using ASan with gcc and MemSan with clang, or valgrind)
#   * arm-gcc and mingw-gcc
#   * ArmCC 5 and ArmCC 6, unless invoked with --no-armcc
#   * Yotta build dependencies, unless invoked with --no-yotta
#   * OpenSSL and GnuTLS command line tools, recent enough for the
#     interoperability tests. If they don't support SSLv3 then a legacy
#     version of these tools must be present as well (search for LEGACY
#     below).
# See the invocation of check_tools below for details.
#
# This script must be invoked from the toplevel directory of a git
# working copy of Mbed TLS.
#
# Note that the output is not saved. You may want to run
#   script -c tests/scripts/all.sh
# or
#   tests/scripts/all.sh >all.log 2>&1
#
# Notes for maintainers
# ---------------------
#
# The tests are roughly in order from fastest to slowest. This doesn't
# have to be exact, but in general you should add slower tests towards
# the end and fast checks near the beginning.
#
# Sanity checks have the following form:
#   1. msg "short description of what is about to be done"
#   2. run sanity check (failure stops the script)
#
# Build or build-and-test steps have the following form:
#   1. msg "short description of what is about to be done"
#   2. cleanup
#   3. preparation (config.pl, cmake, ...) (failure stops the script)
#   4. make
#   5. Run tests if relevant. All tests must be prefixed with
#      if_build_successful for the sake of --keep-going.



################################################################
#### Initialization and command line parsing
################################################################

# Abort on errors (and uninitialised variables)
set -eu

pre_check_environment () {
    if [ -d library -a -d include -a -d tests ]; then :; else
        echo "Must be run from mbed TLS root" >&2
        exit 1
    fi
}

pre_initialize_variables () {
    CONFIG_H='include/mbedtls/config.h'
    CONFIG_BAK="$CONFIG_H.bak"

    ALL_EXCEPT=0
    MEMORY=0
    FORCE=0
    KEEP_GOING=0
    RUN_ARMCC=1
    YOTTA=1

    # Default commands, can be overriden by the environment
    : ${OPENSSL:="openssl"}
    : ${OPENSSL_LEGACY:="$OPENSSL"}
    : ${GNUTLS_CLI:="gnutls-cli"}
    : ${GNUTLS_SERV:="gnutls-serv"}
    : ${GNUTLS_LEGACY_CLI:="$GNUTLS_CLI"}
    : ${GNUTLS_LEGACY_SERV:="$GNUTLS_SERV"}
    : ${OUT_OF_SOURCE_DIR:=./mbedtls_out_of_source_build}
    : ${ARMC5_BIN_DIR:=/usr/bin}
    : ${ARMC6_BIN_DIR:=/usr/bin}

    # if MAKEFLAGS is not set add the -j option to speed up invocations of make
    if [ -n "${MAKEFLAGS+set}" ]; then
        export MAKEFLAGS="-j"
    fi

    # Gather the list of available components. These are the functions
    # defined in this script whose name starts with "component_".
    # Parse the script with sed, because in sh there is no way to list
    # defined functions.
    ALL_COMPONENTS=$(sed -n 's/^ *component_\([0-9A-Z_a-z]*\) *().*/\1/p' <"$0")
}

# Test whether $1 is excluded via $COMPONENTS (a space-separated list of
# wildcard patterns).
is_component_excluded()
{
    set -f
    for pattern in $COMPONENTS; do
        set +f
        case ${1#component_} in $pattern) return 0;; esac
    done
    set +f
    return 1
}

usage()
{
    cat <<EOF
Usage: $0 [OPTION]... [COMPONENT]...
Run mbedtls release validation tests.
By default, run all tests. With one or more COMPONENT, run only those.

Special options:
  -h|--help             Print this help and exit.

General options:
  -f|--force            Force the tests to overwrite any modified files.
  -k|--keep-going       Run all tests and report errors at the end.
  -m|--memory           Additional optional memory tests.
     --armcc            Run ARM Compiler builds (on by default).
     --except           If some components are passed on the command line,
                        run all the tests except for these components. In
                        this mode, you can pass shell wildcard patterns as
                        component names, e.g. "$0 --except 'test_*'" to
                        exclude all components that run tests.
     --no-armcc         Skip ARM Compiler builds.
     --no-force         Refuse to overwrite modified files (default).
     --no-keep-going    Stop at the first error (default).
     --no-memory        No additional memory tests (default).
     --no-yotta         Skip yotta module build.
     --out-of-source-dir=<path>  Directory used for CMake out-of-source build tests.
     --random-seed      Use a random seed value for randomized tests (default).
  -r|--release-test     Run this script in release mode. This fixes the seed value to 1.
  -s|--seed             Integer seed value to use for this test run.
     --yotta            Build yotta module (on by default).

Tool path options:
     --armc5-bin-dir=<ARMC5_bin_dir_path>       ARM Compiler 5 bin directory.
     --armc6-bin-dir=<ARMC6_bin_dir_path>       ARM Compiler 6 bin directory.
     --gnutls-cli=<GnuTLS_cli_path>             GnuTLS client executable to use for most tests.
     --gnutls-serv=<GnuTLS_serv_path>           GnuTLS server executable to use for most tests.
     --gnutls-legacy-cli=<GnuTLS_cli_path>      GnuTLS client executable to use for legacy tests.
     --gnutls-legacy-serv=<GnuTLS_serv_path>    GnuTLS server executable to use for legacy tests.
     --openssl=<OpenSSL_path>                   OpenSSL executable to use for most tests.
     --openssl-legacy=<OpenSSL_path>            OpenSSL executable to use for legacy tests e.g. SSLv3.
EOF
}

# remove built files as well as the cmake cache/config
cleanup()
{
    if [ -n "${MBEDTLS_ROOT_DIR+set}" ]; then
        cd "$MBEDTLS_ROOT_DIR"
    fi

    command make clean

    # Remove CMake artefacts
    find . -name .git -prune -o -name yotta -prune -o \
           -iname CMakeFiles -exec rm -rf {} \+ -o \
           \( -iname cmake_install.cmake -o \
              -iname CTestTestfile.cmake -o \
              -iname CMakeCache.txt \) -exec rm {} \+
    # Recover files overwritten by in-tree CMake builds
    rm -f include/Makefile include/mbedtls/Makefile programs/*/Makefile
    git update-index --no-skip-worktree Makefile library/Makefile programs/Makefile tests/Makefile
    git checkout -- Makefile library/Makefile programs/Makefile tests/Makefile

    if [ -f "$CONFIG_BAK" ]; then
        mv "$CONFIG_BAK" "$CONFIG_H"
    fi
}

# Executed on exit. May be redefined depending on command line options.
final_report () {
    :
}

fatal_signal () {
    cleanup
    final_report $1
    trap - $1
    kill -$1 $$
}

trap 'fatal_signal HUP' HUP
trap 'fatal_signal INT' INT
trap 'fatal_signal TERM' TERM

msg()
{
    if [ -n "${current_component:-}" ]; then
        current_section="${current_component#component_}: $1"
    else
        current_section="$1"
    fi
    echo ""
    echo "******************************************************************"
    echo "* $current_section "
    printf "* "; date
    echo "******************************************************************"
}

armc6_build_test()
{
    FLAGS="$1"

    msg "build: ARM Compiler 6 ($FLAGS), make"
    ARM_TOOL_VARIANT="ult" CC="$ARMC6_CC" AR="$ARMC6_AR" CFLAGS="$FLAGS" \
                    WARNING_CFLAGS='-xc -std=c99' make lib
    make clean
}

err_msg()
{
    echo "$1" >&2
}

check_tools()
{
    for TOOL in "$@"; do
        if ! `type "$TOOL" >/dev/null 2>&1`; then
            err_msg "$TOOL not found!"
            exit 1
        fi
    done
}

pre_parse_command_line () {
    COMPONENTS=

    while [ $# -gt 0 ]; do
        case "$1" in
            --armcc) RUN_ARMCC=1;;
            --armc5-bin-dir) shift; ARMC5_BIN_DIR="$1";;
            --armc6-bin-dir) shift; ARMC6_BIN_DIR="$1";;
            --except) ALL_EXCEPT=1;;
            --force|-f) FORCE=1;;
            --gnutls-cli) shift; GNUTLS_CLI="$1";;
            --gnutls-legacy-cli) shift; GNUTLS_LEGACY_CLI="$1";;
            --gnutls-legacy-serv) shift; GNUTLS_LEGACY_SERV="$1";;
            --gnutls-serv) shift; GNUTLS_SERV="$1";;
            --help|-h) usage; exit;;
            --keep-going|-k) KEEP_GOING=1;;
            --memory|-m) MEMORY=1;;
            --no-armcc) RUN_ARMCC=0;;
            --no-force) FORCE=0;;
            --no-keep-going) KEEP_GOING=0;;
            --no-memory) MEMORY=0;;
            --no-yotta) YOTTA=0;;
            --openssl) shift; OPENSSL="$1";;
            --openssl-legacy) shift; OPENSSL_LEGACY="$1";;
            --out-of-source-dir) shift; OUT_OF_SOURCE_DIR="$1";;
            --random-seed) unset SEED;;
            --release-test|-r) SEED=1;;
            --seed|-s) shift; SEED="$1";;
            --yotta) YOTTA=1;;
            -*)
                echo >&2 "Unknown option: $1"
                echo >&2 "Run $0 --help for usage."
                exit 120
                ;;
            *)
                COMPONENTS="$COMPONENTS $1";;
        esac
        shift
    done

    if [ $ALL_EXCEPT -ne 0 ]; then
        RUN_COMPONENTS=
        for component in $ALL_COMPONENTS; do
            if ! is_component_excluded "$component"; then
                RUN_COMPONENTS="$RUN_COMPONENTS $component"
            fi
        done
    elif [ -z "$COMPONENTS" ]; then
        RUN_COMPONENTS="$ALL_COMPONENTS"
    else
        RUN_COMPONENTS="$COMPONENTS"
    fi
}

pre_check_git () {
    if [ $FORCE -eq 1 ]; then
        if [ $YOTTA -eq 1 ]; then
            rm -rf yotta/module "$OUT_OF_SOURCE_DIR"
        fi
        git checkout-index -f -q $CONFIG_H
        cleanup
    else

        if [ $YOTTA -ne 0 ] && [ -d yotta/module ]; then
            err_msg "Warning - there is an existing yotta module in the directory 'yotta/module'"
            echo "You can either delete your work and retry, or force the test to overwrite the"
            echo "test by rerunning the script as: $0 --force"
            exit 1
        fi

        if [ -d "$OUT_OF_SOURCE_DIR" ]; then
            echo "Warning - there is an existing directory at '$OUT_OF_SOURCE_DIR'" >&2
            echo "You can either delete this directory manually, or force the test by rerunning"
            echo "the script as: $0 --force --out-of-source-dir $OUT_OF_SOURCE_DIR"
            exit 1
        fi

        if ! git diff-files --quiet include/mbedtls/config.h; then
            err_msg "Warning - the configuration file 'include/mbedtls/config.h' has been edited. "
            echo "You can either delete or preserve your work, or force the test by rerunning the"
            echo "script as: $0 --force"
            exit 1
        fi
    fi
}

pre_setup_keep_going () {
    failure_summary=
    failure_count=0
    start_red=
    end_color=
    if [ -t 1 ]; then
        case "${TERM:-}" in
            *color*|cygwin|linux|rxvt*|screen|[Eex]term*)
                start_red=$(printf '\033[31m')
                end_color=$(printf '\033[0m')
                ;;
        esac
    fi
    record_status () {
        if "$@"; then
            last_status=0
        else
            last_status=$?
            text="$current_section: $* -> $last_status"
            failure_summary="$failure_summary
$text"
            failure_count=$((failure_count + 1))
            echo "${start_red}^^^^$text^^^^${end_color}"
        fi
    }
    make () {
        case "$*" in
            *test|*check)
                if [ $build_status -eq 0 ]; then
                    record_status command make "$@"
                else
                    echo "(skipped because the build failed)"
                fi
                ;;
            *)
                record_status command make "$@"
                build_status=$last_status
                ;;
        esac
    }
    final_report () {
        if [ $failure_count -gt 0 ]; then
            echo
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            echo "${start_red}FAILED: $failure_count${end_color}$failure_summary"
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            exit 1
        elif [ -z "${1-}" ]; then
            echo "SUCCESS :)"
        fi
        if [ -n "${1-}" ]; then
            echo "Killed by SIG$1."
        fi
    }
}

if_build_succeeded () {
    if [ $build_status -eq 0 ]; then
        record_status "$@"
    fi
}

pre_print_configuration () {
    msg "info: $0 configuration"
    echo "MEMORY: $MEMORY"
    echo "FORCE: $FORCE"
    echo "SEED: ${SEED-"UNSET"}"
    echo "OPENSSL: $OPENSSL"
    echo "OPENSSL_LEGACY: $OPENSSL_LEGACY"
    echo "GNUTLS_CLI: $GNUTLS_CLI"
    echo "GNUTLS_SERV: $GNUTLS_SERV"
    echo "GNUTLS_LEGACY_CLI: $GNUTLS_LEGACY_CLI"
    echo "GNUTLS_LEGACY_SERV: $GNUTLS_LEGACY_SERV"
    echo "ARMC5_BIN_DIR: $ARMC5_BIN_DIR"
    echo "ARMC6_BIN_DIR: $ARMC6_BIN_DIR"
}

# Make sure the tools we need are available.
pre_check_tools () {
    ARMC5_CC="$ARMC5_BIN_DIR/armcc"
    ARMC5_AR="$ARMC5_BIN_DIR/armar"
    ARMC6_CC="$ARMC6_BIN_DIR/armclang"
    ARMC6_AR="$ARMC6_BIN_DIR/armar"

    # To avoid setting OpenSSL and GnuTLS for each call to compat.sh and ssl-opt.sh
    # we just export the variables they require
    export OPENSSL_CMD="$OPENSSL"
    export GNUTLS_CLI="$GNUTLS_CLI"
    export GNUTLS_SERV="$GNUTLS_SERV"

    # Avoid passing --seed flag in every call to ssl-opt.sh
    if [ -n "${SEED-}" ]; then
        export SEED
    fi

    check_tools "$OPENSSL" "$OPENSSL_LEGACY" "$GNUTLS_CLI" "$GNUTLS_SERV" \
                "$GNUTLS_LEGACY_CLI" "$GNUTLS_LEGACY_SERV" "doxygen" "dot" \
                "arm-none-eabi-gcc" "i686-w64-mingw32-gcc"
    if [ $RUN_ARMCC -ne 0 ]; then
        check_tools "$ARMC5_CC" "$ARMC5_AR" "$ARMC6_CC" "$ARMC6_AR"
    fi

    msg "info: output_env.sh"
    OPENSSL="$OPENSSL" OPENSSL_LEGACY="$OPENSSL_LEGACY" GNUTLS_CLI="$GNUTLS_CLI" \
           GNUTLS_SERV="$GNUTLS_SERV" GNUTLS_LEGACY_CLI="$GNUTLS_LEGACY_CLI" \
           GNUTLS_LEGACY_SERV="$GNUTLS_LEGACY_SERV" ARMC5_CC="$ARMC5_CC" \
           ARMC6_CC="$ARMC6_CC" RUN_ARMCC="$RUN_ARMCC" scripts/output_env.sh
}



################################################################
#### Basic checks
################################################################

#
# Test Suites to be executed
#
# The test ordering tries to optimize for the following criteria:
# 1. Catch possible problems early, by running first tests that run quickly
#    and/or are more likely to fail than others (eg I use Clang most of the
#    time, so start with a GCC build).
# 2. Minimize total running time, by avoiding useless rebuilds
#
# Indicative running times are given for reference.

component_check_recursion () {
    msg "test: recursion.pl" # < 1s
    record_status tests/scripts/recursion.pl library/*.c
}

component_check_generated_files () {
    msg "test: freshness of generated source files" # < 1s
    record_status tests/scripts/check-generated-files.sh
}

component_check_doxy_blocks () {
    msg "test: doxygen markup outside doxygen blocks" # < 1s
    record_status tests/scripts/check-doxy-blocks.pl
}

component_check_files () {
    msg "test: check-files.py" # < 1s
    record_status tests/scripts/check-files.py
}

component_check_names () {
    msg "test/build: declared and exported names" # < 3s
    record_status tests/scripts/check-names.sh
}

component_check_doxygen_warnings () {
    msg "test: doxygen warnings" # ~ 3s
    record_status tests/scripts/doxygen.sh
}


################################################################
#### Build and test many configurations and targets
################################################################

component_build_yotta () {
    if [ $RUN_ARMCC -ne 0 ] && [ $YOTTA -ne 0 ]; then
        # Note - use of yotta is deprecated, and yotta also requires armcc to be on the
        # path, and uses whatever version of armcc it finds there.
        msg "build: create and build yotta module" # ~ 30s
        record_status tests/scripts/yotta-build.sh
    fi
}

component_test_default_cmake_gcc_asan () {
    msg "build: cmake, gcc, ASan" # ~ 1 min 50s
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: ssl-opt.sh (ASan build)" # ~ 1 min
    if_build_succeeded tests/ssl-opt.sh

    msg "test: compat.sh (ASan build)" # ~ 6 min
    if_build_succeeded tests/compat.sh
}

component_test_ref_configs () {
    msg "test/build: ref-configs (ASan build)" # ~ 6 min 20s
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    record_status tests/scripts/test-ref-configs.pl
}

component_test_sslv3 () {
    msg "build: Default + SSLv3 (ASan build)" # ~ 6 min
    scripts/config.pl set MBEDTLS_SSL_PROTO_SSL3
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: SSLv3 - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "build: SSLv3 - compat.sh (ASan build)" # ~ 6 min
    if_build_succeeded tests/compat.sh -m 'tls1 tls1_1 tls1_2 dtls1 dtls1_2'
    if_build_succeeded env OPENSSL_CMD="$OPENSSL_LEGACY" tests/compat.sh -m 'ssl3'

    msg "build: SSLv3 - ssl-opt.sh (ASan build)" # ~ 6 min
    if_build_succeeded tests/ssl-opt.sh
}

component_test_no_renegotiation () {
    msg "build: Default + !MBEDTLS_SSL_RENEGOTIATION (ASan build)" # ~ 6 min
    scripts/config.pl unset MBEDTLS_SSL_RENEGOTIATION
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: !MBEDTLS_SSL_RENEGOTIATION - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: !MBEDTLS_SSL_RENEGOTIATION - ssl-opt.sh (ASan build)" # ~ 6 min
    if_build_succeeded tests/ssl-opt.sh
}

component_test_rsa_no_crt () {
    msg "build: Default + RSA_NO_CRT (ASan build)" # ~ 6 min
    scripts/config.pl set MBEDTLS_RSA_NO_CRT
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: RSA_NO_CRT - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: RSA_NO_CRT - RSA-related part of ssl-opt.sh (ASan build)" # ~ 5s
    if_build_succeeded tests/ssl-opt.sh -f RSA

    msg "test: RSA_NO_CRT - RSA-related part of compat.sh (ASan build)" # ~ 3 min
    if_build_succeeded tests/compat.sh -t RSA
}

component_test_full_cmake_clang () {
    msg "build: cmake, full config, clang" # ~ 50s
    scripts/config.pl full
    scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # too slow for tests
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=Check -D ENABLE_TESTING=On .
    make

    msg "test: main suites (full config)" # ~ 5s
    make test

    msg "test: ssl-opt.sh default (full config)" # ~ 1s
    if_build_succeeded tests/ssl-opt.sh -f Default

    msg "test: compat.sh RC4, DES & NULL (full config)" # ~ 2 min
    if_build_succeeded env OPENSSL_CMD="$OPENSSL_LEGACY" GNUTLS_CLI="$GNUTLS_LEGACY_CLI" GNUTLS_SERV="$GNUTLS_LEGACY_SERV" tests/compat.sh -e '3DES\|DES-CBC3' -f 'NULL\|DES\|RC4\|ARCFOUR'
}

component_build_deprecated () {
    msg "build: make, full config + DEPRECATED_WARNING, gcc -O" # ~ 30s
    scripts/config.pl full
    scripts/config.pl set MBEDTLS_DEPRECATED_WARNING
    # Build with -O -Wextra to catch a maximum of issues.
    make CC=gcc CFLAGS='-O -Werror -Wall -Wextra' lib programs
    make CC=gcc CFLAGS='-O -Werror -Wall -Wextra -Wno-unused-function' tests

    msg "build: make, full config + DEPRECATED_REMOVED, clang -O" # ~ 30s
    # No cleanup, just tweak the configuration and rebuild
    make clean
    scripts/config.pl unset MBEDTLS_DEPRECATED_WARNING
    scripts/config.pl set MBEDTLS_DEPRECATED_REMOVED
    # Build with -O -Wextra to catch a maximum of issues.
    make CC=clang CFLAGS='-O -Werror -Wall -Wextra' lib programs
    make CC=clang CFLAGS='-O -Werror -Wall -Wextra -Wno-unused-function' tests
}

component_test_depends_curves () {
    msg "test/build: curves.pl (gcc)" # ~ 4 min
    record_status tests/scripts/curves.pl
}

component_test_depends_hashes () {
    msg "test/build: depends-hashes.pl (gcc)" # ~ 2 min
    record_status tests/scripts/depends-hashes.pl
}

component_test_depends_pkalgs () {
    msg "test/build: depends-pkalgs.pl (gcc)" # ~ 2 min
    record_status tests/scripts/depends-pkalgs.pl
}

component_build_key_exchanges () {
    msg "test/build: key-exchanges (gcc)" # ~ 1 min
    record_status tests/scripts/key-exchanges.pl
}

component_build_default_make_gcc () {
    msg "build: Unix make, -Os (gcc)" # ~ 30s
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -Os'
}

component_test_no_platform () {
    # Full configuration build, without platform support, file IO and net sockets.
    # This should catch missing mbedtls_printf definitions, and by disabling file
    # IO, it should catch missing '#include <stdio.h>'
    msg "build: full config except platform/fsio/net, make, gcc, C99" # ~ 30s
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
    # Note, _DEFAULT_SOURCE needs to be defined for platforms using glibc version >2.19,
    # to re-enable platform integration features otherwise disabled in C99 builds
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -std=c99 -pedantic -O0 -D_DEFAULT_SOURCE' lib programs
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -O0' test
}

component_build_no_std_function () {
    # catch compile bugs in _uninit functions
    msg "build: full config with NO_STD_FUNCTION, make, gcc" # ~ 30s
    scripts/config.pl full
    scripts/config.pl set MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
    scripts/config.pl unset MBEDTLS_ENTROPY_NV_SEED
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -O0'
}

component_build_no_ssl_srv () {
    msg "build: full config except ssl_srv.c, make, gcc" # ~ 30s
    scripts/config.pl full
    scripts/config.pl unset MBEDTLS_SSL_SRV_C
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -O0'
}

component_build_no_ssl_cli () {
    msg "build: full config except ssl_cli.c, make, gcc" # ~ 30s
    scripts/config.pl full
    scripts/config.pl unset MBEDTLS_SSL_CLI_C
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -O0'
}

component_build_no_sockets () {
    # Note, C99 compliance can also be tested with the sockets support disabled,
    # as that requires a POSIX platform (which isn't the same as C99).
    msg "build: full config except net_sockets.c, make, gcc -std=c99 -pedantic" # ~ 30s
    scripts/config.pl full
    scripts/config.pl unset MBEDTLS_NET_C # getaddrinfo() undeclared, etc.
    scripts/config.pl set MBEDTLS_NO_PLATFORM_ENTROPY # uses syscall() on GNU/Linux
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -O0 -std=c99 -pedantic' lib
}

component_test_no_max_fragment_length () {
    msg "build: default config except MFL extension (ASan build)" # ~ 30s
    scripts/config.pl unset MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: ssl-opt.sh, MFL-related tests"
    if_build_succeeded tests/ssl-opt.sh -f "Max fragment length"
}

component_test_null_entropy () {
    msg "build: default config with  MBEDTLS_TEST_NULL_ENTROPY (ASan build)"
    scripts/config.pl set MBEDTLS_TEST_NULL_ENTROPY
    scripts/config.pl set MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
    scripts/config.pl set MBEDTLS_ENTROPY_C
    scripts/config.pl unset MBEDTLS_ENTROPY_NV_SEED
    scripts/config.pl unset MBEDTLS_ENTROPY_HARDWARE_ALT
    scripts/config.pl unset MBEDTLS_HAVEGE_C
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan -D UNSAFE_BUILD=ON .
    make

    msg "test: MBEDTLS_TEST_NULL_ENTROPY - main suites (inc. selftests) (ASan build)"
    make test
}

component_test_platform_calloc_macro () {
    msg "build: MBEDTLS_PLATFORM_{CALLOC/FREE}_MACRO enabled (ASan build)"
    scripts/config.pl set MBEDTLS_PLATFORM_MEMORY
    scripts/config.pl set MBEDTLS_PLATFORM_CALLOC_MACRO calloc
    scripts/config.pl set MBEDTLS_PLATFORM_FREE_MACRO   free
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: MBEDTLS_PLATFORM_{CALLOC/FREE}_MACRO enabled (ASan build)"
    make test
}

component_test_make_shared () {
    msg "build/test: make shared" # ~ 40s
    make SHARED=1 all check
}

case $(uname -m) in
    amd64|x86_64)
        component_test_m32_o0 () {
            # Build once with -O0, to compile out the i386 specific inline assembly
            msg "build: i386, make, gcc -O0 (ASan build)" # ~ 30s
            scripts/config.pl full
            make CC=gcc CFLAGS='-O0 -Werror -Wall -Wextra -m32 -fsanitize=address'

            msg "test: i386, make, gcc -O0 (ASan build)"
            make test
        }

        component_test_m32_o1 () {
            # Build again with -O1, to compile in the i386 specific inline assembly
            msg "build: i386, make, gcc -O1 (ASan build)" # ~ 30s
            scripts/config.pl full
            make CC=gcc CFLAGS='-O1 -Werror -Wall -Wextra -m32 -fsanitize=address'

            msg "test: i386, make, gcc -O1 (ASan build)"
            make test
        }

        component_test_mx32 () {
            msg "build: 64-bit ILP32, make, gcc" # ~ 30s
            scripts/config.pl full
            make CC=gcc CFLAGS='-Werror -Wall -Wextra -mx32'

            msg "test: 64-bit ILP32, make, gcc"
            make test
        }
        ;;
esac

component_test_have_int32 () {
    msg "build: gcc, force 32-bit bignum limbs"
    scripts/config.pl unset MBEDTLS_HAVE_ASM
    scripts/config.pl unset MBEDTLS_AESNI_C
    scripts/config.pl unset MBEDTLS_PADLOCK_C
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -DMBEDTLS_HAVE_INT32'

    msg "test: gcc, force 32-bit bignum limbs"
    make test
}

component_test_have_int64 () {
    msg "build: gcc, force 64-bit bignum limbs"
    scripts/config.pl unset MBEDTLS_HAVE_ASM
    scripts/config.pl unset MBEDTLS_AESNI_C
    scripts/config.pl unset MBEDTLS_PADLOCK_C
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -DMBEDTLS_HAVE_INT64'

    msg "test: gcc, force 64-bit bignum limbs"
    make test
}

component_build_arm_none_eabi_gcc () {
    msg "build: arm-none-eabi-gcc, make" # ~ 10s
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
    make CC=arm-none-eabi-gcc AR=arm-none-eabi-ar LD=arm-none-eabi-ld CFLAGS='-Werror -Wall -Wextra' lib
}

component_build_arm_none_eabi_gcc_no_udbl_division () {
    msg "build: arm-none-eabi-gcc -DMBEDTLS_NO_UDBL_DIVISION, make" # ~ 10s
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
    make CC=arm-none-eabi-gcc AR=arm-none-eabi-ar LD=arm-none-eabi-ld CFLAGS='-Werror -Wall -Wextra' lib
    echo "Checking that software 64-bit division is not required"
    ! grep __aeabi_uldiv library/*.o
}

component_build_armcc () {
    msg "build: ARM Compiler 5, make"
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

    if [ $RUN_ARMCC -ne 0 ]; then
        make CC="$ARMC5_CC" AR="$ARMC5_AR" WARNING_CFLAGS='--strict --c99' lib
        make clean

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
}

component_test_allow_sha1 () {
    msg "build: allow SHA1 in certificates by default"
    scripts/config.pl set MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES
    make CFLAGS='-Werror -Wall -Wextra'
    msg "test: allow SHA1 in certificates by default"
    make test
    if_build_succeeded tests/ssl-opt.sh -f SHA-1
}

component_build_mingw () {
    msg "build: Windows cross build - mingw64, make (Link Library)" # ~ 30s
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror -Wall -Wextra' WINDOWS_BUILD=1 lib programs

    # note Make tests only builds the tests, but doesn't run them
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror' WINDOWS_BUILD=1 tests
    make WINDOWS_BUILD=1 clean

    msg "build: Windows cross build - mingw64, make (DLL)" # ~ 30s
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror -Wall -Wextra' WINDOWS_BUILD=1 SHARED=1 lib programs
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror -Wall -Wextra' WINDOWS_BUILD=1 SHARED=1 tests
    make WINDOWS_BUILD=1 clean
}

component_test_memsan () {
    msg "build: MSan (clang)" # ~ 1 min 20s
    scripts/config.pl unset MBEDTLS_AESNI_C # memsan doesn't grok asm
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=MemSan .
    make

    msg "test: main suites (MSan)" # ~ 10s
    make test

    msg "test: ssl-opt.sh (MSan)" # ~ 1 min
    if_build_succeeded tests/ssl-opt.sh

    # Optional part(s)

    if [ "$MEMORY" -gt 0 ]; then
        msg "test: compat.sh (MSan)" # ~ 6 min 20s
        if_build_succeeded tests/compat.sh
    fi
}

component_test_memcheck () {
    msg "build: Release (clang)"
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=Release .
    make

    msg "test: main suites valgrind (Release)"
    make memcheck

    # Optional part(s)
    # Currently broken, programs don't seem to receive signals
    # under valgrind on OS X

    if [ "$MEMORY" -gt 0 ]; then
        msg "test: ssl-opt.sh --memcheck (Release)"
        if_build_succeeded tests/ssl-opt.sh --memcheck
    fi

    if [ "$MEMORY" -gt 1 ]; then
        msg "test: compat.sh --memcheck (Release)"
        if_build_succeeded tests/compat.sh --memcheck
    fi
}

component_test_cmake_out_of_source () {
    msg "build: cmake 'out-of-source' build"
    MBEDTLS_ROOT_DIR="$PWD"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"
    cmake "$MBEDTLS_ROOT_DIR"
    make

    msg "test: cmake 'out-of-source' build"
    make test
    # Test an SSL option that requires an auxiliary script in test/scripts/.
    # Also ensure that there are no error messages such as
    # "No such file or directory", which would indicate that some required
    # file is missing (ssl-opt.sh tolerates the absence of some files so
    # may exit with status 0 but emit errors).
    if_build_succeeded ./tests/ssl-opt.sh -f 'Fallback SCSV: beginning of list' 2>ssl-opt.err
    if [ -s ssl-opt.err ]; then
        cat ssl-opt.err >&2
        record_status [ ! -s ssl-opt.err ]
        rm ssl-opt.err
    fi
    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"
    unset MBEDTLS_ROOT_DIR
}



################################################################
#### Termination
################################################################

post_report () {
    msg "Done, cleaning up"
    cleanup

    final_report
}



################################################################
#### Run all the things
################################################################

# Run one component and clean up afterwards.
run_component () {
    # Back up the configuration in case the component modifies it.
    # The cleanup function will restore it.
    cp -p "$CONFIG_H" "$CONFIG_BAK"
    current_component="$1"
    "$@"
    cleanup
}

# Preliminary setup
pre_check_environment
pre_initialize_variables
pre_parse_command_line "$@"

pre_check_git
build_status=0
if [ $KEEP_GOING -eq 1 ]; then
    pre_setup_keep_going
else
    record_status () {
        "$@"
    }
fi
pre_print_configuration
pre_check_tools
cleanup

# Run all the test components.
for component in $RUN_COMPONENTS; do
    run_component "component_$component"
done

# We're done.
post_report
