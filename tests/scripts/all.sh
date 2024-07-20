#! /usr/bin/env bash

# all.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later



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
#    * include/mbedtls/mbedtls_config.h
#    * Makefile, library/Makefile, programs/Makefile, tests/Makefile,
#      programs/fuzz/Makefile
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
#   * G++
#   * arm-gcc and mingw-gcc
#   * ArmCC 5 and ArmCC 6, unless invoked with --no-armcc
#   * OpenSSL and GnuTLS command line tools, in suitable versions for the
#     interoperability tests. The following are the official versions at the
#     time of writing:
#     * GNUTLS_{CLI,SERV} = 3.4.10
#     * GNUTLS_NEXT_{CLI,SERV} = 3.7.2
#     * OPENSSL = 1.0.2g (without Debian/Ubuntu patches)
#     * OPENSSL_NEXT = 3.1.2
# See the invocation of check_tools below for details.
#
# This script must be invoked from the toplevel directory of a git
# working copy of Mbed TLS.
#
# The behavior on an error depends on whether --keep-going (alias -k)
# is in effect.
#  * Without --keep-going: the script stops on the first error without
#    cleaning up. This lets you work in the configuration of the failing
#    component.
#  * With --keep-going: the script runs all requested components and
#    reports failures at the end. In particular the script always cleans
#    up on exit.
#
# Note that the output is not saved. You may want to run
#   script -c tests/scripts/all.sh
# or
#   tests/scripts/all.sh >all.log 2>&1
#
# Notes for maintainers
# ---------------------
#
# The bulk of the code is organized into functions that follow one of the
# following naming conventions:
#  * pre_XXX: things to do before running the tests, in order.
#  * component_XXX: independent components. They can be run in any order.
#      * component_check_XXX: quick tests that aren't worth parallelizing.
#      * component_build_XXX: build things but don't run them.
#      * component_test_XXX: build and test.
#      * component_release_XXX: tests that the CI should skip during PR testing.
#  * support_XXX: if support_XXX exists and returns false then
#    component_XXX is not run by default.
#  * post_XXX: things to do after running the tests.
#  * other: miscellaneous support functions.
#
# Each component must start by invoking `msg` with a short informative message.
#
# Warning: due to the way bash detects errors, the failure of a command
# inside 'if' or '!' is not detected. Use the 'not' function instead of '!'.
#
# Each component is executed in a separate shell process. The component
# fails if any command in it returns a non-zero status.
#
# The framework performs some cleanup tasks after each component. This
# means that components can assume that the working directory is in a
# cleaned-up state, and don't need to perform the cleanup themselves.
# * Run `make clean`.
# * Restore `include/mbedtls/mbedtls_config.h` from a backup made before running
#   the component.
# * Check out `Makefile`, `library/Makefile`, `programs/Makefile`,
#   `tests/Makefile` and `programs/fuzz/Makefile` from git.
#   This cleans up after an in-tree use of CMake.
#
# The tests are roughly in order from fastest to slowest. This doesn't
# have to be exact, but in general you should add slower tests towards
# the end and fast checks near the beginning.



################################################################
#### Initialization and command line parsing
################################################################

# Abort on errors (even on the left-hand side of a pipe).
# Treat uninitialised variables as errors.
set -e -o pipefail -u

# Enable ksh/bash extended file matching patterns
shopt -s extglob

in_mbedtls_repo () {
    test -d include -a -d library -a -d programs -a -d tests
}

in_tf_psa_crypto_repo () {
    test -d include -a -d core -a -d drivers -a -d programs -a -d tests
}

pre_check_environment () {
    if in_mbedtls_repo || in_tf_psa_crypto_repo; then :; else
        echo "Must be run from Mbed TLS / TF-PSA-Crypto root" >&2
        exit 1
    fi
}

pre_initialize_variables () {
    if in_mbedtls_repo; then
        CONFIG_H='include/mbedtls/mbedtls_config.h'
        if [ -d tf-psa-crypto ]; then
            CRYPTO_CONFIG_H='tf-psa-crypto/include/psa/crypto_config.h'
            PSA_CORE_PATH='tf-psa-crypto/core'
            BUILTIN_SRC_PATH='tf-psa-crypto/drivers/builtin/src'
        else
            CRYPTO_CONFIG_H='include/psa/crypto_config.h'
        fi
    else
        CONFIG_H='drivers/builtin/include/mbedtls/mbedtls_config.h'
        CRYPTO_CONFIG_H='include/psa/crypto_config.h'
        PSA_CORE_PATH='core'
        BUILTIN_SRC_PATH='drivers/builtin/src'
    fi
    CONFIG_TEST_DRIVER_H='tests/include/test/drivers/config_test_driver.h'

    # Files that are clobbered by some jobs will be backed up. Use a different
    # suffix from auxiliary scripts so that all.sh and auxiliary scripts can
    # independently decide when to remove the backup file.
    backup_suffix='.all.bak'
    # Files clobbered by config.py
    files_to_back_up="$CONFIG_H $CRYPTO_CONFIG_H $CONFIG_TEST_DRIVER_H"
    if in_mbedtls_repo; then
        # Files clobbered by in-tree cmake
        files_to_back_up="$files_to_back_up Makefile library/Makefile programs/Makefile tests/Makefile programs/fuzz/Makefile"
    fi

    append_outcome=0
    MEMORY=0
    FORCE=0
    QUIET=0
    KEEP_GOING=0

    # Seed value used with the --release-test option.
    #
    # See also RELEASE_SEED in basic-build-test.sh. Debugging is easier if
    # both values are kept in sync. If you change the value here because it
    # breaks some tests, you'll definitely want to change it in
    # basic-build-test.sh as well.
    RELEASE_SEED=1

    # Specify character collation for regular expressions and sorting with C locale
    export LC_COLLATE=C

    : ${MBEDTLS_TEST_OUTCOME_FILE=}
    : ${MBEDTLS_TEST_PLATFORM="$(uname -s | tr -c \\n0-9A-Za-z _)-$(uname -m | tr -c \\n0-9A-Za-z _)"}
    export MBEDTLS_TEST_OUTCOME_FILE
    export MBEDTLS_TEST_PLATFORM

    # Default commands, can be overridden by the environment
    : ${OPENSSL:="openssl"}
    : ${OPENSSL_NEXT:="$OPENSSL"}
    : ${GNUTLS_CLI:="gnutls-cli"}
    : ${GNUTLS_SERV:="gnutls-serv"}
    : ${OUT_OF_SOURCE_DIR:=./mbedtls_out_of_source_build}
    : ${ARMC5_BIN_DIR:=/usr/bin}
    : ${ARMC6_BIN_DIR:=/usr/bin}
    : ${ARM_NONE_EABI_GCC_PREFIX:=arm-none-eabi-}
    : ${ARM_LINUX_GNUEABI_GCC_PREFIX:=arm-linux-gnueabi-}
    : ${CLANG_LATEST:="clang-latest"}
    : ${CLANG_EARLIEST:="clang-earliest"}
    : ${GCC_LATEST:="gcc-latest"}
    : ${GCC_EARLIEST:="gcc-earliest"}
    # if MAKEFLAGS is not set add the -j option to speed up invocations of make
    if [ -z "${MAKEFLAGS+set}" ]; then
        export MAKEFLAGS="-j$(all_sh_nproc)"
    fi
    # if CC is not set, use clang by default (if present) to improve build times
    if [ -z "${CC+set}" ] && (type clang > /dev/null 2>&1); then
        export CC="clang"
    fi

    if [ -n "${OPENSSL_3+set}" ]; then
        export OPENSSL_NEXT="$OPENSSL_3"
    fi

    # Include more verbose output for failing tests run by CMake or make
    export CTEST_OUTPUT_ON_FAILURE=1

    # CFLAGS and LDFLAGS for Asan builds that don't use CMake
    # default to -O2, use -Ox _after_ this if you want another level
    ASAN_CFLAGS='-O2 -Werror -fsanitize=address,undefined -fno-sanitize-recover=all'
    # Normally, tests should use this compiler for ASAN testing
    ASAN_CC=clang

    # Platform tests have an allocation that returns null
    export ASAN_OPTIONS="allocator_may_return_null=1"
    export MSAN_OPTIONS="allocator_may_return_null=1"

    # Gather the list of available components. These are the functions
    # defined in this script whose name starts with "component_".
    ALL_COMPONENTS=$(compgen -A function component_ | sed 's/component_//')

    PSASIM_PATH='tests/psa-client-server/psasim/'

    # Delay determining SUPPORTED_COMPONENTS until the command line options have a chance to override
    # the commands set by the environment
}

setup_quiet_wrappers()
{
    # Pick up "quiet" wrappers for make and cmake, which don't output very much
    # unless there is an error. This reduces logging overhead in the CI.
    #
    # Note that the cmake wrapper breaks unless we use an absolute path here.
    if [[ -e ${PWD}/tests/scripts/quiet ]]; then
        export PATH=${PWD}/tests/scripts/quiet:$PATH
    fi
}

# Test whether the component $1 is included in the command line patterns.
is_component_included()
{
    # Temporarily disable wildcard expansion so that $COMMAND_LINE_COMPONENTS
    # only does word splitting.
    set -f
    for pattern in $COMMAND_LINE_COMPONENTS; do
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
COMPONENT can be the name of a component or a shell wildcard pattern.

Examples:
  $0 "check_*"
    Run all sanity checks.
  $0 --no-armcc --except test_memsan
    Run everything except builds that require armcc and MemSan.

Special options:
  -h|--help             Print this help and exit.
  --list-all-components List all available test components and exit.
  --list-components     List components supported on this platform and exit.

General options:
  -q|--quiet            Only output component names, and errors if any.
  -f|--force            Force the tests to overwrite any modified files.
  -k|--keep-going       Run all tests and report errors at the end.
  -m|--memory           Additional optional memory tests.
     --append-outcome   Append to the outcome file (if used).
     --arm-none-eabi-gcc-prefix=<string>
                        Prefix for a cross-compiler for arm-none-eabi
                        (default: "${ARM_NONE_EABI_GCC_PREFIX}")
     --arm-linux-gnueabi-gcc-prefix=<string>
                        Prefix for a cross-compiler for arm-linux-gnueabi
                        (default: "${ARM_LINUX_GNUEABI_GCC_PREFIX}")
     --armcc            Run ARM Compiler builds (on by default).
     --restore          First clean up the build tree, restoring backed up
                        files. Do not run any components unless they are
                        explicitly specified.
     --error-test       Error test mode: run a failing function in addition
                        to any specified component. May be repeated.
     --except           Exclude the COMPONENTs listed on the command line,
                        instead of running only those.
     --no-append-outcome    Write a new outcome file and analyze it (default).
     --no-armcc         Skip ARM Compiler builds.
     --no-force         Refuse to overwrite modified files (default).
     --no-keep-going    Stop at the first error (default).
     --no-memory        No additional memory tests (default).
     --no-quiet         Print full output from components.
     --out-of-source-dir=<path>  Directory used for CMake out-of-source build tests.
     --outcome-file=<path>  File where test outcomes are written (not done if
                            empty; default: \$MBEDTLS_TEST_OUTCOME_FILE).
     --random-seed      Use a random seed value for randomized tests (default).
  -r|--release-test     Run this script in release mode. This fixes the seed value to ${RELEASE_SEED}.
  -s|--seed             Integer seed value to use for this test run.

Tool path options:
     --armc5-bin-dir=<ARMC5_bin_dir_path>       ARM Compiler 5 bin directory.
     --armc6-bin-dir=<ARMC6_bin_dir_path>       ARM Compiler 6 bin directory.
     --clang-earliest=<Clang_earliest_path>     Earliest version of clang available
     --clang-latest=<Clang_latest_path>         Latest version of clang available
     --gcc-earliest=<GCC_earliest_path>         Earliest version of GCC available
     --gcc-latest=<GCC_latest_path>             Latest version of GCC available
     --gnutls-cli=<GnuTLS_cli_path>             GnuTLS client executable to use for most tests.
     --gnutls-serv=<GnuTLS_serv_path>           GnuTLS server executable to use for most tests.
     --openssl=<OpenSSL_path>                   OpenSSL executable to use for most tests.
     --openssl-next=<OpenSSL_path>              OpenSSL executable to use for recent things like ARIA
EOF
}

# Cleanup before/after running a component.
# Remove built files as well as the cmake cache/config.
# Does not remove generated source files.
cleanup()
{
    if in_mbedtls_repo; then
        command make clean
    fi

    # Remove CMake artefacts
    find . -name .git -prune -o \
           -iname CMakeFiles -exec rm -rf {} \+ -o \
           \( -iname cmake_install.cmake -o \
              -iname CTestTestfile.cmake -o \
              -iname CMakeCache.txt -o \
              -path './cmake/*.cmake' \) -exec rm -f {} \+
    # Remove Makefiles generated by in-tree CMake builds
    rm -f pkgconfig/Makefile framework/Makefile
    rm -f include/Makefile programs/!(fuzz)/Makefile
    rm -f tf-psa-crypto/Makefile tf-psa-crypto/include/Makefile
    rm -f tf-psa-crypto/core/Makefile tf-psa-crypto/drivers/Makefile
    rm -f tf-psa-crypto/drivers/everest/Makefile
    rm -f tf-psa-crypto/drivers/p256-m/Makefile
    rm -f tf-psa-crypto/drivers/builtin/Makefile
    rm -f tf-psa-crypto/drivers/builtin/src/Makefile

    # Remove any artifacts from the component_test_cmake_as_subdirectory test.
    rm -rf programs/test/cmake_subproject/build
    rm -f programs/test/cmake_subproject/Makefile
    rm -f programs/test/cmake_subproject/cmake_subproject

    # Remove any artifacts from the component_test_cmake_as_package test.
    rm -rf programs/test/cmake_package/build
    rm -f programs/test/cmake_package/Makefile
    rm -f programs/test/cmake_package/cmake_package

    # Remove any artifacts from the component_test_cmake_as_installed_package test.
    rm -rf programs/test/cmake_package_install/build
    rm -f programs/test/cmake_package_install/Makefile
    rm -f programs/test/cmake_package_install/cmake_package_install

    # Restore files that may have been clobbered by the job
    for x in $files_to_back_up; do
        if [[ -e "$x$backup_suffix" ]]; then
            cp -p "$x$backup_suffix" "$x"
        fi
    done
}

# This is a helper function to be used in psasim builds. It is meant to clean
# up the library's workspace after the server build and before the client
# build. Built libraries (mbedcrypto, mbedx509 and mbedtls) are supposed to be
# already copied to psasim folder at this point.
helper_psasim_cleanup_before_client() {
    # Clean up library files
    make -C library clean
    # Clean up intermediate files that were used to build the server
    make -C $PSASIM_PATH clean_server_intermediate_files
    # Restore files that were backup before building library files. This
    # includes $CONFIG_H and $CRYPTO_CONFIG_H.
    for x in $files_to_back_up; do
        if [[ -e "$x$backup_suffix" ]]; then
            cp -p "$x$backup_suffix" "$x"
        fi
    done
}

# Final cleanup when this script exits (except when exiting on a failure
# in non-keep-going mode).
final_cleanup () {
    cleanup

    for x in $files_to_back_up; do
        rm -f "$x$backup_suffix"
    done
}

# Executed on exit. May be redefined depending on command line options.
final_report () {
    :
}

fatal_signal () {
    final_cleanup
    final_report $1
    trap - $1
    kill -$1 $$
}

trap 'fatal_signal HUP' HUP
trap 'fatal_signal INT' INT
trap 'fatal_signal TERM' TERM

# Number of processors on this machine. Used as the default setting
# for parallel make.
all_sh_nproc ()
{
    {
        nproc || # Linux
        sysctl -n hw.ncpuonline || # NetBSD, OpenBSD
        sysctl -n hw.ncpu || # FreeBSD
        echo 1
    } 2>/dev/null
}

msg()
{
    if [ -n "${current_component:-}" ]; then
        current_section="${current_component#component_}: $1"
    else
        current_section="$1"
    fi

    if [ $QUIET -eq 1 ]; then
        return
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

    msg "build: ARM Compiler 6 ($FLAGS)"
    make clean
    ARM_TOOL_VARIANT="ult" CC="$ARMC6_CC" AR="$ARMC6_AR" CFLAGS="$FLAGS" \
                    WARNING_CFLAGS='-Werror -xc -std=c99' make lib

    msg "size: ARM Compiler 6 ($FLAGS)"
    "$ARMC6_FROMELF" -z library/*.o
    if [ -n ${PSA_CORE_PATH} ]; then
        "$ARMC6_FROMELF" -z ${PSA_CORE_PATH}/*.o
    fi
    if [ -n ${BUILTIN_SRC_PATH} ]; then
        "$ARMC6_FROMELF" -z ${BUILTIN_SRC_PATH}/*.o
    fi
}

err_msg()
{
    echo "$1" >&2
}

check_tools()
{
    for tool in "$@"; do
        if ! `type "$tool" >/dev/null 2>&1`; then
            err_msg "$tool not found!"
            exit 1
        fi
    done
}

pre_parse_command_line () {
    COMMAND_LINE_COMPONENTS=
    all_except=0
    error_test=0
    list_components=0
    restore_first=0
    no_armcc=

    # Note that legacy options are ignored instead of being omitted from this
    # list of options, so invocations that worked with previous version of
    # all.sh will still run and work properly.
    while [ $# -gt 0 ]; do
        case "$1" in
            --append-outcome) append_outcome=1;;
            --arm-none-eabi-gcc-prefix) shift; ARM_NONE_EABI_GCC_PREFIX="$1";;
            --arm-linux-gnueabi-gcc-prefix) shift; ARM_LINUX_GNUEABI_GCC_PREFIX="$1";;
            --armcc) no_armcc=;;
            --armc5-bin-dir) shift; ARMC5_BIN_DIR="$1";;
            --armc6-bin-dir) shift; ARMC6_BIN_DIR="$1";;
            --clang-earliest) shift; CLANG_EARLIEST="$1";;
            --clang-latest) shift; CLANG_LATEST="$1";;
            --error-test) error_test=$((error_test + 1));;
            --except) all_except=1;;
            --force|-f) FORCE=1;;
            --gcc-earliest) shift; GCC_EARLIEST="$1";;
            --gcc-latest) shift; GCC_LATEST="$1";;
            --gnutls-cli) shift; GNUTLS_CLI="$1";;
            --gnutls-legacy-cli) shift;; # ignored for backward compatibility
            --gnutls-legacy-serv) shift;; # ignored for backward compatibility
            --gnutls-serv) shift; GNUTLS_SERV="$1";;
            --help|-h) usage; exit;;
            --keep-going|-k) KEEP_GOING=1;;
            --list-all-components) printf '%s\n' $ALL_COMPONENTS; exit;;
            --list-components) list_components=1;;
            --memory|-m) MEMORY=1;;
            --no-append-outcome) append_outcome=0;;
            --no-armcc) no_armcc=1;;
            --no-force) FORCE=0;;
            --no-keep-going) KEEP_GOING=0;;
            --no-memory) MEMORY=0;;
            --no-quiet) QUIET=0;;
            --openssl) shift; OPENSSL="$1";;
            --openssl-next) shift; OPENSSL_NEXT="$1";;
            --outcome-file) shift; MBEDTLS_TEST_OUTCOME_FILE="$1";;
            --out-of-source-dir) shift; OUT_OF_SOURCE_DIR="$1";;
            --quiet|-q) QUIET=1;;
            --random-seed) unset SEED;;
            --release-test|-r) SEED=$RELEASE_SEED;;
            --restore) restore_first=1;;
            --seed|-s) shift; SEED="$1";;
            -*)
                echo >&2 "Unknown option: $1"
                echo >&2 "Run $0 --help for usage."
                exit 120
                ;;
            *) COMMAND_LINE_COMPONENTS="$COMMAND_LINE_COMPONENTS $1";;
        esac
        shift
    done

    # Exclude components that are not supported on this platform.
    SUPPORTED_COMPONENTS=
    for component in $ALL_COMPONENTS; do
        case $(type "support_$component" 2>&1) in
            *' function'*)
                if ! support_$component; then continue; fi;;
        esac
        SUPPORTED_COMPONENTS="$SUPPORTED_COMPONENTS $component"
    done

    if [ $list_components -eq 1 ]; then
        printf '%s\n' $SUPPORTED_COMPONENTS
        exit
    fi

    # With no list of components, run everything.
    if [ -z "$COMMAND_LINE_COMPONENTS" ] && [ $restore_first -eq 0 ]; then
        all_except=1
    fi

    # --no-armcc is a legacy option. The modern way is --except '*_armcc*'.
    # Ignore it if components are listed explicitly on the command line.
    if [ -n "$no_armcc" ] && [ $all_except -eq 1 ]; then
        COMMAND_LINE_COMPONENTS="$COMMAND_LINE_COMPONENTS *_armcc*"
    fi

    # Error out if an explicitly requested component doesn't exist.
    if [ $all_except -eq 0 ]; then
        unsupported=0
        # Temporarily disable wildcard expansion so that $COMMAND_LINE_COMPONENTS
        # only does word splitting.
        set -f
        for component in $COMMAND_LINE_COMPONENTS; do
            set +f
            # If the requested name includes a wildcard character, don't
            # check it. Accept wildcard patterns that don't match anything.
            case $component in
                *[*?\[]*) continue;;
            esac
            case " $SUPPORTED_COMPONENTS " in
                *" $component "*) :;;
                *)
                    echo >&2 "Component $component was explicitly requested, but is not known or not supported."
                    unsupported=$((unsupported + 1));;
            esac
        done
        set +f
        if [ $unsupported -ne 0 ]; then
            exit 2
        fi
    fi

    # Build the list of components to run.
    RUN_COMPONENTS=
    for component in $SUPPORTED_COMPONENTS; do
        if is_component_included "$component"; [ $? -eq $all_except ]; then
            RUN_COMPONENTS="$RUN_COMPONENTS $component"
        fi
    done

    unset all_except
    unset no_armcc
}

pre_check_git () {
    if [ $FORCE -eq 1 ]; then
        rm -rf "$OUT_OF_SOURCE_DIR"
        git checkout-index -f -q $CONFIG_H
        cleanup
    else

        if [ -d "$OUT_OF_SOURCE_DIR" ]; then
            echo "Warning - there is an existing directory at '$OUT_OF_SOURCE_DIR'" >&2
            echo "You can either delete this directory manually, or force the test by rerunning"
            echo "the script as: $0 --force --out-of-source-dir $OUT_OF_SOURCE_DIR"
            exit 1
        fi

        if ! git diff --quiet "$CONFIG_H"; then
            err_msg "Warning - the configuration file '$CONFIG_H' has been edited. "
            echo "You can either delete or preserve your work, or force the test by rerunning the"
            echo "script as: $0 --force"
            exit 1
        fi
    fi
}

pre_restore_files () {
    # If the makefiles have been generated by a framework such as cmake,
    # restore them from git. If the makefiles look like modifications from
    # the ones checked into git, take care not to modify them. Whatever
    # this function leaves behind is what the script will restore before
    # each component.
    case "$(head -n1 Makefile)" in
        *[Gg]enerated*)
            git update-index --no-skip-worktree Makefile library/Makefile programs/Makefile tests/Makefile programs/fuzz/Makefile
            git checkout -- Makefile library/Makefile programs/Makefile tests/Makefile programs/fuzz/Makefile
            ;;
    esac
}

pre_back_up () {
    for x in $files_to_back_up; do
        cp -p "$x" "$x$backup_suffix"
    done
}

pre_setup_keep_going () {
    failure_count=0 # Number of failed components
    last_failure_status=0 # Last failure status in this component

    # See err_trap
    previous_failure_status=0
    previous_failed_command=
    previous_failure_funcall_depth=0
    unset report_failed_command

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

    # Keep a summary of failures in a file. We'll print it out at the end.
    failure_summary_file=$PWD/all-sh-failures-$$.log
    : >"$failure_summary_file"

    # Whether it makes sense to keep a component going after the specified
    # command fails (test command) or not (configure or build).
    # This function normally receives the failing simple command
    # ($BASH_COMMAND) as an argument, but if $report_failed_command is set,
    # this is passed instead.
    # This doesn't have to be 100% accurate: all failures are recorded anyway.
    # False positives result in running things that can't be expected to
    # work. False negatives result in things not running after something else
    # failed even though they might have given useful feedback.
    can_keep_going_after_failure () {
        case "$1" in
            "msg "*) false;;
            "cd "*) false;;
            "diff "*) true;;
            *make*[\ /]tests*) false;; # make tests, make CFLAGS=-I../tests, ...
            *test*) true;; # make test, tests/stuff, env V=v tests/stuff, ...
            *make*check*) true;;
            "grep "*) true;;
            "[ "*) true;;
            "! "*) true;;
            *) false;;
        esac
    }

    # This function runs if there is any error in a component.
    # It must either exit with a nonzero status, or set
    # last_failure_status to a nonzero value.
    err_trap () {
        # Save $? (status of the failing command). This must be the very
        # first thing, before $? is overridden.
        last_failure_status=$?
        failed_command=${report_failed_command-$BASH_COMMAND}

        if [[ $last_failure_status -eq $previous_failure_status &&
              "$failed_command" == "$previous_failed_command" &&
              ${#FUNCNAME[@]} == $((previous_failure_funcall_depth - 1)) ]]
        then
            # The same command failed twice in a row, but this time one level
            # less deep in the function call stack. This happens when the last
            # command of a function returns a nonzero status, and the function
            # returns that same status. Ignore the second failure.
            previous_failure_funcall_depth=${#FUNCNAME[@]}
            return
        fi
        previous_failure_status=$last_failure_status
        previous_failed_command=$failed_command
        previous_failure_funcall_depth=${#FUNCNAME[@]}

        text="$current_section: $failed_command -> $last_failure_status"
        echo "${start_red}^^^^$text^^^^${end_color}" >&2
        echo "$text" >>"$failure_summary_file"

        # If the command is fatal (configure or build command), stop this
        # component. Otherwise (test command) keep the component running
        # (run more tests from the same build).
        if ! can_keep_going_after_failure "$failed_command"; then
            exit $last_failure_status
        fi
    }

    final_report () {
        if [ $failure_count -gt 0 ]; then
            echo
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            echo "${start_red}FAILED: $failure_count components${end_color}"
            cat "$failure_summary_file"
            echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        elif [ -z "${1-}" ]; then
            echo "SUCCESS :)"
        fi
        if [ -n "${1-}" ]; then
            echo "Killed by SIG$1."
        fi
        rm -f "$failure_summary_file"
        if [ $failure_count -gt 0 ]; then
            exit 1
        fi
    }
}

# record_status() and if_build_succeeded() are kept temporarily for backward
# compatibility. Don't use them in new components.
record_status () {
    "$@"
}
if_build_succeeded () {
    "$@"
}

# '! true' does not trigger the ERR trap. Arrange to trigger it, with
# a reasonably informative error message (not just "$@").
not () {
    if "$@"; then
        report_failed_command="! $*"
        false
        unset report_failed_command
    fi
}

pre_prepare_outcome_file () {
    case "$MBEDTLS_TEST_OUTCOME_FILE" in
      [!/]*) MBEDTLS_TEST_OUTCOME_FILE="$PWD/$MBEDTLS_TEST_OUTCOME_FILE";;
    esac
    if [ -n "$MBEDTLS_TEST_OUTCOME_FILE" ] && [ "$append_outcome" -eq 0 ]; then
        rm -f "$MBEDTLS_TEST_OUTCOME_FILE"
    fi
}

pre_print_configuration () {
    if [ $QUIET -eq 1 ]; then
        return
    fi

    msg "info: $0 configuration"
    echo "MEMORY: $MEMORY"
    echo "FORCE: $FORCE"
    echo "MBEDTLS_TEST_OUTCOME_FILE: ${MBEDTLS_TEST_OUTCOME_FILE:-(none)}"
    echo "SEED: ${SEED-"UNSET"}"
    echo
    echo "OPENSSL: $OPENSSL"
    echo "OPENSSL_NEXT: $OPENSSL_NEXT"
    echo "GNUTLS_CLI: $GNUTLS_CLI"
    echo "GNUTLS_SERV: $GNUTLS_SERV"
    echo "ARMC5_BIN_DIR: $ARMC5_BIN_DIR"
    echo "ARMC6_BIN_DIR: $ARMC6_BIN_DIR"
}

# Make sure the tools we need are available.
pre_check_tools () {
    # Build the list of variables to pass to output_env.sh.
    set env

    case " $RUN_COMPONENTS " in
        # Require OpenSSL and GnuTLS if running any tests (as opposed to
        # only doing builds). Not all tests run OpenSSL and GnuTLS, but this
        # is a good enough approximation in practice.
        *" test_"* | *" release_test_"*)
            # To avoid setting OpenSSL and GnuTLS for each call to compat.sh
            # and ssl-opt.sh, we just export the variables they require.
            export OPENSSL="$OPENSSL"
            export GNUTLS_CLI="$GNUTLS_CLI"
            export GNUTLS_SERV="$GNUTLS_SERV"
            # Avoid passing --seed flag in every call to ssl-opt.sh
            if [ -n "${SEED-}" ]; then
                export SEED
            fi
            set "$@" OPENSSL="$OPENSSL"
            set "$@" GNUTLS_CLI="$GNUTLS_CLI" GNUTLS_SERV="$GNUTLS_SERV"
            check_tools "$OPENSSL" "$OPENSSL_NEXT" \
                        "$GNUTLS_CLI" "$GNUTLS_SERV"
            ;;
    esac

    case " $RUN_COMPONENTS " in
        *_doxygen[_\ ]*) check_tools "doxygen" "dot";;
    esac

    case " $RUN_COMPONENTS " in
        *_arm_none_eabi_gcc[_\ ]*) check_tools "${ARM_NONE_EABI_GCC_PREFIX}gcc";;
    esac

    case " $RUN_COMPONENTS " in
        *_mingw[_\ ]*) check_tools "i686-w64-mingw32-gcc";;
    esac

    case " $RUN_COMPONENTS " in
        *" test_zeroize "*) check_tools "gdb";;
    esac

    case " $RUN_COMPONENTS " in
        *_armcc*)
            ARMC5_CC="$ARMC5_BIN_DIR/armcc"
            ARMC5_AR="$ARMC5_BIN_DIR/armar"
            ARMC5_FROMELF="$ARMC5_BIN_DIR/fromelf"
            ARMC6_CC="$ARMC6_BIN_DIR/armclang"
            ARMC6_AR="$ARMC6_BIN_DIR/armar"
            ARMC6_FROMELF="$ARMC6_BIN_DIR/fromelf"
            check_tools "$ARMC5_CC" "$ARMC5_AR" "$ARMC5_FROMELF" \
                        "$ARMC6_CC" "$ARMC6_AR" "$ARMC6_FROMELF";;
    esac

    # past this point, no call to check_tool, only printing output
    if [ $QUIET -eq 1 ]; then
        return
    fi

    msg "info: output_env.sh"
    case $RUN_COMPONENTS in
        *_armcc*)
            set "$@" ARMC5_CC="$ARMC5_CC" ARMC6_CC="$ARMC6_CC" RUN_ARMCC=1;;
        *) set "$@" RUN_ARMCC=0;;
    esac
    "$@" scripts/output_env.sh
}

pre_generate_files() {
    # since make doesn't have proper dependencies, remove any possibly outdate
    # file that might be around before generating fresh ones
    make neat
    if [ $QUIET -eq 1 ]; then
        make generated_files >/dev/null
    else
        make generated_files
    fi
}

clang_version() {
    if command -v clang > /dev/null ; then
        clang --version|grep version|sed -E 's#.*version ([0-9]+).*#\1#'
    else
        echo 0  # report version 0 for "no clang"
    fi
}

################################################################
#### Helpers for components using libtestdriver1
################################################################

# How to use libtestdriver1
# -------------------------
#
# 1. Define the list algorithms and key types to accelerate,
#    designated the same way as PSA_WANT_ macros but without PSA_WANT_.
#    Examples:
#      - loc_accel_list="ALG_JPAKE"
#      - loc_accel_list="ALG_FFDH KEY_TYPE_DH_KEY_PAIR KEY_TYPE_DH_PUBLIC_KEY"
# 2. Make configurations changes for the driver and/or main libraries.
#    2a. Call helper_libtestdriver1_adjust_config <base>, where the argument
#        can be either "default" to start with the default config, or a name
#        supported by scripts/config.py (for example, "full"). This selects
#        the base to use, and makes common adjustments.
#    2b. If desired, adjust the PSA_WANT symbols in psa/crypto_config.h.
#        These changes affect both the driver and the main libraries.
#        (Note: they need to have the same set of PSA_WANT symbols, as that
#        determines the ABI between them.)
#    2c. Adjust MBEDTLS_ symbols in mbedtls_config.h. This only affects the
#        main libraries. Typically, you want to disable the module(s) that are
#        being accelerated. You may need to also disable modules that depend
#        on them or options that are not supported with drivers.
#    2d. On top of psa/crypto_config.h, the driver library uses its own config
#        file: tests/include/test/drivers/config_test_driver.h. You usually
#        don't need to edit it: using loc_extra_list (see below) is preferred.
#        However, when there's no PSA symbol for what you want to enable,
#        calling scripts/config.py on this file remains the only option.
# 3. Build the driver library, then the main libraries, test, and programs.
#    3a. Call helper_libtestdriver1_make_drivers "$loc_accel_list". You may
#        need to enable more algorithms here, typically hash algorithms when
#        accelerating some signature algorithms (ECDSA, RSAv2). This is done
#        by passing a 2nd argument listing the extra algorithms.
#        Example:
#          loc_extra_list="ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512"
#          helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"
#    3b. Call helper_libtestdriver1_make_main "$loc_accel_list". Any
#        additional arguments will be passed to make: this can be useful if
#        you don't want to build everything when iterating during development.
#        Example:
#          helper_libtestdriver1_make_main "$loc_accel_list" -C tests test_suite_foo
# 4. Run the tests you want.

# Adjust the configuration - for both libtestdriver1 and main library,
# as they should have the same PSA_WANT macros.
helper_libtestdriver1_adjust_config() {
    base_config=$1
    # Select the base configuration
    if [ "$base_config" != "default" ]; then
        scripts/config.py "$base_config"
    fi

    # Enable PSA-based config (necessary to use drivers)
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG

    # Dynamic secure element support is a deprecated feature and needs to be disabled here.
    # This is done to have the same form of psa_key_attributes_s for libdriver and library.
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_SE_C

    # If threading is enabled on the normal build, then we need to enable it in the drivers as well,
    # otherwise we will end up running multithreaded tests without mutexes to protect them.
    if scripts/config.py get MBEDTLS_THREADING_C; then
        scripts/config.py -f "$CONFIG_TEST_DRIVER_H" set MBEDTLS_THREADING_C
    fi

    if scripts/config.py get MBEDTLS_THREADING_PTHREAD; then
        scripts/config.py -f "$CONFIG_TEST_DRIVER_H" set MBEDTLS_THREADING_PTHREAD
    fi
}

# Build the drivers library libtestdriver1.a (with ASan).
#
# Parameters:
# 1. a space-separated list of things to accelerate;
# 2. optional: a space-separate list of things to also support.
# Here "things" are PSA_WANT_ symbols but with PSA_WANT_ removed.
helper_libtestdriver1_make_drivers() {
    loc_accel_flags=$( echo "$1 ${2-}" | sed 's/[^ ]* */-DLIBTESTDRIVER1_MBEDTLS_PSA_ACCEL_&/g' )
    make CC=$ASAN_CC -C tests libtestdriver1.a CFLAGS=" $ASAN_CFLAGS $loc_accel_flags" LDFLAGS="$ASAN_CFLAGS"
}

# Build the main libraries, programs and tests,
# linking to the drivers library (with ASan).
#
# Parameters:
# 1. a space-separated list of things to accelerate;
# *. remaining arguments if any are passed directly to make
#    (examples: lib, -C tests test_suite_xxx, etc.)
# Here "things" are PSA_WANT_ symbols but with PSA_WANT_ removed.
helper_libtestdriver1_make_main() {
    loc_accel_list=$1
    shift

    # we need flags both with and without the LIBTESTDRIVER1_ prefix
    loc_accel_flags=$( echo "$loc_accel_list" | sed 's/[^ ]* */-DLIBTESTDRIVER1_MBEDTLS_PSA_ACCEL_&/g' )
    loc_accel_flags="$loc_accel_flags $( echo "$loc_accel_list" | sed 's/[^ ]* */-DMBEDTLS_PSA_ACCEL_&/g' )"
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -I../tests/include -I../tests -I../../tests -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_TEST_LIBTESTDRIVER1 $loc_accel_flags" LDFLAGS="-ltestdriver1 $ASAN_CFLAGS" "$@"
}

# Set some default values $CONFIG_H in order to build server or client sides
# in PSASIM. There is only 1 mandatory parameter:
# - $1: target which can be "client" or "server"
helper_psasim_config() {
    TARGET=$1

    if [ "$TARGET" == "client" ]; then
        scripts/config.py full
        scripts/config.py unset MBEDTLS_PSA_CRYPTO_C
        scripts/config.py unset MBEDTLS_PSA_CRYPTO_STORAGE_C
        # Dynamic secure element support is a deprecated feature and it is not
        # available when CRYPTO_C and PSA_CRYPTO_STORAGE_C are disabled.
        scripts/config.py unset MBEDTLS_PSA_CRYPTO_SE_C
        # Disable potentially problematic features
        scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT
        scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
        scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
        scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
        scripts/config.py unset MBEDTLS_ECP_RESTARTABLE
        scripts/config.py unset MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
    else
        scripts/config.py crypto_full
        scripts/config.py unset MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
        # We need to match the client with MBEDTLS_PSA_CRYPTO_SE_C
        scripts/config.py unset MBEDTLS_PSA_CRYPTO_SE_C
        # Also ensure MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER not set (to match client)
        scripts/config.py unset MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
    fi
}

# Helper to build the libraries for client/server in PSASIM. If the server is
# being built, then it builds also the final executable.
# There is only 1 mandatory parameter:
# - $1: target which can be "client" or "server"
helper_psasim_build() {
    TARGET=$1
    shift
    TARGET_LIB=${TARGET}_libs

    make -C $PSASIM_PATH CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS" $TARGET_LIB "$@"

    # Build also the server application after its libraries have been built.
    if [ "$TARGET" == "server" ]; then
        make -C $PSASIM_PATH CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS" test/psa_server
    fi
}

################################################################
#### Configuration helpers
################################################################

# When called with no parameter this function disables all builtin curves.
# The function optionally accepts 1 parameter: a space-separated list of the
# curves that should be kept enabled.
helper_disable_builtin_curves() {
    allowed_list="${1:-}"
    scripts/config.py unset-all "MBEDTLS_ECP_DP_[0-9A-Z_a-z]*_ENABLED"

    for curve in $allowed_list; do
        scripts/config.py set $curve
    done
}

# Helper returning the list of supported elliptic curves from CRYPTO_CONFIG_H,
# without the "PSA_WANT_" prefix. This becomes handy for accelerating curves
# in the following helpers.
helper_get_psa_curve_list () {
    loc_list=""
    for item in $(sed -n 's/^#define PSA_WANT_\(ECC_[0-9A-Z_a-z]*\).*/\1/p' <"$CRYPTO_CONFIG_H"); do
        loc_list="$loc_list $item"
    done

    echo "$loc_list"
}

# Helper returning the list of supported DH groups from CRYPTO_CONFIG_H,
# without the "PSA_WANT_" prefix. This becomes handy for accelerating DH groups
# in the following helpers.
helper_get_psa_dh_group_list () {
    loc_list=""
    for item in $(sed -n 's/^#define PSA_WANT_\(DH_RFC7919_[0-9]*\).*/\1/p' <"$CRYPTO_CONFIG_H"); do
        loc_list="$loc_list $item"
    done

    echo "$loc_list"
}

# Get the list of uncommented PSA_WANT_KEY_TYPE_xxx_ from CRYPTO_CONFIG_H. This
# is useful to easily get a list of key type symbols to accelerate.
# The function accepts a single argument which is the key type: ECC, DH, RSA.
helper_get_psa_key_type_list() {
    key_type="$1"
    loc_list=""
    for item in $(sed -n "s/^#define PSA_WANT_\(KEY_TYPE_${key_type}_[0-9A-Z_a-z]*\).*/\1/p" <"$CRYPTO_CONFIG_H"); do
        # Skip DERIVE for elliptic keys since there is no driver dispatch for
        # it so it cannot be accelerated.
        if [ "$item" != "KEY_TYPE_ECC_KEY_PAIR_DERIVE" ]; then
            loc_list="$loc_list $item"
        fi
    done

    echo "$loc_list"
}

# Helper function for controlling (start & stop) the psasim server.
helper_psasim_server() {
    OPERATION=$1
    if [ "$OPERATION" == "start" ]; then
    (
        cd tests
        msg "start server"
        psa-client-server/psasim/test/start_server.sh
    )
    else
    (
        cd tests
        msg "terminate server and cleanup"
        psa-client-server/psasim//test/kill_server.sh
    )
    fi
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
    msg "Check: recursion.pl" # < 1s
    tests/scripts/recursion.pl library/*.c
    tests/scripts/recursion.pl ${PSA_CORE_PATH}/*.c
    tests/scripts/recursion.pl ${BUILTIN_SRC_PATH}/*.c
}

component_check_generated_files () {
    msg "Check: check-generated-files, files generated with make" # 2s
    make generated_files
    tests/scripts/check-generated-files.sh

    msg "Check: check-generated-files -u, files present" # 2s
    tests/scripts/check-generated-files.sh -u
    # Check that the generated files are considered up to date.
    tests/scripts/check-generated-files.sh

    msg "Check: check-generated-files -u, files absent" # 2s
    command make neat
    tests/scripts/check-generated-files.sh -u
    # Check that the generated files are considered up to date.
    tests/scripts/check-generated-files.sh

    # This component ends with the generated files present in the source tree.
    # This is necessary for subsequent components!
}

component_check_doxy_blocks () {
    msg "Check: doxygen markup outside doxygen blocks" # < 1s
    tests/scripts/check-doxy-blocks.pl
}

component_check_files () {
    msg "Check: file sanity checks (permissions, encodings)" # < 1s
    tests/scripts/check_files.py
}

component_check_changelog () {
    msg "Check: changelog entries" # < 1s
    rm -f ChangeLog.new
    scripts/assemble_changelog.py -o ChangeLog.new
    if [ -e ChangeLog.new ]; then
        # Show the diff for information. It isn't an error if the diff is
        # non-empty.
        diff -u ChangeLog ChangeLog.new || true
        rm ChangeLog.new
    fi
}

component_check_names () {
    msg "Check: declared and exported names (builds the library)" # < 3s
    tests/scripts/check_names.py -v
}

component_check_test_cases () {
    msg "Check: test case descriptions" # < 1s
    if [ $QUIET -eq 1 ]; then
        opt='--quiet'
    else
        opt=''
    fi
    tests/scripts/check_test_cases.py -q $opt
    unset opt
}

component_check_test_dependencies () {
    msg "Check: test case dependencies: legacy vs PSA" # < 1s
    # The purpose of this component is to catch unjustified dependencies on
    # legacy feature macros (MBEDTLS_xxx) in PSA tests. Generally speaking,
    # PSA test should use PSA feature macros (PSA_WANT_xxx, more rarely
    # MBEDTLS_PSA_xxx).
    #
    # Most of the time, use of legacy MBEDTLS_xxx macros are mistakes, which
    # this component is meant to catch. However a few of them are justified,
    # mostly by the absence of a PSA equivalent, so this component includes a
    # list of expected exceptions.

    found="check-test-deps-found-$$"
    expected="check-test-deps-expected-$$"

    # Find legacy dependencies in PSA tests
    grep 'depends_on' \
        tests/suites/test_suite_psa*.data tests/suites/test_suite_psa*.function |
        grep -Eo '!?MBEDTLS_[^: ]*' |
        grep -v -e MBEDTLS_PSA_ -e MBEDTLS_TEST_ |
        sort -u > $found

    # Expected ones with justification - keep in sorted order by ASCII table!
    rm -f $expected
    # No PSA equivalent - WANT_KEY_TYPE_AES means all sizes
    echo "!MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH" >> $expected
    # No PSA equivalent - used to skip decryption tests in PSA-ECB, CBC/XTS/NIST_KW/DES
    echo "!MBEDTLS_BLOCK_CIPHER_NO_DECRYPT" >> $expected
    # MBEDTLS_ASN1_WRITE_C is used by import_rsa_made_up() in test_suite_psa_crypto
    # in order to build a fake RSA key of the wanted size based on
    # PSA_VENDOR_RSA_MAX_KEY_BITS. The legacy module is only used by
    # the test code and that's probably the most convenient way of achieving
    # the test's goal.
    echo "MBEDTLS_ASN1_WRITE_C" >> $expected
    # No PSA equivalent - we should probably have one in the future.
    echo "MBEDTLS_ECP_RESTARTABLE" >> $expected
    # No PSA equivalent - needed by some init tests
    echo "MBEDTLS_ENTROPY_NV_SEED" >> $expected
    # No PSA equivalent - required to run threaded tests.
    echo "MBEDTLS_THREADING_PTHREAD" >> $expected

    # Compare reality with expectation.
    # We want an exact match, to ensure the above list remains up-to-date.
    #
    # The output should be empty. When it's not:
    # - Each '+' line is a macro that was found but not expected. You want to
    # find where that macro occurs, and either replace it with PSA macros, or
    # add it to the exceptions list above with a justification.
    # - Each '-' line is a macro that was expected but not found; it means the
    # exceptions list above should be updated by removing that macro.
    diff -U0 $expected $found

    rm $found $expected
}

component_check_doxygen_warnings () {
    msg "Check: doxygen warnings (builds the documentation)" # ~ 3s
    tests/scripts/doxygen.sh
}



################################################################
#### Build and test many configurations and targets
################################################################

component_test_default_out_of_box () {
    msg "build: make, default config (out-of-box)" # ~1min
    make
    # Disable fancy stuff
    unset MBEDTLS_TEST_OUTCOME_FILE

    msg "test: main suites make, default config (out-of-box)" # ~10s
    make test

    msg "selftest: make, default config (out-of-box)" # ~10s
    programs/test/selftest

    msg "program demos: make, default config (out-of-box)" # ~10s
    tests/scripts/run_demos.py
}

component_test_default_cmake_gcc_asan () {
    msg "build: cmake, gcc, ASan" # ~ 1 min 50s
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "program demos (ASan build)" # ~10s
    tests/scripts/run_demos.py

    msg "test: selftest (ASan build)" # ~ 10s
    programs/test/selftest

    msg "test: metatests (GCC, ASan build)"
    tests/scripts/run-metatests.sh any asan poison

    msg "test: ssl-opt.sh (ASan build)" # ~ 1 min
    tests/ssl-opt.sh

    msg "test: compat.sh (ASan build)" # ~ 6 min
    tests/compat.sh

    msg "test: context-info.sh (ASan build)" # ~ 15 sec
    tests/context-info.sh
}

component_test_default_cmake_gcc_asan_new_bignum () {
    msg "build: cmake, gcc, ASan" # ~ 1 min 50s
    scripts/config.py set MBEDTLS_ECP_WITH_MPI_UINT
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: selftest (ASan build)" # ~ 10s
    programs/test/selftest

    msg "test: ssl-opt.sh (ASan build)" # ~ 1 min
    tests/ssl-opt.sh

    msg "test: compat.sh (ASan build)" # ~ 6 min
    tests/compat.sh

    msg "test: context-info.sh (ASan build)" # ~ 15 sec
    tests/context-info.sh
}

component_test_full_cmake_gcc_asan () {
    msg "build: full config, cmake, gcc, ASan"
    scripts/config.py full
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (inc. selftests) (full config, ASan build)"
    make test

    msg "test: selftest (full config, ASan build)" # ~ 10s
    programs/test/selftest

    msg "test: ssl-opt.sh (full config, ASan build)"
    tests/ssl-opt.sh

    # Note: the next two invocations cover all compat.sh test cases.
    # We should use the same here and in basic-build-test.sh.
    msg "test: compat.sh: default version (full config, ASan build)"
    tests/compat.sh -e 'ARIA\|CHACHA'

    msg "test: compat.sh: next: ARIA, Chacha (full config, ASan build)"
    env OPENSSL="$OPENSSL_NEXT" tests/compat.sh -e '^$' -f 'ARIA\|CHACHA'

    msg "test: context-info.sh (full config, ASan build)" # ~ 15 sec
    tests/context-info.sh
}


component_test_full_cmake_gcc_asan_new_bignum () {
    msg "build: full config, cmake, gcc, ASan"
    scripts/config.py full
    scripts/config.py set MBEDTLS_ECP_WITH_MPI_UINT
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (inc. selftests) (full config, new bignum, ASan)"
    make test

    msg "test: selftest (full config, new bignum, ASan)" # ~ 10s
    programs/test/selftest

    msg "test: ssl-opt.sh (full config, new bignum, ASan)"
    tests/ssl-opt.sh

    # Note: the next two invocations cover all compat.sh test cases.
    # We should use the same here and in basic-build-test.sh.
    msg "test: compat.sh: default version (full config, new bignum, ASan)"
    tests/compat.sh -e 'ARIA\|CHACHA'

    msg "test: compat.sh: next: ARIA, Chacha (full config, new bignum, ASan)"
    env OPENSSL="$OPENSSL_NEXT" tests/compat.sh -e '^$' -f 'ARIA\|CHACHA'

    msg "test: context-info.sh (full config, new bignum, ASan)" # ~ 15 sec
    tests/context-info.sh
}

component_test_psa_crypto_key_id_encodes_owner () {
    msg "build: full config + PSA_CRYPTO_KEY_ID_ENCODES_OWNER, cmake, gcc, ASan"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full config - USE_PSA_CRYPTO + PSA_CRYPTO_KEY_ID_ENCODES_OWNER, cmake, gcc, ASan"
    make test
}

component_test_psa_assume_exclusive_buffers () {
    msg "build: full config + MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS, cmake, gcc, ASan"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full config + MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS, cmake, gcc, ASan"
    make test
}

# check_renamed_symbols HEADER LIB
# Check that if HEADER contains '#define MACRO ...' then MACRO is not a symbol
# name is LIB.
check_renamed_symbols () {
    ! nm "$2" | sed 's/.* //' |
      grep -x -F "$(sed -n 's/^ *# *define  *\([A-Z_a-z][0-9A-Z_a-z]*\)..*/\1/p' "$1")"
}

component_build_psa_crypto_spm () {
    msg "build: full config + PSA_CRYPTO_KEY_ID_ENCODES_OWNER + PSA_CRYPTO_SPM, make, gcc"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
    scripts/config.py set MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
    scripts/config.py set MBEDTLS_PSA_CRYPTO_SPM
    # We can only compile, not link, since our test and sample programs
    # aren't equipped for the modified names used when MBEDTLS_PSA_CRYPTO_SPM
    # is active.
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -I../tests/include/spe' lib

    # Check that if a symbol is renamed by crypto_spe.h, the non-renamed
    # version is not present.
    echo "Checking for renamed symbols in the library"
    check_renamed_symbols tests/include/spe/crypto_spe.h library/libmbedcrypto.a
}

component_test_no_rsa_key_pair_generation() {
    msg "build: default config minus PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE"
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    scripts/config.py unset MBEDTLS_GENPRIME
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE
    make

    msg "test: default config minus PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE"
    make test
}

component_test_ref_configs () {
    msg "test/build: ref-configs (ASan build)" # ~ 6 min 20s
    # test-ref-configs works by overwriting mbedtls_config.h; this makes cmake
    # want to re-generate generated files that depend on it, quite correctly.
    # However this doesn't work as the generation script expects a specific
    # format for mbedtls_config.h, which the other files don't follow. Also,
    # cmake can't know this, but re-generation is actually not necessary as
    # the generated files only depend on the list of available options, not
    # whether they're on or off. So, disable cmake's (over-sensitive here)
    # dependency resolution for generated files and just rely on them being
    # present (thanks to pre_generate_files) by turning GEN_FILES off.
    CC=$ASAN_CC cmake -D GEN_FILES=Off -D CMAKE_BUILD_TYPE:String=Asan .
    tests/scripts/test-ref-configs.pl
}

component_test_no_renegotiation () {
    msg "build: Default + !MBEDTLS_SSL_RENEGOTIATION (ASan build)" # ~ 6 min
    scripts/config.py unset MBEDTLS_SSL_RENEGOTIATION
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: !MBEDTLS_SSL_RENEGOTIATION - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: !MBEDTLS_SSL_RENEGOTIATION - ssl-opt.sh (ASan build)" # ~ 6 min
    tests/ssl-opt.sh
}

component_test_no_pem_no_fs () {
    msg "build: Default + !MBEDTLS_PEM_PARSE_C + !MBEDTLS_FS_IO (ASan build)"
    scripts/config.py unset MBEDTLS_PEM_PARSE_C
    scripts/config.py unset MBEDTLS_FS_IO
    scripts/config.py unset MBEDTLS_PSA_ITS_FILE_C # requires a filesystem
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_STORAGE_C # requires PSA ITS
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: !MBEDTLS_PEM_PARSE_C !MBEDTLS_FS_IO - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: !MBEDTLS_PEM_PARSE_C !MBEDTLS_FS_IO - ssl-opt.sh (ASan build)" # ~ 6 min
    tests/ssl-opt.sh
}

component_test_rsa_no_crt () {
    msg "build: Default + RSA_NO_CRT (ASan build)" # ~ 6 min
    scripts/config.py set MBEDTLS_RSA_NO_CRT
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: RSA_NO_CRT - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: RSA_NO_CRT - RSA-related part of ssl-opt.sh (ASan build)" # ~ 5s
    tests/ssl-opt.sh -f RSA

    msg "test: RSA_NO_CRT - RSA-related part of compat.sh (ASan build)" # ~ 3 min
    tests/compat.sh -t RSA

    msg "test: RSA_NO_CRT - RSA-related part of context-info.sh (ASan build)" # ~ 15 sec
    tests/context-info.sh
}

component_test_no_ctr_drbg_classic () {
    msg "build: Full minus CTR_DRBG, classic crypto in TLS"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_CTR_DRBG_C
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: Full minus CTR_DRBG, classic crypto - main suites"
    make test

    # In this configuration, the TLS test programs use HMAC_DRBG.
    # The SSL tests are slow, so run a small subset, just enough to get
    # confidence that the SSL code copes with HMAC_DRBG.
    msg "test: Full minus CTR_DRBG, classic crypto - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f 'Default\|SSL async private.*delay=\|tickets enabled on server'

    msg "test: Full minus CTR_DRBG, classic crypto - compat.sh (subset)"
    tests/compat.sh -m tls12 -t 'ECDSA PSK' -V NO -p OpenSSL
}

component_test_no_ctr_drbg_use_psa () {
    msg "build: Full minus CTR_DRBG, PSA crypto in TLS"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_CTR_DRBG_C
    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: Full minus CTR_DRBG, USE_PSA_CRYPTO - main suites"
    make test

    # In this configuration, the TLS test programs use HMAC_DRBG.
    # The SSL tests are slow, so run a small subset, just enough to get
    # confidence that the SSL code copes with HMAC_DRBG.
    msg "test: Full minus CTR_DRBG, USE_PSA_CRYPTO - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f 'Default\|SSL async private.*delay=\|tickets enabled on server'

    msg "test: Full minus CTR_DRBG, USE_PSA_CRYPTO - compat.sh (subset)"
    tests/compat.sh -m tls12 -t 'ECDSA PSK' -V NO -p OpenSSL
}

component_test_no_hmac_drbg_classic () {
    msg "build: Full minus HMAC_DRBG, classic crypto in TLS"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_ECDSA_DETERMINISTIC # requires HMAC_DRBG
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: Full minus HMAC_DRBG, classic crypto - main suites"
    make test

    # Normally our ECDSA implementation uses deterministic ECDSA. But since
    # HMAC_DRBG is disabled in this configuration, randomized ECDSA is used
    # instead.
    # Test SSL with non-deterministic ECDSA. Only test features that
    # might be affected by how ECDSA signature is performed.
    msg "test: Full minus HMAC_DRBG, classic crypto - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f 'Default\|SSL async private: sign'

    # To save time, only test one protocol version, since this part of
    # the protocol is identical in (D)TLS up to 1.2.
    msg "test: Full minus HMAC_DRBG, classic crypto - compat.sh (ECDSA)"
    tests/compat.sh -m tls12 -t 'ECDSA'
}

component_test_no_hmac_drbg_use_psa () {
    msg "build: Full minus HMAC_DRBG, PSA crypto in TLS"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_ECDSA_DETERMINISTIC # requires HMAC_DRBG
    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: Full minus HMAC_DRBG, USE_PSA_CRYPTO - main suites"
    make test

    # Normally our ECDSA implementation uses deterministic ECDSA. But since
    # HMAC_DRBG is disabled in this configuration, randomized ECDSA is used
    # instead.
    # Test SSL with non-deterministic ECDSA. Only test features that
    # might be affected by how ECDSA signature is performed.
    msg "test: Full minus HMAC_DRBG, USE_PSA_CRYPTO - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f 'Default\|SSL async private: sign'

    # To save time, only test one protocol version, since this part of
    # the protocol is identical in (D)TLS up to 1.2.
    msg "test: Full minus HMAC_DRBG, USE_PSA_CRYPTO - compat.sh (ECDSA)"
    tests/compat.sh -m tls12 -t 'ECDSA'
}

component_test_psa_external_rng_no_drbg_classic () {
    msg "build: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG, classic crypto in TLS"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py set MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
    scripts/config.py unset MBEDTLS_ENTROPY_C
    scripts/config.py unset MBEDTLS_ENTROPY_NV_SEED
    scripts/config.py unset MBEDTLS_PLATFORM_NV_SEED_ALT
    scripts/config.py unset MBEDTLS_CTR_DRBG_C
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_ECDSA_DETERMINISTIC # requires HMAC_DRBG
    # When MBEDTLS_USE_PSA_CRYPTO is disabled and there is no DRBG,
    # the SSL test programs don't have an RNG and can't work. Explicitly
    # make them use the PSA RNG with -DMBEDTLS_TEST_USE_PSA_CRYPTO_RNG.
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -DMBEDTLS_TEST_USE_PSA_CRYPTO_RNG" LDFLAGS="$ASAN_CFLAGS"

    msg "test: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG, classic crypto - main suites"
    make test

    msg "test: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG, classic crypto - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f 'Default'
}

component_test_psa_external_rng_no_drbg_use_psa () {
    msg "build: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG, PSA crypto in TLS"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
    scripts/config.py unset MBEDTLS_ENTROPY_C
    scripts/config.py unset MBEDTLS_ENTROPY_NV_SEED
    scripts/config.py unset MBEDTLS_PLATFORM_NV_SEED_ALT
    scripts/config.py unset MBEDTLS_CTR_DRBG_C
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_ECDSA_DETERMINISTIC # requires HMAC_DRBG
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG, PSA crypto - main suites"
    make test

    msg "test: PSA_CRYPTO_EXTERNAL_RNG minus *_DRBG, PSA crypto - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f 'Default\|opaque'
}

component_test_psa_external_rng_use_psa_crypto () {
    msg "build: full + PSA_CRYPTO_EXTERNAL_RNG + USE_PSA_CRYPTO minus CTR_DRBG"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_CTR_DRBG_C
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full + PSA_CRYPTO_EXTERNAL_RNG + USE_PSA_CRYPTO minus CTR_DRBG"
    make test

    msg "test: full + PSA_CRYPTO_EXTERNAL_RNG + USE_PSA_CRYPTO minus CTR_DRBG"
    tests/ssl-opt.sh -f 'Default\|opaque'
}

component_test_psa_inject_entropy () {
    msg "build: full + MBEDTLS_PSA_INJECT_ENTROPY"
    scripts/config.py full
    scripts/config.py set MBEDTLS_PSA_INJECT_ENTROPY
    scripts/config.py set MBEDTLS_ENTROPY_NV_SEED
    scripts/config.py set MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
    scripts/config.py unset MBEDTLS_PLATFORM_NV_SEED_ALT
    scripts/config.py unset MBEDTLS_PLATFORM_STD_NV_SEED_READ
    scripts/config.py unset MBEDTLS_PLATFORM_STD_NV_SEED_WRITE
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS '-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/user-config-for-test.h\"'" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full + MBEDTLS_PSA_INJECT_ENTROPY"
    make test
}

component_test_sw_inet_pton () {
    msg "build: default plus MBEDTLS_TEST_SW_INET_PTON"

    # MBEDTLS_TEST_HOOKS required for x509_crt_parse_cn_inet_pton
    scripts/config.py set MBEDTLS_TEST_HOOKS
    make CFLAGS="-DMBEDTLS_TEST_SW_INET_PTON"

    msg "test: default plus MBEDTLS_TEST_SW_INET_PTON"
    make test
}

component_full_no_pkparse_pkwrite() {
    msg "build: full without pkparse and pkwrite"

    scripts/config.py crypto_full
    scripts/config.py unset MBEDTLS_PK_PARSE_C
    scripts/config.py unset MBEDTLS_PK_WRITE_C

    make CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    # Ensure that PK_[PARSE|WRITE]_C were not re-enabled accidentally (additive config).
    not grep mbedtls_pk_parse_key ${BUILTIN_SRC_PATH}/pkparse.o
    not grep mbedtls_pk_write_key_der ${BUILTIN_SRC_PATH}/pkwrite.o

    msg "test: full without pkparse and pkwrite"
    make test
}

component_test_crypto_full_md_light_only () {
    msg "build: crypto_full with only the light subset of MD"
    scripts/config.py crypto_full

    # Disable MD
    scripts/config.py unset MBEDTLS_MD_C
    # Disable direct dependencies of MD_C
    scripts/config.py unset MBEDTLS_HKDF_C
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_PKCS7_C
    # Disable indirect dependencies of MD_C
    scripts/config.py unset MBEDTLS_ECDSA_DETERMINISTIC # needs HMAC_DRBG
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_DETERMINISTIC_ECDSA
    # Disable things that would auto-enable MD_C
    scripts/config.py unset MBEDTLS_PKCS5_C

    # Note: MD-light is auto-enabled in build_info.h by modules that need it,
    # which we haven't disabled, so no need to explicitly enable it.
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    # Make sure we don't have the HMAC functions, but the hashing functions
    not grep mbedtls_md_hmac ${BUILTIN_SRC_PATH}/md.o
    grep mbedtls_md ${BUILTIN_SRC_PATH}/md.o

    msg "test: crypto_full with only the light subset of MD"
    make test
}

component_test_full_no_cipher () {
    msg "build: full no CIPHER"

    scripts/config.py full
    scripts/config.py unset MBEDTLS_CIPHER_C

    # The built-in implementation of the following algs/key-types depends
    # on CIPHER_C so we disable them.
    # This does not hold for KEY_TYPE_CHACHA20 and ALG_CHACHA20_POLY1305
    # so we keep them enabled.
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM_STAR_NO_TAG
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CMAC
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CBC_NO_PADDING
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CBC_PKCS7
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CFB
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CTR
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_ECB_NO_PADDING
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_OFB
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_STREAM_CIPHER
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_KEY_TYPE_DES

    # The following modules directly depends on CIPHER_C
    scripts/config.py unset MBEDTLS_CMAC_C
    scripts/config.py unset MBEDTLS_NIST_KW_C

    make

    # Ensure that CIPHER_C was not re-enabled
    not grep mbedtls_cipher_init ${BUILTIN_SRC_PATH}/cipher.o

    msg "test: full no CIPHER"
    make test
}

component_test_full_no_ccm() {
    msg "build: full no PSA_WANT_ALG_CCM"

    # Full config enables:
    # - USE_PSA_CRYPTO so that TLS code dispatches cipher/AEAD to PSA
    # - CRYPTO_CONFIG so that PSA_WANT config symbols are evaluated
    scripts/config.py full

    # Disable PSA_WANT_ALG_CCM so that CCM is not supported in PSA. CCM_C is still
    # enabled, but not used from TLS since USE_PSA is set.
    # This is helpful to ensure that TLS tests below have proper dependencies.
    #
    # Note: also PSA_WANT_ALG_CCM_STAR_NO_TAG is enabled, but it does not cause
    # PSA_WANT_ALG_CCM to be re-enabled.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CCM

    make

    msg "test: full no PSA_WANT_ALG_CCM"
    make test
}

component_test_full_no_ccm_star_no_tag() {
    msg "build: full no PSA_WANT_ALG_CCM_STAR_NO_TAG"

    # Full config enables CRYPTO_CONFIG so that PSA_WANT config symbols are evaluated
    scripts/config.py full

    # Disable CCM_STAR_NO_TAG, which is the target of this test, as well as all
    # other components that enable MBEDTLS_PSA_BUILTIN_CIPHER internal symbol.
    # This basically disables all unauthenticated ciphers on the PSA side, while
    # keeping AEADs enabled.
    #
    # Note: PSA_WANT_ALG_CCM is enabled, but it does not cause
    # PSA_WANT_ALG_CCM_STAR_NO_TAG to be re-enabled.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CCM_STAR_NO_TAG
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_STREAM_CIPHER
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CTR
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CFB
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_OFB
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_ECB_NO_PADDING
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_NO_PADDING
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_PKCS7

    make

    # Ensure MBEDTLS_PSA_BUILTIN_CIPHER was not enabled
    not grep mbedtls_psa_cipher ${PSA_CORE_PATH}/psa_crypto_cipher.o

    msg "test: full no PSA_WANT_ALG_CCM_STAR_NO_TAG"
    make test
}

component_test_tls1_2_default_stream_cipher_only () {
    msg "build: default with only stream cipher use psa"

    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    # Disable AEAD (controlled by the presence of one of GCM_C, CCM_C, CHACHAPOLY_C)
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM_STAR_NO_TAG
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_GCM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CHACHA20_POLY1305
    # Note: The three unsets below are to be removed for Mbed TLS 4.0
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py unset MBEDTLS_CCM_C
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    #Disable TLS 1.3 (as no AEAD)
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    # Disable CBC. Note: When implemented, PSA_WANT_ALG_CBC_MAC will also need to be unset here to fully disable CBC
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CBC_NO_PADDING
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CBC_PKCS7
    # Disable CBC-legacy (controlled by MBEDTLS_CIPHER_MODE_CBC plus at least one block cipher (AES, ARIA, Camellia, DES))
    # Note: The unset below is to be removed for 4.0
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CBC
    # Disable CBC-EtM (controlled by the same as CBC-legacy plus MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    scripts/config.py unset MBEDTLS_SSL_ENCRYPT_THEN_MAC
    # Enable stream (currently that's just the NULL pseudo-cipher (controlled by MBEDTLS_CIPHER_NULL_CIPHER))
    scripts/config.py set MBEDTLS_CIPHER_NULL_CIPHER
    # Modules that depend on AEAD
    scripts/config.py unset MBEDTLS_SSL_CONTEXT_SERIALIZATION
    scripts/config.py unset MBEDTLS_SSL_TICKET_C

    make

    msg "test: default with only stream cipher use psa"
    make test

    # Not running ssl-opt.sh because most tests require a non-NULL ciphersuite.
}

component_test_tls1_2_default_cbc_legacy_cipher_only () {
    msg "build: default with only CBC-legacy cipher use psa"

    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    # Disable AEAD (controlled by the presence of one of GCM_C, CCM_C, CHACHAPOLY_C)
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM_STAR_NO_TAG
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_GCM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CHACHA20_POLY1305
    # Note: The three unsets below are to be removed for Mbed TLS 4.0
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py unset MBEDTLS_CCM_C
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    #Disable TLS 1.3 (as no AEAD)
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    # Enable CBC-legacy (controlled by MBEDTLS_CIPHER_MODE_CBC plus at least one block cipher (AES, ARIA, Camellia, DES))
    scripts/config.py -f $CRYPTO_CONFIG_H set PSA_WANT_ALG_CBC_NO_PADDING
    # Disable CBC-EtM (controlled by the same as CBC-legacy plus MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    scripts/config.py unset MBEDTLS_SSL_ENCRYPT_THEN_MAC
    # Disable stream (currently that's just the NULL pseudo-cipher (controlled by MBEDTLS_CIPHER_NULL_CIPHER))
    scripts/config.py unset MBEDTLS_CIPHER_NULL_CIPHER
    # Modules that depend on AEAD
    scripts/config.py unset MBEDTLS_SSL_CONTEXT_SERIALIZATION
    scripts/config.py unset MBEDTLS_SSL_TICKET_C

    make

    msg "test: default with only CBC-legacy cipher use psa"
    make test

    msg "test: default with only CBC-legacy cipher use psa - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f "TLS 1.2"
}

component_test_tls1_2_default_cbc_legacy_cbc_etm_cipher_only () {
    msg "build: default with only CBC-legacy and CBC-EtM ciphers use psa"

    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    # Disable AEAD (controlled by the presence of one of GCM_C, CCM_C, CHACHAPOLY_C)
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CCM_STAR_NO_TAG
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_GCM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_CHACHA20_POLY1305
    # Note: The three unsets below are to be removed for Mbed TLS 4.0
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py unset MBEDTLS_CCM_C
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    #Disable TLS 1.3 (as no AEAD)
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    # Enable CBC-legacy (controlled by MBEDTLS_CIPHER_MODE_CBC plus at least one block cipher (AES, ARIA, Camellia, DES))
    scripts/config.py -f $CRYPTO_CONFIG_H set PSA_WANT_ALG_CBC_NO_PADDING
    # Enable CBC-EtM (controlled by the same as CBC-legacy plus MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    scripts/config.py set MBEDTLS_SSL_ENCRYPT_THEN_MAC
    # Disable stream (currently that's just the NULL pseudo-cipher (controlled by MBEDTLS_CIPHER_NULL_CIPHER))
    scripts/config.py unset MBEDTLS_CIPHER_NULL_CIPHER
    # Modules that depend on AEAD
    scripts/config.py unset MBEDTLS_SSL_CONTEXT_SERIALIZATION
    scripts/config.py unset MBEDTLS_SSL_TICKET_C

    make

    msg "test: default with only CBC-legacy and CBC-EtM ciphers use psa"
    make test

    msg "test: default with only CBC-legacy and CBC-EtM ciphers use psa - ssl-opt.sh (subset)"
    tests/ssl-opt.sh -f "TLS 1.2"
}

# We're not aware of any other (open source) implementation of EC J-PAKE in TLS
# that we could use for interop testing. However, we now have sort of two
# implementations ourselves: one using PSA, the other not. At least test that
# these two interoperate with each other.
component_test_tls1_2_ecjpake_compatibility() {
    msg "build: TLS1.2 server+client w/ EC-JPAKE w/o USE_PSA"
    scripts/config.py set MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
    # Explicitly make lib first to avoid a race condition:
    # https://github.com/Mbed-TLS/mbedtls/issues/8229
    make lib
    make -C programs ssl/ssl_server2 ssl/ssl_client2
    cp programs/ssl/ssl_server2 s2_no_use_psa
    cp programs/ssl/ssl_client2 c2_no_use_psa

    msg "build: TLS1.2 server+client w/ EC-JPAKE w/ USE_PSA"
    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    make clean
    make lib
    make -C programs ssl/ssl_server2 ssl/ssl_client2
    make -C programs test/udp_proxy test/query_compile_time_config

    msg "test: server w/o USE_PSA - client w/ USE_PSA, text password"
    P_SRV=../s2_no_use_psa tests/ssl-opt.sh -f "ECJPAKE: working, TLS"
    msg "test: server w/o USE_PSA - client w/ USE_PSA, opaque password"
    P_SRV=../s2_no_use_psa tests/ssl-opt.sh -f "ECJPAKE: opaque password client only, working, TLS"
    msg "test: client w/o USE_PSA - server w/ USE_PSA, text password"
    P_CLI=../c2_no_use_psa tests/ssl-opt.sh -f "ECJPAKE: working, TLS"
    msg "test: client w/o USE_PSA - server w/ USE_PSA, opaque password"
    P_CLI=../c2_no_use_psa tests/ssl-opt.sh -f "ECJPAKE: opaque password server only, working, TLS"

    rm s2_no_use_psa c2_no_use_psa
}

component_test_everest () {
    msg "build: Everest ECDH context (ASan build)" # ~ 6 min
    scripts/config.py set MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: Everest ECDH context - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: metatests (clang, ASan)"
    tests/scripts/run-metatests.sh any asan poison

    msg "test: Everest ECDH context - ECDH-related part of ssl-opt.sh (ASan build)" # ~ 5s
    tests/ssl-opt.sh -f ECDH

    msg "test: Everest ECDH context - compat.sh with some ECDH ciphersuites (ASan build)" # ~ 3 min
    # Exclude some symmetric ciphers that are redundant here to gain time.
    tests/compat.sh -f ECDH -V NO -e 'ARIA\|CAMELLIA\|CHACHA'
}

component_test_everest_curve25519_only () {
    msg "build: Everest ECDH context, only Curve25519" # ~ 6 min
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    scripts/config.py set MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_DETERMINISTIC_ECDSA
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_ECDSA
    scripts/config.py -f $CRYPTO_CONFIG_H set PSA_WANT_ALG_ECDH
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_ECJPAKE_C
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_JPAKE

    # Disable all curves
    scripts/config.py unset-all "MBEDTLS_ECP_DP_[0-9A-Z_a-z]*_ENABLED"
    scripts/config.py -f $CRYPTO_CONFIG_H unset-all "PSA_WANT_ECC_[0-9A-Z_a-z]*$"
    scripts/config.py -f $CRYPTO_CONFIG_H set PSA_WANT_ECC_MONTGOMERY_255

    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: Everest ECDH context, only Curve25519" # ~ 50s
    make test
}

component_test_small_ssl_out_content_len () {
    msg "build: small SSL_OUT_CONTENT_LEN (ASan build)"
    scripts/config.py set MBEDTLS_SSL_IN_CONTENT_LEN 16384
    scripts/config.py set MBEDTLS_SSL_OUT_CONTENT_LEN 4096
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: small SSL_OUT_CONTENT_LEN - ssl-opt.sh MFL and large packet tests"
    tests/ssl-opt.sh -f "Max fragment\|Large packet"
}

component_test_small_ssl_in_content_len () {
    msg "build: small SSL_IN_CONTENT_LEN (ASan build)"
    scripts/config.py set MBEDTLS_SSL_IN_CONTENT_LEN 4096
    scripts/config.py set MBEDTLS_SSL_OUT_CONTENT_LEN 16384
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: small SSL_IN_CONTENT_LEN - ssl-opt.sh MFL tests"
    tests/ssl-opt.sh -f "Max fragment"
}

component_test_small_ssl_dtls_max_buffering () {
    msg "build: small MBEDTLS_SSL_DTLS_MAX_BUFFERING #0"
    scripts/config.py set MBEDTLS_SSL_DTLS_MAX_BUFFERING 1000
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: small MBEDTLS_SSL_DTLS_MAX_BUFFERING #0 - ssl-opt.sh specific reordering test"
    tests/ssl-opt.sh -f "DTLS reordering: Buffer out-of-order hs msg before reassembling next, free buffered msg"
}

component_test_small_mbedtls_ssl_dtls_max_buffering () {
    msg "build: small MBEDTLS_SSL_DTLS_MAX_BUFFERING #1"
    scripts/config.py set MBEDTLS_SSL_DTLS_MAX_BUFFERING 190
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: small MBEDTLS_SSL_DTLS_MAX_BUFFERING #1 - ssl-opt.sh specific reordering test"
    tests/ssl-opt.sh -f "DTLS reordering: Buffer encrypted Finished message, drop for fragmented NewSessionTicket"
}

component_test_psa_collect_statuses () {
  msg "build+test: psa_collect_statuses" # ~30s
  scripts/config.py full
  tests/scripts/psa_collect_statuses.py
  # Check that psa_crypto_init() succeeded at least once
  grep -q '^0:psa_crypto_init:' tests/statuses.log
  rm -f tests/statuses.log
}

component_test_full_cmake_clang () {
    msg "build: cmake, full config, clang" # ~ 50s
    scripts/config.py full
    CC=clang CXX=clang cmake -D CMAKE_BUILD_TYPE:String=Release -D ENABLE_TESTING=On -D TEST_CPP=1 .
    make

    msg "test: main suites (full config, clang)" # ~ 5s
    make test

    msg "test: cpp_dummy_build (full config, clang)" # ~ 1s
    programs/test/cpp_dummy_build

    msg "test: metatests (clang)"
    tests/scripts/run-metatests.sh any pthread

    msg "program demos (full config, clang)" # ~10s
    tests/scripts/run_demos.py

    msg "test: psa_constant_names (full config, clang)" # ~ 1s
    tests/scripts/test_psa_constant_names.py

    msg "test: ssl-opt.sh default, ECJPAKE, SSL async (full config)" # ~ 1s
    tests/ssl-opt.sh -f 'Default\|ECJPAKE\|SSL async private'
}

skip_suites_without_constant_flow () {
    # Skip the test suites that don't have any constant-flow annotations.
    # This will need to be adjusted if we ever start declaring things as
    # secret from macros or functions inside tests/include or tests/src.
    SKIP_TEST_SUITES=$(
        git -C tests/suites grep -L TEST_CF_ 'test_suite_*.function' |
            sed 's/test_suite_//; s/\.function$//' |
            tr '\n' ,)
    export SKIP_TEST_SUITES
}

skip_all_except_given_suite () {
    # Skip all but the given test suite
    SKIP_TEST_SUITES=$(
        ls -1 tests/suites/test_suite_*.function |
        grep -v $1.function |
         sed 's/tests.suites.test_suite_//; s/\.function$//' |
        tr '\n' ,)
    export SKIP_TEST_SUITES
}

component_test_memsan_constant_flow () {
    # This tests both (1) accesses to undefined memory, and (2) branches or
    # memory access depending on secret values. To distinguish between those:
    # - unset MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN - does the failure persist?
    # - or alternatively, change the build type to MemSanDbg, which enables
    # origin tracking and nicer stack traces (which are useful for debugging
    # anyway), and check if the origin was TEST_CF_SECRET() or something else.
    msg "build: cmake MSan (clang), full config minus MBEDTLS_USE_PSA_CRYPTO with constant flow testing"
    scripts/config.py full
    scripts/config.py set MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_AESNI_C # memsan doesn't grok asm
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=MemSan .
    make

    msg "test: main suites (full minus MBEDTLS_USE_PSA_CRYPTO, Msan + constant flow)"
    make test
}

component_test_memsan_constant_flow_psa () {
    # This tests both (1) accesses to undefined memory, and (2) branches or
    # memory access depending on secret values. To distinguish between those:
    # - unset MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN - does the failure persist?
    # - or alternatively, change the build type to MemSanDbg, which enables
    # origin tracking and nicer stack traces (which are useful for debugging
    # anyway), and check if the origin was TEST_CF_SECRET() or something else.
    msg "build: cmake MSan (clang), full config with constant flow testing"
    scripts/config.py full
    scripts/config.py set MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN
    scripts/config.py unset MBEDTLS_AESNI_C # memsan doesn't grok asm
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=MemSan .
    make

    msg "test: main suites (Msan + constant flow)"
    make test
}

component_release_test_valgrind_constant_flow () {
    # This tests both (1) everything that valgrind's memcheck usually checks
    # (heap buffer overflows, use of uninitialized memory, use-after-free,
    # etc.) and (2) branches or memory access depending on secret values,
    # which will be reported as uninitialized memory. To distinguish between
    # secret and actually uninitialized:
    # - unset MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND - does the failure persist?
    # - or alternatively, build with debug info and manually run the offending
    # test suite with valgrind --track-origins=yes, then check if the origin
    # was TEST_CF_SECRET() or something else.
    msg "build: cmake release GCC, full config minus MBEDTLS_USE_PSA_CRYPTO with constant flow testing"
    scripts/config.py full
    scripts/config.py set MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    skip_suites_without_constant_flow
    cmake -D CMAKE_BUILD_TYPE:String=Release .
    make

    # this only shows a summary of the results (how many of each type)
    # details are left in Testing/<date>/DynamicAnalysis.xml
    msg "test: some suites (full minus MBEDTLS_USE_PSA_CRYPTO, valgrind + constant flow)"
    make memcheck

    # Test asm path in constant time module - by default, it will test the plain C
    # path under Valgrind or Memsan. Running only the constant_time tests is fast (<1s)
    msg "test: valgrind asm constant_time"
    scripts/config.py --force set MBEDTLS_TEST_CONSTANT_FLOW_ASM
    skip_all_except_given_suite test_suite_constant_time
    cmake -D CMAKE_BUILD_TYPE:String=Release .
    make clean
    make
    make memcheck
}

component_release_test_valgrind_constant_flow_psa () {
    # This tests both (1) everything that valgrind's memcheck usually checks
    # (heap buffer overflows, use of uninitialized memory, use-after-free,
    # etc.) and (2) branches or memory access depending on secret values,
    # which will be reported as uninitialized memory. To distinguish between
    # secret and actually uninitialized:
    # - unset MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND - does the failure persist?
    # - or alternatively, build with debug info and manually run the offending
    # test suite with valgrind --track-origins=yes, then check if the origin
    # was TEST_CF_SECRET() or something else.
    msg "build: cmake release GCC, full config with constant flow testing"
    scripts/config.py full
    scripts/config.py set MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND
    skip_suites_without_constant_flow
    cmake -D CMAKE_BUILD_TYPE:String=Release .
    make

    # this only shows a summary of the results (how many of each type)
    # details are left in Testing/<date>/DynamicAnalysis.xml
    msg "test: some suites (valgrind + constant flow)"
    make memcheck
}

component_test_tsan () {
    msg "build: TSan (clang)"
    scripts/config.py full
    scripts/config.py set MBEDTLS_THREADING_C
    scripts/config.py set MBEDTLS_THREADING_PTHREAD
    # Self-tests do not currently use multiple threads.
    scripts/config.py unset MBEDTLS_SELF_TEST

    # The deprecated MBEDTLS_PSA_CRYPTO_SE_C interface is not thread safe.
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_SE_C

    CC=clang cmake -D CMAKE_BUILD_TYPE:String=TSan .
    make

    msg "test: main suites (TSan)"
    make test
}

component_test_default_no_deprecated () {
    # Test that removing the deprecated features from the default
    # configuration leaves something consistent.
    msg "build: make, default + MBEDTLS_DEPRECATED_REMOVED" # ~ 30s
    scripts/config.py set MBEDTLS_DEPRECATED_REMOVED
    make CFLAGS='-O -Werror -Wall -Wextra'

    msg "test: make, default + MBEDTLS_DEPRECATED_REMOVED" # ~ 5s
    make test
}

component_test_full_no_deprecated () {
    msg "build: make, full_no_deprecated config" # ~ 30s
    scripts/config.py full_no_deprecated
    make CFLAGS='-O -Werror -Wall -Wextra'

    msg "test: make, full_no_deprecated config" # ~ 5s
    make test

    msg "test: ensure that X509 has no direct dependency on BIGNUM_C"
    not grep mbedtls_mpi library/libmbedx509.a
}

component_test_full_no_deprecated_deprecated_warning () {
    # Test that there is nothing deprecated in "full_no_deprecated".
    # A deprecated feature would trigger a warning (made fatal) from
    # MBEDTLS_DEPRECATED_WARNING.
    msg "build: make, full_no_deprecated config, MBEDTLS_DEPRECATED_WARNING" # ~ 30s
    scripts/config.py full_no_deprecated
    scripts/config.py unset MBEDTLS_DEPRECATED_REMOVED
    scripts/config.py set MBEDTLS_DEPRECATED_WARNING
    make CFLAGS='-O -Werror -Wall -Wextra'

    msg "test: make, full_no_deprecated config, MBEDTLS_DEPRECATED_WARNING" # ~ 5s
    make test
}

component_test_full_deprecated_warning () {
    # Test that when MBEDTLS_DEPRECATED_WARNING is enabled, the build passes
    # with only certain whitelisted types of warnings.
    msg "build: make, full config + MBEDTLS_DEPRECATED_WARNING, expect warnings" # ~ 30s
    scripts/config.py full
    scripts/config.py set MBEDTLS_DEPRECATED_WARNING
    # Expect warnings from '#warning' directives in check_config.h.
    # Note that gcc is required to allow the use of -Wno-error=cpp, which allows us to
    # display #warning messages without them being treated as errors.
    make CC=gcc CFLAGS='-O -Werror -Wall -Wextra -Wno-error=cpp' lib programs

    msg "build: make tests, full config + MBEDTLS_DEPRECATED_WARNING, expect warnings" # ~ 30s
    # Set MBEDTLS_TEST_DEPRECATED to enable tests for deprecated features.
    # By default those are disabled when MBEDTLS_DEPRECATED_WARNING is set.
    # Expect warnings from '#warning' directives in check_config.h and
    # from the use of deprecated functions in test suites.
    make CC=gcc CFLAGS='-O -Werror -Wall -Wextra -Wno-error=deprecated-declarations -Wno-error=cpp -DMBEDTLS_TEST_DEPRECATED' tests

    msg "test: full config + MBEDTLS_TEST_DEPRECATED" # ~ 30s
    make test

    msg "program demos: full config + MBEDTLS_TEST_DEPRECATED" # ~10s
    tests/scripts/run_demos.py
}

# Check that the specified libraries exist and are empty.
are_empty_libraries () {
  nm "$@" >/dev/null 2>/dev/null
  ! nm "$@" 2>/dev/null | grep -v ':$' | grep .
}

component_build_crypto_default () {
  msg "build: make, crypto only"
  scripts/config.py crypto
  make CFLAGS='-O1 -Werror'
  are_empty_libraries library/libmbedx509.* library/libmbedtls.*
}

component_build_crypto_full () {
  msg "build: make, crypto only, full config"
  scripts/config.py crypto_full
  make CFLAGS='-O1 -Werror'
  are_empty_libraries library/libmbedx509.* library/libmbedtls.*
}

component_test_crypto_for_psa_service () {
  msg "build: make, config for PSA crypto service"
  scripts/config.py crypto
  scripts/config.py set MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
  # Disable things that are not needed for just cryptography, to
  # reach a configuration that would be typical for a PSA cryptography
  # service providing all implemented PSA algorithms.
  # System stuff
  scripts/config.py unset MBEDTLS_ERROR_C
  scripts/config.py unset MBEDTLS_TIMING_C
  scripts/config.py unset MBEDTLS_VERSION_FEATURES
  # Crypto stuff with no PSA interface
  scripts/config.py unset MBEDTLS_BASE64_C
  # Keep MBEDTLS_CIPHER_C because psa_crypto_cipher, CCM and GCM need it.
  scripts/config.py unset MBEDTLS_HKDF_C # PSA's HKDF is independent
  # Keep MBEDTLS_MD_C because deterministic ECDSA needs it for HMAC_DRBG.
  scripts/config.py unset MBEDTLS_NIST_KW_C
  scripts/config.py unset MBEDTLS_PEM_PARSE_C
  scripts/config.py unset MBEDTLS_PEM_WRITE_C
  scripts/config.py unset MBEDTLS_PKCS12_C
  scripts/config.py unset MBEDTLS_PKCS5_C
  # MBEDTLS_PK_PARSE_C and MBEDTLS_PK_WRITE_C are actually currently needed
  # in PSA code to work with RSA keys. We don't require users to set those:
  # they will be reenabled in build_info.h.
  scripts/config.py unset MBEDTLS_PK_C
  scripts/config.py unset MBEDTLS_PK_PARSE_C
  scripts/config.py unset MBEDTLS_PK_WRITE_C
  make CFLAGS='-O1 -Werror' all test
  are_empty_libraries library/libmbedx509.* library/libmbedtls.*
}

component_build_crypto_baremetal () {
  msg "build: make, crypto only, baremetal config"
  scripts/config.py crypto_baremetal
  make CFLAGS="-O1 -Werror -I$PWD/tests/include/baremetal-override/"
  are_empty_libraries library/libmbedx509.* library/libmbedtls.*
}
support_build_crypto_baremetal () {
    support_build_baremetal "$@"
}

component_build_baremetal () {
  msg "build: make, baremetal config"
  scripts/config.py baremetal
  make CFLAGS="-O1 -Werror -I$PWD/tests/include/baremetal-override/"
}
support_build_baremetal () {
    # Older Glibc versions include time.h from other headers such as stdlib.h,
    # which makes the no-time.h-in-baremetal check fail. Ubuntu 16.04 has this
    # problem, Ubuntu 18.04 is ok.
    ! grep -q -F time.h /usr/include/x86_64-linux-gnu/sys/types.h
}

# depends.py family of tests
component_test_depends_py_cipher_id () {
    msg "test/build: depends.py cipher_id (gcc)"
    tests/scripts/depends.py cipher_id --unset-use-psa
}

component_test_depends_py_cipher_chaining () {
    msg "test/build: depends.py cipher_chaining (gcc)"
    tests/scripts/depends.py cipher_chaining --unset-use-psa
}

component_test_depends_py_cipher_padding () {
    msg "test/build: depends.py cipher_padding (gcc)"
    tests/scripts/depends.py cipher_padding --unset-use-psa
}

component_test_depends_py_curves () {
    msg "test/build: depends.py curves (gcc)"
    tests/scripts/depends.py curves --unset-use-psa
}

component_test_depends_py_hashes () {
    msg "test/build: depends.py hashes (gcc)"
    tests/scripts/depends.py hashes --unset-use-psa
}

component_test_depends_py_kex () {
    msg "test/build: depends.py kex (gcc)"
    tests/scripts/depends.py kex --unset-use-psa
}

component_test_depends_py_pkalgs () {
    msg "test/build: depends.py pkalgs (gcc)"
    tests/scripts/depends.py pkalgs --unset-use-psa
}

# PSA equivalents of the depends.py tests
component_test_depends_py_cipher_id_psa () {
    msg "test/build: depends.py cipher_id (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py cipher_id
}

component_test_depends_py_cipher_chaining_psa () {
    msg "test/build: depends.py cipher_chaining (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py cipher_chaining
}

component_test_depends_py_cipher_padding_psa () {
    msg "test/build: depends.py cipher_padding (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py cipher_padding
}

component_test_depends_py_curves_psa () {
    msg "test/build: depends.py curves (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py curves
}

component_test_depends_py_hashes_psa () {
    msg "test/build: depends.py hashes (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py hashes
}

component_test_depends_py_kex_psa () {
    msg "test/build: depends.py kex (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py kex
}

component_test_depends_py_pkalgs_psa () {
    msg "test/build: depends.py pkalgs (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py pkalgs
}

component_test_psa_crypto_config_ffdh_2048_only () {
    msg "build: full config - only DH 2048"

    scripts/config.py full

    # Disable all DH groups other than 2048.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_DH_RFC7919_3072
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_DH_RFC7919_4096
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_DH_RFC7919_6144
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_DH_RFC7919_8192

    make CFLAGS="$ASAN_CFLAGS -Werror" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full config - only DH 2048"
    make test

    msg "ssl-opt: full config - only DH 2048"
    tests/ssl-opt.sh -f "ffdh"
}

component_build_no_pk_rsa_alt_support () {
    msg "build: !MBEDTLS_PK_RSA_ALT_SUPPORT" # ~30s

    scripts/config.py full
    scripts/config.py unset MBEDTLS_PK_RSA_ALT_SUPPORT
    scripts/config.py set MBEDTLS_RSA_C
    scripts/config.py set MBEDTLS_X509_CRT_WRITE_C

    # Only compile - this is primarily to test for compile issues
    make CFLAGS='-Werror -Wall -Wextra -I../tests/include/alt-dummy'
}

component_build_module_alt () {
    msg "build: MBEDTLS_XXX_ALT" # ~30s
    scripts/config.py full

    # Disable options that are incompatible with some ALT implementations:
    # aesni.c references mbedtls_aes_context fields directly.
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C
    # MBEDTLS_ECP_RESTARTABLE is documented as incompatible.
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE
    # You can only have one threading implementation: alt or pthread, not both.
    scripts/config.py unset MBEDTLS_THREADING_PTHREAD
    # The SpecifiedECDomain parsing code accesses mbedtls_ecp_group fields
    # directly and assumes the implementation works with partial groups.
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_EXTENDED
    # MBEDTLS_SHA256_*ALT can't be used with MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_*
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY
    # MBEDTLS_SHA512_*ALT can't be used with MBEDTLS_SHA512_USE_A64_CRYPTO_*
    scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT
    scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY

    # Enable all MBEDTLS_XXX_ALT for whole modules. Do not enable
    # MBEDTLS_XXX_YYY_ALT which are for single functions.
    scripts/config.py set-all 'MBEDTLS_([A-Z0-9]*|NIST_KW)_ALT'

    # We can only compile, not link, since we don't have any implementations
    # suitable for testing with the dummy alt headers.
    make CFLAGS='-Werror -Wall -Wextra -I../tests/include/alt-dummy' lib
}

component_test_no_psa_crypto_full_cmake_asan() {
    # full minus MBEDTLS_PSA_CRYPTO_C: run the same set of tests as basic-build-test.sh
    msg "build: cmake, full config minus PSA crypto, ASan"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_CLIENT
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    scripts/config.py unset MBEDTLS_PSA_ITS_FILE_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_SE_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_STORAGE_C
    scripts/config.py unset MBEDTLS_LMS_C
    scripts/config.py unset MBEDTLS_LMS_PRIVATE
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (full minus PSA crypto)"
    make test

    # Note: ssl-opt.sh has some test cases that depend on
    # MBEDTLS_ECP_RESTARTABLE && !MBEDTLS_USE_PSA_CRYPTO
    # This is the only component where those tests are not skipped.
    msg "test: ssl-opt.sh (full minus PSA crypto)"
    tests/ssl-opt.sh

    # Note: the next two invocations cover all compat.sh test cases.
    # We should use the same here and in basic-build-test.sh.
    msg "test: compat.sh: default version (full minus PSA crypto)"
    tests/compat.sh -e 'ARIA\|CHACHA'

    msg "test: compat.sh: next: ARIA, Chacha (full minus PSA crypto)"
    env OPENSSL="$OPENSSL_NEXT" tests/compat.sh -e '^$' -f 'ARIA\|CHACHA'
}

component_test_psa_crypto_config_accel_ecdsa () {
    msg "build: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated ECDSA"

    # Algorithms and key types to accelerate
    loc_accel_list="ALG_ECDSA ALG_DETERMINISTIC_ECDSA \
                    $(helper_get_psa_key_type_list "ECC") \
                    $(helper_get_psa_curve_list)"

    # Configure
    # ---------

    # Start from default config (no USE_PSA) + TLS 1.3
    helper_libtestdriver1_adjust_config "default"

    # Disable the module that's accelerated
    scripts/config.py unset MBEDTLS_ECDSA_C

    # Disable things that depend on it
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED

    # Build
    # -----

    # These hashes are needed for some ECDSA signature tests.
    loc_extra_list="ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"

    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ ${BUILTIN_SRC_PATH}/ecdsa.o

    # Run the tests
    # -------------

    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated ECDSA"
    make test
}

component_test_psa_crypto_config_accel_ecdh () {
    msg "build: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated ECDH"

    # Algorithms and key types to accelerate
    loc_accel_list="ALG_ECDH \
                    $(helper_get_psa_key_type_list "ECC") \
                    $(helper_get_psa_curve_list)"

    # Configure
    # ---------

    # Start from default config (no USE_PSA)
    helper_libtestdriver1_adjust_config "default"

    # Disable the module that's accelerated
    scripts/config.py unset MBEDTLS_ECDH_C

    # Disable things that depend on it
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_ecdh_ ${BUILTIN_SRC_PATH}/ecdh.o

    # Run the tests
    # -------------

    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated ECDH"
    make test
}

component_test_psa_crypto_config_accel_ffdh () {
    msg "build: full with accelerated FFDH"

    # Algorithms and key types to accelerate
    loc_accel_list="ALG_FFDH \
                    $(helper_get_psa_key_type_list "DH") \
                    $(helper_get_psa_dh_group_list)"

    # Configure
    # ---------

    # start with full (USE_PSA and TLS 1.3)
    helper_libtestdriver1_adjust_config "full"

    # Disable the module that's accelerated
    scripts/config.py unset MBEDTLS_DHM_C

    # Disable things that depend on it
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_dhm_ ${BUILTIN_SRC_PATH}/dhm.o

    # Run the tests
    # -------------

    msg "test: full with accelerated FFDH"
    make test

    msg "ssl-opt: full with accelerated FFDH alg"
    tests/ssl-opt.sh -f "ffdh"
}

component_test_psa_crypto_config_reference_ffdh () {
    msg "build: full with non-accelerated FFDH"

    # Start with full (USE_PSA and TLS 1.3)
    helper_libtestdriver1_adjust_config "full"

    # Disable things that are not supported
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
    make

    msg "test suites: full with non-accelerated FFDH alg"
    make test

    msg "ssl-opt: full with non-accelerated FFDH alg"
    tests/ssl-opt.sh -f "ffdh"
}

component_test_psa_crypto_config_accel_pake() {
    msg "build: full with accelerated PAKE"

    loc_accel_list="ALG_JPAKE \
                    $(helper_get_psa_key_type_list "ECC") \
                    $(helper_get_psa_curve_list)"

    # Configure
    # ---------

    helper_libtestdriver1_adjust_config "full"

    # Make built-in fallback not available
    scripts/config.py unset MBEDTLS_ECJPAKE_C
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_ecjpake_init ${BUILTIN_SRC_PATH}/ecjpake.o

    # Run the tests
    # -------------

    msg "test: full with accelerated PAKE"
    make test
}

component_test_psa_crypto_config_accel_ecc_some_key_types () {
    msg "build: full with accelerated EC algs and some key types"

    # Algorithms and key types to accelerate
    # For key types, use an explicitly list to omit GENERATE (and DERIVE)
    loc_accel_list="ALG_ECDSA ALG_DETERMINISTIC_ECDSA \
                    ALG_ECDH \
                    ALG_JPAKE \
                    KEY_TYPE_ECC_PUBLIC_KEY \
                    KEY_TYPE_ECC_KEY_PAIR_BASIC \
                    KEY_TYPE_ECC_KEY_PAIR_IMPORT \
                    KEY_TYPE_ECC_KEY_PAIR_EXPORT \
                    $(helper_get_psa_curve_list)"

    # Configure
    # ---------

    # start with config full for maximum coverage (also enables USE_PSA)
    helper_libtestdriver1_adjust_config "full"

    # Disable modules that are accelerated - some will be re-enabled
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_ECDH_C
    scripts/config.py unset MBEDTLS_ECJPAKE_C
    scripts/config.py unset MBEDTLS_ECP_C

    # Disable all curves - those that aren't accelerated should be re-enabled
    helper_disable_builtin_curves

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE

    # this is not supported by the driver API yet
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # Build
    # -----

    # These hashes are needed for some ECDSA signature tests.
    loc_extra_list="ALG_SHA_1 ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"
    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # ECP should be re-enabled but not the others
    not grep mbedtls_ecdh_ ${BUILTIN_SRC_PATH}/ecdh.o
    not grep mbedtls_ecdsa ${BUILTIN_SRC_PATH}/ecdsa.o
    not grep mbedtls_ecjpake  ${BUILTIN_SRC_PATH}/ecjpake.o
    grep mbedtls_ecp ${BUILTIN_SRC_PATH}/ecp.o

    # Run the tests
    # -------------

    msg "test suites: full with accelerated EC algs and some key types"
    make test
}

# Run tests with only (non-)Weierstrass accelerated
# Common code used in:
# - component_test_psa_crypto_config_accel_ecc_weierstrass_curves
# - component_test_psa_crypto_config_accel_ecc_non_weierstrass_curves
common_test_psa_crypto_config_accel_ecc_some_curves () {
    weierstrass=$1
    if [ $weierstrass -eq 1 ]; then
        desc="Weierstrass"
    else
        desc="non-Weierstrass"
    fi

    msg "build: crypto_full minus PK with accelerated EC algs and $desc curves"

    # Note: Curves are handled in a special way by the libtestdriver machinery,
    # so we only want to include them in the accel list when building the main
    # libraries, hence the use of a separate variable.
    # Note: the following loop is a modified version of
    # helper_get_psa_curve_list that only keeps Weierstrass families.
    loc_weierstrass_list=""
    loc_non_weierstrass_list=""
    for item in $(sed -n 's/^#define PSA_WANT_\(ECC_[0-9A-Z_a-z]*\).*/\1/p' <"$CRYPTO_CONFIG_H"); do
        case $item in
            ECC_BRAINPOOL*|ECC_SECP*)
                loc_weierstrass_list="$loc_weierstrass_list $item"
                ;;
            *)
                loc_non_weierstrass_list="$loc_non_weierstrass_list $item"
                ;;
        esac
    done
    if [ $weierstrass -eq 1 ]; then
        loc_curve_list=$loc_weierstrass_list
    else
        loc_curve_list=$loc_non_weierstrass_list
    fi

    # Algorithms and key types to accelerate
    loc_accel_list="ALG_ECDSA ALG_DETERMINISTIC_ECDSA \
                    ALG_ECDH \
                    ALG_JPAKE \
                    $(helper_get_psa_key_type_list "ECC") \
                    $loc_curve_list"

    # Configure
    # ---------

    # Start with config crypto_full and remove PK_C:
    # that's what's supported now, see docs/driver-only-builds.md.
    helper_libtestdriver1_adjust_config "crypto_full"
    scripts/config.py unset MBEDTLS_PK_C
    scripts/config.py unset MBEDTLS_PK_PARSE_C
    scripts/config.py unset MBEDTLS_PK_WRITE_C

    # Disable modules that are accelerated - some will be re-enabled
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_ECDH_C
    scripts/config.py unset MBEDTLS_ECJPAKE_C
    scripts/config.py unset MBEDTLS_ECP_C

    # Disable all curves - those that aren't accelerated should be re-enabled
    helper_disable_builtin_curves

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE

    # this is not supported by the driver API yet
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # Build
    # -----

    # These hashes are needed for some ECDSA signature tests.
    loc_extra_list="ALG_SHA_1 ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"
    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # We expect ECDH to be re-enabled for the missing curves
    grep mbedtls_ecdh_ ${BUILTIN_SRC_PATH}/ecdh.o
    # We expect ECP to be re-enabled, however the parts specific to the
    # families of curves that are accelerated should be ommited.
    # - functions with mxz in the name are specific to Montgomery curves
    # - ecp_muladd is specific to Weierstrass curves
    ##nm ${BUILTIN_SRC_PATH}/ecp.o | tee ecp.syms
    if [ $weierstrass -eq 1 ]; then
        not grep mbedtls_ecp_muladd ${BUILTIN_SRC_PATH}/ecp.o
        grep mxz ${BUILTIN_SRC_PATH}/ecp.o
    else
        grep mbedtls_ecp_muladd ${BUILTIN_SRC_PATH}/ecp.o
        not grep mxz ${BUILTIN_SRC_PATH}/ecp.o
    fi
    # We expect ECDSA and ECJPAKE to be re-enabled only when
    # Weierstrass curves are not accelerated
    if [ $weierstrass -eq 1 ]; then
        not grep mbedtls_ecdsa ${BUILTIN_SRC_PATH}/ecdsa.o
        not grep mbedtls_ecjpake  ${BUILTIN_SRC_PATH}/ecjpake.o
    else
        grep mbedtls_ecdsa ${BUILTIN_SRC_PATH}/ecdsa.o
        grep mbedtls_ecjpake  ${BUILTIN_SRC_PATH}/ecjpake.o
    fi

    # Run the tests
    # -------------

    msg "test suites: crypto_full minus PK with accelerated EC algs and $desc curves"
    make test
}

component_test_psa_crypto_config_accel_ecc_weierstrass_curves () {
    common_test_psa_crypto_config_accel_ecc_some_curves 1
}

component_test_psa_crypto_config_accel_ecc_non_weierstrass_curves () {
    common_test_psa_crypto_config_accel_ecc_some_curves 0
}

# Auxiliary function to build config for all EC based algorithms (EC-JPAKE,
# ECDH, ECDSA) with and without drivers.
# The input parameter is a boolean value which indicates:
# - 0 keep built-in EC algs,
# - 1 exclude built-in EC algs (driver only).
#
# This is used by the two following components to ensure they always use the
# same config, except for the use of driver or built-in EC algorithms:
# - component_test_psa_crypto_config_accel_ecc_ecp_light_only;
# - component_test_psa_crypto_config_reference_ecc_ecp_light_only.
# This supports comparing their test coverage with analyze_outcomes.py.
config_psa_crypto_config_ecp_light_only () {
    driver_only="$1"
    # start with config full for maximum coverage (also enables USE_PSA)
    helper_libtestdriver1_adjust_config "full"
    if [ "$driver_only" -eq 1 ]; then
        # Disable modules that are accelerated
        scripts/config.py unset MBEDTLS_ECDSA_C
        scripts/config.py unset MBEDTLS_ECDH_C
        scripts/config.py unset MBEDTLS_ECJPAKE_C
        scripts/config.py unset MBEDTLS_ECP_C
    fi

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE
}

# Keep in sync with component_test_psa_crypto_config_reference_ecc_ecp_light_only
component_test_psa_crypto_config_accel_ecc_ecp_light_only () {
    msg "build: full with accelerated EC algs"

    # Algorithms and key types to accelerate
    loc_accel_list="ALG_ECDSA ALG_DETERMINISTIC_ECDSA \
                    ALG_ECDH \
                    ALG_JPAKE \
                    $(helper_get_psa_key_type_list "ECC") \
                    $(helper_get_psa_curve_list)"

    # Configure
    # ---------

    # Use the same config as reference, only without built-in EC algs
    config_psa_crypto_config_ecp_light_only 1

    # Do not disable builtin curves because that support is required for:
    # - MBEDTLS_PK_PARSE_EC_EXTENDED
    # - MBEDTLS_PK_PARSE_EC_COMPRESSED

    # Build
    # -----

    # These hashes are needed for some ECDSA signature tests.
    loc_extra_list="ALG_SHA_1 ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"
    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure any built-in EC alg was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ ${BUILTIN_SRC_PATH}/ecdsa.o
    not grep mbedtls_ecdh_ ${BUILTIN_SRC_PATH}/ecdh.o
    not grep mbedtls_ecjpake_ ${BUILTIN_SRC_PATH}/ecjpake.o
    not grep mbedtls_ecp_mul ${BUILTIN_SRC_PATH}/ecp.o

    # Run the tests
    # -------------

    msg "test suites: full with accelerated EC algs"
    make test

    msg "ssl-opt: full with accelerated EC algs"
    tests/ssl-opt.sh
}

# Keep in sync with component_test_psa_crypto_config_accel_ecc_ecp_light_only
component_test_psa_crypto_config_reference_ecc_ecp_light_only () {
    msg "build: MBEDTLS_PSA_CRYPTO_CONFIG with non-accelerated EC algs"

    config_psa_crypto_config_ecp_light_only 0

    make

    msg "test suites: full with non-accelerated EC algs"
    make test

    msg "ssl-opt: full with non-accelerated EC algs"
    tests/ssl-opt.sh
}

# This helper function is used by:
# - component_test_psa_crypto_config_accel_ecc_no_ecp_at_all()
# - component_test_psa_crypto_config_reference_ecc_no_ecp_at_all()
# to ensure that both tests use the same underlying configuration when testing
# driver's coverage with analyze_outcomes.py.
#
# This functions accepts 1 boolean parameter as follows:
# - 1: building with accelerated EC algorithms (ECDSA, ECDH, ECJPAKE), therefore
#      excluding their built-in implementation as well as ECP_C & ECP_LIGHT
# - 0: include built-in implementation of EC algorithms.
#
# PK_C and RSA_C are always disabled to ensure there is no remaining dependency
# on the ECP module.
config_psa_crypto_no_ecp_at_all () {
    driver_only="$1"
    # start with full config for maximum coverage (also enables USE_PSA)
    helper_libtestdriver1_adjust_config "full"

    if [ "$driver_only" -eq 1 ]; then
        # Disable modules that are accelerated
        scripts/config.py unset MBEDTLS_ECDSA_C
        scripts/config.py unset MBEDTLS_ECDH_C
        scripts/config.py unset MBEDTLS_ECJPAKE_C
        # Disable ECP module (entirely)
        scripts/config.py unset MBEDTLS_ECP_C
    fi

    # Disable all the features that auto-enable ECP_LIGHT (see build_info.h)
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_EXTENDED
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_COMPRESSED
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE
}

# Build and test a configuration where driver accelerates all EC algs while
# all support and dependencies from ECP and ECP_LIGHT are removed on the library
# side.
#
# Keep in sync with component_test_psa_crypto_config_reference_ecc_no_ecp_at_all()
component_test_psa_crypto_config_accel_ecc_no_ecp_at_all () {
    msg "build: full + accelerated EC algs - ECP"

    # Algorithms and key types to accelerate
    loc_accel_list="ALG_ECDSA ALG_DETERMINISTIC_ECDSA \
                    ALG_ECDH \
                    ALG_JPAKE \
                    $(helper_get_psa_key_type_list "ECC") \
                    $(helper_get_psa_curve_list)"

    # Configure
    # ---------

    # Set common configurations between library's and driver's builds
    config_psa_crypto_no_ecp_at_all 1
    # Disable all the builtin curves. All the required algs are accelerated.
    helper_disable_builtin_curves

    # Build
    # -----

    # Things we wanted supported in libtestdriver1, but not accelerated in the main library:
    # SHA-1 and all SHA-2/3 variants, as they are used by ECDSA deterministic.
    loc_extra_list="ALG_SHA_1 ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"

    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure any built-in EC alg was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ ${BUILTIN_SRC_PATH}/ecdsa.o
    not grep mbedtls_ecdh_ ${BUILTIN_SRC_PATH}/ecdh.o
    not grep mbedtls_ecjpake_ ${BUILTIN_SRC_PATH}/ecjpake.o
    # Also ensure that ECP module was not re-enabled
    not grep mbedtls_ecp_ ${BUILTIN_SRC_PATH}/ecp.o

    # Run the tests
    # -------------

    msg "test: full + accelerated EC algs - ECP"
    make test

    msg "ssl-opt: full + accelerated EC algs - ECP"
    tests/ssl-opt.sh
}

# Reference function used for driver's coverage analysis in analyze_outcomes.py
# in conjunction with component_test_psa_crypto_config_accel_ecc_no_ecp_at_all().
# Keep in sync with its accelerated counterpart.
component_test_psa_crypto_config_reference_ecc_no_ecp_at_all () {
    msg "build: full + non accelerated EC algs"

    config_psa_crypto_no_ecp_at_all 0

    make

    msg "test: full + non accelerated EC algs"
    make test

    msg "ssl-opt: full + non accelerated EC algs"
    tests/ssl-opt.sh
}

# This is a common configuration helper used directly from:
# - common_test_psa_crypto_config_accel_ecc_ffdh_no_bignum
# - common_test_psa_crypto_config_reference_ecc_ffdh_no_bignum
# and indirectly from:
# - component_test_psa_crypto_config_accel_ecc_no_bignum
#       - accelerate all EC algs, disable RSA and FFDH
# - component_test_psa_crypto_config_reference_ecc_no_bignum
#       - this is the reference component of the above
#       - it still disables RSA and FFDH, but it uses builtin EC algs
# - component_test_psa_crypto_config_accel_ecc_ffdh_no_bignum
#       - accelerate all EC and FFDH algs, disable only RSA
# - component_test_psa_crypto_config_reference_ecc_ffdh_no_bignum
#       - this is the reference component of the above
#       - it still disables RSA, but it uses builtin EC and FFDH algs
#
# This function accepts 2 parameters:
# $1: a boolean value which states if we are testing an accelerated scenario
#     or not.
# $2: a string value which states which components are tested. Allowed values
#     are "ECC" or "ECC_DH".
config_psa_crypto_config_accel_ecc_ffdh_no_bignum() {
    driver_only="$1"
    test_target="$2"
    # start with full config for maximum coverage (also enables USE_PSA)
    helper_libtestdriver1_adjust_config "full"

    if [ "$driver_only" -eq 1 ]; then
        # Disable modules that are accelerated
        scripts/config.py unset MBEDTLS_ECDSA_C
        scripts/config.py unset MBEDTLS_ECDH_C
        scripts/config.py unset MBEDTLS_ECJPAKE_C
        # Disable ECP module (entirely)
        scripts/config.py unset MBEDTLS_ECP_C
        # Also disable bignum
        scripts/config.py unset MBEDTLS_BIGNUM_C
    fi

    # Disable all the features that auto-enable ECP_LIGHT (see build_info.h)
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_EXTENDED
    scripts/config.py unset MBEDTLS_PK_PARSE_EC_COMPRESSED
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE

    # RSA support is intentionally disabled on this test because RSA_C depends
    # on BIGNUM_C.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset-all "PSA_WANT_KEY_TYPE_RSA_[0-9A-Z_a-z]*"
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset-all "PSA_WANT_ALG_RSA_[0-9A-Z_a-z]*"
    scripts/config.py unset MBEDTLS_RSA_C
    scripts/config.py unset MBEDTLS_PKCS1_V15
    scripts/config.py unset MBEDTLS_PKCS1_V21
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT
    # Also disable key exchanges that depend on RSA
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED

    if [ "$test_target" = "ECC" ]; then
        # When testing ECC only, we disable FFDH support, both from builtin and
        # PSA sides, and also disable the key exchanges that depend on DHM.
        scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_FFDH
        scripts/config.py -f "$CRYPTO_CONFIG_H" unset-all "PSA_WANT_KEY_TYPE_DH_[0-9A-Z_a-z]*"
        scripts/config.py -f "$CRYPTO_CONFIG_H" unset-all "PSA_WANT_DH_RFC7919_[0-9]*"
        scripts/config.py unset MBEDTLS_DHM_C
        scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
        scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
    else
        # When testing ECC and DH instead, we disable DHM and depending key
        # exchanges only in the accelerated build
        if [ "$driver_only" -eq 1 ]; then
            scripts/config.py unset MBEDTLS_DHM_C
            scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
            scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
        fi
    fi

    # Restartable feature is not yet supported by PSA. Once it will in
    # the future, the following line could be removed (see issues
    # 6061, 6332 and following ones)
    scripts/config.py unset MBEDTLS_ECP_RESTARTABLE
}

# Common helper used by:
# - component_test_psa_crypto_config_accel_ecc_no_bignum
# - component_test_psa_crypto_config_accel_ecc_ffdh_no_bignum
#
# The goal is to build and test accelerating either:
# - ECC only or
# - both ECC and FFDH
#
# It is meant to be used in conjunction with
# common_test_psa_crypto_config_reference_ecc_ffdh_no_bignum() for drivers
# coverage analysis in the "analyze_outcomes.py" script.
common_test_psa_crypto_config_accel_ecc_ffdh_no_bignum () {
    test_target="$1"

    # This is an internal helper to simplify text message handling
    if [ "$test_target" = "ECC_DH" ]; then
        accel_text="ECC/FFDH"
        removed_text="ECP - DH"
    else
        accel_text="ECC"
        removed_text="ECP"
    fi

    msg "build: full + accelerated $accel_text algs + USE_PSA - $removed_text - BIGNUM"

    # By default we accelerate all EC keys/algs
    loc_accel_list="ALG_ECDSA ALG_DETERMINISTIC_ECDSA \
                    ALG_ECDH \
                    ALG_JPAKE \
                    $(helper_get_psa_key_type_list "ECC") \
                    $(helper_get_psa_curve_list)"
    # Optionally we can also add DH to the list of accelerated items
    if [ "$test_target" = "ECC_DH" ]; then
        loc_accel_list="$loc_accel_list \
                        ALG_FFDH \
                        $(helper_get_psa_key_type_list "DH") \
                        $(helper_get_psa_dh_group_list)"
    fi

    # Configure
    # ---------

    # Set common configurations between library's and driver's builds
    config_psa_crypto_config_accel_ecc_ffdh_no_bignum 1 "$test_target"
    # Disable all the builtin curves. All the required algs are accelerated.
    helper_disable_builtin_curves

    # Build
    # -----

    # Things we wanted supported in libtestdriver1, but not accelerated in the main library:
    # SHA-1 and all SHA-2/3 variants, as they are used by ECDSA deterministic.
    loc_extra_list="ALG_SHA_1 ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"

    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure any built-in EC alg was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ ${BUILTIN_SRC_PATH}/ecdsa.o
    not grep mbedtls_ecdh_ ${BUILTIN_SRC_PATH}/ecdh.o
    not grep mbedtls_ecjpake_ ${BUILTIN_SRC_PATH}/ecjpake.o
    # Also ensure that ECP, RSA, [DHM] or BIGNUM modules were not re-enabled
    not grep mbedtls_ecp_ ${BUILTIN_SRC_PATH}/ecp.o
    not grep mbedtls_rsa_ ${BUILTIN_SRC_PATH}/rsa.o
    not grep mbedtls_mpi_ ${BUILTIN_SRC_PATH}/bignum.o
    not grep mbedtls_dhm_ ${BUILTIN_SRC_PATH}/dhm.o

    # Run the tests
    # -------------

    msg "test suites: full + accelerated $accel_text algs + USE_PSA - $removed_text - DHM - BIGNUM"

    make test

    msg "ssl-opt: full + accelerated $accel_text algs + USE_PSA - $removed_text - BIGNUM"
    tests/ssl-opt.sh
}

# Common helper used by:
# - component_test_psa_crypto_config_reference_ecc_no_bignum
# - component_test_psa_crypto_config_reference_ecc_ffdh_no_bignum
#
# The goal is to build and test a reference scenario (i.e. with builtin
# components) compared to the ones used in
# common_test_psa_crypto_config_accel_ecc_ffdh_no_bignum() above.
#
# It is meant to be used in conjunction with
# common_test_psa_crypto_config_accel_ecc_ffdh_no_bignum() for drivers'
# coverage analysis in "analyze_outcomes.py" script.
common_test_psa_crypto_config_reference_ecc_ffdh_no_bignum () {
    test_target="$1"

    # This is an internal helper to simplify text message handling
    if [ "$test_target" = "ECC_DH" ]; then
        accel_text="ECC/FFDH"
    else
        accel_text="ECC"
    fi

    msg "build: full + non accelerated $accel_text algs + USE_PSA"

    config_psa_crypto_config_accel_ecc_ffdh_no_bignum 0 "$test_target"

    make

    msg "test suites: full + non accelerated EC algs + USE_PSA"
    make test

    msg "ssl-opt: full + non accelerated $accel_text algs + USE_PSA"
    tests/ssl-opt.sh
}

component_test_psa_crypto_config_accel_ecc_no_bignum () {
    common_test_psa_crypto_config_accel_ecc_ffdh_no_bignum "ECC"
}

component_test_psa_crypto_config_reference_ecc_no_bignum () {
    common_test_psa_crypto_config_reference_ecc_ffdh_no_bignum "ECC"
}

component_test_psa_crypto_config_accel_ecc_ffdh_no_bignum () {
    common_test_psa_crypto_config_accel_ecc_ffdh_no_bignum "ECC_DH"
}

component_test_psa_crypto_config_reference_ecc_ffdh_no_bignum () {
    common_test_psa_crypto_config_reference_ecc_ffdh_no_bignum "ECC_DH"
}

# Helper for setting common configurations between:
# - component_test_tfm_config_p256m_driver_accel_ec()
# - component_test_tfm_config()
common_tfm_config () {
    # Enable TF-M config
    cp configs/config-tfm.h "$CONFIG_H"
    echo "#undef MBEDTLS_PSA_CRYPTO_CONFIG_FILE" >> "$CONFIG_H"
    cp configs/ext/crypto_config_profile_medium.h "$CRYPTO_CONFIG_H"

    # Other config adjustment to make the tests pass.
    # This should probably be adopted upstream.
    #
    # - USE_PSA_CRYPTO for PK_HAVE_ECC_KEYS
    echo "#define MBEDTLS_USE_PSA_CRYPTO" >> "$CONFIG_H"

    # Config adjustment for better test coverage in our environment.
    # This is not needed just to build and pass tests.
    #
    # Enable filesystem I/O for the benefit of PK parse/write tests.
    echo "#define MBEDTLS_FS_IO" >> "$CONFIG_H"
}

# Keep this in sync with component_test_tfm_config() as they are both meant
# to be used in analyze_outcomes.py for driver's coverage analysis.
component_test_tfm_config_p256m_driver_accel_ec () {
    msg "build: TF-M config + p256m driver + accel ECDH(E)/ECDSA"

    common_tfm_config

    # Build crypto library
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS -I../tests/include/spe" LDFLAGS="$ASAN_CFLAGS"

    # Make sure any built-in EC alg was not re-enabled by accident (additive config)
    not grep mbedtls_ecdsa_ ${BUILTIN_SRC_PATH}/ecdsa.o
    not grep mbedtls_ecdh_ ${BUILTIN_SRC_PATH}/ecdh.o
    not grep mbedtls_ecjpake_ ${BUILTIN_SRC_PATH}/ecjpake.o
    # Also ensure that ECP, RSA, DHM or BIGNUM modules were not re-enabled
    not grep mbedtls_ecp_ ${BUILTIN_SRC_PATH}/ecp.o
    not grep mbedtls_rsa_ ${BUILTIN_SRC_PATH}/rsa.o
    not grep mbedtls_dhm_ ${BUILTIN_SRC_PATH}/dhm.o
    not grep mbedtls_mpi_ ${BUILTIN_SRC_PATH}/bignum.o
    # Check that p256m was built
    grep -q p256_ecdsa_ library/libmbedcrypto.a

    # In "config-tfm.h" we disabled CIPHER_C tweaking TF-M's configuration
    # files, so we want to ensure that it has not be re-enabled accidentally.
    not grep mbedtls_cipher ${BUILTIN_SRC_PATH}/cipher.o

    # Run the tests
    msg "test: TF-M config + p256m driver + accel ECDH(E)/ECDSA"
    make test
}

# Keep this in sync with component_test_tfm_config_p256m_driver_accel_ec() as
# they are both meant to be used in analyze_outcomes.py for driver's coverage
# analysis.
component_test_tfm_config() {
    common_tfm_config

    # Disable P256M driver, which is on by default, so that analyze_outcomes
    # can compare this test with test_tfm_config_p256m_driver_accel_ec
    echo "#undef MBEDTLS_PSA_P256M_DRIVER_ENABLED" >> "$CONFIG_H"

    msg "build: TF-M config"
    make CFLAGS='-Werror -Wall -Wextra -I../tests/include/spe' tests

    # Check that p256m was not built
    not grep p256_ecdsa_ library/libmbedcrypto.a

    # In "config-tfm.h" we disabled CIPHER_C tweaking TF-M's configuration
    # files, so we want to ensure that it has not be re-enabled accidentally.
    not grep mbedtls_cipher ${BUILTIN_SRC_PATH}/cipher.o

    msg "test: TF-M config"
    make test
}

# Common helper for component_full_without_ecdhe_ecdsa() and
# component_full_without_ecdhe_ecdsa_and_tls13() which:
# - starts from the "full" configuration minus the list of symbols passed in
#   as 1st parameter
# - build
# - test only TLS (i.e. test_suite_tls and ssl-opt)
build_full_minus_something_and_test_tls () {
    symbols_to_disable="$1"

    msg "build: full minus something, test TLS"

    scripts/config.py full
    for sym in $symbols_to_disable; do
        echo "Disabling $sym"
        scripts/config.py unset $sym
    done

    make

    msg "test: full minus something, test TLS"
    ( cd tests; ./test_suite_ssl )

    msg "ssl-opt: full minus something, test TLS"
    tests/ssl-opt.sh
}

component_full_without_ecdhe_ecdsa () {
    build_full_minus_something_and_test_tls "MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED"
}

component_full_without_ecdhe_ecdsa_and_tls13 () {
    build_full_minus_something_and_test_tls "MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
                                             MBEDTLS_SSL_PROTO_TLS1_3"
}

# This is an helper used by:
# - component_test_psa_ecc_key_pair_no_derive
# - component_test_psa_ecc_key_pair_no_generate
# The goal is to test with all PSA_WANT_KEY_TYPE_xxx_KEY_PAIR_yyy symbols
# enabled, but one. Input arguments are as follows:
# - $1 is the key type under test, i.e. ECC/RSA/DH
# - $2 is the key option to be unset (i.e. generate, derive, etc)
build_and_test_psa_want_key_pair_partial() {
    key_type=$1
    unset_option=$2
    disabled_psa_want="PSA_WANT_KEY_TYPE_${key_type}_KEY_PAIR_${unset_option}"

    msg "build: full - MBEDTLS_USE_PSA_CRYPTO - ${disabled_psa_want}"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3

    # All the PSA_WANT_KEY_TYPE_xxx_KEY_PAIR_yyy are enabled by default in
    # crypto_config.h so we just disable the one we don't want.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset "$disabled_psa_want"

    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full - MBEDTLS_USE_PSA_CRYPTO - ${disabled_psa_want}"
    make test
}

component_test_psa_ecc_key_pair_no_derive() {
    build_and_test_psa_want_key_pair_partial "ECC" "DERIVE"
}

component_test_psa_ecc_key_pair_no_generate() {
    build_and_test_psa_want_key_pair_partial "ECC" "GENERATE"
}

config_psa_crypto_accel_rsa () {
    driver_only=$1

    # Start from crypto_full config (no X.509, no TLS)
    helper_libtestdriver1_adjust_config "crypto_full"

    if [ "$driver_only" -eq 1 ]; then
        # Remove RSA support and its dependencies
        scripts/config.py unset MBEDTLS_RSA_C
        scripts/config.py unset MBEDTLS_PKCS1_V15
        scripts/config.py unset MBEDTLS_PKCS1_V21

        # We need PEM parsing in the test library as well to support the import
        # of PEM encoded RSA keys.
        scripts/config.py -f "$CONFIG_TEST_DRIVER_H" set MBEDTLS_PEM_PARSE_C
        scripts/config.py -f "$CONFIG_TEST_DRIVER_H" set MBEDTLS_BASE64_C
    fi
}

component_test_psa_crypto_config_accel_rsa_crypto () {
    msg "build: crypto_full with accelerated RSA"

    loc_accel_list="ALG_RSA_OAEP ALG_RSA_PSS \
                    ALG_RSA_PKCS1V15_CRYPT ALG_RSA_PKCS1V15_SIGN \
                    KEY_TYPE_RSA_PUBLIC_KEY \
                    KEY_TYPE_RSA_KEY_PAIR_BASIC \
                    KEY_TYPE_RSA_KEY_PAIR_GENERATE \
                    KEY_TYPE_RSA_KEY_PAIR_IMPORT \
                    KEY_TYPE_RSA_KEY_PAIR_EXPORT"

    # Configure
    # ---------

    config_psa_crypto_accel_rsa 1

    # Build
    # -----

    # These hashes are needed for unit tests.
    loc_extra_list="ALG_SHA_1 ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512 ALG_MD5"
    helper_libtestdriver1_make_drivers "$loc_accel_list" "$loc_extra_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_rsa ${BUILTIN_SRC_PATH}/rsa.o

    # Run the tests
    # -------------

    msg "test: crypto_full with accelerated RSA"
    make test
}

component_test_psa_crypto_config_reference_rsa_crypto () {
    msg "build: crypto_full with non-accelerated RSA"

    # Configure
    # ---------
    config_psa_crypto_accel_rsa 0

    # Build
    # -----
    make

    # Run the tests
    # -------------
    msg "test: crypto_full with non-accelerated RSA"
    make test
}

# This is a temporary test to verify that full RSA support is present even when
# only one single new symbols (PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC) is defined.
component_test_new_psa_want_key_pair_symbol() {
    msg "Build: crypto config - MBEDTLS_RSA_C + PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC"

    # Create a temporary output file unless there is already one set
    if [ "$MBEDTLS_TEST_OUTCOME_FILE" ]; then
        REMOVE_OUTCOME_ON_EXIT="no"
    else
        REMOVE_OUTCOME_ON_EXIT="yes"
        MBEDTLS_TEST_OUTCOME_FILE="$PWD/out.csv"
        export MBEDTLS_TEST_OUTCOME_FILE
    fi

    # Start from crypto configuration
    scripts/config.py crypto

    # Remove RSA support and its dependencies
    scripts/config.py unset MBEDTLS_PKCS1_V15
    scripts/config.py unset MBEDTLS_PKCS1_V21
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
    scripts/config.py unset MBEDTLS_RSA_C
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT

    # Enable PSA support
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG

    # Keep only PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC enabled in order to ensure
    # that proper translations is done in crypto_legacy.h.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE

    make

    msg "Test: crypto config - MBEDTLS_RSA_C + PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC"
    make test

    # Parse only 1 relevant line from the outcome file, i.e. a test which is
    # performing RSA signature.
    msg "Verify that 'RSA PKCS1 Sign #1 (SHA512, 1536 bits RSA)' is PASS"
    cat $MBEDTLS_TEST_OUTCOME_FILE | grep 'RSA PKCS1 Sign #1 (SHA512, 1536 bits RSA)' | grep -q "PASS"

    if [ "$REMOVE_OUTCOME_ON_EXIT" == "yes" ]; then
        rm $MBEDTLS_TEST_OUTCOME_FILE
    fi
}

component_test_psa_crypto_config_accel_hash () {
    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated hash"

    loc_accel_list="ALG_MD5 ALG_RIPEMD160 ALG_SHA_1 \
                    ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"

    # Configure
    # ---------

    # Start from default config (no USE_PSA)
    helper_libtestdriver1_adjust_config "default"

    # Disable the things that are being accelerated
    scripts/config.py unset MBEDTLS_MD5_C
    scripts/config.py unset MBEDTLS_RIPEMD160_C
    scripts/config.py unset MBEDTLS_SHA1_C
    scripts/config.py unset MBEDTLS_SHA224_C
    scripts/config.py unset MBEDTLS_SHA256_C
    scripts/config.py unset MBEDTLS_SHA384_C
    scripts/config.py unset MBEDTLS_SHA512_C
    scripts/config.py unset MBEDTLS_SHA3_C

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # There's a risk of something getting re-enabled via config_psa.h;
    # make sure it did not happen. Note: it's OK for MD_C to be enabled.
    not grep mbedtls_md5 ${BUILTIN_SRC_PATH}/md5.o
    not grep mbedtls_sha1 ${BUILTIN_SRC_PATH}/sha1.o
    not grep mbedtls_sha256 ${BUILTIN_SRC_PATH}/sha256.o
    not grep mbedtls_sha512 ${BUILTIN_SRC_PATH}/sha512.o
    not grep mbedtls_ripemd160 ${BUILTIN_SRC_PATH}/ripemd160.o

    # Run the tests
    # -------------

    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated hash"
    make test
}

# Auxiliary function to build config for hashes with and without drivers
config_psa_crypto_hash_use_psa () {
    driver_only="$1"
    # start with config full for maximum coverage (also enables USE_PSA)
    helper_libtestdriver1_adjust_config "full"
    if [ "$driver_only" -eq 1 ]; then
        # disable the built-in implementation of hashes
        scripts/config.py unset MBEDTLS_MD5_C
        scripts/config.py unset MBEDTLS_RIPEMD160_C
        scripts/config.py unset MBEDTLS_SHA1_C
        scripts/config.py unset MBEDTLS_SHA224_C
        scripts/config.py unset MBEDTLS_SHA256_C # see external RNG below
        scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
        scripts/config.py unset MBEDTLS_SHA384_C
        scripts/config.py unset MBEDTLS_SHA512_C
        scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT
        scripts/config.py unset MBEDTLS_SHA3_C
    fi
}

# Note that component_test_psa_crypto_config_reference_hash_use_psa
# is related to this component and both components need to be kept in sync.
# For details please see comments for component_test_psa_crypto_config_reference_hash_use_psa.
component_test_psa_crypto_config_accel_hash_use_psa () {
    msg "test: full with accelerated hashes"

    loc_accel_list="ALG_MD5 ALG_RIPEMD160 ALG_SHA_1 \
                    ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"

    # Configure
    # ---------

    config_psa_crypto_hash_use_psa 1

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # There's a risk of something getting re-enabled via config_psa.h;
    # make sure it did not happen. Note: it's OK for MD_C to be enabled.
    not grep mbedtls_md5 ${BUILTIN_SRC_PATH}/md5.o
    not grep mbedtls_sha1 ${BUILTIN_SRC_PATH}/sha1.o
    not grep mbedtls_sha256 ${BUILTIN_SRC_PATH}/sha256.o
    not grep mbedtls_sha512 ${BUILTIN_SRC_PATH}/sha512.o
    not grep mbedtls_ripemd160 ${BUILTIN_SRC_PATH}/ripemd160.o

    # Run the tests
    # -------------

    msg "test: full with accelerated hashes"
    make test

    # This is mostly useful so that we can later compare outcome files with
    # the reference config in analyze_outcomes.py, to check that the
    # dependency declarations in ssl-opt.sh and in TLS code are correct.
    msg "test: ssl-opt.sh, full with accelerated hashes"
    tests/ssl-opt.sh

    # This is to make sure all ciphersuites are exercised, but we don't need
    # interop testing (besides, we already got some from ssl-opt.sh).
    msg "test: compat.sh, full with accelerated hashes"
    tests/compat.sh -p mbedTLS -V YES
}

# This component provides reference configuration for test_psa_crypto_config_accel_hash_use_psa
# without accelerated hash. The outcome from both components are used by the analyze_outcomes.py
# script to find regression in test coverage when accelerated hash is used (tests and ssl-opt).
# Both components need to be kept in sync.
component_test_psa_crypto_config_reference_hash_use_psa() {
    msg "test: full without accelerated hashes"

    config_psa_crypto_hash_use_psa 0

    make

    msg "test: full without accelerated hashes"
    make test

    msg "test: ssl-opt.sh, full without accelerated hashes"
    tests/ssl-opt.sh
}

# Auxiliary function to build config for hashes with and without drivers
config_psa_crypto_hmac_use_psa () {
    driver_only="$1"
    # start with config full for maximum coverage (also enables USE_PSA)
    helper_libtestdriver1_adjust_config "full"

    if [ "$driver_only" -eq 1 ]; then
        # Disable MD_C in order to disable the builtin support for HMAC. MD_LIGHT
        # is still enabled though (for ENTROPY_C among others).
        scripts/config.py unset MBEDTLS_MD_C
        # Disable also the builtin hashes since they are supported by the driver
        # and MD module is able to perform PSA dispathing.
        scripts/config.py unset-all MBEDTLS_SHA
        scripts/config.py unset MBEDTLS_MD5_C
        scripts/config.py unset MBEDTLS_RIPEMD160_C
    fi

    # Direct dependencies of MD_C. We disable them also in the reference
    # component to work with the same set of features.
    scripts/config.py unset MBEDTLS_PKCS7_C
    scripts/config.py unset MBEDTLS_PKCS5_C
    scripts/config.py unset MBEDTLS_HMAC_DRBG_C
    scripts/config.py unset MBEDTLS_HKDF_C
    # Dependencies of HMAC_DRBG
    scripts/config.py unset MBEDTLS_ECDSA_DETERMINISTIC
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_DETERMINISTIC_ECDSA
}

component_test_psa_crypto_config_accel_hmac() {
    msg "test: full with accelerated hmac"

    loc_accel_list="ALG_HMAC KEY_TYPE_HMAC \
                    ALG_MD5 ALG_RIPEMD160 ALG_SHA_1 \
                    ALG_SHA_224 ALG_SHA_256 ALG_SHA_384 ALG_SHA_512 \
                    ALG_SHA3_224 ALG_SHA3_256 ALG_SHA3_384 ALG_SHA3_512"

    # Configure
    # ---------

    config_psa_crypto_hmac_use_psa 1

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Ensure that built-in support for HMAC is disabled.
    not grep mbedtls_md_hmac ${BUILTIN_SRC_PATH}/md.o

    # Run the tests
    # -------------

    msg "test: full with accelerated hmac"
    make test
}

component_test_psa_crypto_config_reference_hmac() {
    msg "test: full without accelerated hmac"

    config_psa_crypto_hmac_use_psa 0

    make

    msg "test: full without accelerated hmac"
    make test
}

component_test_psa_crypto_config_accel_des () {
    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated DES"

    # Albeit this components aims at accelerating DES which should only support
    # CBC and ECB modes, we need to accelerate more than that otherwise DES_C
    # would automatically be re-enabled by "config_adjust_legacy_from_psa.c"
    loc_accel_list="ALG_ECB_NO_PADDING ALG_CBC_NO_PADDING ALG_CBC_PKCS7 \
                    ALG_CTR ALG_CFB ALG_OFB ALG_XTS ALG_CMAC \
                    KEY_TYPE_DES"

    # Note: we cannot accelerate all ciphers' key types otherwise we would also
    # have to either disable CCM/GCM or accelerate them, but that's out of scope
    # of this component. This limitation will be addressed by #8598.

    # Configure
    # ---------

    # Start from the full config
    helper_libtestdriver1_adjust_config "full"

    # Disable the things that are being accelerated
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CBC
    scripts/config.py unset MBEDTLS_CIPHER_PADDING_PKCS7
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CTR
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CFB
    scripts/config.py unset MBEDTLS_CIPHER_MODE_OFB
    scripts/config.py unset MBEDTLS_CIPHER_MODE_XTS
    scripts/config.py unset MBEDTLS_DES_C
    scripts/config.py unset MBEDTLS_CMAC_C

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_des* ${BUILTIN_SRC_PATH}/des.o

    # Run the tests
    # -------------

    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated DES"
    make test
}

component_test_psa_crypto_config_accel_aead () {
    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated AEAD"

    loc_accel_list="ALG_GCM ALG_CCM ALG_CHACHA20_POLY1305 \
                    KEY_TYPE_AES KEY_TYPE_CHACHA20 KEY_TYPE_ARIA KEY_TYPE_CAMELLIA"

    # Configure
    # ---------

    # Start from full config
    helper_libtestdriver1_adjust_config "full"

    # Disable things that are being accelerated
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py unset MBEDTLS_CCM_C
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C

    # Disable CCM_STAR_NO_TAG because this re-enables CCM_C.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CCM_STAR_NO_TAG

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_ccm ${BUILTIN_SRC_PATH}/ccm.o
    not grep mbedtls_gcm ${BUILTIN_SRC_PATH}/gcm.o
    not grep mbedtls_chachapoly ${BUILTIN_SRC_PATH}/chachapoly.o

    # Run the tests
    # -------------

    msg "test: MBEDTLS_PSA_CRYPTO_CONFIG with accelerated AEAD"
    make test
}

# This is a common configuration function used in:
# - component_test_psa_crypto_config_accel_cipher_aead_cmac
# - component_test_psa_crypto_config_reference_cipher_aead_cmac
common_psa_crypto_config_accel_cipher_aead_cmac() {
    # Start from the full config
    helper_libtestdriver1_adjust_config "full"

    scripts/config.py unset MBEDTLS_NIST_KW_C
}

# The 2 following test components, i.e.
# - component_test_psa_crypto_config_accel_cipher_aead_cmac
# - component_test_psa_crypto_config_reference_cipher_aead_cmac
# are meant to be used together in analyze_outcomes.py script in order to test
# driver's coverage for ciphers and AEADs.
component_test_psa_crypto_config_accel_cipher_aead_cmac () {
    msg "build: full config with accelerated cipher inc. AEAD and CMAC"

    loc_accel_list="ALG_ECB_NO_PADDING ALG_CBC_NO_PADDING ALG_CBC_PKCS7 ALG_CTR ALG_CFB \
                    ALG_OFB ALG_XTS ALG_STREAM_CIPHER ALG_CCM_STAR_NO_TAG \
                    ALG_GCM ALG_CCM ALG_CHACHA20_POLY1305 ALG_CMAC \
                    KEY_TYPE_DES KEY_TYPE_AES KEY_TYPE_ARIA KEY_TYPE_CHACHA20 KEY_TYPE_CAMELLIA"

    # Configure
    # ---------

    common_psa_crypto_config_accel_cipher_aead_cmac

    # Disable the things that are being accelerated
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CBC
    scripts/config.py unset MBEDTLS_CIPHER_PADDING_PKCS7
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CTR
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CFB
    scripts/config.py unset MBEDTLS_CIPHER_MODE_OFB
    scripts/config.py unset MBEDTLS_CIPHER_MODE_XTS
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py unset MBEDTLS_CCM_C
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    scripts/config.py unset MBEDTLS_CMAC_C
    scripts/config.py unset MBEDTLS_DES_C
    scripts/config.py unset MBEDTLS_AES_C
    scripts/config.py unset MBEDTLS_ARIA_C
    scripts/config.py unset MBEDTLS_CHACHA20_C
    scripts/config.py unset MBEDTLS_CAMELLIA_C

    # Disable CIPHER_C entirely as all ciphers/AEADs are accelerated and PSA
    # does not depend on it.
    scripts/config.py unset MBEDTLS_CIPHER_C

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure this was not re-enabled by accident (additive config)
    not grep mbedtls_cipher ${BUILTIN_SRC_PATH}/cipher.o
    not grep mbedtls_des ${BUILTIN_SRC_PATH}/des.o
    not grep mbedtls_aes ${BUILTIN_SRC_PATH}/aes.o
    not grep mbedtls_aria ${BUILTIN_SRC_PATH}/aria.o
    not grep mbedtls_camellia ${BUILTIN_SRC_PATH}/camellia.o
    not grep mbedtls_ccm ${BUILTIN_SRC_PATH}/ccm.o
    not grep mbedtls_gcm ${BUILTIN_SRC_PATH}/gcm.o
    not grep mbedtls_chachapoly ${BUILTIN_SRC_PATH}/chachapoly.o
    not grep mbedtls_cmac ${BUILTIN_SRC_PATH}/cmac.o

    # Run the tests
    # -------------

    msg "test: full config with accelerated cipher inc. AEAD and CMAC"
    make test

    msg "ssl-opt: full config with accelerated cipher inc. AEAD and CMAC"
    tests/ssl-opt.sh

    msg "compat.sh: full config with accelerated cipher inc. AEAD and CMAC"
    tests/compat.sh -V NO -p mbedTLS
}

component_test_psa_crypto_config_reference_cipher_aead_cmac () {
    msg "build: full config with non-accelerated cipher inc. AEAD and CMAC"
    common_psa_crypto_config_accel_cipher_aead_cmac

    make

    msg "test: full config with non-accelerated cipher inc. AEAD and CMAC"
    make test

    msg "ssl-opt: full config with non-accelerated cipher inc. AEAD and CMAC"
    tests/ssl-opt.sh

    msg "compat.sh: full config with non-accelerated cipher inc. AEAD and CMAC"
    tests/compat.sh -V NO -p mbedTLS
}

common_block_cipher_dispatch() {
    TEST_WITH_DRIVER="$1"

    # Start from the full config
    helper_libtestdriver1_adjust_config "full"

    if [ "$TEST_WITH_DRIVER" -eq 1 ]; then
        # Disable key types that are accelerated (there is no legacy equivalent
        # symbol for ECB)
        scripts/config.py unset MBEDTLS_AES_C
        scripts/config.py unset MBEDTLS_ARIA_C
        scripts/config.py unset MBEDTLS_CAMELLIA_C
    fi

    # Disable cipher's modes that, when not accelerated, cause
    # legacy key types to be re-enabled in "config_adjust_legacy_from_psa.h".
    # Keep this also in the reference component in order to skip the same tests
    # that were skipped in the accelerated one.
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CTR
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CFB
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_OFB
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_NO_PADDING
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_PKCS7
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CMAC
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CCM_STAR_NO_TAG
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128

    # Disable direct dependency on AES_C
    scripts/config.py unset MBEDTLS_NIST_KW_C

    # Prevent the cipher module from using deprecated PSA path. The reason is
    # that otherwise there will be tests relying on "aes_info" (defined in
    # "cipher_wrap.c") whose functions are not available when AES_C is
    # not defined. ARIA and Camellia are not a problem in this case because
    # the PSA path is not tested for these key types.
    scripts/config.py set MBEDTLS_DEPRECATED_REMOVED
}

component_test_full_block_cipher_psa_dispatch () {
    msg "build: full + PSA dispatch in block_cipher"

    loc_accel_list="ALG_ECB_NO_PADDING \
                    KEY_TYPE_AES KEY_TYPE_ARIA KEY_TYPE_CAMELLIA"

    # Configure
    # ---------

    common_block_cipher_dispatch 1

    # Build
    # -----

    helper_libtestdriver1_make_drivers "$loc_accel_list"

    helper_libtestdriver1_make_main "$loc_accel_list"

    # Make sure disabled components were not re-enabled by accident (additive
    # config)
    not grep mbedtls_aes_ ${BUILTIN_SRC_PATH}/aes.o
    not grep mbedtls_aria_ ${BUILTIN_SRC_PATH}/aria.o
    not grep mbedtls_camellia_ ${BUILTIN_SRC_PATH}/camellia.o

    # Run the tests
    # -------------

    msg "test: full + PSA dispatch in block_cipher"
    make test
}

# This is the reference component of component_test_full_block_cipher_psa_dispatch
component_test_full_block_cipher_legacy_dispatch () {
    msg "build: full + legacy dispatch in block_cipher"

    common_block_cipher_dispatch 0

    make

    msg "test: full + legacy dispatch in block_cipher"
    make test
}

component_test_aead_chachapoly_disabled() {
    msg "build: full minus CHACHAPOLY"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CHACHA20_POLY1305
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full minus CHACHAPOLY"
    make test
}

component_test_aead_only_ccm() {
    msg "build: full minus CHACHAPOLY and GCM"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_CHACHAPOLY_C
    scripts/config.py unset MBEDTLS_GCM_C
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CHACHA20_POLY1305
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_GCM
    make CC=$ASAN_CC CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full minus CHACHAPOLY and GCM"
    make test
}

component_test_ccm_aes_sha256() {
    msg "build: CCM + AES + SHA256 configuration"

    cp "$CONFIG_TEST_DRIVER_H" "$CONFIG_H"
    cp configs/crypto-config-ccm-aes-sha256.h "$CRYPTO_CONFIG_H"

    make

    msg "test: CCM + AES + SHA256 configuration"
    make test
}

support_build_tfm_armcc () {
    support_build_armcc
}

component_build_tfm_armcc() {
    # test the TF-M configuration can build cleanly with various warning flags enabled
    cp configs/config-tfm.h "$CONFIG_H"

    msg "build: TF-M config, armclang armv7-m thumb2"
    armc6_build_test "--target=arm-arm-none-eabi -march=armv7-m -mthumb -Os -std=c99 -Werror -Wall -Wextra -Wwrite-strings -Wpointer-arith -Wimplicit-fallthrough -Wshadow -Wvla -Wformat=2 -Wno-format-nonliteral -Wshadow -Wasm-operand-widths -Wunused -I../tests/include/spe"
}

component_build_tfm() {
    # Check that the TF-M configuration can build cleanly with various
    # warning flags enabled. We don't build or run tests, since the
    # TF-M configuration needs a TF-M platform. A tweaked version of
    # the configuration that works on mainstream platforms is in
    # configs/config-tfm.h, tested via test-ref-configs.pl.
    cp configs/config-tfm.h "$CONFIG_H"

    msg "build: TF-M config, clang, armv7-m thumb2"
    make lib CC="clang" CFLAGS="--target=arm-linux-gnueabihf -march=armv7-m -mthumb -Os -std=c99 -Werror -Wall -Wextra -Wwrite-strings -Wpointer-arith -Wimplicit-fallthrough -Wshadow -Wvla -Wformat=2 -Wno-format-nonliteral -Wshadow -Wasm-operand-widths -Wunused -I../tests/include/spe"

    msg "build: TF-M config, gcc native build"
    make clean
    make lib CC="gcc" CFLAGS="-Os -std=c99 -Werror -Wall -Wextra -Wwrite-strings -Wpointer-arith -Wshadow -Wvla -Wformat=2 -Wno-format-nonliteral -Wshadow -Wformat-signedness -Wlogical-op -I../tests/include/spe"
}

# Test that the given .o file builds with all (valid) combinations of the given options.
#
# Syntax: build_test_config_combos FILE VALIDATOR_FUNCTION OPT1 OPT2 ...
#
# The validator function is the name of a function to validate the combination of options.
# It may be "" if all combinations are valid.
# It receives a string containing a combination of options, as passed to the compiler,
# e.g. "-DOPT1 -DOPT2 ...". It must return 0 iff the combination is valid, non-zero if invalid.
build_test_config_combos() {
    file=$1
    shift
    validate_options=$1
    shift
    options=("$@")

    # clear all of the options so that they can be overridden on the clang commandline
    for opt in "${options[@]}"; do
        ./scripts/config.py unset ${opt}
    done

    # enter the library directory
    cd library

    # The most common issue is unused variables/functions, so ensure -Wunused is set.
    warning_flags="-Werror -Wall -Wextra -Wwrite-strings -Wpointer-arith -Wimplicit-fallthrough -Wshadow -Wvla -Wformat=2 -Wno-format-nonliteral -Wshadow -Wasm-operand-widths -Wunused"

    # Extract the command generated by the Makefile to build the target file.
    # This ensures that we have any include paths, macro definitions, etc
    # that may be applied by make.
    # Add -fsyntax-only as we only want a syntax check and don't need to generate a file.
    compile_cmd="clang \$(LOCAL_CFLAGS) ${warning_flags} -fsyntax-only -c"

    makefile=$(TMPDIR=. mktemp)
    deps=""

    len=${#options[@]}
    source_file=../${file%.o}.c

    targets=0
    echo 'include Makefile' >${makefile}

    for ((i = 0; i < $((2**${len})); i++)); do
        # generate each of 2^n combinations of options
        # each bit of $i is used to determine if options[i] will be set or not
        target="t"
        clang_args=""
        for ((j = 0; j < ${len}; j++)); do
            if (((i >> j) & 1)); then
                opt=-D${options[$j]}
                clang_args="${clang_args} ${opt}"
                target="${target}${opt}"
            fi
        done

        # if combination is not known to be invalid, add it to the makefile
        if [[ -z $validate_options ]] || $validate_options "${clang_args}"; then
            cmd="${compile_cmd} ${clang_args}"
            echo "${target}: ${source_file}; $cmd ${source_file}" >> ${makefile}

            deps="${deps} ${target}"
            ((++targets))
        fi
    done

    echo "build_test_config_combos: ${deps}" >> ${makefile}

    # execute all of the commands via Make (probably in parallel)
    make -s -f ${makefile} build_test_config_combos
    echo "$targets targets checked"

    # clean up the temporary makefile
    rm ${makefile}
}

validate_aes_config_variations() {
    if [[ "$1" == *"MBEDTLS_AES_USE_HARDWARE_ONLY"* ]]; then
        if [[ !(("$HOSTTYPE" == "aarch64" && "$1" != *"MBEDTLS_AESCE_C"*) || \
                ("$HOSTTYPE" == "x86_64"  && "$1" != *"MBEDTLS_AESNI_C"*)) ]]; then
            return 1
        fi
    fi
    return 0
}

component_build_aes_variations() {
    # 18s - around 90ms per clang invocation on M1 Pro
    #
    # aes.o has many #if defined(...) guards that intersect in complex ways.
    # Test that all the combinations build cleanly.

    MBEDTLS_ROOT_DIR="$PWD"
    msg "build: aes.o for all combinations of relevant config options"

    build_test_config_combos ${BUILTIN_SRC_PATH}/aes.o validate_aes_config_variations \
        "MBEDTLS_AES_SETKEY_ENC_ALT" "MBEDTLS_AES_DECRYPT_ALT" \
        "MBEDTLS_AES_ROM_TABLES" "MBEDTLS_AES_ENCRYPT_ALT" "MBEDTLS_AES_SETKEY_DEC_ALT" \
        "MBEDTLS_AES_FEWER_TABLES" "MBEDTLS_AES_USE_HARDWARE_ONLY" \
        "MBEDTLS_AESNI_C" "MBEDTLS_AESCE_C" "MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH"

    cd "$MBEDTLS_ROOT_DIR"
    msg "build: aes.o for all combinations of relevant config options + BLOCK_CIPHER_NO_DECRYPT"

    # MBEDTLS_BLOCK_CIPHER_NO_DECRYPT is incompatible with ECB in PSA, CBC/XTS/NIST_KW/DES,
    # manually set or unset those configurations to check
    # MBEDTLS_BLOCK_CIPHER_NO_DECRYPT with various combinations in aes.o.
    scripts/config.py set MBEDTLS_BLOCK_CIPHER_NO_DECRYPT
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CBC
    scripts/config.py unset MBEDTLS_CIPHER_MODE_XTS
    scripts/config.py unset MBEDTLS_DES_C
    scripts/config.py unset MBEDTLS_NIST_KW_C
    build_test_config_combos ${BUILTIN_SRC_PATH}/aes.o validate_aes_config_variations \
        "MBEDTLS_AES_SETKEY_ENC_ALT" "MBEDTLS_AES_DECRYPT_ALT" \
        "MBEDTLS_AES_ROM_TABLES" "MBEDTLS_AES_ENCRYPT_ALT" "MBEDTLS_AES_SETKEY_DEC_ALT" \
        "MBEDTLS_AES_FEWER_TABLES" "MBEDTLS_AES_USE_HARDWARE_ONLY" \
        "MBEDTLS_AESNI_C" "MBEDTLS_AESCE_C" "MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH"
}

component_test_no_platform () {
    # Full configuration build, without platform support, file IO and net sockets.
    # This should catch missing mbedtls_printf definitions, and by disabling file
    # IO, it should catch missing '#include <stdio.h>'
    msg "build: full config except platform/fsio/net, make, gcc, C99" # ~ 30s
    scripts/config.py full_no_platform
    scripts/config.py unset MBEDTLS_PLATFORM_C
    scripts/config.py unset MBEDTLS_NET_C
    scripts/config.py unset MBEDTLS_FS_IO
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_SE_C
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_STORAGE_C
    scripts/config.py unset MBEDTLS_PSA_ITS_FILE_C
    scripts/config.py unset MBEDTLS_ENTROPY_NV_SEED
    # Note, _DEFAULT_SOURCE needs to be defined for platforms using glibc version >2.19,
    # to re-enable platform integration features otherwise disabled in C99 builds
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -std=c99 -pedantic -Os -D_DEFAULT_SOURCE' lib programs
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -Os' test
}

component_build_no_std_function () {
    # catch compile bugs in _uninit functions
    msg "build: full config with NO_STD_FUNCTION, make, gcc" # ~ 30s
    scripts/config.py full
    scripts/config.py set MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
    scripts/config.py unset MBEDTLS_ENTROPY_NV_SEED
    scripts/config.py unset MBEDTLS_PLATFORM_NV_SEED_ALT
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Check .
    make
}

component_build_no_ssl_srv () {
    msg "build: full config except SSL server, make, gcc" # ~ 30s
    scripts/config.py full
    scripts/config.py unset MBEDTLS_SSL_SRV_C
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -O1'
}

component_build_no_ssl_cli () {
    msg "build: full config except SSL client, make, gcc" # ~ 30s
    scripts/config.py full
    scripts/config.py unset MBEDTLS_SSL_CLI_C
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -O1'
}

component_build_no_sockets () {
    # Note, C99 compliance can also be tested with the sockets support disabled,
    # as that requires a POSIX platform (which isn't the same as C99).
    msg "build: full config except net_sockets.c, make, gcc -std=c99 -pedantic" # ~ 30s
    scripts/config.py full
    scripts/config.py unset MBEDTLS_NET_C # getaddrinfo() undeclared, etc.
    scripts/config.py set MBEDTLS_NO_PLATFORM_ENTROPY # uses syscall() on GNU/Linux
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -O1 -std=c99 -pedantic' lib
}

component_test_memory_buffer_allocator_backtrace () {
    msg "build: default config with memory buffer allocator and backtrace enabled"
    scripts/config.py set MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_PLATFORM_MEMORY
    scripts/config.py set MBEDTLS_MEMORY_BACKTRACE
    scripts/config.py set MBEDTLS_MEMORY_DEBUG
    cmake -DCMAKE_BUILD_TYPE:String=Release .
    make

    msg "test: MBEDTLS_MEMORY_BUFFER_ALLOC_C and MBEDTLS_MEMORY_BACKTRACE"
    make test
}

component_test_memory_buffer_allocator () {
    msg "build: default config with memory buffer allocator"
    scripts/config.py set MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_PLATFORM_MEMORY
    cmake -DCMAKE_BUILD_TYPE:String=Release .
    make

    msg "test: MBEDTLS_MEMORY_BUFFER_ALLOC_C"
    make test

    msg "test: ssl-opt.sh, MBEDTLS_MEMORY_BUFFER_ALLOC_C"
    # MBEDTLS_MEMORY_BUFFER_ALLOC is slow. Skip tests that tend to time out.
    tests/ssl-opt.sh -e '^DTLS proxy'
}

component_test_no_max_fragment_length () {
    # Run max fragment length tests with MFL disabled
    msg "build: default config except MFL extension (ASan build)" # ~ 30s
    scripts/config.py unset MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: ssl-opt.sh, MFL-related tests"
    tests/ssl-opt.sh -f "Max fragment length"
}

component_test_asan_remove_peer_certificate () {
    msg "build: default config with MBEDTLS_SSL_KEEP_PEER_CERTIFICATE disabled (ASan build)"
    scripts/config.py unset MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE"
    make test

    msg "test: ssl-opt.sh, !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE"
    tests/ssl-opt.sh

    msg "test: compat.sh, !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE"
    tests/compat.sh

    msg "test: context-info.sh, !MBEDTLS_SSL_KEEP_PEER_CERTIFICATE"
    tests/context-info.sh
}

component_test_no_max_fragment_length_small_ssl_out_content_len () {
    msg "build: no MFL extension, small SSL_OUT_CONTENT_LEN (ASan build)"
    scripts/config.py unset MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
    scripts/config.py set MBEDTLS_SSL_IN_CONTENT_LEN 16384
    scripts/config.py set MBEDTLS_SSL_OUT_CONTENT_LEN 4096
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: MFL tests (disabled MFL extension case) & large packet tests"
    tests/ssl-opt.sh -f "Max fragment length\|Large buffer"

    msg "test: context-info.sh (disabled MFL extension case)"
    tests/context-info.sh
}

component_test_variable_ssl_in_out_buffer_len () {
    msg "build: MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH enabled (ASan build)"
    scripts/config.py set MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH enabled"
    make test

    msg "test: ssl-opt.sh, MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH enabled"
    tests/ssl-opt.sh

    msg "test: compat.sh, MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH enabled"
    tests/compat.sh
}

component_test_dtls_cid_legacy () {
    msg "build: MBEDTLS_SSL_DTLS_CONNECTION_ID (legacy) enabled (ASan build)"
    scripts/config.py set MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT 1

    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: MBEDTLS_SSL_DTLS_CONNECTION_ID (legacy)"
    make test

    msg "test: ssl-opt.sh, MBEDTLS_SSL_DTLS_CONNECTION_ID (legacy) enabled"
    tests/ssl-opt.sh

    msg "test: compat.sh, MBEDTLS_SSL_DTLS_CONNECTION_ID (legacy) enabled"
    tests/compat.sh
}

component_test_ssl_alloc_buffer_and_mfl () {
    msg "build: default config with memory buffer allocator and MFL extension"
    scripts/config.py set MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_PLATFORM_MEMORY
    scripts/config.py set MBEDTLS_MEMORY_DEBUG
    scripts/config.py set MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
    scripts/config.py set MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH
    cmake -DCMAKE_BUILD_TYPE:String=Release .
    make

    msg "test: MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH, MBEDTLS_MEMORY_BUFFER_ALLOC_C, MBEDTLS_MEMORY_DEBUG and MBEDTLS_SSL_MAX_FRAGMENT_LENGTH"
    make test

    msg "test: MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH, MBEDTLS_MEMORY_BUFFER_ALLOC_C, MBEDTLS_MEMORY_DEBUG and MBEDTLS_SSL_MAX_FRAGMENT_LENGTH"
    tests/ssl-opt.sh -f "Handshake memory usage"
}

component_test_when_no_ciphersuites_have_mac () {
    msg "build: when no ciphersuites have MAC"
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_NO_PADDING
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_PKCS7
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CMAC
    scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128

    scripts/config.py unset MBEDTLS_CIPHER_NULL_CIPHER
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CBC
    scripts/config.py unset MBEDTLS_CMAC_C

    make

    msg "test: !MBEDTLS_SSL_SOME_SUITES_USE_MAC"
    make test

    msg "test ssl-opt.sh: !MBEDTLS_SSL_SOME_SUITES_USE_MAC"
    tests/ssl-opt.sh -f 'Default\|EtM' -e 'without EtM'
}

component_test_no_date_time () {
    msg "build: default config without MBEDTLS_HAVE_TIME_DATE"
    scripts/config.py unset MBEDTLS_HAVE_TIME_DATE
    cmake -D CMAKE_BUILD_TYPE:String=Check .
    make

    msg "test: !MBEDTLS_HAVE_TIME_DATE - main suites"
    make test
}

component_test_platform_calloc_macro () {
    msg "build: MBEDTLS_PLATFORM_{CALLOC/FREE}_MACRO enabled (ASan build)"
    scripts/config.py set MBEDTLS_PLATFORM_MEMORY
    scripts/config.py set MBEDTLS_PLATFORM_CALLOC_MACRO calloc
    scripts/config.py set MBEDTLS_PLATFORM_FREE_MACRO   free
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: MBEDTLS_PLATFORM_{CALLOC/FREE}_MACRO enabled (ASan build)"
    make test
}

component_test_malloc_0_null () {
    msg "build: malloc(0) returns NULL (ASan+UBSan build)"
    scripts/config.py full
    make CC=$ASAN_CC CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"$PWD/tests/configs/user-config-malloc-0-null.h\"' $ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS"

    msg "test: malloc(0) returns NULL (ASan+UBSan build)"
    make test

    msg "selftest: malloc(0) returns NULL (ASan+UBSan build)"
    # Just the calloc selftest. "make test" ran the others as part of the
    # test suites.
    programs/test/selftest calloc

    msg "test ssl-opt.sh: malloc(0) returns NULL (ASan+UBSan build)"
    # Run a subset of the tests. The choice is a balance between coverage
    # and time (including time indirectly wasted due to flaky tests).
    # The current choice is to skip tests whose description includes
    # "proxy", which is an approximation of skipping tests that use the
    # UDP proxy, which tend to be slower and flakier.
    tests/ssl-opt.sh -e 'proxy'
}

support_test_aesni() {
    # Check that gcc targets x86_64 (we can build AESNI), and check for
    # AESNI support on the host (we can run AESNI).
    #
    # The name of this function is possibly slightly misleading, but needs to align
    # with the name of the corresponding test, component_test_aesni.
    #
    # In principle 32-bit x86 can support AESNI, but our implementation does not
    # support 32-bit x86, so we check for x86-64.
    # We can only grep /proc/cpuinfo on Linux, so this also checks for Linux
    (gcc -v 2>&1 | grep Target | grep -q x86_64) &&
        [[ "$HOSTTYPE" == "x86_64" && "$OSTYPE" == "linux-gnu" ]] &&
        (lscpu | grep -qw aes)
}

component_test_aesni () { # ~ 60s
    # This tests the two AESNI implementations (intrinsics and assembly), and also the plain C
    # fallback. It also tests the logic that is used to select which implementation(s) to build.
    #
    # This test does not require the host to have support for AESNI (if it doesn't, the run-time
    # AESNI detection will fallback to the plain C implementation, so the tests will instead
    # exercise the plain C impl).

    msg "build: default config with different AES implementations"
    scripts/config.py set MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    scripts/config.py set MBEDTLS_HAVE_ASM

    # test the intrinsics implementation
    msg "AES tests, test intrinsics"
    make clean
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -mpclmul -msse2 -maes'
    # check that we built intrinsics - this should be used by default when supported by the compiler
    ./programs/test/selftest aes | grep "AESNI code" | grep -q "intrinsics"

    # test the asm implementation
    msg "AES tests, test assembly"
    make clean
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -mno-pclmul -mno-sse2 -mno-aes'
    # check that we built assembly - this should be built if the compiler does not support intrinsics
    ./programs/test/selftest aes | grep "AESNI code" | grep -q "assembly"

    # test the plain C implementation
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    msg "AES tests, plain C"
    make clean
    make CC=gcc CFLAGS='-O2 -Werror'
    # check that there is no AESNI code present
    ./programs/test/selftest aes | not grep -q "AESNI code"
    not grep -q "AES note: using AESNI" ./programs/test/selftest
    grep -q "AES note: built-in implementation." ./programs/test/selftest

    # test the intrinsics implementation
    scripts/config.py set MBEDTLS_AESNI_C
    scripts/config.py set MBEDTLS_AES_USE_HARDWARE_ONLY
    msg "AES tests, test AESNI only"
    make clean
    make CC=gcc CFLAGS='-Werror -Wall -Wextra -mpclmul -msse2 -maes'
    ./programs/test/selftest aes | grep -q "AES note: using AESNI"
    ./programs/test/selftest aes | not grep -q "AES note: built-in implementation."
    grep -q "AES note: using AESNI" ./programs/test/selftest
    not grep -q "AES note: built-in implementation." ./programs/test/selftest
}

component_test_sha3_variations() {
    msg "sha3 loop unroll variations"

    # define minimal config sufficient to test SHA3
    cat > include/mbedtls/mbedtls_config.h << END
        #define MBEDTLS_SELF_TEST
        #define MBEDTLS_SHA3_C
END

    msg "all loops unrolled"
    make clean
    make -C tests test_suite_shax CFLAGS="-DMBEDTLS_SHA3_THETA_UNROLL=1 -DMBEDTLS_SHA3_PI_UNROLL=1 -DMBEDTLS_SHA3_CHI_UNROLL=1 -DMBEDTLS_SHA3_RHO_UNROLL=1"
    ./tests/test_suite_shax

    msg "all loops rolled up"
    make clean
    make -C tests test_suite_shax CFLAGS="-DMBEDTLS_SHA3_THETA_UNROLL=0 -DMBEDTLS_SHA3_PI_UNROLL=0 -DMBEDTLS_SHA3_CHI_UNROLL=0 -DMBEDTLS_SHA3_RHO_UNROLL=0"
    ./tests/test_suite_shax
}

support_test_aesni_m32() {
    support_test_m32_no_asm && (lscpu | grep -qw aes)
}

component_test_aesni_m32 () { # ~ 60s
    # This tests are duplicated from component_test_aesni for i386 target
    #
    # AESNI intrinsic code supports i386 and assembly code does not support it.

    msg "build: default config with different AES implementations"
    scripts/config.py set MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    scripts/config.py set MBEDTLS_HAVE_ASM

    # test the intrinsics implementation with gcc
    msg "AES tests, test intrinsics (gcc)"
    make clean
    make CC=gcc CFLAGS='-m32 -Werror -Wall -Wextra' LDFLAGS='-m32'
    # check that we built intrinsics - this should be used by default when supported by the compiler
    ./programs/test/selftest aes | grep "AESNI code" | grep -q "intrinsics"
    grep -q "AES note: using AESNI" ./programs/test/selftest
    grep -q "AES note: built-in implementation." ./programs/test/selftest
    grep -q mbedtls_aesni_has_support ./programs/test/selftest

    scripts/config.py set MBEDTLS_AESNI_C
    scripts/config.py set MBEDTLS_AES_USE_HARDWARE_ONLY
    msg "AES tests, test AESNI only"
    make clean
    make CC=gcc CFLAGS='-m32 -Werror -Wall -Wextra -mpclmul -msse2 -maes' LDFLAGS='-m32'
    ./programs/test/selftest aes | grep -q "AES note: using AESNI"
    ./programs/test/selftest aes | not grep -q "AES note: built-in implementation."
    grep -q "AES note: using AESNI" ./programs/test/selftest
    not grep -q "AES note: built-in implementation." ./programs/test/selftest
    not grep -q mbedtls_aesni_has_support ./programs/test/selftest
}

support_test_aesni_m32_clang() {
    # clang >= 4 is required to build with target attributes
    support_test_aesni_m32 && [[ $(clang_version) -ge 4 ]]
}

component_test_aesni_m32_clang() {

    scripts/config.py set MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    scripts/config.py set MBEDTLS_HAVE_ASM

    # test the intrinsics implementation with clang
    msg "AES tests, test intrinsics (clang)"
    make clean
    make CC=clang CFLAGS='-m32 -Werror -Wall -Wextra' LDFLAGS='-m32'
    # check that we built intrinsics - this should be used by default when supported by the compiler
    ./programs/test/selftest aes | grep "AESNI code" | grep -q "intrinsics"
    grep -q "AES note: using AESNI" ./programs/test/selftest
    grep -q "AES note: built-in implementation." ./programs/test/selftest
    grep -q mbedtls_aesni_has_support ./programs/test/selftest
}

# For timebeing, no aarch64 gcc available in CI and no arm64 CI node.
component_build_aes_aesce_armcc () {
    msg "Build: AESCE test on arm64 platform without plain C."
    scripts/config.py baremetal

    # armc[56] don't support SHA-512 intrinsics
    scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT

    # Stop armclang warning about feature detection for A64_CRYPTO.
    # With this enabled, the library does build correctly under armclang,
    # but in baremetal builds (as tested here), feature detection is
    # unavailable, and the user is notified via a #warning. So enabling
    # this feature would prevent us from building with -Werror on
    # armclang. Tracked in #7198.
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
    scripts/config.py set MBEDTLS_HAVE_ASM

    msg "AESCE, build with default configuration."
    scripts/config.py set MBEDTLS_AESCE_C
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    armc6_build_test "-O1 --target=aarch64-arm-none-eabi -march=armv8-a+crypto"

    msg "AESCE, build AESCE only"
    scripts/config.py set MBEDTLS_AESCE_C
    scripts/config.py set MBEDTLS_AES_USE_HARDWARE_ONLY
    armc6_build_test "-O1 --target=aarch64-arm-none-eabi -march=armv8-a+crypto"
}

support_build_aes_armce() {
    # clang >= 11 is required to build with AES extensions
    [[ $(clang_version) -ge 11 ]]
}

component_build_aes_armce () {
    # Test variations of AES with Armv8 crypto extensions
    scripts/config.py set MBEDTLS_AESCE_C
    scripts/config.py set MBEDTLS_AES_USE_HARDWARE_ONLY

    msg "MBEDTLS_AES_USE_HARDWARE_ONLY, clang, aarch64"
    make -B library/../${BUILTIN_SRC_PATH}/aesce.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a+crypto"

    msg "MBEDTLS_AES_USE_HARDWARE_ONLY, clang, arm"
    make -B library/../${BUILTIN_SRC_PATH}/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm"

    msg "MBEDTLS_AES_USE_HARDWARE_ONLY, clang, thumb"
    make -B library/../${BUILTIN_SRC_PATH}/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb"

    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY

    msg "no MBEDTLS_AES_USE_HARDWARE_ONLY, clang, aarch64"
    make -B library/../${BUILTIN_SRC_PATH}/aesce.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a+crypto"

    msg "no MBEDTLS_AES_USE_HARDWARE_ONLY, clang, arm"
    make -B library/../${BUILTIN_SRC_PATH}/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm"

    msg "no MBEDTLS_AES_USE_HARDWARE_ONLY, clang, thumb"
    make -B library/../${BUILTIN_SRC_PATH}/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb"

    # test for presence of AES instructions
    scripts/config.py set MBEDTLS_AES_USE_HARDWARE_ONLY
    msg "clang, test A32 crypto instructions built"
    make -B library/../${BUILTIN_SRC_PATH}/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm -S"
    grep -E 'aes[0-9a-z]+.[0-9]\s*[qv]' ${BUILTIN_SRC_PATH}/aesce.o
    msg "clang, test T32 crypto instructions built"
    make -B library/../${BUILTIN_SRC_PATH}/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb -S"
    grep -E 'aes[0-9a-z]+.[0-9]\s*[qv]' ${BUILTIN_SRC_PATH}/aesce.o
    msg "clang, test aarch64 crypto instructions built"
    make -B library/../${BUILTIN_SRC_PATH}/aesce.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a -S"
    grep -E 'aes[a-z]+\s*[qv]' ${BUILTIN_SRC_PATH}/aesce.o

    # test for absence of AES instructions
    scripts/config.py unset MBEDTLS_AES_USE_HARDWARE_ONLY
    scripts/config.py unset MBEDTLS_AESCE_C
    msg "clang, test A32 crypto instructions not built"
    make -B library/../${BUILTIN_SRC_PATH}/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm -S"
    not grep -E 'aes[0-9a-z]+.[0-9]\s*[qv]' ${BUILTIN_SRC_PATH}/aesce.o
    msg "clang, test T32 crypto instructions not built"
    make -B library/../${BUILTIN_SRC_PATH}/aesce.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb -S"
    not grep -E 'aes[0-9a-z]+.[0-9]\s*[qv]' ${BUILTIN_SRC_PATH}/aesce.o
    msg "clang, test aarch64 crypto instructions not built"
    make -B library/../${BUILTIN_SRC_PATH}/aesce.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a -S"
    not grep -E 'aes[a-z]+\s*[qv]' ${BUILTIN_SRC_PATH}/aesce.o
}

support_build_sha_armce() {
    # clang >= 4 is required to build with SHA extensions
    [[ $(clang_version) -ge 4 ]]
}

component_build_sha_armce () {
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT


    # Test variations of SHA256 Armv8 crypto extensions
    scripts/config.py set MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY
        msg "MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY clang, aarch64"
        make -B library/../${BUILTIN_SRC_PATH}/sha256.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a"
        msg "MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY clang, arm"
        make -B library/../${BUILTIN_SRC_PATH}/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm"
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY


    # test the deprecated form of the config option
    scripts/config.py set MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY
        msg "MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY clang, thumb"
        make -B library/../${BUILTIN_SRC_PATH}/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb"
    scripts/config.py unset MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY

    scripts/config.py set MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT
        msg "MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT clang, aarch64"
        make -B library/../${BUILTIN_SRC_PATH}/sha256.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a"
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT


    # test the deprecated form of the config option
    scripts/config.py set MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT
        msg "MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT clang, arm"
        make -B library/../${BUILTIN_SRC_PATH}/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm -std=c99"
        msg "MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT clang, thumb"
        make -B library/../${BUILTIN_SRC_PATH}/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb"
    scripts/config.py unset MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT


    # examine the disassembly for presence of SHA instructions
    for opt in MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT; do
        scripts/config.py set ${opt}
            msg "${opt} clang, test A32 crypto instructions built"
            make -B library/../${BUILTIN_SRC_PATH}/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm -S"
            grep -E 'sha256[a-z0-9]+.32\s+[qv]' ${BUILTIN_SRC_PATH}/sha256.o

            msg "${opt} clang, test T32 crypto instructions built"
            make -B library/../${BUILTIN_SRC_PATH}/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb -S"
            grep -E 'sha256[a-z0-9]+.32\s+[qv]' ${BUILTIN_SRC_PATH}/sha256.o

            msg "${opt} clang, test aarch64 crypto instructions built"
            make -B library/../${BUILTIN_SRC_PATH}/sha256.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a -S"
            grep -E 'sha256[a-z0-9]+\s+[qv]' ${BUILTIN_SRC_PATH}/sha256.o
        scripts/config.py unset ${opt}
    done


    # examine the disassembly for absence of SHA instructions
    msg "clang, test A32 crypto instructions not built"
    make -B library/../${BUILTIN_SRC_PATH}/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a72+crypto -marm -S"
    not grep -E 'sha256[a-z0-9]+.32\s+[qv]' ${BUILTIN_SRC_PATH}/sha256.o

    msg "clang, test T32 crypto instructions not built"
    make -B library/../${BUILTIN_SRC_PATH}/sha256.o CC=clang CFLAGS="--target=arm-linux-gnueabihf -mcpu=cortex-a32+crypto -mthumb -S"
    not grep -E 'sha256[a-z0-9]+.32\s+[qv]' ${BUILTIN_SRC_PATH}/sha256.o

    msg "clang, test aarch64 crypto instructions not built"
    make -B library/../${BUILTIN_SRC_PATH}/sha256.o CC=clang CFLAGS="--target=aarch64-linux-gnu -march=armv8-a -S"
    not grep -E 'sha256[a-z0-9]+\s+[qv]' ${BUILTIN_SRC_PATH}/sha256.o
}

support_build_aes_aesce_armcc () {
    support_build_armcc
}

component_test_aes_only_128_bit_keys () {
    msg "build: default config + AES_ONLY_128_BIT_KEY_LENGTH"
    scripts/config.py set MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH

    make CFLAGS='-O2 -Werror -Wall -Wextra'

    msg "test: default config + AES_ONLY_128_BIT_KEY_LENGTH"
    make test
}

component_test_no_ctr_drbg_aes_only_128_bit_keys () {
    msg "build: default config + AES_ONLY_128_BIT_KEY_LENGTH - CTR_DRBG_C"
    scripts/config.py set MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH
    scripts/config.py unset MBEDTLS_CTR_DRBG_C

    make CC=clang CFLAGS='-Werror -Wall -Wextra'

    msg "test: default config + AES_ONLY_128_BIT_KEY_LENGTH - CTR_DRBG_C"
    make test
}

component_test_aes_only_128_bit_keys_have_builtins () {
    msg "build: default config + AES_ONLY_128_BIT_KEY_LENGTH - AESNI_C - AESCE_C"
    scripts/config.py set MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C

    make CFLAGS='-O2 -Werror -Wall -Wextra'

    msg "test: default config + AES_ONLY_128_BIT_KEY_LENGTH - AESNI_C - AESCE_C"
    make test

    msg "selftest: default config + AES_ONLY_128_BIT_KEY_LENGTH - AESNI_C - AESCE_C"
    programs/test/selftest
}

component_test_gcm_largetable () {
    msg "build: default config + GCM_LARGE_TABLE - AESNI_C - AESCE_C"
    scripts/config.py set MBEDTLS_GCM_LARGE_TABLE
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C

    make CFLAGS='-O2 -Werror -Wall -Wextra'

    msg "test: default config - GCM_LARGE_TABLE - AESNI_C - AESCE_C"
    make test
}

component_test_aes_fewer_tables () {
    msg "build: default config with AES_FEWER_TABLES enabled"
    scripts/config.py set MBEDTLS_AES_FEWER_TABLES
    make CFLAGS='-O2 -Werror -Wall -Wextra'

    msg "test: AES_FEWER_TABLES"
    make test
}

component_test_aes_rom_tables () {
    msg "build: default config with AES_ROM_TABLES enabled"
    scripts/config.py set MBEDTLS_AES_ROM_TABLES
    make CFLAGS='-O2 -Werror -Wall -Wextra'

    msg "test: AES_ROM_TABLES"
    make test
}

component_test_aes_fewer_tables_and_rom_tables () {
    msg "build: default config with AES_ROM_TABLES and AES_FEWER_TABLES enabled"
    scripts/config.py set MBEDTLS_AES_FEWER_TABLES
    scripts/config.py set MBEDTLS_AES_ROM_TABLES
    make CFLAGS='-O2 -Werror -Wall -Wextra'

    msg "test: AES_FEWER_TABLES + AES_ROM_TABLES"
    make test
}

# helper for common_block_cipher_no_decrypt() which:
# - enable/disable the list of config options passed from -s/-u respectively.
# - build
# - test for tests_suite_xxx
# - selftest
#
# Usage: helper_block_cipher_no_decrypt_build_test
#        [-s set_opts] [-u unset_opts] [-c cflags] [-l ldflags] [option [...]]
# Options:  -s set_opts     the list of config options to enable
#           -u unset_opts   the list of config options to disable
#           -c cflags       the list of options passed to CFLAGS
#           -l ldflags      the list of options passed to LDFLAGS
helper_block_cipher_no_decrypt_build_test () {
    while [ $# -gt 0 ]; do
        case "$1" in
            -s)
                shift; local set_opts="$1";;
            -u)
                shift; local unset_opts="$1";;
            -c)
                shift; local cflags="-Werror -Wall -Wextra $1";;
            -l)
                shift; local ldflags="$1";;
        esac
        shift
    done
    set_opts="${set_opts:-}"
    unset_opts="${unset_opts:-}"
    cflags="${cflags:-}"
    ldflags="${ldflags:-}"

    [ -n "$set_opts" ] && echo "Enabling: $set_opts" && scripts/config.py set-all $set_opts
    [ -n "$unset_opts" ] && echo "Disabling: $unset_opts" && scripts/config.py unset-all $unset_opts

    msg "build: default config + BLOCK_CIPHER_NO_DECRYPT${set_opts:+ + $set_opts}${unset_opts:+ - $unset_opts} with $cflags${ldflags:+, $ldflags}"
    make clean
    make CFLAGS="-O2 $cflags" LDFLAGS="$ldflags"

    # Make sure we don't have mbedtls_xxx_setkey_dec in AES/ARIA/CAMELLIA
    not grep mbedtls_aes_setkey_dec ${BUILTIN_SRC_PATH}/aes.o
    not grep mbedtls_aria_setkey_dec ${BUILTIN_SRC_PATH}/aria.o
    not grep mbedtls_camellia_setkey_dec ${BUILTIN_SRC_PATH}/camellia.o
    # Make sure we don't have mbedtls_internal_aes_decrypt in AES
    not grep mbedtls_internal_aes_decrypt ${BUILTIN_SRC_PATH}/aes.o
    # Make sure we don't have mbedtls_aesni_inverse_key in AESNI
    not grep mbedtls_aesni_inverse_key ${BUILTIN_SRC_PATH}/aesni.o

    msg "test: default config + BLOCK_CIPHER_NO_DECRYPT${set_opts:+ + $set_opts}${unset_opts:+ - $unset_opts} with $cflags${ldflags:+, $ldflags}"
    make test

    msg "selftest: default config + BLOCK_CIPHER_NO_DECRYPT${set_opts:+ + $set_opts}${unset_opts:+ - $unset_opts} with $cflags${ldflags:+, $ldflags}"
    programs/test/selftest
}

# This is a common configuration function used in:
# - component_test_block_cipher_no_decrypt_aesni_legacy()
# - component_test_block_cipher_no_decrypt_aesni_use_psa()
# in order to test BLOCK_CIPHER_NO_DECRYPT with AESNI intrinsics,
# AESNI assembly and AES C implementation on x86_64 and with AESNI intrinsics
# on x86.
common_block_cipher_no_decrypt () {
    # test AESNI intrinsics
    helper_block_cipher_no_decrypt_build_test \
        -s "MBEDTLS_AESNI_C" \
        -c "-mpclmul -msse2 -maes"

    # test AESNI assembly
    helper_block_cipher_no_decrypt_build_test \
        -s "MBEDTLS_AESNI_C" \
        -c "-mno-pclmul -mno-sse2 -mno-aes"

    # test AES C implementation
    helper_block_cipher_no_decrypt_build_test \
        -u "MBEDTLS_AESNI_C"

    # test AESNI intrinsics for i386 target
    helper_block_cipher_no_decrypt_build_test \
        -s "MBEDTLS_AESNI_C" \
        -c "-m32 -mpclmul -msse2 -maes" \
        -l "-m32"
}

# This is a configuration function used in component_test_block_cipher_no_decrypt_xxx:
# usage: 0: no PSA crypto configuration
#        1: use PSA crypto configuration
config_block_cipher_no_decrypt () {
    use_psa=$1

    scripts/config.py set MBEDTLS_BLOCK_CIPHER_NO_DECRYPT
    scripts/config.py unset MBEDTLS_CIPHER_MODE_CBC
    scripts/config.py unset MBEDTLS_CIPHER_MODE_XTS
    scripts/config.py unset MBEDTLS_DES_C
    scripts/config.py unset MBEDTLS_NIST_KW_C

    if [ "$use_psa" -eq 1 ]; then
        # Enable support for cryptographic mechanisms through the PSA API.
        # Note: XTS, KW are not yet supported via the PSA API in Mbed TLS.
        scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
        scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_NO_PADDING
        scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_CBC_PKCS7
        scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_ALG_ECB_NO_PADDING
        scripts/config.py -f "$CRYPTO_CONFIG_H" unset PSA_WANT_KEY_TYPE_DES
    fi
}

component_test_block_cipher_no_decrypt_aesni () {
    # This consistently causes an llvm crash on clang 3.8, so use gcc
    export CC=gcc
    config_block_cipher_no_decrypt 0
    common_block_cipher_no_decrypt
}

component_test_block_cipher_no_decrypt_aesni_use_psa () {
    # This consistently causes an llvm crash on clang 3.8, so use gcc
    export CC=gcc
    config_block_cipher_no_decrypt 1
    common_block_cipher_no_decrypt
}

support_test_block_cipher_no_decrypt_aesce_armcc () {
    support_build_armcc
}

component_test_block_cipher_no_decrypt_aesce_armcc () {
    scripts/config.py baremetal

    # armc[56] don't support SHA-512 intrinsics
    scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT

    # Stop armclang warning about feature detection for A64_CRYPTO.
    # With this enabled, the library does build correctly under armclang,
    # but in baremetal builds (as tested here), feature detection is
    # unavailable, and the user is notified via a #warning. So enabling
    # this feature would prevent us from building with -Werror on
    # armclang. Tracked in #7198.
    scripts/config.py unset MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT
    scripts/config.py set MBEDTLS_HAVE_ASM

    config_block_cipher_no_decrypt 1

    # test AESCE baremetal build
    scripts/config.py set MBEDTLS_AESCE_C
    msg "build: default config + BLOCK_CIPHER_NO_DECRYPT with AESCE"
    armc6_build_test "-O1 --target=aarch64-arm-none-eabi -march=armv8-a+crypto -Werror -Wall -Wextra"

    # Make sure we don't have mbedtls_xxx_setkey_dec in AES/ARIA/CAMELLIA
    not grep mbedtls_aes_setkey_dec ${BUILTIN_SRC_PATH}/aes.o
    not grep mbedtls_aria_setkey_dec ${BUILTIN_SRC_PATH}/aria.o
    not grep mbedtls_camellia_setkey_dec ${BUILTIN_SRC_PATH}/camellia.o
    # Make sure we don't have mbedtls_internal_aes_decrypt in AES
    not grep mbedtls_internal_aes_decrypt ${BUILTIN_SRC_PATH}/aes.o
    # Make sure we don't have mbedtls_aesce_inverse_key and aesce_decrypt_block in AESCE
    not grep mbedtls_aesce_inverse_key ${BUILTIN_SRC_PATH}/aesce.o
    not grep aesce_decrypt_block ${BUILTIN_SRC_PATH}/aesce.o
}

component_test_ctr_drbg_aes_256_sha_256 () {
    msg "build: full + MBEDTLS_ENTROPY_FORCE_SHA256 (ASan build)"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_ENTROPY_FORCE_SHA256
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full + MBEDTLS_ENTROPY_FORCE_SHA256 (ASan build)"
    make test
}

component_test_ctr_drbg_aes_128_sha_512 () {
    msg "build: full + MBEDTLS_CTR_DRBG_USE_128_BIT_KEY (ASan build)"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_CTR_DRBG_USE_128_BIT_KEY
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full + MBEDTLS_CTR_DRBG_USE_128_BIT_KEY (ASan build)"
    make test
}

component_test_ctr_drbg_aes_128_sha_256 () {
    msg "build: full + MBEDTLS_CTR_DRBG_USE_128_BIT_KEY + MBEDTLS_ENTROPY_FORCE_SHA256 (ASan build)"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
    scripts/config.py set MBEDTLS_CTR_DRBG_USE_128_BIT_KEY
    scripts/config.py set MBEDTLS_ENTROPY_FORCE_SHA256
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: full + MBEDTLS_CTR_DRBG_USE_128_BIT_KEY + MBEDTLS_ENTROPY_FORCE_SHA256 (ASan build)"
    make test
}

component_test_se_default () {
    msg "build: default config + MBEDTLS_PSA_CRYPTO_SE_C"
    scripts/config.py set MBEDTLS_PSA_CRYPTO_SE_C
    make CC=clang CFLAGS="$ASAN_CFLAGS -Os" LDFLAGS="$ASAN_CFLAGS"

    msg "test: default config + MBEDTLS_PSA_CRYPTO_SE_C"
    make test
}

component_test_psa_crypto_drivers () {
    msg "build: full + test drivers dispatching to builtins"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_CONFIG
    loc_cflags="$ASAN_CFLAGS -DPSA_CRYPTO_DRIVER_TEST_ALL"
    loc_cflags="${loc_cflags} '-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/user-config-for-test.h\"'"
    loc_cflags="${loc_cflags} -I../tests/include -O2"

    make CC=$ASAN_CC CFLAGS="${loc_cflags}" LDFLAGS="$ASAN_CFLAGS"

    msg "test: full + test drivers dispatching to builtins"
    make test
}

component_test_make_shared () {
    msg "build/test: make shared" # ~ 40s
    make SHARED=1 all check
    ldd programs/util/strerror | grep libmbedcrypto
    programs/test/dlopen_demo.sh
}

component_test_cmake_shared () {
    msg "build/test: cmake shared" # ~ 2min
    cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .
    make
    ldd programs/util/strerror | grep libmbedcrypto
    make test
    programs/test/dlopen_demo.sh
}

test_build_opt () {
    info=$1 cc=$2; shift 2
    $cc --version
    for opt in "$@"; do
          msg "build/test: $cc $opt, $info" # ~ 30s
          make CC="$cc" CFLAGS="$opt -std=c99 -pedantic -Wall -Wextra -Werror"
          # We're confident enough in compilers to not run _all_ the tests,
          # but at least run the unit tests. In particular, runs with
          # optimizations use inline assembly whereas runs with -O0
          # skip inline assembly.
          make test # ~30s
          make clean
    done
}

# For FreeBSD we invoke the function by name so this condition is added
# to disable the existing test_clang_opt function for linux.
if [[ $(uname) != "Linux" ]]; then
    component_test_clang_opt () {
        scripts/config.py full
        test_build_opt 'full config' clang -O0 -Os -O2
    }
fi

component_test_clang_latest_opt () {
    scripts/config.py full
    test_build_opt 'full config' "$CLANG_LATEST" -O0 -Os -O2
}
support_test_clang_latest_opt () {
    type "$CLANG_LATEST" >/dev/null 2>/dev/null
}

component_test_clang_earliest_opt () {
    scripts/config.py full
    test_build_opt 'full config' "$CLANG_EARLIEST" -O0
}
support_test_clang_earliest_opt () {
    type "$CLANG_EARLIEST" >/dev/null 2>/dev/null
}

component_test_gcc_latest_opt () {
    scripts/config.py full
    test_build_opt 'full config' "$GCC_LATEST" -O0 -Os -O2
}
support_test_gcc_latest_opt () {
    type "$GCC_LATEST" >/dev/null 2>/dev/null
}

component_test_gcc_earliest_opt () {
    scripts/config.py full
    test_build_opt 'full config' "$GCC_EARLIEST" -O0
}
support_test_gcc_earliest_opt () {
    type "$GCC_EARLIEST" >/dev/null 2>/dev/null
}

component_build_mbedtls_config_file () {
    msg "build: make with MBEDTLS_CONFIG_FILE" # ~40s
    scripts/config.py -w full_config.h full
    echo '#error "MBEDTLS_CONFIG_FILE is not working"' >"$CONFIG_H"
    make CFLAGS="-I '$PWD' -DMBEDTLS_CONFIG_FILE='\"full_config.h\"'"
    # Make sure this feature is enabled. We'll disable it in the next phase.
    programs/test/query_compile_time_config MBEDTLS_NIST_KW_C
    make clean

    msg "build: make with MBEDTLS_CONFIG_FILE + MBEDTLS_USER_CONFIG_FILE"
    # In the user config, disable one feature (for simplicity, pick a feature
    # that nothing else depends on).
    echo '#undef MBEDTLS_NIST_KW_C' >user_config.h
    make CFLAGS="-I '$PWD' -DMBEDTLS_CONFIG_FILE='\"full_config.h\"' -DMBEDTLS_USER_CONFIG_FILE='\"user_config.h\"'"
    not programs/test/query_compile_time_config MBEDTLS_NIST_KW_C

    rm -f user_config.h full_config.h
}

component_build_psa_config_file () {
    msg "build: make with MBEDTLS_PSA_CRYPTO_CONFIG_FILE" # ~40s
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG
    cp "$CRYPTO_CONFIG_H" psa_test_config.h
    echo '#error "MBEDTLS_PSA_CRYPTO_CONFIG_FILE is not working"' >"$CRYPTO_CONFIG_H"
    make CFLAGS="-I '$PWD' -DMBEDTLS_PSA_CRYPTO_CONFIG_FILE='\"psa_test_config.h\"'"
    # Make sure this feature is enabled. We'll disable it in the next phase.
    programs/test/query_compile_time_config MBEDTLS_CMAC_C
    make clean

    msg "build: make with MBEDTLS_PSA_CRYPTO_CONFIG_FILE + MBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE" # ~40s
    # In the user config, disable one feature and its dependencies, which will
    # reflect on the mbedtls configuration so we can query it with
    # query_compile_time_config.
    echo '#undef PSA_WANT_ALG_CMAC' >psa_user_config.h
    echo '#undef PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128' >> psa_user_config.h
    scripts/config.py unset MBEDTLS_CMAC_C
    make CFLAGS="-I '$PWD' -DMBEDTLS_PSA_CRYPTO_CONFIG_FILE='\"psa_test_config.h\"' -DMBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE='\"psa_user_config.h\"'"
    not programs/test/query_compile_time_config MBEDTLS_CMAC_C

    rm -f psa_test_config.h psa_user_config.h
}

component_build_psa_alt_headers () {
    msg "build: make with PSA alt headers" # ~20s

    # Generate alternative versions of the substitutable headers with the
    # same content except different include guards.
    make -C tests include/alt-extra/psa/crypto_platform_alt.h include/alt-extra/psa/crypto_struct_alt.h

    # Build the library and some programs.
    # Don't build the fuzzers to avoid having to go through hoops to set
    # a correct include path for programs/fuzz/Makefile.
    make CFLAGS="-I ../tests/include/alt-extra -DMBEDTLS_PSA_CRYPTO_PLATFORM_FILE='\"psa/crypto_platform_alt.h\"' -DMBEDTLS_PSA_CRYPTO_STRUCT_FILE='\"psa/crypto_struct_alt.h\"'" lib
    make -C programs -o fuzz CFLAGS="-I ../tests/include/alt-extra -DMBEDTLS_PSA_CRYPTO_PLATFORM_FILE='\"psa/crypto_platform_alt.h\"' -DMBEDTLS_PSA_CRYPTO_STRUCT_FILE='\"psa/crypto_struct_alt.h\"'"

    # Check that we're getting the alternative include guards and not the
    # original include guards.
    programs/test/query_included_headers | grep -x PSA_CRYPTO_PLATFORM_ALT_H
    programs/test/query_included_headers | grep -x PSA_CRYPTO_STRUCT_ALT_H
    programs/test/query_included_headers | not grep -x PSA_CRYPTO_PLATFORM_H
    programs/test/query_included_headers | not grep -x PSA_CRYPTO_STRUCT_H
}

component_test_m32_no_asm () {
    # Build without assembly, so as to use portable C code (in a 32-bit
    # build) and not the i386-specific inline assembly.
    #
    # Note that we require gcc, because clang Asan builds fail to link for
    # this target (cannot find libclang_rt.lsan-i386.a - this is a known clang issue).
    msg "build: i386, make, gcc, no asm (ASan build)" # ~ 30s
    scripts/config.py full
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C # AESNI for 32-bit is tested in test_aesni_m32
    make CC=gcc CFLAGS="$ASAN_CFLAGS -m32" LDFLAGS="-m32 $ASAN_CFLAGS"

    msg "test: i386, make, gcc, no asm (ASan build)"
    make test
}
support_test_m32_no_asm () {
    case $(uname -m) in
        amd64|x86_64) true;;
        *) false;;
    esac
}

component_test_m32_o2 () {
    # Build with optimization, to use the i386 specific inline assembly
    # and go faster for tests.
    msg "build: i386, make, gcc -O2 (ASan build)" # ~ 30s
    scripts/config.py full
    scripts/config.py unset MBEDTLS_AESNI_C # AESNI for 32-bit is tested in test_aesni_m32
    make CC=gcc CFLAGS="$ASAN_CFLAGS -m32" LDFLAGS="-m32 $ASAN_CFLAGS"

    msg "test: i386, make, gcc -O2 (ASan build)"
    make test

    msg "test ssl-opt.sh, i386, make, gcc-O2"
    tests/ssl-opt.sh
}
support_test_m32_o2 () {
    support_test_m32_no_asm "$@"
}

component_test_m32_everest () {
    msg "build: i386, Everest ECDH context (ASan build)" # ~ 6 min
    scripts/config.py set MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED
    scripts/config.py unset MBEDTLS_AESNI_C # AESNI for 32-bit is tested in test_aesni_m32
    make CC=gcc CFLAGS="$ASAN_CFLAGS -m32" LDFLAGS="-m32 $ASAN_CFLAGS"

    msg "test: i386, Everest ECDH context - main suites (inc. selftests) (ASan build)" # ~ 50s
    make test

    msg "test: i386, Everest ECDH context - ECDH-related part of ssl-opt.sh (ASan build)" # ~ 5s
    tests/ssl-opt.sh -f ECDH

    msg "test: i386, Everest ECDH context - compat.sh with some ECDH ciphersuites (ASan build)" # ~ 3 min
    # Exclude some symmetric ciphers that are redundant here to gain time.
    tests/compat.sh -f ECDH -V NO -e 'ARIA\|CAMELLIA\|CHACHA'
}
support_test_m32_everest () {
    support_test_m32_no_asm "$@"
}

component_test_mx32 () {
    msg "build: 64-bit ILP32, make, gcc" # ~ 30s
    scripts/config.py full
    make CC=gcc CFLAGS='-O2 -Werror -Wall -Wextra -mx32' LDFLAGS='-mx32'

    msg "test: 64-bit ILP32, make, gcc"
    make test
}
support_test_mx32 () {
    case $(uname -m) in
        amd64|x86_64) true;;
        *) false;;
    esac
}

component_test_min_mpi_window_size () {
    msg "build: Default + MBEDTLS_MPI_WINDOW_SIZE=1 (ASan build)" # ~ 10s
    scripts/config.py set MBEDTLS_MPI_WINDOW_SIZE 1
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: MBEDTLS_MPI_WINDOW_SIZE=1 - main suites (inc. selftests) (ASan build)" # ~ 10s
    make test
}

component_test_have_int32 () {
    msg "build: gcc, force 32-bit bignum limbs"
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C
    make CC=gcc CFLAGS='-O2 -Werror -Wall -Wextra -DMBEDTLS_HAVE_INT32'

    msg "test: gcc, force 32-bit bignum limbs"
    make test
}

component_test_have_int64 () {
    msg "build: gcc, force 64-bit bignum limbs"
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C
    make CC=gcc CFLAGS='-O2 -Werror -Wall -Wextra -DMBEDTLS_HAVE_INT64'

    msg "test: gcc, force 64-bit bignum limbs"
    make test
}

component_test_have_int32_cmake_new_bignum () {
    msg "build: gcc, force 32-bit bignum limbs, new bignum interface, test hooks (ASan build)"
    scripts/config.py unset MBEDTLS_HAVE_ASM
    scripts/config.py unset MBEDTLS_AESNI_C
    scripts/config.py unset MBEDTLS_AESCE_C
    scripts/config.py set MBEDTLS_TEST_HOOKS
    scripts/config.py set MBEDTLS_ECP_WITH_MPI_UINT
    make CC=gcc CFLAGS="$ASAN_CFLAGS -Werror -Wall -Wextra -DMBEDTLS_HAVE_INT32" LDFLAGS="$ASAN_CFLAGS"

    msg "test: gcc, force 32-bit bignum limbs, new bignum interface, test hooks (ASan build)"
    make test
}

component_test_no_udbl_division () {
    msg "build: MBEDTLS_NO_UDBL_DIVISION native" # ~ 10s
    scripts/config.py full
    scripts/config.py set MBEDTLS_NO_UDBL_DIVISION
    make CFLAGS='-Werror -O1'

    msg "test: MBEDTLS_NO_UDBL_DIVISION native" # ~ 10s
    make test
}

component_test_no_64bit_multiplication () {
    msg "build: MBEDTLS_NO_64BIT_MULTIPLICATION native" # ~ 10s
    scripts/config.py full
    scripts/config.py set MBEDTLS_NO_64BIT_MULTIPLICATION
    make CFLAGS='-Werror -O1'

    msg "test: MBEDTLS_NO_64BIT_MULTIPLICATION native" # ~ 10s
    make test
}

component_test_no_strings () {
    msg "build: no strings" # ~10s
    scripts/config.py full
    # Disable options that activate a large amount of string constants.
    scripts/config.py unset MBEDTLS_DEBUG_C
    scripts/config.py unset MBEDTLS_ERROR_C
    scripts/config.py set MBEDTLS_ERROR_STRERROR_DUMMY
    scripts/config.py unset MBEDTLS_VERSION_FEATURES
    make CFLAGS='-Werror -Os'

    msg "test: no strings" # ~ 10s
    make test
}

component_test_no_x509_info () {
    msg "build: full + MBEDTLS_X509_REMOVE_INFO" # ~ 10s
    scripts/config.pl full
    scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # too slow for tests
    scripts/config.pl set MBEDTLS_X509_REMOVE_INFO
    make CFLAGS='-Werror -O2'

    msg "test: full + MBEDTLS_X509_REMOVE_INFO" # ~ 10s
    make test

    msg "test: ssl-opt.sh, full + MBEDTLS_X509_REMOVE_INFO" # ~ 1 min
    tests/ssl-opt.sh
}

component_build_arm_none_eabi_gcc () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc -O1, baremetal+debug" # ~ 10s
    scripts/config.py baremetal
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" LD="${ARM_NONE_EABI_GCC_PREFIX}ld" CFLAGS='-std=c99 -Werror -Wall -Wextra -O1' lib

    msg "size: ${ARM_NONE_EABI_GCC_PREFIX}gcc -O1, baremetal+debug"
    ${ARM_NONE_EABI_GCC_PREFIX}size -t library/*.o
    ${ARM_NONE_EABI_GCC_PREFIX}size -t ${PSA_CORE_PATH}/*.o
    ${ARM_NONE_EABI_GCC_PREFIX}size -t ${BUILTIN_SRC_PATH}/*.o
}

component_build_arm_linux_gnueabi_gcc_arm5vte () {
    msg "build: ${ARM_LINUX_GNUEABI_GCC_PREFIX}gcc -march=arm5vte, baremetal+debug" # ~ 10s
    scripts/config.py baremetal
    # Build for a target platform that's close to what Debian uses
    # for its "armel" distribution (https://wiki.debian.org/ArmEabiPort).
    # See https://github.com/Mbed-TLS/mbedtls/pull/2169 and comments.
    # Build everything including programs, see for example
    # https://github.com/Mbed-TLS/mbedtls/pull/3449#issuecomment-675313720
    make CC="${ARM_LINUX_GNUEABI_GCC_PREFIX}gcc" AR="${ARM_LINUX_GNUEABI_GCC_PREFIX}ar" CFLAGS='-Werror -Wall -Wextra -march=armv5te -O1' LDFLAGS='-march=armv5te'

    msg "size: ${ARM_LINUX_GNUEABI_GCC_PREFIX}gcc -march=armv5te -O1, baremetal+debug"
    ${ARM_LINUX_GNUEABI_GCC_PREFIX}size -t library/*.o
    ${ARM_LINUX_GNUEABI_GCC_PREFIX}size -t ${PSA_CORE_PATH}/*.o
    ${ARM_LINUX_GNUEABI_GCC_PREFIX}size -t ${BUILTIN_SRC_PATH}/*.o
}
support_build_arm_linux_gnueabi_gcc_arm5vte () {
    type ${ARM_LINUX_GNUEABI_GCC_PREFIX}gcc >/dev/null 2>&1
}

component_build_arm_none_eabi_gcc_arm5vte () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc -march=arm5vte, baremetal+debug" # ~ 10s
    scripts/config.py baremetal
    # This is an imperfect substitute for
    # component_build_arm_linux_gnueabi_gcc_arm5vte
    # in case the gcc-arm-linux-gnueabi toolchain is not available
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" CFLAGS='-std=c99 -Werror -Wall -Wextra -march=armv5te -O1' LDFLAGS='-march=armv5te' SHELL='sh -x' lib

    msg "size: ${ARM_NONE_EABI_GCC_PREFIX}gcc -march=armv5te -O1, baremetal+debug"
    ${ARM_NONE_EABI_GCC_PREFIX}size -t library/*.o
    ${ARM_NONE_EABI_GCC_PREFIX}size -t ${PSA_CORE_PATH}/*.o
    ${ARM_NONE_EABI_GCC_PREFIX}size -t ${BUILTIN_SRC_PATH}/*.o
}

component_build_arm_none_eabi_gcc_m0plus () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc -mthumb -mcpu=cortex-m0plus, baremetal_size" # ~ 10s
    scripts/config.py baremetal_size
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" LD="${ARM_NONE_EABI_GCC_PREFIX}ld" CFLAGS='-std=c99 -Werror -Wall -Wextra -mthumb -mcpu=cortex-m0plus -Os' lib

    msg "size: ${ARM_NONE_EABI_GCC_PREFIX}gcc -mthumb -mcpu=cortex-m0plus -Os, baremetal_size"
    ${ARM_NONE_EABI_GCC_PREFIX}size -t library/*.o
    ${ARM_NONE_EABI_GCC_PREFIX}size -t ${PSA_CORE_PATH}/*.o
    ${ARM_NONE_EABI_GCC_PREFIX}size -t ${BUILTIN_SRC_PATH}/*.o
    for lib in library/*.a; do
        echo "$lib:"
        ${ARM_NONE_EABI_GCC_PREFIX}size -t $lib | grep TOTALS
    done
}

component_build_arm_none_eabi_gcc_no_udbl_division () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc -DMBEDTLS_NO_UDBL_DIVISION, make" # ~ 10s
    scripts/config.py baremetal
    scripts/config.py set MBEDTLS_NO_UDBL_DIVISION
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" LD="${ARM_NONE_EABI_GCC_PREFIX}ld" CFLAGS='-std=c99 -Werror -Wall -Wextra' lib
    echo "Checking that software 64-bit division is not required"
    not grep __aeabi_uldiv library/*.o
    not grep __aeabi_uldiv ${PSA_CORE_PATH}/*.o
    not grep __aeabi_uldiv ${BUILTIN_SRC_PATH}/*.o
}

component_build_arm_none_eabi_gcc_no_64bit_multiplication () {
    msg "build: ${ARM_NONE_EABI_GCC_PREFIX}gcc MBEDTLS_NO_64BIT_MULTIPLICATION, make" # ~ 10s
    scripts/config.py baremetal
    scripts/config.py set MBEDTLS_NO_64BIT_MULTIPLICATION
    make CC="${ARM_NONE_EABI_GCC_PREFIX}gcc" AR="${ARM_NONE_EABI_GCC_PREFIX}ar" LD="${ARM_NONE_EABI_GCC_PREFIX}ld" CFLAGS='-std=c99 -Werror -O1 -march=armv6-m -mthumb' lib
    echo "Checking that software 64-bit multiplication is not required"
    not grep __aeabi_lmul library/*.o
    not grep __aeabi_lmul ${PSA_CORE_PATH}/*.o
    not grep __aeabi_lmul ${BUILTIN_SRC_PATH}/*.o
}

component_build_arm_clang_thumb () {
    # ~ 30s

    scripts/config.py baremetal

    msg "build: clang thumb 2, make"
    make clean
    make CC="clang" CFLAGS='-std=c99 -Werror -Os --target=arm-linux-gnueabihf -march=armv7-m -mthumb' lib

    # Some Thumb 1 asm is sensitive to optimisation level, so test both -O0 and -Os
    msg "build: clang thumb 1 -O0, make"
    make clean
    make CC="clang" CFLAGS='-std=c99 -Werror -O0 --target=arm-linux-gnueabihf -mcpu=arm1136j-s -mthumb' lib

    msg "build: clang thumb 1 -Os, make"
    make clean
    make CC="clang" CFLAGS='-std=c99 -Werror -Os --target=arm-linux-gnueabihf -mcpu=arm1136j-s -mthumb' lib
}

component_build_armcc () {
    msg "build: ARM Compiler 5"
    scripts/config.py baremetal
    # armc[56] don't support SHA-512 intrinsics
    scripts/config.py unset MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT

    # older versions of armcc/armclang don't support AESCE_C on 32-bit Arm
    scripts/config.py unset MBEDTLS_AESCE_C

    # Stop armclang warning about feature detection for A64_CRYPTO.
    # With this enabled, the library does build correctly under armclang,
    # but in baremetal builds (as tested here), feature detection is
    # unavailable, and the user is notified via a #warning. So enabling
    # this feature would prevent us from building with -Werror on
    # armclang. Tracked in #7198.
    scripts/config.py unset MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT

    scripts/config.py set MBEDTLS_HAVE_ASM

    make CC="$ARMC5_CC" AR="$ARMC5_AR" WARNING_CFLAGS='--strict --c99' lib

    msg "size: ARM Compiler 5"
    "$ARMC5_FROMELF" -z library/*.o
    "$ARMC5_FROMELF" -z ${PSA_CORE_PATH}/*.o
    "$ARMC5_FROMELF" -z ${BUILTIN_SRC_PATH}/*.o

    # Compile mostly with -O1 since some Arm inline assembly is disabled for -O0.

    # ARM Compiler 6 - Target ARMv7-A
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv7-a"

    # ARM Compiler 6 - Target ARMv7-M
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv7-m"

    # ARM Compiler 6 - Target ARMv7-M+DSP
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv7-m+dsp"

    # ARM Compiler 6 - Target ARMv8-A - AArch32
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv8.2-a"

    # ARM Compiler 6 - Target ARMv8-M
    armc6_build_test "-O1 --target=arm-arm-none-eabi -march=armv8-m.main"

    # ARM Compiler 6 - Target Cortex-M0 - no optimisation
    armc6_build_test "-O0 --target=arm-arm-none-eabi -mcpu=cortex-m0"

    # ARM Compiler 6 - Target Cortex-M0
    armc6_build_test "-Os --target=arm-arm-none-eabi -mcpu=cortex-m0"

    # ARM Compiler 6 - Target ARMv8.2-A - AArch64
    #
    # Re-enable MBEDTLS_AESCE_C as this should be supported by the version of armclang
    # that we have in our CI
    scripts/config.py set MBEDTLS_AESCE_C
    armc6_build_test "-O1 --target=aarch64-arm-none-eabi -march=armv8.2-a+crypto"
}

support_build_armcc () {
    armc5_cc="$ARMC5_BIN_DIR/armcc"
    armc6_cc="$ARMC6_BIN_DIR/armclang"
    (check_tools "$armc5_cc" "$armc6_cc" > /dev/null 2>&1)
}

component_test_tls12_only () {
    msg "build: default config without MBEDTLS_SSL_PROTO_TLS1_3, cmake, gcc, ASan"
    scripts/config.py unset MBEDTLS_SSL_PROTO_TLS1_3
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make

    msg "test: main suites (inc. selftests) (ASan build)"
    make test

    msg "test: ssl-opt.sh (ASan build)"
    tests/ssl-opt.sh

    msg "test: compat.sh (ASan build)"
    tests/compat.sh
}

component_test_tls13_only () {
    msg "build: default config without MBEDTLS_SSL_PROTO_TLS1_2"
    scripts/config.py set MBEDTLS_SSL_EARLY_DATA
    scripts/config.py set MBEDTLS_SSL_RECORD_SIZE_LIMIT
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test: TLS 1.3 only, all key exchange modes enabled"
    make test

    msg "ssl-opt.sh: TLS 1.3 only, all key exchange modes enabled"
    tests/ssl-opt.sh
}

component_test_tls13_only_psk () {
    msg "build: TLS 1.3 only from default, only PSK key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_ECDH_C
    scripts/config.py unset MBEDTLS_DHM_C
    scripts/config.py unset MBEDTLS_X509_CRT_PARSE_C
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT
    scripts/config.py unset MBEDTLS_SSL_SERVER_NAME_INDICATION
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_PKCS1_V21
    scripts/config.py unset MBEDTLS_PKCS7_C
    scripts/config.py set   MBEDTLS_SSL_EARLY_DATA
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, only PSK key exchange mode enabled"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, only PSK key exchange mode enabled"
    tests/ssl-opt.sh
}

component_test_tls13_only_ephemeral () {
    msg "build: TLS 1.3 only from default, only ephemeral key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_SSL_EARLY_DATA
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, only ephemeral key exchange mode"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, only ephemeral key exchange mode"
    tests/ssl-opt.sh
}

component_test_tls13_only_ephemeral_ffdh () {
    msg "build: TLS 1.3 only from default, only ephemeral ffdh key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_SSL_EARLY_DATA
    scripts/config.py unset MBEDTLS_ECDH_C

    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, only ephemeral ffdh key exchange mode"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, only ephemeral ffdh key exchange mode"
    tests/ssl-opt.sh
}

component_test_tls13_only_psk_ephemeral () {
    msg "build: TLS 1.3 only from default, only PSK ephemeral key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_X509_CRT_PARSE_C
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT
    scripts/config.py unset MBEDTLS_SSL_SERVER_NAME_INDICATION
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_PKCS1_V21
    scripts/config.py unset MBEDTLS_PKCS7_C
    scripts/config.py set   MBEDTLS_SSL_EARLY_DATA
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, only PSK ephemeral key exchange mode"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, only PSK ephemeral key exchange mode"
    tests/ssl-opt.sh
}

component_test_tls13_only_psk_ephemeral_ffdh () {
    msg "build: TLS 1.3 only from default, only PSK ephemeral ffdh key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_X509_CRT_PARSE_C
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT
    scripts/config.py unset MBEDTLS_SSL_SERVER_NAME_INDICATION
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_PKCS1_V21
    scripts/config.py unset MBEDTLS_PKCS7_C
    scripts/config.py set   MBEDTLS_SSL_EARLY_DATA
    scripts/config.py unset MBEDTLS_ECDH_C
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, only PSK ephemeral ffdh key exchange mode"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, only PSK ephemeral ffdh key exchange mode"
    tests/ssl-opt.sh
}

component_test_tls13_only_psk_all () {
    msg "build: TLS 1.3 only from default, without ephemeral key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
    scripts/config.py unset MBEDTLS_X509_CRT_PARSE_C
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT
    scripts/config.py unset MBEDTLS_SSL_SERVER_NAME_INDICATION
    scripts/config.py unset MBEDTLS_ECDSA_C
    scripts/config.py unset MBEDTLS_PKCS1_V21
    scripts/config.py unset MBEDTLS_PKCS7_C
    scripts/config.py set   MBEDTLS_SSL_EARLY_DATA
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, PSK and PSK ephemeral key exchange modes"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, PSK and PSK ephemeral key exchange modes"
    tests/ssl-opt.sh
}

component_test_tls13_only_ephemeral_all () {
    msg "build: TLS 1.3 only from default, without PSK key exchange mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
    scripts/config.py set   MBEDTLS_SSL_EARLY_DATA
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/tls13-only.h\"'"

    msg "test_suite_ssl: TLS 1.3 only, ephemeral and PSK ephemeral key exchange modes"
    cd tests; ./test_suite_ssl; cd ..

    msg "ssl-opt.sh: TLS 1.3 only, ephemeral and PSK ephemeral key exchange modes"
    tests/ssl-opt.sh
}

component_test_tls13_no_padding () {
    msg "build: default config plus early data minus padding"
    scripts/config.py set MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY 1
    scripts/config.py set MBEDTLS_SSL_EARLY_DATA
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make
    msg "test: default config plus early data minus padding"
    make test
    msg "ssl-opt.sh (TLS 1.3 no padding)"
    tests/ssl-opt.sh
}

component_test_tls13_no_compatibility_mode () {
    msg "build: default config plus early data minus middlebox compatibility mode"
    scripts/config.py unset MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
    scripts/config.py set   MBEDTLS_SSL_EARLY_DATA
    CC=$ASAN_CC cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make
    msg "test: default config plus early data minus middlebox compatibility mode"
    make test
    msg "ssl-opt.sh (TLS 1.3 no compatibility mode)"
    tests/ssl-opt.sh
}

component_test_full_minus_session_tickets() {
    msg "build: full config without session tickets"
    scripts/config.py full
    scripts/config.py unset MBEDTLS_SSL_SESSION_TICKETS
    scripts/config.py unset MBEDTLS_SSL_EARLY_DATA
    CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
    make
    msg "test: full config without session tickets"
    make test
    msg "ssl-opt.sh (full config without session tickets)"
    tests/ssl-opt.sh
}

component_build_mingw () {
    msg "build: Windows cross build - mingw64, make (Link Library)" # ~ 30s
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror -Wall -Wextra -maes -msse2 -mpclmul' WINDOWS_BUILD=1 lib programs

    # note Make tests only builds the tests, but doesn't run them
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror -maes -msse2 -mpclmul' WINDOWS_BUILD=1 tests
    make WINDOWS_BUILD=1 clean

    msg "build: Windows cross build - mingw64, make (DLL)" # ~ 30s
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror -Wall -Wextra -maes -msse2 -mpclmul' WINDOWS_BUILD=1 SHARED=1 lib programs
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror -Wall -Wextra -maes -msse2 -mpclmul' WINDOWS_BUILD=1 SHARED=1 tests
    make WINDOWS_BUILD=1 clean

    msg "build: Windows cross build - mingw64, make (Library only, default config without MBEDTLS_AESNI_C)" # ~ 30s
    ./scripts/config.py unset MBEDTLS_AESNI_C #
    make CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS='-Werror -Wall -Wextra' WINDOWS_BUILD=1 lib
    make WINDOWS_BUILD=1 clean
}
support_build_mingw() {
    case $(i686-w64-mingw32-gcc -dumpversion 2>/dev/null) in
        [0-5]*|"") false;;
        *) true;;
    esac
}

component_test_memsan () {
    msg "build: MSan (clang)" # ~ 1 min 20s
    scripts/config.py unset MBEDTLS_AESNI_C # memsan doesn't grok asm
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=MemSan .
    make

    msg "test: main suites (MSan)" # ~ 10s
    make test

    msg "test: metatests (MSan)"
    tests/scripts/run-metatests.sh any msan

    msg "program demos (MSan)" # ~20s
    tests/scripts/run_demos.py

    msg "test: ssl-opt.sh (MSan)" # ~ 1 min
    tests/ssl-opt.sh

    # Optional part(s)

    if [ "$MEMORY" -gt 0 ]; then
        msg "test: compat.sh (MSan)" # ~ 6 min 20s
        tests/compat.sh
    fi
}

component_release_test_valgrind () {
    msg "build: Release (clang)"
    # default config, in particular without MBEDTLS_USE_PSA_CRYPTO
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=Release .
    make

    msg "test: main suites, Valgrind (default config)"
    make memcheck

    # Optional parts (slow; currently broken on OS X because programs don't
    # seem to receive signals under valgrind on OS X).
    # These optional parts don't run on the CI.
    if [ "$MEMORY" -gt 0 ]; then
        msg "test: ssl-opt.sh --memcheck (default config)"
        tests/ssl-opt.sh --memcheck
    fi

    if [ "$MEMORY" -gt 1 ]; then
        msg "test: compat.sh --memcheck (default config)"
        tests/compat.sh --memcheck
    fi

    if [ "$MEMORY" -gt 0 ]; then
        msg "test: context-info.sh --memcheck (default config)"
        tests/context-info.sh --memcheck
    fi
}

component_release_test_valgrind_psa () {
    msg "build: Release, full (clang)"
    # full config, in particular with MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py full
    CC=clang cmake -D CMAKE_BUILD_TYPE:String=Release .
    make

    msg "test: main suites, Valgrind (full config)"
    make memcheck
}

support_test_cmake_out_of_source () {
    distrib_id=""
    distrib_ver=""
    distrib_ver_minor=""
    distrib_ver_major=""

    # Attempt to parse lsb-release to find out distribution and version. If not
    # found this should fail safe (test is supported).
    if [[ -f /etc/lsb-release ]]; then

        while read -r lsb_line; do
            case "$lsb_line" in
                "DISTRIB_ID"*) distrib_id=${lsb_line/#DISTRIB_ID=};;
                "DISTRIB_RELEASE"*) distrib_ver=${lsb_line/#DISTRIB_RELEASE=};;
            esac
        done < /etc/lsb-release

        distrib_ver_major="${distrib_ver%%.*}"
        distrib_ver="${distrib_ver#*.}"
        distrib_ver_minor="${distrib_ver%%.*}"
    fi

    # Running the out of source CMake test on Ubuntu 16.04 using more than one
    # processor (as the CI does) can create a race condition whereby the build
    # fails to see a generated file, despite that file actually having been
    # generated. This problem appears to go away with 18.04 or newer, so make
    # the out of source tests unsupported on Ubuntu 16.04.
    [ "$distrib_id" != "Ubuntu" ] || [ "$distrib_ver_major" -gt 16 ]
}

component_test_cmake_out_of_source () {
    # Remove existing generated files so that we use the ones cmake
    # generates
    make neat

    msg "build: cmake 'out-of-source' build"
    MBEDTLS_ROOT_DIR="$PWD"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"
    # Note: Explicitly generate files as these are turned off in releases
    cmake -D CMAKE_BUILD_TYPE:String=Check -D GEN_FILES=ON "$MBEDTLS_ROOT_DIR"
    make

    msg "test: cmake 'out-of-source' build"
    make test
    # Check that ssl-opt.sh can find the test programs.
    # Also ensure that there are no error messages such as
    # "No such file or directory", which would indicate that some required
    # file is missing (ssl-opt.sh tolerates the absence of some files so
    # may exit with status 0 but emit errors).
    ./tests/ssl-opt.sh -f 'Default' >ssl-opt.out 2>ssl-opt.err
    grep PASS ssl-opt.out
    cat ssl-opt.err >&2
    # If ssl-opt.err is non-empty, record an error and keep going.
    [ ! -s ssl-opt.err ]
    rm ssl-opt.out ssl-opt.err
    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"
}

component_test_cmake_as_subdirectory () {
    # Remove existing generated files so that we use the ones CMake
    # generates
    make neat

    msg "build: cmake 'as-subdirectory' build"
    cd programs/test/cmake_subproject
    # Note: Explicitly generate files as these are turned off in releases
    cmake -D GEN_FILES=ON .
    make
    ./cmake_subproject
}
support_test_cmake_as_subdirectory () {
    support_test_cmake_out_of_source
}

component_test_cmake_as_package () {
    # Remove existing generated files so that we use the ones CMake
    # generates
    make neat

    msg "build: cmake 'as-package' build"
    cd programs/test/cmake_package
    cmake .
    make
    ./cmake_package
}
support_test_cmake_as_package () {
    support_test_cmake_out_of_source
}

component_test_cmake_as_package_install () {
    # Remove existing generated files so that we use the ones CMake
    # generates
    make neat

    msg "build: cmake 'as-installed-package' build"
    cd programs/test/cmake_package_install
    cmake .
    make
    ./cmake_package_install
}
support_test_cmake_as_package_install () {
    support_test_cmake_out_of_source
}

component_build_cmake_custom_config_file () {
    # Make a copy of config file to use for the in-tree test
    cp "$CONFIG_H" include/mbedtls_config_in_tree_copy.h

    MBEDTLS_ROOT_DIR="$PWD"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"

    # Build once to get the generated files (which need an intact config file)
    cmake "$MBEDTLS_ROOT_DIR"
    make

    msg "build: cmake with -DMBEDTLS_CONFIG_FILE"
    scripts/config.py -w full_config.h full
    echo '#error "cmake -DMBEDTLS_CONFIG_FILE is not working."' > "$MBEDTLS_ROOT_DIR/$CONFIG_H"
    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h "$MBEDTLS_ROOT_DIR"
    make

    msg "build: cmake with -DMBEDTLS_CONFIG_FILE + -DMBEDTLS_USER_CONFIG_FILE"
    # In the user config, disable one feature (for simplicity, pick a feature
    # that nothing else depends on).
    echo '#undef MBEDTLS_NIST_KW_C' >user_config.h

    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h -DMBEDTLS_USER_CONFIG_FILE=user_config.h "$MBEDTLS_ROOT_DIR"
    make
    not programs/test/query_compile_time_config MBEDTLS_NIST_KW_C

    rm -f user_config.h full_config.h

    cd "$MBEDTLS_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"

    # Now repeat the test for an in-tree build:

    # Restore config for the in-tree test
    mv include/mbedtls_config_in_tree_copy.h "$CONFIG_H"

    # Build once to get the generated files (which need an intact config)
    cmake .
    make

    msg "build: cmake (in-tree) with -DMBEDTLS_CONFIG_FILE"
    scripts/config.py -w full_config.h full
    echo '#error "cmake -DMBEDTLS_CONFIG_FILE is not working."' > "$MBEDTLS_ROOT_DIR/$CONFIG_H"
    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h .
    make

    msg "build: cmake (in-tree) with -DMBEDTLS_CONFIG_FILE + -DMBEDTLS_USER_CONFIG_FILE"
    # In the user config, disable one feature (for simplicity, pick a feature
    # that nothing else depends on).
    echo '#undef MBEDTLS_NIST_KW_C' >user_config.h

    cmake -DGEN_FILES=OFF -DMBEDTLS_CONFIG_FILE=full_config.h -DMBEDTLS_USER_CONFIG_FILE=user_config.h .
    make
    not programs/test/query_compile_time_config MBEDTLS_NIST_KW_C

    rm -f user_config.h full_config.h
}
support_build_cmake_custom_config_file () {
    support_test_cmake_out_of_source
}

component_build_cmake_programs_no_testing () {
    # Verify that the type of builds performed by oss-fuzz don't get accidentally broken
    msg "build: cmake with -DENABLE_PROGRAMS=ON and -DENABLE_TESTING=OFF"
    cmake -DENABLE_PROGRAMS=ON -DENABLE_TESTING=OFF .
    make
}
support_build_cmake_programs_no_testing () {
    support_test_cmake_out_of_source
}

component_build_zeroize_checks () {
    msg "build: check for obviously wrong calls to mbedtls_platform_zeroize()"

    scripts/config.py full

    # Only compile - we're looking for sizeof-pointer-memaccess warnings
    make CFLAGS="'-DMBEDTLS_USER_CONFIG_FILE=\"../tests/configs/user-config-zeroize-memset.h\"' -DMBEDTLS_TEST_DEFINES_ZEROIZE -Werror -Wsizeof-pointer-memaccess"
}


component_test_zeroize () {
    # Test that the function mbedtls_platform_zeroize() is not optimized away by
    # different combinations of compilers and optimization flags by using an
    # auxiliary GDB script. Unfortunately, GDB does not return error values to the
    # system in all cases that the script fails, so we must manually search the
    # output to check whether the pass string is present and no failure strings
    # were printed.

    # Don't try to disable ASLR. We don't care about ASLR here. We do care
    # about a spurious message if Gdb tries and fails, so suppress that.
    gdb_disable_aslr=
    if [ -z "$(gdb -batch -nw -ex 'set disable-randomization off' 2>&1)" ]; then
        gdb_disable_aslr='set disable-randomization off'
    fi

    for optimization_flag in -O2 -O3 -Ofast -Os; do
        for compiler in clang gcc; do
            msg "test: $compiler $optimization_flag, mbedtls_platform_zeroize()"
            make programs CC="$compiler" DEBUG=1 CFLAGS="$optimization_flag"
            gdb -ex "$gdb_disable_aslr" -x tests/scripts/test_zeroize.gdb -nw -batch -nx 2>&1 | tee test_zeroize.log
            grep "The buffer was correctly zeroized" test_zeroize.log
            not grep -i "error" test_zeroize.log
            rm -f test_zeroize.log
            make clean
        done
    done
}

component_test_psa_compliance () {
    # The arch tests build with gcc, so require use of gcc here to link properly
    msg "build: make, default config (out-of-box), libmbedcrypto.a only"
    CC=gcc make -C library libmbedcrypto.a

    msg "unit test: test_psa_compliance.py"
    CC=gcc ./tests/scripts/test_psa_compliance.py
}

support_test_psa_compliance () {
    # psa-compliance-tests only supports CMake >= 3.10.0
    ver="$(cmake --version)"
    ver="${ver#cmake version }"
    ver_major="${ver%%.*}"

    ver="${ver#*.}"
    ver_minor="${ver%%.*}"

    [ "$ver_major" -eq 3 ] && [ "$ver_minor" -ge 10 ]
}

component_check_code_style () {
    msg "Check C code style"
    ./scripts/code_style.py
}

support_check_code_style() {
    case $(uncrustify --version) in
        *0.75.1*) true;;
        *) false;;
    esac
}

component_check_python_files () {
    msg "Lint: Python scripts"
    tests/scripts/check-python-files.sh
}

component_check_test_helpers () {
    msg "unit test: generate_test_code.py"
    # unittest writes out mundane stuff like number or tests run on stderr.
    # Our convention is to reserve stderr for actual errors, and write
    # harmless info on stdout so it can be suppress with --quiet.
    ./framework/scripts/test_generate_test_code.py 2>&1

    msg "unit test: translate_ciphers.py"
    python3 -m unittest tests/scripts/translate_ciphers.py 2>&1
}

component_test_psasim() {
    msg "build server library and application"
    scripts/config.py crypto
    helper_psasim_config server
    helper_psasim_build server

    helper_psasim_cleanup_before_client

    msg "build library for client"
    helper_psasim_config client
    helper_psasim_build client

    msg "build basic psasim client"
    make -C tests/psa-client-server/psasim CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS" test/psa_client_base
    msg "test basic psasim client"
    tests/psa-client-server/psasim/test/run_test.sh psa_client_base

    msg "build full psasim client"
    make -C tests/psa-client-server/psasim CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS" test/psa_client_full
    msg "test full psasim client"
    tests/psa-client-server/psasim/test/run_test.sh psa_client_full

    make -C tests/psa-client-server/psasim clean
}

component_test_suite_with_psasim()
{
    msg "build server library and application"
    helper_psasim_config server
    # Modify server's library configuration here (if needed)
    helper_psasim_build server

    helper_psasim_cleanup_before_client

    msg "build client library"
    helper_psasim_config client
    # PAKE functions are still unsupported from PSASIM
    scripts/config.py -f $CRYPTO_CONFIG_H unset PSA_WANT_ALG_JPAKE
    scripts/config.py unset MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED
    helper_psasim_build client

    msg "build test suites"
    make PSASIM=1 CFLAGS="$ASAN_CFLAGS" LDFLAGS="$ASAN_CFLAGS" tests

    helper_psasim_server start

    # psasim takes an extremely long execution time on some test suites so we
    # exclude them from the list.
    SKIP_TEST_SUITES="constant_time_hmac,lmots,lms"
    export SKIP_TEST_SUITES

    msg "run test suites"
    make PSASIM=1 test

    helper_psasim_server kill
}

################################################################
#### Termination
################################################################

post_report () {
    msg "Done, cleaning up"
    final_cleanup

    final_report
}



################################################################
#### Run all the things
################################################################

# Function invoked by --error-test to test error reporting.
pseudo_component_error_test () {
    msg "Testing error reporting $error_test_i"
    if [ $KEEP_GOING -ne 0 ]; then
        echo "Expect three failing commands."
    fi
    # If the component doesn't run in a subshell, changing error_test_i to an
    # invalid integer will cause an error in the loop that runs this function.
    error_test_i=this_should_not_be_used_since_the_component_runs_in_a_subshell
    # Expected error: 'grep non_existent /dev/null -> 1'
    grep non_existent /dev/null
    # Expected error: '! grep -q . tests/scripts/all.sh -> 1'
    not grep -q . "$0"
    # Expected error: 'make unknown_target -> 2'
    make unknown_target
    false "this should not be executed"
}

# Run one component and clean up afterwards.
run_component () {
    current_component="$1"
    export MBEDTLS_TEST_CONFIGURATION="$current_component"

    # Unconditionally create a seedfile that's sufficiently long.
    # Do this before each component, because a previous component may
    # have messed it up or shortened it.
    local dd_cmd
    dd_cmd=(dd if=/dev/urandom of=./tests/seedfile bs=64 count=1)
    case $OSTYPE in
        linux*|freebsd*|openbsd*) dd_cmd+=(status=none)
    esac
    "${dd_cmd[@]}"

    # Run the component in a subshell, with error trapping and output
    # redirection set up based on the relevant options.
    if [ $KEEP_GOING -eq 1 ]; then
        # We want to keep running if the subshell fails, so 'set -e' must
        # be off when the subshell runs.
        set +e
    fi
    (
        if [ $QUIET -eq 1 ]; then
            # msg() will be silenced, so just print the component name here.
            echo "${current_component#component_}"
            exec >/dev/null
        fi
        if [ $KEEP_GOING -eq 1 ]; then
            # Keep "set -e" off, and run an ERR trap instead to record failures.
            set -E
            trap err_trap ERR
        fi
        # The next line is what runs the component
        "$@"
        if [ $KEEP_GOING -eq 1 ]; then
            trap - ERR
            exit $last_failure_status
        fi
    )
    component_status=$?
    if [ $KEEP_GOING -eq 1 ]; then
        set -e
        if [ $component_status -ne 0 ]; then
            failure_count=$((failure_count + 1))
        fi
    fi

    # Restore the build tree to a clean state.
    cleanup
    unset current_component
}

# Preliminary setup
pre_check_environment
pre_initialize_variables
pre_parse_command_line "$@"

setup_quiet_wrappers
pre_check_git
pre_restore_files
pre_back_up

build_status=0
if [ $KEEP_GOING -eq 1 ]; then
    pre_setup_keep_going
fi
pre_prepare_outcome_file
pre_print_configuration
pre_check_tools
cleanup
if in_mbedtls_repo; then
    pre_generate_files
fi

# Run the requested tests.
for ((error_test_i=1; error_test_i <= error_test; error_test_i++)); do
    run_component pseudo_component_error_test
done
unset error_test_i
for component in $RUN_COMPONENTS; do
    run_component "component_$component"
done

# We're done.
post_report
