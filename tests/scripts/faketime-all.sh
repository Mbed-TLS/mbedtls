#! /usr/bin/env bash

# faketime-all.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.



################################################################
#### Documentation
################################################################

# Purpose
# -------
#
# Run tests to check if files in `tests/data_files` and the generateing commands
# are valid.
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
#
# The script MUST be run under Linux only.(libfaketime depends on LD_PRELOAD)
#
# The script assumes the presence of a number of tools:
#   * Basic Unix tools (Windows users note: a Unix-style find must be before
#     the Windows find in the PATH)
#   * Python 3.6 or later
#   * GNU Make
#   * GCC
#   * G++
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
#   script -c tests/scripts/faketime-all.sh
# or
#   tests/scripts/faketime-all.sh >all.log 2>&1
#
# Notes for maintainers
# ---------------------
#
# See also: `tests/scripts/all.sh`
#
# This script is base on `all.sh`. The user interface is simillar, but it is
# different for maintainers.
# - This file only includes `test_faketime_*` and `test_regnerate_*` components.
# - `test_faketime_*` will be run with libfaketime
# - `test_regnerate_*` will cleanup and re-generate files in `tests/data_files`
# - To keep consitent with global section of `all.sh`, do not change it if not
#   neccesary.


################################################################
#### Initialization and command line parsing
################################################################

# Abort on errors (even on the left-hand side of a pipe).
# Treat uninitialised variables as errors.
set -e -o pipefail -u

# Enable ksh/bash extended file matching patterns
shopt -s extglob

pre_check_environment () {
    if [ -d library -a -d include -a -d tests ]; then :; else
        echo "Must be run from mbed TLS root" >&2
        exit 1
    fi
}

pre_initialize_variables () {
    CONFIG_H='include/mbedtls/mbedtls_config.h'
    CRYPTO_CONFIG_H='include/psa/crypto_config.h'
    CONFIG_TEST_DRIVER_H='tests/include/test/drivers/config_test_driver.h'

    # Files that are clobbered by some jobs will be backed up. Use a different
    # suffix from auxiliary scripts so that all.sh and auxiliary scripts can
    # independently decide when to remove the backup file.
    backup_suffix='.all.bak'
    # Files clobbered by config.py
    files_to_back_up="$CONFIG_H $CRYPTO_CONFIG_H $CONFIG_TEST_DRIVER_H"
    # Files clobbered by in-tree cmake
    files_to_back_up="$files_to_back_up Makefile library/Makefile programs/Makefile tests/Makefile programs/fuzz/Makefile"

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

    : ${MBEDTLS_TEST_OUTCOME_FILE=}
    : ${MBEDTLS_TEST_PLATFORM="$(uname -s | tr -c \\n0-9A-Za-z _)-$(uname -m | tr -c \\n0-9A-Za-z _)"}
    export MBEDTLS_TEST_OUTCOME_FILE
    export MBEDTLS_TEST_PLATFORM

    # Default commands, can be overridden by the environment
    : ${OPENSSL:="openssl"}
    : ${OPENSSL_LEGACY:="$OPENSSL"}
    : ${OPENSSL_NEXT:="$OPENSSL"}
    : ${GNUTLS_CLI:="gnutls-cli"}
    : ${GNUTLS_SERV:="gnutls-serv"}
    : ${GNUTLS_LEGACY_CLI:="$GNUTLS_CLI"}
    : ${GNUTLS_LEGACY_SERV:="$GNUTLS_SERV"}
    : ${OUT_OF_SOURCE_DIR:=./mbedtls_out_of_source_build}
    : ${ARMC5_BIN_DIR:=/usr/bin}
    : ${ARMC6_BIN_DIR:=/usr/bin}
    : ${ARM_NONE_EABI_GCC_PREFIX:=arm-none-eabi-}
    : ${ARM_LINUX_GNUEABI_GCC_PREFIX:=arm-linux-gnueabi-}
    LIBFAKETIME=

    # if MAKEFLAGS is not set add the -j option to speed up invocations of make
    if [ -z "${MAKEFLAGS+set}" ]; then
        export MAKEFLAGS="-j$(all_sh_nproc)"
    fi

    # Include more verbose output for failing tests run by CMake or make
    export CTEST_OUTPUT_ON_FAILURE=1

    # CFLAGS and LDFLAGS for Asan builds that don't use CMake
    # default to -O2, use -Ox _after_ this if you want another level
    ASAN_CFLAGS='-O2 -Werror -fsanitize=address,undefined -fno-sanitize-recover=all'

    # Gather the list of available components. These are the functions
    # defined in this script whose name starts with "component_".
    # Parse the script with sed. This way we get the functions in the order
    # they are defined.
    ALL_COMPONENTS=$(sed -n 's/^ *component_\([0-9A-Z_a-z]*\) *().*/\1/p' <"$0")
    # This file only includes `test_faketime_*`
    for component in $ALL_COMPONENTS; do
        case $component in
            "test_faketime_"*) ;;
            *)
                err_msg "$component is not allowed in this script";
                exit 1;;
        esac
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
     --gnutls-cli=<GnuTLS_cli_path>             GnuTLS client executable to use for most tests.
     --gnutls-serv=<GnuTLS_serv_path>           GnuTLS server executable to use for most tests.
     --gnutls-legacy-cli=<GnuTLS_cli_path>      GnuTLS client executable to use for legacy tests.
     --gnutls-legacy-serv=<GnuTLS_serv_path>    GnuTLS server executable to use for legacy tests.
     --openssl=<OpenSSL_path>                   OpenSSL executable to use for most tests.
     --openssl-legacy=<OpenSSL_path>            OpenSSL executable to use for legacy tests..
     --openssl-next=<OpenSSL_path>              OpenSSL executable to use for recent things like ARIA
EOF
}

# Cleanup before/after running a component.
# Remove built files as well as the cmake cache/config.
# Does not remove generated source files.
cleanup()
{
    command make clean

    # Remove CMake artefacts
    find . -name .git -prune -o \
           -iname CMakeFiles -exec rm -rf {} \+ -o \
           \( -iname cmake_install.cmake -o \
              -iname CTestTestfile.cmake -o \
              -iname CMakeCache.txt -o \
              -path './cmake/*.cmake' \) -exec rm -f {} \+
    # Recover files overwritten by in-tree CMake builds
    rm -f include/Makefile include/mbedtls/Makefile programs/!(fuzz)/Makefile

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
    ARM_TOOL_VARIANT="ult" CC="$ARMC6_CC" AR="$ARMC6_AR" CFLAGS="$FLAGS" \
                    WARNING_CFLAGS='-Werror -xc -std=c99' make lib

    msg "size: ARM Compiler 6 ($FLAGS)"
    "$ARMC6_FROMELF" -z library/*.o

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

check_faketime() {

    for i in /usr/local/lib/faketime/libfaketime.so.1 \
             /usr/lib/aarch64-linux-gnu/faketime/libfaketime.so.1 \
             /usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1
    do
        if [ -f $i ]; then
            LIBFAKETIME=$i
        fi
    done
    if [ -z "$LIBFAKETIME" ]; then
        err_msg "libfaketime not found!"
        exit 1
    fi
}

pre_parse_command_line_for_dirs () {
    # Make an early pass through the options given, so we can set directories
    # for Arm compilers, before SUPPORTED_COMPONENTS is determined.
    while [ $# -gt 0 ]; do
        case "$1" in
            --armc5-bin-dir) shift; ARMC5_BIN_DIR="$1";;
            --armc6-bin-dir) shift; ARMC6_BIN_DIR="$1";;
        esac
        shift
    done
}

pre_parse_command_line () {
    COMMAND_LINE_COMPONENTS=
    all_except=0
    error_test=0
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
            --armc5-bin-dir) shift; ;; # assignment to ARMC5_BIN_DIR done in pre_parse_command_line_for_dirs
            --armc6-bin-dir) shift; ;; # assignment to ARMC6_BIN_DIR done in pre_parse_command_line_for_dirs
            --error-test) error_test=$((error_test + 1));;
            --except) all_except=1;;
            --force|-f) FORCE=1;;
            --gnutls-cli) shift; GNUTLS_CLI="$1";;
            --gnutls-legacy-cli) shift; GNUTLS_LEGACY_CLI="$1";;
            --gnutls-legacy-serv) shift; GNUTLS_LEGACY_SERV="$1";;
            --gnutls-serv) shift; GNUTLS_SERV="$1";;
            --help|-h) usage; exit;;
            --keep-going|-k) KEEP_GOING=1;;
            --list-all-components) printf '%s\n' $ALL_COMPONENTS; exit;;
            --list-components) printf '%s\n' $SUPPORTED_COMPONENTS; exit;;
            --memory|-m) MEMORY=1;;
            --no-append-outcome) append_outcome=0;;
            --no-armcc) no_armcc=1;;
            --no-force) FORCE=0;;
            --no-keep-going) KEEP_GOING=0;;
            --no-memory) MEMORY=0;;
            --no-quiet) QUIET=0;;
            --openssl) shift; OPENSSL="$1";;
            --openssl-legacy) shift; OPENSSL_LEGACY="$1";;
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

        if ! git diff --quiet include/mbedtls/mbedtls_config.h; then
            err_msg "Warning - the configuration file 'include/mbedtls/mbedtls_config.h' has been edited. "
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
    echo "OPENSSL_LEGACY: $OPENSSL_LEGACY"
    echo "OPENSSL_NEXT: $OPENSSL_NEXT"
    echo "GNUTLS_CLI: $GNUTLS_CLI"
    echo "GNUTLS_SERV: $GNUTLS_SERV"
    echo "GNUTLS_LEGACY_CLI: $GNUTLS_LEGACY_CLI"
    echo "GNUTLS_LEGACY_SERV: $GNUTLS_LEGACY_SERV"
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
        *" test_"*)
            # To avoid setting OpenSSL and GnuTLS for each call to compat.sh
            # and ssl-opt.sh, we just export the variables they require.
            export OPENSSL="$OPENSSL"
            export GNUTLS_CLI="$GNUTLS_CLI"
            export GNUTLS_SERV="$GNUTLS_SERV"
            # Avoid passing --seed flag in every call to ssl-opt.sh
            if [ -n "${SEED-}" ]; then
                export SEED
            fi
            set "$@" OPENSSL="$OPENSSL" OPENSSL_LEGACY="$OPENSSL_LEGACY"
            set "$@" GNUTLS_CLI="$GNUTLS_CLI" GNUTLS_SERV="$GNUTLS_SERV"
            set "$@" GNUTLS_LEGACY_CLI="$GNUTLS_LEGACY_CLI"
            set "$@" GNUTLS_LEGACY_SERV="$GNUTLS_LEGACY_SERV"
            check_tools "$OPENSSL" "$OPENSSL_LEGACY" "$OPENSSL_NEXT" \
                        "$GNUTLS_CLI" "$GNUTLS_SERV" \
                        "$GNUTLS_LEGACY_CLI" "$GNUTLS_LEGACY_SERV"
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

    case " $RUN_COMPONENTS " in
        *_faketime_*)
            check_faketime;;
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
#    4b. Call helper_libtestdriver1_make_main "$loc_accel_list". Any
#        additional arguments will be passed to make: this can be useful if
#        you don't want to build everything when iterating during development.
#        Example:
#          helper_libtestdriver1_make_main "$loc_accel_list" -C tests test_suite_foo
# 4. Run the tests you want.

# Adjust the configuration - for both libtestdriver1 and main library,
# as they should have the same PSA_WANT macros.
helper_libtestdriver1_adjust_config() {
    BASE_CONFIG=$1
    # Select the base configuration
    if [ "$BASE_CONFIG" != "default" ]; then
        scripts/config.py "$BASE_CONFIG"
    fi

    # Enable PSA-based config (necessary to use drivers)
    scripts/config.py set MBEDTLS_PSA_CRYPTO_CONFIG

    # Disable ALG_STREAM_CIPHER and ALG_ECB_NO_PADDING to avoid having
    # partial support for cipher operations in the driver test library.
    scripts/config.py -f include/psa/crypto_config.h unset PSA_WANT_ALG_STREAM_CIPHER
    scripts/config.py -f include/psa/crypto_config.h unset PSA_WANT_ALG_ECB_NO_PADDING

    # Dynamic secure element support is a deprecated feature and needs to be disabled here.
    # This is done to have the same form of psa_key_attributes_s for libdriver and library.
    scripts/config.py unset MBEDTLS_PSA_CRYPTO_SE_C
}

# Build the drivers library libtestdriver1.a (with ASan).
#
# Parameters:
# 1. a space-separated list of things to accelerate;
# 2. optional: a space-separate list of things to also support.
# Here "things" are PSA_WANT_ symbols but with PSA_WANT_ removed.
helper_libtestdriver1_make_drivers() {
    loc_accel_flags=$( echo "$1 ${2-}" | sed 's/[^ ]* */-DLIBTESTDRIVER1_MBEDTLS_PSA_ACCEL_&/g' )
    make -C tests libtestdriver1.a CFLAGS=" $ASAN_CFLAGS $loc_accel_flags" LDFLAGS="$ASAN_CFLAGS"
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
    make CFLAGS="$ASAN_CFLAGS -I../tests/include -I../tests -I../../tests -DPSA_CRYPTO_DRIVER_TEST -DMBEDTLS_TEST_LIBTESTDRIVER1 $loc_accel_flags" LDFLAGS="-ltestdriver1 $ASAN_CFLAGS" "$@"
}

################################################################
#### Helpers for checking `tests/data_files`
################################################################

helper_datafile_run_tests () {
    msg "build: $1" # ~ 1 min 50s
    CC=gcc make

    msg "test: main suites" # ~ 50s
    CC=gcc make test

    msg "test: selftest" # ~ 10s
    programs/test/selftest

    msg "test: ssl-opt.sh" # ~ 1 min
    tests/ssl-opt.sh

    msg "test: compat.sh" # ~ 6 min
    tests/compat.sh

    msg "test: context-info.sh" # ~ 15 sec
    tests/context-info.sh
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

component_test_faketime_default () {
    helper_datafile_run_tests " default configuration with faketime"
}

component_test_faketime_full () {
    scripts/config.py full
    helper_datafile_run_tests " full configuration with faketime"
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

        # Enable faketime for `test_faketime_*`
        if [[ $current_component = component_test_faketime_* ]]; then
            export LD_PRELOAD="$LIBFAKETIME"
            export FAKETIME="+4m"
        else
            unset LD_PRELOAD
            unset FAKETIME
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
pre_parse_command_line_for_dirs "$@"
pre_initialize_variables
pre_parse_command_line "$@"

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
pre_generate_files

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
