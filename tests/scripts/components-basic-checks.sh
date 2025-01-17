# components-basic-checks.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Basic checks
################################################################

component_check_recursion () {
    msg "Check: recursion.pl" # < 1s
    ./framework/scripts/recursion.pl library/*.c
    ./framework/scripts/recursion.pl ${PSA_CORE_PATH}/*.c
    ./framework/scripts/recursion.pl ${BUILTIN_SRC_PATH}/*.c
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
    ./framework/scripts/check-doxy-blocks.pl
}

component_check_files () {
    msg "Check: file sanity checks (permissions, encodings)" # < 1s
    framework/scripts/check_files.py
}

component_check_changelog () {
    msg "Check: changelog entries" # < 1s
    rm -f ChangeLog.new
    ./framework/scripts/assemble_changelog.py -o ChangeLog.new
    if [ -e ChangeLog.new ]; then
        # Show the diff for information. It isn't an error if the diff is
        # non-empty.
        diff -u ChangeLog ChangeLog.new || true
        rm ChangeLog.new
    fi
}

component_check_names () {
    msg "Check: declared and exported names (builds the library)" # < 3s
    framework/scripts/check_names.py -v
}

component_check_test_cases () {
    msg "Check: test case descriptions" # < 1s
    if [ $QUIET -eq 1 ]; then
        opt='--quiet'
    else
        opt=''
    fi
    framework/scripts/check_test_cases.py -q $opt
    unset opt
}

component_check_doxygen_warnings () {
    msg "Check: doxygen warnings (builds the documentation)" # ~ 3s
    ./framework/scripts/doxygen.sh
}

component_check_code_style () {
    msg "Check C code style"
    ./framework/scripts/code_style.py
}

support_check_code_style () {
    case $(uncrustify --version) in
        *0.75.1*) true;;
        *) false;;
    esac
}

component_check_python_files () {
    msg "Lint: Python scripts"
    ./framework/scripts/check-python-files.sh
}

component_check_test_helpers () {
    msg "unit test: generate_test_code.py"
    # unittest writes out mundane stuff like number or tests run on stderr.
    # Our convention is to reserve stderr for actual errors, and write
    # harmless info on stdout so it can be suppress with --quiet.
    ./framework/scripts/test_generate_test_code.py 2>&1

    msg "unit test: translate_ciphers.py"
    python3 -m unittest framework/scripts/translate_ciphers.py 2>&1
}
