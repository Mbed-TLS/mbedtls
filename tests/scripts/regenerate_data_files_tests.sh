#!/usr/bin/env bash
# regenerate_data_files_tests.sh
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

helper_regenerate_data_files () {
    msg "Rebuild data files with $1"
    msg "Build mbedtls tools"
    make  # data_files depends on programs/x509/cert_*

    msg "Cleanup final files make -C tests/data_files $1"
    make -C tests/data_files $1
    shift

    dd if=/dev/urandom of=./tests/data_files/seedfile bs=64 count=1
    msg "Regenerate files"
    make -C tests/data_files all_final $*

    msg "Remove intermediate files"
    make -C tests/data_files clean

    msg "Only modified files are allowd"
    if git status -s --ignored -- tests/data_files | grep -vf tests/data_files/ignored.lst
    then
        err_msg "Files were not generated or not cleanup"
        ( git status -s --ignored -- tests/data_files | grep -vf tests/data_files/ignored.lst) || true
        err_msg "Status after regenerating"
        git status -s --ignored -- tests/data_files
        exit 1
    fi

    cleanup
}

component_test_regnerate_parse_input () {
    helper_regenerate_data_files tidy all_parse_input
}

component_test_regenerate_data_files_full () {
    helper_regenerate_data_files neat
    helper_datafile_run_tests "default configuration with refreshed data files"
}

component_test_regenerate_data_files_default () {
    helper_regenerate_data_files neat
    scripts/config.py full
    helper_datafile_run_tests "default configuration with refreshed data files"
}
