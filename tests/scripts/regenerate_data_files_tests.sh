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

helper_regenerate_data_files () {
    msg "Rebuild data files with $1"
    msg "Build mbedtls tools"
    make  # data_files depends on programs/x509/cert_*

    msg "Cleanup final files make -C tests/data_files $1"
    OPENSSL=/usr/bin/openssl make -C tests/data_files $1
    shift

    dd if=/dev/urandom of=./tests/data_files/seedfile bs=64 count=1
    msg "Regenerate files"
    OPENSSL=/usr/bin/openssl make -C tests/data_files all_final $*

    msg "Remove intermediate files"
    OPENSSL=/usr/bin/openssl make -C tests/data_files clean

    msg "Only modified files are allowd"
    new_or_missed_files=$((git status -s --ignored -- tests/data_files | \
                                grep -v -f tests/data_files/ignored.lst \
                                    -f tests/data_files/uncategorized.lst) \
                            || true)
    if [ -n "${new_or_missed_files}" ]
    then
        err_msg "Files were not generated or not cleanup"
        printf '%s %s\n' $new_or_missed_files
        err_msg "Status after regenerating"
        git status -s --ignored -- tests/data_files
        exit 1
    fi

    # TODO: Add modified files check here.
}

component_test_regenerate_parse_input () {
    helper_regenerate_data_files tidy all_parse_input
}

support_test_regenerate_parse_input () {
    which xxd hexdump faketime 2>&1 >/dev/null && \
        [[ $(/usr/bin/openssl version) == *"3.0.2"* ]]
}
