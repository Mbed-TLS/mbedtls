#!/bin/sh

help () {
    cat <<EOF
Usage: $0
Collect coverage statistics of library code into an HTML report.

General instructions:
1. Build the library with CFLAGS="--coverage -O0 -g3".
   This can be an out-of-tree build.
2. Run whatever tests you want.
3. Run this script from the parent of the directory containing the library
   object files and coverage statistics files.
4. Browse the coverage report in Coverage/index.html.
EOF
}

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

set -eu

lcov_rebuild_stats () {
    rm -rf Coverage
    lcov --capture --initial --directory library -o files.info
    lcov --rc lcov_branch_coverage=1 --capture --directory library -o tests.info
    lcov --rc lcov_branch_coverage=1 --add-tracefile files.info --add-tracefile tests.info -o all.info
    lcov --rc lcov_branch_coverage=1 --remove all.info -o final.info '*.h'
    gendesc tests/Descriptions.txt -o descriptions
    genhtml --title "mbed TLS" --description-file descriptions --keep-descriptions --legend --branch-coverage -o Coverage final.info
    rm -f files.info tests.info all.info final.info descriptions
    echo "Coverage report in: Coverage/index.html"
}

if [ $# -gt 0 ] && [ "$1" = "--help" ]; then
    help
    exit
fi

lcov_rebuild_stats
