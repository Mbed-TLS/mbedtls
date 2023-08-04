#!/bin/bash
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
#
# Purpose
#
# For adapting gitignore files for releases so generated files can be included.
#
# Usage: gitignore_add_generated_files.sh  [ -h | --help ] etc
#

set -eu

print_usage()
{
    echo "Usage: $0"
    echo -e "  -h|--help\t\tPrint this help."
    echo -e "  -i|--ignore\t\tAdd generated files to the gitignores."
    echo -e "  -u|--unignore\t\tRemove generated files from the gitignores."
}

if [[ $# -eq 0 ]]; then
    print_usage
    exit 1
elif [[ $# -ge 2 ]]; then
    echo "Too many arguments!"
    exit 1
fi

case "$1" in
    -i | --ignore)
        IGNORE=true
        ;;
    -u | --uignore)
        IGNORE=false
        ;;
    -h | --help | "")
        print_usage
        exit 1
        ;;
    *)
        echo "Unknown argument: $1"
        echo "run '$0 --help' for options"
        exit 1
esac

GITIGNORES=$(find . -name ".gitignore")
for GITIGNORE in $GITIGNORES; do
    if $IGNORE; then
        sed -i '/###START_COMMENTED_GENERATED_FILES###/,/###END_COMMENTED_GENERATED_FILES###/s/^# //' $GITIGNORE
        sed -i 's/###START_COMMENTED_GENERATED_FILES###/###START_GENERATED_FILES###/' $GITIGNORE
        sed -i 's/###END_COMMENTED_GENERATED_FILES###/###END_GENERATED_FILES###/' $GITIGNORE
    else
        sed -i '/###START_GENERATED_FILES###/,/###END_GENERATED_FILES###/s/^/# /' $GITIGNORE
        sed -i 's/###START_GENERATED_FILES###/###START_COMMENTED_GENERATED_FILES###/' $GITIGNORE
        sed -i 's/###END_GENERATED_FILES###/###END_COMMENTED_GENERATED_FILES###/' $GITIGNORE
    fi
done
