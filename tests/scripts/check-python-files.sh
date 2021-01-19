#! /usr/bin/env sh

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

# Purpose: check Python files for potential programming errors or maintenance
# hurdles. Run pylint to detect some potential mistakes and enforce PEP8
# coding standards. If available, run mypy to perform static type checking.

# We'll keep going on errors and report the status at the end.
ret=0

if type python3 >/dev/null 2>/dev/null; then
    PYTHON=python3
else
    PYTHON=python
fi

can_pylint () {
    # Pylint 1.5.2 from Ubuntu 16.04 is too old:
    #     E: 34, 0: Unable to import 'mbedtls_dev' (import-error)
    # Pylint 1.8.3 from Ubuntu 18.04 passed on the first commit containing this line.
    $PYTHON -m pylint 2>/dev/null --version | awk '
        BEGIN {status = 1}
        /^(pylint[0-9]*|__main__\.py) +[0-9]+\.[0-9]+/ {
            split($2, version, /[^0-9]+/);
            status = !(version[1] >= 2 || (version[1] == 1 && version[2] >= 8));
            exit; # executes the END block
        }
        END {exit status}
    '
}

can_mypy () {
    # Just check that mypy is present and looks sane. I don't know what
    # minimum version is required. The check is not just "type mypy"
    # because that passes if a mypy exists but is not installed for the current
    # python version.
    mypy --version 2>/dev/null >/dev/null
}

# With just a --can-xxx option, check whether the tool for xxx is available
# with an acceptable version, and exit without running any checks. The exit
# status is true if the tool is available and acceptable and false otherwise.
if [ "$1" = "--can-pylint" ]; then
    can_pylint
    exit
elif [ "$1" = "--can-mypy" ]; then
    can_mypy
    exit
fi

echo 'Running pylint ...'
$PYTHON -m pylint -j 2 scripts/mbedtls_dev/*.py scripts/*.py tests/scripts/*.py || {
    echo >&2 "pylint reported errors"
    ret=1
}

# Check types if mypy is available
if type mypy >/dev/null 2>/dev/null; then
    echo
    echo 'Running mypy ...'
    mypy scripts/*.py tests/scripts/*.py ||
      ret=1
fi

exit $ret
