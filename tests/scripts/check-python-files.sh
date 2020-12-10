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
