#!/usr/bin/env python3
"""Install all the required Python packages, with the minimum Python version.
"""

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

import argparse
import os
import re
import sys
import typing

from typing import List
from mbedtls_dev import typing_util

def pylint_doesn_t_notice_that_certain_types_are_used_in_annotations(
        _list: List[typing.Any],
) -> None:
    pass


class Requirements:
    """Collect and massage Python requirements."""

    def __init__(self) -> None:
        self.requirements = [] #type: List[str]

    def adjust_requirement(self, req: str) -> str:
        """Adjust a requirement to the minimum specified version."""
        # allow inheritance #pylint: disable=no-self-use
        # If a requirement specifies a minimum version, impose that version.
        req = re.sub(r'>=|~=', r'==', req)
        return req

    def add_file(self, filename: str) -> None:
        """Add requirements from the specified file.

        This method supports a subset of pip's requirement file syntax:
        * One requirement specifier per line, which is passed to
          `adjust_requirement`.
        * Comments (``#`` at the beginning of the line or after whitespace).
        * ``-r FILENAME`` to include another file.
        """
        for line in open(filename):
            line = line.strip()
            line = re.sub(r'(\A|\s+)#.*', r'', line)
            if not line:
                continue
            m = re.match(r'-r\s+', line)
            if m:
                nested_file = os.path.join(os.path.dirname(filename),
                                           line[m.end(0):])
                self.add_file(nested_file)
                continue
            self.requirements.append(self.adjust_requirement(line))

    def write(self, out: typing_util.Writable) -> None:
        """List the gathered requirements."""
        for req in self.requirements:
            out.write(req + '\n')

    def install(self) -> None:
        """Call pip to install the requirements."""
        if not self.requirements:
            return
        ret = os.spawnl(os.P_WAIT, sys.executable, 'python', '-m', 'pip',
                        'install', *self.requirements)
        if ret != 0:
            sys.exit(ret)


def main() -> None:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-act', '-n',
                        action='store_true',
                        help="Don't act, just print what will be done")
    parser.add_argument('files', nargs='*', metavar='FILE',
                        help="Requirement files"
                             "(default: requirements.txt in the script's directory)")
    options = parser.parse_args()
    if not options.files:
        options.files = [os.path.join(os.path.dirname(__file__),
                                      'ci.requirements.txt')]
    reqs = Requirements()
    for filename in options.files:
        reqs.add_file(filename)
    reqs.write(sys.stdout)
    if not options.no_act:
        reqs.install()

if __name__ == '__main__':
    main()
