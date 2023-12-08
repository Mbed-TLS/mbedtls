#!/usr/bin/env python3
"""Describe the test coverage of PSA functions in terms of return statuses.

1. Build Mbed TLS with MBEDLTS_TEST_HOOKS enabled.
2. Run unit tests with the environment variable
   MBEDTLS_TEST_PSA_WRAPPERS_LOG_FILE set to a file name.
2. Run psa_collect_statuses.py on the log file.

The output is a series of line of the form "psa_foo PSA_ERROR_XXX". Each
function/status combination appears only once.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import re
import subprocess
import sys
from typing import Dict, Set

DEFAULT_PSA_CONSTANT_NAMES = 'programs/psa/psa_constant_names'

class Statuses:
    """Information about observed return statues of API functions."""

    def __init__(self) -> None:
        self.functions = {} #type: Dict[str, Set[int]]
        self.codes = set() #type: Set[int]
        self.status_names = {} #type: Dict[int, str]

    _LOG_LINE_RE = re.compile(r'(?:[^;]*;){5}' # test case identification
                              r'(?:[^;:]*:){3}\s*' # calling site
                              r'(\w+)' # function name
                              r'[^;:]*?' # arguments
                              r'\bstatus=([-+][0-9]+|0[Xx][0-9A-Fa-f]+)'
                              r'(?:$|;)', re.A)

    def collect_log(self, log_file_name: str) -> None:
        """Read logs from PSA test wrappers.
        """
        with open(log_file_name) as log:
            for line in log:
                m = self._LOG_LINE_RE.match(line)
                if not m:
                    continue
                function = m.group(1)
                value = int(m.group(2), 0)
                if function not in self.functions:
                    self.functions[function] = set()
                self.functions[function].add(value)
                self.codes.add(value)

    def get_constant_names(self, psa_constant_names: str) -> None:
        """Run psa_constant_names to obtain names for observed numerical values."""
        values = [str(value) for value in self.codes]
        cmd = [psa_constant_names, 'status'] + values
        output = subprocess.check_output(cmd).decode('ascii')
        for value, name in zip(self.codes, output.rstrip().split('\n')):
            self.status_names[value] = name

    def report(self) -> None:
        """Report observed return values for each function.

        The report is a series of line of the form "psa_foo PSA_ERROR_XXX".
        """
        for function in sorted(self.functions.keys()):
            fdata = self.functions[function]
            names = [self.status_names[value] for value in fdata]
            for name in sorted(names):
                sys.stdout.write('{} {}\n'.format(function, name))

def collect_status_logs(options) -> Statuses:
    """Report observed function return statuses by reading call logs.
    """
    data = Statuses()
    data.collect_log(options.log_file)
    data.get_constant_names(options.psa_constant_names)
    return data

def main() -> None:
    parser = argparse.ArgumentParser(description=globals()['__doc__'])
    parser.add_argument('--psa-constant-names', metavar='PROGRAM',
                        default=DEFAULT_PSA_CONSTANT_NAMES,
                        help='Path to psa_constant_names (default: {})'.format(
                            DEFAULT_PSA_CONSTANT_NAMES
                        ))
    parser.add_argument('log_file', metavar='FILE',
                        help='Log file to read')
    options = parser.parse_args()
    data = collect_status_logs(options)
    data.report()

if __name__ == '__main__':
    main()
