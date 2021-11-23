#!/usr/bin/env python3
"""Complete a test case with cryptographic data.

Given the desired inputs, fill in the expected outputs.
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
import re
import sys

import scripts_path # pylint: disable=unused-import
from mbedtls_dev import crypto_test_maker


SUITE_CLASSES = {
    'psa_crypto': crypto_test_maker.PsaCrypto,
}

def main(args):
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('suite', metavar='SUITE',
                        help="Test suite name")
    options = parser.parse_args(args)
    options.suite = re.sub(r'\Atest_suite_', '', options.suite)
    suite_class = SUITE_CLASSES[options.suite]
    for num, line in enumerate(sys.stdin, 1):
        if re.match(r'\w+:\S', line):
            try:
                tc = suite_class(line)
            except:
                sys.stderr.write('! Error at input line {}:\n'.format(num))
                raise
            sys.stdout.write(tc.data_line() + '\n')
        else:
            sys.stdout.write(line)

if __name__ == '__main__':
    main(sys.argv[1:])
