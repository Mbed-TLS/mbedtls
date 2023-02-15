#!/usr/bin/env python3

# generate_tls13_compat_tests.py
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

"""
Generate TLSv1.3 test cases

"""

import sys
import argparse
from tls13_compat import AVAILABLE_PROGS, CIPHER_SUITE_IANA_VALUE, NAMED_GROUP_IANA_VALUE, \
    SIG_ALG_IANA_VALUE, output_test_cases, TLS13_TESTS


def main():
    """
    Main function of this program
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('-o', '--output', nargs='?',
                        default=None, help='Output file path')

    parser.add_argument('-a', '--generate-all-tls13-tests', action='store_true',
                        default=False, help='Generate all available tls13 compat tests')

    parser.add_argument('--list-tests', action='store_true',
                        default=False, help='List supported tests')

    parser.add_argument('--list-ciphers', action='store_true',
                        default=False, help='List supported ciphersuites')

    parser.add_argument('--list-sig-algs', action='store_true',
                        default=False, help='List supported signature algorithms')

    parser.add_argument('--list-named-groups', action='store_true',
                        default=False, help='List supported named groups')

    parser.add_argument('--list-servers', action='store_true',
                        default=False, help='List supported TLS servers')

    parser.add_argument('--list-clients', action='store_true',
                        default=False, help='List supported TLS Clients')

    parser.add_argument('--test_suite', choices=TLS13_TESTS.keys(), action='append',
                        help='Choose cipher suite for test')
    args = parser.parse_args()

    tests = TLS13_TESTS.keys()

    if not args.generate_all_tls13_tests and args.test_suite:
        tests = args.test_suite

    if any([args.list_ciphers, args.list_sig_algs, args.list_named_groups,
            args.list_servers, args.list_clients, args.list_tests]):
        if args.list_ciphers:
            print(*CIPHER_SUITE_IANA_VALUE.keys())
        if args.list_sig_algs:
            print(*SIG_ALG_IANA_VALUE.keys())
        if args.list_named_groups:
            print(*NAMED_GROUP_IANA_VALUE.keys())
        if args.list_servers:
            print(*AVAILABLE_PROGS)
        if args.list_clients:
            print(*AVAILABLE_PROGS)
        if args.list_tests:
            print(*TLS13_TESTS.keys())
        return 0

    output_test_cases(tests, args.output, ' '.join(sys.argv))

    return 0


if __name__ == "__main__":
    sys.exit(main())
