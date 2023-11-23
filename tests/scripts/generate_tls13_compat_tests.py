#!/usr/bin/env python3

# generate_tls13_compat_tests.py
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

"""
Generate TLSv1.3 test cases

"""

import sys
import argparse
from tls13_compat import output_test_cases, TLS13_TEST_SUITES


def main():
    """
    Main function of this program
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('-o', '--output', nargs='?',
                        default=None, help='Output file path')

    parser.add_argument('--list-test-suites', action='store_true',
                        default=False, help='List supported tests')

    parser.add_argument('--test_suite', choices=TLS13_TEST_SUITES.keys(), action='append',
                        help='Choose cipher suite for test')
    args = parser.parse_args()

    if args.list_test_suites:
        print(*TLS13_TEST_SUITES.keys())
        return 0

    test_suites = args.test_suite or TLS13_TEST_SUITES.keys()

    output_test_cases(test_suites, args.output, ' '.join(sys.argv))

    return 0


if __name__ == "__main__":
    sys.exit(main())
