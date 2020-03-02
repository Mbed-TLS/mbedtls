#!/usr/bin/env python3

"""Sanity checks for test data.
"""

# Copyright (C) 2019, Arm Limited, All Rights Reserved
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
# This file is part of Mbed TLS (https://tls.mbed.org)

import argparse
import glob
import os
import re
import sys

class Results:
    """Store file and line information about errors or warnings in test suites."""

    def __init__(self, options):
        self.errors = 0
        self.warnings = 0
        self.ignore_warnings = options.quiet

    def error(self, file_name, line_number, fmt, *args):
        sys.stderr.write(('{}:{}:ERROR:' + fmt + '\n').
                         format(file_name, line_number, *args))
        self.errors += 1

    def warning(self, file_name, line_number, fmt, *args):
        if not self.ignore_warnings:
            sys.stderr.write(('{}:{}:Warning:' + fmt + '\n')
                             .format(file_name, line_number, *args))
            self.warnings += 1

def collect_test_directories():
    """Get the relative path for the TLS and Crypto test directories."""
    if os.path.isdir('tests'):
        tests_dir = 'tests'
    elif os.path.isdir('suites'):
        tests_dir = '.'
    elif os.path.isdir('../suites'):
        tests_dir = '..'
    directories = [tests_dir]
    crypto_tests_dir = os.path.normpath(os.path.join(tests_dir,
                                                     '../crypto/tests'))
    if os.path.isdir(crypto_tests_dir):
        directories.append(crypto_tests_dir)
    return directories

def check_description(results, seen, file_name, line_number, description):
    """Check test case descriptions for errors."""
    if description in seen:
        results.error(file_name, line_number,
                      'Duplicate description (also line {})',
                      seen[description])
        return
    if re.search(br'[\t;]', description):
        results.error(file_name, line_number,
                      'Forbidden character \'{}\' in description',
                      re.search(br'[\t;]', description).group(0).decode('ascii'))
    if re.search(br'[^ -~]', description):
        results.error(file_name, line_number,
                      'Non-ASCII character in description')
    if len(description) > 66:
        results.warning(file_name, line_number,
                        'Test description too long ({} > 66)',
                        len(description))
    seen[description] = line_number

def check_test_suite(results, data_file_name):
    in_paragraph = False
    descriptions = {}
    with open(data_file_name, 'rb') as data_file:
        for line_number, line in enumerate(data_file, 1):
            line = line.rstrip(b'\r\n')
            if not line:
                in_paragraph = False
                continue
            if line.startswith(b'#'):
                continue
            if not in_paragraph:
                # This is a test case description line.
                check_description(results, descriptions,
                                  data_file_name, line_number, line)
            in_paragraph = True

def check_ssl_opt_sh(results, file_name):
    descriptions = {}
    with open(file_name, 'rb') as file_contents:
        for line_number, line in enumerate(file_contents, 1):
            # Assume that all run_test calls have the same simple form
            # with the test description entirely on the same line as the
            # function name.
            m = re.match(br'\s*run_test\s+"((?:[^\\"]|\\.)*)"', line)
            if not m:
                continue
            description = m.group(1)
            check_description(results, descriptions,
                              file_name, line_number, description)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--quiet', '-q',
                        action='store_true',
                        help='Hide warnings')
    parser.add_argument('--verbose', '-v',
                        action='store_false', dest='quiet',
                        help='Show warnings (default: on; undoes --quiet)')
    options = parser.parse_args()
    test_directories = collect_test_directories()
    results = Results(options)
    for directory in test_directories:
        for data_file_name in glob.glob(os.path.join(directory, 'suites',
                                                     '*.data')):
            check_test_suite(results, data_file_name)
        ssl_opt_sh = os.path.join(directory, 'ssl-opt.sh')
        if os.path.exists(ssl_opt_sh):
            check_ssl_opt_sh(results, ssl_opt_sh)
    if (results.warnings or results.errors) and not options.quiet:
        sys.stderr.write('{}: {} errors, {} warnings\n'
                         .format(sys.argv[0], results.errors, results.warnings))
    sys.exit(1 if results.errors else 0)

if __name__ == '__main__':
    main()
