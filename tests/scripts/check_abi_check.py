#!/usr/bin/env python3

""" Check abi_check.py is working correctly
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

import unittest
import traceback
import sys
import os
import subprocess
import re

SCRIPT_PATH = "scripts/abi_check.py"

def run_abi_check(old_tag, new_tag):
    return subprocess.check_output([SCRIPT_PATH, "-o", old_tag, "-n", new_tag],
                                   stderr=subprocess.STDOUT).decode("utf-8")

def pattern_create(lines):
    return "(("+ "|".join(lines) +").*\n?)+"

class TestAbiCheck(unittest.TestCase):
    ''' This class test abi check script
    '''

    @staticmethod
    def check_repo_path():
        if not all(os.path.isdir(d) for d in ["include", "library", "tests"]):
            raise Exception("Must be run from Mbed TLS root")

    def test_abi_same(self):
        ''' This test checks no false positive
        '''
        possible_lines = ["Checking", "No compatibility issues", "PASS", "Info"]
        pattern = pattern_create(possible_lines)
        out = run_abi_check("mbedtls-3.2.0", "mbedtls-3.2.1")
        self.assertIsNotNone(re.fullmatch(pattern, out, re.MULTILINE))

    def test_abi_different(self):
        ''' This test checks no false negative
        '''
        possible_lines = ["Checking", "Compatibility issues", "Test", "FAIL", "Info"]
        pattern = pattern_create(possible_lines)
        try:
            out = run_abi_check("mbedtls-2.27.0", "mbedtls-3.2.1")
        except subprocess.CalledProcessError as err:
            out = err.output.decode("utf-8")
            self.assertEqual(1, err.returncode)
        self.assertIsNotNone(re.fullmatch(pattern, out, re.MULTILINE))

def run_main():
    try:
        TestAbiCheck.check_repo_path()
        unittest.main()
    except Exception: #pylint: disable=broad-except
        traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    run_main()
