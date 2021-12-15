# utils.py
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
Utils for ssl-opt test

"""
import re
import unittest

def name_to_class_case(name : str):
    """
        function name to class name
    """
    assert re.match(r'[a-z_][a-z0-9_]*', name), "{} is not snake case"
    def replacer(match):
        if match['leading']:
            return match['leading'].upper()
        if match['div']:
            return match['div'][1].upper()
    return re.sub(r'(?P<leading>^_?[a-z])|(?P<div>_[a-z])', replacer, name)

def name_to_function_case(name : str):
    """
        function name to class name
    """
    assert re.match(r'[A-Z_]\w*', name), "{} is not pascal case"
    def replacer(match):
        if match['leading']:
            return match['leading'].lower()
        if match['div']:
            return '_' + match['div'].lower()
    return re.sub(r'(?P<leading>^_?[A-Z])|(?P<div>[A-Z])', replacer, name)

class TestNameConversion(unittest.TestCase):
    def test_func_to_class(self):
        test_pattern = [
            ('_test_hello_world','_TestHelloWorld'),
            ('test_hello_world','TestHelloWorld'),
        ]
        for k , v in test_pattern:
            self.assertEqual(name_to_class_case(k),v)

        for k , v in test_pattern:
            self.assertEqual(name_to_function_case(v),k)
