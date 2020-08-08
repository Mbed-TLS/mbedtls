#!/usr/bin/env python3

# Copyright (c) 2020, Arm Limited, All Rights Reserved
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

"""Unit tests for ../scripts/test_c_generator.py"""

import importlib
import os
import sys
import unittest


class SmokeTest(unittest.TestCase):
    """Test that we seem to have loaded the right module."""
    # pylint: disable=missing-docstring

    def test_docstring(self):
        self.assertTrue(len(c_generator.__doc__) > 0)


def load_module():
    """Load the c_generator module.

    The module is located in a different directory from the test script,
    hence all the complication.
    """
    # Part of the reason to do this in a function is to keep Pylint
    # warnings local to this function at most.
    scripts_dir = os.path.join(os.path.dirname(__file__),
                               os.pardir, os.pardir, 'scripts')
    save_sys_path = sys.path
    try:
        # pylint: disable=invalid-name,global-variable-undefined
        sys.path = [scripts_dir] + sys.path
        global c_generator
        c_generator = importlib.import_module('c_generator')
    finally:
        sys.path = save_sys_path

if __name__ == '__main__':
    load_module()
    unittest.main()
