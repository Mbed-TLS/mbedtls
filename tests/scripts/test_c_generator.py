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
import io
import os
import sys
import unittest

# The file c_generator.py is not in the same directory. To make this testing
# program self-contained, go and look for it in ../../scripts. This is done
# below with C = load_module().
# # import c_generator as C


class OptionsTest(unittest.TestCase):
    """Test the exact rendering of a snippet under varying options."""
    # pylint: disable=invalid-name,missing-docstring

    def assertSnippet(self, snippet, presented_output, **kwargs):
        stream = io.StringIO()
        snippet.output(stream, **kwargs)
        expected_output = presented_output.lstrip('\n').rstrip(' ')
        self.assertEqual(stream.getvalue(), expected_output)

    def test_default_line(self):
        self.assertSnippet(C.Simple('hello'), 'hello;\n')

    def test_indent_spaces(self):
        self.assertSnippet(C.Simple('hello'), '    hello;\n', indent='    ')

    def test_indent_tab(self):
        self.assertSnippet(C.Simple('hello'), '\thello;\n', indent='\t')

    def test_default_block(self):
        self.assertSnippet(C.Block(C.Simple('hello'), C.Simple('world')), """
{
    hello;
    world;
}
        """)

    def test_option_indent(self):
        self.assertSnippet(C.Block(C.Simple('hello'), C.Simple('world')), """
{
   hello;
   world;
}
        """, options=C.Options(indent=3))

    def test_option_indent_nested(self):
        self.assertSnippet(C.Block(C.Block(C.Simple('hello'))), """
{
   {
      hello;
   }
}
        """, options=C.Options(indent=3))

    def test_indent_and_option_indent(self):
        self.assertSnippet(C.Block(C.Block(C.Simple('hello'))), """
  {
     {
        hello;
     }
  }
        """, options=C.Options(indent=3), indent='  ')


class SnippetTest(unittest.TestCase):
    """Test the exact rendering of a snippet under default options."""
    # pylint: disable=invalid-name,missing-docstring

    def assertSnippet(self, snippet, presented_output):
        stream = io.StringIO()
        snippet.output(stream)
        expected_output = presented_output.lstrip('\n').rstrip(' ')
        self.assertEqual(stream.getvalue(), expected_output)

    def test_simple(self):
        self.assertSnippet(C.Simple('hello'), 'hello;\n')

    def test_simple_leading_space(self):
        self.assertSnippet(C.Simple(' hello'), 'hello;\n')

    def test_simple_trailing_space(self):
        self.assertSnippet(C.Simple('hello '), 'hello;\n')

    def test_return_none(self):
        self.assertSnippet(C.Return(None), 'return;\n')

    def test_return_value(self):
        self.assertSnippet(C.Return('foo'), 'return( foo );\n')

    def test_block_empty(self):
        self.assertSnippet(C.Block(), """
{
}
        """)

    def test_block_simple(self):
        self.assertSnippet(C.Block(C.Simple('hello'), C.Simple('world')), """
{
    hello;
    world;
}
        """)

    def test_block_nested(self):
        self.assertSnippet(C.Block(C.Simple('hello'),
                                   C.Block(C.Simple('nested')),
                                   C.Simple('world')), """
{
    hello;
    {
        nested;
    }
    world;
}
        """)

    def test_block_multiple(self):
        self.assertSnippet(C.Block(C.Block(C.Simple('nested')),
                                   C.Block(C.Simple('again')),
                                   C.Block()), """
{
    {
        nested;
    }
    {
        again;
    }
    {
    }
}
        """)



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
        return importlib.import_module('c_generator')
    finally:
        sys.path = save_sys_path

if __name__ == '__main__':
    C = load_module()
    unittest.main()
