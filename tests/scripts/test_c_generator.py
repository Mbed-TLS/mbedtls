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
import operator
import os
import sys
import unittest

# The file c_generator.py is not in the same directory. To make this testing
# program self-contained, go and look for it in ../../scripts. This is done
# below with C = load_module().
# # import c_generator as C


class OptionsTest(unittest.TestCase):
    """Test the exact rendering of a snippet under varying options."""
    # pylint: disable=invalid-name,missing-docstring,too-many-public-methods

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


class ConstructionTest(unittest.TestCase):
    """Test get and set methods on snippets."""
    # pylint: disable=invalid-name,missing-docstring,too-many-public-methods

    @classmethod
    def get_block_structure(cls, snippet):
        if isinstance(snippet, C.Block):
            return [cls.get_block_structure(elt) for elt in snippet]
        elif isinstance(snippet, C.Simple):
            return snippet.get_content()
        else:
            return snippet

    def assertBlock(self, block, expected):
        """Check a nested structure of blocks and simple statements.

        block must be a C.Snippet constructed from C.Block and C.Simple only.

        expected describes the expected structure of the block, using lists
        for blocks and strings for simple statements.

        For example,
            C.Block(C.Simple('foo'), C.Block(), C.Block('hello', 'world'))
        corresponds to
            ['foo', [], ['hello', 'world']
        """
        self.assertEqual(self.get_block_structure(block), expected)

    def test_simple_get_initial(self):
        c = C.Simple('initial')
        self.assertEqual(c.get_content(), 'initial')

    def test_simple_set_get(self):
        c = C.Simple('initial')
        c.set_content('updated')
        self.assertEqual(c.get_content(), 'updated')
        c.set_content('wibble')
        self.assertEqual(c.get_content(), 'wibble')

    def test_simple_get_initial_stripped(self):
        c = C.Simple('  initial  ')
        self.assertEqual(c.get_content(), 'initial')

    def test_simple_set_get_stripped(self):
        c = C.Simple('initial')
        c.set_content('  updated  ')
        self.assertEqual(c.get_content(), 'updated')
        c.set_content('  wibble  ')
        self.assertEqual(c.get_content(), 'wibble')

    def test_block_len_0(self):
        block = C.Block()
        self.assertEqual(len(block), 0)

    def test_block_len_1_simple(self):
        block = C.Block(C.Simple('one'))
        self.assertEqual(len(block), 1)

    def test_block_len_1_nested(self):
        block = C.Block(C.Block())
        self.assertEqual(len(block), 1)

    def test_block_len_2_simple(self):
        block = C.Block(C.Simple('one'), C.Simple('two'))
        self.assertEqual(len(block), 2)

    def test_block_len_2_nested_0(self):
        block = C.Block(C.Simple('one'),
                        C.Block())
        self.assertEqual(len(block), 2)

    def test_block_len_2_nested_2(self):
        block = C.Block(C.Simple('one'),
                        C.Block(C.Simple('foo'), C.Simple('bar')))
        self.assertEqual(len(block), 2)

    def test_block_getitem_good(self):
        block = C.Block(C.Simple('zero'),
                        C.Simple('one'),
                        C.Block(C.Simple('foo'), C.Simple('bar')),
                        C.Simple('three'))
        self.assertEqual(block[0].get_content(), 'zero')
        self.assertEqual(block[1].get_content(), 'one')
        self.assertEqual(block[2][0].get_content(), 'foo')
        self.assertEqual(block[2][1].get_content(), 'bar')
        self.assertEqual(block[3].get_content(), 'three')

    def test_block_getitem_range(self):
        self.assertRaises(IndexError, operator.getitem,
                          C.Block(), 0)
        self.assertRaises(IndexError, operator.getitem,
                          C.Block(C.Simple('')), 1)
        self.assertRaises(IndexError, operator.getitem,
                          C.Block(C.Simple(''), C.Simple('')), 2)

    def test_block_getitem_type(self):
        self.assertRaises(TypeError, operator.getitem,
                          C.Block(C.Simple('zero'), C.Simple('one')), 0.5)

    def test_block_setitem_overwrite(self):
        block = C.Block(C.Simple('foo 0'), C.Simple('foo 1'))
        self.assertEqual(block[0].get_content(), 'foo 0')
        self.assertEqual(block[1].get_content(), 'foo 1')
        block[0] = C.Simple('bar 0')
        self.assertEqual(block[0].get_content(), 'bar 0')
        self.assertEqual(block[1].get_content(), 'foo 1')
        block[1] = C.Simple('bar 1')
        self.assertEqual(block[0].get_content(), 'bar 0')
        self.assertEqual(block[1].get_content(), 'bar 1')

    def test_block_setitem_range(self):
        self.assertRaises(IndexError, operator.setitem,
                          C.Block(), 0, C.Block())
        self.assertRaises(IndexError, operator.setitem,
                          C.Block(C.Simple('')), 1, C.Block())
        self.assertRaises(IndexError, operator.setitem,
                          C.Block(C.Simple(''), C.Simple('')), 2, C.Block())

    def test_block_delitem_first(self):
        block = C.Block(C.Simple('zero'), C.Simple('one'), C.Simple('two'))
        del block[0]
        self.assertEqual(len(block), 2)
        self.assertEqual(block[0].get_content(), 'one')
        self.assertEqual(block[1].get_content(), 'two')

    def test_block_delitem_middle(self):
        block = C.Block(C.Simple('zero'), C.Simple('one'), C.Simple('two'))
        del block[1]
        self.assertEqual(len(block), 2)
        self.assertEqual(block[0].get_content(), 'zero')
        self.assertEqual(block[1].get_content(), 'two')

    def test_block_delitem_last(self):
        block = C.Block(C.Simple('zero'), C.Simple('one'), C.Simple('two'))
        del block[2]
        self.assertEqual(len(block), 2)
        self.assertEqual(block[0].get_content(), 'zero')
        self.assertEqual(block[1].get_content(), 'one')

    def test_block_delitem_slice(self):
        block = C.Block(C.Simple('zero'), C.Simple('one'), C.Simple('two'),
                        C.Simple('three'), C.Simple('four'))
        del block[1:3]
        self.assertEqual(len(block), 3)
        self.assertEqual(block[0].get_content(), 'zero')
        self.assertEqual(block[1].get_content(), 'three')
        self.assertEqual(block[2].get_content(), 'four')

    def test_block_delitem_range(self):
        self.assertRaises(IndexError, operator.delitem,
                          C.Block(), 0)
        self.assertRaises(IndexError, operator.delitem,
                          C.Block(C.Simple('')), 1)
        self.assertRaises(IndexError, operator.delitem,
                          C.Block(C.Simple(''), C.Simple('')), 2)

    def test_block_iter_0(self):
        self.assertRaises(StopIteration, next, iter(C.Block()))

    def test_block_iter_2(self):
        it = iter(C.Block(C.Simple('zero'), C.Simple('one')))
        self.assertEqual(next(it).get_content(), 'zero')
        self.assertEqual(next(it).get_content(), 'one')
        self.assertRaises(StopIteration, next, it)

    def test_block_empty_plus_simple(self):
        block0 = C.Block()
        block = block0 + C.Simple('wibble')
        self.assertBlock(block0, [])
        self.assertBlock(block, ['wibble'])

    def test_block_1_plus_simple(self):
        block0 = C.Block(C.Simple('foo'))
        block = block0 + C.Simple('wibble')
        self.assertBlock(block0, ['foo'])
        self.assertBlock(block, ['foo', 'wibble'])

    def test_block_2_plus_simple(self):
        block0 = C.Block(C.Simple('foo'), C.Simple('bar'))
        block = block0 + C.Simple('wibble')
        self.assertBlock(block0, ['foo', 'bar'])
        self.assertBlock(block, ['foo', 'bar', 'wibble'])

    def test_block_empty_plus_block(self):
        block0 = C.Block()
        block = block0 + C.Block(C.Simple('wibble'), C.Simple('wobble'))
        self.assertBlock(block0, [])
        self.assertBlock(block, ['wibble', 'wobble'])

    def test_block_1_plus_block(self):
        block0 = C.Block(C.Simple('foo'))
        block = block0 + C.Block(C.Simple('wibble'), C.Simple('wobble'))
        self.assertBlock(block0, ['foo'])
        self.assertBlock(block, ['foo', 'wibble', 'wobble'])

    def test_block_2_plus_block(self):
        block0 = C.Block(C.Simple('foo'), C.Simple('bar'))
        block = block0 + C.Block(C.Simple('wibble'), C.Simple('wobble'))
        self.assertBlock(block0, ['foo', 'bar'])
        self.assertBlock(block, ['foo', 'bar', 'wibble', 'wobble'])

    def test_block_1_plus_derived_block(self):
        block0 = C.Block(C.Simple('foo'))
        class MyBlock(C.Block):
            # pylint: disable=too-few-public-methods
            pass
        block = block0 + MyBlock(C.Simple('wibble'), C.Simple('wobble'))
        self.assertBlock(block0, ['foo'])
        self.assertBlock(block, ['foo', 'wibble', 'wobble'])

    def test_block_empty_plus_equal_simple(self):
        block = C.Block()
        block += C.Simple('wibble')
        self.assertBlock(block, ['wibble'])

    def test_block_1_plus_equal_simple(self):
        block = C.Block(C.Simple('foo'))
        block += C.Simple('wibble')
        self.assertBlock(block, ['foo', 'wibble'])

    def test_block_2_plus_equal_simple(self):
        block = C.Block(C.Simple('foo'), C.Simple('bar'))
        block += C.Simple('wibble')
        self.assertBlock(block, ['foo', 'bar', 'wibble'])

    def test_block_empty_plus_equal_block(self):
        block = C.Block()
        block += C.Block(C.Simple('wibble'), C.Simple('wobble'))
        self.assertBlock(block, ['wibble', 'wobble'])

    def test_block_1_plus_equal_block(self):
        block = C.Block(C.Simple('foo'))
        block += C.Block(C.Simple('wibble'), C.Simple('wobble'))
        self.assertBlock(block, ['foo', 'wibble', 'wobble'])

    def test_block_2_plus_equal_block(self):
        block = C.Block(C.Simple('foo'), C.Simple('bar'))
        block += C.Block(C.Simple('wibble'), C.Simple('wobble'))
        self.assertBlock(block, ['foo', 'bar', 'wibble', 'wobble'])

    def test_block_1_plus_equal_derived_block(self):
        block = C.Block(C.Simple('foo'))
        class MyBlock(C.Block):
            # pylint: disable=too-few-public-methods
            pass
        block += MyBlock(C.Simple('wibble'), C.Simple('wobble'))
        self.assertBlock(block, ['foo', 'wibble', 'wobble'])

    def test_block_append_simple(self):
        block = C.Block()
        block.append(C.Simple('one'))
        self.assertBlock(block, ['one'])
        block.append(C.Simple('two'))
        self.assertBlock(block, ['one', 'two'])

    def test_block_append_block_0(self):
        block = C.Block()
        block.append(C.Block())
        self.assertBlock(block, [[]])
        block.append(C.Block(C.Simple('foo')))
        self.assertBlock(block, [[], ['foo']])

    def test_block_copy_0_append_original(self):
        block0 = C.Block()
        block1 = block0.copy()
        block0.append('foo')
        self.assertBlock(block0, ['foo'])
        self.assertBlock(block1, [])

    def test_block_copy_0_append_copy(self):
        block0 = C.Block()
        block1 = block0.copy()
        block1.append('bar')
        self.assertBlock(block0, [])
        self.assertBlock(block1, ['bar'])

    def test_block_copy_0_append_both(self):
        block0 = C.Block()
        block1 = block0.copy()
        block0.append('foo')
        block1.append('bar')
        self.assertBlock(block0, ['foo'])
        self.assertBlock(block1, ['bar'])

    def test_block_copy_is_shallow(self):
        block0 = C.Block(C.Block(C.Simple('foo')), C.Simple('wibble'))
        block1 = block0.copy()
        block1[0][0] = C.Simple('bar')
        block1[1] = C.Simple('wobble')
        self.assertBlock(block0, [['bar'], 'wibble'])
        self.assertBlock(block1, [['bar'], 'wobble'])


class SnippetTest(unittest.TestCase):
    """Test the exact rendering of a snippet under default options."""
    # pylint: disable=invalid-name,missing-docstring,too-many-public-methods

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

    def test_comment_empty(self):
        self.assertSnippet(C.Comment(), '')

    def test_comment_1(self):
        self.assertSnippet(C.Comment('hello'), '/* hello */\n')

    def test_comment_2(self):
        self.assertSnippet(C.Comment('hello', 'world'), """
/* hello
 * world
 */
        """)

    def test_block_comment(self):
        self.assertSnippet(C.Block(C.Comment('hello', 'world')), """
{
    /* hello
     * world
     */
}
        """)

    def test_directive_foo(self):
        self.assertSnippet(C.Directive('foo'),
                           '#foo\n')

    def test_directive_define(self):
        self.assertSnippet(C.Directive('define', 'FOO', '42'),
                           '#define FOO 42\n')

    def test_directive_multiline(self):
        self.assertSnippet(
            C.Directive('define', 'FOO', 'one \ntwo\nthree'),
            """
#define FOO one \\
two\\
three
            """)

    def test_block_directive(self):
        self.assertSnippet(C.Block(C.Directive('foo'), C.Simple('hello')), """
{
#foo
    hello;
}
        """)

    def test_block_directive_multiline(self):
        self.assertSnippet(
            C.Block(C.Directive('define', 'FOO', 'one \ntwo\nthree'),
                    C.Simple('hello')),
            """
{
#define FOO one \\
two\\
three
    hello;
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
