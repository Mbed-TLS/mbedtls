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

"""This module provides a simple interface to generate C source code.

The features in this module are tailored towards generating glue code
between Mbed TLS and PSA Crypto drivers. Suitability for any other purpose
is coincidental.

Construct C code snippets by building snippet objects and calling their
``output`` method. The ``output`` method takes the following arguments:
* ``stream``: an object with a ``write`` method that takes a string as
  argument, for example a file or ``io.StringIO()``.
* ``options`` (optional): an `Options` object to configure the presentation
  of the code.
* ``indent``: a string that is inserted at the beginning of each line.
Calling ``output`` on a snippet object calls ``stream.write()`` one or
more times to write the C code as a string.

The following snippet classes are available:
* `Simple`: a simple statement, or something like it such as a variable
  declaration. This can be anything that C terminates with a semicolon.
* `Return`: a ``return`` statement (with or without a value).
* `Block`: a block which is put between braces.
* `Comment`: a comment. It may contain multiple lines.
* `Directive`: a preprocessor directive.
* `PreprocessorConditional`: conditionally compiled code fragments.

Unit tests are in ``../tests/scripts/test_c_generator.py``.
"""

import copy
import re
import typing
from typing import Any, Iterator, List, Optional, Sequence, Tuple, Union # pylint: disable=unused-import
import typing_extensions #pylint: disable=import-error


class Writable(typing_extensions.Protocol):
    """Abstract class for typing hints."""
    # pylint: disable=no-self-use,too-few-public-methods,unused-argument
    def write(self, text: str) -> Any:
        ...


class Options:
    """Options for code generation."""
    # pylint: disable=too-few-public-methods

    def __init__(self, indent: int = 4) -> None: # pylint: disable=bad-whitespace
        """Set options for code generation.

        indent: the basic indent level.
        """
        self.indent = indent

DEFAULT_OPTIONS = Options()


class Snippet:
    """Abstract base class for multi-line snippets of C code."""

    def __init__(self) -> None:
        pass

    def simple_block_items(self) -> Optional[List['Snippet']]: #pylint: disable=no-self-use
        """Return the statements that make up this simple block, or None.

        If this is a simple block of statements that can be spliced into
        another block, return the list of statements. Otherwise return
        ``None``.
        """
        return None

    @staticmethod
    def output_line(stream: Writable, indent: str, *contents: str) -> None:
        content = ''.join(contents).rstrip()
        if content:
            stream.write(indent + content + '\n')
        else:
            stream.write('\n')

    def output(self, stream: Writable,
               options: Options = DEFAULT_OPTIONS, indent: str = '') -> None: # pylint: disable=bad-whitespace
        raise NotImplementedError


class Comment(Snippet):
    """A comment with its own line(s)."""

    def __init__(self, *lines: str) -> None:
        """A comment. Each argument is placed on its own line."""
        super().__init__()
        self.lines = [line.rstrip() for line in lines]

    def output(self, stream: Writable,
               options: Options = DEFAULT_OPTIONS, indent: str = '') -> None: # pylint: disable=bad-whitespace
        if len(self.lines) == 0:
            return
        elif len(self.lines) == 1:
            self.output_line(stream, indent, '/* ', self.lines[0].lstrip(), ' */')
        else:
            self.output_line(stream, indent, '/* ', self.lines[0])
            for line in self.lines[1:]:
                self.output_line(stream, indent, ' * ', line)
            self.output_line(stream, indent, ' */')


class Directive(Snippet):
    """A preprocessor directive."""

    def __init__(self, *parts: str) -> None:
        """A preprocessor directive.

        The arguments are joined with spaces. Typically the first argument is
        the directive and subsequent arguments are its parameters.

        Any newline character in an argument is replaced with backslash-newline.
        """
        super().__init__()
        self.parts = parts

    def output(self, stream: Writable,
               options: Options = DEFAULT_OPTIONS, indent: str = '') -> None: # pylint: disable=bad-whitespace
        text = ' '.join(self.parts)
        self.output_line(stream, '', '#' + text.replace('\n', '\\\n'))


class Simple(Snippet):
    """A simple statement or statement-like syntactic element.

    This can be, for example, an expression statement, a jump statement,
    or a declaration.
    """

    def __init__(self, content: str) -> None:
        """A simple statement.

        This can be anything that is normally written on a single line and
        terminated by a semicolon, for example an expression statement,
        a jump statement, or a declaration.

        Pass the content without the terminating semicolon.
        """
        super().__init__()
        self.set_content(content)

    def get_content(self) -> str:
        return self.content

    def set_content(self, content: str) -> None:
        self.content = content.strip()

    def output(self, stream: Writable,
               options: Options = DEFAULT_OPTIONS, indent: str = '') -> None: # pylint: disable=bad-whitespace
        self.output_line(stream, indent, self.content, ';')


class Return(Simple):
    """A return statement."""

    def __init__(self, what: Optional[str]) -> None:
        """A return statement.

        Pass a string containing the expression to calculate the return value,
        or `None` to return void.
        """
        if what is None:
            content = 'return'
        else:
            content = 'return( ' + what.strip() + ' )'
        super().__init__(content)


_Item = typing.TypeVar('_Item')
_SelfListLike = typing.TypeVar('_SelfListLike', bound='ListLike')

class ListLike(typing.Generic[_Item]):
    """Abstract class implementing a list-like behavior."""

    def __init__(self) -> None:
        self.items = [] #type: List[_Item]

    def normalize_item(self, item: _Item) -> _Item:
        """Return a normalized form of the given item."""
        raise NotImplementedError

    def copy(self: _SelfListLike) -> _SelfListLike:
        """Make a shallow copy of this snippet which is made of a list of items.

        The copy is not modified if the snippet itself is modified, but is
        modified if its items are modified.
        """
        new = copy.copy(self)
        new.items = copy.copy(self.items)
        return new

    def __len__(self) -> int:
        return len(self.items)

    def __getitem__(self, key: int) -> _Item:
        return self.items[key]

    def __iter__(self) -> Iterator[_Item]:
        # Python would automatically infer this from __getitem__.
        # But mypy doesn't: https://github.com/python/mypy/issues/2220
        return iter(self.items)

    def __setitem__(self, key: int, value: _Item) -> None:
        self.items[key] = self.normalize_item(value)

    def __delitem__(self, key: Union[int, slice]) -> None:
        del self.items[key]

    def append(self, elt: _Item) -> None:
        self.items.append(self.normalize_item(elt))


_SelfDecoratedBlock = typing.TypeVar('_SelfDecoratedBlock', bound='DecoratedBlock')

class DecoratedBlock(Snippet, ListLike[Snippet]):
    """A statement or definition containing a block.

    For example, a loop with its body, or a function definition.
    """

    def __init__(self, *content: Snippet) -> None:
        """A block statement.

        The arguments are the statements or pseudo-statements to put inside
        the block.
        """
        Snippet.__init__(self)
        self.items = list(content)

    def normalize_item(self, item: Snippet) -> Snippet: #pylint: disable=no-self-use
        return item

    def __add__(self: _SelfDecoratedBlock, other: Snippet) -> _SelfDecoratedBlock:
        """Return a new decorated block containing both arguments' content.

        If ``other`` is a `Block`, return a new block containing the elements
        of ``self`` followed by the elements of ``other``.
        Otherwise return a new block containing the elements of ``self``
        followed by ``other``.
        """
        new_block = self.copy()
        new_block += other
        return new_block

    def __iadd__(self: _SelfDecoratedBlock, other: Snippet) -> _SelfDecoratedBlock:
        """Add a block's content or a snippet to this block in place.

        If ``other`` is a `Block`, add its element to our list of elements.
        Otherwise append ``other`` to our list of elements.
        """
        items = other.simple_block_items()
        if items is not None:
            self.items += items
        else:
            self.items.append(other)
        return self

    def output_before(self, stream: Writable, options: Options, indent: str) -> None: # pylint: disable=bad-whitespace
        pass

    def output_after(self, stream: Writable, options: Options, indent: str) -> None: # pylint: disable=bad-whitespace
        pass

    def output(self, stream: Writable,
               options: Options = DEFAULT_OPTIONS, indent: str = '') -> None: # pylint: disable=bad-whitespace
        more_indent = indent + ' ' * options.indent
        self.output_before(stream, options, indent)
        self.output_line(stream, indent, '{')
        for item in self.items:
            item.output(stream, options, more_indent)
        self.output_line(stream, indent, '}')
        self.output_after(stream, options, indent)


class Block(DecoratedBlock):
    """A code block (statements between braces).

    Code blocks behave mostly like lists of statements (or more precisely
    snippets, including pseudo-statements such as comments). You can access or
    modify the ``N``th (pseudo-)statement (counting from 0) in the block
    ``b`` through ``b[N]``.

    If you add a block to another block, the trailing block is spliced into
    the original block: ``Block(a,b,c) + Block(d,e)`` is equivalent to
    ``Block(a,b,c,d,e)``, not to ``Block(a,b,c, Block(d,e))``. This doesn't
    happen with the ``append`` method or with assignment to a block element.
    Adding a snippet that isn't a block is equivalent to appending the snippet.
    """

    def simple_block_items(self):
        return self.items


class PreprocessorConditional(Snippet):
    """Code guarded by conditional compilation directives."""

    def __init__(self) -> None:
        """Start a conditionally compiled snippet (``#if ... #endif``)."""
        super().__init__()
        self.cases = [] #type: List[Tuple[str, Snippet]]
        self.default = None #type: Optional[Snippet]
        self.endif_comment = None #type: Optional[str]

    def add_case(self, condition: str, code: Snippet) -> None:
        """Append a case to the preprocessor if-else chain.

        * ``condition``: A preprocessor expression which is used as an
          ``#if`` condition.
        * ``code``: the code to use if ``condition`` is true.
        """
        self.cases.append((condition.strip(), code))

    def set_default(self, code: Snippet) -> None:
        """The code to execute in the ``#else`` part."""
        self.default = code

    def set_endif_comment(self, text: Optional[str]) -> None:
        """The text to use in a comment in ``#else`` and ``#endif``.

        If omitted or ``None``, the comment is taken from the conditions.
        """
        self.endif_comment = text

    @staticmethod
    def negate_condition(condition: str) -> str:
        """Return a slightly prettyfied version of ``!(condition)``."""
        m = re.match(r'(!\s*)?(\w+|defined *\( *\w+ *\)|defined +\w+)\Z',
                     condition)
        if m:
            if m.group(1):
                return m.group(2)
            else:
                return '!' + condition
        else:
            return '!(' + condition + ')'

    def output(self, stream: Writable,
               options: Options = DEFAULT_OPTIONS, indent: str = '') -> None: # pylint: disable=bad-whitespace
        if not self.cases:
            if self.default is not None:
                self.default.output(stream, options, indent)
            return
        condition, code = self.cases[0]
        self.output_line(stream, '',
                         '#if ' +
                         condition.replace('\n', '\\\n    '))
        code.output(stream, options, indent)
        for condition, code in self.cases[1:]:
            self.output_line(stream, '',
                             '#elif ' +
                             condition.replace('\n', '\\\n      '))
            code.output(stream, options, indent)
        if self.endif_comment is None:
            if self.default is None:
                condition = self.cases[-1][0]
            else:
                condition = ' && '.join([self.negate_condition(cond)
                                         for cond, _code in self.cases])
            endif_comment = (' /* ' +
                             re.sub(r'\s*\n\s*', ' ', condition) +
                             ' */')
        else:
            endif_comment = self.endif_comment.strip()
            if endif_comment:
                endif_comment = ' /* ' + endif_comment + ' */'
        if self.default is not None:
            self.output_line(stream, '', '#else' + endif_comment)
            self.default.output(stream, options, indent)
        self.output_line(stream, '', '#endif' + endif_comment)


class Switch(Snippet):
    """A switch statement.

    Fallthrough between cases is not supported.
    """

    def __init__(self, value: str) -> None:
        super().__init__()
        self.value = value
        self.cases = [] #type: List[Tuple[Sequence[str], Snippet]]
        self.default = None #type: Optional[Snippet]

    def add_case(self, values: Sequence[str], code: Snippet) -> None:
        self.cases.append(([value.strip() for value in values], code))

    def set_default(self, code: Snippet) -> None:
        self.default = code

    def output(self, stream: Writable,
               options: Options = DEFAULT_OPTIONS, indent: str = '') -> None: # pylint: disable=bad-whitespace
        case_indent = indent + ' ' * options.indent
        code_indent = case_indent + ' ' * options.indent
        self.output_line(stream, indent,
                         'switch( ', self.value.strip(), ' )')
        self.output_line(stream, indent, '{')
        items = [(['case ' + value for value in values], code)
                 for values, code in self.cases]
        if self.default is not None:
            items.append((['default'], self.default))
        for labels, code in items:
            for label in labels:
                self.output_line(stream, case_indent, label)
            self.output_line(stream, case_indent, '{')
            code.output(stream, options, code_indent)
            self.output_line(stream, case_indent, '}')
        self.output_line(stream, indent, '}')
