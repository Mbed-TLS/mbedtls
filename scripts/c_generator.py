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

Unit tests are in ``../tests/scripts/test_c_generator.py``.
"""

from typing import List, Optional, Sequence, Tuple # pylint: disable=unused-import


class Writable:
    """Abstract class for typing hints."""
    # pylint: disable=too-few-public-methods
    def write(self, text: str) -> None:
        raise NotImplementedError


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


class Block(Snippet):
    """A code block (statements between braces)."""

    def __init__(self, *content) -> None:
        """A block statement.

        The arguments are the statements or pseudo-statements to put inside
        the block.
        """
        super().__init__()
        self.content = list(content)

    def output(self, stream: Writable,
               options: Options = DEFAULT_OPTIONS, indent: str = '') -> None: # pylint: disable=bad-whitespace
        more_indent = indent + ' ' * options.indent
        self.output_line(stream, indent, '{')
        for item in self.content:
            item.output(stream, options, more_indent)
        self.output_line(stream, indent, '}')
