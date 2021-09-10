#!/usr/bin/env python3
"""Report on structure types defined in Mbed TLS headers.

This script uses the clang python bindings (``pip3 install --user clang``).
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

import argparse
import collections
import glob
import os
import re
import sys
from typing import Dict, FrozenSet, List, Optional

import clang.cindex #type: ignore
from clang.cindex import Cursor, SourceLocation, TranslationUnit
from clang.cindex import CursorKind, TypeKind

from mbedtls_dev import typing_util


class Ast:
    """Abstract representation of the source code."""

    def __init__(self, options) -> None:
        """Prepare for analysis of C source files."""
        if options.clang_library_file:
            clang.cindex.Config.set_library_file(options.clang_library_file)
        self.parse_options = []
        if options.target:
            self.parse_options += ['-target', options.target]
        for d in options.include:
            self.parse_options.append('-I' + d)
        for d in options.define:
            self.parse_options.append('-D' + d)
        self.index = clang.cindex.Index.create()
        self.files = {} #type: Dict[str, TranslationUnit]
        # fields[TYPE_OR_STRUCT_NAME][FIELD_NAME]
        self.fields = {} #type: Dict[str, Dict[str, Cursor]]

    def load(self, *filenames: str) -> None:
        """Load the AST of the given source files."""
        for filename in filenames:
            self.files[filename] = self.index.parse(filename,
                                                    self.parse_options)

    INTERESTING_FILE_RE = re.compile(r'(?:.*/)?(mbedtls|psa)/[^/]*\.h\Z')
    def in_interesting_file(self, location: SourceLocation) -> bool:
        """Whether the given location is in a file that should be analyzed.

        This function detects Mbed TLS headers.
        """
        if not hasattr(location.file, 'name'):
            # Some artificial nodes have associated no file name.
            # Let's hope they're not important.
            return True
        filename = location.file.name
        if self.INTERESTING_FILE_RE.match(filename):
            return True
        return False

    def read_field_definitions(self, filenames: List[str]) -> None:
        """Parse structure field definitions in the given C source files (usually headers)."""
        self.load(*filenames)
        for filename in filenames:
            for node in self.files[filename].cursor.walk_preorder():
                if not self.in_interesting_file(node.location):
                    continue
                if node.kind == CursorKind.FIELD_DECL:
                    # If node.lexical_parent.spelling is an empty string,
                    # the field is inside an anonymous structure nested in
                    # another structure.
                    type_name = node.lexical_parent.spelling
                    if not type_name:
                        continue
                    self.fields.setdefault(type_name, collections.OrderedDict())
                    self.fields[type_name][node.spelling] = node

    def report_field(self, out: typing_util.Writable,
                     prefix: str, field: Cursor) -> None:
        """Print information about a structure field.

        Format: <type>.<name>,"FIELD",<size>,<alignment>,<offset>
        """
        # Empirically, offsetof is in bits, not bytes. To make the output
        # easier to read, convert to bytes (the same unit as size and
        # alignment), which means that bitfields will be located at their
        # first byte.
        offset = field.get_field_offsetof() // 8
        out.write('{},FIELD,{},{},{}\n'.format(
            prefix + field.spelling,
            field.type.get_size(), field.type.get_align(), offset
        ))

    def report_fields(self, out: typing_util.Writable) -> None:
        """Print information about fields of structures defined by the library."""
        for type_name in sorted(self.fields):
            for field in self.fields[type_name].values():
                self.report_field(out, type_name + '.', field)

    @staticmethod
    def header_files() -> List[str]:
        return [filename
                for pat in ['include/*/*.h', 'library/*.h']
                for filename in sorted(glob.glob(pat))]

    def run_analysis(self) -> None:
        self.read_field_definitions(self.header_files())
        self.report_fields(sys.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clang-library-file',
                        help="Alternative location of libclang.so")
    parser.add_argument('--define', '-D',
                        action='append',
                        default=['MBEDTLS_ALLOW_PRIVATE_ACCESS'],
                        help="Additional C preprocessor definition")
    parser.add_argument('--include', '-I',
                        action='append',
                        default=['include'],
                        help="Directory to add to the header include path")
    parser.add_argument('--target', '-t',
                        help="Target triple to build for (default: native build)")
    options = parser.parse_args()
    ast = Ast(options)
    ast.run_analysis()

if __name__ == '__main__':
    main()
