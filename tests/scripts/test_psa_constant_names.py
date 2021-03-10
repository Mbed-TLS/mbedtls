#!/usr/bin/env python3
"""Test the program psa_constant_names.
Gather constant names from header files and test cases. Compile a C program
to print out their numerical values, feed these numerical values to
psa_constant_names, and check that the output is the original name.
Return 0 if all test cases pass, 1 if the output was not always as expected,
or 1 (with a Python backtrace) if there was an operational error.
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
from collections import namedtuple
import os
import re
import subprocess
import sys

import scripts_path # pylint: disable=unused-import
from mbedtls_dev import c_build_helper
from mbedtls_dev import macro_collector

class ReadFileLineException(Exception):
    def __init__(self, filename, line_number):
        message = 'in {} at {}'.format(filename, line_number)
        super(ReadFileLineException, self).__init__(message)
        self.filename = filename
        self.line_number = line_number

class read_file_lines:
    # Dear Pylint, conventionally, a context manager class name is lowercase.
    # pylint: disable=invalid-name,too-few-public-methods
    """Context manager to read a text file line by line.

    ```
    with read_file_lines(filename) as lines:
        for line in lines:
            process(line)
    ```
    is equivalent to
    ```
    with open(filename, 'r') as input_file:
        for line in input_file:
            process(line)
    ```
    except that if process(line) raises an exception, then the read_file_lines
    snippet annotates the exception with the file name and line number.
    """
    def __init__(self, filename, binary=False):
        self.filename = filename
        self.line_number = 'entry'
        self.generator = None
        self.binary = binary
    def __enter__(self):
        self.generator = enumerate(open(self.filename,
                                        'rb' if self.binary else 'r'))
        return self
    def __iter__(self):
        for line_number, content in self.generator:
            self.line_number = line_number
            yield content
        self.line_number = 'exit'
    def __exit__(self, exc_type, exc_value, exc_traceback):
        if exc_type is not None:
            raise ReadFileLineException(self.filename, self.line_number) \
                from exc_value

class InputsForTest(macro_collector.PSAMacroEnumerator):
    # pylint: disable=too-many-instance-attributes
    """Accumulate information about macros to test.

    This includes macro names as well as information about their arguments
    when applicable.
    """

    def __init__(self):
        super().__init__()
        self.all_declared = set()
        # Sets of names per type
        self.statuses.add('PSA_SUCCESS')
        self.algorithms.add('0xffffffff')
        self.ecc_curves.add('0xff')
        self.dh_groups.add('0xff')
        self.key_types.add('0xffff')
        self.key_usage_flags.add('0x80000000')

        # Hard-coded values for unknown algorithms
        #
        # These have to have values that are correct for their respective
        # PSA_ALG_IS_xxx macros, but are also not currently assigned and are
        # not likely to be assigned in the near future.
        self.hash_algorithms.add('0x020000fe') # 0x020000ff is PSA_ALG_ANY_HASH
        self.mac_algorithms.add('0x03007fff')
        self.ka_algorithms.add('0x09fc0000')
        self.kdf_algorithms.add('0x080000ff')
        # For AEAD algorithms, the only variability is over the tag length,
        # and this only applies to known algorithms, so don't test an
        # unknown algorithm.

        # Identifier prefixes
        self.table_by_prefix = {
            'ERROR': self.statuses,
            'ALG': self.algorithms,
            'ECC_CURVE': self.ecc_curves,
            'DH_GROUP': self.dh_groups,
            'KEY_TYPE': self.key_types,
            'KEY_USAGE': self.key_usage_flags,
        }
        # Test functions
        self.table_by_test_function = {
            # Any function ending in _algorithm also gets added to
            # self.algorithms.
            'key_type': [self.key_types],
            'block_cipher_key_type': [self.key_types],
            'stream_cipher_key_type': [self.key_types],
            'ecc_key_family': [self.ecc_curves],
            'ecc_key_types': [self.ecc_curves],
            'dh_key_family': [self.dh_groups],
            'dh_key_types': [self.dh_groups],
            'hash_algorithm': [self.hash_algorithms],
            'mac_algorithm': [self.mac_algorithms],
            'cipher_algorithm': [],
            'hmac_algorithm': [self.mac_algorithms],
            'aead_algorithm': [self.aead_algorithms],
            'key_derivation_algorithm': [self.kdf_algorithms],
            'key_agreement_algorithm': [self.ka_algorithms],
            'asymmetric_signature_algorithm': [],
            'asymmetric_signature_wildcard': [self.algorithms],
            'asymmetric_encryption_algorithm': [],
            'other_algorithm': [],
        }
        self.arguments_for['mac_length'] += ['1', '63']
        self.arguments_for['min_mac_length'] += ['1', '63']
        self.arguments_for['tag_length'] += ['1', '63']
        self.arguments_for['min_tag_length'] += ['1', '63']

    def get_names(self, type_word):
        """Return the set of known names of values of the given type."""
        return {
            'status': self.statuses,
            'algorithm': self.algorithms,
            'ecc_curve': self.ecc_curves,
            'dh_group': self.dh_groups,
            'key_type': self.key_types,
            'key_usage': self.key_usage_flags,
        }[type_word]

    # Regex for interesting header lines.
    # Groups: 1=macro name, 2=type, 3=argument list (optional).
    _header_line_re = \
        re.compile(r'#define +' +
                   r'(PSA_((?:(?:DH|ECC|KEY)_)?[A-Z]+)_\w+)' +
                   r'(?:\(([^\n()]*)\))?')
    # Regex of macro names to exclude.
    _excluded_name_re = re.compile(r'_(?:GET|IS|OF)_|_(?:BASE|FLAG|MASK)\Z')
    # Additional excluded macros.
    _excluded_names = set([
        # Macros that provide an alternative way to build the same
        # algorithm as another macro.
        'PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG',
        'PSA_ALG_FULL_LENGTH_MAC',
        # Auxiliary macro whose name doesn't fit the usual patterns for
        # auxiliary macros.
        'PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG_CASE',
    ])
    def parse_header_line(self, line):
        """Parse a C header line, looking for "#define PSA_xxx"."""
        m = re.match(self._header_line_re, line)
        if not m:
            return
        name = m.group(1)
        self.all_declared.add(name)
        if re.search(self._excluded_name_re, name) or \
           name in self._excluded_names:
            return
        dest = self.table_by_prefix.get(m.group(2))
        if dest is None:
            return
        dest.add(name)
        if m.group(3):
            self.argspecs[name] = self._argument_split(m.group(3))

    _nonascii_re = re.compile(rb'[^\x00-\x7f]+')
    def parse_header(self, filename):
        """Parse a C header file, looking for "#define PSA_xxx"."""
        with read_file_lines(filename, binary=True) as lines:
            for line in lines:
                line = re.sub(self._nonascii_re, rb'', line).decode('ascii')
                self.parse_header_line(line)

    _macro_identifier_re = re.compile(r'[A-Z]\w+')
    def generate_undeclared_names(self, expr):
        for name in re.findall(self._macro_identifier_re, expr):
            if name not in self.all_declared:
                yield name

    def accept_test_case_line(self, function, argument):
        #pylint: disable=unused-argument
        undeclared = list(self.generate_undeclared_names(argument))
        if undeclared:
            raise Exception('Undeclared names in test case', undeclared)
        return True

    def add_test_case_line(self, function, argument):
        """Parse a test case data line, looking for algorithm metadata tests."""
        sets = []
        if function.endswith('_algorithm'):
            sets.append(self.algorithms)
            if function == 'key_agreement_algorithm' and \
               argument.startswith('PSA_ALG_KEY_AGREEMENT('):
                # We only want *raw* key agreement algorithms as such, so
                # exclude ones that are already chained with a KDF.
                # Keep the expression as one to test as an algorithm.
                function = 'other_algorithm'
        sets += self.table_by_test_function[function]
        if self.accept_test_case_line(function, argument):
            for s in sets:
                s.add(argument)

    # Regex matching a *.data line containing a test function call and
    # its arguments. The actual definition is partly positional, but this
    # regex is good enough in practice.
    _test_case_line_re = re.compile(r'(?!depends_on:)(\w+):([^\n :][^:\n]*)')
    def parse_test_cases(self, filename):
        """Parse a test case file (*.data), looking for algorithm metadata tests."""
        with read_file_lines(filename) as lines:
            for line in lines:
                m = re.match(self._test_case_line_re, line)
                if m:
                    self.add_test_case_line(m.group(1), m.group(2))

def gather_inputs(headers, test_suites, inputs_class=InputsForTest):
    """Read the list of inputs to test psa_constant_names with."""
    inputs = inputs_class()
    for header in headers:
        inputs.parse_header(header)
    for test_cases in test_suites:
        inputs.parse_test_cases(test_cases)
    inputs.gather_arguments()
    return inputs

def run_c(type_word, expressions, include_path=None, keep_c=False):
    """Generate and run a program to print out numerical values of C expressions."""
    if type_word == 'status':
        cast_to = 'long'
        printf_format = '%ld'
    else:
        cast_to = 'unsigned long'
        printf_format = '0x%08lx'
    return c_build_helper.get_c_expression_values(
        cast_to, printf_format,
        expressions,
        caller='test_psa_constant_names.py for {} values'.format(type_word),
        file_label=type_word,
        header='#include <psa/crypto.h>',
        include_path=include_path,
        keep_c=keep_c
    )

NORMALIZE_STRIP_RE = re.compile(r'\s+')
def normalize(expr):
    """Normalize the C expression so as not to care about trivial differences.

    Currently "trivial differences" means whitespace.
    """
    return re.sub(NORMALIZE_STRIP_RE, '', expr)

def collect_values(inputs, type_word, include_path=None, keep_c=False):
    """Generate expressions using known macro names and calculate their values.

    Return a list of pairs of (expr, value) where expr is an expression and
    value is a string representation of its integer value.
    """
    names = inputs.get_names(type_word)
    expressions = sorted(inputs.generate_expressions(names))
    values = run_c(type_word, expressions,
                   include_path=include_path, keep_c=keep_c)
    return expressions, values

class Tests:
    """An object representing tests and their results."""

    Error = namedtuple('Error',
                       ['type', 'expression', 'value', 'output'])

    def __init__(self, options):
        self.options = options
        self.count = 0
        self.errors = []

    def run_one(self, inputs, type_word):
        """Test psa_constant_names for the specified type.

        Run the program on the names for this type.
        Use the inputs to figure out what arguments to pass to macros that
        take arguments.
        """
        expressions, values = collect_values(inputs, type_word,
                                             include_path=self.options.include,
                                             keep_c=self.options.keep_c)
        output = subprocess.check_output([self.options.program, type_word] +
                                         values)
        outputs = output.decode('ascii').strip().split('\n')
        self.count += len(expressions)
        for expr, value, output in zip(expressions, values, outputs):
            if self.options.show:
                sys.stdout.write('{} {}\t{}\n'.format(type_word, value, output))
            if normalize(expr) != normalize(output):
                self.errors.append(self.Error(type=type_word,
                                              expression=expr,
                                              value=value,
                                              output=output))

    def run_all(self, inputs):
        """Run psa_constant_names on all the gathered inputs."""
        for type_word in ['status', 'algorithm', 'ecc_curve', 'dh_group',
                          'key_type', 'key_usage']:
            self.run_one(inputs, type_word)

    def report(self, out):
        """Describe each case where the output is not as expected.

        Write the errors to ``out``.
        Also write a total.
        """
        for error in self.errors:
            out.write('For {} "{}", got "{}" (value: {})\n'
                      .format(error.type, error.expression,
                              error.output, error.value))
        out.write('{} test cases'.format(self.count))
        if self.errors:
            out.write(', {} FAIL\n'.format(len(self.errors)))
        else:
            out.write(' PASS\n')

HEADERS = ['psa/crypto.h', 'psa/crypto_extra.h', 'psa/crypto_values.h']
TEST_SUITES = ['tests/suites/test_suite_psa_crypto_metadata.data']

def main():
    parser = argparse.ArgumentParser(description=globals()['__doc__'])
    parser.add_argument('--include', '-I',
                        action='append', default=['include'],
                        help='Directory for header files')
    parser.add_argument('--keep-c',
                        action='store_true', dest='keep_c', default=False,
                        help='Keep the intermediate C file')
    parser.add_argument('--no-keep-c',
                        action='store_false', dest='keep_c',
                        help='Don\'t keep the intermediate C file (default)')
    parser.add_argument('--program',
                        default='programs/psa/psa_constant_names',
                        help='Program to test')
    parser.add_argument('--show',
                        action='store_true',
                        help='Keep the intermediate C file')
    parser.add_argument('--no-show',
                        action='store_false', dest='show',
                        help='Don\'t show tested values (default)')
    options = parser.parse_args()
    headers = [os.path.join(options.include[0], h) for h in HEADERS]
    inputs = gather_inputs(headers, TEST_SUITES)
    tests = Tests(options)
    tests.run_all(inputs)
    tests.report(sys.stdout)
    if tests.errors:
        sys.exit(1)

if __name__ == '__main__':
    main()
