#!/usr/bin/env python3
"""Generate test data for bignum functions.

With no arguments, generate all test data. With non-option arguments,
generate only the specified files.
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
import itertools
import os
import posixpath
import re
import sys
from typing import Iterable, Iterator, Optional, Tuple, TypeVar

import scripts_path # pylint: disable=unused-import
from mbedtls_dev import build_tree
from mbedtls_dev import test_case

T = TypeVar('T') #pylint: disable=invalid-name

def hex_to_int(val):
    return int(val, 16) if val else 0

def quote_str(val):
    return "\"{}\"".format(val)


class BaseTarget:
    """Base target for test case generation.

    Attributes:
        count: Counter for test class.
        desc: Short description of test case.
        func: Function which the class generates tests for.
        gen_file: File to write generated tests to.
        title: Description of the test function/purpose.
    """
    count = 0
    desc = None
    func = None
    gen_file = ""
    title = None

    def __init__(self) -> None:
        type(self).count += 1

    @property
    def args(self) -> Iterable[str]:
        """Create list of arguments for test case."""
        return []

    @property
    def description(self) -> str:
        """Create a numbered test description."""
        return "{} #{} {}".format(self.title, self.count, self.desc)

    def create_test_case(self) -> test_case.TestCase:
        """Generate test case from the current object."""
        tc = test_case.TestCase()
        tc.set_description(self.description)
        tc.set_function(self.func)
        tc.set_arguments(self.args)

        return tc

    @classmethod
    def generate_tests(cls):
        """Generate test cases for the target subclasses."""
        for subclass in sorted(cls.__subclasses__(), key=lambda c: c.__name__):
            yield from subclass.generate_tests()


class BignumTarget(BaseTarget):
    """Target for bignum (mpi) test case generation."""
    gen_file = 'test_suite_mpi.generated'


class BignumOperation(BignumTarget):
    """Common features for test cases covering bignum operations.

    Attributes:
        symb: Symbol used for operation in description.
        input_vals: List of values used to generate test case args.
        input_cases: List of tuples containing test case inputs. This
            can be used to implement specific pairs of inputs.
    """
    symb = ""
    input_vals = [
        "", "0", "7b", "-7b",
        "0000000000000000123", "-0000000000000000123",
        "1230000000000000000", "-1230000000000000000"
    ]
    input_cases = []

    def __init__(self, val_l: str, val_r: str) -> None:
        super().__init__()

        self.arg_l = val_l
        self.arg_r = val_r
        self.int_l = hex_to_int(val_l)
        self.int_r = hex_to_int(val_r)

    @property
    def args(self):
        return [quote_str(self.arg_l), quote_str(self.arg_r), self.result]

    @property
    def description(self):
        desc = self.desc if self.desc else "{} {} {}".format(
            self.val_desc(self.arg_l),
            self.symb,
            self.val_desc(self.arg_r)
        )
        return "{} #{} {}".format(self.title, self.count, desc)

    @property
    def result(self) -> Optional[str]:
        return None

    @staticmethod
    def val_desc(val) -> str:
        """Generate description of the argument val."""
        if val == "":
            return "0 (null)"
        if val == "0":
            return "0 (1 limb)"

        if val[0] == "-":
            tmp = "negative"
            val = val[1:]
        else:
            tmp = "positive"
        if val[0] == "0":
            tmp += " with leading zero limb"
        elif len(val) > 10:
            tmp = "large " + tmp
        return tmp

    @classmethod
    def get_value_pairs(cls) -> Iterator[Tuple[str, ...]]:
        """Generate value pairs."""
        for pair in list(
            itertools.combinations(cls.input_vals, 2)
            ) + cls.input_cases:
            yield pair

    @classmethod
    def generate_tests(cls) -> Iterator[test_case.TestCase]:
        if cls.func is not None:
            # Generate tests for the current class
            for l_value, r_value in cls.get_value_pairs():
                cur_op = cls(l_value, r_value)
                yield cur_op.create_test_case()
        # Once current class completed, check descendants
        yield from super().generate_tests()


class BignumCmp(BignumOperation):
    """Target for bignum comparison test cases."""
    count = 0
    func = "mbedtls_mpi_cmp_mpi"
    title = "MPI compare"
    input_cases = [
        ("-2", "-3"),
        ("-2", "-2"),
        ("2b4", "2b5"),
        ("2b5", "2b6")
        ]

    def __init__(self, val_l, val_r):
        super().__init__(val_l, val_r)
        self._result = (self.int_l > self.int_r) - (self.int_l < self.int_r)
        self.symb = ["<", "==", ">"][self._result + 1]

    @property
    def result(self):
        return str(self._result)


class BignumCmpAbs(BignumCmp):
    """Target for abs comparison variant."""
    count = 0
    func = "mbedtls_mpi_cmp_abs"
    title = "MPI compare (abs)"

    def __init__(self, val_l, val_r):
        super().__init__(val_l.strip("-"), val_r.strip("-"))


class BignumAdd(BignumOperation):
    """Target for bignum addition test cases."""
    count = 0
    func = "mbedtls_mpi_add_mpi"
    title = "MPI add"
    input_cases = list(itertools.combinations(
        [
            "1c67967269c6", "9cde3",
            "-1c67967269c6", "-9cde3",
        ], 2
    ))

    def __init__(self, val_l, val_r):
        super().__init__(val_l, val_r)
        self.symb = "+"

    @property
    def result(self):
        return quote_str(hex(self.int_l + self.int_r).replace("0x", "", 1))


class TestGenerator:
    """Generate test data."""

    def __init__(self, options) -> None:
        self.test_suite_directory = self.get_option(options, 'directory',
                                                    'tests/suites')

    @staticmethod
    def get_option(options, name: str, default: T) -> T:
        value = getattr(options, name, None)
        return default if value is None else value

    def filename_for(self, basename: str) -> str:
        """The location of the data file with the specified base name."""
        return posixpath.join(self.test_suite_directory, basename + '.data')

    def write_test_data_file(self, basename: str,
                             test_cases: Iterable[test_case.TestCase]) -> None:
        """Write the test cases to a .data file.

        The output file is ``basename + '.data'`` in the test suite directory.
        """
        filename = self.filename_for(basename)
        test_case.write_data_file(filename, test_cases)

    # Note that targets whose names contain 'test_format' have their content
    # validated by `abi_check.py`.
    TARGETS = {
        subclass.gen_file: subclass.generate_tests for subclass in
        BaseTarget.__subclasses__()
    }

    def generate_target(self, name: str) -> None:
        test_cases = self.TARGETS[name]()
        self.write_test_data_file(name, test_cases)

def main(args):
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true',
                        help='List available targets and exit')
    parser.add_argument('--list-for-cmake', action='store_true',
                        help='Print \';\'-separated list of available targets and exit')
    parser.add_argument('--directory', metavar='DIR',
                        help='Output directory (default: tests/suites)')
    parser.add_argument('targets', nargs='*', metavar='TARGET',
                        help='Target file to generate (default: all; "-": none)')
    options = parser.parse_args(args)
    build_tree.chdir_to_root()
    generator = TestGenerator(options)
    if options.list:
        for name in sorted(generator.TARGETS):
            print(generator.filename_for(name))
        return
    # List in a cmake list format (i.e. ';'-separated)
    if options.list_for_cmake:
        print(';'.join(generator.filename_for(name)
                       for name in sorted(generator.TARGETS)), end='')
        return
    if options.targets:
        # Allow "-" as a special case so you can run
        # ``generate_bignum_tests.py - $targets`` and it works uniformly whether
        # ``$targets`` is empty or not.
        options.targets = [os.path.basename(re.sub(r'\.data\Z', r'', target))
                           for target in options.targets
                           if target != '-']
    else:
        options.targets = sorted(generator.TARGETS)
    for target in options.targets:
        generator.generate_target(target)

if __name__ == '__main__':
    main(sys.argv[1:])
