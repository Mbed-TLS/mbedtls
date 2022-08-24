#!/usr/bin/env python3
"""Common test generation classes and main function.

These are used both by generate_psa_tests.py and generate_bignum_tests.py.
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
import os
import posixpath
import re

from abc import ABCMeta, abstractmethod
from typing import Callable, Dict, Iterable, Iterator, List, Type, TypeVar

from mbedtls_dev import build_tree
from mbedtls_dev import test_case

T = TypeVar('T') #pylint: disable=invalid-name


class BaseTarget(metaclass=ABCMeta):
    """Base target for test case generation.

    Attributes:
        count: Counter for test cases from this class.
        case_description: Short description of the test case. This may be
            automatically generated using the class, or manually set.
        target_basename: Basename of file to write generated tests to. This
            should be specified in a child class of BaseTarget.
        test_function: Test function which the class generates cases for.
        test_name: A common name or description of the test function. This can
            be the function's name, or a short summary of its purpose.
    """
    count = 0
    case_description = ""
    target_basename = ""
    test_function = ""
    test_name = ""

    def __init__(self) -> None:
        type(self).count += 1

    @abstractmethod
    def arguments(self) -> List[str]:
        """Get the list of arguments for the test case.

        Override this method to provide the list of arguments required for
        generating the test_function.

        Returns:
            List of arguments required for the test function.
        """
        pass

    def description(self) -> str:
        """Create a test description.

        Creates a description of the test case, including a name for the test
        function, and describing the specific test case. This should inform a
        reader of the purpose of the case. The case description may be
        generated in the class, or provided manually as needed.

        Returns:
            Description for the test case.
        """
        return "{} #{} {}".format(self.test_name, self.count, self.case_description)


    def create_test_case(self) -> test_case.TestCase:
        """Generate TestCase from the current object."""
        tc = test_case.TestCase()
        tc.set_description(self.description())
        tc.set_function(self.test_function)
        tc.set_arguments(self.arguments())

        return tc

    @classmethod
    @abstractmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        """Generate test cases for the test function.

        This will be called in classes where `test_function` is set.
        Implementations should yield TestCase objects, by creating instances
        of the class with appropriate input data, and then calling
        `create_test_case()` on each.
        """
        pass

    @classmethod
    def generate_tests(cls) -> Iterator[test_case.TestCase]:
        """Generate test cases for the class and its subclasses.

        In classes with `test_function` set, `generate_function_tests()` is
        used to generate test cases first.
        In all classes, this method will iterate over its subclasses, and
        yield from `generate_tests()` in each.

        Calling this method on a class X will yield test cases from all classes
        derived from X.
        """
        if cls.test_function:
            yield from cls.generate_function_tests()
        for subclass in sorted(cls.__subclasses__(), key=lambda c: c.__name__):
            yield from subclass.generate_tests()


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
    TARGETS = {} # type: Dict[str, Callable[..., test_case.TestCase]]

    def generate_target(self, name: str, *target_args) -> None:
        """Generate cases and write to data file for a target.

        For target callables which require arguments, override this function
        and pass these arguments using super() (see PSATestGenerator).
        """
        test_cases = self.TARGETS[name](*target_args)
        self.write_test_data_file(name, test_cases)

def main(args, generator_class: Type[TestGenerator] = TestGenerator):
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
    generator = generator_class(options)
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
        # ``generate_xxx_tests.py - $targets`` and it works uniformly whether
        # ``$targets`` is empty or not.
        options.targets = [os.path.basename(re.sub(r'\.data\Z', r'', target))
                           for target in options.targets
                           if target != '-']
    else:
        options.targets = sorted(generator.TARGETS)
    for target in options.targets:
        generator.generate_target(target)
