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

    Derive directly from this class when adding new file Targets, setting
    `target_basename`.

    Attributes:
        count: Counter for test cases from this class.
        case_description: Short description of the test case. This may be
            automatically generated using the class, or manually set.
        dependencies: A list of dependencies required for the test case.
        target_basename: Basename of file to write generated tests to. This
            should be specified in a child class of BaseTarget.
        test_function: Test function which the class generates cases for.
        test_name: A common name or description of the test function. This can
            be `test_function`, a clearer equivalent, or a short summary of the
            test function's purpose.
    """
    count = 0
    case_description = ""
    dependencies = [] # type: List[str]
    target_basename = ""
    test_function = ""
    test_name = ""

    def __new__(cls, *args, **kwargs):
        # pylint: disable=unused-argument
        cls.count += 1
        return super().__new__(cls)

    @abstractmethod
    def arguments(self) -> List[str]:
        """Get the list of arguments for the test case.

        Override this method to provide the list of arguments required for
        the `test_function`.

        Returns:
            List of arguments required for the test function.
        """
        raise NotImplementedError

    def description(self) -> str:
        """Create a test case description.

        Creates a description of the test case, including a name for the test
        function, a case number, and a description the specific test case.
        This should inform a reader what is being tested, and provide context
        for the test case.

        Returns:
            Description for the test case.
        """
        return "{} #{} {}".format(
            self.test_name, self.count, self.case_description
            ).strip()


    def create_test_case(self) -> test_case.TestCase:
        """Generate TestCase from the instance."""
        tc = test_case.TestCase()
        tc.set_description(self.description())
        tc.set_function(self.test_function)
        tc.set_arguments(self.arguments())
        tc.set_dependencies(self.dependencies)

        return tc

    @classmethod
    @abstractmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        """Generate test cases for the class test function.

        This will be called in classes where `test_function` is set.
        Implementations should yield TestCase objects, by creating instances
        of the class with appropriate input data, and then calling
        `create_test_case()` on each.
        """
        raise NotImplementedError

    @classmethod
    def generate_tests(cls) -> Iterator[test_case.TestCase]:
        """Generate test cases for the class and its subclasses.

        In classes with `test_function` set, `generate_function_tests()` is
        called to generate test cases first.

        In all classes, this method will iterate over its subclasses, and
        yield from `generate_tests()` in each. Calling this method on a class X
        will yield test cases from all classes derived from X.
        """
        if cls.test_function:
            yield from cls.generate_function_tests()
        for subclass in sorted(cls.__subclasses__(), key=lambda c: c.__name__):
            yield from subclass.generate_tests()


class TestGenerator:
    """Generate test data."""
    def __init__(self, options) -> None:
        self.test_suite_directory = getattr(options, 'directory')

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
    TARGETS = {} # type: Dict[str, Callable[..., Iterable[test_case.TestCase]]]

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
    parser.add_argument('--directory', default="tests/suites", metavar='DIR',
                        help='Output directory (default: tests/suites)')
    parser.add_argument('targets', nargs='*', metavar='TARGET',
                        default=sorted(generator_class.TARGETS),
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
    # Allow "-" as a special case so you can run
    # ``generate_xxx_tests.py - $targets`` and it works uniformly whether
    # ``$targets`` is empty or not.
    options.targets = [os.path.basename(re.sub(r'\.data\Z', r'', target))
                       for target in options.targets
                       if target != '-']
    for target in options.targets:
        generator.generate_target(target)
