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

import itertools
import sys
from typing import Callable, Dict, Iterator, List, Optional, Tuple, TypeVar

import scripts_path # pylint: disable=unused-import
from mbedtls_dev import test_case
from mbedtls_dev import test_generation

T = TypeVar('T') #pylint: disable=invalid-name

def hex_to_int(val):
    return int(val, 16) if val else 0

def quote_str(val):
    return "\"{}\"".format(val)


class BignumTarget(test_generation.BaseTarget):
    """Target for bignum (mpi) test case generation."""
    target_basename = 'test_suite_mpi.generated'


class BignumOperation(BignumTarget):
    """Common features for test cases covering bignum operations.

    Attributes:
        symbol: Symbol used for operation in description.
        input_values: List of values to use as test case inputs.
        input_cases: List of tuples containing pairs of test case inputs. This
            can be used to implement specific pairs of inputs.
    """
    symbol = ""
    input_values = [
        "", "0", "7b", "-7b",
        "0000000000000000123", "-0000000000000000123",
        "1230000000000000000", "-1230000000000000000"
    ] # type: List[str]
    input_cases = [] # type: List[Tuple[str, ...]]

    def __init__(self, val_l: str, val_r: str) -> None:
        super().__init__()

        self.arg_l = val_l
        self.arg_r = val_r
        self.int_l = hex_to_int(val_l)
        self.int_r = hex_to_int(val_r)

    def arguments(self):
        return [quote_str(self.arg_l), quote_str(self.arg_r), self.result()]

    def description(self):
        if not self.case_description:
            self.case_description = "{} {} {}".format(
                self.value_description(self.arg_l),
                self.symbol,
                self.value_description(self.arg_r)
            )
        return super().description()

    def result(self) -> Optional[str]:
        return None

    @staticmethod
    def value_description(val) -> str:
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
        yield from itertools.combinations(cls.input_values, 2)
        yield from cls.input_cases

    @classmethod
    def generate_tests(cls) -> Iterator[test_case.TestCase]:
        if cls.test_function:
            # Generate tests for the current class
            for l_value, r_value in cls.get_value_pairs():
                cur_op = cls(l_value, r_value)
                yield cur_op.create_test_case()
        # Once current class completed, check descendants
        yield from super().generate_tests()


class BignumCmp(BignumOperation):
    """Target for bignum comparison test cases."""
    count = 0
    test_function = "mbedtls_mpi_cmp_mpi"
    test_name = "MPI compare"
    input_cases = [
        ("-2", "-3"),
        ("-2", "-2"),
        ("2b4", "2b5"),
        ("2b5", "2b6")
        ]

    def __init__(self, val_l, val_r):
        super().__init__(val_l, val_r)
        self._result = int(self.int_l > self.int_r) - int(self.int_l < self.int_r)
        self.symbol = ["<", "==", ">"][self._result + 1]

    def result(self):
        return str(self._result)


class BignumCmpAbs(BignumCmp):
    """Target for abs comparison variant."""
    count = 0
    test_function = "mbedtls_mpi_cmp_abs"
    test_name = "MPI compare (abs)"

    def __init__(self, val_l, val_r):
        super().__init__(val_l.strip("-"), val_r.strip("-"))


class BignumAdd(BignumOperation):
    """Target for bignum addition test cases."""
    count = 0
    test_function = "mbedtls_mpi_add_mpi"
    test_name = "MPI add"
    input_cases = list(itertools.combinations(
        [
            "1c67967269c6", "9cde3",
            "-1c67967269c6", "-9cde3",
        ], 2
    ))

    def __init__(self, val_l, val_r):
        super().__init__(val_l, val_r)
        self.symbol = "+"

    def result(self):
        return quote_str(hex(self.int_l + self.int_r).replace("0x", "", 1))


class BignumTestGenerator(test_generation.TestGenerator):
    """Test generator subclass including bignum targets."""
    TARGETS = {
        subclass.target_basename: subclass.generate_tests for subclass in
        test_generation.BaseTarget.__subclasses__()
    } # type: Dict[str, Callable[[], test_case.TestCase]]

if __name__ == '__main__':
    test_generation.main(sys.argv[1:], BignumTestGenerator)
