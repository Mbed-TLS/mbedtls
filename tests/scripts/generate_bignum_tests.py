#!/usr/bin/env python3
"""Generate test data for bignum functions.

With no arguments, generate all test data. With non-option arguments,
generate only the specified files.

Class structure:

Child classes of test_data_generation.BaseTarget (file targets) represent an output
file. These indicate where test cases will be written to, for all subclasses of
this target. Multiple file targets should not reuse a `target_basename`.

Each subclass derived from a file target can either be:
  - A concrete class, representing a test function, which generates test cases.
  - An abstract class containing shared methods and attributes, not associated
        with a test function. An example is BignumOperation, which provides
        common features used for bignum binary operations.

Both concrete and abstract subclasses can be derived from, to implement
additional test cases (see BignumCmp and BignumCmpAbs for examples of deriving
from abstract and concrete classes).


Adding test case generation for a function:

A subclass representing the test function should be added, deriving from a
file target such as BignumTarget. This test class must set/implement the
following:
  - test_function: the function name from the associated .function file.
  - test_name: a descriptive name or brief summary to refer to the test
        function.
  - arguments(): a method to generate the list of arguments required for the
        test_function.
  - generate_function_tests(): a method to generate TestCases for the function.
        This should create instances of the class with required input data, and
        call `.create_test_case()` to yield the TestCase.

Additional details and other attributes/methods are given in the documentation
of BaseTarget in test_data_generation.py.
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

import sys

from abc import ABCMeta
from typing import Dict, Iterator, List

import scripts_path # pylint: disable=unused-import
from mbedtls_dev import test_case
from mbedtls_dev import test_data_generation
from mbedtls_dev import bignum_common
# Import modules containing additional test classes
# Test function classes in these modules will be registered by
# the framework
from mbedtls_dev import bignum_core # pylint: disable=unused-import

class BignumTarget(test_data_generation.BaseTarget, metaclass=ABCMeta):
    #pylint: disable=abstract-method
    """Target for bignum (legacy) test case generation."""
    target_basename = 'test_suite_bignum.generated'


class BignumOperation(bignum_common.OperationCommon, BignumTarget, metaclass=ABCMeta):
    #pylint: disable=abstract-method
    """Common features for bignum operations in legacy tests."""
    input_values = [
        "", "0", "7b", "-7b",
        "0000000000000000123", "-0000000000000000123",
        "1230000000000000000", "-1230000000000000000"
    ]

    def description(self) -> str:
        """Generate a description for the test case.

        If not set, case_description uses the form A `symbol` B, where symbol
        is used to represent the operation. Descriptions of each value are
        generated to provide some context to the test case.
        """
        if not self.case_description:
            self.case_description = "{} {} {}".format(
                self.value_description(self.arg_a),
                self.symbol,
                self.value_description(self.arg_b)
            )
        return super().description()

    @staticmethod
    def value_description(val) -> str:
        """Generate a description of the argument val.

        This produces a simple description of the value, which is used in test
        case naming to add context.
        """
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
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for a_value, b_value in cls.get_value_pairs():
            yield cls(a_value, b_value).create_test_case()


class BignumCmp(BignumOperation):
    """Test cases for bignum value comparison."""
    count = 0
    test_function = "mpi_cmp_mpi"
    test_name = "MPI compare"
    input_cases = [
        ("-2", "-3"),
        ("-2", "-2"),
        ("2b4", "2b5"),
        ("2b5", "2b6")
        ]

    def __init__(self, val_a, val_b) -> None:
        super().__init__(val_a, val_b)
        self._result = int(self.int_a > self.int_b) - int(self.int_a < self.int_b)
        self.symbol = ["<", "==", ">"][self._result + 1]

    def result(self) -> List[str]:
        return [str(self._result)]


class BignumCmpAbs(BignumCmp):
    """Test cases for absolute bignum value comparison."""
    count = 0
    test_function = "mpi_cmp_abs"
    test_name = "MPI compare (abs)"

    def __init__(self, val_a, val_b) -> None:
        super().__init__(val_a.strip("-"), val_b.strip("-"))


class BignumAdd(BignumOperation):
    """Test cases for bignum value addition."""
    count = 0
    symbol = "+"
    test_function = "mpi_add_mpi"
    test_name = "MPI add"
    input_cases = bignum_common.combination_pairs(
        [
            "1c67967269c6", "9cde3",
            "-1c67967269c6", "-9cde3",
        ]
    )

    def result(self) -> List[str]:
        return [bignum_common.quote_str("{:x}").format(self.int_a + self.int_b)]



class BignumReadWrite(BignumTarget, metaclass=ABCMeta):
    #pylint: disable=abstract-method
    """Common features for read/write test cases.

    This adds functionality common in bignum read and write tests. This
    includes conversion of strings between radices, test case description
    generation, and setting expected return values in error cases.

    Attributes:
        radix_input_values: Dictionary of radices to test, with input values
            used for test cases with each radix.
        return_value: Expected return value from read/write operation.
        return_description: Dictionary containing non-zero return values and
            descriptions of the cause of the error.
    """
    radix_input_values = {
        10: [
            "0", "1", "", "-0", "128", "-23", "-023", "056", "a28", "28a",
            (
                "56125680981752282334141896320372489490613963693556392520816"
                "01789211135060411169768270549831951204904051669882782929207"
                "68080069408739749795845270734810126360163539134623767555567"
                "20019831187364993587901952757307830896531678727717924"
            )
        ],
        16: [
            "0", "1", "", "-0", "80", "-17", "-017", "038", "a28", "28a",
            (
                "0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883"
                "e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418b"
                "f4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f89"
                "3efbb2f958b4424"
            )
        ],
        15: ["1d", "1f"],
        17: ["38"],
        19: ["a28"]
    } # type: Dict[int, List[str]]
    return_value: str = "0"
    return_description = {
        "MBEDTLS_ERR_MPI_INVALID_CHARACTER": "Invalid character",
        "MBEDTLS_ERR_MPI_BAD_INPUT_DATA": "Illegal radix",
        "MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL": "Buffer too small"
    } # type: Dict[str, str]

    def __init__(self, val_a: str, radix: int, case_description: str = "") -> None:
        self.val_a = val_a
        self.radix = radix
        if case_description:
            self.case_description = case_description

    def description(self) -> str:
        """Generate a description for the test case.

        If not set, case description includes the radix and a description
        of the input. If the expected return value is non-zero, adds the error
        cause to the description.
        """
        if self.case_description == "":
            self.case_description = "{} {} {}".format(
                "radix", self.radix, self.value_description(self.val_a)
            ).strip()
        if self.return_value != "0":
            self.case_description = "{} ({})".format(
                self.case_description,
                self.return_description.get(self.return_value)
            )
        return super().description()

    @staticmethod
    def value_description(val: str) -> str:
        """Generate a description of the input value.

        This produces a simple description of the value, which is used in test
        case naming to add context.
        """
        tmp_components = [] # List[str]
        if val == "":
            return "empty string"
        if val[0] == "-":
            tmp_components.append("negative")
            val = val[1:]
        if val.startswith("0") and len(val) > 1:
            tmp_components.append("leading zero")
        elif val.startswith("0"):
            tmp_components.append("zero")
        return " ".join(tmp_components)

    def convert_radix(self, val: str, in_radix: int, out_radix: int) -> str:
        """Convert a string between radices.

        Sets return_value when radix is out of the supported range (2 to 16),
        or when an invalid character is read.
        """
        digits = "0123456789abcdef"
        sign = ""
        if max(out_radix, in_radix) > 16 or min(out_radix, in_radix) < 2:
            self.return_value = "MBEDTLS_ERR_MPI_BAD_INPUT_DATA"
            return ""
        if val == "" and out_radix == 16:
            return ""

        if val.startswith("-"):
            val = val[1:]
            sign = "-"
        for char in val:
            if char not in digits[:in_radix]:
                self.return_value = "MBEDTLS_ERR_MPI_INVALID_CHARACTER"
                return ""

        int_val = abs(int(val, in_radix)) if val != "" else 0
        if int_val == 0:
            sign = ""
        # Convert value to output radix
        # Use string formatting for hex and dec
        if out_radix == 16:
            ret = "{:x}".format(int_val)
            # Add zero if hex value is odd number of digits
            ret = "{}{}{}".format(sign, "0" if len(ret) % 2 else "", ret)
        elif out_radix == 10:
            ret = "{}{}".format(sign, int_val)
        elif int_val == 0:
            ret = "0"
        else:
            # For other radices, create list of digits and join
            ret_digits = [] # type: List[str]
            while int_val:
                ret_digits.insert(0, digits[int_val % out_radix])
                int_val //= out_radix
            ret = "{}{}".format(sign, "".join(ret_digits))
        return ret

    @classmethod
    def additional_test_cases(cls) -> Iterator[test_case.TestCase]:
        """Generate additional edge case tests.

        This can be used to implement additional test cases which require
        additional arguments. By default yields no test cases.
        """
        yield from ()

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for radix in cls.radix_input_values:
            for input_value in cls.radix_input_values[radix]:
                cur_op = cls(input_value, radix)
                yield cur_op.create_test_case()
        yield from cls.additional_test_cases()


class BignumReadString(BignumReadWrite):
    """Test cases for reading bignum values from strings."""
    count = 0
    test_function = "mpi_read_string"
    test_name = "Read MPI string"

    def __init__(self, val_a: str, radix: int, case_description: str = "") -> None:
        super().__init__(val_a, radix, case_description)
        self.val_x = self.convert_radix(val_a, self.radix, 16)

    def arguments(self) -> List[str]:
        return [
            str(self.radix),
            bignum_common.quote_str(self.val_a),
            bignum_common.quote_str(self.val_x.upper()),
            self.return_value
        ]


class BignumWriteString(BignumReadWrite):
    """Test cases for writing bignum values to strings."""
    count = 0
    test_function = "mpi_write_string"
    test_name = "Write MPI string"

    def __init__(self, val_a: str, radix: int, case_description: str = "",
                 undersize_buffer: bool = False):
        super().__init__(val_a, radix, case_description)
        self.val_x = self.convert_radix(val_a, 16, self.radix)

        # Set the buffer size for the output value
        if self.val_x == "":
            self.buf_size = self.min_buf_size(1)
        else:
            self.buf_size = self.min_buf_size(int(self.val_x, self.radix))

        if undersize_buffer:
            self.buf_size -= 1
            self.val_x = ""
            self.return_value = "MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL"

    def arguments(self) -> List[str]:
        return [
            bignum_common.quote_str(self.val_a),
            str(self.radix),
            bignum_common.quote_str(self.val_x.upper()),
            str(self.buf_size),
            self.return_value
        ]

    def min_buf_size(self, val: int) -> int:
        """Calculate minimum buffer size for a value.

        Logic is equivalent to that used in `mbedtls_mpi_write_string()` in
        the C library.
        """
        n = abs(val).bit_length()
        if self.radix >= 4:
            n >>= 1
        if self.radix >= 16:
            n >>= 1
        n += 3 # Null, negative sign and rounding compensation
        n += n & 1 # Ensure n is even for hex
        return n

    @classmethod
    def additional_test_cases(cls) -> Iterator[test_case.TestCase]:
        # Add tests for undersized write buffer
        for radix in [2, 10, 16]:
            yield cls("-23", radix, undersize_buffer=True).create_test_case()


if __name__ == '__main__':
    # Use the section of the docstring relevant to the CLI as description
    test_data_generation.main(sys.argv[1:], "\n".join(__doc__.splitlines()[:4]))
