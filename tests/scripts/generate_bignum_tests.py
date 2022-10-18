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
from typing import Iterator, List, Tuple

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
    input_values = [
        "", "0", "2", "-2", "-3", "-7b", "7b", "0000000000000000123",
        "-0000000000000000123", "2b5", "-1230000000000000000", "1230000000000000000"
    ]
    input_cases = [
        ("2b5", "2b4"), ("2b5", "2b6"), ("-2", "-1"), ("-2", "1c67967269c6")
    ]
    unique_combinations_only = False

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
    input_values = ["", "0", "-2", "2", "-3", "2b5"]
    input_cases = [("2b5", "2b4"), ("2b5", "2b6"), ("-2", "-1"), ("-2", "1")]

    def __init__(self, val_a, val_b) -> None:
        super().__init__(val_a.strip("-"), val_b.strip("-"))
        self.arg_a = val_a
        self.arg_b = val_b


class BignumCmpInt(BignumCmp):
    """Test cases for bignum value comparison with int."""
    count = 0
    test_function = "mpi_cmp_int"
    test_name = "MPI compare (int)"
    input_values = [] # type: List[str]
    input_cases = [
        ("693", "693"), ("693", "692"), ("693", "694"), ("-2", "-2"), ("-2", "-3"), ("-2", "-1")
    ]

    def __init__(self, val_a: str, val_b: str) -> None:
        # Read val_a and val_b as decimal strings
        val_a = "{:x}".format(int(val_a))
        val_b = "{:x}".format(int(val_b))
        super().__init__(val_a, val_b)

    def arguments(self) -> List[str]:
        return [str(self.int_a), str(self.int_b)] + self.result()


class BignumAdd(BignumOperation):
    """Test cases for bignum value addition."""
    count = 0
    symbol = "+"
    test_function = "mpi_add_mpi"
    test_name = "MPI add"
    input_values = ["", "00", "01", "-01", "9cde3", "-9cde3", "bc614e", "-bc614e"]
    input_cases = [
        ("01", ""), ("-01", ""),
        (
            (
                "4df72d07b4b71c8dacb6cffa954f8d88254b6277099308baf003fab73227f34029643b5a"
                "263f66e0d3c3fa297ef71755efd53b8fb6cb812c6bbf7bcf179298bd9947c4c8b1432414"
                "0a2c0f5fad7958a69050a987a6096e9f055fb38edf0c5889eca4a0cfa99b45fbdeee4c69"
                "6b328ddceae4723945901ec025076b12b"
            ), (
                "cb50e82a8583f44ee0025942e7362991b24e12663a0ddc234a57b0f7b4ff7b025bf5a670"
                "7dedc2898e70b739042c95a996283dffdf67558768784553c61e302e8812bc90f0bb0696"
                "870cfb910b560cefed8d99bbf7a00b31ccdbd56f3594e5a653cfd127d2167b13119e5c45"
                "c3f76b4e3d904a9bc0cbb43c33aa7f23b"
            )
        ), (
            (
                "1f55332c3a48b910f9942f6c914e58bef37a47ee45cb164a5b6b8d1006bf59a059c21449"
                "939ebebfdf517d2e1dbac88010d7b1f141e997bd6801ddaec9d05910f4f2de2b2c4d714e"
                "2c14a72fc7f17aa428d59c531627f09"
            ), (
                "941379d00fed1491dec0abfc13b52b9049625b3c42c3a972a2549e7a3e1b12c5a304b23e"
                "9ed6e251b8af28a4b3124900b23138bfafda925ab3410d57d6f8f0dd8c8c32eb0b4329fb"
                "f792e43f9593e766fa0c3c0be077b4e5162616a6428c51b"
            )
        )
    ]

    def result(self) -> List[str]:
        return ["\"{:x}\"".format(self.int_a + self.int_b)]


class BignumAddInplace(BignumAdd):
    """Test cases for bignum value addition inplace."""
    count = 0
    test_function = "mpi_add_mpi_inplace"
    test_name = "MPI add inplace"
    input_values = [
        "bc614e", "ffffffffffffffffffffffffffffffff",
        (
            "1f55332c3a48b910f9942f6c914e58bef37a47ee45cb164a5b6b8d1006bf59a059c21449939e"
            "bebfdf517d2e1dbac88010d7b1f141e997bd6801ddaec9d05910f4f2de2b2c4d714e2c14a72f"
            "c7f17aa428d59c531627f09"
        )
    ]

    def arguments(self) -> List[str]:
        return [bignum_common.quote_str(self.arg_a)] + self.result()

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for a_value in cls.input_values:
            yield cls(a_value, a_value).create_test_case()


class BignumAddAbs(BignumAdd):
    """Test cases for absolute bignum value addition."""
    count = 0
    test_function = "mpi_add_abs"
    test_name = "MPI add (abs)"
    input_values = [
        "", "01", "08", "9cde3", "-9cde3", "bc614e", "-bc614e",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFF8"
    ]
    input_cases = [
        ("01", "00"),
        (
            (
                "-1f55332c3a48b910f9942f6c914e58bef37a47ee45cb164a5b6b8d1006bf59a059c2144"
                "9939ebebfdf517d2e1dbac88010d7b1f141e997bd6801ddaec9d05910f4f2de2b2c4d714"
                "e2c14a72fc7f17aa428d59c531627f09"
            ), (
                "941379d00fed1491dec0abfc13b52b9049625b3c42c3a972a2549e7a3e1b12c5a304b23e"
                "9ed6e251b8af28a4b3124900b23138bfafda925ab3410d57d6f8f0dd8c8c32eb0b4329fb"
                "f792e43f9593e766fa0c3c0be077b4e5162616a6428c51b"
            )
        )
    ]

    def result(self) -> List[str]:
        return ["\"{:x}\"".format(abs(self.int_a) + abs(self.int_b))]


class BignumAddInt(BignumAdd):
    """Test case for bignum value addition with int."""
    count = 0
    test_function = "mpi_add_int"
    test_name = "MPI add (int)"
    input_cases = [
        (
            "10cc4ebcb68cbdaa438b80692d9e586b384ae3e1fa33f3db5962d394bec17fd92ad4189",
            "9871232"
        ),
        (
            "10cc4ebcb68cbdaa438b80692d9e586b384ae3e1fa33f3db5962d394bec17fd92ad4189",
            "-9871232"
        ),
        ("", "0"), ("", "1")
    ]
    input_values = [] # type: List[str]

    def __init__(self, val_a: str, val_b: str) -> None:
        # Read val_b as decimal string
        val_b = "{:x}".format(int(val_b))
        super().__init__(val_a, val_b)

    def arguments(self) -> List[str]:
        return [bignum_common.quote_str(self.arg_a), str(self.int_b)] + self.result()


class BignumSub(BignumOperation):
    """Test cases for bignum value subtraction."""
    count = 0
    symbol = "-"
    test_function = "mpi_sub_mpi"
    test_name = "MPI sub"
    input_values = ["", "0", "1", "-1"]
    input_cases = [
        ("5", "7"), ("5", "-7"), ("-5", "7"), ("-5", "-7"),
        (
            (
                "cb50e82a8583f44ee0025942e7362991b24e12663a0ddc234a57b0f7b4ff7b025bf5a670"
                "7dedc2898e70b739042c95a996283dffdf67558768784553c61e302e8812bc90f0bb0696"
                "870cfb910b560cefed8d99bbf7a00b31ccdbd56f3594e5a653cfd127d2167b13119e5c45"
                "c3f76b4e3d904a9bc0cbb43c33aa7f23b"
            ), (
                "4df72d07b4b71c8dacb6cffa954f8d88254b6277099308baf003fab73227f34029643b5a"
                "263f66e0d3c3fa297ef71755efd53b8fb6cb812c6bbf7bcf179298bd9947c4c8b1432414"
                "0a2c0f5fad7958a69050a987a6096e9f055fb38edf0c5889eca4a0cfa99b45fbdeee4c69"
                "6b328ddceae4723945901ec025076b12b"
            )
        ), (
            (
                "1f55332c3a48b910f9942f6c914e58bef37a47ee45cb164a5b6b8d1006bf59a059c21449"
                "939ebebfdf517d2e1dbac88010d7b1f141e997bd6801ddaec9d05910f4f2de2b2c4d714e"
                "2c14a72fc7f17aa428d59c531627f09"
            ), (
                "941379d00fed1491dec0abfc13b52b9049625b3c42c3a972a2549e7a3e1b12c5a304b23e"
                "9ed6e251b8af28a4b3124900b23138bfafda925ab3410d57d6f8f0dd8c8c32eb0b4329fb"
                "f792e43f9593e766fa0c3c0be077b4e5162616a6428c51b"
            )
        )
    ]
    unique_combinations_only = False

    def result(self) -> List[str]:
        return ["\"{:x}\"".format(self.int_a - self.int_b)]

    @classmethod
    def get_value_pairs(cls) -> Iterator[Tuple[str, str]]:
        for a, b in super().get_value_pairs():
            int_a = int(a, 16) if a else 0
            int_b = int(b, 16) if b else 0
            if not (abs(int_a) == abs(int_b) and int_a < 0 and int_b < 0):
                yield a, b


class BignumSubAbs(BignumSub):
    """Test cases for bignum value subtraction."""
    count = 0
    test_function = "mpi_sub_abs"
    test_name = "MPI sub (abs)"
    input_values = [] # type: List[str]
    input_cases = [
        ("5", "7"), ("5", "-7"), ("-5", "7"), ("-5", "-7"),
        ("7", "5"), ("7", "-5"), ("-7", "5"), ("-7", "-5"),
        ("5", "123456789abcdef01"), ("5", "-123456789abcdef01"),
        ("-5", "123456789abcdef01"), ("-5", "-123456789abcdef01"),
        ("FFFFFFFFFF", "01"), ("FFFFFFFFF0", "01"),
        ("FF00000000", "0F00000000"), ("FF00000000", "0F00000001")
    ]

    def result(self) -> List[str]:
        result = abs(self.int_a) - abs(self.int_b)
        ret = "0"
        if result < 0:
            result = 0
            ret = "MBEDTLS_ERR_MPI_NEGATIVE_VALUE"
        return ["\"{:x}\"".format(result), ret]


class BignumSubInt(BignumSub):
    """Test cases for bignum value subtraction with int."""
    count = 0
    test_function = "mpi_sub_int"
    test_name = "MPI sub (int)"
    input_values = [] # type: List[str]
    input_cases = [
        (
            "10cc4ebcb68cbdaa438b80692d9e586b384ae3e1fa33f3db5962d394bec17fd92ad4189",
            "-9871232"
        ), (
            "10cc4ebcb68cbdaa438b80692d9e586b384ae3e1fa33f3db5962d394bec17fd92ad4189",
            "9871232"
        ), ("", "0"), ("", "1"), ("", "-1")]

    def __init__(self, val_a: str, val_b: str) -> None:
        # Read val_b as decimal string
        val_b = "{:x}".format(int(val_b))
        super().__init__(val_a, val_b)

    def arguments(self) -> List[str]:
        return [bignum_common.quote_str(self.arg_a), str(self.int_b)] + self.result()

    @classmethod
    def get_value_pairs(cls) -> Iterator[Tuple[str, str]]:
        for a, b in super().get_value_pairs():
            if b and int(b, 16) < 0xFFFFFFFF:
                yield (a, b)


class BignumMul(BignumOperation):
    """Test cases for bignum value multiplication."""
    count = 0
    symbol = "*"
    test_function = "mpi_mul_mpi"
    test_name = "MPI mul"
    input_values = [
        "", "00", "-01",
        (
            "01b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731a1ce6bebc6cb5fe6f"
            "5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9dfa16f7cc72c56c84b6"
            "36d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc9f8cf8ef208a9b88c"
            "89"
        ), (
            "-000000000000000001b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731"
            "a1ce6bebc6cb5fe6f5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9df"
            "a16f7cc72c56c84b636d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc"
            "9f8cf8ef208a9b88c89"
        ), (
            "000000000000000001b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731a"
            "1ce6bebc6cb5fe6f5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9dfa"
            "16f7cc72c56c84b636d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc9"
            "f8cf8ef208a9b88c89"
        ), (
            "-01b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731a1ce6bebc6cb5fe6"
            "f5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9dfa16f7cc72c56c84b"
            "636d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc9f8cf8ef208a9b88"
            "c89"
        ), (
            "02f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe9e0f0683f82c439d"
            "979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec8ece154d334f5535"
            "64b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2d83a8dd05ae1eaf24"
            "51"
        ), (
            "-000000000000000002f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fb"
            "e9e0f0683f82c439d979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68e"
            "c8ece154d334f553564b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2"
            "d83a8dd05ae1eaf2451"
        ), (
            "000000000000000002f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe"
            "9e0f0683f82c439d979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec"
            "8ece154d334f553564b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2d"
            "83a8dd05ae1eaf2451"
        ), (
            "-02f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe9e0f0683f82c439"
            "d979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec8ece154d334f553"
            "564b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2d83a8dd05ae1eaf2"
            "451"
        ), (
            "-01b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731a1ce6bebc6cb5fe6"
            "f5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9dfa16f7cc72c56c84b"
            "636d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc9f8cf8ef208a9b88"
            "c890000000000000000"
        ), (
            "01b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731a1ce6bebc6cb5fe6f"
            "5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9dfa16f7cc72c56c84b6"
            "36d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc9f8cf8ef208a9b88c"
            "890000000000000000"
        ), (
            "-02f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe9e0f0683f82c439"
            "d979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec8ece154d334f553"
            "564b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2d83a8dd05ae1eaf2"
            "4510000000000000000"
        ), (
            "02f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe9e0f0683f82c439d"
            "979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec8ece154d334f5535"
            "64b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2d83a8dd05ae1eaf24"
            "510000000000000000"
        ),
    ]
    input_cases = [
        ("5", "7"), ("-5", "7"), ("5", "-7"), ("-5", "-7"), ("", "01"), ("01", ""),
        (
            (
                "02f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe9e0f0683f82"
                "c439d979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec8ece15"
                "4d334f553564b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2d8"
                "3a8dd05ae1eaf245100000000000000000000000000000000"
            ), (
                "01b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731a1ce6bebc6cb"
                "5fe6f5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9dfa16f7cc"
                "72c56c84b636d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc9f"
                "8cf8ef208a9b88c89"
            ),
        ), (
            (
                "-02f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe9e0f0683f8"
                "2c439d979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec8ece1"
                "54d334f553564b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2d"
                "83a8dd05ae1eaf245100000000000000000000000000000000"
            ), (
                "01b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731a1ce6bebc6cb"
                "5fe6f5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9dfa16f7cc"
                "72c56c84b636d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc9f"
                "8cf8ef208a9b88c89"
            ),
        ), (
            (
                "02f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe9e0f0683f82"
                "c439d979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec8ece15"
                "4d334f553564b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2d8"
                "3a8dd05ae1eaf245100000000000000000000000000000000"
            ), (
                "-01b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731a1ce6bebc6c"
                "b5fe6f5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9dfa16f7c"
                "c72c56c84b636d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc9"
                "f8cf8ef208a9b88c89"
            ),
        ), (
            (
                "-02f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe9e0f0683f8"
                "2c439d979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec8ece1"
                "54d334f553564b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2d"
                "83a8dd05ae1eaf245100000000000000000000000000000000"
            ), (
                "-01b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731a1ce6bebc6c"
                "b5fe6f5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9dfa16f7c"
                "c72c56c84b636d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc9"
                "f8cf8ef208a9b88c89"
            ),
        ), (
            (
                "02f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe9e0f0683f82"
                "c439d979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec8ece15"
                "4d334f553564b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2d8"
                "3a8dd05ae1eaf2451"
            ), (
                "01b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731a1ce6bebc6cb"
                "5fe6f5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9dfa16f7cc"
                "72c56c84b636d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc9f"
                "8cf8ef208a9b88c8900000000000000000000000000000000"
            ),
        ), (
            (
                "-02f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe9e0f0683f8"
                "2c439d979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec8ece1"
                "54d334f553564b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2d"
                "83a8dd05ae1eaf2451"
            ), (
                "01b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731a1ce6bebc6cb"
                "5fe6f5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9dfa16f7cc"
                "72c56c84b636d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc9f"
                "8cf8ef208a9b88c8900000000000000000000000000000000"
            ),
        ), (
            (
                "02f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe9e0f0683f82"
                "c439d979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec8ece15"
                "4d334f553564b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2d8"
                "3a8dd05ae1eaf2451"
            ), (
                "-01b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731a1ce6bebc6c"
                "b5fe6f5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9dfa16f7c"
                "c72c56c84b636d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc9"
                "f8cf8ef208a9b88c8900000000000000000000000000000000"
            ),
        ), (
            (
                "-02f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe9e0f0683f8"
                "2c439d979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec8ece1"
                "54d334f553564b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f9168d2d"
                "83a8dd05ae1eaf2451"
            ), (
                "-01b0b14c432710cde936e3fc100515e95dca61e10b8a68d9632bfa0546a9731a1ce6bebc6c"
                "b5fe6f5fd7e57b25f737f6a0ce5402e216b8b81c06f0c5ccce447d7f5631d14bff9dfa16f7c"
                "c72c56c84b636d00a5f35199d17ee9bf3f8746f44374ffd4ae22cf84089f04a9f7f356d6dc9"
                "f8cf8ef208a9b88c8900000000000000000000000000000000"
            ),
        ),
    ]

    def result(self) -> List[str]:
        return ["\"{:x}\"".format(self.int_a * self.int_b)]


class BignumMulInt(BignumMul):
    """Test cases for bignum value multiplication by int."""
    count = 0
    test_function = "mpi_mul_int"
    test_name = "MPI mul (int)"
    input_values = [] # type: List[str]
    input_cases = [
        (
            "10cc4ebcb68cbdaa438b80692d9e586b384ae3e1fa33f3db5962d394bec17fd92ad4189",
            "9871232"
        ), (
            "10cc4ebcb68cbdaa438b80692d9e586b384ae3e1fa33f3db5962d394bec17fd92ad4189",
            "-9871232"
        ), (
            "-10cc4ebcb68cbdaa438b80692d9e586b384ae3e1fa33f3db5962d394bec17fd92ad4189",
            "9871232"
        ), (
            "-10cc4ebcb68cbdaa438b80692d9e586b384ae3e1fa33f3db5962d394bec17fd92ad4189",
            "-9871232"
        ), ("", "0"), ("", "1"), ("", "4660")
    ]

    def __init__(self, val_a: str, val_b: str) -> None:
        # Read val_b as decimal string
        val_b = "{:x}".format(int(val_b))
        super().__init__(val_a, val_b)

    def arguments(self) -> List[str]:
        return [bignum_common.quote_str(self.arg_a), str(self.int_b)] + self.result()

    def result(self) -> List[str]:
        return (super().result() if self.arg_a else ["\"\""]) + [
            "\"==\"" if self.int_b >= 0 or self.int_a == 0 else "\"!=\""
        ]

    @classmethod
    def get_value_pairs(cls) -> Iterator[Tuple[str, str]]:
        for a, b in super().get_value_pairs():
            if b and abs(int(b, 16)) < 0xFFFFFFFF:
                yield (a, b)


class BignumDiv(BignumOperation):
    """Test cases for bignum value division."""
    count = 0
    symbol = "/"
    test_function = "mpi_div_mpi"
    test_name = "MPI div"
    input_values = ["", "0", "7", "3e8"]
    input_cases = [
        ("3e8", "d"), ("3e8", "-d"), ("", "1"), ("", "-1"), ("309", "7"),
        (
            "9e22d6da18a33d1ef28d2a82242b3f6e9c9742f63e5d440f58a190bfaf23a7866e67589adb80",
            "22"
        ), (
            (
                "503ae899d35ae5b7706b067aed7cb2952da37a5d4ad58f05f69abe14e8aaae88eab2baed"
                "858177cb4595c0edc92e5ac13c2bba2bfa23276dd023e9e52f547d4c9edb138d86aad329"
                "d7afb01e15eab7281e181cb249fc91bf09d621d86561301edda156f80e3bbff853a31285"
                "2fe9e3d0541cb86801390aff1dc3c05bcb592c266f625b70e419b4c7e7e85399bb06c0e5"
                "0b099b4292f9eaff4d869681faa1f745b5fcb3349ed93c572739a31dcf76b43370cf9f86"
                "cc54e982dfac9467bde915c697e60554e0d698be6bb2dd1f8bc64659f6baee7641b51f4b"
                "5ed7010c04600fcd382db84a93fe3d4d86e86a459c6cebb5a"
            ), (
                "2f77b94b179d4a51360f04fa56e2c0784ce3b8a742280b016904896a5605fbe9e0f0683f"
                "82c439d979ab14e11b34e05ae96232b18fb2e0d1319f4942732d7eadf92ae90cb8c68ec8"
                "ece154d334f553564b6f6db185b33b8d3635598c3d128acde8bbb7b13697e48d1a542e5f"
                "9168d2d83a8dd05ae1eaf2451"
            )
        )
    ]
    unique_combinations_only = False

    def description(self) -> str:
        if not self.case_description and self.int_b == 0:
            self.case_description = "(division by zero)"
        return super().description()

    def result(self) -> List[str]:
        if self.int_b == 0:
            quot, rem = 0, 0
            ret = "MBEDTLS_ERR_MPI_DIVISION_BY_ZERO"
        else:
            quot, rem = divmod(self.int_a, self.int_b)
            # Python will return a remainder with the same sign as divisor
            if rem < 0:
                rem -= self.int_b
                quot += 1
            ret = "0"
        return [
            "\"{:x}\"".format(quot) if quot else "\"\"",
            "\"{:x}\"".format(rem) if rem else "\"\"",
            ret
        ]


class BignumDivInt(BignumDiv):
    """Test cases for bignum value division with int divisor."""
    count = 0
    test_function = "mpi_div_int"
    test_name = "MPI div (int)"
    input_values = [] # type: List[str]
    input_cases = [
        ("3e8", "13"), ("3e8", "0"), ("3e8", "-13"), ("", "0"), ("00", "0"), ("", "1"),
        (
            "9e22d6da18a33d1ef28d2a82242b3f6e9c9742f63e5d440f58a190bfaf23a7866e67589adb80",
            "34"
        ), (
            "9e22d6da18a33d1ef28d2a82242b3f6e9c9742f63e5d440f58a190bfaf23a7866e67589adb80",
            "-34"
        )
    ]

    def __init__(self, val_a: str, val_b: str) -> None:
        # Read val_b as decimal string
        val_b = "{:x}".format(int(val_b))
        super().__init__(val_a, val_b)

    def arguments(self) -> List[str]:
        return [bignum_common.quote_str(self.arg_a), str(self.int_b)] + self.result()


class BignumMod(BignumOperation):
    """Test cases for bignum value modulo."""
    count = 0
    symbol = "mod"
    test_function = "mpi_mod_mpi"
    test_name = "MPI mod"
    input_values = ["", "-d", "d", "3e8", "-3e8"]
    input_cases = [("3e8", "0"), ("", "1"), ("", "-1")]

    def description(self) -> str:
        if not self.case_description and self.int_b == 0:
            self.case_description = "(division by zero)"
        elif not self.case_description and self.int_b < 0:
            self.case_description = "(negative mod)"
        return super().description()

    def result(self) -> List[str]:
        remainder = 0
        if self.int_b == 0:
            ret = "MBEDTLS_ERR_MPI_DIVISION_BY_ZERO"
        elif self.int_b < 0:
            ret = "MBEDTLS_ERR_MPI_NEGATIVE_VALUE"
        else:
            remainder = self.int_a % self.int_b
            ret = "0"
        return ["\"{:x}\"".format(remainder), ret]


class BignumModInt(BignumMod):
    """Test cases for bignum value modulo with int modulus."""
    count = 0
    test_function = "mpi_mod_int"
    test_name = "MPI mod (int)"
    input_values = [] # type: List[str]
    input_cases = [
        ("3e8", "d"), ("3e8", ""), ("3e8", "0"), ("-3e8", "d"), ("3e8", "-d"),
        ("-3e8", "-d"), ("3e8", "1"), ("3e9", "2"), ("3e8", "2"), ("", "1"),
        ("", "2"), ("", "-1"), ("", "-2")
    ]

    def arguments(self) -> List[str]:
        return [bignum_common.quote_str(self.arg_a), str(self.int_b)] + self.result()

    def result(self) -> List[str]:
        rem, ret = super().result()
        rem = rem.replace("\"", "")
        return [str(int(rem, 16)), ret]

    @classmethod
    def get_value_pairs(cls) -> Iterator[Tuple[str, str]]:
        for a, b in super().get_value_pairs():
            if b and abs(int(b, 16)) < 0xFFFFFFFF:
                yield (a, b)


class BignumExpMod(BignumTarget):
    """Test cases for bignum exponentiation mod N."""
    count = 0
    test_function = "mpi_exp_mod"
    test_name = "MPI exp mod"
    input_cases = [
        ("17", "d", "1d"), ("17", "d", "1e"), ("17", "d", ""), ("17", "d", "-1d"),
        ("-17", "d", "1d"), ("17", "-d", "1d"), ("-17", "-d", "1d"), ("", "", "09"),
        ("", "00", "09"), ("", "01", "09"), ("", "02", "09"), ("00", "", "09"),
        ("00", "00", "09"), ("00", "01", "09"), ("00", "02", "09"), ("01", "", "09"),
        ("04", "", "09"), ("0a", "", "09"), ("01", "00", "09"), ("04", "00", "09"),
        ("0a", "00", "09"), ("-2540be400", "2540be400", "1869f"),
        (
            (
                "109fe45714866e56fdd4ad9b6b686df27224afb7868cf4f0cbb794526932853cbf0beea6"
                "1594166654d13cd9fe0d9da594a97ee20230f12fb5434de73fb4f8102725a01622b31b1e"
                "a42e3a265019039ac1df31869bd97930d792fb72cdaa971d8a8015af"
            ), (
                "33ae3764fd06a00cdc3cba5c45dc79a9edb4e67e4d057cc74139d531c25190d111775fc4"
                "a0f4439b8b1930bbd766e7b46f170601f316c8a18ff8d5cb5ca5581f168345d101edb462"
                "b7d93b7c520ccb8fb276b447a63d869203cc11f67a1122dc4da034218de85e39"
            ), (
                "11a9351d2d32ccd568e75bf8b4ebbb2a36be691b55832edac662ff79803df8af525fba45"
                "3068be16ac3920bcc1b468f8f7fe786e0fa4ecbabcad31e5e3b05def802eb8600deaf11e"
                "f452487db878df20a80606e4bb6a163b83895d034cc8b53dbcd005be42ffdd2ce99bed06"
                "089a0b79d"
            )
        ), (
            (
                "-9f13012cd92aa72fb86ac8879d2fde4f7fd661aaae43a00971f081cc60ca277059d5c37"
                "e89652e2af2585d281d66ef6a9d38a117e9608e9e7574cd142dc55278838a2161dd56db9"
                "470d4c1da2d5df15a908ee2eb886aaa890f23be16de59386663a12f1afbb325431a3e835"
                "e3fd89b98b96a6f77382f458ef9a37e1f84a03045c8676ab55291a94c2228ea15448ee96"
                "b626b998"
            ), (
                "40a54d1b9e86789f06d9607fb158672d64867665c73ee9abb545fc7a785634b354c7bae5"
                "b962ce8040cf45f2c1f3d3659b2ee5ede17534c8fc2ec85c815e8df1fe7048d12c90ee31"
                "b88a68a081f17f0d8ce5f4030521e9400083bcea73a429031d4ca7949c2000d597088e0c"
                "39a6014d8bf962b73bb2e8083bd0390a4e00b9b3"
            ), (
                "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df74"
                "96ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6"
                "ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4"
                "976eaa9afd5138fe8376435b9fc61d2fc0eb06e3"
            )
        )
    ]

    def __init__(self, val_a: str, val_e: str, val_n: str) -> None:
        self.arg_a = val_a
        self.arg_e = val_e
        self.arg_b = val_e
        self.arg_n = val_n
        self.int_a = bignum_common.hex_to_int(val_a)
        self.int_e = bignum_common.hex_to_int(val_e)
        self.int_n = bignum_common.hex_to_int(val_n)
        if self.int_a.bit_length() > 792:
            self.dependencies = ["MPI_MAX_BITS_LARGER_THAN_792"]

    def arguments(self) -> List[str]:
        return [
            bignum_common.quote_str(self.arg_a), bignum_common.quote_str(self.arg_e),
            bignum_common.quote_str(self.arg_n)
        ] + self.result()

    def description(self) -> str:
        if not self.case_description:
            if self.int_n == 0:
                self.case_description = "(N = 0)"
            elif self.int_n < 0:
                self.case_description = "(negative N)"
            elif self.int_n % 2 == 0:
                self.case_description = "(even N)"
            elif self.int_e < 0:
                self.case_description = "(negative exponent)"
            elif self.int_a < 0:
                self.case_description = "(negative base)"
            else:
                self.case_description = "{:x} ^ {:x} mod {:x}".format(
                    self.int_a, self.int_e, self.int_n
                )
        return super().description()

    def result(self) -> List[str]:
        if self.int_n <= 0 or self.int_n % 2 == 0 or self.int_e < 0:
            ret = "MBEDTLS_ERR_MPI_BAD_INPUT_DATA"
            val = 0
        else:
            ret = "0"
            val = pow(self.int_a, self.int_e, self.int_n)
        return ["\"{:x}\"".format(val), ret]

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for a_value, e_value, n_value in cls.input_cases:
            yield cls(a_value, e_value, n_value).create_test_case()


class BignumExpModSize(BignumTarget):
    """Test case for bignum exponentiation mod N, from input sizes."""
    count = 0
    test_function = "mpi_exp_mod_size"
    test_name = "MPI exp mod (by size)"
    input_cases = [
        ("2", "MBEDTLS_MPI_MAX_SIZE", "10"), ("2", "MBEDTLS_MPI_MAX_SIZE + 1", "10"),
        ("2", "2", "MBEDTLS_MPI_MAX_SIZE"), ("2", "2", "MBEDTLS_MPI_MAX_SIZE + 1"),
        ("2", "MBEDTLS_MPI_MAX_SIZE", "MBEDTLS_MPI_MAX_SIZE"),
        ("2", "MBEDTLS_MPI_MAX_SIZE + 1", "MBEDTLS_MPI_MAX_SIZE + 1")
    ]

    def __init__(self, size_a: str, size_e: str, size_n: str) -> None:
        self.arg_a = size_a
        self.arg_e = size_e
        self.arg_n = size_n
        self.arg_rr = ""

    def arguments(self) -> List[str]:
        return [
            self.arg_a, self.arg_e, self.arg_n, bignum_common.quote_str(self.arg_rr)
        ] + self.result()

    def result(self) -> List[str]:
        if "MBEDTLS_MPI_MAX_SIZE +" in "".join((self.arg_e, self.arg_n)):
            return ["MBEDTLS_ERR_MPI_BAD_INPUT_DATA"]
        else:
            return ["0"]

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for size_a, size_e, size_n in cls.input_cases:
            yield cls(size_a, size_e, size_n).create_test_case()


if __name__ == '__main__':
    # Use the section of the docstring relevant to the CLI as description
    test_data_generation.main(sys.argv[1:], "\n".join(__doc__.splitlines()[:4]))
