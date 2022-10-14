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


if __name__ == '__main__':
    # Use the section of the docstring relevant to the CLI as description
    test_data_generation.main(sys.argv[1:], "\n".join(__doc__.splitlines()[:4]))
