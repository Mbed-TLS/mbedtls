"""Framework classes for generation of bignum core test cases."""
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

from abc import ABCMeta
from typing import Iterator, List

from . import test_case
from . import test_data_generation
from . import bignum_common

class BignumCoreTarget(test_data_generation.BaseTarget, metaclass=ABCMeta):
    #pylint: disable=abstract-method
    """Target for bignum core test case generation."""
    target_basename = 'test_suite_bignum_core.generated'


class BignumCoreOperation(bignum_common.OperationCommon, BignumCoreTarget, metaclass=ABCMeta):
    #pylint: disable=abstract-method
    """Common features for bignum core operations."""
    input_values = [
        "0", "1", "3", "f", "fe", "ff", "100", "ff00", "fffe", "ffff", "10000",
        "fffffffe", "ffffffff", "100000000", "1f7f7f7f7f7f7f",
        "8000000000000000", "fefefefefefefefe", "fffffffffffffffe",
        "ffffffffffffffff", "10000000000000000", "1234567890abcdef0",
        "fffffffffffffffffefefefefefefefe", "fffffffffffffffffffffffffffffffe",
        "ffffffffffffffffffffffffffffffff", "100000000000000000000000000000000",
        "1234567890abcdef01234567890abcdef0",
        "fffffffffffffffffffffffffffffffffffffffffffffffffefefefefefefefe",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "10000000000000000000000000000000000000000000000000000000000000000",
        "1234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef0",
        (
            "4df72d07b4b71c8dacb6cffa954f8d88254b6277099308baf003fab73227f34029"
            "643b5a263f66e0d3c3fa297ef71755efd53b8fb6cb812c6bbf7bcf179298bd9947"
            "c4c8b14324140a2c0f5fad7958a69050a987a6096e9f055fb38edf0c5889eca4a0"
            "cfa99b45fbdeee4c696b328ddceae4723945901ec025076b12b"
        )
    ]

    def description(self) -> str:
        """Generate a description for the test case.

        If not set, case_description uses the form A `symbol` B, where symbol
        is used to represent the operation. Descriptions of each value are
        generated to provide some context to the test case.
        """
        if not self.case_description:
            self.case_description = "{} {} {}".format(
                self.arg_a, self.symbol, self.arg_b
            )
        return super().description()

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for a_value, b_value in cls.get_value_pairs():
            yield cls(a_value, b_value).create_test_case()



class BignumCoreAddIf(BignumCoreOperation):
    """Test cases for bignum core add if."""
    count = 0
    symbol = "+"
    test_function = "mpi_core_add_if"
    test_name = "mbedtls_mpi_core_add_if"

    def result(self) -> str:
        tmp = self.int_a + self.int_b
        bound_val = max(self.int_a, self.int_b)
        bound_4 = bignum_common.bound_mpi4(bound_val)
        bound_8 = bignum_common.bound_mpi8(bound_val)
        carry_4, remainder_4 = divmod(tmp, bound_4)
        carry_8, remainder_8 = divmod(tmp, bound_8)
        return "\"{:x}\":{}:\"{:x}\":{}".format(
            remainder_4, carry_4, remainder_8, carry_8
        )


class BignumCoreSub(BignumCoreOperation):
    """Test cases for bignum core sub."""
    count = 0
    symbol = "-"
    test_function = "mpi_core_sub"
    test_name = "mbedtls_mpi_core_sub"
    unique_combinations_only = False

    def result(self) -> str:
        if self.int_a >= self.int_b:
            result_4 = result_8 = self.int_a - self.int_b
            carry = 0
        else:
            bound_val = max(self.int_a, self.int_b)
            bound_4 = bignum_common.bound_mpi4(bound_val)
            result_4 = bound_4 + self.int_a - self.int_b
            bound_8 = bignum_common.bound_mpi8(bound_val)
            result_8 = bound_8 + self.int_a - self.int_b
            carry = 1
        return "\"{:x}\":\"{:x}\":{}".format(result_4, result_8, carry)


class BignumCoreMLA(BignumCoreOperation):
    """Test cases for fixed-size multiply accumulate."""
    count = 0
    test_function = "mpi_core_mla"
    test_name = "mbedtls_mpi_core_mla"
    unique_combinations_only = False

    input_values = [
        "0", "1", "fffe", "ffffffff", "100000000", "20000000000000",
        "ffffffffffffffff", "10000000000000000", "1234567890abcdef0",
        "fffffffffffffffffefefefefefefefe",
        "100000000000000000000000000000000",
        "1234567890abcdef01234567890abcdef0",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "1234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef0",
        (
            "4df72d07b4b71c8dacb6cffa954f8d88254b6277099308baf003fab73227f"
            "34029643b5a263f66e0d3c3fa297ef71755efd53b8fb6cb812c6bbf7bcf17"
            "9298bd9947c4c8b14324140a2c0f5fad7958a69050a987a6096e9f055fb38"
            "edf0c5889eca4a0cfa99b45fbdeee4c696b328ddceae4723945901ec02507"
            "6b12b"
        )
    ] # type: List[str]
    input_scalars = [
        "0", "3", "fe", "ff", "ffff", "10000", "ffffffff", "100000000",
        "7f7f7f7f7f7f7f7f", "8000000000000000", "fffffffffffffffe"
    ] # type: List[str]

    def __init__(self, val_a: str, val_b: str, val_s: str) -> None:
        super().__init__(val_a, val_b)
        self.arg_scalar = val_s
        self.int_scalar = bignum_common.hex_to_int(val_s)
        if bignum_common.limbs_mpi4(self.int_scalar) > 1:
            self.dependencies = ["MBEDTLS_HAVE_INT64"]

    def arguments(self) -> List[str]:
        return [
            bignum_common.quote_str(self.arg_a),
            bignum_common.quote_str(self.arg_b),
            bignum_common.quote_str(self.arg_scalar),
            self.result()
        ]

    def description(self) -> str:
        """Override and add the additional scalar."""
        if not self.case_description:
            self.case_description = "0x{} + 0x{} * 0x{}".format(
                self.arg_a, self.arg_b, self.arg_scalar
            )
        return super().description()

    def result(self) -> str:
        result = self.int_a + (self.int_b * self.int_scalar)
        bound_val = max(self.int_a, self.int_b)
        bound_4 = bignum_common.bound_mpi4(bound_val)
        bound_8 = bignum_common.bound_mpi8(bound_val)
        carry_4, remainder_4 = divmod(result, bound_4)
        carry_8, remainder_8 = divmod(result, bound_8)
        return "\"{:x}\":\"{:x}\":\"{:x}\":\"{:x}\"".format(
            remainder_4, carry_4, remainder_8, carry_8
        )

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        """Override for additional scalar input."""
        for a_value, b_value in cls.get_value_pairs():
            for s_value in cls.input_scalars:
                cur_op = cls(a_value, b_value, s_value)
                yield cur_op.create_test_case()
