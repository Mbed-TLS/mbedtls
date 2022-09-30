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
from typing import Iterator

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
