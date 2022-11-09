"""Framework classes for generation of bignum mod_raw test cases."""
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
from typing import Dict, Iterator, List

from . import test_case
from . import test_data_generation
from . import bignum_common

class BignumModRawTarget(test_data_generation.BaseTarget, metaclass=ABCMeta):
    #pylint: disable=abstract-method
    """Target for bignum mod_raw test case generation."""
    target_basename = 'test_suite_bignum_mod_raw.generated'

# BEGIN MERGE SLOT 1

# END MERGE SLOT 1

# BEGIN MERGE SLOT 2

# END MERGE SLOT 2

# BEGIN MERGE SLOT 3

# END MERGE SLOT 3

# BEGIN MERGE SLOT 4

# END MERGE SLOT 4

# BEGIN MERGE SLOT 5

# END MERGE SLOT 5

# BEGIN MERGE SLOT 6

# END MERGE SLOT 6

# BEGIN MERGE SLOT 7
class BignumModRawOperation(bignum_common.OperationCommon, BignumModRawTarget, metaclass=ABCMeta):
    #pylint: disable=abstract-method
    pass

class BignumModRawOperationArchSplit(BignumModRawOperation):
    #pylint: disable=abstract-method
    """Common features for bignum core operations where the result depends on
    the limb size."""

    def __init__(self, val_a: str, val_b: str, bits_in_limb: int) -> None:
        super().__init__(val_a, val_b)
        bound_val = max(self.int_a, self.int_b)
        self.bits_in_limb = bits_in_limb
        self.bound = bignum_common.bound_mpi(bound_val, self.bits_in_limb)
        limbs = bignum_common.limbs_mpi(bound_val, self.bits_in_limb)
        byte_len = limbs * self.bits_in_limb // 8
        self.hex_digits = 2 * byte_len
        if self.bits_in_limb == 32:
            self.dependencies = ["MBEDTLS_HAVE_INT32"]
        elif self.bits_in_limb == 64:
            self.dependencies = ["MBEDTLS_HAVE_INT64"]
        else:
            raise ValueError("Invalid number of bits in limb!")
        self.arg_a = self.arg_a.zfill(self.hex_digits)
        self.arg_b = self.arg_b.zfill(self.hex_digits)
        self.arg_a_int = bignum_common.hex_to_int(self.arg_a)
        self.arg_b_int = bignum_common.hex_to_int(self.arg_b)

    def pad_to_limbs(self, val) -> str:
        return "{:x}".format(val).zfill(self.hex_digits)

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for a_value, b_value in cls.get_value_pairs():
            yield cls(a_value, b_value, 32).create_test_case()
            yield cls(a_value, b_value, 64).create_test_case()
# END MERGE SLOT 7

# BEGIN MERGE SLOT 8

# END MERGE SLOT 8

# BEGIN MERGE SLOT 9

# END MERGE SLOT 9

# BEGIN MERGE SLOT 10

# END MERGE SLOT 10
