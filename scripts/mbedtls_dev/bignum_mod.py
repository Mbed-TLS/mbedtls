"""Framework classes for generation of bignum mod test cases."""
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

from . import test_data_generation
from . import bignum_common

class BignumModTarget(test_data_generation.BaseTarget, metaclass=ABCMeta):
    #pylint: disable=abstract-method
    """Target for bignum mod test case generation."""
    target_basename = 'test_suite_bignum_mod.generated'

class BignumModOperation(bignum_common.OperationCommon, BignumModTarget, metaclass=ABCMeta):
    #pylint: disable=abstract-method
    """Target for bignum mod_raw test case generation."""

    def __init__(self, val_n: str, val_a: str, val_b: str = "0", bits_in_limb: int = 64) -> None:
        super().__init__(val_a=val_a, val_b=val_b)
        self.val_n = val_n
        self.bits_in_limb = bits_in_limb

    @property
    def int_n(self) -> int:
        return bignum_common.hex_to_int(self.val_n)

    @property
    def boundary(self) -> int:
        data_in = [self.int_a, self.int_b, self.int_n]
        return max([n for n in data_in if n is not None])

    @property
    def limbs(self) -> int:
        return bignum_common.limbs_mpi(self.boundary, self.bits_in_limb)

    @property
    def hex_digits(self) -> int:
        return 2 * (self.limbs * self.bits_in_limb // 8)

    @property
    def hex_n(self) -> str:
        return "{:x}".format(self.int_n).zfill(self.hex_digits)

    @property
    def hex_a(self) -> str:
        return "{:x}".format(self.int_a).zfill(self.hex_digits)

    @property
    def hex_b(self) -> str:
        return "{:x}".format(self.int_b).zfill(self.hex_digits)

    @property
    def r(self) -> int: # pylint: disable=invalid-name
        l = bignum_common.limbs_mpi(self.int_n, self.bits_in_limb)
        return bignum_common.bound_mpi_limbs(l, self.bits_in_limb)

    @property
    def r_inv(self) -> int:
        return bignum_common.invmod(self.r, self.int_n)

    @property
    def r2(self) -> int: # pylint: disable=invalid-name
        return pow(self.r, 2)

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

# END MERGE SLOT 7

# BEGIN MERGE SLOT 8

# END MERGE SLOT 8

# BEGIN MERGE SLOT 9

# END MERGE SLOT 9

# BEGIN MERGE SLOT 10

# END MERGE SLOT 10
