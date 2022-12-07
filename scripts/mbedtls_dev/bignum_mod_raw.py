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

from typing import Dict, List

from . import test_data_generation
from . import bignum_common

class BignumModRawTarget(test_data_generation.BaseTarget):
    #pylint: disable=abstract-method, too-few-public-methods
    """Target for bignum mod_raw test case generation."""
    target_basename = 'test_suite_bignum_mod_raw.generated'

# BEGIN MERGE SLOT 1

# END MERGE SLOT 1

# BEGIN MERGE SLOT 2

class BignumModRawSub(bignum_common.ModOperationCommon,
                      BignumModRawTarget):
    """Test cases for bignum mpi_mod_raw_sub()."""
    symbol = "-"
    test_function = "mpi_mod_raw_sub"
    test_name = "mbedtls_mpi_mod_raw_sub"
    input_style = "fixed"
    arity = 2

    def arguments(self) -> List[str]:
        return [bignum_common.quote_str(n) for n in [self.arg_a,
                                                     self.arg_b,
                                                     self.arg_n]
               ] + self.result()

    def result(self) -> List[str]:
        result = (self.int_a - self.int_b) % self.int_n
        return [self.format_result(result)]

# END MERGE SLOT 2

# BEGIN MERGE SLOT 3

# END MERGE SLOT 3

# BEGIN MERGE SLOT 4

# END MERGE SLOT 4

# BEGIN MERGE SLOT 5

class BignumModRawAdd(bignum_common.ModOperationCommon,
                      BignumModRawTarget):
    """Test cases for bignum mpi_mod_raw_add()."""
    symbol = "+"
    test_function = "mpi_mod_raw_add"
    test_name = "mbedtls_mpi_mod_raw_add"
    input_style = "fixed"
    arity = 2

    def result(self) -> List[str]:
        result = (self.int_a + self.int_b) % self.int_n
        return [self.format_result(result)]

# END MERGE SLOT 5

# BEGIN MERGE SLOT 6

# END MERGE SLOT 6

# BEGIN MERGE SLOT 7

class BignumModRawConvertToMont(bignum_common.ModOperationCommon,
                                BignumModRawTarget):
    """ Test cases for mpi_mod_raw_to_mont_rep(). """
    test_function = "mpi_mod_raw_to_mont_rep"
    test_name = "Convert into Mont: "
    symbol = "R *"
    input_style = "arch_split"
    arity = 1

    def result(self) -> List[str]:
        result = self.to_montgomery(self.int_a)
        return [self.format_result(result)]

class BignumModRawConvertFromMont(bignum_common.ModOperationCommon,
                                  BignumModRawTarget):
    """ Test cases for mpi_mod_raw_from_mont_rep(). """
    test_function = "mpi_mod_raw_from_mont_rep"
    test_name = "Convert from Mont: "
    symbol = "1/R *"
    input_style = "arch_split"
    arity = 1

    def result(self) -> List[str]:
        result = self.from_montgomery(self.int_a)
        return [self.format_result(result)]


# END MERGE SLOT 7

# BEGIN MERGE SLOT 8

# END MERGE SLOT 8

# BEGIN MERGE SLOT 9

# END MERGE SLOT 9

# BEGIN MERGE SLOT 10

# END MERGE SLOT 10
