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

from typing import Dict, List # pylint: disable=unused-import

from . import test_data_generation
from . import bignum_common # pylint: disable=unused-import

class BignumModTarget(test_data_generation.BaseTarget):
    #pylint: disable=abstract-method, too-few-public-methods
    """Target for bignum mod test case generation."""
    target_basename = 'test_suite_bignum_mod.generated'

# BEGIN MERGE SLOT 1

# END MERGE SLOT 1

# BEGIN MERGE SLOT 2

# END MERGE SLOT 2

# BEGIN MERGE SLOT 3

class BignumModSub(bignum_common.ModOperationCommon, BignumModTarget):
    """Test cases for bignum mpi_mod_sub()."""
    symbol = "-"
    test_function = "mpi_mod_sub"
    test_name = "mbedtls_mpi_mod_sub"
    input_style = "fixed"
    arity = 2

    def result(self) -> List[str]:
        result = (self.int_a - self.int_b) % self.int_n
        # To make negative tests easier, append 0 for success to the
        # generated cases
        return [self.format_result(result), "0"]

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
