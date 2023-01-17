"""Framework classes for generation of ecp test cases."""
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

from typing import List

from . import test_data_generation
from . import ecp_common

class EcpTarget(test_data_generation.BaseTarget):
    #pylint: disable=abstract-method, too-few-public-methods
    """Target for ecp test case generation."""
    target_basename = 'test_suite_ecp.generated'

class EcpQuasiReduction(ecp_common.EcpOperationCommon,
                        EcpTarget):
    """Test cases for ecp quasi_reduction()."""
    symbol = "-"
    test_function = "ecp_quasi_reduction"
    test_name = "mbedtls_ecp_quasi_reduction"
    input_style = "fixed"
    arity = 1

    # Extend the default values with n < x < 2n
    input_values = ecp_common.EcpOperationCommon.input_values + [
        "73",
        "ebeddd7b4fefae8755bbfb9c181a73347096b3ec70d1a021",
        ("1f4e1d074d0b50e8d8818f9a9e5df9959f902bb955fd24fd3d791175226ad8c1"
         "fcb6d59fa41a3dcb25412009e5e356eb65b50ca67782285290420b45b32f0d63"
         "7c9ee549a52ad8d631ba4945435c9aec77227ec59faff878b71b920a3d631929"
         "d636c9a409d6ffdcd95e2568e128596811fb9ade15e69f6efd509381ebbf3599")
        ] # type: List[str]

    def result(self) -> List[str]:
        result = self.int_a % self.int_n
        return [self.format_result(result)]

    @property
    def is_valid(self) -> bool:
        return bool(self.int_a < 2 * self.int_n)
