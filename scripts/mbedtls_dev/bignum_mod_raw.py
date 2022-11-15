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

class BignumModRawSub(BignumModRawOperation):
    """Test cases for bignum mod raw sub."""
    count = 0
    symbol = "-"
    test_function = "mpi_mod_raw_sub"
    test_name = "mbedtls_mpi_mod_raw_sub"
    unique_combinations_only = False

    input_values = [
        "0", "1", "fe", "ff", "fffe", "ffff",
        "fffffffffffffffe", "ffffffffffffffff",
        "fffffffffffffffffffffffffffffffe",
        "ffffffffffffffffffffffffffffffff",
        "1234567890abcdef01234567890abcdef0",
        "3653f8dd9b1f282e4067c3584ee207f8da94e3e8ab73738f",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "1234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef0",
        (
            "14c15c910b11ad28cc21ce88d0060cc54278c2614e1bcb383bb4a570294c4ea3"
            "738d243a6e58d5ca49c7b59b995253fd6c79a3de69f85e3131f3b9238224b122"
            "c3e4a892d9196ada4fcfa583e1df8af9b474c7e89286a1754abcb06ae8abb93f"
            "01d89a024cdce7a6d7288ff68c320f89f1347e0cdd905ecfd160c5d0ef412ed6"
        )
    ]

    modulus_values = [
        "7", "ff",
        "d1c127a667786703830500038ebaef20e5a3e2dc378fb75b"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff67",
        (
            "c93ba7ec74d96f411ba008bdb78e63ff11bb5df46a51e16b2c9d156f8e4e18ab"
            "f5e052cb01f47d0d1925a77f60991577e128fb6f52f34a27950a594baadd3d80"
            "57abeb222cf3cca962db16abf79f2ada5bd29ab2f51244bf295eff9f6aaba130"
            "2efc449b128be75eeaca04bc3c1a155d11d14e8be32a2c8287b3996cf6ad5223"
        ),
        (
            "5c083126e978d4fdf3b645a1cac083126e978d4fdf3b645a1cac083126e978d4"
            "fdf3b645a1cac083126e978d4fdf3b645a1cac083126e978d4fdf3b645a1cac0"
            "83126e978d4fdf3b645a1cac083126e978d4fdf3b645a1cac083126e978d4fdf"
            "3b645a1cac083126e978d4fdf3b645a1cac083126e978d4fdf3b645a1cac05d2"
        )
    ]

    descr_tpl = '{} #{} \"{}\" - \"{}\" % \"{}\".'

    BITS_IN_LIMB = 32

    @property
    def boundary(self) -> int:
        return self.int_n

    @property
    def x(self): # pylint: disable=invalid-name
        return (self.int_a - self.int_b) % self.int_n if self.int_n > 0 else 0

    @property
    def hex_x(self) -> str:
        return format(self.x, 'x').zfill(self.hex_digits)

    def description(self) -> str:
        return self.descr_tpl.format(self.test_name,
                                     self.count,
                                     self.int_a,
                                     self.int_b,
                                     self.int_n)

    def arguments(self) -> List[str]:
        return [bignum_common.quote_str(n) for n in [self.hex_a,
                                                     self.hex_b,
                                                     self.hex_n,
                                                     self.hex_x]]

    def result(self) -> List[str]:
        return [self.hex_x]

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for a_value, b_value in cls.get_value_pairs():
            int_a = bignum_common.hex_to_int(a_value)
            int_b = bignum_common.hex_to_int(b_value)
            highest = max(int_a, int_b)

            # Choose a modulus bigger then the arguments
            for n_value in cls.modulus_values:
                int_n = bignum_common.hex_to_int(n_value)
                if highest < int_n:
                    yield cls(n_value, a_value, b_value, cls.BITS_IN_LIMB).create_test_case()

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

class BignumModRawConvertToMont(bignum_common.ModOperationCommon,
                                BignumModRawTarget):
    """ Test cases for mpi_mod_raw_to_mont_rep(). """
    test_function = "mpi_mod_raw_to_mont_rep"
    test_name = "Convert into Mont: "
    symbol = "R *"
    input_style = "arch_split"
    arity = 1

    def result(self) -> List[str]:
        result = (self.int_a * self.r) % self.int_n
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
        result = (self.int_a * self.r_inv) % self.int_n
        return [self.format_result(result)]


# END MERGE SLOT 7

# BEGIN MERGE SLOT 8

# END MERGE SLOT 8

# BEGIN MERGE SLOT 9

# END MERGE SLOT 9

# BEGIN MERGE SLOT 10

# END MERGE SLOT 10
