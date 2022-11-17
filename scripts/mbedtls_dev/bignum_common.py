"""Common features for bignum in test generation framework."""
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

from abc import abstractmethod
from typing import Iterator, List, Tuple, TypeVar

from . import test_case
from . import test_data_generation

T = TypeVar('T') #pylint: disable=invalid-name

def invmod(a: int, n: int) -> int:
    """Return inverse of a to modulo n.

    Equivalent to pow(a, -1, n) in Python 3.8+. Implementation is equivalent
    to long_invmod() in CPython.
    """
    b, c = 1, 0
    while n:
        q, r = divmod(a, n)
        a, b, c, n = n, c, b - q*c, r
    # at this point a is the gcd of the original inputs
    if a == 1:
        return b
    raise ValueError("Not invertible")

def hex_to_int(val: str) -> int:
    """Implement the syntax accepted by mbedtls_test_read_mpi().

    This is a superset of what is accepted by mbedtls_test_read_mpi_core().
    """
    if val in ['', '-']:
        return 0
    return int(val, 16)

def quote_str(val) -> str:
    return "\"{}\"".format(val)

def bound_mpi(val: int, bits_in_limb: int) -> int:
    """First number exceeding number of limbs needed for given input value."""
    return bound_mpi_limbs(limbs_mpi(val, bits_in_limb), bits_in_limb)

def bound_mpi_limbs(limbs: int, bits_in_limb: int) -> int:
    """First number exceeding maximum of given number of limbs."""
    bits = bits_in_limb * limbs
    return 1 << bits

def limbs_mpi(val: int, bits_in_limb: int) -> int:
    """Return the number of limbs required to store value."""
    return (val.bit_length() + bits_in_limb - 1) // bits_in_limb

def combination_pairs(values: List[T]) -> List[Tuple[T, T]]:
    """Return all pair combinations from input values."""
    return [(x, y) for x in values for y in values]

class OperationCommon(test_data_generation.BaseTest):
    """Common features for bignum binary operations.

    This adds functionality common in binary operation tests.

    Attributes:
        symbol: Symbol to use for the operation in case description.
        input_values: List of values to use as test case inputs. These are
            combined to produce pairs of values.
        input_cases: List of tuples containing pairs of test case inputs. This
            can be used to implement specific pairs of inputs.
        unique_combinations_only: Boolean to select if test case combinations
            must be unique. If True, only A,B or B,A would be included as a test
            case. If False, both A,B and B,A would be included.
        arch_split: Boolean to select if different test cases are needed
            depending on the architecture/limb size. This will cause test
            objects being generated with different architectures. Individual
            test objects can tell their architecture by accessing the
            bits_in_limb instance variable.
    """
    symbol = ""
    input_values = [] # type: List[str]
    input_cases = [] # type: List[Tuple[str, str]]
    unique_combinations_only = True
    arch_split = False
    limb_sizes = [32, 64] # type: List[int]

    def __init__(self, val_a: str, val_b: str, bits_in_limb: int = 64) -> None:
        self.arg_a = val_a
        self.arg_b = val_b
        self.int_a = hex_to_int(val_a)
        self.int_b = hex_to_int(val_b)
        if bits_in_limb not in self.limb_sizes:
            raise ValueError("Invalid number of bits in limb!")
        if self.arch_split:
            self.dependencies = ["MBEDTLS_HAVE_INT{:d}".format(bits_in_limb)]
        self.bits_in_limb = bits_in_limb

    def arguments(self) -> List[str]:
        return [
            quote_str(self.arg_a), quote_str(self.arg_b)
        ] + self.result()

    def description(self) -> str:
        """Generate a description for the test case.

        If not set, case_description uses the form A `symbol` B, where symbol
        is used to represent the operation. Descriptions of each value are
        generated to provide some context to the test case.
        """
        if not self.case_description:
            self.case_description = "{:x} {} {:x}".format(
                self.int_a, self.symbol, self.int_b
            )
        return super().description()

    @abstractmethod
    def result(self) -> List[str]:
        """Get the result of the operation.

        This could be calculated during initialization and stored as `_result`
        and then returned, or calculated when the method is called.
        """
        raise NotImplementedError

    @classmethod
    def get_value_pairs(cls) -> Iterator[Tuple[str, str]]:
        """Generator to yield pairs of inputs.

        Combinations are first generated from all input values, and then
        specific cases provided.
        """
        if cls.unique_combinations_only:
            yield from combination_pairs(cls.input_values)
        else:
            yield from (
                (a, b)
                for a in cls.input_values
                for b in cls.input_values
            )
        yield from cls.input_cases

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for a_value, b_value in cls.get_value_pairs():
            if cls.arch_split:
                for bil in cls.limb_sizes:
                    yield cls(a_value, b_value,
                              bits_in_limb=bil).create_test_case()
            else:
                yield cls(a_value, b_value).create_test_case()


class ModOperationCommon(OperationCommon):
    #pylint: disable=abstract-method
    """Target for bignum mod_raw test case generation."""

    def __init__(self, val_n: str, val_a: str, val_b: str = "0",
                 bits_in_limb: int = 64) -> None:
        super().__init__(val_a=val_a, val_b=val_b, bits_in_limb=bits_in_limb)
        self.val_n = val_n

    @property
    def int_n(self) -> int:
        return hex_to_int(self.val_n)

    @property
    def boundary(self) -> int:
        data_in = [self.int_a, self.int_b, self.int_n]
        return max([n for n in data_in if n is not None])

    @property
    def limbs(self) -> int:
        return limbs_mpi(self.boundary, self.bits_in_limb)

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
        l = limbs_mpi(self.int_n, self.bits_in_limb)
        return bound_mpi_limbs(l, self.bits_in_limb)

    @property
    def r_inv(self) -> int:
        return invmod(self.r, self.int_n)

    @property
    def r2(self) -> int: # pylint: disable=invalid-name
        return pow(self.r, 2)


class OperationCommonArchSplit(OperationCommon):
    #pylint: disable=abstract-method
    """Common features for operations where the result depends on
    the limb size."""

    def __init__(self, val_a: str, val_b: str, bits_in_limb: int) -> None:
        super().__init__(val_a, val_b)
        bound_val = max(self.int_a, self.int_b)
        self.bits_in_limb = bits_in_limb
        self.bound = bound_mpi(bound_val, self.bits_in_limb)
        limbs = limbs_mpi(bound_val, self.bits_in_limb)
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

    def pad_to_limbs(self, val) -> str:
        return "{:x}".format(val).zfill(self.hex_digits)

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for a_value, b_value in cls.get_value_pairs():
            yield cls(a_value, b_value, 32).create_test_case()
            yield cls(a_value, b_value, 64).create_test_case()


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
