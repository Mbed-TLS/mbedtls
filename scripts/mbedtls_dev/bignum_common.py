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

import random

from abc import abstractmethod
from typing import Dict, Iterator, List, Tuple, TypeVar

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


class OperationCommon:
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
    """
    symbol = ""
    input_values = [] # type: List[str]
    input_cases = [] # type: List[Tuple[str, str]]
    unique_combinations_only = True

    def __init__(self, val_a: str, val_b: str) -> None:
        self.arg_a = val_a
        self.arg_b = val_b
        self.int_a = hex_to_int(val_a)
        self.int_b = hex_to_int(val_b)

    def arguments(self) -> List[str]:
        return [
            quote_str(self.arg_a), quote_str(self.arg_b)
        ] + self.result()

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

# BEGIN MERGE SLOT 1

# END MERGE SLOT 1

# BEGIN MERGE SLOT 2

# END MERGE SLOT 2

# BEGIN MERGE SLOT 3

# END MERGE SLOT 3

# BEGIN MERGE SLOT 4

# END MERGE SLOT 4

# BEGIN MERGE SLOT 5
def moduli_case_generate() -> None:
    """Generate random valid inputs for tests using moduli.

    For each modulus, generates random values for A and B and simple descriptions
    for the test case.
    """
    moduli = [
        ("3", ""), ("7", ""), ("B", ""), ("29", ""), ("FF", ""),
        ("101", ""), ("38B", ""), ("8003", ""), ("10001", ""),
        ("7F7F7", ""), ("800009", ""), ("100002B", ""), ("37EEE9D", ""),
        ("8000000B", ""), ("8CD626B9", ""), ("10000000F", ""),
        ("174876E7E9", "is prime (dec) 99999999977"),
        ("8000000017", ""), ("864CB9076D", ""), ("F7F7F7F7F7", ""),
        ("1000000000F", ""), ("800000000005", ""), ("800795D9BA47", ""),
        ("1000000000015", ""), ("100000000000051", ""), ("ABCDEF0123456789", ""),
        (
            "25A55A46E5DA99C71C7",
            "is the 3rd repunit prime (dec) 11111111111111111111111"
        ),
        ("314DC643FB763F2B8C0E2DE00879", "is (dec)99999999977^3"),
        ("47BF19662275FA2F6845C74942ED1D852E521", "is (dec) 99999999977^4"),
        (
            "97EDD86E4B5C4592C6D32064AC55C888A7245F07CA3CC455E07C931",
            "is (dec) 99999999977^6"
        ),
        (
            "DD15FE80B731872AC104DB37832F7E75A244AA2631BC87885B861E8F20375499",
            "is (dec) 99999999977^7"
        ),
        (
            "141B8EBD9009F84C241879A1F680FACCED355DA36C498F73E96E880CF78EA5F96146380E41",
            "is (dec) 99999999977^8"
        ),
        (
            (
                "2A94608DE88B6D5E9F8920F5ABB06B24CC35AE1FBACC87D075C621C3E283"
                "3EC902713E40F51E3B3C214EDFABC451"
            ),
            "is (dec) 99999999977^10"
        ),
        (
            "8335616AED761F1F7F44E6BD49E807B82E3BF2BF11BFA6AF813C808DBF33DBFA11"
            "DABD6E6144BEF37C6800000000000000000000000000000000051",
            "is prime, (dec) 10^143 + 3^4"
        )
    ] # type: List[Tuple[str, str]]
    primes = [
        "3", "7", "B", "29", "101", "38B", "8003", "10001", "800009",
        "100002B", "37EEE9D", "8000000B", "8CD626B9",
        # From here they require > 1 4-byte MPI
        "10000000F", "174876E7E9", "8000000017", "864CB9076D", "1000000000F",
        "800000000005", "800795D9BA47", "1000000000015", "100000000000051",
        # From here they require > 1 8-byte MPI
        "25A55A46E5DA99C71C7",      # this is 11111111111111111111111 decimal
        # 10^143 + 3^4: (which is prime)
        # 100000000000000000000000000000000000000000000000000000000000000000000000000000
        # 000000000000000000000000000000000000000000000000000000000000000081
        (
            "8335616AED761F1F7F44E6BD49E807B82E3BF2BF11BFA6AF813C808DBF33DBFA11"
            "DABD6E6144BEF37C6800000000000000000000000000000000051"
        )
    ] # type: List[str]
    generated_inputs = []
    for mod, description in moduli:
        n = hex_to_int(mod)
        mod_read = "{:x}".format(n)
        case_count = 3 if n < 5 else 4
        cases = {} # type: Dict[int, int]
        i = 0
        while i < case_count:
            a = random.randint(1, n)
            b = random.randint(1, n)
            if cases.get(a) == b:
                continue
            cases[a] = b
            if description:
                out_description = "0x{} {}".format(mod_read, description)
            elif i == 0 and len(mod) > 1 and mod in primes:
                out_description = "(0x{} is prime)".format(mod)
            else:
                out_description = ""
            generated_inputs.append(
                ("{:x}".format(a), "{:x}".format(b), mod, out_description)
            )
            i += 1
    print(generated_inputs)
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
