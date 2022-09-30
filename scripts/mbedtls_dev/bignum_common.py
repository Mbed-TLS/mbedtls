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

import itertools
import typing

from abc import abstractmethod
from typing import Iterator, List, Tuple, TypeVar

T = TypeVar('T') #pylint: disable=invalid-name

def hex_to_int(val: str) -> int:
    return int(val, 16) if val else 0

def quote_str(val) -> str:
    return "\"{}\"".format(val)

def bound_mpi8(val: int) -> int:
    """First number exceeding 8-byte limbs needed for given input value."""
    return bound_mpi8_limbs(limbs_mpi8(val))

def bound_mpi4(val: int) -> int:
    """First number exceeding 4-byte limbs needed for given input value."""
    return bound_mpi4_limbs(limbs_mpi4(val))

def bound_mpi8_limbs(limbs: int) -> int:
    """First number exceeding maximum of given 8-byte limbs."""
    bits = 64 * limbs
    return 1 << bits

def bound_mpi4_limbs(limbs: int) -> int:
    """First number exceeding maximum of given 4-byte limbs."""
    bits = 32 * limbs
    return 1 << bits

def limbs_mpi8(val: int) -> int:
    """Return the number of 8-byte limbs required to store value."""
    return (val.bit_length() + 63) // 64

def limbs_mpi4(val: int) -> int:
    """Return the number of 4-byte limbs required to store value."""
    return (val.bit_length() + 31) // 32

def combination_pairs(values: List[T]) -> List[Tuple[T, T]]:
    """Return all pair combinations from input values.

    The return value is cast, as older versions of mypy are unable to derive
    the specific type returned by itertools.combinations_with_replacement.
    """
    return typing.cast(
        List[Tuple[T, T]],
        list(itertools.combinations_with_replacement(values, 2))
    )


class OperationCommon:
    """Common features for bignum binary operations.

    This adds functionality common in binary operation tests.

    Attributes:
        symbol: Symbol to use for the operation in case description.
        input_values: List of values to use as test case inputs. These are
            combined to produce pairs of values.
        input_cases: List of tuples containing pairs of test case inputs. This
            can be used to implement specific pairs of inputs.
    """
    symbol = ""
    input_values = [] # type: List[str]
    input_cases = [] # type: List[Tuple[str, str]]

    def __init__(self, val_a: str, val_b: str) -> None:
        self.arg_a = val_a
        self.arg_b = val_b
        self.int_a = hex_to_int(val_a)
        self.int_b = hex_to_int(val_b)

    def arguments(self) -> List[str]:
        return [quote_str(self.arg_a), quote_str(self.arg_b), self.result()]

    @abstractmethod
    def result(self) -> str:
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
        yield from combination_pairs(cls.input_values)
        yield from cls.input_cases
