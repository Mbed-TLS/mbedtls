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
from typing import Iterator, List, Tuple

from . import test_case
from . import test_data_generation
from . import bignum_common

class BignumCoreTarget(test_data_generation.BaseTarget, metaclass=ABCMeta):
    #pylint: disable=abstract-method
    """Target for bignum core test case generation."""
    target_basename = 'test_suite_bignum_core.generated'


class BignumCoreShiftR(BignumCoreTarget, metaclass=ABCMeta):
    """Test cases for mbedtls_bignum_core_shift_r()."""
    count = 0
    test_function = "mpi_core_shift_r"
    test_name = "Core shift right"

    DATA = [
        ('00', '0', [0, 1, 8]),
        ('01', '1', [0, 1, 2, 8, 64]),
        ('dee5ca1a7ef10a75', '64-bit',
         list(range(11)) + [31, 32, 33, 63, 64, 65, 71, 72]),
        ('002e7ab0070ad57001', '[leading 0 limb]',
         [0, 1, 8, 63, 64]),
        ('a1055eb0bb1efa1150ff', '80-bit',
         [0, 1, 8, 63, 64, 65, 72, 79, 80, 81, 88, 128, 129, 136]),
        ('020100000000000000001011121314151617', '138-bit',
         [0, 1, 8, 9, 16, 72, 73, 136, 137, 138, 144]),
    ]

    def __init__(self, input_hex: str, descr: str, count: int) -> None:
        self.input_hex = input_hex
        self.number_description = descr
        self.shift_count = count
        self.result = bignum_common.hex_to_int(input_hex) >> count

    def arguments(self) -> List[str]:
        return ['"{}"'.format(self.input_hex),
                str(self.shift_count),
                '"{:0{}x}"'.format(self.result, len(self.input_hex))]

    def description(self) -> str:
        return 'Core shift {} >> {}'.format(self.number_description,
                                            self.shift_count)

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for input_hex, descr, counts in cls.DATA:
            for count in counts:
                yield cls(input_hex, descr, count).create_test_case()

class BignumCoreCTLookup(BignumCoreTarget, metaclass=ABCMeta):
    """Test cases for mbedtls_mpi_core_ct_uint_table_lookup()."""
    test_function = "mpi_core_ct_uint_table_lookup"
    test_name = "Constant time MPI table lookup"

    bitsizes = [
        (32, "One limb"),
        (192, "Smallest curve sized"),
        (512, "Largest curve sized"),
        (2048, "Small FF/RSA sized"),
        (4096, "Large FF/RSA sized"),
        ]

    window_sizes = [0, 1, 2, 3, 4, 5, 6]

    def __init__(self,
                 bitsize: int, descr: str, window_size: int) -> None:
        self.bitsize = bitsize
        self.bitsize_description = descr
        self.window_size = window_size

    def arguments(self) -> List[str]:
        return [str(self.bitsize), str(self.window_size)]

    def description(self) -> str:
        return '{} - {} MPI with {} bit window'.format(
            BignumCoreCTLookup.test_name,
            self.bitsize_description,
            self.window_size
            )

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for bitsize, bitsize_description in cls.bitsizes:
            for window_size in cls.window_sizes:
                yield (cls(bitsize, bitsize_description, window_size)
                       .create_test_case())

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
            self.case_description = "{:x} {} {:x}".format(
                self.int_a, self.symbol, self.int_b
            )
        return super().description()

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for a_value, b_value in cls.get_value_pairs():
            yield cls(a_value, b_value).create_test_case()


class BignumCoreOperationArchSplit(BignumCoreOperation):
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

    def pad_to_limbs(self, val) -> str:
        return "{:x}".format(val).zfill(self.hex_digits)

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for a_value, b_value in cls.get_value_pairs():
            yield cls(a_value, b_value, 32).create_test_case()
            yield cls(a_value, b_value, 64).create_test_case()

class BignumCoreAddAndAddIf(BignumCoreOperationArchSplit):
    """Test cases for bignum core add and add-if."""
    count = 0
    symbol = "+"
    test_function = "mpi_core_add_and_add_if"
    test_name = "mpi_core_add_and_add_if"

    def result(self) -> List[str]:
        result = self.int_a + self.int_b

        carry, result = divmod(result, self.bound)

        return [
            bignum_common.quote_str(self.pad_to_limbs(result)),
            str(carry)
        ]

class BignumCoreSub(BignumCoreOperation):
    """Test cases for bignum core sub."""
    count = 0
    symbol = "-"
    test_function = "mpi_core_sub"
    test_name = "mbedtls_mpi_core_sub"
    unique_combinations_only = False

    def result(self) -> List[str]:
        if self.int_a >= self.int_b:
            result_4 = result_8 = self.int_a - self.int_b
            carry = 0
        else:
            bound_val = max(self.int_a, self.int_b)
            bound_4 = bignum_common.bound_mpi(bound_val, 32)
            result_4 = bound_4 + self.int_a - self.int_b
            bound_8 = bignum_common.bound_mpi(bound_val, 64)
            result_8 = bound_8 + self.int_a - self.int_b
            carry = 1
        return [
            "\"{:x}\"".format(result_4),
            "\"{:x}\"".format(result_8),
            str(carry)
        ]


class BignumCoreMLA(BignumCoreOperation):
    """Test cases for fixed-size multiply accumulate."""
    count = 0
    test_function = "mpi_core_mla"
    test_name = "mbedtls_mpi_core_mla"
    unique_combinations_only = False

    input_values = [
        "0", "1", "fffe", "ffffffff", "100000000", "20000000000000",
        "ffffffffffffffff", "10000000000000000", "1234567890abcdef0",
        "fffffffffffffffffefefefefefefefe",
        "100000000000000000000000000000000",
        "1234567890abcdef01234567890abcdef0",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "1234567890abcdef01234567890abcdef01234567890abcdef01234567890abcdef0",
        (
            "4df72d07b4b71c8dacb6cffa954f8d88254b6277099308baf003fab73227f"
            "34029643b5a263f66e0d3c3fa297ef71755efd53b8fb6cb812c6bbf7bcf17"
            "9298bd9947c4c8b14324140a2c0f5fad7958a69050a987a6096e9f055fb38"
            "edf0c5889eca4a0cfa99b45fbdeee4c696b328ddceae4723945901ec02507"
            "6b12b"
        )
    ] # type: List[str]
    input_scalars = [
        "0", "3", "fe", "ff", "ffff", "10000", "ffffffff", "100000000",
        "7f7f7f7f7f7f7f7f", "8000000000000000", "fffffffffffffffe"
    ] # type: List[str]

    def __init__(self, val_a: str, val_b: str, val_s: str) -> None:
        super().__init__(val_a, val_b)
        self.arg_scalar = val_s
        self.int_scalar = bignum_common.hex_to_int(val_s)
        if bignum_common.limbs_mpi(self.int_scalar, 32) > 1:
            self.dependencies = ["MBEDTLS_HAVE_INT64"]

    def arguments(self) -> List[str]:
        return [
            bignum_common.quote_str(self.arg_a),
            bignum_common.quote_str(self.arg_b),
            bignum_common.quote_str(self.arg_scalar)
        ] + self.result()

    def description(self) -> str:
        """Override and add the additional scalar."""
        if not self.case_description:
            self.case_description = "0x{} + 0x{} * 0x{}".format(
                self.arg_a, self.arg_b, self.arg_scalar
            )
        return super().description()

    def result(self) -> List[str]:
        result = self.int_a + (self.int_b * self.int_scalar)
        bound_val = max(self.int_a, self.int_b)
        bound_4 = bignum_common.bound_mpi(bound_val, 32)
        bound_8 = bignum_common.bound_mpi(bound_val, 64)
        carry_4, remainder_4 = divmod(result, bound_4)
        carry_8, remainder_8 = divmod(result, bound_8)
        return [
            "\"{:x}\"".format(remainder_4),
            "\"{:x}\"".format(carry_4),
            "\"{:x}\"".format(remainder_8),
            "\"{:x}\"".format(carry_8)
        ]

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        """Override for additional scalar input."""
        for a_value, b_value in cls.get_value_pairs():
            for s_value in cls.input_scalars:
                cur_op = cls(a_value, b_value, s_value)
                yield cur_op.create_test_case()


class BignumCoreMontmul(BignumCoreTarget):
    """Test cases for Montgomery multiplication."""
    count = 0
    test_function = "mpi_core_montmul"
    test_name = "mbedtls_mpi_core_montmul"

    start_2_mpi4 = False
    start_2_mpi8 = False

    replay_test_cases = [
        (2, 1, 1, 1, "19", "1", "1D"), (2, 1, 1, 1, "7", "1", "9"),
        (2, 1, 1, 1, "4", "1", "9"),
        (
            12, 1, 6, 1, (
                "3C246D0E059A93A266288A7718419EC741661B474C58C032C5EDAF92709402"
                "B07CC8C7CE0B781C641A1EA8DB2F4343"
            ), "1", (
                "66A198186C18C10B2F5ED9B522752A9830B69916E535C8F047518A889A43A5"
                "94B6BED27A168D31D4A52F88925AA8F5"
            )
        ), (
            8, 1, 4, 1,
            "1E442976B0E63D64FCCE74B999E470CA9888165CB75BFA1F340E918CE03C6211",
            "1", "B3A119602EE213CDE28581ECD892E0F592A338655DCE4CA88054B3D124D0E561"
        ), (
            22, 1, 11, 1, (
                "7CF5AC97304E0B63C65413F57249F59994B0FED1D2A8D3D83ED5FA38560FFB"
                "82392870D6D08F87D711917FD7537E13B7E125BE407E74157776839B0AC9DB"
                "23CBDFC696104353E4D2780B2B4968F8D8542306BCA7A2366E"
            ), "1", (
                "284139EA19C139EBE09A8111926AAA39A2C2BE12ED487A809D3CB5BC558547"
                "25B4CDCB5734C58F90B2F60D99CC1950CDBC8D651793E93C9C6F0EAD752500"
                "A32C56C62082912B66132B2A6AA42ADA923E1AD22CEB7BA0123"
            )
        )
    ] # type: List[Tuple[int, int, int, int, str, str, str]]

    random_test_cases = bignum_common.GENERATED_MODULI_CASES # type: List[Tuple[str, str, str, str]]

    def __init__(
            self, val_a: str, val_b: str, val_n: str, case_description: str = ""
        ):
        self.case_description = case_description
        self.arg_a = val_a
        self.int_a = bignum_common.hex_to_int(val_a)
        self.arg_b = val_b
        self.int_b = bignum_common.hex_to_int(val_b)
        self.arg_n = val_n
        self.int_n = bignum_common.hex_to_int(val_n)

        limbs_a4 = bignum_common.limbs_mpi(self.int_a, 32)
        limbs_a8 = bignum_common.limbs_mpi(self.int_a, 64)
        self.limbs_b4 = bignum_common.limbs_mpi(self.int_b, 32)
        self.limbs_b8 = bignum_common.limbs_mpi(self.int_b, 64)
        self.limbs_an4 = bignum_common.limbs_mpi(self.int_n, 32)
        self.limbs_an8 = bignum_common.limbs_mpi(self.int_n, 64)

        if limbs_a4 > self.limbs_an4 or limbs_a8 > self.limbs_an8:
            raise Exception("Limbs of input A ({}) exceeds N ({})".format(
                self.arg_a, self.arg_n
            ))

    def arguments(self) -> List[str]:
        return [
            str(self.limbs_an4), str(self.limbs_b4),
            str(self.limbs_an8), str(self.limbs_b8),
            bignum_common.quote_str(self.arg_a),
            bignum_common.quote_str(self.arg_b),
            bignum_common.quote_str(self.arg_n)
        ] + self.result()

    def description(self) -> str:
        if self.case_description != "replay":
            if not self.start_2_mpi4 and self.limbs_an4 > 1:
                tmp = "(start of 2-MPI 4-byte bignums) "
                self.__class__.start_2_mpi4 = True
            elif not self.start_2_mpi8 and self.limbs_an8 > 1:
                tmp = "(start of 2-MPI 8-byte bignums) "
                self.__class__.start_2_mpi8 = True
            else:
                tmp = "(gen) "
            self.case_description = tmp + self.case_description
        return super().description()

    def result(self) -> List[str]:
        """Get the result of the operation."""
        r4 = bignum_common.bound_mpi_limbs(self.limbs_an4, 32)
        i4 = bignum_common.invmod(r4, self.int_n)
        x4 = self.int_a * self.int_b * i4
        x4 = x4 % self.int_n

        r8 = bignum_common.bound_mpi_limbs(self.limbs_an8, 64)
        i8 = bignum_common.invmod(r8, self.int_n)
        x8 = self.int_a * self.int_b * i8
        x8 = x8 % self.int_n
        return [
            "\"{:x}\"".format(x4),
            "\"{:x}\"".format(x8)
        ]

    def set_limbs(
            self, limbs_an4: int, limbs_b4: int, limbs_an8: int, limbs_b8: int
        ) -> None:
        """Set number of limbs for each input.

        Replaces default values set during initialization.
        """
        self.limbs_an4 = limbs_an4
        self.limbs_b4 = limbs_b4
        self.limbs_an8 = limbs_an8
        self.limbs_b8 = limbs_b8

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        """Generate replay and randomly generated test cases."""
        # Test cases which replay captured invocations during unit test runs.
        for limbs_an4, limbs_b4, limbs_an8, limbs_b8, a, b, n in cls.replay_test_cases:
            cur_op = cls(a, b, n, case_description="replay")
            cur_op.set_limbs(limbs_an4, limbs_b4, limbs_an8, limbs_b8)
            yield cur_op.create_test_case()
        # Random test cases can be generated using mpi_modmul_case_generate()
        # Uses a mixture of primes and odd numbers as N, with four randomly
        # generated cases for each N.
        for a, b, n, description in cls.random_test_cases:
            cur_op = cls(a, b, n, case_description=description)
            yield cur_op.create_test_case()

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
