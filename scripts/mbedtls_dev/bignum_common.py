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

# Random test cases (A, B, N, N_description) generated with moduli_case_generate()
GENERATED_MODULI_CASES = [
    ("2", "2", "3", ""), ("1", "2", "3", ""), ("2", "1", "3", ""),
    ("6", "5", "7", ""), ("3", "4", "7", ""), ("1", "6", "7", ""), ("5", "6", "7", ""),
    ("3", "4", "B", ""), ("7", "4", "B", ""), ("9", "7", "B", ""), ("2", "a", "B", ""),
    ("25", "16", "29", "(0x29 is prime)"), ("8", "28", "29", ""),
    ("18", "21", "29", ""), ("15", "f", "29", ""),
    ("e2", "ea", "FF", ""), ("43", "72", "FF", ""),
    ("d8", "70", "FF", ""), ("3c", "7c", "FF", ""),
    ("99", "b9", "101", "(0x101 is prime)"), ("65", "b2", "101", ""),
    ("81", "32", "101", ""), ("51", "dd", "101", ""),
    ("d5", "143", "38B", "(0x38B is prime)"), ("3d", "387", "38B", ""),
    ("160", "2e5", "38B", ""), ("10f", "137", "38B", ""),
    ("7dac", "25a", "8003", "(0x8003 is prime)"), ("6f1c", "3286", "8003", ""),
    ("59ed", "2f3f", "8003", ""), ("6893", "736d", "8003", ""),
    ("d199", "2832", "10001", "(0x10001 is prime)"), ("c3b2", "3e5b", "10001", ""),
    ("abe4", "214e", "10001", ""), ("4360", "a05d", "10001", ""),
    ("3f5a1", "165b2", "7F7F7", ""), ("3bd29", "37863", "7F7F7", ""),
    ("60c47", "64819", "7F7F7", ""), ("16584", "12c49", "7F7F7", ""),
    ("1ff03f", "610347", "800009", "(0x800009 is prime)"), ("340fd5", "19812e", "800009", ""),
    ("3fe2e8", "4d0dc7", "800009", ""), ("40356", "e6392", "800009", ""),
    ("dd8a1d", "266c0e", "100002B", "(0x100002B is prime)"),
    ("3fa1cb", "847fd6", "100002B", ""), ("5f439d", "5c3196", "100002B", ""),
    ("18d645", "f72dc6", "100002B", ""),
    ("20051ad", "37def6e", "37EEE9D", "(0x37EEE9D is prime)"),
    ("2ec140b", "3580dbf", "37EEE9D", ""), ("1d91b46", "190d4fc", "37EEE9D", ""),
    ("34e488d", "1224d24", "37EEE9D", ""),
    ("2a4fe2cb", "263466a9", "8000000B", "(0x8000000B is prime)"),
    ("5643fe94", "29a1aefa", "8000000B", ""), ("29633513", "7b007ac4", "8000000B", ""),
    ("2439cef5", "5c9d5a47", "8000000B", ""),
    ("4de3cfaa", "50dea178", "8CD626B9", "(0x8CD626B9 is prime)"),
    ("b8b8563", "10dbbbac", "8CD626B9", ""), ("4e8a6151", "5574ec19", "8CD626B9", ""),
    ("69224878", "309cfc23", "8CD626B9", ""),
    ("fb6f7fb6", "afb05423", "10000000F", "(0x10000000F is prime)"),
    ("8391a243", "26034dcd", "10000000F", ""), ("d26b98c", "14b2d6aa", "10000000F", ""),
    ("6b9f1371", "a21daf1d", "10000000F", ""),
    (
        "9f49435ad", "c8264ade8", "174876E7E9",
        "0x174876E7E9 is prime (dec) 99999999977"
    ),
    ("c402da434", "1fb427acf", "174876E7E9", ""),
    ("f6ebc2bb1", "1096d39f2a", "174876E7E9", ""),
    ("153b7f7b6b", "878fda8ff", "174876E7E9", ""),
    ("2c1adbb8d6", "4384d2d3c6", "8000000017", "(0x8000000017 is prime)"),
    ("2e4f9cf5fb", "794f3443d9", "8000000017", ""),
    ("149e495582", "3802b8f7b7", "8000000017", ""),
    ("7b9d49df82", "69c68a442a", "8000000017", ""),
    ("683a134600", "6dd80ea9f6", "864CB9076D", "(0x864CB9076D is prime)"),
    ("13a870ff0d", "59b099694a", "864CB9076D", ""),
    ("37d06b0e63", "4d2147e46f", "864CB9076D", ""),
    ("661714f8f4", "22e55df507", "864CB9076D", ""),
    ("2f0a96363", "52693307b4", "F7F7F7F7F7", ""),
    ("3c85078e64", "f2275ecb6d", "F7F7F7F7F7", ""),
    ("352dae68d1", "707775b4c6", "F7F7F7F7F7", ""),
    ("37ae0f3e0b", "912113040f", "F7F7F7F7F7", ""),
    ("6dada15e31", "f58ed9eff7", "1000000000F", "(0x1000000000F is prime)"),
    ("69627a7c89", "cfb5ebd13d", "1000000000F", ""),
    ("a5e1ad239b", "afc030c731", "1000000000F", ""),
    ("f1cc45f4c5", "c64ad607c8", "1000000000F", ""),
    ("2ebad87d2e31", "4c72d90bca78", "800000000005", "(0x800000000005 is prime)"),
    ("a30b3cc50d", "29ac4fe59490", "800000000005", ""),
    ("33674e9647b4", "5ec7ee7e72d3", "800000000005", ""),
    ("3d956f474f61", "74070040257d", "800000000005", ""),
    ("48348e3717d6", "43fcb4399571", "800795D9BA47", "(0x800795D9BA47 is prime)"),
    ("5234c03cc99b", "2f3cccb87803", "800795D9BA47", ""),
    ("3ed13db194ab", "44b8f4ba7030", "800795D9BA47", ""),
    ("1c11e843bfdb", "95bd1b47b08", "800795D9BA47", ""),
    ("a81d11cb81fd", "1e5753a3f33d", "1000000000015", "(0x1000000000015 is prime)"),
    ("688c4db99232", "36fc0cf7ed", "1000000000015", ""),
    ("f0720cc07e07", "fc76140ed903", "1000000000015", ""),
    ("2ec61f8d17d1", "d270c85e36d2", "1000000000015", ""),
    (
        "6a24cd3ab63820", "ed4aad55e5e348", "100000000000051",
        "(0x100000000000051 is prime)"
    ),
    ("e680c160d3b248", "31e0d8840ed510", "100000000000051", ""),
    ("a80637e9aebc38", "bb81decc4e1738", "100000000000051", ""),
    ("9afa5a59e9d630", "be9e65a6d42938", "100000000000051", ""),
    ("ab5e104eeb71c000", "2cffbd639e9fea00", "ABCDEF0123456789", ""),
    ("197b867547f68a00", "44b796cf94654800", "ABCDEF0123456789", ""),
    ("329f9483a04f2c00", "9892f76961d0f000", "ABCDEF0123456789", ""),
    ("4a2e12dfb4545000", "1aa3e89a69794500", "ABCDEF0123456789", ""),
    (
        "8b9acdf013d140f000", "12e4ceaefabdf2b2f00", "25A55A46E5DA99C71C7",
        "0x25A55A46E5DA99C71C7 is the 3rd repunit prime(dec) 11111111111111111111111"
    ),
    ("1b8d960ea277e3f5500", "14418aa980e37dd000", "25A55A46E5DA99C71C7", ""),
    ("7314524977e8075980", "8172fa45618ccd0d80", "25A55A46E5DA99C71C7", ""),
    ("ca14f031769be63580", "147a2f3cf2964ca9400", "25A55A46E5DA99C71C7", ""),
    (
        "18532ba119d5cd0cf39735c0000", "25f9838e31634844924733000000",
        "314DC643FB763F2B8C0E2DE00879",
        "0x314DC643FB763F2B8C0E2DE00879 is (dec)99999999977^3"
    ),
    (
        "a56e2d2517519e3970e70c40000", "ec27428d4bb380458588fa80000",
        "314DC643FB763F2B8C0E2DE00879", ""
    ),
    (
        "1cb5e8257710e8653fff33a00000", "15fdd42fe440fd3a1d121380000",
        "314DC643FB763F2B8C0E2DE00879", ""
    ),
    (
        "e50d07a65fc6f93e538ce040000", "1f4b059ca609f3ce597f61240000",
        "314DC643FB763F2B8C0E2DE00879", ""
    ),
    (
        "1ea3ade786a095d978d387f30df9f20000000",
        "127c448575f04af5a367a7be06c7da0000000",
        "47BF19662275FA2F6845C74942ED1D852E521",
        "0x47BF19662275FA2F6845C74942ED1D852E521 is (dec) 99999999977^4"
    ),
    (
        "16e15b0ca82764e72e38357b1f10a20000000",
        "43e2355d8514bbe22b0838fdc3983a0000000",
        "47BF19662275FA2F6845C74942ED1D852E521", ""
    ),
    (
        "be39332529d93f25c3d116c004c620000000",
        "5cccec42370a0a2c89c6772da801a0000000",
        "47BF19662275FA2F6845C74942ED1D852E521", ""
    ),
    (
        "ecaa468d90de0eeda474d39b3e1fc0000000",
        "1e714554018de6dc0fe576bfd3b5660000000",
        "47BF19662275FA2F6845C74942ED1D852E521", ""
    ),
    (
        "32298816711c5dce46f9ba06e775c4bedfc770e6700000000000000",
        "8ee751fd5fb24f0b4a653cb3a0c8b7d9e724574d168000000000000",
        "97EDD86E4B5C4592C6D32064AC55C888A7245F07CA3CC455E07C931",
        (
            "0x97EDD86E4B5C4592C6D32064AC55C888A7245F07CA3CC455E07C931"
            " is (dec) 99999999977^6"
        )
    ),
    (
        "29213b9df3cfd15f4b428645b67b677c29d1378d810000000000000",
        "6cbb732c65e10a28872394dfdd1936d5171c3c3aac0000000000000",
        "97EDD86E4B5C4592C6D32064AC55C888A7245F07CA3CC455E07C931", ""
    ),
    (
        "6f18db06ad4abc52c0c50643dd13098abccd4a232f0000000000000",
        "7e6bf41f2a86098ad51f98dfc10490ba3e8081bc830000000000000",
        "97EDD86E4B5C4592C6D32064AC55C888A7245F07CA3CC455E07C931", ""
    ),
    (
        "62d3286cd706ad9d73caff63f1722775d7e8c731208000000000000",
        "530f7ba02ae2b04c2fe3e3d27ec095925631a6c2528000000000000",
        "97EDD86E4B5C4592C6D32064AC55C888A7245F07CA3CC455E07C931", ""
    ),
    (
        "a6c6503e3c031fdbf6009a89ed60582b7233c5a85de28b16000000000000000",
        "75c8ed18270b583f16d442a467d32bf95c5e491e9b8523798000000000000000",
        "DD15FE80B731872AC104DB37832F7E75A244AA2631BC87885B861E8F20375499",
        (
            "0xDD15FE80B731872AC104DB37832F7E75A244AA2631BC87885B861E8F20375499"
            " is (dec) 99999999977^7"
        )
    ),
    (
        "bf84d1f85cf6b51e04d2c8f4ffd03532d852053cf99b387d4000000000000000",
        "397ba5a743c349f4f28bc583ecd5f06e0a25f9c6d98f09134000000000000000",
        "DD15FE80B731872AC104DB37832F7E75A244AA2631BC87885B861E8F20375499", ""
    ),
    (
        "6db11c3a4152ed1a2aa6fa34b0903ec82ea1b88908dcb482000000000000000",
        "ac8ac576a74ad6ca48f201bf89f77350ce86e821358d85920000000000000000",
        "DD15FE80B731872AC104DB37832F7E75A244AA2631BC87885B861E8F20375499", ""
    ),
    (
        "3001d96d7fe8b733f33687646fc3017e3ac417eb32e0ec708000000000000000",
        "925ddbdac4174e8321a48a32f79640e8cf7ec6f46ea235a80000000000000000",
        "DD15FE80B731872AC104DB37832F7E75A244AA2631BC87885B861E8F20375499", ""
    ),
    (
        "1029048755f2e60dd98c8de6d9989226b6bb4f0db8e46bd1939de560000000000000000000",
        "51bb7270b2e25cec0301a03e8275213bb6c2f6e6ec93d4d46d36ca0000000000000000000",
        "141B8EBD9009F84C241879A1F680FACCED355DA36C498F73E96E880CF78EA5F96146380E41",
        (
            "0x141B8EBD9009F84C241879A1F680FACCED355DA36C498F73E96E880CF78EA5F96146"
            "380E41 is 99999999977^8"
        )
    ),
    (
        "1c5337ff982b3ad6611257dbff5bbd7a9920ba2d4f5838a0cc681ce000000000000000000",
        "520c5d049ca4702031ba728591b665c4d4ccd3b2b86864d4c160fd2000000000000000000",
        "141B8EBD9009F84C241879A1F680FACCED355DA36C498F73E96E880CF78EA5F96146380E41",
        ""
    ),
    (
        "57074dfa00e42f6555bae624b7f0209f218adf57f73ed34ab0ff90c000000000000000000",
        "41eb14b6c07bfd3d1fe4f4a610c17cc44fcfcda695db040e011065000000000000000000",
        "141B8EBD9009F84C241879A1F680FACCED355DA36C498F73E96E880CF78EA5F96146380E41",
        ""
    ),
    (
        "d8ed7feed2fe855e6997ad6397f776158573d425031bf085a615784000000000000000000",
        "6f121dcd18c578ab5e229881006007bb6d319b179f11015fe958b9c000000000000000000",
        "141B8EBD9009F84C241879A1F680FACCED355DA36C498F73E96E880CF78EA5F96146380E41",
        ""
    ),
    (
        (
            "2a462b156180ea5fe550d3758c764e06fae54e626b5f503265a09df76edbdfbf"
            "a1e6000000000000000000000000"
        ), (
            "1136f41d1879fd4fb9e49e0943a46b6704d77c068ee237c3121f9071cfd3e6a0"
            "0315800000000000000000000000"
        ), (
            "2A94608DE88B6D5E9F8920F5ABB06B24CC35AE1FBACC87D075C621C3E2833EC90"
            "2713E40F51E3B3C214EDFABC451"
        ), (
            "0x2A94608DE88B6D5E9F8920F5ABB06B24CC35AE1FBACC87D075C621C3E2833EC"
            "902713E40F51E3B3C214EDFABC451 is (dec) 99999999977^10"
        )
    ),
    (
        (
            "c1ac3800dfb3c6954dea391d206200cf3c47f795bf4a5603b4cb88ae7e574de47"
            "40800000000000000000000000"
        ), (
            "c0d16eda0549ede42fa0deb4635f7b7ce061fadea02ee4d85cba4c4f709603419"
            "3c800000000000000000000000"
        ), (
            "2A94608DE88B6D5E9F8920F5ABB06B24CC35AE1FBACC87D075C621C3E2833EC90"
            "2713E40F51E3B3C214EDFABC451"
        ), ""
    ),
    (
        (
            "19e45bb7633094d272588ad2e43bcb3ee341991c6731b6fa9d47c4018d7ce7bba"
            "5ee800000000000000000000000"
        ), (
            "1e4f83166ae59f6b9cc8fd3e7677ed8bfc01bb99c98bd3eb084246b64c1e18c33"
            "65b800000000000000000000000"
        ), (
            "2A94608DE88B6D5E9F8920F5ABB06B24CC35AE1FBACC87D075C621C3E2833EC90"
            "2713E40F51E3B3C214EDFABC451"
        ), ""
    ),
    (
        (
            "1aa93395fad5f9b7f20b8f9028a054c0bb7c11bb8520e6a95e5a34f06cb70bcdd"
            "01a800000000000000000000000"
        ), (
            "54b45afa5d4310192f8d224634242dd7dcfb342318df3d9bd37b4c614788ba13b"
            "8b000000000000000000000000"
        ), (
            "2A94608DE88B6D5E9F8920F5ABB06B24CC35AE1FBACC87D075C621C3E2833EC90"
            "2713E40F51E3B3C214EDFABC451"
        ), ""
    ),
    (
        (
            "544f2628a28cfb5ce0a1b7180ee66b49716f1d9476c466c57f0c4b23089917843"
            "06d48f78686115ee19e25400000000000000000000000000000000"
        ), (
            "677eb31ef8d66c120fa872a60cd47f6e10cbfdf94f90501bd7883cba03d185be0"
            "a0148d1625745e9c4c827300000000000000000000000000000000"
        ), (
            "8335616AED761F1F7F44E6BD49E807B82E3BF2BF11BFA6AF813C808DBF33DBFA1"
            "1DABD6E6144BEF37C6800000000000000000000000000000000051"
        ), (
            "0x8335616AED761F1F7F44E6BD49E807B82E3BF2BF11BFA6AF813C808DBF33DBF"
            "A11DABD6E6144BEF37C6800000000000000000000000000000000051 is prime,"
            " (dec) 10^143 + 3^4"
        )
    ),
    (
        (
            "76bb3470985174915e9993522aec989666908f9e8cf5cb9f037bf4aee33d8865c"
            "b6464174795d07e30015b80000000000000000000000000000000"
        ), (
            "6aaaf60d5784dcef612d133613b179a317532ecca0eed40b8ad0c01e6d4a6d8c7"
            "9a52af190abd51739009a900000000000000000000000000000000"
        ), (
            "8335616AED761F1F7F44E6BD49E807B82E3BF2BF11BFA6AF813C808DBF33DBFA1"
            "1DABD6E6144BEF37C6800000000000000000000000000000000051"
        ), ""
    ),
    (
        (
            "6cfdd6e60912e441d2d1fc88f421b533f0103a5322ccd3f4db84861643ad63fd6"
            "3d1d8cfbc1d498162786ba00000000000000000000000000000000"
        ), (
            "1177246ec5e93814816465e7f8f248b350d954439d35b2b5d75d917218e7fd5fb"
            "4c2f6d0667f9467fdcf33400000000000000000000000000000000"
        ), (
            "8335616AED761F1F7F44E6BD49E807B82E3BF2BF11BFA6AF813C808DBF33DBFA1"
            "1DABD6E6144BEF37C6800000000000000000000000000000000051"
        ), ""
    ),
    (
        (
            "7a09a0b0f8bbf8057116fb0277a9bdf3a91b5eaa8830d448081510d8973888be5"
            "a9f0ad04facb69aa3715f00000000000000000000000000000000"
        ), (
            "764dec6c05a1c0d87b649efa5fd94c91ea28bffb4725d4ab4b33f1a3e8e3b314d"
            "799020e244a835a145ec9800000000000000000000000000000000"
        ), (
            "8335616AED761F1F7F44E6BD49E807B82E3BF2BF11BFA6AF813C808DBF33DBFA1"
            "1DABD6E6144BEF37C6800000000000000000000000000000000051"
        ), ""
    )
]
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
