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

from abc import ABCMeta
from typing import Iterator, List

from . import test_case
from . import test_data_generation
from . import bignum_common

class BignumModRawTarget(test_data_generation.BaseTarget, metaclass=ABCMeta):
    #pylint: disable=abstract-method
    """Target for bignum mod_raw test case generation."""
    target_basename = 'test_suite_bignum_mod_raw.generated'

class BignumModRawOperation(bignum_common.OperationCommon, BignumModRawTarget, metaclass=ABCMeta):
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

class BignumModRawOperationArchSplit(BignumModRawOperation):
    #pylint: disable=abstract-method
    """Common features for bignum mod raw operations where the result depends on
    the limb size."""

    limb_sizes = [32, 64] # type: List[int]

    def __init__(self, val_n: str, val_a: str, val_b: str = "0", bits_in_limb: int = 64) -> None:
        super().__init__(val_n=val_n, val_a=val_a, val_b=val_b, bits_in_limb=bits_in_limb)

        if bits_in_limb not in self.limb_sizes:
            raise ValueError("Invalid number of bits in limb!")

        self.dependencies = ["MBEDTLS_HAVE_INT{:d}".format(bits_in_limb)]

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for a_value, b_value in cls.get_value_pairs():
            for bil in cls.limb_sizes:
                yield cls(a_value, b_value, bits_in_limb=bil).create_test_case()
# BEGIN MERGE SLOT 1

# END MERGE SLOT 1

# BEGIN MERGE SLOT 2

# END MERGE SLOT 2

# BEGIN MERGE SLOT 3

# END MERGE SLOT 3

# BEGIN MERGE SLOT 4

# END MERGE SLOT 4

# BEGIN MERGE SLOT 5
class BignumModRawOperation(bignum_common.OperationCommon, BignumModRawTarget, metaclass=ABCMeta):
    #pylint: disable=abstract-method
    """Common features for bignum mod raw operations."""
    modulus_input_cases = [
        ('1', '1', '3', ''), ('2', '2', '3', ''), ('1', '2', '3', ''),
        ('4', '4', '7', ''), ('1', '1', '7', ''),
        ('5', '5', '7', ''), ('1', '6', '7', ''),
        ('4', '6', 'B', ''), ('a', '9', 'B', ''),
        ('2', '6', 'B', ''), ('2', '5', 'B', ''),
        ('e', '23', '29', '(0x29 is prime)'),
        ('4', '4', '29', ''), ('d', '1c', '29', ''), ('20', '10', '29', ''),
        ('aa', '71', 'FF', ''), ('8d', '35', 'FF', ''), ('22', '9f', 'FF', ''),
        ('97', 'a6', 'FF', ''),
        ('f6', '8', '101', '(0x101 is prime)'),
        ('53', '39', '101', ''), ('fe', 'ed', '101', ''), ('ca', '5a', '101', ''),
        ('227', '2bd', '38B', '(0x38B is prime)'), ('37f', '11e', '38B', ''),
        ('1e1', '2e7', '38B', ''), ('2a6', '241', '38B', ''),
        ('785b', '5d22', '8003', '(0x8003 is prime)'), ('52d9', '580d', '8003', ''),
        ('6cfb', '6a96', '8003', ''), ('4555', '1fc1', '8003', ''),
        ('4add', 'd1fc', '10001', '(0x10001 is prime)'),
        ('3bdb', 'acf5', '10001', ''), ('9425', '76b3', '10001', ''),
        ('ac88', '5c3c', '10001', ''),
        ('7d7aa', '4a3d1', '7F7F7', ''), ('6d929', '45081', '7F7F7', ''),
        ('3aadd', 'dacd', '7F7F7', ''), ('10238', 'b9e6', '7F7F7', ''),
        ('421e2e', '260489', '800009', '(0x800009 is prime)'),
        ('1640f2', '78b356', '800009', ''), ('2b0c4c', '127eea', '800009', ''),
        ('1d306d', '6cc8df', '800009', ''),
        ('dc2732', '3c8100', '100002B', '(0x100002B is prime)'),
        ('c81e95', '10bac0', '100002B', ''), ('980948', 'cdd6b6', '100002B', ''),
        ('2eec7b', '9a92a0', '100002B', ''),
        ('1ce7570', '2360cfc', '37EEE9D', '(0x37EEE9D is prime)'),
        ('17f06e7', '11d6149', '37EEE9D', ''), ('1141301', 'ab463e', '37EEE9D', ''),
        ('3181497', '70c465', '37EEE9D', ''),
        ('5bcc7e7', '22727b3c', '8000000B', '(0x8000000B is prime)'),
        ('4daf4ea0', '219c1b66', '8000000B', ''), ('27cc772d', '29c18aa6', '8000000B', ''),
        ('45d46519', '417a070b', '8000000B', ''),
        ('6cf4d2d2', '3ddf2061', '8CD626B9', '(0x8CD626B9 is prime)'),
        ('ae896a9', '836ff74', '8CD626B9', ''), ('25bde6ab', '33a67856', '8CD626B9', ''),
        ('2e4bd5c6', '7d2c89d0', '8CD626B9', ''),
        ('79476456', 'aeadfbe0', '10000000F', '(0x10000000F is prime)'),
        ('ad81d0b', '5736a59', '10000000F', ''), ('b8eeac73', 'c157d159', '10000000F', ''),
        ('b391a5ca', 'a526d2e5', '10000000F', ''),
        ('d860265ac', '3390f84f2', '174876E7E9', '0x174876e7e9 is prime (dec) 99999999977'),
        ('106ea9118c', '13e38844c5', '174876E7E9', ''),
        ('156d09eeb6', '1138329b8a', '174876E7E9', ''),
        ('16e9168d6c', '6b36b1876', '174876E7E9', ''),
        ('51a9b7c713', '304acaee63', '8000000017', '(0x8000000017 is prime)'),
        ('747fbab258', '9ce70b248', '8000000017', ''),
        ('55e760ba9d', '2f2a9141c5', '8000000017', ''),
        ('506b5b4087', '3005c93631', '8000000017', ''),
        ('828095ff27', '18cd64acc9', '864CB9076D', '(0x864CB9076D is prime)'),
        ('2c492047f7', '6de4da25b8', '864CB9076D', ''),
        ('59c058ab9c', '5f59cce970', '864CB9076D', ''),
        ('71995b7a4c', '36445b9257', '864CB9076D', ''),
        ('3e522e9359', '82d6b62a24', 'F7F7F7F7F7', ''),
        ('7047aa58cf', 'e836f569c7', 'F7F7F7F7F7', ''),
        ('d8cd40436', 'aae1995a57', 'F7F7F7F7F7', ''),
        ('7aebaa254e', '9a06256db5', 'F7F7F7F7F7', ''),
        ('a71a53408a', '887e9041cd', '1000000000F', '(0x1000000000F is prime)'),
        ('13a4343abd', '8b46f31e47', '1000000000F', ''),
        ('d8a62d55a7', '76589492ab', '1000000000F', ''),
        ('2e41b6bd5c', '7902b19f63', '1000000000F', ''),
        ('2f5da7be0d65', '2c5a98b643c6', '800000000005', '(0x800000000005 is prime)'),
        ('587511799f09', '65cbc071f174', '800000000005', ''),
        ('713a1dcf70b1', '6f8e41e4e0af', '800000000005', ''),
        ('654b468150d6', '6e29fea931b9', '800000000005', ''),
        ('285d41131565', '574f7dad5a0f', '800795D9BA47', '(0x800795D9BA47 is prime)'),
        ('30dcfc8c8ee1', '390115343eee', '800795D9BA47', ''),
        ('50bdb09d2e3c', '4c55900a10e', '800795D9BA47', ''),
        ('495afd3c6e39', '46a74c3840ae', '800795D9BA47', ''),
        ('7ff671779376', '7113810a63a2', '1000000000015', '(0x1000000000015 is prime)'),
        ('68aad767ed30', 'a8560cd6e4c4', '1000000000015', ''),
        ('e773767dc918', '281ba84de08', '1000000000015', ''),
        ('66656c6aa75a', 'c9e4c6222159', '1000000000015', ''),
        ('e6846a2ce03c95', '65658d69de8640', '100000000000051', '(0x100000000000051 is prime)'),
        ('787715cc2f5ef5', '7e0189405a59c7', '100000000000051', ''),
        ('6b5ec3559f617a', '7eb8562ef5164a', '100000000000051', ''),
        ('6cb88015e3bd25', '6cfd305746768c', '100000000000051', ''),
        ('24be3840ebcddd0b', '29b7edad912616db', 'ABCDEF0123456789', ''),
        ('21714c6785528d1f', '38689b84c9b4140b', 'ABCDEF0123456789', ''),
        ('1eebfec7d24d7679', 'a10fb3b62abe6e39', 'ABCDEF0123456789', ''),
        ('2c2d765a1f3ff522', '24b333498ae4f7ba', 'ABCDEF0123456789', ''),
        (
            "22b26101b9755ec1359",
            "19347518a4ca98782cf",
            "25A55A46E5DA99C71C7",
            (
                "0x25a55a46e5da99c71c7 is the 3rd repunit prime (dec) 1111111111111111111111"
                "1"
            )
        ),
        ("2fe4a10f6c18460de2", "2029a8b1164dc73a0ea", "25A55A46E5DA99C71C7", ""),
        ("1cc51613a8fdee265f8", "19d30243bb169217f4e", "25A55A46E5DA99C71C7", ""),
        ("10e77d9e9d44674ce60", "21e8bfbd11936bda1e5", "25A55A46E5DA99C71C7", ""),
        (
            "1ad3ddfb9d66f948f60273c15231",
            "2a60a1e72d79a8f9ffd263ad5c9",
            "314DC643FB763F2B8C0E2DE00879",
            "0x314dc643fb763f2b8c0e2de00879 is (dec)99999999977^3"
        ),
        (
            "230ec7c100e018ffe9a0a9ee23d9",
            "1d4734b130f75e9cc67e7247459e",
            "314DC643FB763F2B8C0E2DE00879",
            ""
        ),
        (
            "1994b5c71998d17d05d076a3ff2d",
            "1cf2a78578abc575d658417b375d",
            "314DC643FB763F2B8C0E2DE00879",
            ""
        ),
        (
            "157a3c8bcea173401ca5eb61907d",
            "d54e810c2614af0984d3f4251d7",
            "314DC643FB763F2B8C0E2DE00879",
            ""
        ),
        (
            "38bd01e323cf58658f54128f280ee44984269",
            "104b1544d4b138cabb5b10867805ea2468ce9",
            "47BF19662275FA2F6845C74942ED1D852E521",
            "0x47bf19662275fa2f6845c74942ed1d852e521 is (dec) 99999999977^4"
        ),
        (
            "515f59a0c0212723ec3bf43baee93ec0e4b6",
            "2e59a49313118bb846de0880982963ad72bbe",
            "47BF19662275FA2F6845C74942ED1D852E521",
            "0x47bf19662275fa2f6845c74942ed1d852e521 is (dec) 99999999977^4",
        ),
        (
            "3dcc79d3f306f3065c8dd06b607e3bead1b33",
            "a7d9b5db961ed42f4fbc9080ec28f55b7652",
            "47BF19662275FA2F6845C74942ED1D852E521",
            "0x47bf19662275fa2f6845c74942ed1d852e521 is (dec) 99999999977^4",
        ),
        (
            "46d9cf7f5ebedb69524be3ce104dd4032a106",
            "224e8b9ea6a0d28ca1d9b116e2a9fa3c384d3",
            "47BF19662275FA2F6845C74942ED1D852E521",
            "0x47bf19662275fa2f6845c74942ed1d852e521 is (dec) 99999999977^4",
        ),
        (
            "420ce9a713c0fa57e5aad2d20ea9ebb7923090d1eafd3889a470726",
            "16eb0e0b157a49f43905797ac7ca33ccc99b22dc47189973cfe6d87",
            "97EDD86E4B5C4592C6D32064AC55C888A7245F07CA3CC455E07C931",
            (
                "0x97edd86e4b5c4592c6d32064ac55c888a7245f07ca3cc455e07c931 is (dec) 99999999"
                "977^6"
            )
        ),
        (
            "11c924fc3d55a5d1d6586c5f3e65372d2433a555d487bad25a0062e",
            "5492c8579e432a26ade285421e6bf31124cffacb1db4e3cf101306b",
            "97EDD86E4B5C4592C6D32064AC55C888A7245F07CA3CC455E07C931",
            ""
        ),
        (
            "7c7a4202fe96c8dc128783f25f224e24041beaec22e4f6d4717ca49",
            "86228f2216ebc82be610c1d42ce1dd1a61a8dcc15debaf62f605804",
            "97EDD86E4B5C4592C6D32064AC55C888A7245F07CA3CC455E07C931",
            ""
        ),
        (
            "4b5d09d792ad96e3183dcd58be49ba7e639c99aca9f02a0623f7ad4",
            "5a332603ddc0e307829c17c7d371c4f3f04f50038db33cb66a1f58",
            "97EDD86E4B5C4592C6D32064AC55C888A7245F07CA3CC455E07C931",
            ""
        ),
        (
            "c6b709197103ee6fac0f6d8546cb50547ed049a33343547820819af185fc42e2",
            "b1b95c801df2b6085f0cb178bc629c04e53d4f5fa9247b82a00e8515d9f498b1",
            "DD15FE80B731872AC104DB37832F7E75A244AA2631BC87885B861E8F20375499",
            (
                "0xdd15fe80b731872ac104db37832f7e75a244aa2631bc87885b861e8f20375499 is (dec)"
                " 99999999977^7"
            )
        ),
        (
            "b201f90f94e3c37884ffa97e417cfbbb64781847ac421c7f7376bfbe690fbccb",
            "9c5602656461bf4b4e461f5eda7382f08f3a51dbd3022270f34b5ce47521bf58",
            "DD15FE80B731872AC104DB37832F7E75A244AA2631BC87885B861E8F20375499",
            ""
        ),
        (
            "9e8b2e35935140b552246e18db090bdd895e04d6c48bdd01e4825168a940b6e9",
            "8d940e6208b16078734f449a226c7923dfc075e436f24fab4b147d5d684e6236",
            "DD15FE80B731872AC104DB37832F7E75A244AA2631BC87885B861E8F20375499",
            ""
        ),
        (
            "a31337b811caa2c82bb7e45ebfe0b2e441647089160460ab0ecc14b4f88e462f",
            "caca12179004230c2b6befa36bf824858b49218fe89e3bbabb6cb65de60cac98",
            "DD15FE80B731872AC104DB37832F7E75A244AA2631BC87885B861E8F20375499",
            ""
        ),
        (
            "e9b17d50032f18580f2450928fdfc642fcc9360ee6b0b87afa6684fffca6ae8dbc5137982",
            "8338f0f76be1cd422a16414797cee234c833cc79e3c2ab7ace25f74393107997172cc5ab3",
            "141B8EBD9009F84C241879A1F680FACCED355DA36C498F73E96E880CF78EA5F96146380E41",
            (
                "0x141b8ebd9009f84c241879a1f680facced355da36c498f73e96e880cf78ea5f96146380e4"
                "1 is (dec) 99999999977^8"
            ),
        ),
        (
            "d2bad1976c915fb047de661d041e1935f0e069d27821f85041ca0f1d7de9b30c43d45a4ca",
            "1111d9a55dce5998645c05159854a3249e52eb028849315303a5d370c63083f4be26ce6cec",
            "141B8EBD9009F84C241879A1F680FACCED355DA36C498F73E96E880CF78EA5F96146380E41",
            ""
        ),
        (
            "b17bf2884d65d7e4f927db2a00ad7f6a2573d6503b5fd9afa43a36435db230e5f0d840861",
            "53ddb006b78da1601483110f11717b914c8cb6190c4314766c029518105d8d5eb57171e63",
            "141B8EBD9009F84C241879A1F680FACCED355DA36C498F73E96E880CF78EA5F96146380E41",
            ""
        ),
        (
            "c0959708ad338b97881c844a715c577fbc767f9c134c768cb1d8ec450cd8fcc8aaef4299e",
            "d48e00413812626969d8e28a1067d1c217385f7d1b4f646557a5024b04554533b2e17be3d",
            "141B8EBD9009F84C241879A1F680FACCED355DA36C498F73E96E880CF78EA5F96146380E41",
            (
                "0x141b8ebd9009f84c241879a1f680facced355da36c498f73e96e880cf78ea5f96146380e4"
                "1 is (dec) 99999999977^8"
            ),
        ),
        (
            (
                "1ddec6e06c2028fca75c93545380715797b1a0ef0d62a1d46e41da6bb7318f4c7bff8433974"
                "53fa8c58e1db479d2"
            ),
            (
                "1c96ebcfa1dd0ef3cc2c18dd9d25a1c7d05ac9957abfc82623dc09f56608efaa5f463164a99"
                "c33385bd51f37b7ff"
            ),
            (
                "2A94608DE88B6D5E9F8920F5ABB06B24CC35AE1FBACC87D075C621C3E2833EC902713E40F51"
                "E3B3C214EDFABC451"
            ),
            (
                "0x2a94608de88b6d5e9f8920f5abb06b24cc35ae1fbacc87d075c621c3e2833ec902713e40f"
                "51e3b3c214edfabc451 is (dec) 99999999977^10"
            ),
        ),
        (
            (
                "1c69cf95d47246c5cb87185bfd347b9f13e71f4513055dbbd488c0da31334a0e1242db19d46"
                "07e56a12b6f7ed6e9"
            ),
            (
                "1ff83a67f26bacb0d2b4632704410890719895b34fc073b5c88120b1eebe7947a821907446b"
                "91a318732f38c2560"
            ),
            (
                "2A94608DE88B6D5E9F8920F5ABB06B24CC35AE1FBACC87D075C621C3E2833EC902713E40F51"
                "E3B3C214EDFABC451"
            ),
            (
                "0x2a94608de88b6d5e9f8920f5abb06b24cc35ae1fbacc87d075c621c3e2833ec902713e40f"
                "51e3b3c214edfabc451 is (dec) 99999999977^10"
            ),
        ),
        (
            (
                "1fb94a8e70af7a8c4bd7158127015c49792524121bfd70115952ce0e88d358f7e178f7869d7"
                "61cfb7ce9ac05ed24"
            ),
            (
                "26183f151f6dfb6cbc0f604fc86da6f236e214b9523433fcdc9ce4e9f1d9ae160f394ef2a2e"
                "0407f3c7c9ce598b7"
            ),
            (
                "2A94608DE88B6D5E9F8920F5ABB06B24CC35AE1FBACC87D075C621C3E2833EC902713E40F51"
                "E3B3C214EDFABC451"
            ),
            (
                "0x2a94608de88b6d5e9f8920f5abb06b24cc35ae1fbacc87d075c621c3e2833ec902713e40f"
                "51e3b3c214edfabc451 is (dec) 99999999977^10"
            ),
        ),
        (
            (
                "133a5029cceb75614fa1a1da5dc2b6ffd034c227a3923c9338cedc28caf194c32c95f152379"
                "e725a8bff6fdd7c99"
            ),
            (
                "129511d6de42ab2572916fff044f78abcce684996637baeea6100aedae21457484c9b262dba"
                "f0693de626cacc629"
            ),
            (
                "2A94608DE88B6D5E9F8920F5ABB06B24CC35AE1FBACC87D075C621C3E2833EC902713E40F51"
                "E3B3C214EDFABC451"
            ),
            (
                "0x2a94608de88b6d5e9f8920f5abb06b24cc35ae1fbacc87d075c621c3e2833ec902713e40f"
                "51e3b3c214edfabc451 is (dec) 99999999977^10"
            ),
        ),
        (
            (
                "47e652fbbf6ea9988c05a4ce9867556651af11f273888deab082bd19bc70db31f50f0be07e1"
                "c6ea54f30245ec217101df4409e455848436a94064df"
            ),
            (
                "555bb28ae570197e72c65c91534c2a3157671afa85effdbcea665272764f337aff730c9f2b1"
                "c36da60a6d90bc132cdb9428b9e24a9f051d7059d367"
            ),
            (
                "8335616AED761F1F7F44E6BD49E807B82E3BF2BF11BFA6AF813C808DBF33DBFA11DABD6E614"
                "4BEF37C6800000000000000000000000000000000051"
            ),
            (
                "0x8335616aed761f1f7f44e6bd49e807b82e3bf2bf11bfa6af813c808dbf33dbfa11dabd6e6"
                "144bef37c6800000000000000000000000000000000051 is prime, (dec) 10^143 + 3^4"
            ),
        ),
        (
            (
                "7393a93645f1bb55d3a9d7f82c26a1f5435a34491a33d64ce9cf73ce34d73cd9a34e3b8af42"
                "635f5088b44aa111921eef9312bdafeedf3a6499604b"
            ),
            (
                "20db0471c84e47f73f96570c0d7fadb20d1b83541a24d3cbd68069b53dfa24445af024bd7fa"
                "4e608d2733efc72f10d9e9353cfb446c31ad5b23252e"
            ),
            (
                "8335616AED761F1F7F44E6BD49E807B82E3BF2BF11BFA6AF813C808DBF33DBFA11DABD6E614"
                "4BEF37C6800000000000000000000000000000000051"
            ),
            (
                "0x8335616aed761f1f7f44e6bd49e807b82e3bf2bf11bfa6af813c808dbf33dbfa11dabd6e6"
                "144bef37c6800000000000000000000000000000000051 is prime, (dec) 10^143 + 3^4"
            ),
        ),
        (
            (
                "3037c19db086c4013e348d0a4f1a64266c94789b30135314e1d196a21d2567c2fe9c71a5f76"
                "7f42c0e30fdddd3b8630612e7c906fc1cca410eab2a5"
            ),
            (
                "5abf09db098310045b5cef2a8e691d439216ee9086f27a6159dd7f4aafe2d91c23ecdbbb571"
                "bc3d691dc0f6fc7f040647ebb0f8e03e0c6b40d6eb12"
            ),
            (
                "8335616AED761F1F7F44E6BD49E807B82E3BF2BF11BFA6AF813C808DBF33DBFA11DABD6E614"
                "4BEF37C6800000000000000000000000000000000051"
            ),
            (
                "0x8335616aed761f1f7f44e6bd49e807b82e3bf2bf11bfa6af813c808dbf33dbfa11dabd6e6"
                "144bef37c6800000000000000000000000000000000051 is prime, (dec) 10^143 + 3^4"
            ),
        ),
        (
            (
                "18a848c36b0e048b9ea7a13b38dd7b1a866c65501fb34505b6216c5451f7ab624589f416bd8"
                "d2a54d84d0d1f71b2822f18ea8ddc35be6fec3ef64db"
            ),
            (
                "f77c1bb58578cea7df86e324a7734c3708892ba60e785b13f9fd976a4b69cf3da041c33312e"
                "771cb02c8fcaae065e4957dac45d217266b624ecc9"
            ),
            (
                "8335616AED761F1F7F44E6BD49E807B82E3BF2BF11BFA6AF813C808DBF33DBFA11DABD6E614"
                "4BEF37C6800000000000000000000000000000000051"
            ),
            (
                "0x8335616aed761f1f7f44e6bd49e807b82e3bf2bf11bfa6af813c808dbf33dbfa11dabd6e6"
                "144bef37c6800000000000000000000000000000000051 is prime, (dec) 10^143 + 3^4"
            ),
        ),
    ]

    def __init__(self, val_a: str, val_b: str, modulus: str, mod_desc: str) -> None:
        super().__init__(val_a, val_b)
        self.arg_n = modulus
        self.int_n = bignum_common.hex_to_int(modulus)
        self.mod_desc = mod_desc

    def description(self) -> str:
        """Generate a description for the test case.

        If not set, case_description uses the form A `symbol` B mod N, where
        symbol is used to represent the operation. Descriptions of each value
        are generated to provide some context to the test case.
        """
        if not self.case_description:
            self.case_description = "{:x} {} {:x} mod {:x} {}".format(
                self.int_a, self.symbol, self.int_b, self.int_n, self.mod_desc
            ).strip()
        return super().description()

    def arguments(self) -> List[str]:
        return [
            bignum_common.quote_str(self.arg_a),
            bignum_common.quote_str(self.arg_b),
            bignum_common.quote_str(self.arg_n),
        ] + self.result()

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for a, b, n, mod_desc in cls.modulus_input_cases:
            yield cls(a, b, n, mod_desc).create_test_case()


class BignumModRawAdd(BignumModRawOperation):
    """Test cases for mbedtls_mpi_mod_raw_add."""
    count = 0
    symbol = "+"
    test_function = "mpi_mod_raw_add"
    test_name = "mod_raw add"

    def result(self) -> List[str]:
        result = (self.int_a + self.int_b) % self.int_n
        limbs = bignum_common.limbs_mpi(self.int_n, 32)
        return [bignum_common.quote_str(bignum_common.grow_mpi(result, limbs, 32))]

# END MERGE SLOT 5

# BEGIN MERGE SLOT 6

# END MERGE SLOT 6

# BEGIN MERGE SLOT 7
class BignumModRawConvertToMont(BignumModRawOperationArchSplit):
    """ Test cases for mpi_mod_raw_to_mont_rep(). """

    test_function = "mpi_mod_raw_to_mont_rep"
    test_name = "Convert into Mont: "

    test_data_moduli = ["b",
                        "fd",
                        "eeff99aa37",
                        "eeff99aa11",
                        "800000000005",
                        "7fffffffffffffff",
                        "80fe000a10000001",
                        "25a55a46e5da99c71c7",
                        "1058ad82120c3a10196bb36229c1",
                        "7e35b84cb19ea5bc57ec37f5e431462fa962d98c1e63738d4657f"
                        "18ad6532e6adc3eafe67f1e5fa262af94cee8d3e7268593942a2a"
                        "98df75154f8c914a282f8b",
                        "8335616aed761f1f7f44e6bd49e807b82e3bf2bf11bfa63",
                        "ffcece570f2f991013f26dd5b03c4c5b65f97be5905f36cb4664f"
                        "2c78ff80aa8135a4aaf57ccb8a0aca2f394909a74cef1ef6758a6"
                        "4d11e2c149c393659d124bfc94196f0ce88f7d7d567efa5a649e2"
                        "deefaa6e10fdc3deac60d606bf63fc540ac95294347031aefd73d"
                        "6a9ee10188aaeb7a90d920894553cb196881691cadc51808715a0"
                        "7e8b24fcb1a63df047c7cdf084dd177ba368c806f3d51ddb5d389"
                        "8c863e687ecaf7d649a57a46264a582f94d3c8f2edaf59f77a7f6"
                        "bdaf83c991e8f06abe220ec8507386fce8c3da84c6c3903ab8f3a"
                        "d4630a204196a7dbcbd9bcca4e40ec5cc5c09938d49f5e1e6181d"
                        "b8896f33bb12e6ef73f12ec5c5ea7a8a337"
                        ]

    test_input_numbers = ["0",
                          "1",
                          "97",
                          "f5",
                          "6f5c3",
                          "745bfe50f7",
                          "ffa1f9924123",
                          "334a8b983c79bd",
                          "5b84f632b58f3461",
                          "19acd15bc38008e1",
                          "ffffffffffffffff",
                          "54ce6a6bb8247fa0427cfc75a6b0599",
                          "fecafe8eca052f154ce6a6bb8247fa019558bfeecce9bb9",
                          "a87d7a56fa4bfdc7da42ef798b9cf6843d4c54794698cb14d72"
                          "851dec9586a319f4bb6d5695acbd7c92e7a42a5ede6972adcbc"
                          "f68425265887f2d721f462b7f1b91531bac29fa648facb8e3c6"
                          "1bd5ae42d5a59ba1c89a95897bfe541a8ce1d633b98f379c481"
                          "6f25e21f6ac49286b261adb4b78274fe5f61c187581f213e84b"
                          "2a821e341ef956ecd5de89e6c1a35418cd74a549379d2d4594a"
                          "577543147f8e35b3514e62cf3e89d1156cdc91ab5f4c928fbd6"
                          "9148c35df5962fed381f4d8a62852a36823d5425f7487c13a12"
                          "523473fb823aa9d6ea5f42e794e15f2c1a8785cf6b7d51a4617"
                          "947fb3baf674f74a673cf1d38126983a19ed52c7439fab42c2185"
                          ]

    descr_tpl = '{} #{} N: \"{}\" A: \"{}\".'

    def result(self) -> List[str]:
        return [self.hex_x]

    def arguments(self) -> List[str]:
        return [bignum_common.quote_str(n) for n in [self.hex_n,
                                                     self.hex_a,
                                                     self.hex_x]]

    def description(self) -> str:
        return self.descr_tpl.format(self.test_name,
                                     self.count,
                                     self.int_n,
                                     self.int_a)

    @classmethod
    def generate_function_tests(cls) -> Iterator[test_case.TestCase]:
        for bil in [32, 64]:
            for n in cls.test_data_moduli:
                for i in cls.test_input_numbers:
                    # Skip invalid combinations where A.limbs > N.limbs
                    if bignum_common.hex_to_int(i) > bignum_common.hex_to_int(n):
                        continue
                    yield cls(n, i, bits_in_limb=bil).create_test_case()

    @property
    def x(self) -> int: # pylint: disable=invalid-name
        return (self.int_a * self.r) % self.int_n

    @property
    def hex_x(self) -> str:
        return "{:x}".format(self.x).zfill(self.hex_digits)

class BignumModRawConvertFromMont(BignumModRawConvertToMont):
    """ Test cases for mpi_mod_raw_from_mont_rep(). """

    test_function = "mpi_mod_raw_from_mont_rep"
    test_name = "Convert from Mont: "

    test_input_numbers = ["0",
                          "1",
                          "3ca",
                          "539ed428",
                          "7dfe5c6beb35a2d6",
                          "dca8de1c2adfc6d7aafb9b48e",
                          "a7d17b6c4be72f3d5c16bf9c1af6fc933",
                          "2fec97beec546f9553142ed52f147845463f579",
                          "378dc83b8bc5a7b62cba495af4919578dce6d4f175cadc4f",
                          "b6415f2a1a8e48a518345db11f56db3829c8f2c6415ab4a395a"
                          "b3ac2ea4cbef4af86eb18a84eb6ded4c6ecbfc4b59c2879a675"
                          "487f687adea9d197a84a5242a5cf6125ce19a6ad2e7341f1c57"
                          "d43ea4f4c852a51cb63dabcd1c9de2b827a3146a3d175b35bea"
                          "41ae75d2a286a3e9d43623152ac513dcdea1d72a7da846a8ab3"
                          "58d9be4926c79cfb287cf1cf25b689de3b912176be5dcaf4d4c"
                          "6e7cb839a4a3243a6c47c1e2c99d65c59d6fa3672575c2f1ca8"
                          "de6a32e854ec9d8ec635c96af7679fce26d7d159e4a9da3bd74"
                          "e1272c376cd926d74fe3fb164a5935cff3d5cdb92b35fe2cea32"
                          "138a7e6bfbc319ebd1725dacb9a359cbf693f2ecb785efb9d627"
                         ]

    @property
    def x(self): # pylint: disable=invalid-name
        return (self.int_a * self.r_inv) % self.int_n
# END MERGE SLOT 7

# BEGIN MERGE SLOT 8

# END MERGE SLOT 8

# BEGIN MERGE SLOT 9

# END MERGE SLOT 9

# BEGIN MERGE SLOT 10

# END MERGE SLOT 10
