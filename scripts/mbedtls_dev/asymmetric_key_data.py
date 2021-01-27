"""Sample key material for asymmetric key types.

Meant for use in crypto_knowledge.py.
"""

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

import binascii
import re
from typing import Dict

STR_TRANS_REMOVE_BLANKS = str.maketrans('', '', ' \t\n\r')

def unhexlify(text: str) -> bytes:
    return binascii.unhexlify(text.translate(STR_TRANS_REMOVE_BLANKS))

def construct_asymmetric_key_data(src) -> Dict[str, Dict[int, bytes]]:
    """Split key pairs into separate table entries and convert hex to bytes.

    Input format: src[abbreviated_type][size] = (private_key_hex, public_key_hex)
    Output format: dst['PSA_KEY_TYPE_xxx'][size] = key_bytes
    """
    dst = {} #type: Dict[str, Dict[int, bytes]]
    for typ in src:
        private = 'PSA_KEY_TYPE_' + re.sub(r'(\(|\Z)', r'_KEY_PAIR\1', typ, 1)
        public = 'PSA_KEY_TYPE_' + re.sub(r'(\(|\Z)', r'_PUBLIC_KEY\1', typ, 1)
        dst[private] = {}
        dst[public] = {}
        for size in src[typ]:
            dst[private][size] = unhexlify(src[typ][size][0])
            dst[public][size] = unhexlify(src[typ][size][1])
    return dst

## These are valid keys that don't try to exercise any edge cases. They're
## either test vectors from some specification, or randomly generated. All
## pairs consist of a private key and its public key.
#pylint: disable=line-too-long
ASYMMETRIC_KEY_DATA = construct_asymmetric_key_data({
    'ECC(PSA_ECC_FAMILY_SECP_R1)': {
        256: ("49c9a8c18c4b885638c431cf1df1c994131609b580d4fd43a0cab17db2f13eee",
              "047772656f814b399279d5e1f1781fac6f099a3c5ca1b0e35351834b08b65e0b572590cdaf8f769361bcf34acfc11e5e074e8426bdde04be6e653945449617de45"),
        384: ("3f5d8d9be280b5696cc5cc9f94cf8af7e6b61dd6592b2ab2b3a4c607450417ec327dcdcaed7c10053d719a0574f0a76a",
              "04d9c662b50ba29ca47990450e043aeaf4f0c69b15676d112f622a71c93059af999691c5680d2b44d111579db12f4a413a2ed5c45fcfb67b5b63e00b91ebe59d09a6b1ac2c0c4282aa12317ed5914f999bc488bb132e8342cc36f2ca5e3379c747"),
        521: ("01b1b6ad07bb79e7320da59860ea28e055284f6058f279de666e06d435d2af7bda28d99fa47b7dd0963e16b0073078ee8b8a38d966a582f46d19ff95df3ad9685aae",
              "04001de142d54f69eb038ee4b7af9d3ca07736fd9cf719eb354d69879ee7f3c136fb0fbf9f08f86be5fa128ec1a051d3e6c643e85ada8ffacf3663c260bd2c844b6f5600cee8e48a9e65d09cadd89f235dee05f3b8a646be715f1f67d5b434e0ff23a1fc07ef7740193e40eeff6f3bcdfd765aa9155033524fe4f205f5444e292c4c2f6ac1"),
    },
    'RSA': {
        1024: ("""
3082025e
 020100
 02818100af057d396ee84fb75fdbb5c2b13c7fe5a654aa8aa2470b541ee1feb0b12d25c79711531249e1129628042dbbb6c120d1443524ef4c0e6e1d8956eeb2077af12349ddeee54483bc06c2c61948cd02b202e796aebd94d3a7cbf859c2c1819c324cb82b9cd34ede263a2abffe4733f077869e8660f7d6834da53d690ef7985f6bc3
 0203010001
 02818100874bf0ffc2f2a71d14671ddd0171c954d7fdbf50281e4f6d99ea0e1ebcf82faa58e7b595ffb293d1abe17f110b37c48cc0f36c37e84d876621d327f64bbe08457d3ec4098ba2fa0a319fba411c2841ed7be83196a8cdf9daa5d00694bc335fc4c32217fe0488bce9cb7202e59468b1ead119000477db2ca797fac19eda3f58c1
 024100e2ab760841bb9d30a81d222de1eb7381d82214407f1b975cbbfe4e1a9467fd98adbd78f607836ca5be1928b9d160d97fd45c12d6b52e2c9871a174c66b488113
 024100c5ab27602159ae7d6f20c3c2ee851e46dc112e689e28d5fcbbf990a99ef8a90b8bb44fd36467e7fc1789ceb663abda338652c3c73f111774902e840565927091
 024100b6cdbd354f7df579a63b48b3643e353b84898777b48b15f94e0bfc0567a6ae5911d57ad6409cf7647bf96264e9bd87eb95e263b7110b9a1f9f94acced0fafa4d
 024071195eec37e8d257decfc672b07ae639f10cbb9b0c739d0c809968d644a94e3fd6ed9287077a14583f379058f76a8aecd43c62dc8c0f41766650d725275ac4a1
 024100bb32d133edc2e048d463388b7be9cb4be29f4b6250be603e70e3647501c97ddde20a4e71be95fd5e71784e25aca4baf25be5738aae59bbfe1c997781447a2b24
""", """
 308189
  02818100af057d396ee84fb75fdbb5c2b13c7fe5a654aa8aa2470b541ee1feb0b12d25c79711531249e1129628042dbbb6c120d1443524ef4c0e6e1d8956eeb2077af12349ddeee54483bc06c2c61948cd02b202e796aebd94d3a7cbf859c2c1819c324cb82b9cd34ede263a2abffe4733f077869e8660f7d6834da53d690ef7985f6bc3
 0203010001
"""),
    },
})
