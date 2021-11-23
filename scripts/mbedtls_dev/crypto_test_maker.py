"""Generate unit test cases for Mbed TLS crypto functions.

Functions in this module are aligned with test functions in
``tests/suites/*.function`` at the time of writing, and their output is
suitable for corresponding ``.data`` files. However this module is not
meant to be complete and is not kept up to date.
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

import re
from typing import List, Optional, Union

from mbedtls_dev import crypto_knowledge
from mbedtls_dev import crypto_reference
from mbedtls_dev import test_case


class Common(test_case.TestCase):
    """Helper code for test function simulators."""

    def __init__(self, function: str, *args: str) -> None:
        """Dynamic dispatch to the method whose name is function.

        Extra args are passed to the function. If args is empty, function can
        be a colon-separated sequence where the first element is the function
        name, as in a data line in a .data file.

        The method must return a list of arguments which will be appended
        to the input arguments.
        """
        super().__init__()
        function = function.strip()
        if len(args) == 0 and ':' in function:
            parts = function.split(':')
            function = parts[0]
            args = tuple(arg for arg in parts[1:] if arg)
        outputs = getattr(self, function)(*args)
        self.function = function
        self.arguments = list(args) + list(outputs)

    @staticmethod
    def format(b: Union[int, bytes]) -> str:
        """Format a test parameter (int or hex string)."""
        if isinstance(b, bytes):
            return '"' + b.hex() + '"'
        else:
            return str(b)

    @staticmethod
    def parse_int(arg: Union[int, str]) -> int:
        """Parse an integer literal parameter.

        An already constructed integer is also accepted.
        """
        if isinstance(arg, int):
            return arg
        else:
            return int(arg, 0)

    @staticmethod
    def parse_bytes(arg: Union[bytes, str]) -> bytes:
        """Parse a hex string parameter.

        An already constructed bytes object is also accepted.
        """
        if isinstance(arg, bytes):
            return arg
        elif arg.startswith('"') and arg.endswith('"'):
            return bytes.fromhex(arg[1:-1])
        else:
            raise ValueError(arg)

    def data_line(self) -> str:
        """Format the data line of the test case."""
        assert self.function is not None
        return ':'.join([self.function] + self.arguments)


class PsaCrypto(Common):
    """test_suite_psa_crypto functions"""
    #pylint: disable=too-many-arguments

    def derive_key_type(
            self,
            alg: str, key_data: str,
            input1: str, input2: str,
            key_type: str, bits: Union[int, str],
            _output: Optional[str] = None
    ) -> List[str]:
        """Outputs: [exported_derived_key]"""
        # Parse the algorithm
        alg = alg.replace(' ', '')
        m = re.match(r'PSA_ALG_HKDF\((\w+)\)\Z', alg)
        if not m:
            raise TypeError('PSA crypto algorithm', alg)
        kdf_alg = crypto_reference.KeyDerivationAlgorithm(
            crypto_reference.KeyDerivationBaseAlgorithm.HKDF,
            crypto_reference.HashAlgorithm.from_psa(m.group(1))
        )
        # Parse the output key type
        m = re.match(r'(\w+)\(([\w,]*)\)?', key_type)
        if not m:
            raise TypeError('PSA key type', key_type)
        params = None if m.group(2) is None else m.group(2).split(',')
        kt = crypto_knowledge.KeyType(m.group(1), params)
        # Perform the key derivation
        op = crypto_reference.KeyDerivation(kdf_alg)
        op.input_bytes(crypto_reference.KeyDerivationInputStep.SECRET,
                       self.parse_bytes(key_data))
        op.input_bytes(crypto_reference.KeyDerivationInputStep.SALT,
                       self.parse_bytes(input1))
        op.input_bytes(crypto_reference.KeyDerivationInputStep.INFO,
                       self.parse_bytes(input2))
        output = self.format(op.output_key(kt, self.parse_int(bits)))
        return [output]
