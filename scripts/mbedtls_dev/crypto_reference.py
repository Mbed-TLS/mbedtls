"""Reference implementation of some cryptographic mechanisms.

This module can be used to generate test cases.

This module requires the Cryptodome library installed with
``pip install pycryptodomex``. You need at least version 3.7.3 for
the type subs for mypy.
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

#pylint: disable=fixme,unused-import

import enum
import types
import typing
from typing import Dict, List, Optional, Set, Tuple

# TODO: support pycryptodome, which installs the Cryptodome library under the
# module name ``Crypto``.
from Cryptodome import Hash, Protocol, PublicKey
import Cryptodome.Hash.MD5
import Cryptodome.Hash.SHA1
import Cryptodome.Hash.SHA224
import Cryptodome.Hash.SHA256
import Cryptodome.Hash.SHA384
import Cryptodome.Hash.SHA512
import Cryptodome.Hash.SHA3_224
import Cryptodome.Hash.SHA3_256
import Cryptodome.Hash.SHA3_384
import Cryptodome.Hash.SHA3_512
import Cryptodome.Protocol.KDF

from mbedtls_dev import crypto_knowledge


class BadState(Exception):
    pass

class InsufficientData(Exception):
    pass

class InvalidArgument(Exception):
    pass

class NotSupported(Exception):
    pass


class HashAlgorithm(enum.Enum):
    """Encoding of a hash algorithm."""

    #pylint: disable=bad-whitespace
    MD2         = 0x01
    MD4         = 0x02
    MD5         = 0x03
    RIPEMD160   = 0x04
    SHA_1       = 0x05
    SHA_224     = 0x08
    SHA_256     = 0x09
    SHA_384     = 0x0a
    SHA_512     = 0x0b
    SHA_512_224 = 0x0c
    SHA_512_256 = 0x0d
    SHA3_224    = 0x10
    SHA3_256    = 0x11
    SHA3_384    = 0x12
    SHA3_512    = 0x13

    @classmethod
    def from_psa(cls, name: str) -> 'HashAlgorithm':
        """Convert from a PSA algorithm name."""
        if name.startswith('PSA_ALG_'):
            name = name[8:]
        return cls[name]

    def to_module(self) -> types.ModuleType:
        """Return a module that computes this hash."""
        #pylint: disable=too-many-return-statements
        if self == self.MD5:
            return Hash.MD5
        if self == self.SHA_1:
            return Hash.SHA1
        if self == self.SHA_224:
            return Hash.SHA224
        if self == self.SHA_256:
            return Hash.SHA256
        if self == self.SHA_384:
            return Hash.SHA384
        if self == self.SHA_512:
            return Hash.SHA512
        if self == self.SHA3_224:
            return Hash.SHA3_224
        if self == self.SHA3_256:
            return Hash.SHA3_256
        if self == self.SHA3_384:
            return Hash.SHA3_384
        if self == self.SHA3_512:
            return Hash.SHA3_512
        raise ValueError(self)


class KeyDerivationInputStep(enum.Enum):
    SECRET = 0x0101
    PASSWORD = 0x0102
    LABEL = 0x0201
    SALT = 0x0202
    INFO = 0x0203
    SEED = 0x0204
    COST = 0x0205

class KeyDerivationBaseAlgorithm(enum.Enum):
    """Encoding of a key derivation base algorithm (which can be parametrized by a hash)."""

    HKDF = 1

class KeyDerivationAlgorithm:
    """Encoding of a key derivation algorithm."""

    def __init__(self,
                 base: KeyDerivationBaseAlgorithm,
                 halg: HashAlgorithm) -> None:
        self.base = base
        self.hash = halg

    def get_base(self) -> KeyDerivationBaseAlgorithm:
        return self.base

    def get_hash(self) -> HashAlgorithm:
        return self.hash

class KeyDerivation:
    """PSA-like key derivation operation."""

    def __init__(self, alg: KeyDerivationAlgorithm) -> None:
        """Set up the key derivation operation.

        Similar to psa_key_derivation_setup().
        """
        self.alg = alg #type: KeyDerivationAlgorithm
        self.capacity = None #type: Optional[int] # None means infinite
        self.offset = None #type: Optional[int] # None means output not started
        self.inputs = {} #type: Dict[KeyDerivationInputStep, bytes]

    def set_capacity(self, capacity: int) -> None:
        """Cap or reduce the capacity of the operation.

        Similar to psa_key_derivation_set_capacity().
        """
        if self.capacity is not None and self.capacity < capacity:
            raise InvalidArgument('Cannot enlarge capacity')
        self.capacity = capacity

    def get_capacity(self) -> int:
        """Get the current capacity of the operation.

        Similar to psa_key_derivation_get_capacity().
        """
        if self.capacity is None:
            return 0xffffffffffffffff # approximate infinite as 2^64-1
        return self.capacity

    def input_bytes(self, step: KeyDerivationInputStep, data: bytes) -> None:
        """Provide one input to the key derivation.

        Similar to psa_key_derivation_input_bytes().
        """
        if self.offset is not None:
            raise BadState('Input not accepted after output has started')
        if step in self.inputs:
            raise BadState('Input step {} already passed'.format(step))
        if self.alg.get_base() == KeyDerivationBaseAlgorithm.HKDF:
            permitted_steps = frozenset([KeyDerivationInputStep.SALT,
                                         KeyDerivationInputStep.SECRET,
                                         KeyDerivationInputStep.INFO])
        else:
            raise NotImplementedError
        if step not in permitted_steps:
            raise InvalidArgument('Input step {} invalid'.format(step))
        self.inputs[step] = data

    def check_inputs(self) -> None:
        """Check that all required inputs are present.

        Set a value for optional inputs.
        """
        if self.alg.get_base() == KeyDerivationBaseAlgorithm.HKDF:
            if KeyDerivationInputStep.SALT not in self.inputs:
                self.inputs[KeyDerivationInputStep.SALT] = b''
            if KeyDerivationInputStep.SECRET not in self.inputs:
                raise BadState('Input step SECRET missing')
            if KeyDerivationInputStep.INFO not in self.inputs:
                raise BadState('Input step INFO missing')
        else:
            raise NotImplementedError

    def output_bytes(self, length: int) -> bytes:
        """Retrieve (more) bytes of output from the key derivation.

        Similar to psa_key_derivation_output_bytes().
        """
        if self.offset is None:
            self.check_inputs()
            self.offset = 0
        if self.capacity is not None:
            if length > self.capacity:
                raise InsufficientData
            self.capacity -= length
        if self.alg.get_base() == KeyDerivationBaseAlgorithm.HKDF:
            hashmod = self.alg.get_hash().to_module()
            whole_output = Protocol.KDF.HKDF(
                master=self.inputs[KeyDerivationInputStep.SECRET],
                key_len=self.offset+length,
                salt=self.inputs[KeyDerivationInputStep.SALT],
                hashmod=hashmod,
                context=self.inputs[KeyDerivationInputStep.INFO],
            )
            assert isinstance(whole_output, bytes)
            output = whole_output[self.offset:]
            assert len(output) == length
        else:
            raise NotImplementedError
        self.offset += length
        return output

