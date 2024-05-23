"""Generate test data for cryptographic mechanisms.

This module is a work in progress, only implementing a few cases for now.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

import hashlib
import hmac
from abc import ABCMeta, abstractmethod
from re import match
from typing import Callable, Dict, Iterator, List, Optional #pylint: disable=unused-import

from . import crypto_knowledge
from . import psa_information
from . import test_case


def psa_low_level_dependencies(*expressions: str) -> List[str]:
    """Infer dependencies of a PSA low-level test case by looking for PSA_xxx symbols.

    This function generates MBEDTLS_PSA_BUILTIN_xxx symbols.
    """
    high_level = psa_information.automatic_dependencies(*expressions)
    for dep in high_level:
        assert dep.startswith('PSA_WANT_')
    return ['MBEDTLS_PSA_BUILTIN_' + dep[9:] for dep in high_level]


class PSALowLevel(metaclass=ABCMeta):
    """Generate test cases for the PSA low-level interface."""

    def __init__(self, alg_type, info: psa_information.Information) -> None:
        self.info = info
        base_algorithms = sorted(info.constructors.algorithms)
        all_algorithms = \
            [crypto_knowledge.Algorithm(expr)
             for expr in info.constructors.generate_expressions(base_algorithms)]
        self.algorithms = \
            [alg
             for alg in all_algorithms
             if (not alg.is_wildcard and
                 alg.can_do(alg_type))]

    @staticmethod
    def one_test_case(alg: crypto_knowledge.Algorithm,
                      function: str,
                      note: str,
                      arguments: List[str]) -> test_case.TestCase:
        """Construct one test case."""
        tc = test_case.TestCase()
        tc.set_description('{}{} {}'
                           .format(function,
                                   ' ' + note if note else '',
                                   alg.short_expression()))
        tc.set_dependencies(psa_low_level_dependencies(alg.expression))
        tc.set_function(function)
        tc.set_arguments([alg.expression] +
                         ['"{}"'.format(arg) for arg in arguments])
        return tc

    @abstractmethod
    def test_cases(self,
                   alg: crypto_knowledge.Algorithm
                   ) -> Iterator[test_case.TestCase]:
        """Enumerate all test cases for one algorithm."""
        raise NotImplementedError

    def all_test_cases(self) -> Iterator[test_case.TestCase]:
        """Enumerate all test cases for all hash algorithms."""
        for alg in self.algorithms:
            yield from self.test_cases(alg)


class HashPSALowLevel(PSALowLevel):
    """Generate test cases for the PSA low-level hash interface."""

    def __init__(self, info: psa_information.Information) -> None:
        super().__init__(crypto_knowledge.AlgorithmCategory.HASH, info)
        # calculate[alg] = function to return the hash of its argument in hex
        # TO-DO: implement the None entries with a third-party library, because
        # hashlib might not have everything, depending on the Python version and
        # the underlying OpenSSL. On Ubuntu 16.04, truncated sha512 and sha3/shake
        # are not available. On Ubuntu 22.04, md2, md4 and ripemd160 are not
        # available.
        self.calculate = {
            'PSA_ALG_MD5': lambda data: hashlib.md5(data).hexdigest(),
            'PSA_ALG_RIPEMD160': None, #lambda data: hashlib.new('ripdemd160').hexdigest()
            'PSA_ALG_SHA_1': lambda data: hashlib.sha1(data).hexdigest(),
            'PSA_ALG_SHA_224': lambda data: hashlib.sha224(data).hexdigest(),
            'PSA_ALG_SHA_256': lambda data: hashlib.sha256(data).hexdigest(),
            'PSA_ALG_SHA_384': lambda data: hashlib.sha384(data).hexdigest(),
            'PSA_ALG_SHA_512': lambda data: hashlib.sha512(data).hexdigest(),
            'PSA_ALG_SHA_512_224': None, #lambda data: hashlib.new('sha512_224').hexdigest()
            'PSA_ALG_SHA_512_256': None, #lambda data: hashlib.new('sha512_256').hexdigest()
            'PSA_ALG_SHA3_224': None, #lambda data: hashlib.sha3_224(data).hexdigest(),
            'PSA_ALG_SHA3_256': None, #lambda data: hashlib.sha3_256(data).hexdigest(),
            'PSA_ALG_SHA3_384': None, #lambda data: hashlib.sha3_384(data).hexdigest(),
            'PSA_ALG_SHA3_512': None, #lambda data: hashlib.sha3_512(data).hexdigest(),
            'PSA_ALG_SHAKE256_512': None, #lambda data: hashlib.shake_256(data).hexdigest(64),
        } #type: Dict[str, Optional[Callable[[bytes], str]]]


    def test_cases(self,
                   alg: crypto_knowledge.Algorithm
                   ) -> Iterator[test_case.TestCase]:
        """Enumerate all test cases for one hash algorithm."""
        calc = self.calculate[alg.expression]
        if calc is None:
            return # not implemented yet

        short = b'abc'
        hash_short = calc(short)
        long = (b'Hello, world. Here are 16 unprintable bytes: ['
                b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a'
                b'\x80\x81\x82\x83\xfe\xff]. '
                b' This message was brought to you by a natural intelligence. '
                b' If you can read this, good luck with your debugging!')
        hash_long = calc(long)

        yield self.one_test_case(alg, 'hash_empty', '', [calc(b'')])
        yield self.one_test_case(alg, 'hash_valid_one_shot', '',
                                 [short.hex(), hash_short])
        for n in [0, 1, 64, len(long) - 1, len(long)]:
            yield self.one_test_case(alg, 'hash_valid_multipart',
                                     '{} + {}'.format(n, len(long) - n),
                                     [long[:n].hex(), calc(long[:n]),
                                      long[n:].hex(), hash_long])


class MacPSALowLevel(PSALowLevel):
    """Generate test cases for the PSA low-level hmac interface."""

    def __init__(self, info: psa_information.Information) -> None:
        super().__init__(crypto_knowledge.AlgorithmCategory.MAC, info)
        # calculate[alg] = function to return the hash of its argument in hex
        # TO-DO: implement the None entries with a third-party library, because
        # hmac might not have everything, depending on the Python version and
        # the underlying OpenSSL. On Ubuntu 16.04, truncated sha512 and sha3/shake
        # are not available. On Ubuntu 22.04, md2, md4 and ripemd160 are not
        # available.
        self.calculate = {
            'PSA_ALG_CBC_MAC': None,
            'PSA_ALG_CMAC': None,
            'PSA_ALG_HMAC(PSA_ALG_MD5)': \
                lambda key, msg: hmac.new(key, msg, 'md5').digest(),
            'PSA_ALG_HMAC(PSA_ALG_RIPEMD160)': \
                None, #lambda key, msg: hmac.new(key, msg, 'ripdemd160').digest()
            'PSA_ALG_HMAC(PSA_ALG_SHA_1)': \
                lambda key, msg: hmac.new(key, msg, 'sha1').digest(),
            'PSA_ALG_HMAC(PSA_ALG_SHA_224)': \
                lambda key, msg: hmac.new(key, msg, 'sha224').digest(),
            'PSA_ALG_HMAC(PSA_ALG_SHA_256)': \
                lambda key, msg: hmac.new(key, msg, 'sha256').digest(),
            'PSA_ALG_HMAC(PSA_ALG_SHA_384)': \
                lambda key, msg: hmac.new(key, msg, 'sha384').digest(),
            'PSA_ALG_HMAC(PSA_ALG_SHA_512)': \
                lambda key, msg: hmac.new(key, msg, 'sha512').digest(),
            'PSA_ALG_HMAC(PSA_ALG_SHA_512_224)': \
                None, #lambda key, msg: hmac.new(key, msg, 'sha512_224').digest()
            'PSA_ALG_HMAC(PSA_ALG_SHA_512_256)': \
                None, #lambda key, msg: hmac.new(key, msg, 'sha512_256').digest()
            'PSA_ALG_HMAC(PSA_ALG_SHA3_224)': \
                None, #lambda key, msg: hmac.new(key, msg, 'sha3_224').digest()
            'PSA_ALG_HMAC(PSA_ALG_SHA3_256)': \
                None, #lambda key, msg: hmac.new(key, msg, 'sha3_256').digest()
            'PSA_ALG_HMAC(PSA_ALG_SHA3_384)': \
                None, #lambda key, msg: hmac.new(key, msg, 'sha3_384').digest()
            'PSA_ALG_HMAC(PSA_ALG_SHA3_512)': \
                None, #lambda key, msg: hmac.new(key, msg, 'sha3_512').digest()
            'PSA_ALG_HMAC(PSA_ALG_SHAKE256_512)': \
                None, #lambda key, msg: hmac.new(key, msg, 'shake_256').digest()
        } #type: Dict[str, Optional[Callable[[bytes,bytes], bytes]]]


    def test_cases(self,
                   alg: crypto_knowledge.Algorithm
                   ) -> Iterator[test_case.TestCase]:
        """Enumerate all test cases for hmac for one hash algorithm."""

        m = match(r'PSA_ALG_TRUNCATED_MAC\((.*),([0-9]+)\)', alg.expression)
        if m is not None:
            truncate = lambda x: x[0:int(m.group(2))]
            calc = self.calculate[m.group(1)]
        else:
            truncate = lambda x: x
            calc = self.calculate[alg.expression]

        if calc is None:
            return # not implemented yet

        key = b'supadupasecretkey'
        short = b'abc'
        mac_short = truncate(calc(key, short))
        long = (b'Hello, world. Here are 16 unprintable bytes: ['
                b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a'
                b'\x80\x81\x82\x83\xfe\xff]. '
                b' This message was brought to you by a natural intelligence. '
                b' If you can read this, good luck with your debugging!')
        mac_long = truncate(calc(key, long))

        empty_args = [key, truncate(calc(key, b''))]
        empty_args = [each_byte.hex() for each_byte in empty_args]
        yield self.one_test_case(alg, 'mac_empty', '', empty_args)

        one_shot_args = [key, short, mac_short]
        one_shot_args = [each_byte.hex() for each_byte in one_shot_args]
        yield self.one_test_case(alg, 'mac_valid_one_shot', '', one_shot_args)
        for n in [0, 1, 64, len(long) - 1, len(long)]:
            calculated_part = truncate(calc(key, long[:n]))
            yield self.one_test_case(alg, 'mac_valid_multipart',
                                     '{} + {}'.format(n, len(long) - n),
                                     [key.hex(),
                                      long[:n].hex(), calculated_part.hex(),
                                      long[n:].hex(), mac_long.hex()])
