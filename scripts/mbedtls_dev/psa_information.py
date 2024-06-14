"""Collect information about PSA cryptographic mechanisms.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later


import re
from typing import Dict, FrozenSet, Iterator, List, Optional, Set

from . import macro_collector
from . import test_case


def psa_want_symbol(name: str) -> str:
    """Return the PSA_WANT_xxx symbol associated with a PSA crypto feature."""
    if name.startswith('PSA_'):
        return name[:4] + 'WANT_' + name[4:]
    else:
        raise ValueError('Unable to determine the PSA_WANT_ symbol for ' + name)

def finish_family_dependency(dep: str, bits: int) -> str:
    """Finish dep if it's a family dependency symbol prefix.
    A family dependency symbol prefix is a PSA_WANT_ symbol that needs to be
    qualified by the key size. If dep is such a symbol, finish it by adjusting
    the prefix and appending the key size. Other symbols are left unchanged.
    """
    return re.sub(r'_FAMILY_(.*)', r'_\1_' + str(bits), dep)

def finish_family_dependencies(dependencies: List[str], bits: int) -> List[str]:
    """Finish any family dependency symbol prefixes.
    Apply `finish_family_dependency` to each element of `dependencies`.
    """
    return [finish_family_dependency(dep, bits) for dep in dependencies]

SYMBOLS_WITHOUT_DEPENDENCY = frozenset([
    'PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG', # modifier, only in policies
    'PSA_ALG_AEAD_WITH_SHORTENED_TAG', # modifier
    'PSA_ALG_ANY_HASH', # only in policies
    'PSA_ALG_AT_LEAST_THIS_LENGTH_MAC', # modifier, only in policies
    'PSA_ALG_KEY_AGREEMENT', # chaining
    'PSA_ALG_TRUNCATED_MAC', # modifier
])

def automatic_dependencies(*expressions: str) -> List[str]:
    """Infer dependencies of a test case by looking for PSA_xxx symbols.
    The arguments are strings which should be C expressions. Do not use
    string literals or comments as this function is not smart enough to
    skip them.
    """
    used = set()
    for expr in expressions:
        used.update(re.findall(r'PSA_(?:ALG|ECC_FAMILY|KEY_TYPE)_\w+', expr))
    used.difference_update(SYMBOLS_WITHOUT_DEPENDENCY)
    return sorted(psa_want_symbol(name) for name in used)


class Information:
    """Gather information about PSA constructors."""

    def __init__(self) -> None:
        self.constructors = self.read_psa_interface()

    @staticmethod
    def remove_unwanted_macros(
            constructors: macro_collector.PSAMacroEnumerator
    ) -> None:
        """Remove macros from consideration during value enumeration."""
        # Remove some mechanisms that are declared but not implemented.
        # The corresponding test cases would be commented out anyway
        # thanks to the detect_not_implemented_dependencies mechanism,
        # but for those particular key types, we don't even have enough
        # support in the test scripts to construct test keys. So
        # we arrange to not even attempt to generate test cases.
        constructors.key_types.discard('PSA_KEY_TYPE_DH_KEY_PAIR')
        constructors.key_types.discard('PSA_KEY_TYPE_DH_PUBLIC_KEY')
        constructors.key_types.discard('PSA_KEY_TYPE_DSA_KEY_PAIR')
        constructors.key_types.discard('PSA_KEY_TYPE_DSA_PUBLIC_KEY')

    def read_psa_interface(self) -> macro_collector.PSAMacroEnumerator:
        """Return the list of known key types, algorithms, etc."""
        constructors = macro_collector.InputsForTest()
        header_file_names = ['include/psa/crypto_values.h',
                             'include/psa/crypto_extra.h']
        test_suites = ['tests/suites/test_suite_psa_crypto_metadata.data']
        for header_file_name in header_file_names:
            constructors.parse_header(header_file_name)
        for test_cases in test_suites:
            constructors.parse_test_cases(test_cases)
        self.remove_unwanted_macros(constructors)
        constructors.gather_arguments()
        return constructors


class TestCase(test_case.TestCase):
    """A PSA test case with automatically inferred dependencies.

    For mechanisms like ECC curves where the support status includes
    the key bit-size, this class assumes that only one bit-size is
    involved in a given test case.
    """

    # Use a class variable to cache the set of implemented dependencies.
    # Call read_implemented_dependencies() to fill the cache.
    _implemented_dependencies = None #type: Optional[FrozenSet[str]]

    DEPENDENCY_SYMBOL_RE = re.compile(r'\bPSA_WANT_\w+\b')
    @classmethod
    def _yield_implemented_dependencies(cls) -> Iterator[str]:
        for filename in ['include/psa/crypto_config.h',
                         'include/mbedtls/config_psa.h']:
            with open(filename) as inp:
                content = inp.read()
            yield from cls.DEPENDENCY_SYMBOL_RE.findall(content)

    @classmethod
    def read_implemented_dependencies(cls) -> FrozenSet[str]:
        if cls._implemented_dependencies is None:
            cls._implemented_dependencies = \
                frozenset(cls._yield_implemented_dependencies())
            # Redundant return to reassure pylint (mypy is fine without it).
            # Known issue: https://github.com/pylint-dev/pylint/issues/3045
            return cls._implemented_dependencies
        return cls._implemented_dependencies

    # We skip test cases for which the dependency symbols are not defined.
    # We assume that this means that a required mechanism is not implemented.
    # Note that if we erroneously skip generating test cases for
    # mechanisms that are not implemented, this should be caught
    # by the NOT_SUPPORTED test cases generated by generate_psa_tests.py
    # in test_suite_psa_crypto_not_supported and test_suite_psa_crypto_op_fail:
    # those emit negative tests, which will not be skipped here.
    def detect_not_implemented_dependencies(self) -> None:
        """Detect dependencies that are not implemented."""
        all_implemented_dependencies = self.read_implemented_dependencies()
        not_implemented = [dep
                           for dep in self.dependencies
                           if (dep.startswith('PSA_WANT') and
                               dep not in all_implemented_dependencies)]
        if not_implemented:
            self.skip_because('not implemented: ' +
                              ' '.join(not_implemented))

    def __init__(self) -> None:
        super().__init__()
        self.key_bits = None #type: Optional[int]
        self.negated_dependencies = set() #type: Set[str]

    def assumes_not_supported(self, name: str) -> None:
        """Negate the given mechanism for automatic dependency generation.

        Call this function before set_arguments() for a test case that should
        run if the given mechanism is not supported.

        A mechanism is either a PSA_XXX symbol (e.g. PSA_KEY_TYPE_AES,
        PSA_ALG_HMAC, etc.) or a PSA_WANT_XXX symbol.
        """
        symbol = name
        if not symbol.startswith('PSA_WANT_'):
            symbol = psa_want_symbol(name)
        self.negated_dependencies.add(symbol)

    def set_key_bits(self, key_bits: Optional[int]) -> None:
        """Use the given key size for automatic dependency generation.

        Call this function before set_arguments() if relevant.

        This is only relevant for ECC and DH keys. For other key types,
        this information is ignored.
        """
        self.key_bits = key_bits

    def set_arguments(self, arguments: List[str]) -> None:
        """Set test case arguments and automatically infer dependencies."""
        super().set_arguments(arguments)
        dependencies = automatic_dependencies(*arguments)
        # In test cases for not-supported features, the dependencies for
        # the not-supported feature(s) must be negated. We make sure that
        # all negated dependencies are present in the result, even in edge
        # cases where they would not be detected automatically (for example,
        # to restrict ECDSA-not-supported test cases to configurations
        # where neither deterministic ECDSA nor randomized ECDSA are supported,
        # to avoid the edge case that both ECDSA verifications are the same).
        dependencies = ([dep for dep in dependencies
                         if dep not in self.negated_dependencies] +
                        ['!' + dep for dep in self.negated_dependencies])
        if self.key_bits is not None:
            dependencies = finish_family_dependencies(dependencies, self.key_bits)
        self.dependencies += sorted(dependencies)
        self.detect_not_implemented_dependencies()
