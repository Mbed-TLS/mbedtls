"""Collect information about PSA cryptographic mechanisms.
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
from typing import Dict, FrozenSet, List, Optional

from . import macro_collector


class Information:
    """Gather information about PSA constructors."""

    def __init__(self) -> None:
        self.constructors = self.read_psa_interface()

    @staticmethod
    def remove_unwanted_macros(
            constructors: macro_collector.PSAMacroEnumerator
    ) -> None:
        # Mbed TLS does not support finite-field DSA.
        # Don't attempt to generate any related test case.
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

# Define set of regular expressions and dependencies to optionally append
# extra dependencies for test case.
AES_128BIT_ONLY_DEP_REGEX = r'AES\s(192|256)'
AES_128BIT_ONLY_DEP = ["!MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH"]

DEPENDENCY_FROM_KEY = {
    AES_128BIT_ONLY_DEP_REGEX: AES_128BIT_ONLY_DEP
}#type: Dict[str, List[str]]
def generate_key_dependencies(description: str) -> List[str]:
    """Return additional dependencies based on pairs of REGEX and dependencies.
    """
    deps = []
    for regex, dep in DEPENDENCY_FROM_KEY.items():
        if re.search(regex, description):
            deps += dep

    return deps

# A temporary hack: at the time of writing, not all dependency symbols
# are implemented yet. Skip test cases for which the dependency symbols are
# not available. Once all dependency symbols are available, this hack must
# be removed so that a bug in the dependency symbols properly leads to a test
# failure.
def read_implemented_dependencies(filename: str) -> FrozenSet[str]:
    return frozenset(symbol
                     for line in open(filename)
                     for symbol in re.findall(r'\bPSA_WANT_\w+\b', line))
_implemented_dependencies = None #type: Optional[FrozenSet[str]] #pylint: disable=invalid-name
def hack_dependencies_not_implemented(dependencies: List[str]) -> None:
    global _implemented_dependencies #pylint: disable=global-statement,invalid-name
    if _implemented_dependencies is None:
        _implemented_dependencies = \
            read_implemented_dependencies('include/psa/crypto_config.h')
    if not all((dep.lstrip('!') in _implemented_dependencies or
                not dep.lstrip('!').startswith('PSA_WANT'))
               for dep in dependencies):
        dependencies.append('DEPENDENCY_NOT_IMPLEMENTED_YET')

def tweak_key_pair_dependency(dep: str, usage: str):
    """
    This helper function add the proper suffix to PSA_WANT_KEY_TYPE_xxx_KEY_PAIR
    symbols according to the required usage.
    """
    ret_list = list()
    if dep.endswith('KEY_PAIR'):
        if usage == "BASIC":
            # BASIC automatically includes IMPORT and EXPORT for test purposes (see
            # config_psa.h).
            ret_list.append(re.sub(r'KEY_PAIR', r'KEY_PAIR_BASIC', dep))
            ret_list.append(re.sub(r'KEY_PAIR', r'KEY_PAIR_IMPORT', dep))
            ret_list.append(re.sub(r'KEY_PAIR', r'KEY_PAIR_EXPORT', dep))
        elif usage == "GENERATE":
            ret_list.append(re.sub(r'KEY_PAIR', r'KEY_PAIR_GENERATE', dep))
    else:
        # No replacement to do in this case
        ret_list.append(dep)
    return ret_list

def fix_key_pair_dependencies(dep_list: List[str], usage: str):
    new_list = [new_deps
                for dep in dep_list
                for new_deps in tweak_key_pair_dependency(dep, usage)]

    return new_list
