#!/usr/bin/env python3
"""Generate test data for PSA cryptographic mechanisms.
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

import argparse
import os
import re
import sys
from typing import Iterable, List, TypeVar

import scripts_path # pylint: disable=unused-import
from mbedtls_dev import crypto_knowledge
from mbedtls_dev import macro_collector
from mbedtls_dev import test_case

T = TypeVar('T') #pylint: disable=invalid-name


def test_case_for_key_type_not_supported(verb: str, key_type: str, bits: int,
                                         dependencies: List[str],
                                         *args: str) -> test_case.TestCase:
    """Return one test case exercising a key creation method
    for an unsupported key type or size.
    """
    tc = test_case.TestCase()
    adverb = 'not' if dependencies else 'never'
    tc.set_description('PSA {} {} {}-bit {} supported'
                       .format(verb, key_type, bits, adverb))
    tc.set_dependencies(dependencies)
    tc.set_function(verb + '_not_supported')
    tc.set_arguments([key_type] + list(args))
    return tc

class TestGenerator:
    """Gather information and generate test data."""

    def __init__(self, options):
        self.test_suite_directory = self.get_option(options, 'directory',
                                                    'tests/suites')
        self.constructors = self.read_psa_interface()

    @staticmethod
    def get_option(options, name: str, default: T) -> T:
        value = getattr(options, name, None)
        return default if value is None else value

    @staticmethod
    def remove_unwanted_macros(
            constructors: macro_collector.PSAMacroCollector
    ) -> None:
        # Mbed TLS doesn't support DSA. Don't attempt to generate any related
        # test case.
        constructors.key_types.discard('PSA_KEY_TYPE_DSA_KEY_PAIR')
        constructors.key_types.discard('PSA_KEY_TYPE_DSA_PUBLIC_KEY')
        constructors.algorithms_from_hash.pop('PSA_ALG_DSA', None)
        constructors.algorithms_from_hash.pop('PSA_ALG_DETERMINISTIC_DSA', None)

    def read_psa_interface(self) -> macro_collector.PSAMacroCollector:
        """Return the list of known key types, algorithms, etc."""
        constructors = macro_collector.PSAMacroCollector()
        header_file_names = ['include/psa/crypto_values.h',
                             'include/psa/crypto_extra.h']
        for header_file_name in header_file_names:
            with open(header_file_name, 'rb') as header_file:
                constructors.read_file(header_file)
        self.remove_unwanted_macros(constructors)
        return constructors

    def write_test_data_file(self, basename: str,
                             test_cases: Iterable[test_case.TestCase]) -> None:
        """Write the test cases to a .data file.

        The output file is ``basename + '.data'`` in the test suite directory.
        """
        filename = os.path.join(self.test_suite_directory, basename + '.data')
        test_case.write_data_file(filename, test_cases)

    @staticmethod
    def test_cases_for_key_type_not_supported(
            kt: crypto_knowledge.KeyType
    ) -> List[test_case.TestCase]:
        """Return test cases exercising key creation when the given type is unsupported."""
        if kt.name == 'PSA_KEY_TYPE_RAW_DATA':
            # This key type is always supported.
            return []
        want_symbol = re.sub(r'\APSA_', r'PSA_WANT_', kt.name)
        import_dependencies = ['!' + want_symbol]
        if kt.name.endswith('_PUBLIC_KEY'):
            generate_dependencies = []
        else:
            generate_dependencies = import_dependencies
        test_cases = []
        for bits in kt.sizes_to_test():
            test_cases.append(test_case_for_key_type_not_supported(
                'import', kt.name, bits, import_dependencies,
                test_case.hex_string(kt.key_material(bits))
            ))
            test_cases.append(test_case_for_key_type_not_supported(
                'generate', kt.name, bits, generate_dependencies,
                str(bits)
            ))
            # To be added: derive
        return test_cases

    def generate_not_supported(self) -> None:
        """Generate test cases that exercise the creation of keys of unsupported types."""
        test_cases = []
        for key_type in sorted(self.constructors.key_types):
            kt = crypto_knowledge.KeyType(key_type)
            test_cases += self.test_cases_for_key_type_not_supported(kt)
        # To be added: parametrized key types (ECC, FFDH)
        self.write_test_data_file(
            'test_suite_psa_crypto_not_supported.generated',
            test_cases)

    def generate_all(self):
        self.generate_not_supported()

def main(args):
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.parse_args(args)
    generator = TestGenerator(options)
    generator.generate_all()

if __name__ == '__main__':
    main(sys.argv[1:])
