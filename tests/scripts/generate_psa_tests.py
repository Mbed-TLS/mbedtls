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
import sys
from typing import TypeVar

import scripts_path # pylint: disable=unused-import
from mbedtls_dev import macro_collector

T = TypeVar('T') #pylint: disable=invalid-name

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

def main(args):
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.parse_args(args)
    generator = TestGenerator(options)

if __name__ == '__main__':
    main(sys.argv[1:])
