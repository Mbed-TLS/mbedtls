#!/usr/bin/env python3
"""Generate test data for ecp functions.

The command line usage, class structure and available methods are the same
as in generate_bignum_tests.py.
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

import sys

import scripts_path # pylint: disable=unused-import
from mbedtls_dev import test_data_generation
# Import modules containing additional test classes
# Test function classes in these modules will be registered by
# the framework
from mbedtls_dev import ecp # pylint: disable=unused-import

if __name__ == '__main__':
    # Use the section of the docstring relevant to the CLI as description
    test_data_generation.main(sys.argv[1:], "\n".join(__doc__.splitlines()[:4]))
