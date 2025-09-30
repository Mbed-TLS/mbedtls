#!/usr/bin/env python3
"""Run the PSA Crypto API compliance test suite.

Clone the psa-arch-tests repo and check out the specified commit.
The clone is stored at <repository-root>/psa-arch-tests.
Check out the commit specified by the calling script and apply patches if needed.
The patches are located at <repository-root>/scripts/data_files/psa-arch-tests/ .
Compile the library and the compliance tests and run the test suite.

This script can specify a list of expected failures.
Unexpected failures and successes are reported as errors, to help
keep the list of known defects as up to date as possible.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

from typing import List

import scripts_path # pylint: disable=unused-import
from mbedtls_framework import psa_compliance

PSA_ARCH_TESTS_REF = 'v23.06_API1.5_ADAC_EAC'

# PSA Compliance tests we expect to fail due to known defects in Mbed TLS /
# TF-PSA-Crypto (or the test suite).
# The test numbers correspond to the numbers used by the console output of the test suite.
# Test number 2xx corresponds to the files in the folder
# psa-arch-tests/api-tests/dev_apis/crypto/test_c0xx
EXPECTED_FAILURES = [] # type: List[int]

if __name__ == '__main__':
    psa_compliance.main(PSA_ARCH_TESTS_REF, expected_failures=EXPECTED_FAILURES)
