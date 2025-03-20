#!/usr/bin/env python3
"""Run the PSA Crypto API compliance test suite.
Clone the repo and check out the commit specified by PSA_ARCH_TEST_REPO and PSA_ARCH_TEST_REF,
then compile and run the test suite. The clone is stored at <repository root>/psa-arch-tests.
Known defects in either the test suite or mbedtls / TF-PSA-Crypto - identified by their test
number - are ignored, while unexpected failures AND successes are reported as errors, to help
keep the list of known defects as up to date as possible.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import os
import re
import shutil
import subprocess
import sys
from typing import List
from pathlib import Path

from mbedtls_framework import build_tree

# PSA Compliance tests we expect to fail due to known defects in Mbed TLS /
# TF-PSA-Crypto (or the test suite).
# The test numbers correspond to the numbers used by the console output of the test suite.
# Test number 2xx corresponds to the files in the folder
# psa-arch-tests/api-tests/dev_apis/crypto/test_c0xx
EXPECTED_FAILURES = {} # type: dict

PSA_ARCH_TESTS_REPO = 'https://github.com/ARM-software/psa-arch-tests.git'
PSA_ARCH_TESTS_REF = 'v23.06_API1.5_ADAC_EAC'

#pylint: disable=too-many-branches,too-many-statements,too-many-locals
def main(library_build_dir: str):
    root_dir = os.getcwd()
    install_dir = Path(library_build_dir + "/install_dir").resolve()
    tmp_env = os.environ
    tmp_env['CC'] = 'gcc'
    subprocess.check_call(['cmake', '.', '-GUnix Makefiles',
                           '-B' + library_build_dir,
                           '-DCMAKE_INSTALL_PREFIX=' + str(install_dir)],
                          env=tmp_env)
    subprocess.check_call(['cmake', '--build', library_build_dir, '--target', 'install'])

    if build_tree.is_mbedtls_3_6():
        libraries_to_link = [str(install_dir.joinpath("lib/libmbedcrypto.a"))]
    else:
        libraries_to_link = [str(install_dir.joinpath("lib/" + lib))
                             for lib in ["libtfpsacrypto.a", "libbuiltin.a",
                                         "libp256m.a", "libeverest.a"]]

    psa_arch_tests_dir = 'psa-arch-tests'
    os.makedirs(psa_arch_tests_dir, exist_ok=True)
    try:
        os.chdir(psa_arch_tests_dir)

        # Reuse existing local clone
        subprocess.check_call(['git', 'init'])
        subprocess.check_call(['git', 'fetch', PSA_ARCH_TESTS_REPO, PSA_ARCH_TESTS_REF])
        subprocess.check_call(['git', 'checkout', 'FETCH_HEAD'])

        build_dir = 'api-tests/build'
        try:
            shutil.rmtree(build_dir)
        except FileNotFoundError:
            pass
        os.mkdir(build_dir)
        os.chdir(build_dir)

        #pylint: disable=bad-continuation
        subprocess.check_call([
            'cmake', '..',
                     '-GUnix Makefiles',
                     '-DTARGET=tgt_dev_apis_stdc',
                     '-DTOOLCHAIN=HOST_GCC',
                     '-DSUITE=CRYPTO',
                     '-DPSA_CRYPTO_LIB_FILENAME={}'.format(';'.join(libraries_to_link)),
                     '-DPSA_INCLUDE_PATHS=' + str(install_dir.joinpath("include"))
        ])

        subprocess.check_call(['cmake', '--build', '.'])

        proc = subprocess.Popen(['./psa-arch-tests-crypto'],
                                bufsize=1, stdout=subprocess.PIPE, universal_newlines=True)

        test_re = re.compile(
            '^TEST: (?P<test_num>[0-9]*)|'
            '^TEST RESULT: (?P<test_result>FAILED|PASSED)'
        )
        test = -1
        unexpected_successes = set(EXPECTED_FAILURES)
        expected_failures = [] # type: List[int]
        unexpected_failures = [] # type: List[int]
        if proc.stdout is None:
            return 1

        for line in proc.stdout:
            print(line, end='')
            match = test_re.match(line)
            if match is not None:
                groupdict = match.groupdict()
                test_num = groupdict['test_num']
                if test_num is not None:
                    test = int(test_num)
                elif groupdict['test_result'] == 'FAILED':
                    try:
                        unexpected_successes.remove(test)
                        expected_failures.append(test)
                        print('Expected failure, ignoring')
                    except KeyError:
                        unexpected_failures.append(test)
                        print('ERROR: Unexpected failure')
                elif test in unexpected_successes:
                    print('ERROR: Unexpected success')
        proc.wait()

        print()
        print('***** test_psa_compliance.py report ******')
        print()
        print('Expected failures:', ', '.join(str(i) for i in expected_failures))
        print('Unexpected failures:', ', '.join(str(i) for i in unexpected_failures))
        print('Unexpected successes:', ', '.join(str(i) for i in sorted(unexpected_successes)))
        print()
        if unexpected_successes or unexpected_failures:
            if unexpected_successes:
                print('Unexpected successes encountered.')
                print('Please remove the corresponding tests from '
                      'EXPECTED_FAILURES in tests/scripts/compliance_test.py')
                print()
            print('FAILED')
            return 1
        else:
            print('SUCCESS')
            return 0
    finally:
        os.chdir(root_dir)

if __name__ == '__main__':
    BUILD_DIR = 'out_of_source_build'

    # pylint: disable=invalid-name
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', nargs=1,
                        help='path to Mbed TLS / TF-PSA-Crypto build directory')
    args = parser.parse_args()

    if args.build_dir is not None:
        BUILD_DIR = args.build_dir[0]

    sys.exit(main(BUILD_DIR))
