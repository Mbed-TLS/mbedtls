#!/usr/bin/env python3
#pylint: disable=missing-module-docstring
import os
import re
import shutil
import subprocess
import sys

EXPECTED_FAILURES = {
    216, 221, 224, 225, 248, 249, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263
}
PSA_ARCH_TESTS_REPO = 'https://github.com/ronald-cron-arm/psa-arch-tests.git'
PSA_ARCH_TESTS_REF = 'crypto1.0-3.0'

#pylint: disable=too-many-statements
def main():
    mbedtls_dir = os.getcwd()

    if not os.path.exists('library/libmbedcrypto.a'):
        subprocess.check_call(['make', '-C', 'library', 'libmbedcrypto.a'])

    psa_arch_tests_dir = 'psa-arch-tests'
    try:
        os.mkdir(psa_arch_tests_dir)
    except FileExistsError:
        pass
    os.chdir(psa_arch_tests_dir)

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
        'cmake', '..', '-GUnix Makefiles',
                       '-DTARGET=tgt_dev_apis_stdc',
                       '-DTOOLCHAIN=HOST_GCC',
                       '-DSUITE=CRYPTO',
                       '-DPSA_CRYPTO_LIB_FILENAME={}/library/libmbedcrypto.a'.format(mbedtls_dir),
                       '-DPSA_INCLUDE_PATHS={}/include'.format(mbedtls_dir)
    ])
    subprocess.check_call(['cmake', '--build', '.'])

    proc = subprocess.Popen(['./psa-arch-tests-crypto'],
                            bufsize=1, stdout=subprocess.PIPE, universal_newlines=True)

    test_re = re.compile('^TEST(?:: ([0-9]*)| RESULT: FAILED)')
    test = -1
    unexpected_successes = set(EXPECTED_FAILURES)
    expected_failures = []
    unexpected_failures = []
    for line in proc.stdout:
        print(line[:-1])
        match = test_re.match(line)
        if match is not None:
            if match.group(1) is not None:
                test = int(match.group(1))
            else:
                try:
                    unexpected_successes.remove(test)
                    expected_failures.append(test)
                except KeyError:
                    unexpected_failures.append(test)
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
            #pylint: disable=line-too-long
            print('Please remove the corresponding tests from EXPECTED_FAILURES in tests/scripts/compliance_test.py')
            print()
        print('FAILED')
        sys.exit(1)
    else:
        os.chdir(mbedtls_dir)
        shutil.rmtree(psa_arch_tests_dir)
        print('SUCCESS')

if __name__ == '__main__':
    main()
