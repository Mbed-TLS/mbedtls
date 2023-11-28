#!/usr/bin/env python3

"""Analyze the test outcomes from a full CI run.

This script can also run on outcomes from a partial run, but the results are
less likely to be useful.
"""

import argparse
import sys
import traceback
import re
import subprocess
import os

import check_test_cases

class Results:
    """Process analysis results."""

    def __init__(self):
        self.error_count = 0
        self.warning_count = 0

    def new_section(self, fmt, *args, **kwargs):
        self._print_line('\n*** ' + fmt + ' ***\n', *args, **kwargs)

    def info(self, fmt, *args, **kwargs):
        self._print_line('Info: ' + fmt, *args, **kwargs)

    def error(self, fmt, *args, **kwargs):
        self.error_count += 1
        self._print_line('Error: ' + fmt, *args, **kwargs)

    def warning(self, fmt, *args, **kwargs):
        self.warning_count += 1
        self._print_line('Warning: ' + fmt, *args, **kwargs)

    @staticmethod
    def _print_line(fmt, *args, **kwargs):
        sys.stderr.write((fmt + '\n').format(*args, **kwargs))

class TestCaseOutcomes:
    """The outcomes of one test case across many configurations."""
    # pylint: disable=too-few-public-methods

    def __init__(self):
        # Collect a list of witnesses of the test case succeeding or failing.
        # Currently we don't do anything with witnesses except count them.
        # The format of a witness is determined by the read_outcome_file
        # function; it's the platform and configuration joined by ';'.
        self.successes = []
        self.failures = []

    def hits(self):
        """Return the number of times a test case has been run.

        This includes passes and failures, but not skips.
        """
        return len(self.successes) + len(self.failures)

def execute_reference_driver_tests(results: Results, ref_component, driver_component, \
                                   outcome_file):
    """Run the tests specified in ref_component and driver_component. Results
    are stored in the output_file and they will be used for the following
    coverage analysis"""
    # If the outcome file already exists, we assume that the user wants to
    # perform the comparison analysis again without repeating the tests.
    if os.path.exists(outcome_file):
        results.info("Outcome file ({}) already exists. Tests will be skipped.", outcome_file)
        return

    shell_command = "tests/scripts/all.sh --outcome-file " + outcome_file + \
                    " " + ref_component + " " + driver_component
    results.info("Running: {}", shell_command)
    ret_val = subprocess.run(shell_command.split(), check=False).returncode

    if ret_val != 0:
        results.error("failed to run reference/driver components")

def analyze_coverage(results, outcomes, allow_list, full_coverage):
    """Check that all available test cases are executed at least once."""
    available = check_test_cases.collect_available_test_cases()
    for key in available:
        hits = outcomes[key].hits() if key in outcomes else 0
        if hits == 0 and key not in allow_list:
            if full_coverage:
                results.error('Test case not executed: {}', key)
            else:
                results.warning('Test case not executed: {}', key)
        elif hits != 0 and key in allow_list:
            # Test Case should be removed from the allow list.
            if full_coverage:
                results.error('Allow listed test case was executed: {}', key)
            else:
                results.warning('Allow listed test case was executed: {}', key)

def name_matches_pattern(name, str_or_re):
    """Check if name matches a pattern, that may be a string or regex.
    - If the pattern is a string, name must be equal to match.
    - If the pattern is a regex, name must fully match.
    """
    # The CI's python is too old for re.Pattern
    #if isinstance(str_or_re, re.Pattern):
    if not isinstance(str_or_re, str):
        return str_or_re.fullmatch(name)
    else:
        return str_or_re == name

def analyze_driver_vs_reference(results: Results, outcomes,
                                component_ref, component_driver,
                                ignored_suites, ignored_tests=None):
    """Check that all tests executed in the reference component are also
    executed in the corresponding driver component.
    Skip:
    - full test suites provided in ignored_suites list
    - only some specific test inside a test suite, for which the corresponding
      output string is provided
    """
    seen_reference_passing = False
    for key in outcomes:
        # key is like "test_suite_foo.bar;Description of test case"
        (full_test_suite, test_string) = key.split(';')
        test_suite = full_test_suite.split('.')[0] # retrieve main part of test suite name

        # Immediately skip fully-ignored test suites
        if test_suite in ignored_suites or full_test_suite in ignored_suites:
            continue

        # For ignored test cases inside test suites, just remember and:
        # don't issue an error if they're skipped with drivers,
        # but issue an error if they're not (means we have a bad entry).
        ignored = False
        if full_test_suite in ignored_tests:
            for str_or_re in ignored_tests[test_suite]:
                if name_matches_pattern(test_string, str_or_re):
                    ignored = True

        # Search for tests that run in reference component and not in driver component
        driver_test_passed = False
        reference_test_passed = False
        for entry in outcomes[key].successes:
            if component_driver in entry:
                driver_test_passed = True
            if component_ref in entry:
                reference_test_passed = True
                seen_reference_passing = True
        if reference_test_passed and not driver_test_passed and not ignored:
            results.error("PASS -> SKIP/FAIL: {}", key)
        if ignored and driver_test_passed:
            results.error("uselessly ignored: {}", key)

    if not seen_reference_passing:
        results.error("no passing test in reference component: bad outcome file?")

def analyze_outcomes(results: Results, outcomes, args):
    """Run all analyses on the given outcome collection."""
    analyze_coverage(results, outcomes, args['allow_list'],
                     args['full_coverage'])

def read_outcome_file(outcome_file):
    """Parse an outcome file and return an outcome collection.

An outcome collection is a dictionary mapping keys to TestCaseOutcomes objects.
The keys are the test suite name and the test case description, separated
by a semicolon.
"""
    outcomes = {}
    with open(outcome_file, 'r', encoding='utf-8') as input_file:
        for line in input_file:
            (platform, config, suite, case, result, _cause) = line.split(';')
            key = ';'.join([suite, case])
            setup = ';'.join([platform, config])
            if key not in outcomes:
                outcomes[key] = TestCaseOutcomes()
            if result == 'PASS':
                outcomes[key].successes.append(setup)
            elif result == 'FAIL':
                outcomes[key].failures.append(setup)
    return outcomes

def do_analyze_coverage(results: Results, outcome_file, args):
    """Perform coverage analysis."""
    results.new_section("Analyze coverage")
    outcomes = read_outcome_file(outcome_file)
    analyze_outcomes(results, outcomes, args)

def do_analyze_driver_vs_reference(results: Results, outcome_file, args):
    """Perform driver vs reference analyze."""
    results.new_section("Analyze driver {} vs reference {}",
                        args['component_driver'], args['component_ref'])

    execute_reference_driver_tests(results, args['component_ref'], \
                                   args['component_driver'], outcome_file)

    ignored_suites = ['test_suite_' + x for x in args['ignored_suites']]

    outcomes = read_outcome_file(outcome_file)

    analyze_driver_vs_reference(results, outcomes,
                                args['component_ref'], args['component_driver'],
                                ignored_suites, args['ignored_tests'])

# List of tasks with a function that can handle this task and additional arguments if required
KNOWN_TASKS = {
    'analyze_coverage':                 {
        'test_function': do_analyze_coverage,
        'args': {
            'allow_list': [
                # Algorithm not supported yet
                'test_suite_psa_crypto_metadata;Asymmetric signature: pure EdDSA',
                # Algorithm not supported yet
                'test_suite_psa_crypto_metadata;Cipher: XTS',
            ],
            'full_coverage': False,
        }
    },
    # There are 2 options to use analyze_driver_vs_reference_xxx locally:
    # 1. Run tests and then analysis:
    #   - tests/scripts/all.sh --outcome-file "$PWD/out.csv" <component_ref> <component_driver>
    #   - tests/scripts/analyze_outcomes.py out.csv analyze_driver_vs_reference_xxx
    # 2. Let this script run both automatically:
    #   - tests/scripts/analyze_outcomes.py out.csv analyze_driver_vs_reference_xxx
    'analyze_driver_vs_reference_hash': {
        'test_function': do_analyze_driver_vs_reference,
        'args': {
            'component_ref': 'test_psa_crypto_config_reference_hash_use_psa',
            'component_driver': 'test_psa_crypto_config_accel_hash_use_psa',
            'ignored_suites': [
                'shax', 'mdx', # the software implementations that are being excluded
                'md.psa',  # purposefully depends on whether drivers are present
                'psa_crypto_low_hash.generated', # testing the builtins
            ],
            'ignored_tests': {
            }
        }
    },
    'analyze_driver_vs_reference_cipher_aead': {
        'test_function': do_analyze_driver_vs_reference,
        'args': {
            'component_ref': 'test_psa_crypto_config_reference_cipher_aead',
            'component_driver': 'test_psa_crypto_config_accel_cipher_aead',
            # Modules replaced by drivers.
            'ignored_suites': [
                # low-level (block/stream) cipher modules
                'aes', 'aria', 'camellia', 'des', 'chacha20',
                # AEAD modes
                'ccm', 'chachapoly', 'cmac', 'gcm',
                # The Cipher abstraction layer
                'cipher',
            ],
            'ignored_tests': {
                # PEM decryption is not supported so far.
                # The rest of PEM (write, unencrypted read) works though.
                'test_suite_pem': [
                    re.compile(r'PEM read .*(AES|DES|\bencrypt).*'),
                ],
                # Following tests depend on AES_C/DES_C but are not about
                # them really, just need to know some error code is there.
                'test_suite_error': [
                    'Low and high error',
                    'Single low error'
                ],
                # Similar to test_suite_error above.
                'test_suite_version': [
                    'Check for MBEDTLS_AES_C when already present',
                ],
                # The en/decryption part of PKCS#12 is not supported so far.
                # The rest of PKCS#12 (key derivation) works though.
                'test_suite_pkcs12': [
                    re.compile(r'PBE Encrypt, .*'),
                    re.compile(r'PBE Decrypt, .*'),
                ],
                # The en/decryption part of PKCS#5 is not supported so far.
                # The rest of PKCS#5 (PBKDF2) works though.
                'test_suite_pkcs5': [
                    re.compile(r'PBES2 Encrypt, .*'),
                    re.compile(r'PBES2 Decrypt .*'),
                ],
                # Encrypted keys are not supported so far.
                # pylint: disable=line-too-long
                'test_suite_pkparse': [
                    'Key ASN1 (Encrypted key PKCS12, trailing garbage data)',
                    'Key ASN1 (Encrypted key PKCS5, trailing garbage data)',
                    re.compile(r'Parse RSA Key .*\(PKCS#8 encrypted .*\)'),
                ],
            }
        }
    },
    'analyze_driver_vs_reference_ecp_light_only': {
        'test_function': do_analyze_driver_vs_reference,
        'args': {
            'component_ref': 'test_psa_crypto_config_reference_ecc_ecp_light_only',
            'component_driver': 'test_psa_crypto_config_accel_ecc_ecp_light_only',
            'ignored_suites': [
                # Modules replaced by drivers
                'ecdsa', 'ecdh', 'ecjpake',
            ],
            'ignored_tests': {
                # This test wants a legacy function that takes f_rng, p_rng
                # arguments, and uses legacy ECDSA for that. The test is
                # really about the wrapper around the PSA RNG, not ECDSA.
                'test_suite_random': [
                    'PSA classic wrapper: ECDSA signature (SECP256R1)',
                ],
                # In the accelerated test ECP_C is not set (only ECP_LIGHT is)
                # so we must ignore disparities in the tests for which ECP_C
                # is required.
                'test_suite_ecp': [
                    re.compile(r'ECP check public-private .*'),
                    re.compile(r'ECP gen keypair .*'),
                    re.compile(r'ECP point muladd .*'),
                    re.compile(r'ECP point multiplication .*'),
                    re.compile(r'ECP test vectors .*'),
                ],
                'test_suite_ssl': [
                    # This deprecated function is only present when ECP_C is On.
                    'Test configuration of groups for DHE through mbedtls_ssl_conf_curves()',
                ],
            }
        }
    },
    'analyze_driver_vs_reference_no_ecp_at_all': {
        'test_function': do_analyze_driver_vs_reference,
        'args': {
            'component_ref': 'test_psa_crypto_config_reference_ecc_no_ecp_at_all',
            'component_driver': 'test_psa_crypto_config_accel_ecc_no_ecp_at_all',
            'ignored_suites': [
                # Modules replaced by drivers
                'ecp', 'ecdsa', 'ecdh', 'ecjpake',
            ],
            'ignored_tests': {
                # See ecp_light_only
                'test_suite_random': [
                    'PSA classic wrapper: ECDSA signature (SECP256R1)',
                ],
                'test_suite_pkparse': [
                    # When PK_PARSE_C and ECP_C are defined then PK_PARSE_EC_COMPRESSED
                    # is automatically enabled in build_info.h (backward compatibility)
                    # even if it is disabled in config_psa_crypto_no_ecp_at_all(). As a
                    # consequence compressed points are supported in the reference
                    # component but not in the accelerated one, so they should be skipped
                    # while checking driver's coverage.
                    re.compile(r'Parse EC Key .*compressed\)'),
                    re.compile(r'Parse Public EC Key .*compressed\)'),
                ],
                # See ecp_light_only
                'test_suite_ssl': [
                    'Test configuration of groups for DHE through mbedtls_ssl_conf_curves()',
                ],
            }
        }
    },
    'analyze_driver_vs_reference_ecc_no_bignum': {
        'test_function': do_analyze_driver_vs_reference,
        'args': {
            'component_ref': 'test_psa_crypto_config_reference_ecc_no_bignum',
            'component_driver': 'test_psa_crypto_config_accel_ecc_no_bignum',
            'ignored_suites': [
                # Modules replaced by drivers
                'ecp', 'ecdsa', 'ecdh', 'ecjpake',
                'bignum_core', 'bignum_random', 'bignum_mod', 'bignum_mod_raw',
                'bignum.generated', 'bignum.misc',
            ],
            'ignored_tests': {
                # See ecp_light_only
                'test_suite_random': [
                    'PSA classic wrapper: ECDSA signature (SECP256R1)',
                ],
                # See no_ecp_at_all
                'test_suite_pkparse': [
                    re.compile(r'Parse EC Key .*compressed\)'),
                    re.compile(r'Parse Public EC Key .*compressed\)'),
                ],
                'test_suite_asn1parse': [
                    'INTEGER too large for mpi',
                ],
                'test_suite_asn1write': [
                    re.compile(r'ASN.1 Write mpi.*'),
                ],
                'test_suite_debug': [
                    re.compile(r'Debug print mbedtls_mpi.*'),
                ],
                # See ecp_light_only
                'test_suite_ssl': [
                    'Test configuration of groups for DHE through mbedtls_ssl_conf_curves()',
                ],
            }
        }
    },
    'analyze_driver_vs_reference_ecc_ffdh_no_bignum': {
        'test_function': do_analyze_driver_vs_reference,
        'args': {
            'component_ref': 'test_psa_crypto_config_reference_ecc_ffdh_no_bignum',
            'component_driver': 'test_psa_crypto_config_accel_ecc_ffdh_no_bignum',
            'ignored_suites': [
                # Modules replaced by drivers
                'ecp', 'ecdsa', 'ecdh', 'ecjpake', 'dhm',
                'bignum_core', 'bignum_random', 'bignum_mod', 'bignum_mod_raw',
                'bignum.generated', 'bignum.misc',
            ],
            'ignored_tests': {
                # See ecp_light_only
                'test_suite_random': [
                    'PSA classic wrapper: ECDSA signature (SECP256R1)',
                ],
                # See no_ecp_at_all
                'test_suite_pkparse': [
                    re.compile(r'Parse EC Key .*compressed\)'),
                    re.compile(r'Parse Public EC Key .*compressed\)'),
                ],
                'test_suite_asn1parse': [
                    'INTEGER too large for mpi',
                ],
                'test_suite_asn1write': [
                    re.compile(r'ASN.1 Write mpi.*'),
                ],
                'test_suite_debug': [
                    re.compile(r'Debug print mbedtls_mpi.*'),
                ],
                # See ecp_light_only
                'test_suite_ssl': [
                    'Test configuration of groups for DHE through mbedtls_ssl_conf_curves()',
                ],
            }
        }
    },
    'analyze_driver_vs_reference_ffdh_alg': {
        'test_function': do_analyze_driver_vs_reference,
        'args': {
            'component_ref': 'test_psa_crypto_config_reference_ffdh',
            'component_driver': 'test_psa_crypto_config_accel_ffdh',
            'ignored_suites': ['dhm'],
            'ignored_tests': {}
        }
    },
    'analyze_driver_vs_reference_tfm_config': {
        'test_function':  do_analyze_driver_vs_reference,
        'args': {
            'component_ref': 'test_tfm_config',
            'component_driver': 'test_tfm_config_p256m_driver_accel_ec',
            'ignored_suites': [
                # Modules replaced by drivers
                'asn1parse', 'asn1write',
                'ecp', 'ecdsa', 'ecdh', 'ecjpake',
                'bignum_core', 'bignum_random', 'bignum_mod', 'bignum_mod_raw',
                'bignum.generated', 'bignum.misc',
            ],
            'ignored_tests': {
                # See ecp_light_only
                'test_suite_random': [
                    'PSA classic wrapper: ECDSA signature (SECP256R1)',
                ],
            }
        }
    }
}

def main():
    main_results = Results()

    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('outcomes', metavar='OUTCOMES.CSV',
                            help='Outcome file to analyze')
        parser.add_argument('specified_tasks', default='all', nargs='?',
                            help='Analysis to be done. By default, run all tasks. '
                                 'With one or more TASK, run only those. '
                                 'TASK can be the name of a single task or '
                                 'comma/space-separated list of tasks. ')
        parser.add_argument('--list', action='store_true',
                            help='List all available tasks and exit.')
        parser.add_argument('--require-full-coverage', action='store_true',
                            dest='full_coverage', help="Require all available "
                            "test cases to be executed and issue an error "
                            "otherwise. This flag is ignored if 'task' is "
                            "neither 'all' nor 'analyze_coverage'")
        options = parser.parse_args()

        if options.list:
            for task in KNOWN_TASKS:
                print(task)
            sys.exit(0)

        if options.specified_tasks == 'all':
            tasks_list = KNOWN_TASKS.keys()
        else:
            tasks_list = re.split(r'[, ]+', options.specified_tasks)
            for task in tasks_list:
                if task not in KNOWN_TASKS:
                    sys.stderr.write('invalid task: {}\n'.format(task))
                    sys.exit(2)

        KNOWN_TASKS['analyze_coverage']['args']['full_coverage'] = options.full_coverage

        for task in tasks_list:
            test_function = KNOWN_TASKS[task]['test_function']
            test_args = KNOWN_TASKS[task]['args']
            test_function(main_results, options.outcomes, test_args)

        main_results.info("Overall results: {} warnings and {} errors",
                          main_results.warning_count, main_results.error_count)

        sys.exit(0 if (main_results.error_count == 0) else 1)

    except Exception: # pylint: disable=broad-except
        # Print the backtrace and exit explicitly with our chosen status.
        traceback.print_exc()
        sys.exit(120)

if __name__ == '__main__':
    main()
