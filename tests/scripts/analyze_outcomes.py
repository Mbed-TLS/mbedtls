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

    @staticmethod
    def log(fmt, *args, **kwargs):
        sys.stderr.write((fmt + '\n').format(*args, **kwargs))

    def error(self, fmt, *args, **kwargs):
        self.log('Error: ' + fmt, *args, **kwargs)
        self.error_count += 1

    def warning(self, fmt, *args, **kwargs):
        self.log('Warning: ' + fmt, *args, **kwargs)
        self.warning_count += 1

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

def execute_reference_driver_tests(ref_component, driver_component, outcome_file):
    """Run the tests specified in ref_component and driver_component. Results
    are stored in the output_file and they will be used for the following
    coverage analysis"""
    # If the outcome file already exists, we assume that the user wants to
    # perform the comparison analysis again without repeating the tests.
    if os.path.exists(outcome_file):
        Results.log("Outcome file (" + outcome_file + ") already exists. " + \
                    "Tests will be skipped.")
        return

    shell_command = "tests/scripts/all.sh --outcome-file " + outcome_file + \
                    " " + ref_component + " " + driver_component
    Results.log("Running: " + shell_command)
    ret_val = subprocess.run(shell_command.split(), check=False).returncode

    if ret_val != 0:
        Results.log("Error: failed to run reference/driver components")
        sys.exit(ret_val)

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

def analyze_driver_vs_reference(outcomes, component_ref, component_driver,
                                ignored_suites, ignored_test=None):
    """Check that all tests executed in the reference component are also
    executed in the corresponding driver component.
    Skip:
    - full test suites provided in ignored_suites list
    - only some specific test inside a test suite, for which the corresponding
      output string is provided
    """
    available = check_test_cases.collect_available_test_cases()
    result = True

    for key in available:
        # Continue if test was not executed by any component
        hits = outcomes[key].hits() if key in outcomes else 0
        if hits == 0:
            continue
        # Skip ignored test suites
        full_test_suite = key.split(';')[0] # retrieve full test suite name
        test_string = key.split(';')[1] # retrieve the text string of this test
        test_suite = full_test_suite.split('.')[0] # retrieve main part of test suite name
        if test_suite in ignored_suites or full_test_suite in ignored_suites:
            continue
        if ((full_test_suite in ignored_test) and
                (test_string in ignored_test[full_test_suite])):
            continue
        # Search for tests that run in reference component and not in driver component
        driver_test_passed = False
        reference_test_passed = False
        for entry in outcomes[key].successes:
            if component_driver in entry:
                driver_test_passed = True
            if component_ref in entry:
                reference_test_passed = True
        if(reference_test_passed and not driver_test_passed):
            Results.log(key)
            result = False
    return result

def analyze_outcomes(outcomes, args):
    """Run all analyses on the given outcome collection."""
    results = Results()
    analyze_coverage(results, outcomes, args['allow_list'],
                     args['full_coverage'])
    return results

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

def do_analyze_coverage(outcome_file, args):
    """Perform coverage analysis."""
    outcomes = read_outcome_file(outcome_file)
    Results.log("\n*** Analyze coverage ***\n")
    results = analyze_outcomes(outcomes, args)
    return results.error_count == 0

def do_analyze_driver_vs_reference(outcome_file, args):
    """Perform driver vs reference analyze."""
    execute_reference_driver_tests(args['component_ref'], \
                                    args['component_driver'], outcome_file)

    ignored_suites = ['test_suite_' + x for x in args['ignored_suites']]

    outcomes = read_outcome_file(outcome_file)
    Results.log("\n*** Analyze driver {} vs reference {} ***\n".format(
        args['component_driver'], args['component_ref']))
    return analyze_driver_vs_reference(outcomes, args['component_ref'],
                                       args['component_driver'], ignored_suites,
                                       args['ignored_tests'])

# List of tasks with a function that can handle this task and additional arguments if required
TASKS = {
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
    'analyze_driver_vs_reference_ecp_light_only': {
        'test_function': do_analyze_driver_vs_reference,
        'args': {
            'component_ref': 'test_psa_crypto_config_reference_ecc_ecp_light_only',
            'component_driver': 'test_psa_crypto_config_accel_ecc_ecp_light_only',
            'ignored_suites': [
                'ecdsa',
                'ecdh',
                'ecjpake',
            ],
            'ignored_tests': {
                'test_suite_random': [
                    'PSA classic wrapper: ECDSA signature (SECP256R1)',
                ],
                # In the accelerated test ECP_C is not set (only ECP_LIGHT is)
                # so we must ignore disparities in the tests for which ECP_C
                # is required.
                'test_suite_ecp': [
                    'ECP check public-private #1 (OK)',
                    'ECP check public-private #2 (group none)',
                    'ECP check public-private #3 (group mismatch)',
                    'ECP check public-private #4 (Qx mismatch)',
                    'ECP check public-private #5 (Qy mismatch)',
                    'ECP check public-private #6 (wrong Qx)',
                    'ECP check public-private #7 (wrong Qy)',
                    'ECP gen keypair [#1]',
                    'ECP gen keypair [#2]',
                    'ECP gen keypair [#3]',
                    'ECP gen keypair wrapper',
                    'ECP point muladd secp256r1 #1',
                    'ECP point muladd secp256r1 #2',
                    'ECP point multiplication Curve25519 (element of order 2: origin) #3',
                    'ECP point multiplication Curve25519 (element of order 4: 1) #4',
                    'ECP point multiplication Curve25519 (element of order 8) #5',
                    'ECP point multiplication Curve25519 (normalized) #1',
                    'ECP point multiplication Curve25519 (not normalized) #2',
                    'ECP point multiplication rng fail Curve25519',
                    'ECP point multiplication rng fail secp256r1',
                    'ECP test vectors Curve25519',
                    'ECP test vectors Curve448 (RFC 7748 6.2, after decodeUCoordinate)',
                    'ECP test vectors brainpoolP256r1 rfc 7027',
                    'ECP test vectors brainpoolP384r1 rfc 7027',
                    'ECP test vectors brainpoolP512r1 rfc 7027',
                    'ECP test vectors secp192k1',
                    'ECP test vectors secp192r1 rfc 5114',
                    'ECP test vectors secp224k1',
                    'ECP test vectors secp224r1 rfc 5114',
                    'ECP test vectors secp256k1',
                    'ECP test vectors secp256r1 rfc 5114',
                    'ECP test vectors secp384r1 rfc 5114',
                    'ECP test vectors secp521r1 rfc 5114',
                ],
                'test_suite_psa_crypto': [
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1 (1 redraw)',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1, exercise ECDSA',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp384r1',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp521r1 #0',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp521r1 #1',
                ],
                'test_suite_ssl': [
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
                # Ignore test suites for the modules that are disabled in the
                # accelerated test case.
                'ecp',
                'ecdsa',
                'ecdh',
                'ecjpake',
            ],
            'ignored_tests': {
                'test_suite_random': [
                    'PSA classic wrapper: ECDSA signature (SECP256R1)',
                ],
                'test_suite_psa_crypto': [
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1 (1 redraw)',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1, exercise ECDSA',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp384r1',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp521r1 #0',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp521r1 #1',
                    'PSA key derivation: bits=7 invalid for ECC BRAINPOOL_P_R1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECP_K1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECP_R1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECP_R2 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECT_K1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECT_R1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECT_R2 (ECC enabled)',
                ],
                'test_suite_pkparse': [
                    # When PK_PARSE_C and ECP_C are defined then PK_PARSE_EC_COMPRESSED
                    # is automatically enabled in build_info.h (backward compatibility)
                    # even if it is disabled in config_psa_crypto_no_ecp_at_all(). As a
                    # consequence compressed points are supported in the reference
                    # component but not in the accelerated one, so they should be skipped
                    # while checking driver's coverage.
                    'Parse EC Key #10a (SEC1 PEM, secp384r1, compressed)',
                    'Parse EC Key #11a (SEC1 PEM, secp521r1, compressed)',
                    'Parse EC Key #12a (SEC1 PEM, bp256r1, compressed)',
                    'Parse EC Key #13a (SEC1 PEM, bp384r1, compressed)',
                    'Parse EC Key #14a (SEC1 PEM, bp512r1, compressed)',
                    'Parse EC Key #2a (SEC1 PEM, secp192r1, compressed)',
                    'Parse EC Key #8a (SEC1 PEM, secp224r1, compressed)',
                    'Parse EC Key #9a (SEC1 PEM, secp256r1, compressed)',
                    'Parse Public EC Key #2a (RFC 5480, PEM, secp192r1, compressed)',
                    'Parse Public EC Key #3a (RFC 5480, secp224r1, compressed)',
                    'Parse Public EC Key #4a (RFC 5480, secp256r1, compressed)',
                    'Parse Public EC Key #5a (RFC 5480, secp384r1, compressed)',
                    'Parse Public EC Key #6a (RFC 5480, secp521r1, compressed)',
                    'Parse Public EC Key #7a (RFC 5480, brainpoolP256r1, compressed)',
                    'Parse Public EC Key #8a (RFC 5480, brainpoolP384r1, compressed)',
                    'Parse Public EC Key #9a (RFC 5480, brainpoolP512r1, compressed)',
                ],
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
                # Ignore test suites for the modules that are disabled in the
                # accelerated test case.
                'ecp',
                'ecdsa',
                'ecdh',
                'ecjpake',
                'bignum_core',
                'bignum_random',
                'bignum_mod',
                'bignum_mod_raw',
                'bignum.generated',
                'bignum.misc',
            ],
            'ignored_tests': {
                'test_suite_random': [
                    'PSA classic wrapper: ECDSA signature (SECP256R1)',
                ],
                'test_suite_psa_crypto': [
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1 (1 redraw)',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1, exercise ECDSA',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp384r1',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp521r1 #0',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp521r1 #1',
                    'PSA key derivation: bits=7 invalid for ECC BRAINPOOL_P_R1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECP_K1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECP_R1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECP_R2 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECT_K1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECT_R1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECT_R2 (ECC enabled)',
                ],
                'test_suite_pkparse': [
                    # See the description provided above in the
                    # analyze_driver_vs_reference_no_ecp_at_all component.
                    'Parse EC Key #10a (SEC1 PEM, secp384r1, compressed)',
                    'Parse EC Key #11a (SEC1 PEM, secp521r1, compressed)',
                    'Parse EC Key #12a (SEC1 PEM, bp256r1, compressed)',
                    'Parse EC Key #13a (SEC1 PEM, bp384r1, compressed)',
                    'Parse EC Key #14a (SEC1 PEM, bp512r1, compressed)',
                    'Parse EC Key #2a (SEC1 PEM, secp192r1, compressed)',
                    'Parse EC Key #8a (SEC1 PEM, secp224r1, compressed)',
                    'Parse EC Key #9a (SEC1 PEM, secp256r1, compressed)',
                    'Parse Public EC Key #2a (RFC 5480, PEM, secp192r1, compressed)',
                    'Parse Public EC Key #3a (RFC 5480, secp224r1, compressed)',
                    'Parse Public EC Key #4a (RFC 5480, secp256r1, compressed)',
                    'Parse Public EC Key #5a (RFC 5480, secp384r1, compressed)',
                    'Parse Public EC Key #6a (RFC 5480, secp521r1, compressed)',
                    'Parse Public EC Key #7a (RFC 5480, brainpoolP256r1, compressed)',
                    'Parse Public EC Key #8a (RFC 5480, brainpoolP384r1, compressed)',
                    'Parse Public EC Key #9a (RFC 5480, brainpoolP512r1, compressed)',
                ],
                'test_suite_asn1parse': [
                    # This test depends on BIGNUM_C
                    'INTEGER too large for mpi',
                ],
                'test_suite_asn1write': [
                    # Following tests depends on BIGNUM_C
                    'ASN.1 Write mpi 0 (1 limb)',
                    'ASN.1 Write mpi 0 (null)',
                    'ASN.1 Write mpi 0x100',
                    'ASN.1 Write mpi 0x7f',
                    'ASN.1 Write mpi 0x7f with leading 0 limb',
                    'ASN.1 Write mpi 0x80',
                    'ASN.1 Write mpi 0x80 with leading 0 limb',
                    'ASN.1 Write mpi 0xff',
                    'ASN.1 Write mpi 1',
                    'ASN.1 Write mpi, 127*8 bits',
                    'ASN.1 Write mpi, 127*8+1 bits',
                    'ASN.1 Write mpi, 127*8-1 bits',
                    'ASN.1 Write mpi, 255*8 bits',
                    'ASN.1 Write mpi, 255*8-1 bits',
                    'ASN.1 Write mpi, 256*8-1 bits',
                ],
                'test_suite_debug': [
                    # Following tests depends on BIGNUM_C
                    'Debug print mbedtls_mpi #2: 3 bits',
                    'Debug print mbedtls_mpi: 0 (empty representation)',
                    'Debug print mbedtls_mpi: 0 (non-empty representation)',
                    'Debug print mbedtls_mpi: 49 bits',
                    'Debug print mbedtls_mpi: 759 bits',
                    'Debug print mbedtls_mpi: 764 bits #1',
                    'Debug print mbedtls_mpi: 764 bits #2',
                ],
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
                # Ignore test suites for the modules that are disabled in the
                # accelerated test case.
                'ecp',
                'ecdsa',
                'ecdh',
                'ecjpake',
                'bignum_core',
                'bignum_random',
                'bignum_mod',
                'bignum_mod_raw',
                'bignum.generated',
                'bignum.misc',
                'dhm',
            ],
            'ignored_tests': {
                'test_suite_random': [
                    'PSA classic wrapper: ECDSA signature (SECP256R1)',
                ],
                'test_suite_psa_crypto': [
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1 (1 redraw)',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1, exercise ECDSA',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp384r1',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp521r1 #0',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp521r1 #1',
                    'PSA key derivation: bits=7 invalid for ECC BRAINPOOL_P_R1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECP_K1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECP_R1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECP_R2 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECT_K1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECT_R1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECT_R2 (ECC enabled)',
                ],
                'test_suite_pkparse': [
                    # See the description provided above in the
                    # analyze_driver_vs_reference_no_ecp_at_all component.
                    'Parse EC Key #10a (SEC1 PEM, secp384r1, compressed)',
                    'Parse EC Key #11a (SEC1 PEM, secp521r1, compressed)',
                    'Parse EC Key #12a (SEC1 PEM, bp256r1, compressed)',
                    'Parse EC Key #13a (SEC1 PEM, bp384r1, compressed)',
                    'Parse EC Key #14a (SEC1 PEM, bp512r1, compressed)',
                    'Parse EC Key #2a (SEC1 PEM, secp192r1, compressed)',
                    'Parse EC Key #8a (SEC1 PEM, secp224r1, compressed)',
                    'Parse EC Key #9a (SEC1 PEM, secp256r1, compressed)',
                    'Parse Public EC Key #2a (RFC 5480, PEM, secp192r1, compressed)',
                    'Parse Public EC Key #3a (RFC 5480, secp224r1, compressed)',
                    'Parse Public EC Key #4a (RFC 5480, secp256r1, compressed)',
                    'Parse Public EC Key #5a (RFC 5480, secp384r1, compressed)',
                    'Parse Public EC Key #6a (RFC 5480, secp521r1, compressed)',
                    'Parse Public EC Key #7a (RFC 5480, brainpoolP256r1, compressed)',
                    'Parse Public EC Key #8a (RFC 5480, brainpoolP384r1, compressed)',
                    'Parse Public EC Key #9a (RFC 5480, brainpoolP512r1, compressed)',
                ],
                'test_suite_asn1parse': [
                    # This test depends on BIGNUM_C
                    'INTEGER too large for mpi',
                ],
                'test_suite_asn1write': [
                    # Following tests depends on BIGNUM_C
                    'ASN.1 Write mpi 0 (1 limb)',
                    'ASN.1 Write mpi 0 (null)',
                    'ASN.1 Write mpi 0x100',
                    'ASN.1 Write mpi 0x7f',
                    'ASN.1 Write mpi 0x7f with leading 0 limb',
                    'ASN.1 Write mpi 0x80',
                    'ASN.1 Write mpi 0x80 with leading 0 limb',
                    'ASN.1 Write mpi 0xff',
                    'ASN.1 Write mpi 1',
                    'ASN.1 Write mpi, 127*8 bits',
                    'ASN.1 Write mpi, 127*8+1 bits',
                    'ASN.1 Write mpi, 127*8-1 bits',
                    'ASN.1 Write mpi, 255*8 bits',
                    'ASN.1 Write mpi, 255*8-1 bits',
                    'ASN.1 Write mpi, 256*8-1 bits',
                ],
                'test_suite_debug': [
                    # Following tests depends on BIGNUM_C
                    'Debug print mbedtls_mpi #2: 3 bits',
                    'Debug print mbedtls_mpi: 0 (empty representation)',
                    'Debug print mbedtls_mpi: 0 (non-empty representation)',
                    'Debug print mbedtls_mpi: 49 bits',
                    'Debug print mbedtls_mpi: 759 bits',
                    'Debug print mbedtls_mpi: 764 bits #1',
                    'Debug print mbedtls_mpi: 764 bits #2',
                ],
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
                # Ignore test suites for the modules that are disabled in the
                # accelerated test case.
                'ecp',
                'ecdsa',
                'ecdh',
                'ecjpake',
                'bignum_core',
                'bignum_random',
                'bignum_mod',
                'bignum_mod_raw',
                'bignum.generated',
                'bignum.misc',
            ],
            'ignored_tests': {
                # Ignore all tests that require DERIVE support which is disabled
                # in the driver version
                'test_suite_psa_crypto': [
                    'PSA key agreement setup: ECDH + HKDF-SHA-256: good',
                    ('PSA key agreement setup: ECDH + HKDF-SHA-256: good, key algorithm broader '
                     'than required'),
                    'PSA key agreement setup: ECDH + HKDF-SHA-256: public key not on curve',
                    'PSA key agreement setup: KDF instead of a key agreement algorithm',
                    'PSA key agreement setup: bad key agreement algorithm',
                    'PSA key agreement: ECDH SECP256R1 (RFC 5903) + HKDF-SHA-256: capacity=8160',
                    'PSA key agreement: ECDH SECP256R1 (RFC 5903) + HKDF-SHA-256: read 0+32',
                    'PSA key agreement: ECDH SECP256R1 (RFC 5903) + HKDF-SHA-256: read 1+31',
                    'PSA key agreement: ECDH SECP256R1 (RFC 5903) + HKDF-SHA-256: read 31+1',
                    'PSA key agreement: ECDH SECP256R1 (RFC 5903) + HKDF-SHA-256: read 32+0',
                    'PSA key agreement: ECDH SECP256R1 (RFC 5903) + HKDF-SHA-256: read 32+32',
                    'PSA key agreement: ECDH SECP256R1 (RFC 5903) + HKDF-SHA-256: read 64+0',
                    'PSA key derivation: ECDH on P256 with HKDF-SHA256, info first',
                    'PSA key derivation: ECDH on P256 with HKDF-SHA256, key output',
                    'PSA key derivation: ECDH on P256 with HKDF-SHA256, missing info',
                    'PSA key derivation: ECDH on P256 with HKDF-SHA256, omitted salt',
                    'PSA key derivation: ECDH on P256 with HKDF-SHA256, raw output',
                    'PSA key derivation: ECDH on P256 with HKDF-SHA256, salt after secret',
                    'PSA key derivation: ECDH with TLS 1.2 PRF SHA-256, good case',
                    'PSA key derivation: ECDH with TLS 1.2 PRF SHA-256, missing label',
                    'PSA key derivation: ECDH with TLS 1.2 PRF SHA-256, missing label and secret',
                    'PSA key derivation: ECDH with TLS 1.2 PRF SHA-256, no inputs',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1 (1 redraw)',
                    'PSA key derivation: HKDF-SHA-256 -> ECC secp256r1, exercise ECDSA',
                    'PSA key derivation: TLS 1.2 Mix-PSK-to-MS, SHA-256, 0+48, ka',
                    'PSA key derivation: TLS 1.2 Mix-PSK-to-MS, SHA-256, 24+24, ka',
                    'PSA key derivation: TLS 1.2 Mix-PSK-to-MS, SHA-256, 48+0, ka',
                    'PSA key derivation: TLS 1.2 Mix-PSK-to-MS, bad state #1, ka',
                    'PSA key derivation: TLS 1.2 Mix-PSK-to-MS, bad state #3, ka',
                    'PSA key derivation: TLS 1.2 Mix-PSK-to-MS, bad state #4, ka',
                    'PSA key derivation: bits=7 invalid for ECC BRAINPOOL_P_R1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC MONTGOMERY (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECP_K1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECP_R1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECP_R2 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECT_K1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECT_R1 (ECC enabled)',
                    'PSA key derivation: bits=7 invalid for ECC SECT_R2 (ECC enabled)',
                    'PSA raw key agreement: ECDH SECP256R1 (RFC 5903)',
                ],
                'test_suite_random': [
                    'PSA classic wrapper: ECDSA signature (SECP256R1)',
                ],
                'test_suite_psa_crypto_pake': [
                    'PSA PAKE: ecjpake size macros',
                ],
                'test_suite_asn1parse': [
                    # This test depends on BIGNUM_C
                    'INTEGER too large for mpi',
                ],
                'test_suite_asn1write': [
                    # Following tests depends on BIGNUM_C
                    'ASN.1 Write mpi 0 (1 limb)',
                    'ASN.1 Write mpi 0 (null)',
                    'ASN.1 Write mpi 0x100',
                    'ASN.1 Write mpi 0x7f',
                    'ASN.1 Write mpi 0x7f with leading 0 limb',
                    'ASN.1 Write mpi 0x80',
                    'ASN.1 Write mpi 0x80 with leading 0 limb',
                    'ASN.1 Write mpi 0xff',
                    'ASN.1 Write mpi 1',
                    'ASN.1 Write mpi, 127*8 bits',
                    'ASN.1 Write mpi, 127*8+1 bits',
                    'ASN.1 Write mpi, 127*8-1 bits',
                    'ASN.1 Write mpi, 255*8 bits',
                    'ASN.1 Write mpi, 255*8-1 bits',
                    'ASN.1 Write mpi, 256*8-1 bits',
                ],
            }
        }
    }
}

def main():
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('outcomes', metavar='OUTCOMES.CSV',
                            help='Outcome file to analyze')
        parser.add_argument('task', default='all', nargs='?',
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
            for task in TASKS:
                Results.log(task)
            sys.exit(0)

        result = True

        if options.task == 'all':
            tasks = TASKS.keys()
        else:
            tasks = re.split(r'[, ]+', options.task)

            for task in tasks:
                if task not in TASKS:
                    Results.log('Error: invalid task: {}'.format(task))
                    sys.exit(1)

        TASKS['analyze_coverage']['args']['full_coverage'] = \
            options.full_coverage

        for task in TASKS:
            if task in tasks:
                if not TASKS[task]['test_function'](options.outcomes, TASKS[task]['args']):
                    result = False

        if result is False:
            sys.exit(1)
        Results.log("SUCCESS :-)")
    except Exception: # pylint: disable=broad-except
        # Print the backtrace and exit explicitly with our chosen status.
        traceback.print_exc()
        sys.exit(120)

if __name__ == '__main__':
    main()
