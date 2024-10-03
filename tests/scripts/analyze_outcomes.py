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
import typing

import collect_test_cases


# `ComponentOutcomes` is a named tuple which is defined as:
# ComponentOutcomes(
#     successes = {
#         "<suite_case>",
#         ...
#     },
#     failures = {
#         "<suite_case>",
#         ...
#     }
# )
# suite_case = "<suite>;<case>"
ComponentOutcomes = typing.NamedTuple('ComponentOutcomes',
                                      [('successes', typing.Set[str]),
                                       ('failures', typing.Set[str])])

# `Outcomes` is a representation of the outcomes file,
# which defined as:
# Outcomes = {
#     "<component>": ComponentOutcomes,
#     ...
# }
Outcomes = typing.Dict[str, ComponentOutcomes]


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

def execute_reference_driver_tests(results: Results, ref_component: str, driver_component: str, \
                                   outcome_file: str) -> None:
    """Run the tests specified in ref_component and driver_component. Results
    are stored in the output_file and they will be used for the following
    coverage analysis"""
    results.new_section("Test {} and {}", ref_component, driver_component)

    shell_command = "tests/scripts/all.sh --outcome-file " + outcome_file + \
                    " " + ref_component + " " + driver_component
    results.info("Running: {}", shell_command)
    ret_val = subprocess.run(shell_command.split(), check=False).returncode

    if ret_val != 0:
        results.error("failed to run reference/driver components")

IgnoreEntry = typing.Union[str, typing.Pattern]

def name_matches_pattern(name: str, str_or_re: IgnoreEntry) -> bool:
    """Check if name matches a pattern, that may be a string or regex.
    - If the pattern is a string, name must be equal to match.
    - If the pattern is a regex, name must fully match.
    """
    # The CI's python is too old for re.Pattern
    #if isinstance(str_or_re, re.Pattern):
    if not isinstance(str_or_re, str):
        return str_or_re.fullmatch(name) is not None
    else:
        return str_or_re == name

def read_outcome_file(outcome_file: str) -> Outcomes:
    """Parse an outcome file and return an outcome collection.
    """
    outcomes = {}
    with open(outcome_file, 'r', encoding='utf-8') as input_file:
        for line in input_file:
            (_platform, component, suite, case, result, _cause) = line.split(';')
            # Note that `component` is not unique. If a test case passes on Linux
            # and fails on FreeBSD, it'll end up in both the successes set and
            # the failures set.
            suite_case = ';'.join([suite, case])
            if component not in outcomes:
                outcomes[component] = ComponentOutcomes(set(), set())
            if result == 'PASS':
                outcomes[component].successes.add(suite_case)
            elif result == 'FAIL':
                outcomes[component].failures.add(suite_case)

    return outcomes


class Task:
    """Base class for outcome analysis tasks."""

    # Override the following in child classes.
    # Map test suite names (with the test_suite_prefix) to a list of ignored
    # test cases. Each element in the list can be either a string or a regex;
    # see the `name_matches_pattern` function.
    IGNORED_TESTS = {} #type: typing.Dict[str, typing.List[IgnoreEntry]]

    def __init__(self, options) -> None:
        """Pass command line options to the tasks.

        Each task decides which command line options it cares about.
        """
        pass

    def section_name(self) -> str:
        """The section name to use in results."""
        raise NotImplementedError

    def ignored_tests(self, test_suite: str) -> typing.Iterator[IgnoreEntry]:
        """Generate the ignore list for the specified test suite."""
        if test_suite in self.IGNORED_TESTS:
            yield from self.IGNORED_TESTS[test_suite]
        pos = test_suite.find('.')
        if pos != -1:
            base_test_suite = test_suite[:pos]
            if base_test_suite in self.IGNORED_TESTS:
                yield from self.IGNORED_TESTS[base_test_suite]

    def is_test_case_ignored(self, test_suite: str, test_string: str) -> bool:
        """Check if the specified test case is ignored."""
        for str_or_re in self.ignored_tests(test_suite):
            if name_matches_pattern(test_string, str_or_re):
                return True
        return False

    def run(self, results: Results, outcomes: Outcomes):
        """Run the analysis on the specified outcomes.

        Signal errors via the results objects
        """
        raise NotImplementedError


class CoverageTask(Task):
    """Analyze test coverage."""

    # Test cases whose suite and description are matched by an entry in
    # IGNORED_TESTS are expected to be never executed.
    # All other test cases are expected to be executed at least once.

    def __init__(self, options) -> None:
        super().__init__(options)
        self.full_coverage = options.full_coverage #type: bool

    @staticmethod
    def section_name() -> str:
        return "Analyze coverage"

    def run(self, results: Results, outcomes: Outcomes) -> None:
        """Check that all available test cases are executed at least once."""
        # Make sure that the generated data files are present (and up-to-date).
        # This allows analyze_outcomes.py to run correctly on a fresh Git
        # checkout.
        cp = subprocess.run(['make', 'generated_files'],
                            cwd='tests',
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            check=False)
        if cp.returncode != 0:
            sys.stderr.write(cp.stdout.decode('utf-8'))
            results.error("Failed \"make generated_files\" in tests. "
                          "Coverage analysis may be incorrect.")
        available = collect_test_cases.collect_available_test_cases()
        for suite_case in available:
            hit = any(suite_case in comp_outcomes.successes or
                      suite_case in comp_outcomes.failures
                      for comp_outcomes in outcomes.values())
            (test_suite, test_description) = suite_case.split(';')
            ignored = self.is_test_case_ignored(test_suite, test_description)

            if not hit and not ignored:
                if self.full_coverage:
                    results.error('Test case not executed: {}', suite_case)
                else:
                    results.warning('Test case not executed: {}', suite_case)
            elif hit and ignored:
                # If a test case is no longer always skipped, we should remove
                # it from the ignore list.
                if self.full_coverage:
                    results.error('Test case was executed but marked as ignored for coverage: {}',
                                  suite_case)
                else:
                    results.warning('Test case was executed but marked as ignored for coverage: {}',
                                    suite_case)


class DriverVSReference(Task):
    """Compare outcomes from testing with and without a driver.

    There are 2 options to use analyze_driver_vs_reference_xxx locally:
    1. Run tests and then analysis:
      - tests/scripts/all.sh --outcome-file "$PWD/out.csv" <component_ref> <component_driver>
      - tests/scripts/analyze_outcomes.py out.csv analyze_driver_vs_reference_xxx
    2. Let this script run both automatically:
      - tests/scripts/analyze_outcomes.py out.csv analyze_driver_vs_reference_xxx
    """

    # Override the following in child classes.
    # Configuration name (all.sh component) used as the reference.
    REFERENCE = ''
    # Configuration name (all.sh component) used as the driver.
    DRIVER = ''
    # Ignored test suites (without the test_suite_ prefix).
    IGNORED_SUITES = [] #type: typing.List[str]

    def __init__(self, options) -> None:
        super().__init__(options)
        self.ignored_suites = frozenset('test_suite_' + x
                                        for x in self.IGNORED_SUITES)

    def section_name(self) -> str:
        return f"Analyze driver {self.DRIVER} vs reference {self.REFERENCE}"

    def run(self, results: Results, outcomes: Outcomes) -> None:
        """Check that all tests passing in the driver component are also
        passing in the corresponding reference component.
        Skip:
        - full test suites provided in ignored_suites list
        - only some specific test inside a test suite, for which the corresponding
          output string is provided
        """
        ref_outcomes = outcomes.get("component_" + self.REFERENCE)
        driver_outcomes = outcomes.get("component_" + self.DRIVER)

        if ref_outcomes is None or driver_outcomes is None:
            results.error("required components are missing: bad outcome file?")
            return

        if not ref_outcomes.successes:
            results.error("no passing test in reference component: bad outcome file?")
            return

        for suite_case in ref_outcomes.successes:
            # suite_case is like "test_suite_foo.bar;Description of test case"
            (full_test_suite, test_string) = suite_case.split(';')
            test_suite = full_test_suite.split('.')[0] # retrieve main part of test suite name

            # Immediately skip fully-ignored test suites
            if test_suite in self.ignored_suites or \
               full_test_suite in self.ignored_suites:
                continue

            # For ignored test cases inside test suites, just remember and:
            # don't issue an error if they're skipped with drivers,
            # but issue an error if they're not (means we have a bad entry).
            ignored = self.is_test_case_ignored(full_test_suite, test_string)

            if not ignored and not suite_case in driver_outcomes.successes:
                results.error("SKIP/FAIL -> PASS: {}", suite_case)
            if ignored and suite_case in driver_outcomes.successes:
                results.error("uselessly ignored: {}", suite_case)


# The names that we give to classes derived from DriverVSReference do not
# follow the usual naming convention, because it's more readable to use
# underscores and parts of the configuration names. Also, these classes
# are just there to specify some data, so they don't need repetitive
# documentation.
#pylint: disable=invalid-name,missing-class-docstring

class DriverVSReference_hash(DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_hash_use_psa'
    DRIVER = 'test_psa_crypto_config_accel_hash_use_psa'
    IGNORED_SUITES = [
        'shax', 'mdx', # the software implementations that are being excluded
        'md.psa',  # purposefully depends on whether drivers are present
        'psa_crypto_low_hash.generated', # testing the builtins
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(MD5|RIPEMD160|SHA[0-9]+)_.*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
    }

class DriverVSReference_hmac(DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_hmac'
    DRIVER = 'test_psa_crypto_config_accel_hmac'
    IGNORED_SUITES = [
        # These suites require legacy hash support, which is disabled
        # in the accelerated component.
        'shax', 'mdx',
        # This suite tests builtins directly, but these are missing
        # in the accelerated case.
        'psa_crypto_low_hash.generated',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(MD5|RIPEMD160|SHA[0-9]+)_.*'),
            re.compile(r'.*\bMBEDTLS_MD_C\b')
        ],
        'test_suite_md': [
            # Builtin HMAC is not supported in the accelerate component.
            re.compile('.*HMAC.*'),
            # Following tests make use of functions which are not available
            # when MD_C is disabled, as it happens in the accelerated
            # test component.
            re.compile('generic .* Hash file .*'),
            'MD list',
        ],
        'test_suite_md.psa': [
            # "legacy only" tests require hash algorithms to be NOT
            # accelerated, but this of course false for the accelerated
            # test component.
            re.compile('PSA dispatch .* legacy only'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
    }

class DriverVSReference_cipher_aead_cmac(DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_cipher_aead_cmac'
    DRIVER = 'test_psa_crypto_config_accel_cipher_aead_cmac'
    # Modules replaced by drivers.
    IGNORED_SUITES = [
        # low-level (block/stream) cipher modules
        'aes', 'aria', 'camellia', 'des', 'chacha20',
        # AEAD modes and CMAC
        'ccm', 'chachapoly', 'cmac', 'gcm',
        # The Cipher abstraction layer
        'cipher',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(AES|ARIA|CAMELLIA|CHACHA20|DES)_.*'),
            re.compile(r'.*\bMBEDTLS_(CCM|CHACHAPOLY|CMAC|GCM)_.*'),
            re.compile(r'.*\bMBEDTLS_AES(\w+)_C\b.*'),
            re.compile(r'.*\bMBEDTLS_CIPHER_.*'),
        ],
        # PEM decryption is not supported so far.
        # The rest of PEM (write, unencrypted read) works though.
        'test_suite_pem': [
            re.compile(r'PEM read .*(AES|DES|\bencrypt).*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
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
            re.compile(r'Parse (RSA|EC) Key .*\(.* ([Ee]ncrypted|password).*\)'),
        ],
        # Encrypted keys are not supported so far.
        'ssl-opt': [
            'TLS: password protected server key',
            'TLS: password protected client key',
            'TLS: password protected server key, two certificates',
        ],
    }

class DriverVSReference_ecp_light_only(DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_ecc_ecp_light_only'
    DRIVER = 'test_psa_crypto_config_accel_ecc_ecp_light_only'
    IGNORED_SUITES = [
        # Modules replaced by drivers
        'ecdsa', 'ecdh', 'ecjpake',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(ECDH|ECDSA|ECJPAKE|ECP)_.*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
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
            re.compile(r'ECP calculate public: .*'),
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

class DriverVSReference_no_ecp_at_all(DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_ecc_no_ecp_at_all'
    DRIVER = 'test_psa_crypto_config_accel_ecc_no_ecp_at_all'
    IGNORED_SUITES = [
        # Modules replaced by drivers
        'ecp', 'ecdsa', 'ecdh', 'ecjpake',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(ECDH|ECDSA|ECJPAKE|ECP)_.*'),
            re.compile(r'.*\bMBEDTLS_PK_PARSE_EC_COMPRESSED\b.*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
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

class DriverVSReference_ecc_no_bignum(DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_ecc_no_bignum'
    DRIVER = 'test_psa_crypto_config_accel_ecc_no_bignum'
    IGNORED_SUITES = [
        # Modules replaced by drivers
        'ecp', 'ecdsa', 'ecdh', 'ecjpake',
        'bignum_core', 'bignum_random', 'bignum_mod', 'bignum_mod_raw',
        'bignum.generated', 'bignum.misc',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_BIGNUM_C\b.*'),
            re.compile(r'.*\bMBEDTLS_(ECDH|ECDSA|ECJPAKE|ECP)_.*'),
            re.compile(r'.*\bMBEDTLS_PK_PARSE_EC_COMPRESSED\b.*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
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

class DriverVSReference_ecc_ffdh_no_bignum(DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_ecc_ffdh_no_bignum'
    DRIVER = 'test_psa_crypto_config_accel_ecc_ffdh_no_bignum'
    IGNORED_SUITES = [
        # Modules replaced by drivers
        'ecp', 'ecdsa', 'ecdh', 'ecjpake', 'dhm',
        'bignum_core', 'bignum_random', 'bignum_mod', 'bignum_mod_raw',
        'bignum.generated', 'bignum.misc',
    ]
    IGNORED_TESTS = {
        'ssl-opt': [
            # DHE support in TLS 1.2 requires built-in MBEDTLS_DHM_C
            # (because it needs custom groups, which PSA does not
            # provide), even with MBEDTLS_USE_PSA_CRYPTO.
            re.compile(r'PSK callback:.*\bdhe-psk\b.*'),
        ],
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_BIGNUM_C\b.*'),
            re.compile(r'.*\bMBEDTLS_DHM_C\b.*'),
            re.compile(r'.*\bMBEDTLS_(ECDH|ECDSA|ECJPAKE|ECP)_.*'),
            re.compile(r'.*\bMBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED\b.*'),
            re.compile(r'.*\bMBEDTLS_PK_PARSE_EC_COMPRESSED\b.*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
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

class DriverVSReference_ffdh_alg(DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_ffdh'
    DRIVER = 'test_psa_crypto_config_accel_ffdh'
    IGNORED_SUITES = ['dhm']
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_DHM_C\b.*'),
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
    }

class DriverVSReference_tfm_config(DriverVSReference):
    REFERENCE = 'test_tfm_config_no_p256m'
    DRIVER = 'test_tfm_config_p256m_driver_accel_ec'
    IGNORED_SUITES = [
        # Modules replaced by drivers
        'asn1parse', 'asn1write',
        'ecp', 'ecdsa', 'ecdh', 'ecjpake',
        'bignum_core', 'bignum_random', 'bignum_mod', 'bignum_mod_raw',
        'bignum.generated', 'bignum.misc',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_BIGNUM_C\b.*'),
            re.compile(r'.*\bMBEDTLS_(ASN1\w+)_C\b.*'),
            re.compile(r'.*\bMBEDTLS_(ECDH|ECDSA|ECP)_.*'),
            re.compile(r'.*\bMBEDTLS_PSA_P256M_DRIVER_ENABLED\b.*')
        ],
        'test_suite_config.crypto_combinations': [
            'Config: ECC: Weierstrass curves only',
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
        # See ecp_light_only
        'test_suite_random': [
            'PSA classic wrapper: ECDSA signature (SECP256R1)',
        ],
    }

class DriverVSReference_rsa(DriverVSReference):
    REFERENCE = 'test_psa_crypto_config_reference_rsa_crypto'
    DRIVER = 'test_psa_crypto_config_accel_rsa_crypto'
    IGNORED_SUITES = [
        # Modules replaced by drivers.
        'rsa', 'pkcs1_v15', 'pkcs1_v21',
        # We temporarily don't care about PK stuff.
        'pk', 'pkwrite', 'pkparse'
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(PKCS1|RSA)_.*'),
            re.compile(r'.*\bMBEDTLS_GENPRIME\b.*')
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
        # Following tests depend on RSA_C but are not about
        # them really, just need to know some error code is there.
        'test_suite_error': [
            'Low and high error',
            'Single high error'
        ],
        # Constant time operations only used for PKCS1_V15
        'test_suite_constant_time': [
            re.compile(r'mbedtls_ct_zeroize_if .*'),
            re.compile(r'mbedtls_ct_memmove_left .*')
        ],
        'test_suite_psa_crypto': [
            # We don't support generate_key_custom entry points
            # in drivers yet.
            re.compile(r'PSA generate key custom: RSA, e=.*'),
            re.compile(r'PSA generate key ext: RSA, e=.*'),
        ],
    }

class DriverVSReference_block_cipher_dispatch(DriverVSReference):
    REFERENCE = 'test_full_block_cipher_legacy_dispatch'
    DRIVER = 'test_full_block_cipher_psa_dispatch'
    IGNORED_SUITES = [
        # Skipped in the accelerated component
        'aes', 'aria', 'camellia',
        # These require AES_C, ARIA_C or CAMELLIA_C to be enabled in
        # order for the cipher module (actually cipher_wrapper) to work
        # properly. However these symbols are disabled in the accelerated
        # component so we ignore them.
        'cipher.ccm', 'cipher.gcm', 'cipher.aes', 'cipher.aria',
        'cipher.camellia',
    ]
    IGNORED_TESTS = {
        'test_suite_config': [
            re.compile(r'.*\bMBEDTLS_(AES|ARIA|CAMELLIA)_.*'),
            re.compile(r'.*\bMBEDTLS_AES(\w+)_C\b.*'),
        ],
        'test_suite_cmac': [
            # Following tests require AES_C/ARIA_C/CAMELLIA_C to be enabled,
            # but these are not available in the accelerated component.
            'CMAC null arguments',
            re.compile('CMAC.* (AES|ARIA|Camellia).*'),
        ],
        'test_suite_cipher.padding': [
            # Following tests require AES_C/CAMELLIA_C to be enabled,
            # but these are not available in the accelerated component.
            re.compile('Set( non-existent)? padding with (AES|CAMELLIA).*'),
        ],
        'test_suite_pkcs5': [
            # The AES part of PKCS#5 PBES2 is not yet supported.
            # The rest of PKCS#5 (PBKDF2) works, though.
            re.compile(r'PBES2 .* AES-.*')
        ],
        'test_suite_pkparse': [
            # PEM (called by pkparse) requires AES_C in order to decrypt
            # the key, but this is not available in the accelerated
            # component.
            re.compile('Parse RSA Key.*(password|AES-).*'),
        ],
        'test_suite_pem': [
            # Following tests require AES_C, but this is diabled in the
            # accelerated component.
            re.compile('PEM read .*AES.*'),
            'PEM read (unknown encryption algorithm)',
        ],
        'test_suite_error': [
            # Following tests depend on AES_C but are not about them
            # really, just need to know some error code is there.
            'Single low error',
            'Low and high error',
        ],
        'test_suite_version': [
            # Similar to test_suite_error above.
            'Check for MBEDTLS_AES_C when already present',
        ],
        'test_suite_platform': [
            # Incompatible with sanitizers (e.g. ASan). If the driver
            # component uses a sanitizer but the reference component
            # doesn't, we have a PASS vs SKIP mismatch.
            'Check mbedtls_calloc overallocation',
        ],
    }

#pylint: enable=invalid-name,missing-class-docstring



# List of tasks with a function that can handle this task and additional arguments if required
KNOWN_TASKS = {
    'analyze_coverage': CoverageTask,
    'analyze_driver_vs_reference_hash': DriverVSReference_hash,
    'analyze_driver_vs_reference_hmac': DriverVSReference_hmac,
    'analyze_driver_vs_reference_cipher_aead_cmac': DriverVSReference_cipher_aead_cmac,
    'analyze_driver_vs_reference_ecp_light_only': DriverVSReference_ecp_light_only,
    'analyze_driver_vs_reference_no_ecp_at_all': DriverVSReference_no_ecp_at_all,
    'analyze_driver_vs_reference_ecc_no_bignum': DriverVSReference_ecc_no_bignum,
    'analyze_driver_vs_reference_ecc_ffdh_no_bignum': DriverVSReference_ecc_ffdh_no_bignum,
    'analyze_driver_vs_reference_ffdh_alg': DriverVSReference_ffdh_alg,
    'analyze_driver_vs_reference_tfm_config': DriverVSReference_tfm_config,
    'analyze_driver_vs_reference_rsa': DriverVSReference_rsa,
    'analyze_block_cipher_dispatch': DriverVSReference_block_cipher_dispatch,
}

def main() -> None:
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
            for task_name in KNOWN_TASKS:
                print(task_name)
            sys.exit(0)

        if options.specified_tasks == 'all':
            tasks_list = list(KNOWN_TASKS.keys())
        else:
            tasks_list = re.split(r'[, ]+', options.specified_tasks)
            for task_name in tasks_list:
                if task_name not in KNOWN_TASKS:
                    sys.stderr.write('invalid task: {}\n'.format(task_name))
                    sys.exit(2)

        # If the outcome file exists, parse it once and share the result
        # among tasks to improve performance.
        # Otherwise, it will be generated by execute_reference_driver_tests.
        if not os.path.exists(options.outcomes):
            if len(tasks_list) > 1:
                sys.stderr.write("mutiple tasks found, please provide a valid outcomes file.\n")
                sys.exit(2)

            task_name = tasks_list[0]
            task_class = KNOWN_TASKS[task_name]
            if not issubclass(task_class, DriverVSReference):
                sys.stderr.write("please provide valid outcomes file for {}.\n".format(task_name))
                sys.exit(2)
            # mypy isn't smart enough to know that REFERENCE and DRIVER
            # are *class* attributes of all classes derived from
            # DriverVSReference. (It would be smart enough if we had an
            # instance of task_class, but we can't construct an instance
            # until we have the outcome data, so at this point we only
            # have the class.) So we use indirection to access the class
            # attributes.
            execute_reference_driver_tests(main_results,
                                           getattr(task_class, 'REFERENCE'),
                                           getattr(task_class, 'DRIVER'),
                                           options.outcomes)

        outcomes = read_outcome_file(options.outcomes)

        for task_name in tasks_list:
            task_constructor = KNOWN_TASKS[task_name]
            task_instance = task_constructor(options)
            main_results.new_section(task_instance.section_name())
            task_instance.run(main_results, outcomes)

        main_results.info("Overall results: {} warnings and {} errors",
                          main_results.warning_count, main_results.error_count)

        sys.exit(0 if (main_results.error_count == 0) else 1)

    except Exception: # pylint: disable=broad-except
        # Print the backtrace and exit explicitly with our chosen status.
        traceback.print_exc()
        sys.exit(120)

if __name__ == '__main__':
    main()
