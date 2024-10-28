#!/usr/bin/env python3

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

"""
Test Mbed TLS with a subset of algorithms.

This script can be divided into several steps:

First, include/mbedtls/mbedtls_config.h or a different config file passed
in the arguments is parsed to extract any configuration options (using config.py).

Then, test domains (groups of jobs, tests) are built based on predefined data
collected in the DomainData class. Here, each domain has five major traits:
- domain name, can be used to run only specific tests via command-line;
- configuration building method, described in detail below;
- list of symbols passed to the configuration building method;
- commands to be run on each job (only build, build and test, or any other custom);
- optional list of symbols to be excluded from testing.

The configuration building method can be one of the three following:

- ComplementaryDomain - build a job for each passed symbol by disabling a single
  symbol and its reverse dependencies (defined in REVERSE_DEPENDENCIES);

- ExclusiveDomain - build a job where, for each passed symbol, only this particular
  one is defined and other symbols from the list are unset. For each job look for
  any non-standard symbols to set/unset in EXCLUSIVE_GROUPS. These are usually not
  direct dependencies, but rather non-trivial results of other configs missing. Then
  look for any unset symbols and handle their reverse dependencies.
  Examples of EXCLUSIVE_GROUPS usage:
  - MBEDTLS_SHA512_C job turns off all hashes except SHA512. MBEDTLS_SSL_COOKIE_C
    requires either SHA256 or SHA384 to work, so it also has to be disabled.
    This is not a dependency on SHA512_C, but a result of an exclusive domain
    config building method. Relevant field:
    'MBEDTLS_SHA512_C': ['-MBEDTLS_SSL_COOKIE_C'],

- DualDomain - combination of the two above - both complementary and exclusive domain
  job generation code will be run. Currently only used for hashes.

Lastly, the collected jobs are executed and (optionally) tested, with
error reporting and coloring as configured in options. Each test starts with
a full config without a couple of slowing down or unnecessary options
(see set_reference_config), then the specific job config is derived.
"""
import argparse
import os
import re
import subprocess
import sys
import traceback
from typing import Union

# Add the Mbed TLS Python library directory to the module search path
import scripts_path # pylint: disable=unused-import
import config
from mbedtls_framework import c_build_helper

class Colors: # pylint: disable=too-few-public-methods
    """Minimalistic support for colored output.
Each field of an object of this class is either None if colored output
is not possible or not desired, or a pair of strings (start, stop) such
that outputting start switches the text color to the desired color and
stop switches the text color back to the default."""
    red = None
    green = None
    cyan = None
    bold_red = None
    bold_green = None
    def __init__(self, options=None):
        """Initialize color profile according to passed options."""
        if not options or options.color in ['no', 'never']:
            want_color = False
        elif options.color in ['yes', 'always']:
            want_color = True
        else:
            want_color = sys.stderr.isatty()
        if want_color:
            # Assume ANSI compatible terminal
            normal = '\033[0m'
            self.red = ('\033[31m', normal)
            self.green = ('\033[32m', normal)
            self.cyan = ('\033[36m', normal)
            self.bold_red = ('\033[1;31m', normal)
            self.bold_green = ('\033[1;32m', normal)
NO_COLORS = Colors(None)

def log_line(text, prefix='depends.py:', suffix='', color=None):
    """Print a status message."""
    if color is not None:
        prefix = color[0] + prefix
        suffix = suffix + color[1]
    sys.stderr.write(prefix + ' ' + text + suffix + '\n')
    sys.stderr.flush()

def log_command(cmd):
    """Print a trace of the specified command.
cmd is a list of strings: a command name and its arguments."""
    log_line(' '.join(cmd), prefix='+')

def option_exists(conf, option):
    return option in conf.settings

def set_config_option_value(conf, option, colors, value: Union[bool, str]):
    """Set/unset a configuration option, optionally specifying a value.
value can be either True/False (set/unset config option), or a string,
which will make a symbol defined with a certain value."""
    if not option_exists(conf, option):
        log_line('Symbol {} was not found in {}'.format(option, conf.filename), color=colors.red)
        return False

    if value is False:
        log_command(['config.py', 'unset', option])
        conf.unset(option)
    elif value is True:
        log_command(['config.py', 'set', option])
        conf.set(option)
    else:
        log_command(['config.py', 'set', option, value])
        conf.set(option, value)
    return True

def set_reference_config(conf, colors):
    """Change the library configuration file (mbedtls_config.h) to the reference state.
The reference state is the one from which the tested configurations are
derived."""
    # Turn off options that are not relevant to the tests and slow them down.
    log_command(['config.py', 'full'])
    conf.adapt(config.full_adapter)
    set_config_option_value(conf, 'MBEDTLS_TEST_HOOKS', colors, False)

class Job:
    """A job builds the library in a specific configuration and runs some tests."""
    def __init__(self, name, config_settings, commands):
        """Build a job object.
The job uses the configuration described by config_settings. This is a
dictionary where the keys are preprocessor symbols and the values are
booleans or strings. A boolean indicates whether or not to #define the
symbol. With a string, the symbol is #define'd to that value.
After setting the configuration, the job runs the programs specified by
commands. This is a list of lists of strings; each list of string is a
command name and its arguments and is passed to subprocess.call with
shell=False."""
        self.name = name
        self.config_settings = config_settings
        self.commands = commands

    def announce(self, colors, what):
        '''Announce the start or completion of a job.
If what is None, announce the start of the job.
If what is True, announce that the job has passed.
If what is False, announce that the job has failed.'''
        if what is True:
            log_line(self.name + ' PASSED', color=colors.green)
        elif what is False:
            log_line(self.name + ' FAILED', color=colors.red)
        else:
            log_line('starting ' + self.name, color=colors.cyan)

    def configure(self, conf, colors):
        '''Set library configuration options as required for the job.'''
        set_reference_config(conf, colors)
        for key, value in sorted(self.config_settings.items()):
            ret = set_config_option_value(conf, key, colors, value)
            if ret is False:
                return False
        return True

    def _consistency_check(self):
        '''Check if the testable option is consistent with the goal.

        The purpose of this function to ensure that every option is set or unset according to
        the settings.
        '''
        log_command(['consistency check'])
        c_name = None
        exe_name = None
        header = '#include "mbedtls/build_info.h"\n'

        # Generate a C error directive for each setting to test if it is active
        for option, value in sorted(self.config_settings.items()):
            header += '#if '
            if value:
                header += '!'
            header += f'defined({option})\n'
            header += f'#error "{option}"\n'
            header += '#endif\n'
        include_path = ['include', 'tf-psa-crypto/include',
                        'tf-psa-crypto/drivers/builtin/include']

        try:
            # Generate a C file, build and run it
            c_file, c_name, exe_name = c_build_helper.create_c_file(self.name)
            c_build_helper.generate_c_file(c_file, 'depends.py', header, lambda x: '')
            c_file.close()
            c_build_helper.compile_c_file(c_name, exe_name, include_path)
            return True

        except c_build_helper.CompileError as e:
            # Read the command line output to find out which setting has been failed
            failed = {m.group(1) for m in re.finditer('.*#error "(.*)"', e.message) if m}
            log_line('Inconsistent config option(s):')
            for option in sorted(failed):
                log_line('  ' + option)
            return False

        finally:
            c_build_helper.remove_file_if_exists(c_name)
            c_build_helper.remove_file_if_exists(exe_name)

    def test(self, options):
        '''Run the job's build and test commands.
Return True if all the commands succeed and False otherwise.
If options.keep_going is false, stop as soon as one command fails. Otherwise
run all the commands, except that if the first command fails, none of the
other commands are run (typically, the first command is a build command
and subsequent commands are tests that cannot run if the build failed).'''
        if not self._consistency_check():
            return False
        built = False
        success = True
        for command in self.commands:
            log_command(command)
            env = os.environ.copy()
            if 'MBEDTLS_TEST_CONFIGURATION' in env:
                env['MBEDTLS_TEST_CONFIGURATION'] += '-' + self.name
            ret = subprocess.call(command, env=env)
            if ret != 0:
                if command[0] not in ['make', options.make_command]:
                    log_line('*** [{}] Error {}'.format(' '.join(command), ret))
                if not options.keep_going or not built:
                    return False
                success = False
            built = True
        return success

# If the configuration option A requires B, make sure that
# B in REVERSE_DEPENDENCIES[A].
# All the information here should be contained in check_config.h or check_crypto_config.h.
# This file includes a copy because it changes rarely and it would be a pain
# to extract automatically.
REVERSE_DEPENDENCIES = {
    'MBEDTLS_AES_C': ['MBEDTLS_CTR_DRBG_C',
                      'MBEDTLS_NIST_KW_C',
                      'PSA_WANT_KEY_TYPE_AES',
                      'PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128'],
    'MBEDTLS_ARIA_C': ['PSA_WANT_KEY_TYPE_ARIA'],
    'MBEDTLS_CAMELLIA_C': ['PSA_WANT_KEY_TYPE_CAMELLIA'],
    'MBEDTLS_CCM_C': ['PSA_WANT_ALG_CCM',
                      'PSA_WANT_ALG_CCM_STAR_NO_TAG'],
    'MBEDTLS_CHACHA20_C': ['MBEDTLS_CHACHAPOLY_C',
                           'PSA_WANT_KEY_TYPE_CHACHA20',
                           'PSA_WANT_ALG_CHACHA20_POLY1305',
                           'PSA_WANT_ALG_STREAM_CIPHER'],
    'MBEDTLS_CMAC_C': ['PSA_WANT_ALG_CMAC',
                       'PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128'],
    'MBEDTLS_DES_C': ['PSA_WANT_KEY_TYPE_DES'],
    'MBEDTLS_GCM_C': ['PSA_WANT_ALG_GCM'],

    'MBEDTLS_CIPHER_MODE_CBC': ['PSA_WANT_ALG_CBC_PKCS7',
                                'PSA_WANT_ALG_CBC_NO_PADDING'],
    'MBEDTLS_CIPHER_MODE_CFB': ['PSA_WANT_ALG_CFB'],
    'MBEDTLS_CIPHER_MODE_CTR': ['PSA_WANT_ALG_CTR'],
    'MBEDTLS_CIPHER_MODE_OFB': ['PSA_WANT_ALG_OFB'],

    'MBEDTLS_CIPHER_PADDING_PKCS7': ['MBEDTLS_PKCS5_C',
                                     'MBEDTLS_PKCS12_C',
                                     'PSA_WANT_ALG_CBC_PKCS7'],

    'MBEDTLS_ECP_DP_BP256R1_ENABLED': ['PSA_WANT_ECC_BRAINPOOL_P_R1_256'],
    'MBEDTLS_ECP_DP_BP384R1_ENABLED': ['PSA_WANT_ECC_BRAINPOOL_P_R1_384'],
    'MBEDTLS_ECP_DP_BP512R1_ENABLED': ['PSA_WANT_ECC_BRAINPOOL_P_R1_512'],
    'MBEDTLS_ECP_DP_CURVE25519_ENABLED': ['PSA_WANT_ECC_MONTGOMERY_255'],
    'MBEDTLS_ECP_DP_CURVE448_ENABLED': ['PSA_WANT_ECC_MONTGOMERY_448'],
    'MBEDTLS_ECP_DP_SECP192R1_ENABLED': ['PSA_WANT_ECC_SECP_R1_192'],
    'MBEDTLS_ECP_DP_SECP224R1_ENABLED': ['PSA_WANT_ECC_SECP_R1_224'],
    'MBEDTLS_ECP_DP_SECP256R1_ENABLED': ['PSA_WANT_ECC_SECP_R1_256',
                                         'PSA_WANT_ALG_JPAKE',
                                         'MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED'],
    'MBEDTLS_ECP_DP_SECP384R1_ENABLED': ['PSA_WANT_ECC_SECP_R1_384'],
    'MBEDTLS_ECP_DP_SECP512R1_ENABLED': ['PSA_WANT_ECC_SECP_R1_512'],
    'MBEDTLS_ECP_DP_SECP521R1_ENABLED': ['PSA_WANT_ECC_SECP_R1_521'],
    'MBEDTLS_ECP_DP_SECP192K1_ENABLED': ['PSA_WANT_ECC_SECP_K1_192'],
    'MBEDTLS_ECP_DP_SECP256K1_ENABLED': ['PSA_WANT_ECC_SECP_K1_256'],

    'MBEDTLS_ECDSA_C': ['MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED',
                        'MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED',
                        'PSA_WANT_ALG_ECDSA',
                        'PSA_WANT_ALG_DETERMINISTIC_ECDSA'],
    'MBEDTLS_ECP_C': ['MBEDTLS_ECDSA_C',
                      'MBEDTLS_ECDH_C', 'PSA_WANT_ALG_ECDH',
                      'MBEDTLS_ECJPAKE_C',
                      'MBEDTLS_ECP_RESTARTABLE',
                      'MBEDTLS_PK_PARSE_EC_EXTENDED',
                      'MBEDTLS_PK_PARSE_EC_COMPRESSED',
                      'MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED',
                      'MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED',
                      'MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED',
                      'MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED',
                      'MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED',
                      'PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY',
                      'PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC',
                      'PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT',
                      'PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT',
                      'PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE',
                      'PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE'],
    'MBEDTLS_ECJPAKE_C': ['MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED',
                          'PSA_WANT_ALG_JPAKE'],
    'MBEDTLS_PKCS1_V21': ['MBEDTLS_X509_RSASSA_PSS_SUPPORT',
                          'PSA_WANT_ALG_RSA_OAEP',
                          'PSA_WANT_ALG_RSA_PSS'],
    'MBEDTLS_PKCS1_V15': ['MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED',
                          'MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED',
                          'MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED',
                          'MBEDTLS_KEY_EXCHANGE_RSA_ENABLED',
                          'PSA_WANT_ALG_RSA_PKCS1V15_CRYPT',
                          'PSA_WANT_ALG_RSA_PKCS1V15_SIGN'],
    'MBEDTLS_RSA_C': ['MBEDTLS_PKCS1_V15',
                      'MBEDTLS_PKCS1_V21',
                      'MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED',
                      'PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY',
                      'PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC',
                      'PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT',
                      'PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT',
                      'PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE'],

    'MBEDTLS_MD5_C' : ['PSA_WANT_ALG_MD5'],
    'MBEDTLS_RIPEMD160_C' : ['PSA_WANT_ALG_RIPEMD160'],
    'MBEDTLS_SHA1_C' : ['PSA_WANT_ALG_SHA_1'],
    'MBEDTLS_SHA224_C': ['MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED',
                         'MBEDTLS_ENTROPY_FORCE_SHA256',
                         'MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT',
                         'MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY',
                         'PSA_WANT_ALG_SHA_224'],
    'MBEDTLS_SHA256_C': ['MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED',
                         'MBEDTLS_ENTROPY_FORCE_SHA256',
                         'MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT',
                         'MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY',
                         'MBEDTLS_LMS_C',
                         'MBEDTLS_LMS_PRIVATE',
                         'PSA_WANT_ALG_SHA_256',
                         'PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS'],
    'MBEDTLS_SHA384_C' : ['PSA_WANT_ALG_SHA_384'],
    'MBEDTLS_SHA512_C': ['MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT',
                         'MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY',
                         'PSA_WANT_ALG_SHA_512'],
    'MBEDTLS_SHA3_C' : ['PSA_WANT_ALG_SHA3_224',
                        'PSA_WANT_ALG_SHA3_256',
                        'PSA_WANT_ALG_SHA3_384',
                        'PSA_WANT_ALG_SHA3_512'],
}

# If an option is tested in an exclusive test, alter the following defines.
# These are not necessarily dependencies, but just minimal required changes
# if a given define is the only one enabled from an exclusive group.
EXCLUSIVE_GROUPS = {
    'MBEDTLS_SHA512_C': ['-MBEDTLS_SSL_COOKIE_C',
                         '-MBEDTLS_SSL_TLS_C'],
    'MBEDTLS_ECP_DP_CURVE448_ENABLED': ['-MBEDTLS_ECDSA_C',
                                        '-MBEDTLS_ECDSA_DETERMINISTIC',
                                        '-MBEDTLS_ECJPAKE_C',],
    'MBEDTLS_ECP_DP_CURVE25519_ENABLED': ['-MBEDTLS_ECDSA_C',
                                          '-MBEDTLS_ECDSA_DETERMINISTIC',
                                          '-MBEDTLS_ECJPAKE_C'],
    'MBEDTLS_ARIA_C': ['-MBEDTLS_CMAC_C',
                       '-MBEDTLS_CCM_C',
                       '-MBEDTLS_GCM_C',
                       '-MBEDTLS_SSL_TICKET_C',
                       '-MBEDTLS_SSL_CONTEXT_SERIALIZATION'],
    'MBEDTLS_CAMELLIA_C': ['-MBEDTLS_CMAC_C'],
    'MBEDTLS_CHACHA20_C': ['-MBEDTLS_CMAC_C',
                           '-MBEDTLS_CCM_C',
                           '-MBEDTLS_GCM_C',
                           '-PSA_WANT_ALG_ECB_NO_PADDING'],
    'MBEDTLS_DES_C': ['-MBEDTLS_CCM_C',
                      '-MBEDTLS_GCM_C',
                      '-MBEDTLS_SSL_TICKET_C',
                      '-MBEDTLS_SSL_CONTEXT_SERIALIZATION'],
}
def handle_exclusive_groups(config_settings, symbol):
    """For every symbol tested in an exclusive group check if there are other
defines to be altered. """
    for dep in EXCLUSIVE_GROUPS.get(symbol, []):
        unset = dep.startswith('-')
        dep = dep[1:]
        config_settings[dep] = not unset

def turn_off_dependencies(config_settings):
    """For every option turned off config_settings, also turn off what depends on it.

    An option O is turned off if config_settings[O] is False.
    Handle the dependencies recursively.
    """
    for key, value in sorted(config_settings.items()):
        if value is not False:
            continue

        # Save the processed settings to handle cross referencies
        revdep = set(REVERSE_DEPENDENCIES.get(key, []))
        history = set()
        while revdep:
            dep = revdep.pop()
            history.add(dep)
            config_settings[dep] = False
            # Do not add symbols which are already processed
            revdep.update(set(REVERSE_DEPENDENCIES.get(dep, [])) - history)

class BaseDomain: # pylint: disable=too-few-public-methods, unused-argument
    """A base class for all domains."""
    def __init__(self, symbols, commands, exclude):
        """Initialize the jobs container"""
        self.jobs = []

class ExclusiveDomain(BaseDomain): # pylint: disable=too-few-public-methods
    """A domain consisting of a set of conceptually-equivalent settings.
Establish a list of configuration symbols. For each symbol, run a test job
with this symbol set and the others unset."""
    def __init__(self, symbols, commands, exclude=None):
        """Build a domain for the specified list of configuration symbols.
The domain contains a set of jobs that enable one of the elements
of symbols and disable the others.
Each job runs the specified commands.
If exclude is a regular expression, skip generated jobs whose description
would match this regular expression."""
        super().__init__(symbols, commands, exclude)
        base_config_settings = {}
        for symbol in symbols:
            base_config_settings[symbol] = False
        for symbol in symbols:
            description = symbol
            if exclude and re.match(exclude, description):
                continue
            config_settings = base_config_settings.copy()
            config_settings[symbol] = True
            handle_exclusive_groups(config_settings, symbol)
            turn_off_dependencies(config_settings)
            job = Job(description, config_settings, commands)
            self.jobs.append(job)

class ComplementaryDomain(BaseDomain): # pylint: disable=too-few-public-methods
    """A domain consisting of a set of loosely-related settings.
Establish a list of configuration symbols. For each symbol, run a test job
with this symbol unset.
If exclude is a regular expression, skip generated jobs whose description
would match this regular expression."""
    def __init__(self, symbols, commands, exclude=None):
        """Build a domain for the specified list of configuration symbols.
Each job in the domain disables one of the specified symbols.
Each job runs the specified commands."""
        super().__init__(symbols, commands, exclude)
        for symbol in symbols:
            description = '!' + symbol
            if exclude and re.match(exclude, description):
                continue
            config_settings = {symbol: False}
            turn_off_dependencies(config_settings)
            job = Job(description, config_settings, commands)
            self.jobs.append(job)

class DualDomain(ExclusiveDomain, ComplementaryDomain): # pylint: disable=too-few-public-methods
    """A domain that contains both the ExclusiveDomain and BaseDomain tests.
Both parent class __init__ calls are performed in any order and
each call adds respective jobs. The job array initialization is done once in
BaseDomain, before the parent __init__ calls."""

class CipherInfo: # pylint: disable=too-few-public-methods
    """Collect data about cipher.h."""
    def __init__(self):
        self.base_symbols = set()
        if os.path.isdir('tf-psa-crypto'):
            cipher_h_path = 'tf-psa-crypto/drivers/builtin/include/mbedtls/cipher.h'
        else:
            cipher_h_path = 'include/mbedtls/cipher.h'
        with open(cipher_h_path, encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r' *MBEDTLS_CIPHER_ID_(\w+),', line)
                if m and m.group(1) not in ['NONE', 'NULL', '3DES']:
                    self.base_symbols.add('MBEDTLS_' + m.group(1) + '_C')

class DomainData:
    """A container for domains and jobs, used to structurize testing."""
    def config_symbols_matching(self, regexp):
        """List the mbedtls_config.h settings matching regexp."""
        return [symbol for symbol in self.all_config_symbols
                if re.match(regexp, symbol)]

    def __init__(self, options, conf):
        """Gather data about the library and establish a list of domains to test."""
        build_command = [options.make_command, 'CFLAGS=-Werror -O2']
        build_and_test = [build_command, [options.make_command, 'test']]
        self.all_config_symbols = set(conf.settings.keys())
        # Find hash modules by name.
        hash_symbols = self.config_symbols_matching(r'MBEDTLS_(MD|RIPEMD|SHA)[0-9]+_C\Z')
        # Find elliptic curve enabling macros by name.
        curve_symbols = self.config_symbols_matching(r'MBEDTLS_ECP_DP_\w+_ENABLED\Z')
        # Find key exchange enabling macros by name.
        key_exchange_symbols = self.config_symbols_matching(r'MBEDTLS_KEY_EXCHANGE_\w+_ENABLED\Z')
        # Find cipher IDs (block permutations and stream ciphers --- chaining
        # and padding modes are exercised separately) information by parsing
        # cipher.h, as the information is not readily available in mbedtls_config.h.
        cipher_info = CipherInfo()
        # Find block cipher chaining and padding mode enabling macros by name.
        cipher_chaining_symbols = self.config_symbols_matching(r'MBEDTLS_CIPHER_MODE_\w+\Z')
        cipher_padding_symbols = self.config_symbols_matching(r'MBEDTLS_CIPHER_PADDING_\w+\Z')
        self.domains = {
            # Cipher IDs, chaining modes and padding modes. Run the test suites.
            'cipher_id': ExclusiveDomain(cipher_info.base_symbols,
                                         build_and_test),
            'cipher_chaining': ExclusiveDomain(cipher_chaining_symbols,
                                               build_and_test),
            'cipher_padding': ExclusiveDomain(cipher_padding_symbols,
                                              build_and_test),
            # Elliptic curves. Run the test suites.
            'curves': ExclusiveDomain(curve_symbols, build_and_test),
            # Hash algorithms. Excluding exclusive domains of MD, RIPEMD, SHA1,
            # SHA224 and SHA384 because MBEDTLS_ENTROPY_C is extensively used
            # across various modules, but it depends on either SHA256 or SHA512.
            # As a consequence an "exclusive" test of anything other than SHA256
            # or SHA512 with MBEDTLS_ENTROPY_C enabled is not possible.
            'hashes': DualDomain(hash_symbols, build_and_test,
                                 exclude=r'MBEDTLS_(MD|RIPEMD|SHA1_)' \
                                          '|MBEDTLS_SHA224_' \
                                          '|MBEDTLS_SHA384_' \
                                          '|MBEDTLS_SHA3_'),
            # Key exchange types.
            'kex': ExclusiveDomain(key_exchange_symbols, build_and_test),
            'pkalgs': ComplementaryDomain(['MBEDTLS_ECDSA_C',
                                           'MBEDTLS_ECP_C',
                                           'MBEDTLS_PKCS1_V21',
                                           'MBEDTLS_PKCS1_V15',
                                           'MBEDTLS_RSA_C',
                                           'MBEDTLS_X509_RSASSA_PSS_SUPPORT'],
                                          build_and_test),
        }
        self.jobs = {}
        for domain in self.domains.values():
            for job in domain.jobs:
                self.jobs[job.name] = job

    def get_jobs(self, name):
        """Return the list of jobs identified by the given name.
A name can either be the name of a domain or the name of one specific job."""
        if name in self.domains:
            return sorted(self.domains[name].jobs, key=lambda job: job.name)
        else:
            return [self.jobs[name]]

def run(options, job, conf, colors=NO_COLORS):
    """Run the specified job (a Job instance)."""
    subprocess.check_call([options.make_command, 'clean'])
    job.announce(colors, None)
    if not job.configure(conf, colors):
        job.announce(colors, False)
        return False
    conf.write()
    success = job.test(options)
    job.announce(colors, success)
    return success

def run_tests(options, domain_data, conf):
    """Run the desired jobs.
domain_data should be a DomainData instance that describes the available
domains and jobs.
Run the jobs listed in options.tasks."""
    colors = Colors(options)
    jobs = []
    failures = []
    successes = []
    for name in options.tasks:
        jobs += domain_data.get_jobs(name)
    conf.backup()
    try:
        for job in jobs:
            success = run(options, job, conf, colors=colors)
            if not success:
                if options.keep_going:
                    failures.append(job.name)
                else:
                    return False
            else:
                successes.append(job.name)
        conf.restore()
    except:
        # Restore the configuration, except in stop-on-error mode if there
        # was an error, where we leave the failing configuration up for
        # developer convenience.
        if options.keep_going:
            conf.restore()
        raise
    if successes:
        log_line('{} passed'.format(' '.join(successes)), color=colors.bold_green)
    if failures:
        log_line('{} FAILED'.format(' '.join(failures)), color=colors.bold_red)
        return False
    else:
        return True

def main():
    try:
        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=
            "Test Mbed TLS with a subset of algorithms.\n\n"
            "Example usage:\n"
            r"./tests/scripts/depends.py \!MBEDTLS_SHA1_C MBEDTLS_SHA256_C""\n"
            "./tests/scripts/depends.py MBEDTLS_AES_C hashes\n"
            "./tests/scripts/depends.py cipher_id cipher_chaining\n")
        parser.add_argument('--color', metavar='WHEN',
                            help='Colorize the output (always/auto/never)',
                            choices=['always', 'auto', 'never'], default='auto')
        parser.add_argument('-c', '--config', metavar='FILE',
                            help='Configuration file to modify',
                            default=config.MbedTLSConfigFile.default_path[0])
        parser.add_argument('-r', '--crypto-config', metavar='FILE',
                            help='Crypto configuration file to modify',
                            default=config.CryptoConfigFile.default_path[0])
        parser.add_argument('-C', '--directory', metavar='DIR',
                            help='Change to this directory before anything else',
                            default='.')
        parser.add_argument('-k', '--keep-going',
                            help='Try all configurations even if some fail (default)',
                            action='store_true', dest='keep_going', default=True)
        parser.add_argument('-e', '--no-keep-going',
                            help='Stop as soon as a configuration fails',
                            action='store_false', dest='keep_going')
        parser.add_argument('--list-jobs',
                            help='List supported jobs and exit',
                            action='append_const', dest='list', const='jobs')
        parser.add_argument('--list-domains',
                            help='List supported domains and exit',
                            action='append_const', dest='list', const='domains')
        parser.add_argument('--make-command', metavar='CMD',
                            help='Command to run instead of make (e.g. gmake)',
                            action='store', default='make')
        parser.add_argument('tasks', metavar='TASKS', nargs='*',
                            help='The domain(s) or job(s) to test (default: all).',
                            default=True)
        options = parser.parse_args()
        os.chdir(options.directory)
        conf = config.CombinedConfig(config.MbedTLSConfigFile(options.config),
                                     config.CryptoConfigFile(options.crypto_config))
        domain_data = DomainData(options, conf)

        if options.tasks is True:
            options.tasks = sorted(domain_data.domains.keys())
        if options.list:
            for arg in options.list:
                for domain_name in sorted(getattr(domain_data, arg).keys()):
                    print(domain_name)
            sys.exit(0)
        else:
            sys.exit(0 if run_tests(options, domain_data, conf) else 1)
    except Exception: # pylint: disable=broad-except
        traceback.print_exc()
        sys.exit(3)

if __name__ == '__main__':
    main()
