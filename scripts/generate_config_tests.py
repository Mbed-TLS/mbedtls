#!/usr/bin/env python3
"""Generate test data for configuration reporting.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import re
import sys
from typing import Iterable, Iterator, List, Optional, Tuple

import project_scripts # pylint: disable=unused-import
import config
from mbedtls_framework import test_case
from mbedtls_framework import test_data_generation


def single_option_case(setting: config.Setting, when_on: bool,
                       dependencies: List[str],
                       note: Optional[str]) -> test_case.TestCase:
    """Construct a test case for a boolean setting.

    This test case passes if the setting and its dependencies are enabled,
    and is skipped otherwise.

    * setting: the setting to be tested.
    * when_on: True to test with the setting enabled, or False to test
      with the setting disabled.
    * dependencies: extra dependencies for the test case.
    * note: a note to add after the option name in the test description.
      This is generally a summary of dependencies, and is generally empty
      if the given setting is only tested once.
    """
    base = setting.name if when_on else '!' + setting.name
    tc = test_case.TestCase()
    tc.set_function('pass')
    description_suffix = ' (' + note + ')' if note else ''
    tc.set_description('Config: ' + base + description_suffix)
    tc.set_dependencies([base] + dependencies)
    return tc


PSA_WANT_KEY_TYPE_KEY_PAIR_RE = \
    re.compile(r'(?P<prefix>PSA_WANT_KEY_TYPE_(?P<type>\w+)_KEY_PAIR_)(?P<operation>\w+)\Z')

# If foo is an option that is only meaningful when bar is enabled, set
# SUPER_SETTINGS[foo]=bar. More generally, bar can be a colon-separated
# list of options, meaning that all the options must be enabled. Each option
# can be prefixed with '!' to negate it. This is the same syntax as a
# depends_on directive in test data.
# See also `find_super_option`.
SUPER_SETTINGS = {
    'MBEDTLS_AESCE_C': 'MBEDTLS_AES_C',
    'MBEDTLS_AESNI_C': 'MBEDTLS_AES_C',
    'MBEDTLS_ERROR_STRERROR_DUMMY': '!MBEDTLS_ERROR_C',
    'MBEDTLS_GENPRIME': 'MBEDTLS_RSA_C',
    'MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES': 'MBEDTLS_ENTROPY_C',
    'MBEDTLS_NO_PLATFORM_ENTROPY': 'MBEDTLS_ENTROPY_C',
    'MBEDTLS_PKCS1_V15': 'MBEDTLS_RSA_C',
    'MBEDTLS_PKCS1_V21': 'MBEDTLS_RSA_C',
    'MBEDTLS_PSA_CRYPTO_CLIENT': '!MBEDTLS_PSA_CRYPTO_C',
    'MBEDTLS_PSA_INJECT_ENTROPY': 'MBEDTLS_PSA_CRYPTO_C',
    'MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS': 'MBEDTLS_PSA_CRYPTO_C',
}

def find_super_option(cfg: config.Config,
                      setting: config.Setting) -> Optional[str]:
    """If setting is only meaningful when some option is enabled, return that option.

    The return value can be a colon-separated list of options, if the setting
    is only meaningful when all of these options are enabled. Options can be
    negated by prefixing them with '!'. This is the same syntax as a
    depends_on directive in test data.
    """
    #pylint: disable=too-many-return-statements
    name = setting.name
    if name in SUPER_SETTINGS:
        return SUPER_SETTINGS[name]
    if name.startswith('MBEDTLS_') and not name.endswith('_C'):
        if name.startswith('MBEDTLS_CIPHER_PADDING_'):
            return 'MBEDTLS_CIPHER_C:MBEDTLS_CIPHER_MODE_CBC'
        if name.startswith('MBEDTLS_PK_PARSE_EC_'):
            return 'MBEDTLS_PK_C:MBEDTLS_PK_HAVE_ECC_KEYS'
        if name.startswith('MBEDTLS_SSL_TLS1_3_') or \
           name == 'MBEDTLS_SSL_EARLY_DATA':
            return 'MBEDTLS_SSL_CLI_C:MBEDTLS_SSL_SRV_C:MBEDTLS_SSL_PROTO_TLS1_3'
        if name.startswith('MBEDTLS_SSL_DTLS_'):
            return 'MBEDTLS_SSL_CLI_C:MBEDTLS_SSL_SRV_C:MBEDTLS_SSL_PROTO_DTLS'
        if name.startswith('MBEDTLS_SSL_'):
            return 'MBEDTLS_SSL_CLI_C:MBEDTLS_SSL_SRV_C'
        for pos in re.finditer(r'_', name):
            super_name = name[:pos.start()] + '_C'
            if cfg.known(super_name):
                return super_name
    m = PSA_WANT_KEY_TYPE_KEY_PAIR_RE.match(name)
    if m and m.group('operation') != 'BASIC':
        return m.group('prefix') + 'BASIC'
    return None

def conditions_for_option(cfg: config.Config,
                          setting: config.Setting
                          ) -> Iterator[Tuple[List[str], str]]:
    """Enumerate the conditions under which to test the given setting.

    * cfg: all configuration options.
    * setting: the setting to be tested.

    Generate a stream of conditions, i.e. extra dependencies to test with
    together with a human-readable explanation of each dependency. Some
    typical cases:

    * By default, generate a one-element stream with no extra dependencies.
    * If the setting is ignored unless some other option is enabled, generate
      a one-element stream with that other option as an extra dependency.
    * If the setting is known to interact with some other option, generate
      a stream with one element where this option is on and one where it's off.
    * To skip the setting altogether, generate an empty stream.
    """
    name = setting.name
    if name.endswith('_ALT') and not config.is_seamless_alt(name):
        # We don't test alt implementations, except (most) platform alts
        return
    super_setting = find_super_option(cfg, setting)
    if super_setting:
        yield [super_setting], ''
        return
    yield [], ''


def enumerate_boolean_option_cases(cfg: config.Config
                                   ) -> Iterable[test_case.TestCase]:
    """Emit test cases for all boolean options."""
    for name in sorted(cfg.settings.keys()):
        setting = cfg.settings[name]
        if not name.startswith('PSA_WANT_') and setting.value:
            continue # non-boolean setting
        for when_on in True, False:
            for deps, note in conditions_for_option(cfg, setting):
                yield single_option_case(setting, when_on, deps, note)



class ConfigTestGenerator(test_data_generation.TestGenerator):
    """Generate test cases for configuration reporting."""

    def __init__(self, options):
        self.mbedtls_config = config.ConfigFile()
        self.targets['test_suite_config.mbedtls_boolean'] = \
            lambda: enumerate_boolean_option_cases(self.mbedtls_config)
        self.psa_config = config.ConfigFile('include/psa/crypto_config.h')
        self.targets['test_suite_config.psa_boolean'] = \
            lambda: enumerate_boolean_option_cases(self.psa_config)
        super().__init__(options)


if __name__ == '__main__':
    test_data_generation.main(sys.argv[1:], __doc__, ConfigTestGenerator)
