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
