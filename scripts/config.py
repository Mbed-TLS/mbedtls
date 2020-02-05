#!/usr/bin/env python3

"""Mbed TLS configuration file manipulation library and tool

Basic usage, to read the Mbed TLS or Mbed Crypto configuration:
    config = ConfigFile()
    if 'MBEDTLS_RSA_C' in config: print('RSA is enabled')
"""

## Copyright (C) 2019, ARM Limited, All Rights Reserved
## SPDX-License-Identifier: Apache-2.0
##
## Licensed under the Apache License, Version 2.0 (the "License"); you may
## not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
## http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
## WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##
## This file is part of Mbed TLS (https://tls.mbed.org)

import os
import re

class Setting:
    """Representation of one Mbed TLS config.h setting.

    Fields:
    * name: the symbol name ('MBEDTLS_xxx').
    * value: the value of the macro. The empty string for a plain #define
      with no value.
    * active: True if name is defined, False if a #define for name is
      present in config.h but commented out.
    * section: the name of the section that contains this symbol.
    """
    # pylint: disable=too-few-public-methods
    def __init__(self, active, name, value='', section=None):
        self.active = active
        self.name = name
        self.value = value
        self.section = section

class Config:
    """Representation of the Mbed TLS configuration.

    In the documentation of this class, a symbol is said to be *active*
    if there is a #define for it that is not commented out, and *known*
    if there is a #define for it whether commented out or not.

    This class supports the following protocols:
    * `name in config` is `True` if the symbol `name` is active, `False`
      otherwise (whether `name` is inactive or not known).
    * `config[name]` is the value of the macro `name`. If `name` is inactive,
      raise `KeyError` (even if `name` is known).
    * `config[name] = value` sets the value associated to `name`. `name`
      must be known, but does not need to be set. This does not cause
      name to become set.
    """

    def __init__(self):
        self.settings = {}

    def __contains__(self, name):
        """True if the given symbol is active (i.e. set).

        False if the given symbol is not set, even if a definition
        is present but commented out.
        """
        return name in self.settings and self.settings[name].active

    def all(self, *names):
        """True if all the elements of names are active (i.e. set)."""
        return all(self.__contains__(name) for name in names)

    def any(self, *names):
        """True if at least one symbol in names are active (i.e. set)."""
        return any(self.__contains__(name) for name in names)

    def known(self, name):
        """True if a #define for name is present, whether it's commented out or not."""
        return name in self.settings

    def __getitem__(self, name):
        """Get the value of name, i.e. what the preprocessor symbol expands to.

        If name is not known, raise KeyError. name does not need to be active.
        """
        return self.settings[name].value

    def get(self, name, default=None):
        """Get the value of name. If name is inactive (not set), return default.

        If a #define for name is present and not commented out, return
        its expansion, even if this is the empty string.

        If a #define for name is present but commented out, return default.
        """
        if name in self.settings:
            return self.settings[name].value
        else:
            return default

    def __setitem__(self, name, value):
        """If name is known, set its value.

        If name is not known, raise KeyError.
        """
        self.settings[name].value = value

    def set(self, name, value=None):
        """Set name to the given value and make it active.

        If value is None and name is already known, don't change its value.
        If value is None and name is not known, set its value to the empty
        string.
        """
        if name in self.settings:
            if value is not None:
                self.settings[name].value = value
            self.settings[name].active = True
        else:
            self.settings[name] = Setting(True, name, value=value)

    def unset(self, name):
        """Make name unset (inactive).

        name remains known if it was known before.
        """
        if name not in self.settings:
            return
        self.settings[name].active = False

    def adapt(self, adapter):
        """Run adapter on each known symbol and (de)activate it accordingly.

        `adapter` must be a function that returns a boolean. It is called as
        `adapter(name, active, section)` for each setting, where `active` is
        `True` if `name` is set and `False` if `name` is known but unset,
        and `section` is the name of the section containing `name`. If
        `adapter` returns `True`, then set `name` (i.e. make it active),
        otherwise unset `name` (i.e. make it known but inactive).
        """
        for setting in self.settings.values():
            setting.active = adapter(setting.name, setting.active,
                                     setting.section)

def is_full_section(section):
    """Is this section affected by "config.py full" and friends?"""
    return section.endswith('support') or section.endswith('modules')

def realfull_adapter(_name, active, section):
    """Activate all symbols found in the system and feature sections."""
    if not is_full_section(section):
        return active
    return True

def include_in_full(name):
    """Rules for symbols in the "full" configuration."""
    if re.search(r'PLATFORM_[A-Z0-9]+_ALT', name):
        return True
    if name in [
            'MBEDTLS_DEPRECATED_REMOVED',
            'MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED',
            'MBEDTLS_ECP_RESTARTABLE',
            'MBEDTLS_HAVE_SSE2',
            'MBEDTLS_MEMORY_BACKTRACE',
            'MBEDTLS_MEMORY_BUFFER_ALLOC_C',
            'MBEDTLS_MEMORY_DEBUG',
            'MBEDTLS_NO_64BIT_MULTIPLICATION',
            'MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES',
            'MBEDTLS_NO_PLATFORM_ENTROPY',
            'MBEDTLS_NO_UDBL_DIVISION',
            'MBEDTLS_PKCS11_C',
            'MBEDTLS_PLATFORM_NO_STD_FUNCTIONS',
            'MBEDTLS_PSA_CRYPTO_SPM',
            'MBEDTLS_PSA_INJECT_ENTROPY',
            'MBEDTLS_REMOVE_3DES_CIPHERSUITES',
            'MBEDTLS_REMOVE_ARC4_CIPHERSUITES',
            'MBEDTLS_RSA_NO_CRT',
            'MBEDTLS_SSL_HW_RECORD_ACCEL',
            'MBEDTLS_SSL_PROTO_SSL3',
            'MBEDTLS_SSL_SRV_SUPPORT_SSLV2_CLIENT_HELLO',
            'MBEDTLS_TEST_NULL_ENTROPY',
            'MBEDTLS_X509_ALLOW_EXTENSIONS_NON_V3',
            'MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION',
            'MBEDTLS_ZLIB_SUPPORT',
    ]:
        return False
    if name.endswith('_ALT'):
        return False
    return True

def full_adapter(name, active, section):
    """Config adapter for "full"."""
    if not is_full_section(section):
        return active
    return include_in_full(name)

def keep_in_baremetal(name):
    """Rules for symbols in the "baremetal" configuration."""
    if name in [
            'MBEDTLS_DEPRECATED_WARNING',
            'MBEDTLS_ENTROPY_NV_SEED',
            'MBEDTLS_FS_IO',
            'MBEDTLS_HAVEGE_C',
            'MBEDTLS_HAVE_TIME',
            'MBEDTLS_HAVE_TIME_DATE',
            'MBEDTLS_MEMORY_BACKTRACE',
            'MBEDTLS_MEMORY_BUFFER_ALLOC_C',
            'MBEDTLS_NET_C',
            'MBEDTLS_PLATFORM_FPRINTF_ALT',
            'MBEDTLS_PLATFORM_TIME_ALT',
            'MBEDTLS_PSA_CRYPTO_STORAGE_C',
            'MBEDTLS_PSA_ITS_FILE_C',
            'MBEDTLS_THREADING_C',
            'MBEDTLS_THREADING_PTHREAD',
            'MBEDTLS_TIMING_C',
    ]:
        return False
    return True

def baremetal_adapter(name, active, section):
    """Config adapter for "baremetal"."""
    if not is_full_section(section):
        return active
    if name == 'MBEDTLS_NO_PLATFORM_ENTROPY':
        return True
    return include_in_full(name) and keep_in_baremetal(name)

def include_in_crypto(name):
    """Rules for symbols in a crypto configuration."""
    if name.startswith('MBEDTLS_X509_') or \
       name.startswith('MBEDTLS_SSL_') or \
       name.startswith('MBEDTLS_KEY_EXCHANGE_'):
        return False
    if name in [
            'MBEDTLS_CERTS_C',
            'MBEDTLS_DEBUG_C',
            'MBEDTLS_NET_C',
            'MBEDTLS_PKCS11_C',
    ]:
        return False
    return True

def crypto_adapter(adapter):
    """Modify an adapter to disable non-crypto symbols.

    ``crypto_adapter(adapter)(name, active, section)`` is like
    ``adapter(name, active, section)``, but unsets all X.509 and TLS symbols.
    """
    def continuation(name, active, section):
        if not include_in_crypto(name):
            return False
        if adapter is None:
            return active
        return adapter(name, active, section)
    return continuation

class ConfigFile(Config):
    """Representation of the Mbed TLS configuration read for a file.

    See the documentation of the `Config` class for methods to query
    and modify the configuration.
    """

    _path_in_tree = 'include/mbedtls/config.h'
    default_path = [_path_in_tree,
                    os.path.join(os.path.dirname(__file__),
                                 os.pardir,
                                 _path_in_tree),
                    os.path.join(os.path.dirname(os.path.abspath(os.path.dirname(__file__))),
                                 _path_in_tree)]

    def __init__(self, filename=None):
        """Read the Mbed TLS configuration file."""
        if filename is None:
            for filename in self.default_path:
                if os.path.lexists(filename):
                    break
        super().__init__()
        self.filename = filename
        self.current_section = 'header'
        with open(filename, 'r', encoding='utf-8') as file:
            self.templates = [self._parse_line(line) for line in file]
        self.current_section = None

    def set(self, name, value=None):
        if name not in self.settings:
            self.templates.append((name, '', '#define ' + name + ' '))
        super().set(name, value)

    _define_line_regexp = (r'(?P<indentation>\s*)' +
                           r'(?P<commented_out>(//\s*)?)' +
                           r'(?P<define>#\s*define\s+)' +
                           r'(?P<name>\w+)' +
                           r'(?P<arguments>(?:\((?:\w|\s|,)*\))?)' +
                           r'(?P<separator>\s*)' +
                           r'(?P<value>.*)')
    _section_line_regexp = (r'\s*/?\*+\s*[\\@]name\s+SECTION:\s*' +
                            r'(?P<section>.*)[ */]*')
    _config_line_regexp = re.compile(r'|'.join([_define_line_regexp,
                                                _section_line_regexp]))
    def _parse_line(self, line):
        """Parse a line in config.h and return the corresponding template."""
        line = line.rstrip('\r\n')
        m = re.match(self._config_line_regexp, line)
        if m is None:
            return line
        elif m.group('section'):
            self.current_section = m.group('section')
            return line
        else:
            active = not m.group('commented_out')
            name = m.group('name')
            value = m.group('value')
            template = (name,
                        m.group('indentation'),
                        m.group('define') + name +
                        m.group('arguments') + m.group('separator'))
            self.settings[name] = Setting(active, name, value,
                                          self.current_section)
            return template

    def _format_template(self, name, indent, middle):
        """Build a line for config.h for the given setting.

        The line has the form "<indent>#define <name> <value>"
        where <middle> is "#define <name> ".
        """
        setting = self.settings[name]
        value = setting.value
        if value is None:
            value = ''
        # Normally the whitespace to separte the symbol name from the
        # value is part of middle, and there's no whitespace for a symbol
        # with no value. But if a symbol has been changed from having a
        # value to not having one, the whitespace is wrong, so fix it.
        if value:
            if middle[-1] not in '\t ':
                middle += ' '
        else:
            middle = middle.rstrip()
        return ''.join([indent,
                        '' if setting.active else '//',
                        middle,
                        value]).rstrip()

    def write_to_stream(self, output):
        """Write the whole configuration to output."""
        for template in self.templates:
            if isinstance(template, str):
                line = template
            else:
                line = self._format_template(*template)
            output.write(line + '\n')

    def write(self, filename=None):
        """Write the whole configuration to the file it was read from.

        If filename is specified, write to this file instead.
        """
        if filename is None:
            filename = self.filename
        with open(filename, 'w', encoding='utf-8') as output:
            self.write_to_stream(output)

if __name__ == '__main__':
    def main():
        """Command line config.h manipulation tool."""
        parser = argparse.ArgumentParser(description="""
        Mbed TLS and Mbed Crypto configuration file manipulation tool.
        """)
        parser.add_argument('--file', '-f',
                            help="""File to read (and modify if requested).
                            Default: {}.
                            """.format(ConfigFile.default_path))
        parser.add_argument('--force', '-o',
                            action='store_true',
                            help="""For the set command, if SYMBOL is not
                            present, add a definition for it.""")
        parser.add_argument('--write', '-w', metavar='FILE',
                            help="""File to write to instead of the input file.""")
        subparsers = parser.add_subparsers(dest='command',
                                           title='Commands')
        parser_get = subparsers.add_parser('get',
                                           help="""Find the value of SYMBOL
                                           and print it. Exit with
                                           status 0 if a #define for SYMBOL is
                                           found, 1 otherwise.
                                           """)
        parser_get.add_argument('symbol', metavar='SYMBOL')
        parser_set = subparsers.add_parser('set',
                                           help="""Set SYMBOL to VALUE.
                                           If VALUE is omitted, just uncomment
                                           the #define for SYMBOL.
                                           Error out of a line defining
                                           SYMBOL (commented or not) is not
                                           found, unless --force is passed.
                                           """)
        parser_set.add_argument('symbol', metavar='SYMBOL')
        parser_set.add_argument('value', metavar='VALUE', nargs='?',
                                default='')
        parser_unset = subparsers.add_parser('unset',
                                             help="""Comment out the #define
                                             for SYMBOL. Do nothing if none
                                             is present.""")
        parser_unset.add_argument('symbol', metavar='SYMBOL')

        def add_adapter(name, function, description):
            subparser = subparsers.add_parser(name, help=description)
            subparser.set_defaults(adapter=function)
        add_adapter('baremetal', baremetal_adapter,
                    """Like full, but exclude features that require platform
                    features such as file input-output.""")
        add_adapter('full', full_adapter,
                    """Uncomment most features.
                    Exclude alternative implementations and platform support
                    options, as well as some options that are awkward to test.
                    """)
        add_adapter('realfull', realfull_adapter,
                    """Uncomment all boolean #defines.
                    Suitable for generating documentation, but not for building.""")
        add_adapter('crypto', crypto_adapter(None),
                    """Only include crypto features. Exclude X.509 and TLS.""")
        add_adapter('crypto_baremetal', crypto_adapter(baremetal_adapter),
                    """Like baremetal, but with only crypto features,
                    excluding X.509 and TLS.""")
        add_adapter('crypto_full', crypto_adapter(full_adapter),
                    """Like full, but with only crypto features,
                    excluding X.509 and TLS.""")

        args = parser.parse_args()
        config = ConfigFile(args.file)
        if args.command is None:
            parser.print_help()
            return 1
        elif args.command == 'get':
            if args.symbol in config:
                value = config[args.symbol]
                if value:
                    sys.stdout.write(value + '\n')
            return args.symbol not in config
        elif args.command == 'set':
            if not args.force and args.symbol not in config.settings:
                sys.stderr.write("A #define for the symbol {} "
                                 "was not found in {}\n"
                                 .format(args.symbol, config.filename))
                return 1
            config.set(args.symbol, value=args.value)
        elif args.command == 'unset':
            config.unset(args.symbol)
        else:
            config.adapt(args.adapter)
        config.write(args.write)

    # Import modules only used by main only if main is defined and called.
    # pylint: disable=wrong-import-position
    import argparse
    import sys
    sys.exit(main())
