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

import re

class Setting:
    """Representation of one Mbed TLS config.h setting.

    Fields:
    * name: the symbol name ('MBEDTLS_xxx').
    * value: the value of the macro. The empty string for a plain #define
      with no value.
    * active: True if name is defined, False if a #define for name is
      present in config.h but commented out.
    """
    # pylint: disable=too-few-public-methods
    def __init__(self, active, name, value=''):
        self.active = active
        self.name = name
        self.value = value

class Config:
    """Representation of the Mbed TLS configuration.

    In the documentation of this class, a symbol is said to be *active*
    if there is a #define for it that is not commented out, and *known*
    if there is a #define for it whether commented out or not.

    This class supports the following protocols:
    * `name in config` is True if the symbol `name` is set in the
      configuration, False otherwise (whether `name` is known but commented
      out or not known at all).
    * `config[name]` is the value of the macro `name`. If `name` is not
      set, raise `KeyError` (even if a definition for `name` is present
      but commented out).
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

        name remains known.
        """
        self.set(name)
        self.settings[name].active = False

    def adapt(self, adapter):
        """Run adapter on each known symbol and (de)activate it accordingly.

        `adapter` must be a function that returns a boolean. It is called as
        `adapter(name, active)` for each setting, where `active` is `True`
        if `name` is set and `False` if `name` is known but unset. If
        `adapter` returns `True`, then set `name` (i.e. make it active),
        otherwise unset `name` (i.e. make it known but inactive).
        """
        for setting in self.settings.values():
            setting.active = adapter(setting.name, setting.active)

def realfull_adapter(_name, _set):
    """Uncomment everything."""
    return True

class ConfigFile(Config):
    """Representation of the Mbed TLS configuration read for a file.

    See the documentation of the `Config` class for methods to query
    and modify the configuration.
    """

    default_path = 'include/mbedtls/config.h'

    def __init__(self, filename=None):
        """Read the Mbed TLS configuration file."""
        if filename is None:
            filename = self.default_path
        super().__init__()
        self.filename = filename
        with open(filename) as file:
            self.templates = [self._parse_line(line) for line in file]

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
    def _parse_line(self, line):
        """Parse a line in config.h and return the corresponding template."""
        line = line.rstrip('\r\n')
        m = re.match(self._define_line_regexp, line)
        if m:
            active = not m.group('commented_out')
            name = m.group('name')
            value = m.group('value')
            template = (name,
                        m.group('indentation'),
                        m.group('define') + name +
                        m.group('arguments') + m.group('separator'))
            self.settings[name] = Setting(active, name, value)
            return template
        else:
            return line

    def _format_template(self, name, indent, middle):
        """Build a line for config.h for the given setting.

        The line has the form "<indent>#define <name><middle> <value>".
        """
        setting = self.settings[name]
        return ''.join([indent,
                        '' if setting.active else '//',
                        middle,
                        setting.value]).rstrip()

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
        with open(filename, 'w') as output:
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
                            help="""For the set command, if SYMBOL is not
                            present, add a definition for it.""")
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
        parser_set.add_argument('value', metavar='VALUE', nargs='?')
        parser_unset = subparsers.add_parser('unset',
                                             help="""Comment out the #define
                                             for SYMBOL. Do nothing if none
                                             is present.""")
        parser_unset.add_argument('symbol', metavar='SYMBOL')

        def add_adapter(name, function, description):
            subparser = subparsers.add_parser(name, help=description)
            subparser.set_defaults(adapter=function)
        add_adapter('realfull', realfull_adapter,
                    """Uncomment all #defines. No exceptions.""")

        args = parser.parse_args()
        config = ConfigFile(args.file)
        if args.command == 'get':
            if args.symbol in config:
                value = config[args.symbol]
                if value:
                    sys.stdout.write(value + '\n')
            return args.symbol not in config
        elif args.command == 'set':
            if not args.force and args.symbol not in config:
                sys.stderr.write("A #define for the symbol {} "
                                 "was not found in {}"
                                 .format(args.symbol, args.file))
                return 1
            config.set(args.symbol, value=args.value)
        elif args.command == 'unset':
            config.unset(args.symbol)
        else:
            config.adapt(args.adapter)
        config.write()

    # Import modules only used by main only if main is defined and called.
    # pylint: disable=wrong-import-position
    import argparse
    import sys
    sys.exit(main())
