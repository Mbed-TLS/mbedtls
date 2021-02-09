#!/usr/bin/env python3
"""Gather some statistics about Mbed TLS configuration settings.
"""

import argparse
from collections import Counter
import glob
import os
import re
import subprocess
import sys
import tempfile

import config



class Setting:
    """Information about an Mbed TLS compile-time setting."""
    def __init__(self, config_setting):
        self.active = config_setting.active
        self.active_in_full = None
        self.name = config_setting.name
        self.value = config_setting.value
        self.section = config_setting.value

def is_wanted_setting(options, setting):
    """Whether we want information about the given setting."""
    if options.names:
        if not re.search(options.names, setting.name):
            return False
    if setting.name in {'_CRT_SECURE_NO_DEPRECATE',
                        'MBEDTLS_CONFIG_H'}:
        # Not really settings (config.py should suppress these)
        return False
    if setting.name == 'MBEDTLS_PSA_CRYPTO_SPM' or\
       setting.name.endswith('_ALT'):
        # Requires additional headers (will break diffstat)
        return False
    if setting.name.endswith('_C'):
        # Not interesting right now
        return False
    if setting.name.startswith('MBEDTLS_PLATFORM_'):
        # Not interesting right now
        return False
    if setting.value:
        return False
    return True



class StatGatherer:
    """Collection of methods to gather information about Mbed TLS compile-time settings.

    This class maintains a cache of expensive-to-compute information.
    """

    EXCLUDED_LIBRARY_FILES = frozenset(
        'library/version_features.c'
    )

    def __init__(self):
        self.library_files = (frozenset(glob.glob('library/*.[hc]')) -
                              self.EXCLUDED_LIBRARY_FILES)
        self.test_function_files = frozenset(glob.glob('tests/suites/test_suite_*.function'))
        self.test_data_files = frozenset(glob.glob('tests/suites/test_suite_*.data'))
        self.test_script_files = frozenset(['tests/ssl-opt.sh'])
        self.test_dependencies = Counter()
        self.preprocessed_dir = tempfile.TemporaryDirectory()
        self.preprocess_in_config(self.preprocessed_dir.name,
                                  'mbedtls/config.h')

    def count_unit_test_dependencies(self):
        """Count how many test functions and test cases depend on each symbol.
        """
        cmd = ['grep', '-o', '-E', 'depends_on:[ !0-9A-Z_a-z]+',
               *sorted(self.test_function_files), *sorted(self.test_data_files),
               '/dev/null']
        output = subprocess.check_output(cmd, encoding='ascii')
        for name in re.split(r'\W+', output):
            if name == 'depends_on':
                continue
            self.test_dependencies[name] += 1

    def count_test_script_dependencies(self):
        """Count how many SSL test cases depend on each symbol.
        """
        cmd = ['grep', '^ *requires_config_enabled',
               *sorted(self.test_script_files),
               '/dev/null']
        output = subprocess.check_output(cmd, encoding='ascii')
        for line in re.split('\n', output):
            m = re.match(r'\brequires_config_enabled +(\w+)', line)
            if m:
                name = m.group(1)
                self.test_dependencies[name] += 1

    def gather_general_stats(self):
        """Gather information that is obtained for every symbol at once."""
        self.count_unit_test_dependencies()
        self.count_test_script_dependencies()

    POST_CPP_FILTER = r"""awk '
    /^# [0-9]+ / {file = $3}
    /^[^ #]/ && file == "\"<stdin>\"" {wanted = 1}
    wanted && /^[^#]/ {print}
    '"""
    def preprocess_in_config(self, dir_name, config_file_name):
        """Preprocess the library in a given configuration.

        The preprocessed files are placed in `dir_name`. They can be
        used to estimate how different two configurations are.
        """
        cpp_cmd = 'cpp -DMBEDTLS_CONFIG_FILE=\'"{}"\' -Ilibrary -Iinclude'.format(
            config_file_name,
        )
        try:
            subprocess.check_call([
                '{ echo \'#include MBEDTLS_CONFIG_FILE\'; ' +
                'echo \'#include "mbedtls/check_config.h"\'; } | ' +
                cpp_cmd + ' 2>/dev/null'],
                                  shell=True, stdout=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            # This option can't be turned on/off from the default config
            return False
        for filename in self.library_files:
            if not filename.endswith('.c'):
                continue
            cmd = cpp_cmd + ' - <{} | {} >{}/{}'.format(
                filename,
                self.POST_CPP_FILTER,
                dir_name, os.path.basename(filename)
            )
            subprocess.check_call([cmd], shell=True)
        return True

    def populate(self, setting):
        """Populate a setting with general information about it."""
        setting.test_dependencies = self.test_dependencies[setting.name]

    @staticmethod
    def diffstat(reference, modified):
        """Estimate the differences between files in the two specified directories.

        Return the number of lines that are only present on one side.
        """
        cmd = 'diff -ru {} {} | diffstat'.format(reference, modified)
        output = subprocess.check_output([cmd], shell=True, encoding='ascii')
        summary = output.rstrip('\n').split('\n')[-1]
        differences = 0
        for kind in ('insertions', 'deletions'):
            m = re.search(r'([0-9]+) ' + kind, summary)
            if m:
                differences += int(m.group(1))
        return differences

    def count_code_lines(self, name, active_by_default):
        """Estimate how many the code lines are affected by the given setting.

        Compare the source code in the default configuration and when the
        given setting is toggled from its default value.
        Return the number of code lines in the library source modules
        affected by the setting, or `None` if the setting can't be toggled
        in the default configuration.
        """
        verb = 'unset' if active_by_default else 'set'
        with tempfile.NamedTemporaryFile() as temp_config:
            subprocess.check_call(['scripts/config.py', '-w', temp_config.name,
                                   verb, name])
            with tempfile.TemporaryDirectory() as dir_name:
                if self.preprocess_in_config(dir_name, temp_config.name):
                    return self.diffstat(self.preprocessed_dir.name, dir_name)
                else:
                    return None

def gather_stats(options):
    """Gather all information that this script knows about.

    Return a dictionary mapping names to settings.
    """
    config_data = config.ConfigFile()
    stat_gatherer = StatGatherer()
    stat_gatherer.gather_general_stats()
    settings = {}
    for name in config_data.settings:
        if not is_wanted_setting(options, config_data.settings[name]):
            continue
        setting = Setting(config_data.settings[name])
        stat_gatherer.populate(setting)
        settings[name] = setting
    config_data.adapt(config.full_adapter)
    for name in settings:
        settings[name].active_in_full = config_data.settings[name].active
        settings[name].code_lines = \
            stat_gatherer.count_code_lines(name, settings[name].active)
    return settings



class StatsWriter:
    """Format-agnostic parent class for stats writers."""

    def __init__(self, out=None):
        self.set_output(out)

    def set_output(self, out):
        if isinstance(out, str):
            self.out = open(out, 'w')
        else:
            self.out = out

    def header(self):
        raise NotImplementedError

    def row(self, setting):
        raise NotImplementedError

    def footer(self):
        raise NotImplementedError

    def table(self, settings):
        self.header()
        for name in sorted(settings):
            self.row(settings[name])
        self.footer()

class HTMLStatsWriter(StatsWriter):
    """HTML stats writer.

    Write a simple HTML table.
    """

    COLUMN_NAMES = ['Option', 'Default', 'In full', 'Test cases', 'Code lines']

    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)

    def header(self):
        self.out.write('<html>\n')
        title = 'Statistics about Mbed TLS configuration options'
        self.out.write('<head><title>' + title + '</title></head>')
        self.out.write('<body>\n')
        self.out.write('<table>\n')
        self.out.write('  <tr>\n')
        for text in self.COLUMN_NAMES:
            self.out.write('    <th>' + text + '</th>\n')
        self.out.write('  </tr>\n')

    def td(self, text):
        self.out.write('    <td>' + text + '</td>\n')

    def row(self, setting):
        self.out.write('  <tr>\n')
        self.td(setting.name)
        self.td('Y' if setting.active else 'n')
        self.td('Y' if setting.active_in_full else 'n')
        self.td(str(setting.test_dependencies))
        self.td(str(setting.code_lines) if setting.code_lines is not None else '?')
        self.out.write('  </tr>\n')

    def footer(self):
        self.out.write('</table>\n')
        self.out.write('</body>\n')
        self.out.write('</html>\n')



def show_stats(options):
    """Write statistics as specified in `options`."""
    settings = gather_stats(options)
    if options.format == 'html':
        writer = HTMLStatsWriter()
    else:
        raise Exception('Unknown format: ' + format)
    writer.set_output(options.output if options.output is not None else
                      sys.stdout)
    writer.table(settings)

def main(args):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--names', '-n',
                        help='Only report on settings whose names contains this regex')
    parser.add_argument('--format', '-f',
                        choices=['html'],
                        default='html',
                        help='Output format')
    parser.add_argument('--output', '-o',
                        help='Output file name (default: stdout)')
    options = parser.parse_args(args)
    show_stats(options)

if __name__ == '__main__':
    main(sys.argv[1:])
