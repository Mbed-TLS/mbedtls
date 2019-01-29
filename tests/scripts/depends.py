#!/usr/bin/env python3

# Copyright (c) 2018, Arm Limited, All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file is part of Mbed TLS (https://tls.mbed.org)

"""Test Mbed TLS with a subset of algorithms.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import traceback

class Colors:
    """Minimalistic support for colored output.
Each field of an object of this class is either None if colored output
is not possible or not desired, or a pair of strings (start, stop) such
that outputting start switches the text color to the desired color and
stop switches the text color back to the default."""
    red = None
    green = None
    bold_red = None
    bold_green = None
    def __init__(self, options=None):
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
            self.bold_red = ('\033[1;31m', normal)
            self.bold_green = ('\033[1;32m', normal)
NO_COLORS = Colors(None)

def log_line(text, prefix='depends.py:', suffix='', color=None):
    """Print a status message."""
    if color != None:
        prefix = color[0] + prefix
        suffix = suffix + color[1]
    sys.stderr.write(prefix + ' ' + text + suffix + '\n')
    sys.stderr.flush()

def log_command(cmd):
    """Print a trace of the specified command.
cmd is a list of strings: a command name and its arguments."""
    log_line(' '.join(cmd), prefix='+')

def backup_config(options):
    """Back up the library configuration file (config.h).
If the backup file already exists, it is presumed to be the desired backup,
so don't make another backup."""
    if os.path.exists(options.config_backup):
        options.own_backup = False
    else:
        options.own_backup = True
        shutil.copy(options.config, options.config_backup)

def restore_config(options):
    """Restore the library configuration file (config.h).
Remove the backup file if it was saved earlier."""
    if options.own_backup:
        shutil.move(options.config_backup, options.config)
    else:
        shutil.copy(options.config_backup, options.config)

def run_config_pl(options, args):
    """Run scripts/config.pl with the specified arguments."""
    cmd = ['scripts/config.pl']
    if options.config != 'include/mbedtls/config.h':
        cmd += ['--file', options.config]
    cmd += args
    log_command(cmd)
    subprocess.check_call(cmd)

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
            log_line('starting ' + self.name)

    def set_reference_config(self, options):
        """Change the library configuration file (config.h) to the reference state.
    The reference state is the one from which the tested configurations are
    derived."""
        # Turn off memory management options that are not relevant to
        # the tests and slow them down.
        run_config_pl(options, ['full'])
        run_config_pl(options, ['unset', 'MBEDTLS_MEMORY_BACKTRACE'])
        run_config_pl(options, ['unset', 'MBEDTLS_MEMORY_BUFFER_ALLOC_C'])
        run_config_pl(options, ['unset', 'MBEDTLS_MEMORY_DEBUG'])

    def configure(self, options):
        '''Set library configuration options as required for the job.
config_file_name indicates which file to modify.'''
        self.set_reference_config(options)
        for key, value in sorted(self.config_settings.items()):
            if value is True:
                args = ['set', key]
            elif value is False:
                args = ['unset', key]
            else:
                args = ['set', key, value]
            run_config_pl(options, args)

    def test(self, options):
        '''Run the job's build and test commands.
Return True if all the commands succeed and False otherwise.
If options.keep_going is false, stop as soon as one command fails. Otherwise
run all the commands, except that if the first command fails, none of the
other commands are run (typically, the first command is a build command
and subsequent commands are tests that cannot run if the build failed).'''
        built = False
        success = True
        for command in self.commands:
            log_command(command)
            ret = subprocess.call(command)
            if ret != 0:
                if command[0] not in ['make', options.make_command]:
                    log_line('*** [{}] Error {}'.format(' '.join(command), ret))
                if not options.keep_going or not built:
                    return False
                success = False
            built = True
        return success

# SSL/TLS versions up to 1.1 and corresponding options. These require
# both MD5 and SHA-1.
ssl_pre_1_2_dependencies = ['MBEDTLS_SSL_CBC_RECORD_SPLITTING',
                            'MBEDTLS_SSL_PROTO_SSL3',
                            'MBEDTLS_SSL_PROTO_TLS1',
                            'MBEDTLS_SSL_PROTO_TLS1_1']

# If the configuration option A requires B, make sure that
# B in reverse_dependencies[A].
reverse_dependencies = {
    'MBEDTLS_ECDSA_C': ['MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED'],
    'MBEDTLS_ECP_C': ['MBEDTLS_ECDSA_C',
                      'MBEDTLS_ECDH_C',
                      'MBEDTLS_ECJPAKE_C',
                      'MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED',
                      'MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED',
                      'MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED',
                      'MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED',
                      'MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED'],
    'MBEDTLS_MD5_C': ssl_pre_1_2_dependencies,
    'MBEDTLS_PKCS1_V21': ['MBEDTLS_X509_RSASSA_PSS_SUPPORT'],
    'MBEDTLS_PKCS1_V15': ['MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED',
                          'MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED',
                          'MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED',
                          'MBEDTLS_KEY_EXCHANGE_RSA_ENABLED'],
    'MBEDTLS_RSA_C': ['MBEDTLS_X509_RSASSA_PSS_SUPPORT',
                      'MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED',
                      'MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED',
                      'MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED',
                      'MBEDTLS_KEY_EXCHANGE_RSA_ENABLED'],
    'MBEDTLS_SHA1_C': ssl_pre_1_2_dependencies,
    'MBEDTLS_X509_RSASSA_PSS_SUPPORT': [],
}

def turn_off_dependencies(config_settings):
    """For every option turned off config_settings, also turn off what depends on it.
An option O is turned off if config_settings[O] is False."""
    for key, value in sorted(config_settings.items()):
        if value is not False:
            continue
        for dep in reverse_dependencies.get(key, []):
            config_settings[dep] = False

class Domain:
    """A domain is a set of jobs that all relate to a particular configuration aspect."""
    pass

class ExclusiveDomain(Domain):
    """A domain consisting of a set of conceptually-equivalent settings.
Establish a list of configuration symbols. For each symbol, run a test job
with this symbol set and the others unset, and a test job with this symbol
unset and the others set."""
    def __init__(self, symbols, commands):
        self.jobs = []
        for invert in [False, True]:
            base_config_settings = {}
            for symbol in symbols:
                base_config_settings[symbol] = invert
            for symbol in symbols:
                description = '!' + symbol if invert else symbol
                config_settings = base_config_settings.copy()
                config_settings[symbol] = not invert
                turn_off_dependencies(config_settings)
                job = Job(description, config_settings, commands)
                self.jobs.append(job)

class ComplementaryDomain:
    """A domain consisting of a set of loosely-related settings.
Establish a list of configuration symbols. For each symbol, run a test job
with this symbol unset."""
    def __init__(self, symbols, commands):
        self.jobs = []
        for symbol in symbols:
            description = '!' + symbol
            config_settings = {symbol: False}
            turn_off_dependencies(config_settings)
            job = Job(description, config_settings, commands)
            self.jobs.append(job)

class DomainData:
    """Collect data about the library."""
    def collect_config_symbols(self, options):
        """Read the list of settings from config.h.
Return them in a generator."""
        with open(options.config) as config_file:
            rx = re.compile(r'\s*(?://\s*)?#define\s+(\w+)\s*(?:$|/[/*])')
            for line in config_file:
                m = re.match(rx, line)
                if m:
                    yield m.group(1)

    def config_symbols_matching(self, regexp):
        """List the config.h settings matching regexp."""
        return [symbol for symbol in self.all_config_symbols
                if re.match(regexp, symbol)]

    def __init__(self, options):
        """Gather data about the library and establish a list of domains to test."""
        build_command = [options.make_command, 'CFLAGS=-Werror']
        build_and_test = [build_command, [options.make_command, 'test']]
        self.all_config_symbols = set(self.collect_config_symbols(options))
        # Find hash modules by name.
        hash_symbols = self.config_symbols_matching(r'MBEDTLS_(MD|RIPEMD|SHA)[0-9]+_C\Z')
        # Find elliptic curve enabling macros by name.
        curve_symbols = self.config_symbols_matching(r'MBEDTLS_ECP_DP_\w+_ENABLED\Z')
        # Find key exchange enabling macros by name.
        key_exchange_symbols = self.config_symbols_matching(r'MBEDTLS_KEY_EXCHANGE_\w+_ENABLED\Z')
        self.domains = {
            # Elliptic curves. Run the test suites.
            'curves': ExclusiveDomain(curve_symbols, build_and_test),
            # Hash algorithms. Exclude configurations with only one
            # hash which is obsolete. Run the test suites.
            'hashes': ExclusiveDomain(hash_symbols, build_and_test),
            # Key exchange types. Just check the build.
            'kex': ExclusiveDomain(key_exchange_symbols, [build_command]),
            # Public-key algorithms. Run the test suites.
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

def run(options, job, colors=NO_COLORS):
    """Run the specified job (a Job instance)."""
    subprocess.check_call([options.make_command, 'clean'])
    job.announce(colors, None)
    job.configure(options)
    success = job.test(options)
    job.announce(colors, success)
    return success

def main(options, domain_data):
    """Run the desired jobs.
domain_data should be a DomainData instance that describes the available
domains and jobs.
Run the jobs listed in options.domains."""
    if not hasattr(options, 'config_backup'):
        options.config_backup = options.config + '.bak'
    colors = Colors(options)
    jobs = []
    failures = []
    successes = []
    for name in options.domains:
        jobs += domain_data.get_jobs(name)
    backup_config(options)
    try:
        for job in jobs:
            success = run(options, job, colors=colors)
            if not success:
                if options.keep_going:
                    failures.append(job.name)
                else:
                    return False
            else:
                successes.append(job.name)
        restore_config(options)
    except:
        # Restore the configuration, except in stop-on-error mode if there
        # was an error, where we leave the failing configuration up for
        # developer convenience.
        if options.keep_going:
            restore_config(options)
        raise
    if successes:
        log_line('{} passed'.format(' '.join(successes)), color=colors.bold_green)
    if failures:
        log_line('{} FAILED'.format(' '.join(failures)), color=colors.bold_red)
        return False
    else:
        return True


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--color', metavar='WHEN',
                            help='Colorize the output (always/auto/never)',
                            choices=['always', 'auto', 'never'], default='auto')
        parser.add_argument('-c', '--config', metavar='FILE',
                            help='Configuration file to modify',
                            default='include/mbedtls/config.h')
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
        parser.add_argument('domains', metavar='DOMAIN', nargs='*',
                            help='The domain(s) to test (default: all)',
                            default=True)
        options = parser.parse_args()
        os.chdir(options.directory)
        domain_data = DomainData(options)
        if options.domains == True:
            options.domains = sorted(domain_data.domains.keys())
        if options.list:
            for what in options.list:
                for key in sorted(getattr(domain_data, what).keys()):
                    print(key)
            exit(0)
        else:
            sys.exit(0 if main(options, domain_data) else 1)
    except SystemExit:
        raise
    except:
        traceback.print_exc()
        exit(3)
