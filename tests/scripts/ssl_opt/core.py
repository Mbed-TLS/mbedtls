# core.py
#
# Copyright The Mbed TLS Contributors
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

"""
Core Structure and utils for ssl-opt test

"""

import os
import re
from subprocess import check_output
from .utils import name_to_class_case, name_to_function_case

MBEDTLS_SOURCE_ROOT = os.getenv('MBEDTLS_SOURCE_ROOT', os.path.abspath('.'))
MBEDTLS_BINARY_ROOT = os.getenv('MBEDTLS_BINARY_ROOT', MBEDTLS_SOURCE_ROOT)

class CommandNotImplementedError(NotImplementedError):
    pass


class Command:
    _command_ = 'base'

    def __init__(self, *args, **kwargs) -> None:
        self._filename = kwargs.get('filename', None)
        self._lineno = kwargs.get('lineno', None)
        self._args = [i.strip() for i in args]

    def __call__(self,  *args, **kwargs) -> bool:
        raise NotImplementedError

    def __str__(self):
        ret = [self._command_]
        ret.extend(self._args)
        return '{} # {}:{}'.format(' '.join(ret), self._filename, self._lineno)

    def __hash__(self) -> int:
        ret = [self._command_]
        if self._args:
            ret.append(self._args[0])
        return hash(' '.join(ret))

    def __eq__(self, __o: object) -> bool:
        return hash(self) == hash(__o)


class PreCheck(Command):
    _command_ = 'pre_check'


class SSLOptionTest(Command):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._prechecks = kwargs.get('prechecks', [])

    def __call__(self, srv_port=None, pxy_port=None):
        for i in self._prechecks:
            i(self)
        return self

    def __str__(self):
        ret = [str(i) for i in self._prechecks] + [super().__str__()]
        return '\n'.join(ret)


# Map of command and class
CMD_CLASS_MAP = {}

# decrators
def class_factory(name, methods={}, attributes={}, BaseClass=PreCheck):
    for k, v in methods.items():
        def func(self, *args, **kwargs):
            return v(self, *args, **kwargs)
        attributes.update({k: func})
    newclass = type(name_to_class_case(name), (BaseClass,), attributes)
    return newclass


def command(cls):
    assert type(cls) is type
    snakecase_name = name_to_function_case(cls.__name__)
    setattr(cls, '_command_', snakecase_name)
    CMD_CLASS_MAP[snakecase_name] = cls
    return cls


def pre_check(func=None):
    def __call__(self, option):
        return func(*self._args, option=option, filename=self._filename, lineno=self._lineno)
    cls = type(name_to_class_case(func.__name__), (PreCheck,),
               {'__call__': __call__, '_command_': func.__name__})
    return command(cls)


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(
                Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class MbedTLSBuildConfig(metaclass=Singleton):
    P_QUERY = os.path.join(MBEDTLS_BINARY_ROOT,
                           'programs/test/query_compile_time_config')
    CONFIG_H = os.path.join(MBEDTLS_SOURCE_ROOT,
                            'include/mbedtls/mbedtls_config.h')

    def __init__(self) -> None:
        self.__config_values = None

    def list_configs(self):
        if self.__config_values:
            return self.__config_values

        if os.path.exists(self.P_QUERY):
            self.__config_values = {}
            for line in check_output([self.P_QUERY, '-l'],
                                     universal_newlines=True).splitlines(keepends=False):
                line = line.split('=')
                if len(line) == 1:
                    self.__config_values[line[0]] = ''
                elif len(line) == 2:
                    self.__config_values[line[0]] = line[1]
                else:
                    raise Exception('Unexpect')
        elif os.path.exists(self.CONFIG_H):
            self.__config_values = {}
            with open(self.CONFIG_H) as f:
                regex = re.compile(
                    r'^\s*?#\s*?define\s+(?P<name>MBEDTLS_\w+)\s+(?P<value>.*)$')
                for line in f:
                    m = regex.match(line)
                    if not m:
                        continue
                    self.__config_values[m['name']] = m['value']
        return self.__config_values


# CONFIGS=set(subprocess.check_output([P_QUERY,'-l']).decode().split())
# CONFIGS_ENABLED={ i.split('=')[0] for i in CONFIGS}
# CONFIG_VALUES=dict([tuple(i.split('=')) for i in CONFIGS if len(i.split('='))==2])

@pre_check
def requires_config_disabled(*args, filename=None, lineno=None, **kwargs):
    configs = set(MbedTLSBuildConfig().list_configs().keys())
    return ['{filename}:{lineno} {i}'.format(filename=filename, lineno=lineno, i=i)
            for i in set(args) & configs]


@pre_check
def requires_config_enabled(*args, filename=None, lineno=None, **kwargs):
    configs = set(MbedTLSBuildConfig().list_configs().keys())
    return ['{filename}:{lineno} {i}'.format(filename=filename, lineno=lineno, i=i)
            for i in set(args) - configs]


@pre_check
def requires_max_content_len(value, option=None, filename=None, lineno=None):
    # raise NotImplementedError
    ret = []
    configs = MbedTLSBuildConfig().list_configs()
    for i in ('MBEDTLS_SSL_IN_CONTENT_LEN', 'MBEDTLS_SSL_OUT_CONTENT_LEN'):
        if int(configs[i]) < int(value):
            ret.append('{filename}:{lineno} {i}({v}) < {value}'.format(
                filename=None, lineno=None, i=i, v=configs[i], value=value))
    return ret


@pre_check
def requires_config_value_at_least(*args, **kwargs):
    raise NotImplementedError


@pre_check
def requires_config_value_at_most(*args, **kwargs):
    raise NotImplementedError


@pre_check
def not_with_valgrind(*args, **kwargs):
    raise NotImplementedError


@pre_check
def only_with_valgrind(*args, **kwargs):
    raise NotImplementedError


@pre_check
def requires_full_size_output_buffer(*args, **kwargs):
    raise NotImplementedError


@pre_check
def requires_gnutls(*args, **kwargs):
    raise NotImplementedError


@pre_check
def requires_gnutls_next(*args, **kwargs):
    raise NotImplementedError


@pre_check
def requires_gnutls_next_disable_tls13_compat(*args, **kwargs):
    raise NotImplementedError


@pre_check
def requires_gnutls_next_no_ticket(*args, **kwargs):
    raise NotImplementedError


@pre_check
def requires_gnutls_tls1_3(*args, **kwargs):
    raise NotImplementedError


@pre_check
def requires_ipv6(*args, **kwargs):
    raise NotImplementedError


@pre_check
def requires_not_i686(*args, **kwargs):
    raise NotImplementedError


@pre_check
def requires_openssl_next(*args, **kwargs):
    raise NotImplementedError


@pre_check
def requires_openssl_tls1_3(*args, **kwargs):
    raise NotImplementedError


@pre_check
def skip_handshake_stage_check(*args, **kwargs):
    raise NotImplementedError


@pre_check
def skip_next_test(*args, **kwargs):
    raise NotImplementedError


@pre_check
def client_needs_more_time(*args, **kwargs):
    raise NotImplementedError


@pre_check
def server_needs_more_time(*args, **kwargs):
    raise NotImplementedError


@pre_check
def requires_config_value_equals(*args, **kwargs):
    raise NotImplementedError


@command
class RunTest(SSLOptionTest):
    pass


class OptionTestCreateState:
    def __init__(self) -> None:
        self._commands = []

    def commands(self):
        return self._commands

    def __call__(self, cmd, *args, filename=None, lineno=None):
        cmd_class = CMD_CLASS_MAP.get(cmd, None)
        if not cmd_class:
            raise CommandNotImplementedError(cmd)
        if issubclass(cmd_class, PreCheck):
            self._commands.append(
                cmd_class(*args, filename=filename, lineno=lineno))
            return
        elif issubclass(cmd_class, SSLOptionTest):
            test = cmd_class(*args, filename=filename,
                             lineno=lineno, prechecks=self._commands)
            self._commands = []
            return test
        else:
            raise Exception('Unexpect')
