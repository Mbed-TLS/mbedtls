#!/usr/bin/env python3
# pylint: skip-file

# compat-tls13.py
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
TLS1_3 Compat test cases

"""

import sys
import os
import socket
from contextlib import closing
import atexit
import abc
import time
import itertools
import threading
from multiprocessing.pool import ThreadPool as Pool
from subprocess import Popen, TimeoutExpired, check_output
import psutil


@atexit.register
def cleanup():
    for child in psutil.Process().children(recursive=True):
        child.terminate()

thread_local = threading.local()
# pylint: disable-next=too-few-public-methods
class FreePort:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.used_ports = set()

    @staticmethod
    def _get_free_port():
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            # pylint: disable=no-member
            s.bind(('', 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]

    def __call__(self):
        # free_port = self._get_free_port()
        # return free_port
        if not hasattr(thread_local, 'local_ports'):
            thread_local.local_ports = set()

        free_ports = thread_local.local_ports - \
            {conn.laddr.port for conn in psutil.net_connections()}

        if free_ports:
            return list(free_ports)[0]

        with self.lock:
            free_port = self._get_free_port()
            other_ports = self.used_ports - thread_local.local_ports
            while free_port in other_ports:
                free_port = self._get_free_port()
            thread_local.local_ports |= {free_port}
            self.used_ports |= {free_port}
            return free_port

get_free_port=FreePort()

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..'))


CERTIFICATES = {
    'ecdsa_secp256r1_sha256': (
        'data_files/ecdsa_secp256r1_sha256.crt',
        'data_files/ecdsa_secp256r1_sha256.key'),
    'ecdsa_secp384r1_sha384': (
        'data_files/ecdsa_secp384r1_sha384.crt',
        'data_files/ecdsa_secp384r1_sha384.key'),
    'ecdsa_secp521r1_sha512': (
        'data_files/ecdsa_secp521r1_sha512.crt',
        'data_files/ecdsa_secp521r1_sha512.key'),
}

CAFILE = 'data_files/test-ca2.crt'


def run_program(srv_cmd, outf, shell=True):
    return Popen(srv_cmd, stdout=outf, stderr=outf, shell=shell)


def list_subprocess(pid):
    process = psutil.Process(pid)
    for p in process.children(recursive=True):
        yield p
    yield process


def is_port_available(port):
    for conn in psutil.net_connections():
        if conn.laddr.port == port:
            return False
    return True


def terminate_process(proc):
    done_flag = False

    pid = proc.pid

    def kill(proc_pid):
        process = psutil.Process(proc_pid)
        for proc in process.children(recursive=True):
            proc.kill()
        process.kill()
    kill(pid)

    p = psutil.Process(pid)
    while done_flag is False:
        try:
            p.status()
            p.wait(timeout=10)
            done_flag = True
        except psutil.NoSuchProcess:
            done_flag = True
        except TimeoutExpired:
            kill(pid)


def remove_duplicates(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]



class TLSProgram(metaclass=abc.ABCMeta):
    # pylint: disable-next=dangerous-default-value
    def __init__(self, ciphersuites=[],
                 signature_algorithms=[],
                 named_groups=[]):
        self.add_ciphersuites(*ciphersuites)
        self.add_named_groups(*named_groups)
        self.add_signature_algorithms(*signature_algorithms)
        if not hasattr(self, 'is_server'):
            self.is_server = False

    @staticmethod
    def port_is_used_by_proc(pid, port):
        for p in list_subprocess(pid):
            ports = [conn.laddr.port for conn in p.connections()]
            if port in ports:
                return True
        return False

    @staticmethod
    def wait_srv_listen_on_port(srv_proc, srv_port, timeout=None):
        start_time = time.time() + timeout if timeout else 0
        while True:
            try:
                srv_proc.wait(0.1)
                return
            except TimeoutExpired:
                pass
            ports = []
            for p in list_subprocess(srv_proc.pid):
                ports.extend([conn.laddr.port for conn in p.connections()])
            if srv_port in ports:
                return
            if timeout and time.time() - start_time > timeout:
                raise ServStartFail(f'Expected listen port({srv_port})'
                                    + f' not in server listen ports({ports})')

    def run(self, port, host='localhost', outf=None, timeout=None):
        proc = run_program(self.cmd(port=port, host=host), outf)
        if self.is_server:
            self.wait_srv_listen_on_port(proc, port, timeout=timeout)
            return proc, proc.poll()
        try:
            ret = proc.wait(timeout=timeout)
        except TimeoutExpired as e:
            terminate_process(proc)
            raise CliNotFinished('After 60 seconds') from e
        return proc, ret

    @abc.abstractmethod
    def cmd(self, port=None, host='localhost'):
        pass

    @abc.abstractmethod
    def add_ciphersuites(self, *ciphersuites):
        pass

    @abc.abstractmethod
    def add_signature_algorithms(self, *signature_algorithms):
        pass

    @abc.abstractmethod
    def add_named_groups(self, *named_groups):
        pass


class OpenSSLServ(TLSProgram):
    program = os.getenv('OPENSSL_NEXT', 'openssl')

    # pylint: disable-next=dangerous-default-value
    def __init__(
            self,
            ciphersuites=[],
            signature_algorithms=[],
            named_groups=[]):
        self.ciphersuites = []
        self.named_groups = []
        self.signature_algorithms = []
        self.certificates = []
        self.is_server = True
        super().__init__(
            ciphersuites=ciphersuites,
            signature_algorithms=signature_algorithms,
            named_groups=named_groups)

    CIPHER_SUITE = {
        'TLS_AES_256_GCM_SHA384': [
            'AES-256-GCM',
            'SHA384',
            'AEAD'],
        'TLS_AES_128_GCM_SHA256': [
            'AES-128-GCM',
            'SHA256',
            'AEAD'],
        'TLS_CHACHA20_POLY1305_SHA256': [
            'CHACHA20-POLY1305',
            'SHA256',
            'AEAD'],
        'TLS_AES_128_CCM_SHA256': [
            'AES-128-CCM',
            'SHA256',
            'AEAD'],
        'TLS_AES_128_CCM_8_SHA256': [
            'AES-128-CCM-8',
            'SHA256',
            'AEAD']}

    def add_ciphersuites(self, *ciphersuites):
        self.ciphersuites.extend(ciphersuites)

    def add_signature_algorithms(self, *signature_algorithms):
        self.signature_algorithms.extend(signature_algorithms)
        for sig_alg in signature_algorithms:
            self.certificates.append(CERTIFICATES[sig_alg])

    NAMED_GROUP = {
        'secp256r1': 'P-256',
        'secp384r1': 'P-384',
        'secp521r1': 'P-521',
        'x25519': 'X25519',
        'x448': 'X448',
    }

    def add_named_groups(self, *named_groups):
        for named_group in named_groups:
            self.named_groups.append(self.NAMED_GROUP[named_group])

    def cmd(self, port=None, host='localhost'):
        ret = [self.program, 's_server', '-www']
        for cert, key in self.certificates:
            ret += [f'-cert {cert} -key {key}']
        ret += [f'-accept {port}']
        ciphersuites = ','.join(self.ciphersuites)
        signature_algorithms = ','.join(self.signature_algorithms)
        named_groups = ','.join(self.named_groups)
        ret += [f"-ciphersuites {ciphersuites} ",
                f"-sigalgs {signature_algorithms}",
                f"-groups {named_groups}"]
        ret += ['-msg -tls1_3 -no_middlebox -num_tickets 0 -no_resume_ephemeral -no_cache']
        return ' '.join(ret)

    def dump_precheck(self):
        return ["requires_openssl_tls1_3" ]

    def dump(self):
        ret = ['$OPENSSL_NEXT', 's_server', '-www']
        for cert, key in self.certificates:
            ret += [f'-cert {cert} -key {key}']
        ret += [f'-accept $SRV_PORT']
        ciphersuites = ','.join(self.ciphersuites)
        signature_algorithms = ','.join(self.signature_algorithms)
        named_groups = ','.join(self.named_groups)
        ret += [f"-ciphersuites {ciphersuites} ",
                f"-sigalgs {signature_algorithms}",
                f"-groups {named_groups}"]
        ret += ['-msg -tls1_3 -no_middlebox -num_tickets 0 -no_resume_ephemeral -no_cache']
        ret = ' '.join(ret)
        return f'"{ret}"'

class OpenSSLCli(OpenSSLServ):
    # pylint: disable-next=dangerous-default-value
    def __init__(
            self,
            ciphersuites=[],
            signature_algorithms=[],
            named_groups=[]):
        super().__init__(
            ciphersuites=ciphersuites,
            signature_algorithms=signature_algorithms,
            named_groups=named_groups)
        self.is_server = False

    def cmd(self, port=None, host='localhost'):
        ret = [
            r"echo 'GET / HTTP/1.0\n' |",
            f"{self.program} s_client",
            f"-connect {host}:{port}"]

        ciphersuites = ','.join(self.ciphersuites)
        signature_algorithms = ','.join(self.signature_algorithms)
        named_groups = ','.join(self.named_groups)
        ret += [f"-ciphersuites {ciphersuites} ",
                f"-sigalgs {signature_algorithms}",
                f"-groups {named_groups}"]
        ret += ['-msg -tls1_3 -no_middlebox ']
        return ' '.join(ret)


class GnuTLSServ(TLSProgram):
    program = os.getenv('GNUTLS_NEXT_SERV', 'gnutls-serv')

    def __init__(  # pylint: disable=dangerous-default-value
            self,
            ciphersuites=[],
            signature_algorithms=[],
            named_groups=[]):
        self.priority_strings = []
        self.certificates = []
        self.is_server = True
        super().__init__(
            ciphersuites=ciphersuites,
            signature_algorithms=signature_algorithms,
            named_groups=named_groups)

    CIPHER_SUITE = {
        'TLS_AES_256_GCM_SHA384': [
            'AES-256-GCM',
            'SHA384',
            'AEAD'],
        'TLS_AES_128_GCM_SHA256': [
            'AES-128-GCM',
            'SHA256',
            'AEAD'],
        'TLS_CHACHA20_POLY1305_SHA256': [
            'CHACHA20-POLY1305',
            'SHA256',
            'AEAD'],
        'TLS_AES_128_CCM_SHA256': [
            'AES-128-CCM',
            'SHA256',
            'AEAD'],
        'TLS_AES_128_CCM_8_SHA256': [
            'AES-128-CCM-8',
            'SHA256',
            'AEAD']}

    def add_ciphersuites(self, *ciphersuites):
        for cihpersuite in ciphersuites:
            self.priority_strings.extend(self.CIPHER_SUITE[cihpersuite])

    SIGNATURE_ALGORITHM = {
        'ecdsa_secp256r1_sha256': ['SIGN-ECDSA-SECP256R1-SHA256'],
        'ecdsa_secp521r1_sha512': ['SIGN-ECDSA-SECP521R1-SHA512'],
        'ecdsa_secp384r1_sha384': ['SIGN-ECDSA-SECP384R1-SHA384']}

    def add_signature_algorithms(self, *signature_algorithms):
        for sig_alg in signature_algorithms:
            self.priority_strings.extend(self.SIGNATURE_ALGORITHM[sig_alg])
            self.certificates.append(CERTIFICATES[sig_alg])

    NAMED_GROUP = {
        'secp256r1': ['GROUP-SECP256R1'],
        'secp384r1': ['GROUP-SECP384R1'],
        'secp521r1': ['GROUP-SECP521R1'],
        'x25519': ['GROUP-X25519'],
        'x448': ['GROUP-X448'],
    }

    def add_named_groups(self, *named_groups):
        for named_group in named_groups:
            self.priority_strings.extend(self.NAMED_GROUP[named_group])

    def cmd(self, port=None, host='localhost'):
        ret = [
            self.program,
            f'-p {port}',
            '--http',
            '--disable-client-cert',
            '--debug=4']
        for cert, key in self.certificates:
            ret += [f'--x509certfile {cert} --x509keyfile {key}']
        priority_strings = ':+'.join(['NONE'] +
                                     list(set(self.priority_strings)) +
                                     ['VERS-TLS1.3'])
        priority_strings += ':%NO_TICKETS:%DISABLE_TLS13_COMPAT_MODE'
        ret += [f'--priority={priority_strings}']
        return ' '.join(ret)

    def dump_precheck(self):
        return ["requires_gnutls_tls1_3",
                "requires_gnutls_next_no_ticket",
                "requires_gnutls_next_disable_tls13_compat",]
    def dump(self):
        ret = [
            '$GNUTLS_NEXT_SERV',
            '-p $SRV_PORT',
            '--http',
            '--disable-client-cert',
            '--debug=4']
        for cert, key in self.certificates:
            ret += [f'--x509certfile {cert} --x509keyfile {key}']
        priority_strings = ':+'.join(['NONE'] +
                                     list(set(self.priority_strings)) +
                                     ['VERS-TLS1.3'])
        priority_strings += ':%NO_TICKETS:%DISABLE_TLS13_COMPAT_MODE'
        ret += [f'--priority={priority_strings}']
        ret = ' '.join(ret)
        return f'"{ret}"'


class GnuTLSCli(GnuTLSServ):
    program = os.getenv('GNUTLS_NEXT_CLI', 'gnutls-cli')

    # pylint: disable-next=dangerous-default-value
    def __init__(
            self,
            ciphersuites=[],
            signature_algorithms=[],
            named_groups=[]):
        super().__init__(
            ciphersuites=ciphersuites,
            signature_algorithms=signature_algorithms,
            named_groups=named_groups)
        self.is_server = False

    def cmd(self, port=None, host='localhost'):
        ret = [
            r"echo 'GET / HTTP/1.0\n' |",
            f"{self.program} -p {port} --x509cafile {CAFILE} --debug=4"]
        priority_strings = ':+'.join(['NONE'] +
                                     list(set(self.priority_strings)) +
                                     ['VERS-TLS1.3'])
        priority_strings += ':%NO_TICKETS:%DISABLE_TLS13_COMPAT_MODE'
        ret += [f'--priority={priority_strings}']
        ret += [f'{host}']
        return ' '.join(ret)


class MbedTLSCli(TLSProgram):
    program = os.getenv('M_CLI', '../programs/ssl/ssl_client2')

    def __init__(  # pylint: disable=dangerous-default-value
            self,
            ciphersuites=[],
            signature_algorithms=[],
            named_groups=[]):
        self.ciphersuites = []
        self.certificates = []
        self.signature_algorithms = []
        self.named_groups = []
        self.needed_named_groups = []
        super().__init__(
            ciphersuites=ciphersuites,
            signature_algorithms=signature_algorithms,
            named_groups=named_groups)

    CIPHER_SUITE = {
        'TLS_AES_256_GCM_SHA384': 'TLS1-3-AES-256-GCM-SHA384',
        'TLS_AES_128_GCM_SHA256': 'TLS1-3-AES-128-GCM-SHA256',
        'TLS_CHACHA20_POLY1305_SHA256': 'TLS1-3-CHACHA20-POLY1305-SHA256',
        'TLS_AES_128_CCM_SHA256': 'TLS1-3-AES-128-CCM-SHA256',
        'TLS_AES_128_CCM_8_SHA256': 'TLS1-3-AES-128-CCM-8-SHA256'}

    def add_ciphersuites(self, *ciphersuites):
        for cihpersuite in ciphersuites:
            self.ciphersuites.append(self.CIPHER_SUITE[cihpersuite])

    def add_signature_algorithms(self, *signature_algorithms):
        for sig_alg in signature_algorithms:
            self.signature_algorithms.append(sig_alg)
            if sig_alg == 'ecdsa_secp256r1_sha256':
                self.needed_named_groups.append('secp256r1')
            elif sig_alg == 'ecdsa_secp521r1_sha512':
                self.needed_named_groups.append('secp521r1')
            elif sig_alg == 'ecdsa_secp384r1_sha384':
                self.needed_named_groups.append('secp384r1')

            self.certificates.append(CERTIFICATES[sig_alg])

    def add_named_groups(self, *named_groups):
        for named_group in named_groups:
            self.named_groups.append(named_group)

    def cmd(self, port=None, host='localhost'):
        ret = [self.program]
        ret += [
            f'server_addr=127.0.0.1 server_port={port}',
            'debug_level=4 force_version=tls1_3']
        ret += [f'ca_file={CAFILE}']
        self.ciphersuites = list(set(self.ciphersuites))
        cipher = ','.join(self.ciphersuites)
        if cipher:
            ret += [f"force_ciphersuite={cipher}"]
        self.named_groups = remove_duplicates(
            self.named_groups + self.needed_named_groups)
        group = ','.join(self.named_groups)
        if group:
            ret += [f"curves={group}"]
        sig_alg = ','.join(self.signature_algorithms)
        ret += [f'sig_algs={sig_alg}']
        return ' '.join(ret)

    def dump(self):
        ret = ['$P_CLI']
        ret += [
            'server_addr=127.0.0.1 server_port=$SRV_PORT',
            'debug_level=4 force_version=tls1_3']
        ret += [f'ca_file={CAFILE}']
        self.ciphersuites = list(set(self.ciphersuites))
        cipher = ','.join(self.ciphersuites)
        if cipher:
            ret += [f"force_ciphersuite={cipher}"]
        self.named_groups = remove_duplicates(
            self.named_groups + self.needed_named_groups)
        group = ','.join(self.named_groups)
        if group:
            ret += [f"curves={group}"]
        sig_alg = ','.join(self.signature_algorithms)
        ret += [f'sig_algs={sig_alg}']
        ret = ' '.join(ret)
        return f'"{ret}"'

class ConfigCheck:
    CONFIGS_ENABLED = set(check_output(
        r" cat ../include/mbedtls/mbedtls_config.h |"
        r"sed -n 's!^ *#define  *\([A-Za-z][0-9A-Z_a-z]*\) *\(/*\)*!\1!p' |"
        r"tr '\n' ' '", shell=True).decode().split())
    def __init__(self, *configs):
        self._configs=configs
    def dump(self):
        return [f'{self._prefix} {config}' for config in self._configs]
class ConfigEnableCheck(ConfigCheck):
    _prefix='requires_config_enabled'
    def __call__(self, *args, **kwargs) :
        return list(set(self._configs) - self.CONFIGS_ENABLED)
class ConfigDisableCheck(ConfigCheck):
    _prefix='requires_config_disabled'
    def __call__(self, *args, **kwargs) :
        configs = self._configs
        return list(set(configs) & self.CONFIGS_ENABLED)


requires_config_enabled = ConfigEnableCheck
requires_config_disabled = ConfigDisableCheck


class TestFail(Exception):
    pass


class ServStartFail(TestFail):
    pass


class CliNotFinished(TestFail):
    pass

# pylint: disable-next=too-few-public-methods
class ResultCheck(metaclass=abc.ABCMeta):

    # pylint: disable-next=unused-argument,too-many-arguments
    def __call__(self, exit_value: int,
                 exceptions: TestFail,
                 srv_out: os.PathLike,
                 cli_out: os.PathLike,
                 indent: str = '') -> list[str]:
        pass

# pylint: disable-next=too-few-public-methods
class ReturnValueCheck(ResultCheck):

    def __init__(self, expected_return: int = 0) -> None:
        self._expected_return = expected_return

    # pylint: disable-next=unused-argument,too-many-arguments
    def __call__(self, exit_value: int,
                 exceptions: TestFail,
                 srv_out: os.PathLike,
                 cli_out: os.PathLike,
                 indent: str = '') -> list[str]:
        ret = []
        if exit_value != self._expected_return:
            ret.append(f'{indent}bad client exit code (expected' +
                       f' {self._expected_return}, got {exit_value})')
        return ret
    def dump(self):
        return [ str(self._expected_return)]


class LinePattern:
    def __init__(self, *patterns, inverse=False) -> None:
        self._patterns = set(patterns)
        self._left_patterns = set(patterns)
        self._inverse = inverse

    def __call__(self, line) -> None:
        self._left_patterns = set(
            filter(lambda i: i not in line, self._left_patterns))

    def result(self, indent=''):
        if not self._inverse:
            result = list(self._left_patterns)
            inverse = ''
        else:
            result = list(self._patterns - self._left_patterns)
            inverse = 'NOT'
        return [f"{indent}pattern '{i}' MUST {inverse} be present in the Client output"
                for i in result]
    def dump(self,flag_true,flag_false):
        flag=flag_true if not self._inverse else flag_false
        return [f'{flag} "{i}"' for i in self._patterns]


class LogCheck(ResultCheck):

    # pylint: disable-next=dangerous-default-value
    def __init__(self, clients=[], servers=[]):
        self._clients = clients
        self._servers = servers

    @staticmethod
    def check(filename, check_patterns, indent=''):
        if not bool(check_patterns):
            return []
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                for line_checker in check_patterns:
                    line_checker(line)
        ret = []
        for line_checker in check_patterns:
            ret.extend(line_checker.result(indent=indent))
        return ret

    # pylint: disable-next=too-many-arguments
    def __call__(self, exit_value: int,
                 exceptions: TestFail,
                 srv_out: os.PathLike,
                 cli_out: os.PathLike,
                 indent: str = '  ! ') -> list[str]:
        return self.check(cli_out, self._clients, indent=indent) + \
            self.check(srv_out, self._servers, indent=indent)
    def dump(self):
        clients=[i for x in self._clients  for i in x.dump('-c','-C')]
        servers=[i for x in self._servers  for i in x.dump('-s','-S')]
        return clients + servers


class SSLOptionTest:
    # pylint: disable-next=too-many-arguments
    def __init__(self, name, srv, cli, pre_checks, post_checks):
        self._name = name
        self._srv_cls, self._srv_options = srv
        self._cli_cls, self._cli_options = cli
        self._pre_checks = pre_checks
        self._post_checks = post_checks
        self._srv = None
        self._cli = None

    @property
    def name(self):
        return self._name

    @property
    def serv(self):
        if self._srv is None:
            self._srv = self._srv_cls(**self._srv_options)
        return self._srv

    @property
    def cli(self):
        if self._cli is None:
            self._cli = self._cli_cls(**self._cli_options)
        return self._cli

    @property
    def pre_checks(self):
        return self._pre_checks

    @property
    def post_checks(self):
        return self._post_checks


CIPHER_SUITE_IANA_VALUE = {
    "TLS_AES_128_GCM_SHA256": 0x1301,
    "TLS_AES_256_GCM_SHA384": 0x1302,
    "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
    "TLS_AES_128_CCM_SHA256": 0x1304,
    "TLS_AES_128_CCM_8_SHA256": 0x1305
}

SIG_ALG_IANA_VALUE = {
    "ecdsa_secp256r1_sha256": 0x0403,
    "ecdsa_secp384r1_sha384": 0x0503,
    "ecdsa_secp521r1_sha512": 0x0603,
}


def generate_compat_test_cases():
    signature_algorithms = GnuTLSServ.SIGNATURE_ALGORITHM.keys()
    named_groups = GnuTLSServ.NAMED_GROUP.keys()
    ciphersuites = GnuTLSServ.CIPHER_SUITE.keys()
    servers = [OpenSSLServ, GnuTLSServ]
    clients = [MbedTLSCli]
    for i in itertools.product(
            ciphersuites,
            named_groups,
            signature_algorithms,
            servers,
            clients):
        cipher, group, sig_alg, srv_cls, cli_cls = i

        line_pattern = LinePattern(
            f"ECDH curve: {group}",
            "server hello, chosen ciphersuite: "
            + f"( {CIPHER_SUITE_IANA_VALUE[cipher]:04x} ) - {MbedTLSCli.CIPHER_SUITE[cipher]}",
            f"Certificate Verify: Signature algorithm ( {SIG_ALG_IANA_VALUE[sig_alg]:04x} )",
            "Verifying peer X.509 certificate... ok",
        )
        tests = dict(
            ciphersuites=[cipher],
            signature_algorithms=[sig_alg],
            named_groups=[group])
        name = f'TLS1.3 {cli_cls.__name__[0]}->{srv_cls.__name__[0]}: '
        name += ','.join([cipher[4:], group, sig_alg])
        yield SSLOptionTest(name,
                            (srv_cls, tests),
                            (cli_cls, tests),
                            [requires_config_enabled('MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL'),
                             requires_config_disabled('MBEDTLS_USE_PSA_CRYPTO') ],
                            [ReturnValueCheck(), LogCheck(clients=[line_pattern])])


def generate_test_cases():
    yield from generate_compat_test_cases()


def run_options_test(option_test, output):
    srv_f, cli_f = output
    srv_port = get_free_port()
    srv_f.write(
        f"#{option_test.name}\n{option_test.serv.cmd(srv_port)}\n".encode())
    srv_f.flush()
    cli_f.write(
        f"#{option_test.name}\n{option_test.cli.cmd(srv_port)}\n".encode())
    cli_f.flush()
    srv_proc, _ = option_test.serv.run(srv_port, outf=srv_f, timeout=10)
    try:
        _, status = option_test.cli.run(srv_port, outf=cli_f,timeout=60)
    finally:
        terminate_process(srv_proc)
    return status


def dump_as_ssl_opt():
    for a in generate_test_cases():
        print()
        ret=[ i for j in a.pre_checks for i in j.dump()] + a.serv.dump_precheck()
        print('\n'.join(ret))
        prefix=' '*12
        print(f' \\\n{prefix}'.join([f'run_test    "{a.name}"',a.serv.dump(), a.cli.dump()]
                                    + a.post_checks[0].dump()
                                    + a.post_checks[1].dump()))
    return 0

# pylint: disable-next=too-many-locals,unused-argument
def main(dump=False, preserve_logs=False, show_numbers=False,
         number=None, print_skip_reason=False, jobs=1,**kwargs):
    if dump:
        return dump_as_ssl_opt()

    def thread_body(a):
        no, option_test = a
        if number and not no in number:
            return no, option_test.name, 'SKIP', [f'Test {no} not in {number}']
        reason = []
        for func in option_test.pre_checks:
            reason.extend(func(option_test))
        if reason:
            return no, option_test.name, 'SKIP', reason
        exceptions = []
        srv_out, cli_out = f'o-srv-{no}.log', f'o-cli-{no}.log'
        with open(srv_out, 'wb') as srv_f, open(cli_out, 'wb') as cli_f:
            try:
                ret = run_options_test(option_test, (srv_f, cli_f))
            except TestFail as e:
                while e is not None:
                    exceptions.append(e)
                    e = e.__context__

        reason = []
        for func in option_test.post_checks:
            reason.extend(func(ret, exceptions, srv_out, cli_out))

        if not preserve_logs and not reason:
            os.remove(f'o-srv-{no}.log')
            os.remove(f'o-cli-{no}.log')
        return no, option_test.name, 'FAIL' if reason else 'PASS', reason

    pass_tests, fail_tests, skip_tests = [], [], []

    def output_result(no, name, result, reason):
        indent = '      ! ' if show_numbers else '  ! '
        report_str = f'{no:4} {name}' if show_numbers else f'{name}'

        print(report_str, '.' * (94 - len(report_str)), result)
        if result == 'PASS':
            pass_tests.append(report_str)
        elif result == 'FAIL':
            fail_tests.append(report_str)
            for r in reason:
                if isinstance(r, list):
                    print(f'\n{indent}'.join(r))
                else:
                    print(r)
        elif result == 'SKIP':
            skip_tests.append(report_str)
            if print_skip_reason:
                print(f'\n{indent}'.join(reason))
    def parallel_run():
        with Pool(processes=jobs) as pool:
            cur_no = 0
            pending_results = {}
            for no, name, result, reason in pool.imap_unordered(
                    thread_body, zip(range(2**32), generate_test_cases())):
                pending_results[no] = (name, result, reason)
                if no > cur_no:
                    continue
                while cur_no in pending_results:
                    output_result(cur_no, *pending_results[cur_no])
                    del pending_results[cur_no]
                    cur_no += 1
    def single_run():
        for a in zip(range(2**32), generate_test_cases()):
                output_result(* thread_body(a) )

    if jobs == 1:
        single_run()
    else:
        parallel_run()
    prefix_out_str = 'FAILED' if fail_tests else 'PASSED'
    print(f"{prefix_out_str} " +
          f"({len(pass_tests):4} / {len(pass_tests+fail_tests+skip_tests):4}" +
          f" tests ({len(skip_tests):4} skipped))")
    print(len(pass_tests), len(fail_tests), len(get_free_port.used_ports))
    return len(fail_tests)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()

    def list_str(s):
        return set({int(i) for i in s.split(',')})
    parser.add_argument('-p', '--preserve-logs', action=argparse.BooleanOptionalAction,
                        default=False, help='Preserve logs of successful tests as well')
    parser.add_argument('-s', '--show-numbers', action=argparse.BooleanOptionalAction,
                        default=False, help='Show test numbers in front of test names')
    parser.add_argument('-m', '--memcheck', action=argparse.BooleanOptionalAction,
                        default=False, help='Check memory leaks and errors')
    parser.add_argument('--print-skip-reason', action=argparse.BooleanOptionalAction,
                        default=False, help='Show the skip reason')
    parser.add_argument('-n', '--number', nargs='?', type=list_str, default={},
                        help="Execute only numbered test (comma-separated, e.g. '245,256')")
    parser.add_argument('-j','--jobs', nargs='?',default=4, type=int,
                         help='Run tests in parallel.')
    parser.add_argument('--dump', action=argparse.BooleanOptionalAction,
                        default=False, help='Dump as `ssl-opt.sh` like test command lines')
    args = parser.parse_args()
    sys.exit(main(**vars(args)))
