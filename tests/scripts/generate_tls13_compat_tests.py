#!/usr/bin/env python3

# generate_tls13_compat_tests.py
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
Generate TLSv1.3 Compat test cases

"""

import sys
import abc
import argparse

# pylint: disable=useless-super-delegation

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
    'rsa_pss_rsae_sha256': (
        'data_files/server2-sha256.crt', 'data_files/server2.key'
    )
}

CAFILE = {
    'ecdsa_secp256r1_sha256': 'data_files/test-ca2.crt',
    'ecdsa_secp384r1_sha384': 'data_files/test-ca2.crt',
    'ecdsa_secp521r1_sha512': 'data_files/test-ca2.crt',
    'rsa_pss_rsae_sha256': 'data_files/test-ca_cat12.crt'
}

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
    'rsa_pss_rsae_sha256': 0x0804,
}

NAMED_GROUP_IANA_VALUE = {
    'secp256r1': 0x17,
    'secp384r1': 0x18,
    'secp521r1': 0x19,
    'x25519': 0x1d,
    'x448': 0x1e,
}


def remove_duplicates(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]


class TLSProgram(metaclass=abc.ABCMeta):
    """
    Base class for generate server/client command.
    """

    def __init__(self, ciphersuite, signature_algorithm, named_group):
        self._cipher = ciphersuite
        self._sig_alg = signature_algorithm
        self._named_group = named_group
        self.add_ciphersuites(ciphersuite)
        self.add_named_groups(named_group)
        self.add_signature_algorithms(signature_algorithm)

    @abc.abstractmethod
    def add_ciphersuites(self, *ciphersuites):
        pass

    @abc.abstractmethod
    def add_signature_algorithms(self, *signature_algorithms):
        pass

    @abc.abstractmethod
    def add_named_groups(self, *named_groups):
        pass

    @abc.abstractmethod
    def pre_checks(self):
        return []

    @abc.abstractmethod
    def cmd(self):
        pass

    @abc.abstractmethod
    def post_checks(self):
        return []


class OpenSSLServ(TLSProgram):
    """
    Generate test commands for OpenSSL server.
    """
    program = '$OPENSSL_NEXT'

    def __init__(
            self,
            ciphersuite,
            signature_algorithm,
            named_group):
        self.ciphersuites = []
        self.named_groups = []
        self.signature_algorithms = []
        self.certificates = []
        super().__init__(ciphersuite, signature_algorithm, named_group)

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

    def cmd(self):
        ret = ['$O_NEXT_SRV_NO_CERT']
        for cert, key in self.certificates:
            ret += ['-cert {cert} -key {key}'.format(cert=cert, key=key)]
        ret += ['-accept $SRV_PORT']
        ciphersuites = ','.join(self.ciphersuites)
        signature_algorithms = ','.join(self.signature_algorithms)
        named_groups = ','.join(self.named_groups)
        ret += ["-ciphersuites {ciphersuites}".format(ciphersuites=ciphersuites),
                "-sigalgs {signature_algorithms}".format(
                    signature_algorithms=signature_algorithms),
                "-groups {named_groups}".format(named_groups=named_groups)]
        ret += ['-msg -tls1_3 -no_middlebox -num_tickets 0 -no_resume_ephemeral -no_cache']
        return ' '.join(ret)

    def pre_checks(self):
        return ["requires_openssl_tls1_3"]

    def post_checks(self):
        return ['-c "HTTP/1.0 200 ok"']


class GnuTLSServ(TLSProgram):
    """
    Generate test commands for GnuTLS server.
    """

    def __init__(self, ciphersuite, signature_algorithm, named_group):
        self.priority_strings = []
        self.certificates = []
        super().__init__(ciphersuite, signature_algorithm, named_group)

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
        for ciphersuite in ciphersuites:
            self.priority_strings.extend(self.CIPHER_SUITE[ciphersuite])

    SIGNATURE_ALGORITHM = {
        'ecdsa_secp256r1_sha256': ['SIGN-ECDSA-SECP256R1-SHA256'],
        'ecdsa_secp521r1_sha512': ['SIGN-ECDSA-SECP521R1-SHA512'],
        'ecdsa_secp384r1_sha384': ['SIGN-ECDSA-SECP384R1-SHA384'],
        'rsa_pss_rsae_sha256': ['SIGN-RSA-PSS-RSAE-SHA256']}

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

    def pre_checks(self):
        return ["requires_gnutls_tls1_3",
                "requires_gnutls_next_no_ticket",
                "requires_gnutls_next_disable_tls13_compat", ]

    def post_checks(self):
        return ['-c "HTTP/1.0 200 OK"']

    def cmd(self):
        ret = [
            '$G_NEXT_SRV_NO_CERT',
            '--http',
            '--disable-client-cert',
            '--debug=4']
        for cert, key in self.certificates:
            ret += ['--x509certfile {cert} --x509keyfile {key}'.format(
                cert=cert, key=key)]
        priority_strings = ':+'.join(['NONE'] +
                                     list(set(self.priority_strings)) +
                                     ['VERS-TLS1.3'])
        priority_strings += ':%NO_TICKETS:%DISABLE_TLS13_COMPAT_MODE'
        ret += ['--priority={priority_strings}'.format(
            priority_strings=priority_strings)]
        ret = ' '.join(ret)
        return ret


class MbedTLSCli(TLSProgram):
    """
    Generate test commands for mbedTLS client.
    """

    def __init__(self, ciphersuite, signature_algorithm, named_group):
        self.ciphersuites = []
        self.certificates = []
        self.signature_algorithms = []
        self.named_groups = []
        self.needed_named_groups = []
        super().__init__(ciphersuite, signature_algorithm, named_group)

    CIPHER_SUITE = {
        'TLS_AES_256_GCM_SHA384': 'TLS1-3-AES-256-GCM-SHA384',
        'TLS_AES_128_GCM_SHA256': 'TLS1-3-AES-128-GCM-SHA256',
        'TLS_CHACHA20_POLY1305_SHA256': 'TLS1-3-CHACHA20-POLY1305-SHA256',
        'TLS_AES_128_CCM_SHA256': 'TLS1-3-AES-128-CCM-SHA256',
        'TLS_AES_128_CCM_8_SHA256': 'TLS1-3-AES-128-CCM-8-SHA256'}

    def add_ciphersuites(self, *ciphersuites):
        for ciphersuite in ciphersuites:
            self.ciphersuites.append(self.CIPHER_SUITE[ciphersuite])

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

    def pre_checks(self):

        ret = ['requires_config_enabled MBEDTLS_DEBUG_C',
               'requires_config_enabled MBEDTLS_SSL_CLI_C',
               'requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL',
               'requires_config_disabled MBEDTLS_USE_PSA_CRYPTO']
        if 'rsa_pss_rsae_sha256' in self.signature_algorithms:
            ret.append(
                'requires_config_enabled MBEDTLS_X509_RSASSA_PSS_SUPPORT')
        return ret

    def post_checks(self):

        check_strings = ["ECDH curve: {group}".format(group=self._named_group),
                         "server hello, chosen ciphersuite: ( {:04x} ) - {}".format(
                             CIPHER_SUITE_IANA_VALUE[self._cipher],
                             self.CIPHER_SUITE[self._cipher]),
                         "Certificate Verify: Signature algorithm ( {:04x} )".format(
                             SIG_ALG_IANA_VALUE[self._sig_alg]),
                         "Verifying peer X.509 certificate... ok", ]
        return ['-c "{}"'.format(i) for i in check_strings]

    def cmd(self):
        ret = ['$P_CLI']
        ret += [
            'server_addr=127.0.0.1 server_port=$SRV_PORT',
            'debug_level=4 force_version=tls1_3']
        ret += ['ca_file={CAFILE}'.format(CAFILE=CAFILE[self._sig_alg])]
        self.ciphersuites = list(set(self.ciphersuites))
        cipher = ','.join(self.ciphersuites)
        if cipher:
            ret += ["force_ciphersuite={cipher}".format(cipher=cipher)]
        self.named_groups = remove_duplicates(
            self.named_groups + self.needed_named_groups)
        group = ','.join(self.named_groups)
        if group:
            ret += ["curves={group}".format(group=group)]
        sig_alg = ','.join(self.signature_algorithms)
        ret += ['sig_algs={sig_alg}'.format(sig_alg=sig_alg)]
        ret = ' '.join(ret)
        return ret


SERVER_CLS = {'OpenSSL': OpenSSLServ, 'GnuTLS': GnuTLSServ}
CLIENT_CLS = {'mbedTLS': MbedTLSCli}


def generate_compat_test(server=None, client=None, cipher=None,  # pylint: disable=unused-argument
                         sig_alg=None, named_group=None, **kwargs):
    """
    Generate test case with `ssl-opt.sh` format.
    """
    name = 'TLS1.3 {client[0]}->{server[0]}: {cipher},{named_group},{sig_alg}'.format(
        client=client, server=server, cipher=cipher, sig_alg=sig_alg, named_group=named_group)
    server = SERVER_CLS[server](cipher, sig_alg, named_group)
    client = CLIENT_CLS[client](cipher, sig_alg, named_group)

    cmd = ['run_test "{}"'.format(name), '"{}"'.format(
        server.cmd()), '"{}"'.format(client.cmd()), '0']
    cmd += server.post_checks()
    cmd += client.post_checks()
    prefix = ' \\\n' + (' '*12)
    cmd = prefix.join(cmd)
    print('\n'.join(server.pre_checks() + client.pre_checks() + [cmd]))
    return 0


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('--list-ciphers', action='store_true',
                        default=False, help='List supported ciphersuites')

    parser.add_argument('--list-sig-algs', action='store_true',
                        default=False, help='List supported signature algorithms')

    parser.add_argument('--list-named-groups', action='store_true',
                        default=False, help='List supported named groups')

    parser.add_argument('--list-servers', action='store_true',
                        default=False, help='List supported TLS servers')

    parser.add_argument('--list-clients', action='store_true',
                        default=False, help='List supported TLS Clients')

    parser.add_argument('server', choices=SERVER_CLS.keys(), nargs='?',
                        default=list(SERVER_CLS.keys())[0],
                        help='Choose TLS server program for test')
    parser.add_argument('client', choices=CLIENT_CLS.keys(), nargs='?',
                        default=list(CLIENT_CLS.keys())[0],
                        help='Choose TLS client program for test')
    parser.add_argument('cipher', choices=CIPHER_SUITE_IANA_VALUE.keys(), nargs='?',
                        default=list(CIPHER_SUITE_IANA_VALUE.keys())[0],
                        help='Choose cipher suite for test')
    parser.add_argument('sig_alg', choices=SIG_ALG_IANA_VALUE.keys(), nargs='?',
                        default=list(SIG_ALG_IANA_VALUE.keys())[0],
                        help='Choose cipher suite for test')
    parser.add_argument('named_group', choices=NAMED_GROUP_IANA_VALUE.keys(), nargs='?',
                        default=list(NAMED_GROUP_IANA_VALUE.keys())[0],
                        help='Choose cipher suite for test')

    args = parser.parse_args()
    if args.list_ciphers or args.list_sig_algs or args.list_named_groups \
            or args.list_servers or args.list_clients:
        if args.list_ciphers:
            print(*CIPHER_SUITE_IANA_VALUE.keys())
        if args.list_sig_algs:
            print(*SIG_ALG_IANA_VALUE.keys())
        if args.list_named_groups:
            print(*NAMED_GROUP_IANA_VALUE.keys())
        if args.list_servers:
            print(*SERVER_CLS.keys())
        if args.list_clients:
            print(*CLIENT_CLS.keys())
        return 0
    return generate_compat_test(**vars(args))


if __name__ == "__main__":
    sys.exit(main())
