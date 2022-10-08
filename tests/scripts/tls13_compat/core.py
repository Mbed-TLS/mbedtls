# tls13_compat/core.py
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
Base classes and constants for generating TLSv1.3 Compat test cases

"""

from collections import namedtuple
from enum import IntEnum

# define certificates configuration entry
Certificate = namedtuple("Certificate", ['cafile', 'certfile', 'keyfile'])
# define the certificate parameters for signature algorithms
CERTIFICATES = {
    'ecdsa_secp256r1_sha256': Certificate('data_files/test-ca2.crt',
                                          'data_files/ecdsa_secp256r1.crt',
                                          'data_files/ecdsa_secp256r1.key'),
    'ecdsa_secp384r1_sha384': Certificate('data_files/test-ca2.crt',
                                          'data_files/ecdsa_secp384r1.crt',
                                          'data_files/ecdsa_secp384r1.key'),
    'ecdsa_secp521r1_sha512': Certificate('data_files/test-ca2.crt',
                                          'data_files/ecdsa_secp521r1.crt',
                                          'data_files/ecdsa_secp521r1.key'),
    'rsa_pss_rsae_sha256': Certificate('data_files/test-ca_cat12.crt',
                                       'data_files/server2-sha256.crt', 'data_files/server2.key'
                                       )
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


class KexMode(IntEnum):
    psk = 1
    ephemeral = 2
    psk_or_ephemeral = 3
    psk_ephemeral = 4
    psk_all = 5
    ephemeral_all = 6
    all = 7


PSK_DEFAULT_IDENTITIES = {
    'default': ('Client_identity', '6162636465666768696a6b6c6d6e6f70'),
    'dummy_key1': ('abc', 'dead'),
    'dummy_key2': ('def', 'beef'),
}


class TLSProgram:
    """
    Base class for generate server/client command.
    """

    SUPPORT_KEX_MODES = list(KexMode)

    def __init__(self, **kwargs):
        """
        Args :
            ciphersuite (list, str) : List of ciphersuites
            signature_algorithm (list, str) : List of signature algorithms
            named_group (list, str) : List of named groups
            cert_sig_alg (list, str) : List of certificate with signature algorithms
            psk (list, str) : List of psk pairs .
            compat_mode (bool) : Enable/disable compat mode
            num_tickets (int, None): Number of tickets sent by server. Disable session ticket when
                                     it is 0. And when None use the default value from program.
            tls_version (list, str): List of enabled versions. Default to TLS 1.3 only.
            cli_auth (bool) : Enable/disable cli_auth.
            kex_mode (KexMode, None): Set kex mode or None to use default
        """
        def get_list_arg(arg):
            arg = kwargs.get(arg, [])
            if arg is None:
                return []
            if isinstance(arg, list):
                return arg
            return [arg]

        self._ciphers = get_list_arg('ciphersuite')
        self._sig_algs = get_list_arg('signature_algorithm')
        self._named_groups = get_list_arg('named_group')
        self._cert_sig_algs = get_list_arg('cert_sig_alg')
        self._psk_identities = get_list_arg('psk') or PSK_DEFAULT_IDENTITIES.values()
        self._compat_mode = kwargs.get('compat_mode', True)
        self._tls_version = get_list_arg('tls_version') or ['tls13']
        self._num_tickets = kwargs.get('num_tickets', None)
        self._cli_auth = kwargs.get('cli_auth', False)
        self._kex_mode = kwargs.get('kex_mode', None)

    # add_ciphersuites should not be overridden by sub class
    def add_ciphersuites(self, *ciphersuites):
        self._ciphers.extend(
            [cipher for cipher in ciphersuites if cipher not in self._ciphers])

    # add_signature_algorithms should not be overridden by sub class
    def add_signature_algorithms(self, *signature_algorithms):
        self._sig_algs.extend(
            [sig_alg for sig_alg in signature_algorithms if sig_alg not in self._sig_algs])

    # add_named_groups should not be overridden by sub class
    def add_named_groups(self, *named_groups):
        self._named_groups.extend(
            [named_group for named_group in named_groups if named_group not in self._named_groups])

    # add_cert_signature_algorithms should not be overridden by sub class
    def add_cert_signature_algorithms(self, *signature_algorithms):
        self._cert_sig_algs.extend(
            [sig_alg for sig_alg in signature_algorithms if sig_alg not in self._cert_sig_algs])

    # add_psk_identities should not be overridden by sub class
    def add_psk_identities(self, *psk_identities):
        self._psk_identities.extend(
            [psks for psks in psk_identities if psks not in self._psk_identities])

    # pylint: disable=no-self-use
    def pre_checks(self):
        return []

    # pylint: disable=no-self-use
    def cmd(self):
        if not self._cert_sig_algs:
            self._cert_sig_algs = list(CERTIFICATES.keys())
        return self.pre_cmd()

    # pylint: disable=no-self-use,unused-argument
    def post_checks(self, *args, **kwargs):
        return []

    # pylint: disable=no-self-use
    def pre_cmd(self):
        return ['false']


class OpenSSLBase(TLSProgram):
    """
    Generate base test commands for OpenSSL.
    """
    PROG_NAME = 'OpenSSL'
    NAMED_GROUP = {
        'secp256r1': 'P-256',
        'secp384r1': 'P-384',
        'secp521r1': 'P-521',
        'x25519': 'X25519',
        'x448': 'X448',
    }

    SUPPORT_KEX_MODES = [KexMode.ephemeral_all, KexMode.all]

    def get_ciphersuite(self):
        ret = []
        if self._ciphers:
            ciphersuites = ':'.join(self._ciphers)
            ret += ["-ciphersuites {ciphersuites}".format(
                ciphersuites=ciphersuites)]
        return ret

    def get_sig_algs(self):
        ret = []
        if self._sig_algs:
            signature_algorithms = set(self._sig_algs + self._cert_sig_algs)
            signature_algorithms = ':'.join(signature_algorithms)
            ret += ["-sigalgs {signature_algorithms}".format(
                signature_algorithms=signature_algorithms)]
        return ret

    def get_name_groups(self):
        ret = []
        if self._named_groups:
            named_groups = ':'.join(
                map(lambda named_group: self.NAMED_GROUP[named_group], self._named_groups))
            ret += ["-groups {named_groups}".format(named_groups=named_groups)]
        return ret

    def cmd(self):
        ret = super().cmd()

        ret += self.get_ciphersuite() + self.get_sig_algs() + self.get_name_groups()
        if not self._compat_mode:
            ret += ['-no_middlebox']
        ret += ['-msg -tls1_3']
        return ret

    def pre_checks(self):
        return ["requires_openssl_tls1_3"]


class OpenSSLServ(OpenSSLBase):
    """
    Generate test commands for OpenSSL server.
    """

    def cmd(self):
        ret = super().cmd()
        ret += ['-num_tickets 0 -no_resume_ephemeral -no_cache']
        return ret

    def post_checks(self, *args, **kwargs):
        return ['-c "HTTP/1.0 200 ok"']

    def pre_cmd(self):
        ret = ['$O_NEXT_SRV_NO_CERT']
        for _, cert, key in map(lambda sig_alg: CERTIFICATES[sig_alg], self._cert_sig_algs):
            ret += ['-cert {cert} -key {key}'.format(cert=cert, key=key)]
        return ret


class OpenSSLCli(OpenSSLBase):
    """
    Generate test commands for OpenSSL client.
    """

    def pre_cmd(self):
        ret = ['$O_NEXT_CLI_NO_CERT']
        if self._cert_sig_algs:
            ret.append(
                '-CAfile {cafile}'.format(cafile=CERTIFICATES[self._cert_sig_algs[0]].cafile))
        return ret


class GnuTLSBase(TLSProgram):
    """
    Generate base test commands for GnuTLS.
    """
    PROG_NAME = 'GnuTLS'
    SUPPORT_KEX_MODES = [KexMode.ephemeral_all, KexMode.all]

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

    SIGNATURE_ALGORITHM = {
        'ecdsa_secp256r1_sha256': ['SIGN-ECDSA-SECP256R1-SHA256'],
        'ecdsa_secp521r1_sha512': ['SIGN-ECDSA-SECP521R1-SHA512'],
        'ecdsa_secp384r1_sha384': ['SIGN-ECDSA-SECP384R1-SHA384'],
        'rsa_pss_rsae_sha256': ['SIGN-RSA-PSS-RSAE-SHA256']}

    NAMED_GROUP = {
        'secp256r1': ['GROUP-SECP256R1'],
        'secp384r1': ['GROUP-SECP384R1'],
        'secp521r1': ['GROUP-SECP521R1'],
        'x25519': ['GROUP-X25519'],
        'x448': ['GROUP-X448'],
    }

    def pre_checks(self):
        return ["requires_gnutls_tls1_3",
                "requires_gnutls_next_no_ticket",
                "requires_gnutls_next_disable_tls13_compat", ]

    def cmd(self):
        ret = super().cmd()

        priority_string_list = []

        def update_priority_string_list(items, map_table):
            for item in items:
                for i in map_table[item]:
                    if i not in priority_string_list:
                        yield i

        if self._ciphers:
            priority_string_list.extend(update_priority_string_list(
                self._ciphers, self.CIPHER_SUITE))
        else:
            priority_string_list.extend(['CIPHER-ALL', 'MAC-ALL'])

        if self._sig_algs:
            signature_algorithms = set(self._sig_algs + self._cert_sig_algs)
            priority_string_list.extend(update_priority_string_list(
                signature_algorithms, self.SIGNATURE_ALGORITHM))
        else:
            priority_string_list.append('SIGN-ALL')

        if self._named_groups:
            priority_string_list.extend(update_priority_string_list(
                self._named_groups, self.NAMED_GROUP))
        else:
            priority_string_list.append('GROUP-ALL')

        priority_string_list = ['NONE'] + \
            priority_string_list + ['VERS-TLS1.3']

        priority_string = ':+'.join(priority_string_list)
        priority_string += ':%NO_TICKETS'

        if not self._compat_mode:
            priority_string += [':%DISABLE_TLS13_COMPAT_MODE']

        ret += ['--priority={priority_string}'.format(
            priority_string=priority_string)]
        return ret


class GnuTLSServ(GnuTLSBase):
    """
    Generate test commands for GnuTLS server.
    """

    def pre_cmd(self):
        ret = ['$G_NEXT_SRV_NO_CERT', '--http',
               '--disable-client-cert', '--debug=4']

        for _, cert, key in map(lambda sig_alg: CERTIFICATES[sig_alg], self._cert_sig_algs):
            ret += ['--x509certfile {cert} --x509keyfile {key}'.format(
                cert=cert, key=key)]
        return ret

    def post_checks(self, *args, **kwargs):
        return ['-c "HTTP/1.0 200 OK"']


class GnuTLSCli(GnuTLSBase):
    """
    Generate test commands for GnuTLS client.
    """

    def pre_cmd(self):
        ret = ['$G_NEXT_CLI_NO_CERT', '--debug=4', '--single-key-share']
        if self._cert_sig_algs:
            ret.append(
                '--x509cafile {cafile}'.format(cafile=CERTIFICATES[self._cert_sig_algs[0]].cafile))
        return ret

