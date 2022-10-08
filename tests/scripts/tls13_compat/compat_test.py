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
Functions for generating TLSv1.3 Compat test cases

"""

import itertools
from .core import CIPHER_SUITE_IANA_VALUE, NAMED_GROUP_IANA_VALUE, SIG_ALG_IANA_VALUE, \
    GnuTLSCli, GnuTLSServ, MbedTLSBase, MbedTLSCli, MbedTLSServ, OpenSSLCli, OpenSSLServ

SERVER_CLASSES = [OpenSSLServ, GnuTLSServ, MbedTLSServ]
CLIENT_CLASSES = [OpenSSLCli, GnuTLSCli, MbedTLSCli]


def generate_compat_test(client=None, server=None, cipher=None, named_group=None, sig_alg=None):
    """
    Generate test case with `ssl-opt.sh` format.
    """
    # Skip tests when MBedTLS is not server or client.
    if not (issubclass(server, MbedTLSBase) or issubclass(client, MbedTLSBase)):
        return None
    name = 'TLS 1.3 {client[0]}->{server[0]}: {cipher},{named_group},{sig_alg}'.format(
        client=client.PROG_NAME, server=server.PROG_NAME, cipher=cipher[4:], sig_alg=sig_alg,
        named_group=named_group)

    server_object = server(ciphersuite=cipher,
                           named_group=named_group,
                           signature_algorithm=sig_alg,
                           cert_sig_alg=sig_alg)
    client_object = client(ciphersuite=cipher,
                           named_group=named_group,
                           signature_algorithm=sig_alg,
                           cert_sig_alg=sig_alg)

    cmd = ['run_test "{}"'.format(name),
           '"{}"'.format(' '.join(server_object.cmd())),
           '"{}"'.format(' '.join(client_object.cmd())),
           '0']
    cmd += server_object.post_checks()
    cmd += client_object.post_checks()
    cmd += ['-C "received HelloRetryRequest message"']
    prefix = ' \\\n' + (' '*9)
    cmd = prefix.join(cmd)
    return '\n'.join(server_object.pre_checks() + client_object.pre_checks() + [cmd])


def generate_tls13_compat_tests():
    """
    Generate normal test case with `ssl-opt.sh` format. Iterator all possible parameters.
    """
    for client, server, cipher, named_group, sig_alg in \
        itertools.product(CLIENT_CLASSES,
                          SERVER_CLASSES,
                          CIPHER_SUITE_IANA_VALUE.keys(),
                          NAMED_GROUP_IANA_VALUE.keys(),
                          SIG_ALG_IANA_VALUE.keys()):

        yield generate_compat_test(client=client, server=server,
                                   cipher=cipher, named_group=named_group,
                                   sig_alg=sig_alg)

