# tls13_compat/compat.py
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

"""
Functions for generating TLSv1.3 Compat test cases

"""
import itertools
from .core import CIPHER_SUITE_IANA_VALUE, NAMED_GROUP_IANA_VALUE, SIG_ALG_IANA_VALUE, \
    GnuTLSCli, MbedTLSBase, MbedTLSCli, MbedTLSServ, GnuTLSServ, OpenSSLCli, OpenSSLServ

SERVER_CLASSES = [OpenSSLServ, GnuTLSServ, MbedTLSServ]
CLIENT_CLASSES = [OpenSSLCli, GnuTLSCli, MbedTLSCli]


def has_mbedtls_prog(*args):
    return any([issubclass(i, MbedTLSBase) for i in args])


def generate_basic_run_test(name, server_obj, client_obj, exit_value):
    serv_cmd = ' '.join(server_obj.cmd())
    cli_cmd = ' '.join(client_obj.cmd())
    return ['run_test "{name}"'.format(name=name),
            '"{serv_cmd}"'.format(serv_cmd=serv_cmd),
            '"{cli_cmd}"'.format(cli_cmd=cli_cmd),
            '{exit_value}'.format(exit_value=exit_value)] + \
        server_obj.post_checks() + client_obj.post_checks(), 9


def generate_compat_test(client=None, server=None, cipher=None, named_group=None, sig_alg=None):
    """
    Generate test case with `ssl-opt.sh` format.
    """

    if not has_mbedtls_prog(client, server):
        return None

    name = 'TLS 1.3 {client.PROG_NAME[0]}->{server.PROG_NAME[0]}: ' + \
           '{cipher},{named_group},{sig_alg}'
    name = name.format(client=client, cipher=cipher[4:], server=server,
                       named_group=named_group, sig_alg=sig_alg)

    server_object = server(ciphersuite=cipher,
                           named_group=named_group,
                           signature_algorithm=sig_alg,
                           cert_sig_alg=sig_alg)
    client_object = client(ciphersuite=cipher,
                           named_group=named_group,
                           signature_algorithm=sig_alg,
                           cert_sig_alg=sig_alg)

    cmd, prefix_len = generate_basic_run_test(
        name, server_object, client_object, 0)
    cmd += ['-C "received HelloRetryRequest message"']
    prefix = ' \\\n' + (' '*prefix_len)
    cmd = prefix.join(cmd)
    return '\n'.join(server_object.pre_checks() + client_object.pre_checks() + [cmd])


def generate_tls13_compat_test_cases():
    """Generate normal compat test cases"""
    for client, server, cipher, named_group, sig_alg in \
        itertools.product(CLIENT_CLASSES,
                          SERVER_CLASSES,
                          CIPHER_SUITE_IANA_VALUE.keys(),
                          NAMED_GROUP_IANA_VALUE.keys(),
                          SIG_ALG_IANA_VALUE.keys()):
        test_case = generate_compat_test(client=client, server=server,
                                         cipher=cipher, named_group=named_group,
                                         sig_alg=sig_alg)
        if test_case:
            yield test_case
