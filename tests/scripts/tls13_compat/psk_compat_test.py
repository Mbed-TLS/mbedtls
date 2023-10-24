"""
    Generate PSK mode tests
"""

import itertools

from .core import NAMED_GROUP_IANA_VALUE, GnuTLSCli, GnuTLSServ, MbedTLSBase, MbedTLSCli, \
    MbedTLSServ, OpenSSLCli, KexMode, OpenSSLServ, TLSProgram


class PSKOpenSSLCli(OpenSSLCli):
    """
    Generate PSK test command for OpenSSL Client
    """

    def cmd(self):

        ret = super().pre_cmd() + ['-tls1_3', '-msg']
        if self.psk_identities:
            identity, psk = self.psk_identities[0]
            ret += ['-psk_identity', identity, '-psk', psk]

        if self._kex_mode and self._kex_mode & KexMode.psk:
            ret.append('-allow_no_dhe_kex')

        if self._named_groups:
            named_groups = ':'.join(
                map(lambda named_group: self.NAMED_GROUP[named_group], self._named_groups))
            ret += ["-groups {named_groups}".format(named_groups=named_groups)]

        return ret


class PSKOpenSSLServ(OpenSSLServ):
    """
    Generate PSK test command for OpenSSL Client
    """

    def cmd(self):
        # OpenSSL s_server need it.
        if not self._cert_sig_algs:
            self.add_cert_signature_algorithms("ecdsa_secp256r1_sha256")

        ret = super().pre_cmd() + ['-tls1_3', '-msg']
        if self.psk_identities:
            identity, psk = self.psk_identities[0]
            ret += ['-psk_identity', identity, '-psk', psk]

        if self._kex_mode and self._kex_mode & KexMode.psk:
            ret.append('-allow_no_dhe_kex')

        if self._named_groups:
            named_groups = ':'.join(
                map(lambda named_group: self.NAMED_GROUP[named_group], self._named_groups))
            ret += ["-groups {named_groups}".format(named_groups=named_groups)]

        return ret

    def post_checks(self, *args, **kwargs):
        return []

    def select_expected_kex_mode(self, peer_kex_mode, psk_mode=0):
        common_kex_mode = KexMode(self._kex_mode & peer_kex_mode)
        if common_kex_mode == KexMode.none:
            return KexMode.none
        if psk_mode == 1:
            if common_kex_mode & KexMode.ephemeral:
                return KexMode.ephemeral
            else:
                return KexMode.none
        elif psk_mode == 2:
            if peer_kex_mode == KexMode.psk_or_ephemeral and self._kex_mode == KexMode.ephemeral_all:
                # special case
                return KexMode.ephemeral
            return KexMode.none

        return KexMode(list(filter(lambda a: a != 0, [common_kex_mode & i for i in (
            KexMode.psk_ephemeral, KexMode.psk, KexMode.ephemeral)]))[0])


class PSKGnuTLSCli(GnuTLSCli):
    """
    Generate PSK test command for GnuTLS Client
    """
    SUPPORT_KEX_MODES = GnuTLSCli.SUPPORT_KEX_MODES + \
        [KexMode.psk_or_ephemeral]

    def cmd(self):

        priority_string_list = self.get_priority_string().split(':')

        if self._kex_mode & KexMode.psk_ephemeral:
            priority_string_list += ['+ECDHE-PSK', '+DHE-PSK']

        if self._kex_mode & KexMode.psk:
            priority_string_list.append('+PSK')

        ret = super().pre_cmd() + ['--priority',
                                   ':'.join(priority_string_list)]

        if self.psk_identities:
            identity, psk = self.psk_identities[0]
            ret += ['--pskusername', identity, '--pskkey', psk]

        ret += ['localhost']
        return ret


class PSKGnuTLSServ(GnuTLSServ):
    """
    Generate PSK test command for GnuTLS Client
    """

    def cmd(self):
        def update_priority_string_list(items, map_table):
            for item in items:
                for i in map_table[item]:
                    yield '+' + i

        # OpenSSL s_server need it.
        if not self._cert_sig_algs:
            self.add_cert_signature_algorithms("ecdsa_secp256r1_sha256")

        priority_string_list = [
            'NORMAL', '-VERS-ALL', '+VERS-TLS1.3', '-KX-ALL']
        if self._kex_mode & KexMode.psk_all:
            if self._kex_mode & KexMode.psk_ephemeral:
                priority_string_list += ['+ECDHE-PSK', '+DHE-PSK']
            else:
                priority_string_list += ['-ECDHE-PSK', '-DHE-PSK']
            if self._kex_mode & KexMode.psk:
                priority_string_list.append('+PSK')
            else:
                priority_string_list.append('-PSK')
        if self._kex_mode & KexMode.ephemeral:
            priority_string_list += ['+SIGN-ALL']
        if self._named_groups:
            priority_string_list.append('-GROUP-ALL')
            priority_string_list.extend(update_priority_string_list(
                self._named_groups, self.NAMED_GROUP))

        # workaround GnuTLS psk settings
        ret = super().pre_cmd() + ['--priority',
                                   ':'.join(priority_string_list)]
        if self.psk_identities:
            ret += ['--pskpasswd data_files/passwd.psk']

        return ret

    def post_checks(self, *args, **kwargs):
        return []

    def select_expected_kex_mode(self, peer_kex_mode, psk_mode=0):
        common_kex_mode = KexMode(self._kex_mode & peer_kex_mode)
        if common_kex_mode == KexMode.none:
            return KexMode.none
        if (self._kex_mode, peer_kex_mode) == (KexMode.psk_or_ephemeral, KexMode.all):
            return KexMode.ephemeral

        if psk_mode in (1, 2):
            # - Fallback tests of GnuTLS server depends on session ticket,
            #   verified on `gnutls-serv 3.7.3`
            # - `material mismatch` always fail
            if peer_kex_mode == KexMode.psk_or_ephemeral and self._kex_mode == KexMode.ephemeral_all:
                # special case
                return KexMode.ephemeral
            return KexMode.none
        # if common_kex_mode == KexMode.psk_or_ephemeral:
        #     return KexMode.ephemeral

        return KexMode(list(filter(lambda a: a != 0, [common_kex_mode & i for i in (
            KexMode.psk_ephemeral, KexMode.psk, KexMode.ephemeral, )]))[0])


def mbedtls_get_kex_config_option(kex_mode):
    ret = []
    for kex in (KexMode.psk, KexMode.psk_ephemeral, KexMode.ephemeral):
        if kex & kex_mode:
            ret += ['MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_{}_ENABLED'.format(
                kex.name.upper())]
    return ret


class PSKMbedTLSServ(MbedTLSServ):
    """
    Generate PSK test command for MbedTLS server
    """

    def cmd(self):

        ret = super().pre_cmd() + ['debug_level=5']

        assert self._kex_mode
        ret.append('tls13_kex_modes={}'.format(self._kex_mode.name))
        if self._kex_mode & KexMode.psk_all:
            ret.append('$(get_srv_psk_list)')

        if self._named_groups:
            named_groups = ','.join(self._named_groups)
            ret += ["groups={named_groups}".format(named_groups=named_groups)]
        return ret

    def post_checks(self, *args, **kwargs):
        expected_kex_mode = kwargs.get(
            'expected_kex_mode', KexMode.psk_ephemeral)
        client_kex_mode = kwargs.get('client_kex_mode', KexMode.psk_ephemeral)
        psk_mode = kwargs.get('psk_mode', 0)

        def get_check_char(arg):
            return 's' if arg else 'S'
        has_pre_shared_key = self._kex_mode & KexMode.psk_all and client_kex_mode & KexMode.psk_all
        ret = [
            '-{} "ClientHello: supported_groups(10) extension exists."'.format(
                get_check_char(client_kex_mode & KexMode.ephemeral_all)),
            '-{} "ClientHello: signature_algorithms(13) extension exists."'.format(
                get_check_char(client_kex_mode & KexMode.ephemeral)),
            '-{} "ClientHello: pre_shared_key(41) extension exists."'.format(
                get_check_char(client_kex_mode & KexMode.psk_all)),
            '-{} "ClientHello: psk_key_exchange_modes(45) extension exists."'.format(
                get_check_char(client_kex_mode & KexMode.psk_all)),
            '-{} "ClientHello: key_share(51) extension exists."'.format(
                get_check_char(client_kex_mode & KexMode.ephemeral_all)),
            '-{} "Found PSK_EPHEMERAL KEX MODE"'.format(
                get_check_char(client_kex_mode & KexMode.psk_ephemeral)),
            '-{} "Found PSK KEX MODE"'.format(
                get_check_char(client_kex_mode & KexMode.psk)),
            '-{} "Pre shared key found"'.format(
                get_check_char(psk_mode == 0 and has_pre_shared_key)),
            '-{} "No matched PSK or ticket"'.format(
                get_check_char(psk_mode == 1 and has_pre_shared_key)),
            '-{} "Invalid binder."'.format(
                get_check_char(psk_mode == 2 and has_pre_shared_key)),
        ]

        for i in (KexMode.psk, KexMode.psk_ephemeral, KexMode.ephemeral):
            ret.append(
                '-{} "key exchange mode: {}$"'.format(
                    get_check_char(i == expected_kex_mode), i.name))
        return ret

    def select_expected_kex_mode(self, peer_kex_mode, psk_mode=0):
        common_kex_mode = KexMode(self._kex_mode & peer_kex_mode)
        if common_kex_mode == KexMode.none:
            return common_kex_mode

        if psk_mode == 1:
            if common_kex_mode & KexMode.ephemeral:
                return KexMode.ephemeral
            else:
                return KexMode.none
        elif psk_mode == 2:
            return KexMode.none

        ret = list(filter(lambda a: a != 0, [common_kex_mode & i for i in (
            KexMode.psk_ephemeral, KexMode.ephemeral, KexMode.psk)]))
        if ret:
            return KexMode(ret[0])
        return KexMode.none


class PSKMbedTLSCli(MbedTLSCli):
    """
    Generate PSK test command for MbedTLS client
    """

    def cmd(self):

        ret = super().pre_cmd() + ['debug_level=5']

        assert self._kex_mode != KexMode.none
        if self._kex_mode & KexMode.ephemeral == 0:
            # When both are enabled and ephemeral disabled, signature_algorithm is sent to
            # server. That does not match client's configuration.
            ret.append('force_version=tls13')
        ret.append('tls13_kex_modes={}'.format(self._kex_mode.name))

        if self.psk_identities:
            ret.append('psk_identity={} psk={}'.format(
                *self.psk_identities[0]))

        if self._named_groups:
            named_groups = ','.join(self._named_groups)
            ret += ["groups={named_groups}".format(named_groups=named_groups)]

        return ret

    def post_checks(self, *args, **kwargs):
        # raise 'Err'
        client_kex_mode = self._kex_mode

        def get_check_char(arg):
            return 'c' if arg else 'C'
        expected_kex_mode = kwargs.get(
            'expected_kex_mode', KexMode.psk_ephemeral)
        assert expected_kex_mode in (
            KexMode.none, KexMode.psk, KexMode.psk_ephemeral, KexMode.ephemeral)
        ret = [
            '-{} "ClientHello: supported_groups(10) extension exists."'.format(
                get_check_char(client_kex_mode & KexMode.ephemeral_all)),
            '-{} "ClientHello: signature_algorithms(13) extension exists."'.format(
                get_check_char(client_kex_mode & KexMode.ephemeral)),
            '-{} "ClientHello: pre_shared_key(41) extension exists."'.format(
                get_check_char(client_kex_mode & KexMode.psk_all)),
            '-{} "ClientHello: psk_key_exchange_modes(45) extension exists."'.format(
                get_check_char(client_kex_mode & KexMode.psk_all)),
            '-{} "ClientHello: key_share(51) extension exists."'.format(
                get_check_char(client_kex_mode & KexMode.ephemeral_all)),
            '-{} "Adding PSK-ECDHE key exchange mode"'.format(
                get_check_char(client_kex_mode & KexMode.psk_ephemeral)),
            '-{} "Adding pure PSK key exchange mode"'.format(
                get_check_char(client_kex_mode & KexMode.psk)),
            '-{} "ServerHello: pre_shared_key(41) extension exists."'.format(
                get_check_char(expected_kex_mode & KexMode.psk_all)),
            '-{} "ServerHello: key_share(51) extension exists."'.format(
                get_check_char(expected_kex_mode & KexMode.ephemeral_all)),
        ]
        if expected_kex_mode:
            ret += ['-c "Selected key exchange mode: {}$"'.format(
                KexMode(expected_kex_mode).name)]

        return ret


PSK_SERVER_CLASSES = [PSKMbedTLSServ, PSKGnuTLSServ, PSKOpenSSLServ]
PSK_CLIENT_CLASSES = [PSKOpenSSLCli, PSKGnuTLSCli, PSKMbedTLSCli]


def generate_psk_ephemeral_test(client=None, server=None, client_named_group=None,
                                server_named_group=None):
    """
    Generate Hello Retry Request test case with `ssl-opt.sh` format.
    """
    if not issubclass(server, MbedTLSBase) and not issubclass(client, MbedTLSBase):
        return None

    def get_best_match_kex_mode(cls: TLSProgram):
        kex_mode = KexMode.psk_ephemeral
        if kex_mode not in cls.SUPPORT_KEX_MODES:
            for kex in cls.SUPPORT_KEX_MODES:
                if kex_mode & kex:
                    return kex
        return kex_mode

    server_object = server(named_group=server_named_group,
                           kex_mode=get_best_match_kex_mode(server))
    client_object = client(named_group=client_named_group,
                           kex_mode=get_best_match_kex_mode(client))

    if client_named_group != server_named_group:
        # HRR will be triggered in this case.
        if isinstance(client_object, PSKGnuTLSCli) and client_named_group == 'ffdhe2048':
            # GnuTLS 3.7.3 does not send groups as expected.
            return None

        name = 'TLS 1.3 {client[0]}->{server[0]}: psk_ephemeral group(' \
            '{c_named_group}->{s_named_group}) check, good'.format(
                client=client.PROG_NAME, server=server.PROG_NAME, c_named_group=client_named_group,
                s_named_group=server_named_group)
        client_object.add_named_groups(server_named_group)
    else:
        name = 'TLS 1.3 {client[0]}->{server[0]}: ' \
               'psk_ephemeral group({c_named_group}) check, good'.format(
                   client=client.PROG_NAME, server=server.PROG_NAME,
                   c_named_group=client_named_group)

    cmd = ['run_test "{}"'.format(name),
           '"{}"'.format(' '.join(server_object.cmd())),
           '"{}"'.format(' '.join(client_object.cmd())),
           '0']

    if issubclass(server, MbedTLSBase):
        cmd.append('-s "write selected_group: {named_group}"'.format(
            named_group=server_named_group))

        if client_named_group != server_named_group:
            cmd.append(
                '-s "HRR selected_group: {:s}"'.format(server_named_group))

    if issubclass(client, MbedTLSBase):
        if client_named_group != server_named_group:
            cmd.append('-c "received HelloRetryRequest message"')

    cmd += server_object.post_checks(expected_kex_mode=KexMode.psk_ephemeral,
                                     client_kex_mode=client_object._kex_mode)
    cmd += client_object.post_checks()

    prefix = ' \\\n' + (' '*9)
    cmd = prefix.join(cmd)
    return '\n'.join(server_object.pre_checks(peer_kex_mode=client_object._kex_mode) +
                     client_object.pre_checks(peer_kex_mode=server_object._kex_mode) +
                     [cmd])


def generate_all_psk_ephemeral_group_tests():
    """
        Generate psk named_groups compat tests
    """
    for client, server, client_named_group, server_named_group in \
        itertools.product(PSK_CLIENT_CLASSES,
                          PSK_SERVER_CLASSES,
                          NAMED_GROUP_IANA_VALUE.keys(),
                          NAMED_GROUP_IANA_VALUE.keys()):

        yield generate_psk_ephemeral_test(client=client, server=server,
                                          client_named_group=client_named_group,
                                          server_named_group=server_named_group)


# pylint: disable=too-many-arguments,too-many-locals
def generate_kex_modes_test(client, server, c_kex_mode, s_kex_mode, c_psk, s_psk):
    """
    Generate a key exchange mode test
    """
    # client or server MUST be 'mbedTLS'
    if not (issubclass(server, MbedTLSBase) or issubclass(client, MbedTLSBase)):
        return None

    # kex modes MUST be supported by client and server.
    if c_kex_mode not in client.SUPPORT_KEX_MODES or \
            s_kex_mode not in server.SUPPORT_KEX_MODES:
        return None

    server_object = server(kex_mode=s_kex_mode, psk=s_psk)
    client_object = client(kex_mode=c_kex_mode, psk=c_psk)
    cert_sig_alg = "ecdsa_secp256r1_sha256"

    server_object.add_cert_signature_algorithms(cert_sig_alg)
    client_object.add_cert_signature_algorithms(cert_sig_alg)
    expected_kex_mode = None
    result = None
    psk_mode = None

    expected_exit_value = 0

    if c_psk == s_psk:
        psk_mode = 0
    elif c_psk[0] != s_psk[0]:
        # id mismatch
        psk_mode = 1
    else:
        # material mismatch
        psk_mode = 2

    # if not (server_object.psk_identities or client_object.psk_identities):
    #     # skip both ephemral
    #     return None
    if psk_mode in (1, 2) and not isinstance(server_object, MbedTLSServ):
        return None

    if not (server_object.psk_identities and client_object.psk_identities) and psk_mode != 0:
        # skip id/material mismatch for ephemeral client/server
        return None

    expected_kex_mode = server_object.select_expected_kex_mode(
        c_kex_mode, psk_mode=psk_mode)

    assert expected_kex_mode in (
        KexMode.none, KexMode.psk, KexMode.psk_ephemeral, KexMode.ephemeral), server_object

    if expected_kex_mode == KexMode.none:
        expected_exit_value = 1
    else:
        expected_exit_value = 0

    result = ' good' if expected_exit_value == 0 else ' fail'
    if c_kex_mode & s_kex_mode == KexMode.none:
        if psk_mode in (1, 2):
            return None
        result += ', no common kex mode'

    if psk_mode == 1:
        result += ', id mismatch'
        if expected_kex_mode:
            result += ', fallback'
    elif psk_mode == 2:
        result += ', material mismatch'
    name = 'TLS 1.3 {client[0]}->{server[0]}: {c_kex_mode}/{s_kex_mode},{result}'.format(
        client=client.PROG_NAME, server=server.PROG_NAME, c_kex_mode=c_kex_mode.name,
        s_kex_mode=s_kex_mode.name, result=result)

    cmd = ['run_test "{}"'.format(name),
           '"{}"'.format(' '.join(server_object.cmd())),
           '"{}"'.format(' '.join(client_object.cmd())),
           '{}'.format(expected_exit_value)]
    cmd += server_object.post_checks(
        expected_kex_mode=expected_kex_mode, client_kex_mode=c_kex_mode, psk_mode=psk_mode)
    cmd += client_object.post_checks(expected_kex_mode=expected_kex_mode)
    prefix = ' \\\n' + (' '*9)
    cmd = prefix.join(cmd)
    ret = '\n'.join(server_object.pre_checks(peer_kex_mode=c_kex_mode) +
                    client_object.pre_checks(peer_kex_mode=s_kex_mode) + [cmd])
    return ret


def generate_all_kex_mode_tests():
    """
    Generate key exchange mode tests
    """
    test_psks = [('Client_identity', '6162636465666768696a6b6c6d6e6f70'),
                 ('wrong_identity', '6162636465666768696a6b6c6d6e6f70'),
                 ('Client_identity', '6162636465666768696a6b6c6d6e6f71')]

    for client, server, c_kex_mode, s_kex_mode, c_psk, s_psk in \
        itertools.product(PSK_CLIENT_CLASSES,
                          PSK_SERVER_CLASSES,
                          list(KexMode),
                          list(KexMode),
                          #   [KexMode.psk_or_ephemeral],
                          #   [KexMode.psk_ephemeral],
                          test_psks,
                          test_psks[:1]):
        if c_psk == KexMode.none or s_psk == KexMode.none:
            continue
        yield generate_kex_modes_test(client, server, c_kex_mode, s_kex_mode, c_psk, s_psk)
