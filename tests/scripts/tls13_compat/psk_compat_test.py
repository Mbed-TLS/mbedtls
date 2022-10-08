"""
    Generate PSK mode tests
"""

import itertools

from .core import NAMED_GROUP_IANA_VALUE, GnuTLSCli, GnuTLSServ, MbedTLSBase, MbedTLSCli, \
    MbedTLSServ, OpenSSLCli, KexMode, OpenSSLServ


class PSKOpenSSLCli(OpenSSLCli):
    """
    Generate PSK test command for OpenSSL Client
    """

    def cmd(self):
        psk_identities = self._psk_identities
        identity, psk = list(psk_identities)[0]
        ret = super().pre_cmd() + ['-tls1_3', '-msg',
                                   '-psk_identity', identity, '-psk', psk]

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
        psk_identities = self._psk_identities
        identity, psk = list(psk_identities)[0]

        # OpenSSL s_server need it.
        if not self._cert_sig_algs:
            self.add_cert_signature_algorithms("ecdsa_secp256r1_sha256")

        ret = super().pre_cmd() + ['-tls1_3', '-msg',
                                   '-psk_identity', identity, '-psk', psk]

        if self._kex_mode and self._kex_mode & KexMode.psk:
            ret.append('-allow_no_dhe_kex')

        if self._named_groups:
            named_groups = ':'.join(
                map(lambda named_group: self.NAMED_GROUP[named_group], self._named_groups))
            ret += ["-groups {named_groups}".format(named_groups=named_groups)]

        return ret

    def post_checks(self, *args, **kwargs):
        return []

    def select_expected_kex_mode(self, peer_kex_mode):
        common_kex_mode = KexMode(self._kex_mode & peer_kex_mode)
        return KexMode(list(filter(lambda a: a != 0, [common_kex_mode & i for i in (
            KexMode.psk_ephemeral, KexMode.psk, KexMode.ephemeral)]))[0])


class PSKGnuTLSCli(GnuTLSCli):
    """
    Generate PSK test command for GnuTLS Client
    """

    def cmd(self):
        identity, psk = list(self._psk_identities)[0]

        def update_priority_string_list(items, map_table):
            for item in items:
                for i in map_table[item]:
                    yield '+' + i

        priority_string_list = ['NORMAL', '-VERS-ALL',
                                '+VERS-TLS1.3', '-KX-ALL', '+ECDHE-PSK', '+DHE-PSK']
        if self._kex_mode and self._kex_mode & KexMode.psk:
            priority_string_list.append('+PSK')
        if self._named_groups:
            priority_string_list.append('-GROUP-ALL')
            priority_string_list.extend(update_priority_string_list(
                self._named_groups, self.NAMED_GROUP))
        ret = ret = super().pre_cmd() + ['--priority', ':'.join(priority_string_list),
                                         '--pskusername', identity, '--pskkey', psk, 'localhost']
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

        priority_string_list = ['NORMAL', '-VERS-ALL',
                                '+VERS-TLS1.3', '-KX-ALL', '+ECDHE-PSK', '+DHE-PSK']
        if self._kex_mode and self._kex_mode & KexMode.psk:
            priority_string_list.append('+PSK')
        if self._named_groups:
            priority_string_list.append('-GROUP-ALL')
            priority_string_list.extend(update_priority_string_list(
                self._named_groups, self.NAMED_GROUP))

        # workaround GnuTLS psk settings
        ret = super().pre_cmd() + ['--priority', ':'.join(priority_string_list),
                                   '--pskpasswd data_files/passwd.psk']
        return ret

    def post_checks(self, *args, **kwargs):
        return []

    def select_expected_kex_mode(self, peer_kex_mode):
        special_cases = {(KexMode.psk_all, KexMode.ephemeral_all): None}
        if (peer_kex_mode, self._kex_mode) in special_cases:
            return special_cases[(peer_kex_mode, self._kex_mode)]

        common_kex_mode = KexMode(self._kex_mode & peer_kex_mode)
        if common_kex_mode == KexMode.ephemeral_all:
            return KexMode.psk_ephemeral
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

        ret = super().pre_cmd() + ['force_version=tls13', 'debug_level=5']
        if self._kex_mode:
            ret.append('tls13_kex_modes={}'.format(self._kex_mode.name))

        ret.append('$(get_srv_psk_list)')

        if self._named_groups:
            named_groups = ','.join(self._named_groups)
            ret += ["curves={named_groups}".format(named_groups=named_groups)]
        return ret

    def pre_checks(self):
        configs = ['MBEDTLS_SSL_PROTO_TLS1_3',
                   'MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE', 'MBEDTLS_SSL_SRV_C', 'MBEDTLS_DEBUG_C']
        configs += mbedtls_get_kex_config_option(self._kex_mode)

        return ['requires_config_enabled {}'.format(i) for i in configs]

    def post_checks(self, *args, **kwargs):
        expected_kex_mode = kwargs.get('expected_kex_mode', None)
        client_kex_mode = kwargs.get('client_kex_mode', None)

        def get_check_char(arg):
            return 's' if arg else 'S'
        if client_kex_mode:
            ret = [
                '-{} "found psk key exchange modes extension"'.format(
                    get_check_char(client_kex_mode & KexMode.psk_all)),
                '-{} "found pre_shared_key extension"'.format(
                    get_check_char(client_kex_mode & KexMode.psk_all)),
                '-{} "Found PSK_EPHEMERAL KEX MODE"'.format(
                    get_check_char(client_kex_mode & KexMode.psk_ephemeral)),
                '-{} "Found PSK KEX MODE"'.format(
                    get_check_char(client_kex_mode & KexMode.psk))
            ]
        else:
            ret = []
        if expected_kex_mode is not None:
            assert isinstance(expected_kex_mode, KexMode) and expected_kex_mode in (
                KexMode.psk, KexMode.psk_ephemeral, KexMode.ephemeral), expected_kex_mode

            for i in (KexMode.psk, KexMode.psk_ephemeral, KexMode.ephemeral):
                ret.append(
                    '-{} "key exchange mode: {}$"'.format(
                        get_check_char(i == expected_kex_mode), i.name))
        return ret

    def select_expected_kex_mode(self, peer_kex_mode):
        common_kex_mode = KexMode(self._kex_mode & peer_kex_mode)
        return KexMode(list(filter(lambda a: a != 0, [common_kex_mode & i for i in (
            KexMode.psk_ephemeral, KexMode.ephemeral, KexMode.psk)]))[0])


class PSKMbedTLSCli(MbedTLSCli):
    """
    Generate PSK test command for MbedTLS client
    """

    def cmd(self):
        identity, psk = list(self._psk_identities)[0]

        ret = super().pre_cmd() + ['debug_level=5']

        if self._kex_mode:
            if self._kex_mode & KexMode.ephemeral == 0:
                ret.append('force_version=tls13')
            ret.append('tls13_kex_modes={}'.format(self._kex_mode.name))
        else:
            self._kex_mode = KexMode.all

        ret.append('psk_identity={} psk={}'.format(identity, psk))

        if self._named_groups:
            named_groups = ','.join(self._named_groups)
            ret += ["curves={named_groups}".format(named_groups=named_groups)]

        return ret

    def pre_checks(self):
        configs = ['MBEDTLS_SSL_PROTO_TLS1_3',
                   'MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE', 'MBEDTLS_SSL_CLI_C', 'MBEDTLS_DEBUG_C']
        configs += mbedtls_get_kex_config_option(self._kex_mode)

        return ['requires_config_enabled {}'.format(i) for i in configs]

    def post_checks(self, *args, **kwargs):
        expected_kex_mode = kwargs.get('expected_kex_mode', None)
        client_kex_mode = kwargs.get('client_kex_mode', None)

        def get_check_char(arg):
            return 'c' if arg else 'C'
        if client_kex_mode:
            ret = [
                '-{} "found psk key exchange modes extension"'.format(
                    get_check_char(client_kex_mode & KexMode.psk_all)),
                '-{} "found pre_shared_key extension"'.format(
                    get_check_char(client_kex_mode & KexMode.psk_all)),
                '-{} "Found PSK_EPHEMERAL KEX MODE"'.format(
                    get_check_char(client_kex_mode & KexMode.psk_ephemeral)),
                '-{} "Found PSK KEX MODE"'.format(
                    get_check_char(client_kex_mode & KexMode.psk))
            ]
        else:
            ret = []
        if expected_kex_mode is not None:
            assert isinstance(expected_kex_mode, KexMode) and expected_kex_mode in (
                KexMode.psk, KexMode.psk_ephemeral, KexMode.ephemeral), expected_kex_mode

            for i in (KexMode.psk, KexMode.psk_ephemeral, KexMode.ephemeral):
                ret.append(
                    '-{} "key exchange mode: {}$"'.format(
                        get_check_char(i == expected_kex_mode), i.name))
        return ret

