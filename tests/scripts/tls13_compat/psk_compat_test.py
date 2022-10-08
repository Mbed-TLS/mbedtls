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

