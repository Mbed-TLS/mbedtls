#!/usr/bin/env python3

"""TF PSA Crypto configuration file manipulation library and tool

Basic usage, to read the TF PSA Crypto configuration:
    config = TfPSACryptoConfig()
    if 'PSA_WANT_ALG_MD5' in config: print('MD5 is enabled')
"""

## Copyright The Mbed TLS Contributors
## SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
##

import os
import sys

import framework_scripts_path # pylint: disable=unused-import
from mbedtls_framework import config_common


PSA_UNSUPPORTED_FEATURE = frozenset([
    'PSA_WANT_ALG_CBC_MAC',
    'PSA_WANT_ALG_XTS',
    'PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_DERIVE',
    'PSA_WANT_KEY_TYPE_DH_KEY_PAIR_DERIVE'
])

PSA_UNSTABLE_FEATURE = frozenset([
    'PSA_WANT_ECC_SECP_K1_224'
])


class TfPSACryptoConfigFile(config_common.ConfigFile):
    """Representation of a TF PSA Crypto configuration file."""

    _path_in_tree = 'tf-psa-crypto/include/psa/crypto_config.h'
    default_path = [_path_in_tree,
                    os.path.join(os.path.dirname(__file__),
                                 os.pardir,
                                 _path_in_tree),
                    os.path.join(os.path.dirname(os.path.abspath(os.path.dirname(__file__))),
                                 _path_in_tree)]

    def __init__(self, filename=None):
        super().__init__(self.default_path, 'Crypto', filename)


class TfPSACryptoConfig(config_common.Config):
    """Representation of the TF PSA Crypto configuration.

    See the documentation of the `Config` class for methods to query
    and modify the configuration.
    """

    def __init__(self, *configfiles):
        """Read the PSA crypto configuration files."""

        super().__init__()
        self.configfiles.extend(configfiles)
        self.settings.update({name: config_common.Setting(configfile, active, name, value, section)
                             for configfile in configfiles
                             for (active, name, value, section) in configfile.parse_file()})

    def set(self, name, value=None):
        """Set name to the given value and make it active."""

        if name in PSA_UNSUPPORTED_FEATURE:
            raise ValueError(f'Feature is unsupported: \'{name}\'')
        if name in PSA_UNSTABLE_FEATURE:
            raise ValueError(f'Feature is unstable: \'{name}\'')

        if name not in self.settings:
            self._get_configfile().templates.append((name, '', f'#define {name} '))

        # Default value for PSA macros is '1'
        if name.startswith('PSA_') and not value:
            value = '1'

        super().set(name, value)


class TfPSACryptoConfigTool(config_common.ConfigTool):
    """Command line TF PSA Crypto config file manipulation tool."""

    def __init__(self):
        super().__init__(TfPSACryptoConfigFile.default_path[0], single_config=False)
        configfiles = [TfPSACryptoConfigFile(file) for file in self.args.file]
        self.config = TfPSACryptoConfig(*configfiles)

    def custom_parser_options(self):
        """Adds TF PSA Crypto specific options for the parser."""


if __name__ == '__main__':
    sys.exit(TfPSACryptoConfigTool().main())
