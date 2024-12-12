#!/usr/bin/env python3

"""TF PSA Crypto configuration file manipulation library and tool

Basic usage, to read the TF PSA Crypto configuration:
    config = TFPSACryptoConfig()
    if 'PSA_WANT_ALG_MD5' in config: print('MD5 is enabled')
"""

## Copyright The Mbed TLS Contributors
## SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
##

import re
import os
import sys

import framework_scripts_path # pylint: disable=unused-import
from mbedtls_framework import config_common


PSA_SYMBOL_REGEXP = re.compile(r'^PSA_.*')

PSA_UNSUPPORTED_FEATURE = frozenset([
    'PSA_WANT_ALG_CBC_MAC',
    'PSA_WANT_ALG_XTS',
    'PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_DERIVE',
    'PSA_WANT_KEY_TYPE_DH_KEY_PAIR_DERIVE'
])

PSA_DEPRECATED_FEATURE = frozenset([
    'PSA_WANT_KEY_TYPE_ECC_KEY_PAIR',
    'PSA_WANT_KEY_TYPE_RSA_KEY_PAIR'
])

PSA_UNSTABLE_FEATURE = frozenset([
    'PSA_WANT_ECC_SECP_K1_224'
])

# The goal of the full configuration is to have everything that can be tested
# together. This includes deprecated or insecure options. It excludes:
# * Options that require additional build dependencies or unusual hardware.
# * Options that make testing less effective.
# * Options that are incompatible with other options, or more generally that
#   interact with other parts of the code in such a way that a bulk enabling
#   is not a good way to test them.
# * Options that remove features.
EXCLUDE_FROM_FULL = frozenset([
    #pylint: disable=line-too-long
    'MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH', # interacts with CTR_DRBG_128_BIT_KEY
    'MBEDTLS_AES_USE_HARDWARE_ONLY', # hardware dependency
    'MBEDTLS_BLOCK_CIPHER_NO_DECRYPT', # incompatible with ECB in PSA, CBC/XTS/NIST_KW/DES
    'MBEDTLS_CTR_DRBG_USE_128_BIT_KEY', # interacts with ENTROPY_FORCE_SHA256
    'MBEDTLS_DEPRECATED_REMOVED', # conflicts with deprecated options
    'MBEDTLS_DEPRECATED_WARNING', # conflicts with deprecated options
    'MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED', # influences the use of ECDH in TLS
    'MBEDTLS_ECP_WITH_MPI_UINT', # disables the default ECP and is experimental
    'MBEDTLS_ENTROPY_FORCE_SHA256', # interacts with CTR_DRBG_128_BIT_KEY
    'MBEDTLS_HAVE_SSE2', # hardware dependency
    'MBEDTLS_MEMORY_BACKTRACE', # depends on MEMORY_BUFFER_ALLOC_C
    'MBEDTLS_MEMORY_BUFFER_ALLOC_C', # makes sanitizers (e.g. ASan) less effective
    'MBEDTLS_MEMORY_DEBUG', # depends on MEMORY_BUFFER_ALLOC_C
    'MBEDTLS_NO_64BIT_MULTIPLICATION', # influences anything that uses bignum
    'MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES', # removes a feature
    'MBEDTLS_NO_PLATFORM_ENTROPY', # removes a feature
    'MBEDTLS_NO_UDBL_DIVISION', # influences anything that uses bignum
    'MBEDTLS_PSA_P256M_DRIVER_ENABLED', # influences SECP256R1 KeyGen/ECDH/ECDSA
    'MBEDTLS_PLATFORM_NO_STD_FUNCTIONS', # removes a feature
    'MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS', # removes a feature
    'MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG', # behavior change + build dependency
    'MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER', # interface and behavior change
    'MBEDTLS_PSA_CRYPTO_SPM', # platform dependency (PSA SPM)
    'MBEDTLS_PSA_INJECT_ENTROPY', # conflicts with platform entropy sources
    'MBEDTLS_RSA_NO_CRT', # influences the use of RSA in X.509 and TLS
    'MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY', # interacts with *_USE_A64_CRYPTO_IF_PRESENT
    'MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY', # interacts with *_USE_ARMV8_A_CRYPTO_IF_PRESENT
    'MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY', # interacts with *_USE_A64_CRYPTO_IF_PRESENT
    'MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT', # setting *_USE_ARMV8_A_CRYPTO is sufficient
    'MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN', # build dependency (clang+memsan)
    'MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND', # build dependency (valgrind headers)
    'MBEDTLS_PSA_STATIC_KEY_SLOTS', # only relevant for embedded devices
    'MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE', # only relevant for embedded devices
    *PSA_UNSUPPORTED_FEATURE,
    *PSA_DEPRECATED_FEATURE,
    *PSA_UNSTABLE_FEATURE
])

def is_boolean_setting(name, value):
    """Is this a boolean setting?

    Mbed TLS boolean settings are enabled if the preprocessor macro is
    defined, and disabled if the preprocessor macro is not defined. The
    macro definition line in the configuration file has an empty expansion.

    PSA_WANT_xxx settings are also boolean, but when they are enabled,
    they expand to a nonzero value. We leave them undefined when they
    are disabled. (Setting them to 0 currently means to enable them, but
    this might change to mean disabling them. Currently we just never set
    them to 0.)
    """
    if re.match(PSA_SYMBOL_REGEXP, name):
        return True
    if not value:
        return True
    return False

def is_seamless_alt(name):
    """Whether the xxx_ALT symbol should be included in the full configuration.

    Include alternative implementations of platform functions, which are
    configurable function pointers that default to the built-in function.
    This way we test that the function pointers exist and build correctly
    without changing the behavior, and tests can verify that the function
    pointers are used by modifying those pointers.

    Exclude alternative implementations of library functions since they require
    an implementation of the relevant functions and an xxx_alt.h header.
    """
    if name in (
            'MBEDTLS_PLATFORM_GMTIME_R_ALT',
            'MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT',
            'MBEDTLS_PLATFORM_MS_TIME_ALT',
            'MBEDTLS_PLATFORM_ZEROIZE_ALT',
    ):
        # Similar to non-platform xxx_ALT, requires platform_alt.h
        return False
    return name.startswith('MBEDTLS_PLATFORM_')

def include_in_full(name):
    """Rules for symbols in the "full" configuration."""
    if name in EXCLUDE_FROM_FULL:
        return False
    if name.endswith('_ALT'):
        return is_seamless_alt(name)
    return True

def full_adapter(name, value, active):
    """Config adapter for "full"."""
    if not is_boolean_setting(name, value):
        return active
    return include_in_full(name)


class TFPSACryptoConfigFile(config_common.ConfigFile):
    """Representation of a TF PSA Crypto configuration file."""

    _path_in_tree = 'include/psa/crypto_config.h'
    default_path = [_path_in_tree,
                    os.path.join(os.path.dirname(__file__),
                                 os.pardir,
                                 _path_in_tree),
                    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 _path_in_tree)]

    def __init__(self, filename=None):
        super().__init__(self.default_path, 'TF-PSA-Crypto', filename)


class TFPSACryptoConfig(config_common.Config):
    """Representation of the TF PSA Crypto configuration.

    See the documentation of the `Config` class for methods to query
    and modify the configuration.
    """

    def __init__(self, filename=None):
        """Read the PSA crypto configuration files."""

        super().__init__()
        configfile = TFPSACryptoConfigFile(filename)
        self.configfiles.append(configfile)
        self.settings.update({name: config_common.Setting(configfile, active, name, value, section)
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
        if not value and re.match(PSA_SYMBOL_REGEXP, name):
            value = '1'

        super().set(name, value)


class TFPSACryptoConfigTool(config_common.ConfigTool):
    """Command line TF PSA Crypto config file manipulation tool."""

    def __init__(self):
        super().__init__(TFPSACryptoConfigFile.default_path[0])
        self.config = TFPSACryptoConfig(self.args.file)

    def custom_parser_options(self):
        """Adds TF PSA Crypto specific options for the parser."""

        self.add_adapter(
            'full', full_adapter,
            """Uncomment most features.
            Exclude alternative implementations and platform support options, as well as
            some options that are awkward to test.
            """)


if __name__ == '__main__':
    sys.exit(TFPSACryptoConfigTool().main())
