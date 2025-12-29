#!/usr/bin/env python3

"""Generate C preprocessor code to check for bad configurations.
"""

from typing import Iterator

import framework_scripts_path # pylint: disable=unused-import
from mbedtls_framework.config_checks_generator import * \
    #pylint: disable=wildcard-import,unused-wildcard-import
from mbedtls_framework import config_history

class CryptoInternal(SubprojectInternal):
    SUBPROJECT = 'TF-PSA-Crypto'

class CryptoOption(SubprojectOption):
    SUBPROJECT = 'psa/crypto_config.h'

ALWAYS_ENABLED_SINCE_4_0 = frozenset([
    'MBEDTLS_PSA_CRYPTO_CONFIG',
    'MBEDTLS_USE_PSA_CRYPTO',
])

def checkers_for_removed_options() -> Iterator[Checker]:
    """Discover removed options. Yield corresponding checkers."""
    history = config_history.ConfigHistory()
    old_public = history.options('mbedtls', '3.6')
    new_public = history.options('mbedtls', '4.0')
    crypto_public = history.options('tfpsacrypto', '1.0')
    crypto_internal = history.internal('tfpsacrypto', '1.0')
    for option in sorted(old_public - new_public):
        if option in ALWAYS_ENABLED_SINCE_4_0:
            continue
        if option in crypto_public:
            yield CryptoOption(option)
        elif option in crypto_internal:
            yield CryptoInternal(option)
        else:
            yield Removed(option, 'Mbed TLS 4.0')

def all_checkers() -> Iterator[Checker]:
    """Yield all checkers."""
    yield from checkers_for_removed_options()

MBEDTLS_CHECKS = BranchData(
    header_directory='library',
    header_prefix='mbedtls_',
    project_cpp_prefix='MBEDTLS',
    checkers=list(all_checkers()),
)

if __name__ == '__main__':
    main(MBEDTLS_CHECKS)
