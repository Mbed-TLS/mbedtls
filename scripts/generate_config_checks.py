#!/usr/bin/env python3

"""Generate C preprocessor code to check for bad configurations.
"""

import framework_scripts_path # pylint: disable=unused-import
from mbedtls_framework.config_checks_generator import * \
    #pylint: disable=wildcard-import,unused-wildcard-import

class CryptoInternal(SubprojectInternal):
    SUBPROJECT = 'TF-PSA-Crypto'

class CryptoOption(SubprojectOption):
    SUBPROJECT = 'psa/crypto_config.h'

MBEDTLS_CHECKS = BranchData(
    header_directory='library',
    header_prefix='mbedtls_',
    project_cpp_prefix='MBEDTLS',
    checkers=[
        CryptoInternal('MBEDTLS_MD5_C', 'PSA_WANT_ALG_MD5 in psa/crypto_config.h'),
        CryptoOption('MBEDTLS_BASE64_C'),
        Removed('MBEDTLS_KEY_EXCHANGE_RSA_ENABLED', 'Mbed TLS 4.0'),
        Removed('MBEDTLS_PADLOCK_C', 'Mbed TLS 4.0'),
    ],
)

if __name__ == '__main__':
    main(MBEDTLS_CHECKS)
