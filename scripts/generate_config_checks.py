#!/usr/bin/env python3

"""Generate C preprocessor code to check for bad configurations.
"""

import framework_scripts_path # pylint: disable=unused-import
from mbedtls_framework.config_checks_generator import * \
    #pylint: disable=wildcard-import,unused-wildcard-import

MBEDTLS_CHECKS = BranchData(
    header_directory='library',
    header_prefix='mbedtls_',
    project_cpp_prefix='MBEDTLS',
    checkers=[
        Removed('MBEDTLS_KEY_EXCHANGE_RSA_ENABLED', 'Mbed TLS 4.0'),
        Removed('MBEDTLS_PADLOCK_C', 'Mbed TLS 4.0'),
    ],
)

if __name__ == '__main__':
    main(MBEDTLS_CHECKS)
