#!/usr/bin/env python3

"""Generate query_config.c

The file query_config.c contains a C function that can be used to check if
a configuration macro is defined and to retrieve its expansion in string
form (if any). This facilitates querying the compile time configuration of
the library, for example, for testing.

The query_config.c is generated from the default configuration files
include/mbedtls/mbedtls_config.h and include/psa/crypto_config.h.
The idea is that mbedtls_config.h and crypto_config.h contain ALL the
compile time configurations available in Mbed TLS (commented or uncommented).
This script extracts the configuration macros from the two files and this
information is used to automatically generate the body of the query_config()
function by using the template in scripts/data_files/query_config.fmt.

Usage: scripts/generate_query_config.py without arguments, or
generate_query_config.py mbedtls_config_file psa_crypto_config_file template_file output_file
"""

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

import sys
import os
import re

default_mbedtls_config_file = './include/mbedtls/mbedtls_config.h'
default_psa_crypto_config_file = './include/psa/crypto_config.h'
default_query_config_format_file = './scripts/data_files/query_config.fmt'
default_query_config_file = './programs/test/query_config.c'

if len(sys.argv) > 1:
    if len(sys.argv) != 5:
        sys.exit(f'Invalid number of arguments - usage: {sys.argv[0]} [MBED_TLS_CONFIG_FILE PSA_CRYPTO_CONFIG_FILE TEMPLATE_FILE OUTPUT_FILE]')
    mbedtls_config_file, psa_crypto_config_file, query_config_format_file, query_config_file = sys.argv[1:]

    if not os.path.isfile(mbedtls_config_file):
        sys.exit(f'No such file: {mbedtls_config_file}')
    if not os.path.isfile(psa_crypto_config_file):
        sys.exit(f'No such file: {psa_crypto_config_file}')
    if not os.path.isfile(query_config_format_file):
        sys.exit(f'No such file: {query_config_format_file}')
else:
    mbedtls_config_file = default_mbedtls_config_file
    psa_crypto_config_file = default_psa_crypto_config_file
    query_config_format_file = default_query_config_format_file
    query_config_file = default_query_config_file

    if not (os.path.isfile(mbedtls_config_file) and \
            os.path.isfile(query_config_format_file) and \
            os.path.isfile(psa_crypto_config_file)):
        os.chdir('..')
        if not (os.path.isfile(mbedtls_config_file) and \
                os.path.isfile(query_config_format_file) and \
                os.path.isfile(psa_crypto_config_file)):
            sys.exit('No arguments supplied, must be run from project root or a first-level subdirectory')

# Excluded macros from the generated query_config.c. For example, macros that
# have commas or function-like macros cannot be transformed into strings easily
# using the preprocessor, so they should be excluded or the preprocessor will
# throw errors.
excluded = [
    'MBEDTLS_SSL_CIPHERSUITES'
]
excluded_re = '|'.join(excluded)

# This variable will contain the string to replace in the CHECK_CONFIG of the
# format file
config_check = ''
list_config = ''

for config_file in [mbedtls_config_file, psa_crypto_config_file]:
    if config_file is None:
        continue  # we might not have been given a PSA crypto config file

    with open(config_file, 'r', encoding='utf-8') as f:
        for line in f:
            if match := re.match(r'^(\/\/)?\s*#\s*define\s+(MBEDTLS_\w+|PSA_WANT_\w+).*', line):
                name = match.group(2)

                # Skip over the macro if it is in the excluded list
                if re.match(excluded_re, name):
                    continue

                config_check += f'''\
#if defined({name})
    if( strcmp( "{name}", config ) == 0 )
    {{
        MACRO_EXPANSION_TO_STR( {name} );
        return( 0 );
    }}
#endif /* {name} */

'''

                list_config += f'''\
#if defined({name})
    OUTPUT_MACRO_NAME_VALUE({name});
#endif /* {name} */

'''

# Read the full format file into a string
with open(query_config_format_file, 'r', encoding='utf-8') as f:
    query_config_format = f.read()

# Replace the body of the query_config() function with the code we just wrote
query_config_format = query_config_format.replace('CHECK_CONFIG', config_check)
query_config_format = query_config_format.replace('LIST_CONFIG', list_config)

# Rewrite the query_config.c file
with open(query_config_file, 'w', encoding='utf-8') as f:
    f.write(query_config_format)
