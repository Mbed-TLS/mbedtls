#!/usr/bin/env python3

"""
Generate `tests/src/test_ca_certs.h` which includes certficaties for testing.
"""

#
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


import os
import sys
import jinja2
import argparse

MACROS = [
    ("comment1", None, None),
    ("string", "TEST_CA_CRT_EC_PEM", "tests/data_files/test-ca2.crt"),
    ("binary", "TEST_CA_CRT_EC_DER", "tests/data_files/test-ca2.crt.der"),
    ("string", "TEST_CA_KEY_EC_PEM", "tests/data_files/test-ca2.key.enc"),
    ("password", "TEST_CA_PWD_EC_PEM", "PolarSSLTest"),
    ("binary", "TEST_CA_KEY_EC_DER", "tests/data_files/test-ca2.key.der"),
    ("string", "TEST_CA_CRT_RSA_SHA256_PEM",
     "tests/data_files/test-ca-sha256.crt"),
    ("binary", "TEST_CA_CRT_RSA_SHA256_DER",
     "tests/data_files/test-ca-sha256.crt.der"),
    ("string", "TEST_CA_CRT_RSA_SHA1_PEM", "tests/data_files/test-ca-sha1.crt"),
    ("binary", "TEST_CA_CRT_RSA_SHA1_DER", "tests/data_files/test-ca-sha1.crt.der"),
    ("string", "TEST_CA_KEY_RSA_PEM", "tests/data_files/test-ca.key"),
    ("password", "TEST_CA_PWD_RSA_PEM", "PolarSSLTest"),
    ("binary", "TEST_CA_KEY_RSA_DER", "tests/data_files/test-ca.key.der"),
    ("comment2", None, None),
    ("string", "TEST_SRV_CRT_EC_PEM", "tests/data_files/server5.crt"),
    ("binary", "TEST_SRV_CRT_EC_DER", "tests/data_files/server5.crt.der"),
    ("string", "TEST_SRV_KEY_EC_PEM", "tests/data_files/server5.key"),
    ("binary", "TEST_SRV_KEY_EC_DER", "tests/data_files/server5.key.der"),
    ("string", "TEST_SRV_CRT_RSA_SHA256_PEM",
     "tests/data_files/server2-sha256.crt"),
    ("binary", "TEST_SRV_CRT_RSA_SHA256_DER",
     "tests/data_files/server2-sha256.crt.der"),
    ("string", "TEST_SRV_CRT_RSA_SHA1_PEM", "tests/data_files/server2.crt"),
    ("binary", "TEST_SRV_CRT_RSA_SHA1_DER", "tests/data_files/server2.crt.der"),
    ("string", "TEST_SRV_KEY_RSA_PEM", "tests/data_files/server2.key"),
    ("binary", "TEST_SRV_KEY_RSA_DER", "tests/data_files/server2.key.der"),
    ("comment3", None, None),
    ("string", "TEST_CLI_CRT_EC_PEM", "tests/data_files/cli2.crt"),
    ("binary", "TEST_CLI_CRT_EC_DER", "tests/data_files/cli2.crt.der"),
    ("string", "TEST_CLI_KEY_EC_PEM", "tests/data_files/cli2.key"),
    ("binary", "TEST_CLI_KEY_EC_DER", "tests/data_files/cli2.key.der"),
    ("string", "TEST_CLI_CRT_RSA_PEM", "tests/data_files/cli-rsa-sha256.crt"),
    ("binary", "TEST_CLI_CRT_RSA_DER", "tests/data_files/cli-rsa-sha256.crt.der"),
    ("string", "TEST_CLI_KEY_RSA_PEM", "tests/data_files/cli-rsa.key"),
    ("binary", "TEST_CLI_KEY_RSA_DER", "tests/data_files/cli-rsa.key.der")
]


def write_cert_macros():
    this_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(this_dir, '..', '..'))
    template_loader = jinja2.FileSystemLoader(
        searchpath=os.path.join(this_dir, '..', 'data_files'))
    template_env = jinja2.Environment(
        loader=template_loader, lstrip_blocks=True, trim_blocks=True)

    def read_as_c_array(filename):
        with open(os.path.join(project_root, filename), 'rb') as f:
            data = f.read(12)
            while data:
                yield ', '.join(['{:#04x}'.format(b) for b in data])
                data = f.read(12)

    def read_lines(filename):
        with open(os.path.join(project_root, filename)) as f:
            try:
                for line in f:
                    yield line.strip()
            except:
                print(filename)
                raise

    def put_to_column(value, position=0):
        return ' '*position + value

    template_env.filters['read_as_c_array'] = read_as_c_array
    template_env.filters['read_lines'] = read_lines
    template_env.filters['put_to_column'] = put_to_column

    template = template_env.get_template('test_ca_certs.h.jinja2')
    with open(os.path.join(this_dir, '..', 'src', 'test_ca_certs.h'), 'w') as f:
        f.write(template.render(macros=MACROS))


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('-l', '--list', action='store_true',
                        help='List certificate source files')
    args = parser.parse_args()
    if args.list:
        this_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(this_dir, '..', '..'))
        for i, _, name in MACROS:
            if i not in ('string', 'binary'):
                continue
            a=os.path.join(
                project_root, 'tests', 'data_files')
            b=os.path.abspath(os.path.join(project_root,name))

            print(os.path.relpath(b,a))
    else:
        write_cert_macros()
    return 0


if __name__ == '__main__':
    sys.exit(main())
