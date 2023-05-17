#!/usr/bin/env python3

"""
Generate OpenSSL config file and database for generating crl files
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
from datetime import datetime, timedelta,timezone
from asn1crypto import pem, x509
JINJA2_ENV=None
def get_jinja2_env():
    global JINJA2_ENV
    if JINJA2_ENV is None:
        this_dir = os.path.dirname(os.path.abspath(__file__))
        template_loader = jinja2.FileSystemLoader(
            searchpath=os.path.join(this_dir, '..', 'data_files'))
        JINJA2_ENV = jinja2.Environment(
            loader=template_loader)
    return JINJA2_ENV

def write_target_file(template, output, **kwargs):
    template_env = get_jinja2_env()
    template = template_env.get_template(template)
    with open(output, 'w') as f:
        f.write(template.render(**kwargs))
    return 0

def generate_ca(args):
    write_target_file(args.template,
                      args.output or f'{args.ca_name}.opensslconf',
                      ca_name=args.ca_name,
                      database=args.database or f'{args.ca_name}.db')

def get_openssl_subject(cert):
    openssl_trans_map=dict([('country_name', 'C'),
('organization_name', 'O'),
('common_name', 'CN')])
    ret=['']
    for tag,value in cert.subject.native.items():
        ret.append(f'{openssl_trans_map[tag]}={value}')
    return '/'.join(ret)

def get_cert_serial_subj(cert_file):
    with open(cert_file, 'rb') as f:
        for type_name, headers, der_bytes in pem.unarmor(f.read(), multiple=True):
            if type_name != "CERTIFICATE" or headers:
                raise Exception("Not X509 cert or encrypted ")
            cert=x509.Certificate.load(der_bytes)
            not_valid_after=cert.not_valid_after.strftime("%y%m%d%H%M%SZ")
            serial_number=f'{cert.serial_number:02x}'
            subject = get_openssl_subject(cert)
            yield not_valid_after,serial_number,subject


def revoke_certificates(args):
    with open(args.database,'w') as f:
        for cert_file in args.certificates:
            for expired_date, serial, subject in get_cert_serial_subj(cert_file):
                revoke_date=datetime.now(timezone.utc).strftime("%y%m%d%H%M%SZ")
                f.write(f'R\t{expired_date}\t{revoke_date}\t{serial}\tunkown\t{subject}\n')
    # for cert_file in args.valid:
    #     for expired_date, serial, subject in get_cert_serial_subj(cert_file):
    #         output.append(f'V\t{expired_date}\t\t{serial}\tunkown\t{subject}')
    # with open(args.output,'w') as f:
    #     f.write('\n'.join(output))

def main():
    parser = argparse.ArgumentParser(__doc__)
    subparsers = parser.add_subparsers(help='sub-command help')

    ca_parser=subparsers.add_parser('ca', help='generate ca config file')
    ca_parser.add_argument('--template', type=str, nargs='?',default='ca.opensslconf.jinja2')
    ca_parser.add_argument('--output',type=str,nargs='?')
    ca_parser.add_argument('--database',type=str,nargs='?')
    ca_parser.add_argument('--ca_name',type=str,default='test-ca')
    ca_parser.set_defaults(func=generate_ca)

    db_parser= subparsers.add_parser('revoke', help='generate cert status db')
    db_parser.add_argument('certificates', metavar='certificates', type=str, nargs='+',
                    help='certificate files')
    db_parser.add_argument('--database',type=str,nargs='?',default='test-ca.db')
    db_parser.set_defaults(func=revoke_certificates)

    args = parser.parse_args()
    if hasattr(args,'func'):
        args.func(args)
    else:
        parser.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())
