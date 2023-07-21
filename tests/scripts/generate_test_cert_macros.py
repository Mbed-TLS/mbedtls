#!/usr/bin/env python3

"""
Generate `tests/src/test_certs.h` which includes certficaties/keys/certificate list for testing.
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
import argparse
import jinja2

class MacroDefineAction(argparse.Action):
    #pylint: disable=signature-differs, too-few-public-methods
    def __call__(self, parser, namespace, values, option_string):
        if not hasattr(namespace, 'values'):
            setattr(namespace, 'values', [])
        macro_name, filename = values
        if self.dest in ('string', 'binary') and not os.path.exists(filename):
            raise argparse.ArgumentError(
                None, '`{}`: Input file does not exist.'.format(filename))
        namespace.values.append((self.dest, macro_name, filename))


def macro_define_type(value):
    ret = value.split('=', 1)
    if len(ret) != 2:
        raise argparse.ArgumentTypeError(
            '`{}` is not MACRO=value format'.format(value))
    return ret


def build_argparser(parser):
    parser.description = __doc__
    parser.add_argument('--string', type=macro_define_type, action=MacroDefineAction,
                        metavar='MACRO_NAME=path/to/file', help='PEM to C string. ')
    parser.add_argument('--binary', type=macro_define_type, action=MacroDefineAction,
                        metavar='MACRO_NAME=path/to/file',
                        help='DER to C arrary.')
    parser.add_argument('--password', type=macro_define_type, action=MacroDefineAction,
                        metavar='MACRO_NAME=password', help='Password to C string.')
    parser.add_argument('--output', type=str, required=True)


def main():
    parser = argparse.ArgumentParser()
    build_argparser(parser)
    args = parser.parse_args()
    return generate(**vars(args))

#pylint: disable=dangerous-default-value, unused-argument
def generate(values=[], output=None, **kwargs):
    """Generate C header file.
    """
    this_dir = os.path.dirname(os.path.abspath(__file__))
    template_loader = jinja2.FileSystemLoader(
        searchpath=os.path.join(this_dir, '..', 'data_files'))
    template_env = jinja2.Environment(
        loader=template_loader, lstrip_blocks=True, trim_blocks=True)

    def read_as_c_array(filename):
        with open(filename, 'rb') as f:
            data = f.read(12)
            while data:
                yield ', '.join(['{:#04x}'.format(b) for b in data])
                data = f.read(12)

    def read_lines(filename):
        with open(filename) as f:
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

    template = template_env.get_template('test_certs.h.jinja2')

    with open(output, 'w') as f:
        f.write(template.render(macros=values))


if __name__ == '__main__':
    sys.exit(main())
