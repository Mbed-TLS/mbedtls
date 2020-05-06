#!/usr/bin/env python3

"""Generate wrapper code for PSA Cryptography drivers.
"""

# Copyright (C) 2020, ARM Limited, All Rights Reserved
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
#
# This file is part of mbed TLS (https://tls.mbed.org)

import argparse
import glob
import os
import re

import psa_crypto_driver_description
import psa_crypto_driver_header

def inbuf(name):
    return ['const uint8_t *' + name,
            'size_t ' + name + '_length',]

def outbuf(name):
    return ['uint8_t *' + name,
            'size_t ' + name + '_size',
            'size_t *' + name + '_length']

class Wrapper:
    def __init__(self, name, parameters):
        self.name = name
        self.parameters = parameters

    FUNCTION_TEMPLATE = """
psa_status_t psa_driver_wrapper_{name}({parameters})
{{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;
{use_parameters}{body}    return status;
}}
    """.rstrip(' ')

    def body(self, drivers):
        raise NotImplementedError

    PARAMETER_NAME_RE = re.compile(r'\w+\Z')
    @classmethod
    def name_from_declaration(cls, decl):
        return re.search(cls.PARAMETER_NAME_RE, decl).group(0)

    @classmethod
    def gen_call(cls, name, named_parameters, parameters_with_types):
        args = named_parameters
        args += map(cls.name_from_declaration, parameters_with_types)
        return '{}({})'.format(name, ', '.join(args))

    def write(self, out, transparent_drivers, opaque_drivers):
        body = self.body(transparent_drivers, opaque_drivers)
        parameters = ('\n    ' + ',\n    '.join(self.parameters)
                      if self.parameters
                      else 'void')
        use_parameters = ''.join('    (void){};\n'.format(param)
                                 for param in map(self.name_from_declaration,
                                                  self.parameters))
        out.write(self.FUNCTION_TEMPLATE.format(name=self.name,
                                                parameters=parameters,
                                                use_parameters=use_parameters,
                                                body=body))

class OperationWrapper(Wrapper):
    """Wrapper for a single-part operation."""

    def __init__(self, name, other_parameters):
        parameters = ([
            'psa_key_slot_t *slot',
            'psa_algorithm_t alg',
        ] + other_parameters)
        super().__init__(name, parameters)

    START = """
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    status = psa_get_key_slot_attributes(slot, &attributes);
    if (status != PSA_SUCCESS) return status;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime);

    switch (location) {
    """[1:].rstrip(' ')

    END = """
    default:
        break;
    }

exit:
    psa_reset_key_attributes(&attributes);
    """[1:].rstrip(' ')

    @staticmethod
    def gen_case(value, lines):
        return '\n        '.join(['    case ' + value + ':',
                                  *lines, 'break;']) + '\n\n'

    def driver_call(self, driver):
        name = driver.prefix + '_' + self.name
        # FIXME: this is wrong for transparent drivers for asymmetric keys,
        # and maybe for opaque drivers as well.
        key_pointer = 'slot->data.raw.data'
        key_size = 'slot->data.raw.bytes'
        call = self.gen_call(name,
                             ['&attributes', key_pointer, key_size],
                             self.parameters[1:])
        return 'status = {};'.format(call)

    def transparent_body(self, transparent_drivers):
        case_body = []
        for driver in transparent_drivers:
            case_body += [self.driver_call(driver),
                          'if (status != PSA_ERROR_NOT_SUPPORTED) goto exit;']
        return case_body

    def body(self, transparent_drivers, opaque_drivers):
        if not (transparent_drivers or opaque_drivers):
            return ''
        cases = []
        if transparent_drivers:
            case_body = self.transparent_body(transparent_drivers)
            cases.append(('PSA_KEY_LOCATION_LOCAL_STORAGE', case_body))
        for driver in opaque_drivers:
            case_body = [self.driver_call(driver)]
            cases.append((driver.location_symbol, case_body))
        return ''.join([self.START] +
                       [self.gen_case(*case) for case in cases] +
                       [self.END])

WRAPPERS = [
    OperationWrapper('sign_hash',
                     [*inbuf('hash'), *outbuf('signature')]),
]

def write_location_constants(out, drivers):
    """Generate location constants and write them out.

    Record the name of the location constant in the driver structure.
    """
    value = 0
    for driver in drivers:
        value += 1
        symbol = 'PSA_KEY_LOCATION_DRIVER_' + driver.prefix.upper()
        driver.location_symbol = symbol
        out.write('#define {} {}\n'.format(symbol, value))
    out.write('\n')

HEADER_TEMPLATE = """
/* Automatically generated by {script}. Do not edit. */

#include "psa/crypto_driver_common.h"
#include "psa_crypto_core.h"
#include "psa_crypto_driver_wrappers.h"

"""[1:]

FOOTER = """
/* End of automatically generated file. */
"""

def write_prototypes(out, drivers):
    for drv in drivers:
        out.write('/* Declare functions from the {} driver */\n'
                  .format(drv.prefix))
        psa_crypto_driver_header.write_header_content(out, drv)
        out.write('\n')

def write_driver_wrappers(output_file, drivers):
    transparent_drivers = [drv for drv in drivers if drv.is_transparent()]
    opaque_drivers = [drv for drv in drivers if drv.is_opaque()]
    with open(output_file, 'w') as out:
        out.write(HEADER_TEMPLATE.format(script=__file__))
        write_prototypes(out, transparent_drivers + opaque_drivers)
        write_location_constants(out, opaque_drivers)
        for wrapper in WRAPPERS:
            transparent = [drv for drv in transparent_drivers
                           if drv.has_function(wrapper.name)]
            opaque = [drv for drv in opaque_drivers
                           if drv.has_function(wrapper.name)]
            wrapper.write(out, transparent, opaque),
        out.write(FOOTER)

def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument('--output-file', '-o',
                        default='library/psa_crypto_driver_wrappers.c',
                        help="Name of the output file")
    parser.add_argument('input_files', metavar='INPUT', nargs='*',
                        help="driver description files in JSON format")
    options = parser.parse_args()
    drivers = list(map(psa_crypto_driver_description.from_json_file,
                       options.input_files))
    write_driver_wrappers(options.output_file, drivers)

if __name__ == '__main__':
    main()
