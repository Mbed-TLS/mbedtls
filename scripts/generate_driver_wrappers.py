#!/usr/bin/env python3
"""Generate library/psa_crypto_driver_wrappers.c

   This module is invoked by the build sripts to auto generate the
   psa_crypto_driver_wrappers.c based on template files in
   script/data_files/driver_templates/.
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
import json
from typing import Tuple
import argparse
import jsonschema
from jsonschema import validate
import jinja2
from mbedtls_dev import build_tree

def render(template_path: str, driver_jsoncontext: list) -> str:
    """
    Render template from the input file and driver JSON.
    """
    environment = jinja2.Environment(
        loader=jinja2.FileSystemLoader(os.path.dirname(template_path)),
        keep_trailing_newline=True)
    template = environment.get_template(os.path.basename(template_path))

    return template.render(drivers=driver_jsoncontext)


def generate_driver_wrapper_file(template_dir: str, \
                                 output_dir: str, driver_jsoncontext: list) -> None:
    """
    Generate the file psa_crypto_driver_wrapper.c.
    """
    driver_wrapper_template_filename = \
        os.path.join(template_dir, "psa_crypto_driver_wrappers.c.jinja")

    result = render(driver_wrapper_template_filename, driver_jsoncontext)

    with open(os.path.join(output_dir, "psa_crypto_driver_wrappers.c"), 'w') as out_file:
        out_file.write(result)


def validate_json(driverjson_data: list, driverschema: list) -> bool:
    """
    Validate the Driver JSON against schema
    """
    try:
        validate(instance=driverjson_data, schema=driverschema)
    except jsonschema.exceptions.ValidationError as err:
        print(err)
        print("The driver JSON data is InValid")
        return False

    return True

def merge_driverjsonfiles(mbedtls_root: str, json_directory: str, \
                          jsondriver_list: str) -> Tuple[bool, list]:
    """
    Merge driver JSON files into a single ordered JSON after validation.
    """
    result = list()
    driverlist = list()
    with open(os.path.join(mbedtls_root, \
        'scripts/data_files/driver_jsons/driver_transparent_schema.json'), 'r') as file:
        transparent_driver_schema = json.load(file)
    with open(os.path.join(mbedtls_root, \
        'scripts/data_files/driver_jsons/driver_opaque_schema.json'), 'r') as file:
        opaque_driver_schema = json.load(file)

    with open(os.path.join(json_directory, jsondriver_list), 'r') as driverlistfile:
        driverlist = json.load(driverlistfile)
    for file_name in driverlist:
        with open(os.path.join(json_directory, file_name), 'r') as infile:
            json_data = json.load(infile)
            if json_data['type'] == 'transparent':
                ret = validate_json(json_data, transparent_driver_schema)
            elif json_data['type'] == 'opaque':
                ret = validate_json(json_data, opaque_driver_schema)
            else:
                ret = False
                print("Unknown Driver type")
            if ret is False:
                return ret, []
            result.append(json_data)
    return True, result


def main() -> int:
    """
    Main with command line arguments.
    """
    def_arg_mbedtls_root = build_tree.guess_mbedtls_root()
    def_arg_output_dir = os.path.join(def_arg_mbedtls_root, 'library')
    def_arg_template_dir = os.path.join(def_arg_mbedtls_root, \
                           'scripts/data_files/driver_templates/')
    def_arg_json_dir = os.path.join(def_arg_mbedtls_root, \
                       'scripts/data_files/driver_jsons/')

    parser = argparse.ArgumentParser()
    parser.add_argument('--mbedtls-root', nargs='?', default=def_arg_mbedtls_root,
                        help='root directory of mbedtls source code')
    parser.add_argument('--template_dir', nargs='?', default=def_arg_template_dir,
                        help='root directory of mbedtls source code')
    parser.add_argument('--json_dir', nargs='?', default=def_arg_json_dir,
                        help='root directory of mbedtls source code')
    parser.add_argument('output_directory', nargs='?',
                        default=def_arg_output_dir, help='output file\'s location')
    args = parser.parse_args()

    mbedtls_root = os.path.abspath(args.mbedtls_root)
    output_directory = args.output_directory
    template_directory = args.template_dir
    json_directory = args.json_dir

    # load list of driver jsons from driverlist.json
    ret, merged_driverjson = merge_driverjsonfiles(mbedtls_root, json_directory, 'driverlist.json')
    if ret is False:
        return 1
    generate_driver_wrapper_file(template_directory, output_directory, merged_driverjson)

    return 0

if __name__ == '__main__':
    sys.exit(main())
