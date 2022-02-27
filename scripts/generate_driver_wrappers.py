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
from typing import Tuple, NewType
import argparse
import jsonschema
import jinja2
from mbedtls_dev import build_tree

JSONSchema = NewType('JSONSchema', object)
Driver = NewType('Driver', object)

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


def validate_json(driverjson_data: Driver, driverschema_list: dict) -> bool:
    """
    Validate the Driver JSON against an appropriate schema
    the schema passed could be that matching an opaque/ transparent driver.
    """

    driver_type = driverjson_data["type"]
    driver_prefix = driverjson_data["prefix"]
    try:
        _schema = driverschema_list[driver_type]
        jsonschema.validate(instance=driverjson_data, schema=_schema)

    except KeyError as err:
        # This could happen if the driverjson_data.type does not exist in the passed in schema list
        # schemas = {'transparent': transparent_driver_schema, 'opaque': opaque_driver_schema}
        # Print onto stdout and stderr.
        print("Unknown Driver type " + driver_type +
              " for driver " + driver_prefix, str(err))
        print("Unknown Driver type " + driver_type +
              " for driver " + driver_prefix, str(err), file=sys.stderr)
        return False

    except jsonschema.exceptions.ValidationError as err:
        # Print onto stdout and stderr.
        print("Error: Failed to validate data file: {} using schema: {}."
              "\n Exception Message: \"{}\""
              " ".format(driverjson_data, _schema, str(err)))
        print("Error: Failed to validate data file: {} using schema: {}."
              "\n Exception Message: \"{}\""
              " ".format(driverjson_data, _schema, str(err)), file=sys.stderr)
        return False

    return True

def read_driver_descriptions(mbedtls_root: str, json_directory: str, \
                          jsondriver_list: str) -> Tuple[bool, list]:
    """
    Merge driver JSON files into a single ordered JSON after validation.
    """
    result = []
    with open(os.path.join(mbedtls_root,
                           'scripts',
                           'data_files',
                           'driver_jsons',
                           'driver_transparent_schema.json'), 'r') as file:
        transparent_driver_schema = json.load(file)
    with open(os.path.join(mbedtls_root,
                           'scripts',
                           'data_files',
                           'driver_jsons',
                           'driver_opaque_schema.json'), 'r') as file:
        opaque_driver_schema = json.load(file)

    driver_schema_list = {'transparent':transparent_driver_schema,
                          'opaque':opaque_driver_schema}

    with open(os.path.join(json_directory, jsondriver_list), 'r') as driverlistfile:
        driverlist = json.load(driverlistfile)
    for file_name in driverlist:
        with open(os.path.join(json_directory, file_name), 'r') as infile:
            json_data = json.load(infile)
            ret = validate_json(json_data, driver_schema_list)
            if ret is False:
                return ret, []
            result.append(json_data)
    return True, result


def main() -> int:
    """
    Main with command line arguments.
    returns 1 when read_driver_descriptions returns False
    """
    def_arg_mbedtls_root = build_tree.guess_mbedtls_root()
    def_arg_output_dir = os.path.join(def_arg_mbedtls_root, 'library')
    def_arg_template_dir = os.path.join(def_arg_mbedtls_root,
                                        'scripts',
                                        'data_files',
                                        'driver_templates')
    def_arg_json_dir = os.path.join(def_arg_mbedtls_root,
                                    'scripts',
                                    'data_files',
                                    'driver_jsons')

    parser = argparse.ArgumentParser()
    parser.add_argument('--mbedtls-root', nargs='?', default=def_arg_mbedtls_root,
                        help='root directory of mbedtls source code')
    parser.add_argument('--template-dir', nargs='?', default=def_arg_template_dir,
                        help='root directory of mbedtls source code')
    parser.add_argument('--json-dir', nargs='?', default=def_arg_json_dir,
                        help='root directory of mbedtls source code')
    parser.add_argument('output-directory', nargs='?',
                        default=def_arg_output_dir, help='output file\'s location')
    args = parser.parse_args()

    mbedtls_root = os.path.abspath(args.mbedtls_root)
    output_directory = def_arg_output_dir
    if args.template_dir is None:
        args.template_dir = os.path.join(args.mbedtls_root, def_arg_template_dir)
    template_directory = args.template_dir
    if args.json_dir is None:
        args.json_dir = os.path.join(args.mbedtls_root, def_arg_json_dir)
    json_directory = args.json_dir

    # Read and validate list of driver jsons from driverlist.json
    ret, merged_driver_json = read_driver_descriptions(mbedtls_root, json_directory,
                                                       'driverlist.json')
    if ret is False:
        return 1
    generate_driver_wrapper_file(template_directory, output_directory, merged_driver_json)

    return 0

if __name__ == '__main__':
    sys.exit(main())
