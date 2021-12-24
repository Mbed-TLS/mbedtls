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
import argparse
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

    return template.render(drivers = driver_jsoncontext)


def generate_driver_wrapper_file(template_dir: str, output_dir: str, driver_jsoncontext: list ) -> None:
    """
    Generate the file psa_crypto_driver_wrapper.c.
    """
    driver_wrapper_template_filename = \
        os.path.join(template_dir, "psa_crypto_driver_wrappers.c.jinja")

    result = render(driver_wrapper_template_filename, driver_jsoncontext)

    with open(os.path.join(output_dir, "psa_crypto_driver_wrappers.c"), 'w') as out_file:
        out_file.write(result)

def validate_mergedjson(merged_driverjson: list) -> int:
    """
    Validate the merged Driver JSON for errors that we can catch early
    """
    return 0


def merge_driverjsonfiles(json_directory: str, jsondriverlistName: str) -> list:
    """
    Merge driver JSON files into a single ordered JSON.
    """
    result = list()
    driverlist = list()
    with open(os.path.join(json_directory, jsondriverlistName), 'r') as driverlistfile:
        driverlist = json.load(driverlistfile)
    for file_name in driverlist:
        with open(os.path.join(json_directory, file_name), 'r') as infile:
            result.extend(json.load(infile))

    return result


def main() -> int:
    """
    Main with command line arguments.
    """
    def_arg_mbedtls_root = build_tree.guess_mbedtls_root()
    def_arg_output_dir = os.path.join(def_arg_mbedtls_root, 'library')
    def_arg_template_dir = os.path.join(def_arg_mbedtls_root, 'scripts/data_files/driver_templates/')
    def_arg_json_dir = os.path.join(def_arg_mbedtls_root, 'scripts/data_files/driver_jsons/')

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

    mbedtls_root       = os.path.abspath(args.mbedtls_root)
    output_directory   = args.output_directory
    template_directory = args.template_dir
    json_directory     = args.json_dir

    # load list of driver jsons from driverlist.json
    merged_driverjson = merge_driverjsonfiles(json_directory, 'driverlist.json')
    ret = validate_mergedjson(merged_driverjson)
    if ret == 1:
        print("Validation failed ")
        return 1

    generate_driver_wrapper_file(template_directory, output_directory, merged_driverjson)

    return 0

if __name__ == '__main__':
    sys.exit(main())
